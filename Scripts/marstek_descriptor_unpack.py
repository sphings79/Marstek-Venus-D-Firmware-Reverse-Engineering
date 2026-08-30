#!/usr/bin/env python3
"""
Nutzung
-----------
cd ~/Downloads/Claude
python3 marstek_descriptor_unpack.py \
  "/Users/<user>/Claude/Projects/Marstek FW Archiv/firmwares/VNSD-0/Control/150/VNSD-0_app_0150_0805_115146.bin" \
  Descriptor_Table_Decoded_v150.csv
marstek_descriptor_unpack.py
============================
Entpackt die Modbus-Descriptor-Tabelle aus einer Marstek Venus D Control-Firmware
(STM32, Flash-Basis 0x08000000) -- rein statisch, ohne Geraet und ohne Ghidra.

Hintergrund
-----------
Die 246 x 12 Byte grosse Descriptor-Tabelle bei SRAM 0x20000354 wird NICHT vom
Code berechnet, sondern ist ein ganz normales .data-Global. Das .data-Image liegt
LZ77-komprimiert am Flash-Ende und wird beim Boot von der C-Runtime entpackt.
Deshalb schlugen alle bisherigen statischen Suchen fehl.

Packformat (1 Byte Opcode, reverse-engineered)
----------------------------------------------
    op = *src++
    nlit = (op & 0x07) - 1            # 0..6 Literale;  (op & 7) == 0 -> Escape
    len4 = (op >> 4) & 0x0F           # Laengenfeld (4 Bit, inkl. Bit 7)

    <nlit Literalbytes kopieren>

    if op & 0x08:                     # LZ77-Match
        dist  = *src++                # 1 Byte Rueckwaerts-Distanz
        mlen  = len4 + 2
        <mlen Bytes von (out_ptr - dist) kopieren, ueberlappend erlaubt>
    else:                             # Nullrun
        <len4 Nullbytes ausgeben>

Weil jedes 0x00 im Ausgabestrom als Nullrun kodiert wird, enthaelt der
komprimierte Bereich keinerlei 0x00-Bytes -- daran ist er im Flash erkennbar.
Die Distanzen sind fast immer Vielfache von 12 (0x0C, 0x18, 0x24, 0x30 ...),
d.h. Rueckverweise auf vorherige Descriptor-Eintraege.

Escape (op & 7) == 0 ist selten (~7x im ganzen Image) und noch nicht restlos
eindeutig; dieses Skript loest ihn per Lookahead-Suche auf und meldet jede
getroffene Entscheidung.

Eintragslayout (12 Byte)
------------------------
    +0  u16  Registernummer (direkte PDU-Adresse, kein Offset)
    +2  u16  0 (Padding)
    +4  u32  Quellzeiger (SRAM / Flash)
    +8  u8   Typcode   01=u8 02=u16 04=u32 11=i8 12=i16 14=i32 24=float 31=ascii
    +9  u8   Elementgroesse (low nibble)
    +10 u8   Skalencode 0=x1 1=x10 2=x100 3=/10 4=/100 5=negate
    +11 u8   Anzahl Elemente

Verifiziert gegen VNSD-0_app_1492_0702_142136.bin (v149.2):
246/246 Eintraege, Registerbereich 30000..38014, vier unabhaengige Startoffsets
liefern eine byte-identische Tabelle (SHA-256 becbf8146ce51ffb...).
"""
import struct, sys, csv

TYPES = {0x01:'u8',0x02:'u16',0x04:'u32',0x11:'i8',0x12:'i16',
         0x14:'i32',0x24:'float32',0x31:'ascii'}
SCALES = {0:'x1',1:'x10',2:'x100',3:'/10',4:'/100',5:'negate'}
BASE = 0x08000000


def find_packed_regions(d, minlen=1200):
    """Alle zusammenhaengenden Bereiche ohne 0x00-Byte (das Packformat kodiert
    jede Null als Nullrun, daher ist der Stream garantiert nullfrei)."""
    regs = []; run = None
    for o in range(len(d)):
        if d[o] != 0x00:
            if run is None: run = o
        else:
            if run is not None and o - run >= minlen: regs.append((run, o))
            run = None
    if run is not None and len(d) - run >= minlen: regs.append((run, len(d)))
    regs.sort(key=lambda r: r[0] - r[1])
    return regs


def _step(out, d, i, end, nlit_override=None, consume_extra=1):
    op = d[i]; i += 1
    nl = op & 7
    len4 = (op >> 4) & 0x0F
    if nl == 0:
        if nlit_override is None:
            if i >= end: return None
            nlit = d[i] + 4; i += 1        # Default-Heuristik fuer den Escape
        else:
            nlit = nlit_override
            if consume_extra: i += 1
    else:
        nlit = nl - 1
    if i + nlit > end: return None
    out += d[i:i+nlit]; i += nlit
    if op & 8:
        if i >= end: return None
        dist = d[i]; i += 1
        mlen = len4 + 2
        if dist == 0 or dist > len(out): return None
        p = len(out) - dist
        for k in range(mlen): out.append(out[p+k])
    else:
        out += b'\x00' * len4
    return i


def _entries(out, base):
    """Zaehlt gueltige aufeinanderfolgende 12-Byte-Eintraege ab base."""
    n = 0; q = base; last = -1
    while q + 12 <= len(out):
        reg, pad = struct.unpack_from('<HH', out, q)
        ptr = struct.unpack_from('<I', out, q+4)[0]
        ty = out[q+8]
        ok = (20000 <= reg <= 59999 and pad == 0 and ty in TYPES and reg >= last
              and (ptr == 0 or 0x08000000 <= ptr < 0x08100000
                   or 0x20000000 <= ptr < 0x20020000
                   or 0x60000000 <= ptr < 0x60100000))
        if not ok: break
        last = reg; n += 1; q += 12
    return n


def decompress(d, start, end, anchor):
    out = bytearray(); i = start; base = None; fixes = []
    while i < end:
        if (d[i] & 7) != 0 or base is None:
            ni = _step(out, d, i, end)              # Escape-Default: naechstes Byte + 4
            if ni is None: break
            i = ni
        else:
            best = None
            for consume in (1, 0):
                for nlit in range(0, 33):
                    t = bytearray(out); ti = _step(t, d, i, end, nlit, consume)
                    if ti is None: continue
                    for _ in range(120):                 # Lookahead
                        if ti >= end or (d[ti] & 7) == 0: break
                        n2 = _step(t, d, ti, end)
                        if n2 is None: break
                        ti = n2
                    cand = (_entries(t, base), len(t), nlit, consume)
                    if best is None or cand[:2] > best[:2]: best = cand
            if best is None: break
            fixes.append(('0x%08X' % (BASE+i), '%02X' % d[i], best[2], best[3]))
            ni = _step(out, d, i, end, best[2], best[3])
            if ni is None: break
            i = ni
        if base is None and anchor in out:
            base = out.find(anchor)
    return out, base, fixes


def main(path, out_csv, anchor_hex=None):
    d = open(path, 'rb').read()
    probe = bytes.fromhex(anchor_hex) if anchor_hex else b'\x30\x75\x00\x00'
    regions = find_packed_regions(d)
    print('Nullfreie Kandidatenbereiche:',
          ', '.join('0x%08X-0x%08X (%d B)' % (BASE+a, BASE+b, b-a) for a, b in regions[:6]))

    best = None
    for lo, hi in regions[:6]:
        # 0xFF-Fuellung am Ende abschneiden
        e = min(len(d), hi + 0x400)
        while e > lo and d[e-1] == 0xFF: e -= 1
        for st in range(max(0, lo - 0x800), min(lo + 0x60, e)):
            out, base, fixes = decompress(d, st, e, probe)
            if base is None: continue
            n = _entries(out, base)
            if best is None or n > best[0]:
                best = (n, st, out, base, fixes, lo, e)
            if n >= 246: break
        if best and best[0] >= 246: break
    if best is None:
        print('FEHLER: kein Descriptor-Anker gefunden.'); return 1

    n, st, out, base, fixes, lo, e = best
    print('Gepackter Stream: 0x%08X .. 0x%08X   Start 0x%08X'
          % (BASE+lo, BASE+e, BASE+st))
    print('-> %d Byte entpackt, Tabelle bei Offset +0x%X, %d Eintraege' % (len(out), base, n))
    if fixes:
        print('Escape-Opcodes (op & 7 == 0) per Lookahead aufgeloest:')
        for f in fixes: print('   %s op=%s nlit=%d consume_extra=%d' % f)

    rows = []
    for k in range(n):
        q = base + k*12
        reg, _ = struct.unpack_from('<HH', out, q)
        ptr = struct.unpack_from('<I', out, q+4)[0]
        ty, sz, sc, cnt = out[q+8:q+12]
        rows.append(dict(register=reg, type=TYPES.get(ty, hex(ty)),
                         type_code='0x%02X' % ty, scale=sc,
                         scale_str=SCALES.get(sc, '?'), elem_size=sz & 0x0F,
                         count=cnt, source_ptr='0x%08X' % ptr, notes=''))
    with open(out_csv, 'w', newline='') as f:
        w = csv.DictWriter(f, fieldnames=['register','type','type_code','scale',
                                          'scale_str','elem_size','count',
                                          'source_ptr','notes'])
        w.writeheader(); w.writerows(rows)
    print('CSV geschrieben: %s (%d Zeilen)' % (out_csv, len(rows)))
    return 0


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(__doc__)
        print('Aufruf: %s <firmware.bin> [ausgabe.csv]' % sys.argv[0]); sys.exit(1)
    sys.exit(main(sys.argv[1], sys.argv[2] if len(sys.argv) > 2
                  else 'Descriptor_Table_Decoded.csv'))
