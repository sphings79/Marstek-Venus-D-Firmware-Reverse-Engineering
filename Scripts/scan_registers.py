#!/usr/bin/env python3
"""
Marstek Venus D — Flexibler Register-Scanner (Raw-Socket, kein pymodbus)
========================================================================
Verwendung:
  python3 scan_registers.py --host 192.168.1.100 --regs 30005
  python3 scan_registers.py --host 192.168.1.100 --regs 30000-30040,32200,34000-34033
  python3 scan_registers.py --host 192.168.1.100 --regs 34002 --watch 5
  python3 scan_registers.py --host 192.168.1.100 --file unknown_regs.txt --out result.csv
  python3 scan_registers.py --host 192.168.1.100 --regs 30000-30010 --unknown-only
  python3 scan_registers.py --host 192.168.1.100 --regs 30000-49999 --decode-all --out full.csv

Changelog:
  2026-08-14 (a):
    - Live-Ausgabe (jeder Wert sofort), Fortschrittszeile, echte Abfrage-Zeitstempel.
    - BMS-Pack-Layout korrigiert (max_cell_v = Offset +5, charge_status = +4).
  2026-08-14 (b):
    - VOLLSTÄNDIGE Register-Namen: Das Script lädt jetzt zur Laufzeit die
      Register-Map-CSV (Marstek_Venus_D_Register_Map_Final_all_register.csv)
      und labelt damit ALLE dokumentierten Register — nicht mehr nur den fest
      verdrahteten KNOWN-Satz. Pfad autom. gesucht oder via --regmap.
    - Konfidenz-Tiers im Output: bekannte Register normal, vermutete mit
      Präfix "Verm:", unbekannte mit "Unb:".
    - Voll-Dekodierung: Jeder Registerwert wird zusätzlich als int16/uint16/hex/
      bin/ASCII(BE+LE)/BCD/÷10/÷100/÷1000 sowie 32-Bit-Kombi mit dem Folgeregister
      ausgegeben (in der CSV immer, im Terminal für Verm:/Unb: bzw. --decode-all).
"""

import socket, struct, csv, time, sys, os, argparse, signal, select
from datetime import datetime

BATCH_SIZE = 32
DELAY_S    = 0.15

stop_flag = False
def sigint_handler(sig, frame):
    global stop_flag
    print("\n  Ctrl+C — beende...", flush=True)
    stop_flag = True
signal.signal(signal.SIGINT, sigint_handler)


# ═══════════════════════════════════════════════════════════
# Modbus TCP Raw-Socket
# ═══════════════════════════════════════════════════════════

def build_req(tid, slave, reg, count):
    pdu  = struct.pack(">BBHH", slave, 0x03, reg, count)
    mbap = struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu))
    return mbap + pdu


def recv_response(sock, timeout=3.0, expect_tid=None):
    """Liest eine MBAP-Antwort vom Socket.

    Mit expect_tid werden Frames mit fremder Transaction-ID verworfen und es
    wird weitergelesen. Ohne diese Pruefung landet eine verspaetete Antwort
    (nach einem Timeout, oder von einem anderen Client am selben Proxy) beim
    naechsten Request — dann sind alle Folgewerte des Durchlaufs um einen
    Frame verschoben und stehen auf dem falschen Register.
    """
    resp = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        ready = select.select([sock], [], [], min(remaining, 1.0))
        if not ready[0]:
            if time.time() >= deadline:
                return None
            continue
        chunk = sock.recv(512)
        if not chunk:
            return None
        resp += chunk
        while len(resp) >= 6:
            total_expected = 6 + struct.unpack(">H", resp[4:6])[0]
            if len(resp) < total_expected:
                break
            frame, resp = resp[:total_expected], resp[total_expected:]
            if expect_tid is None or struct.unpack(">H", frame[0:2])[0] == expect_tid:
                return frame
            # fremde/veraltete Antwort -> verwerfen, weiterlesen


def parse(data, count):
    if not data or len(data) < 9:
        return None
    fc = data[7]
    if fc & 0x80:
        return None
    if fc != 0x03:
        return None
    byte_count = data[8]
    n = byte_count // 2
    if n < 1 or len(data) < 9 + byte_count:
        return None
    if n != count:          # Antwortlaenge passt nicht zur Anfrage -> verwerfen
        return None
    return list(struct.unpack(f">{n}H", data[9:9 + byte_count]))


def mb_connect(host, port, timeout=5.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(None)
        return s
    except Exception as e:
        print(f"    Connect failed: {e}", flush=True)
        return None


def mb_reconnect(host, port):
    time.sleep(1.5)
    s = mb_connect(host, port)
    if s is None:
        time.sleep(2.0)
        s = mb_connect(host, port)
    return s


# ═══════════════════════════════════════════════════════════
# Bekannte Register — fest verdrahteter Fallback + kuratierte Skalen
# (wird durch die Register-Map-CSV ergänzt/überschrieben, s. u.)
# ═══════════════════════════════════════════════════════════

KNOWN = {
    30000:("device_type","",""), 30001:("battery_power","1","W"), 30006:("ac_power","1","W"),
    30020:("mppt1_voltage","0.1","V"), 30021:("mppt2_voltage","0.1","V"),
    30022:("mppt3_voltage","0.1","V"), 30023:("mppt4_voltage","0.1","V"),
    30024:("mppt1_current","0.1","A"), 30025:("mppt2_current","0.1","A"),
    30026:("mppt3_current","0.1","A"), 30027:("mppt4_current","0.1","A"),
    30037:("mppt1_power","0.1","W"), 30038:("mppt2_power","0.1","W"),
    30039:("mppt3_power","0.1","W"), 30040:("mppt4_power","0.1","W"),
    30100:("battery_voltage","0.01","V"), 30101:("battery_current","0.1","A"),
    30200:("ems_version","1",""), 30202:("vns_version","1",""), 30204:("bms_version","1",""),
    30205:("mppt_version","1",""),
    30300:("wifi_status","1",""), 30301:("bt_status","1",""),
    30302:("cloud_status","1",""), 30303:("wifi_rssi","-1","dBm"),
    30400:("device_ip_hi","ip",""), 30401:("device_ip_lo","ip",""),
    30402:("gw_ip_hi","ip",""), 30403:("gw_ip_lo","ip",""),
    32105:("bat_total_energy","0.001","kWh"),
    32200:("ac_voltage","0.1","V"), 32204:("ac_frequency","0.1","Hz"),
    32300:("offgrid_voltage","0.1","V"), 32301:("offgrid_current","0.01","A"),
    33000:("total_chg_hi","u32",""), 33001:("total_chg_lo","u32×0.01","kWh"),
    33002:("total_dsg_hi","u32",""), 33003:("total_dsg_lo","u32×0.01","kWh"),
    33004:("daily_chg_hi","u32",""), 33005:("daily_chg_lo","u32×0.01","kWh"),
    33006:("daily_dsg_hi","u32",""), 33007:("daily_dsg_lo","u32×0.01","kWh"),
    33008:("month_chg_hi","u32",""), 33009:("month_chg_lo","u32×0.01","kWh"),
    33010:("month_dsg_hi","u32",""), 33011:("month_dsg_lo","u32×0.01","kWh"),
    35000:("env_temp","0.1","°C"), 35001:("radiator_temp1","0.1","°C"),
    35002:("radiator_temp2","0.1","°C"), 35010:("max_cell_temp","0.1","°C"),
    35100:("inverter_state","1",""),
    36000:("alarm_hi","hex",""), 36001:("alarm_lo","hex",""),
    36100:("fault_0","hex",""), 36101:("fault_1","hex",""),
    36102:("fault_2","hex",""), 36103:("fault_3","hex",""),
    37004:("ac_current","0.01","A"),
    37007:("max_cell_v","0.001","V"), 37008:("min_cell_v","0.001","V"),
    42000:("rs485_unlock","hex",""), 42010:("force_mode","1",""),
    42011:("charge_to_soc","1","%"),
    42020:("set_chg_power","1","W"), 42021:("set_dsg_power","1","W"),
    43000:("work_mode","1",""), 44002:("max_chg_pwr","1","W"), 44003:("max_dsg_pwr","1","W"),
}
# BMS Packs 1-7  (Offset relativ zu 34000 + pack*100)
#   +4 charge_status (0=idle, 3=aktiv), +5 max_cell_v, +6 min_cell_v
_BMS = {0:("bat_volt","0.01","V"),1:("bat_curr","0.1","A"),2:("bat_soc","0.1","%"),
        3:("cycle_cnt","1",""),4:("charge_status","1",""),
        5:("max_cell_v","0.001","V"),6:("min_cell_v","0.001","V"),
        7:("max_ntc","0.1","°C"),8:("protect1","hex",""),9:("protect2","hex",""),
        10:("bms_ver","1",""),11:("ntc0","0.1","°C"),12:("ntc1","0.1","°C"),
        13:("ntc2","0.1","°C"),14:("ntc3","0.1","°C"),
        15:("mos_ntc","0.1","°C"),16:("env_ntc","0.1","°C"),17:("avg_ntc","0.1","°C")}
for i in range(16): _BMS[18+i] = (f"cell{i+1}","0.001","V")
for p in range(7):
    for o,(n,s,u) in _BMS.items(): KNOWN[34000+p*100+o] = (f"p{p+1}_{n}",s,u)
for s in range(6):
    b = 43100+s*5
    KNOWN.update({b:(f"sched{s+1}_days","hex",""),b+1:(f"sched{s+1}_start","HHMM",""),
                  b+2:(f"sched{s+1}_end","HHMM",""),b+3:(f"sched{s+1}_mode","1","W"),
                  b+4:(f"sched{s+1}_en","1","")})


# ═══════════════════════════════════════════════════════════
# Register-Map-CSV laden (vollständige Namen + Konfidenz-Tier)
# ═══════════════════════════════════════════════════════════

# reg -> {"name","tier","scale","unit","type"}  (tier: OK | VERM | UNB)
REGINFO = {}

# Spalten-Aliase: all_register.csv (kanonisch) zuerst, dann Alt-Schema
REGMAP_NAMES = (
    "Marstek_Venus_D_Register_Map_Final_all_register.csv",
    "Marstek_Venus_D_Register_Map_v150_annotiert.csv",
)
_COLS = {
    "reg":   ("register", "Register"),
    "name":  ("name", "Key"),
    "conf":  ("konfidenz", "confidence", "Confidence"),
    "unit":  ("einheit", "unit", "Unit"),
    "type":  ("typ", "type", "Type"),
    "scale": ("anzeige_faktor", "scale", "Scale"),
}

def _col(row, field):
    """Holt ein Feld ueber die Spalten-Aliase, unabhaengig vom Map-Schema."""
    for key in _COLS[field]:
        val = row.get(key)
        if val:
            return val.strip()
    return ""

def _classify(conf, key):
    c = (conf or "").lower().strip()
    k = (key or "").strip()
    if (not k) or k.startswith("unknown_") or "❓" in c or "🆕" in c or "unbek" in c or "unknown" in c:
        return "UNB"
    # Konfidenz-Stufen der all_register.csv (kanonische Map)
    if c in ("hoch", "write-handler"):
        return "OK"
    if c in ("mittel", "hypothese"):
        return "VERM"
    if c == "niedrig":
        return "UNB"
    if "✅" in c or "pack-pattern" in c or "multi-scan" in c or "confirmed" in c or "verified" in c \
       or "test" in c or "ota" in c:
        return "OK"
    if "🔍" in c or c.startswith("verm") or "vermut" in c or "📊" in c or "scan" in c:
        return "VERM"
    return "VERM" if k else "UNB"

def find_regmap(explicit=None):
    cands = []
    if explicit: cands.append(explicit)
    here = os.path.dirname(os.path.abspath(__file__))
    for name in REGMAP_NAMES:
        cands += [
            os.path.join(here, name),
            os.path.join(here, "..", "Modbus_RS485_TCP", name),
            os.path.join(os.getcwd(), name),
            os.path.join(os.getcwd(), "Modbus_RS485_TCP", name),
        ]
    for c in cands:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return None

def load_regmap(path):
    """Laedt die Register-Map. Versteht beide Spalten-Schemata:
    all_register.csv (kanonisch, deutsch) und das Alt-Schema (englisch)."""
    n = 0
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        rd = csv.DictReader(f)
        for row in rd:
            reg = _col(row, "reg")
            if not reg.isdigit():
                continue
            reg = int(reg)
            name = _col(row, "name")
            REGINFO[reg] = {
                "name":  name,
                "tier":  _classify(_col(row, "conf"), name),
                "scale": _col(row, "scale"),
                "unit":  _col(row, "unit"),
                "type":  _col(row, "type"),
            }
            n += 1
    return n


# ═══════════════════════════════════════════════════════════
# Interpretation & Voll-Dekodierung
# ═══════════════════════════════════════════════════════════

def parse_regs(spec):
    regs = set()
    for part in spec.split(","):
        part = part.strip()
        if not part: continue
        if "-" in part:
            a, b = part.split("-", 1)
            regs.update(range(int(a), int(b)+1))
        else:
            regs.add(int(part))
    return sorted(regs)


def load_file(path):
    regs = set()
    with open(path) as f:
        for line in f:
            line = line.split("#")[0].strip()
            if line: regs.update(parse_regs(line))
    return sorted(regs)


def _fmt(val, unit):
    if val == int(val): return f"{int(val)} {unit}".strip()
    return f"{val:.3f} {unit}".strip()


def interpret_known(reg, raw):
    """Kuratierte Interpretation aus dem KNOWN-Dict (bevorzugt)."""
    info = KNOWN.get(reg)
    if not info: return None
    _, scale, unit = info
    signed = raw - 65536 if raw >= 32768 else raw
    try:
        if scale == "ip":   return f"{(raw>>8)&0xFF}.{raw&0xFF}"
        if scale == "hex":  return f"0x{raw:04X}"
        if scale == "HHMM": return f"{raw//100:02d}:{raw%100:02d}"
        if scale in ("u32","u32×0.01",""): return ""
        if scale == "-1":   return f"{-raw} {unit}"
        s = float(scale)
        val = signed * s if unit in ("W","A","°C") and signed < 0 else raw * s
        return _fmt(val, unit)
    except Exception:
        return None


def interpret_map(reg, raw):
    """Interpretation aus der Register-Map (für alle nicht-KNOWN Register)."""
    info = REGINFO.get(reg)
    if not info: return ""
    scale, unit, typ = info["scale"], info["unit"], info["type"].lower()
    if unit == "-": unit = ""
    signed = raw - 65536 if raw >= 32768 else raw
    if typ in ("char", "ascii"):
        def ch(b): return chr(b) if 32 <= b <= 126 else "·"
        return f"'{ch((raw>>8)&0xff)}{ch(raw&0xff)}'"
    if scale in ("bitmask",) or (scale == "-" and unit == "-"):
        return f"0x{raw:04X}" if "bit" in typ or scale == "bitmask" else ""
    if scale == "-1":
        return f"{-raw} {unit}".strip()
    try:
        s = float(scale)
    except Exception:
        return ""
    base = signed if typ.startswith("int") or typ in ("i16","i32") else raw
    return _fmt(base * s, unit)


def interpret(reg, raw):
    # 1) Spezialformate, die nur KNOWN ausdrückt (IP/hex/Zeit/u32) → KNOWN
    kinfo = KNOWN.get(reg)
    if kinfo and kinfo[1] in ("ip", "hex", "HHMM", "u32", "u32×0.01", ""):
        v = interpret_known(reg, raw)
        if v is not None:
            return v
    # 2) Für alles andere gewinnt die Register-Map (aktuell + vom Nutzer gepflegt) —
    #    verhindert, dass eine veraltete KNOWN-Skala eine korrigierte Map überstimmt.
    if reg in REGINFO:
        v = interpret_map(reg, raw)
        if v != "":
            return v
    # 3) Fallback: KNOWN. Bringt KNOWN eine eigene Einheit mit, die die Map
    #    nicht kennt oder anders sieht, wird sie verworfen — sonst faerbt eine
    #    veraltete KNOWN-Einheit ein korrigiertes Register ein (34x07 wurde als
    #    "0 °C" angezeigt, obwohl es laut Map protect1 ist). Einheitenlose
    #    KNOWN-Eintraege (Versionen, Zaehler) bleiben nutzbar.
    kunit = kinfo[2] if kinfo else ""
    if kunit and reg in REGINFO:
        munit = REGINFO[reg]["unit"]
        if munit in ("", "-") or munit != kunit:
            return ""
    v = interpret_known(reg, raw)
    return v if v is not None else ""


def reg_label(reg):
    """Liefert (tier, name) — tier: OK|VERM|UNB."""
    info = REGINFO.get(reg)
    if info and info["name"]:
        return info["tier"], info["name"]
    if reg in KNOWN:
        return "OK", KNOWN[reg][0]
    if info:  # in Map, aber ohne Namen
        return "UNB", "?"
    return "UNB", "?"


def tier_name(reg):
    """Name mit Tier-Präfix: bekannte plain, vermutete 'Verm:', unbekannte 'Unb:'."""
    tier, name = reg_label(reg)
    if tier == "VERM": return f"Verm: {name}"
    if tier == "UNB":  return f"Unb: {name}"
    return name


def _f32(u32):
    """u32-Bitmuster als IEEE754-float32 (oder '-' bei NaN/inf/absurd)."""
    import struct
    try:
        v = struct.unpack("<f", struct.pack("<I", u32 & 0xFFFFFFFF))[0]
    except Exception:
        return "-"
    if v != v or v in (float("inf"), float("-inf")):  # NaN/inf
        return "-"
    av = abs(v)
    if av != 0 and (av < 1e-6 or av > 1e12):          # unplausibel
        return "-"
    return f"{v:.4g}"


def decode_all(raw, nxt=None):
    """Alle plausiblen Dekodierungen eines Registerwerts (für's 'Erahnen').
    Deckt die FW-Read_Serializer-Typen ab: u8/u16/u32/i8/i16/i32/float/ASCII."""
    signed = raw - 65536 if raw >= 32768 else raw
    def ch(b): return chr(b) if 32 <= b <= 126 else "·"
    hi, lo = (raw >> 8) & 0xFF, raw & 0xFF
    ns = [(raw>>12)&0xF,(raw>>8)&0xF,(raw>>4)&0xF,raw&0xF]
    bcd = "".join(str(n) for n in ns) if all(n <= 9 for n in ns) else "-"
    d = {
        "uint16": raw,
        "int16":  signed,
        "hex":    f"0x{raw:04X}",
        "bin16":  format(raw, "016b"),
        "u8_hi":  hi,
        "u8_lo":  lo,
        "i8_hi":  hi - 256 if hi >= 128 else hi,
        "i8_lo":  lo - 256 if lo >= 128 else lo,
        "ascii_be": ch(hi)+ch(lo),
        "ascii_le": ch(lo)+ch(hi),
        "bcd":    bcd,
        "div10":  f"{raw/10:.1f}",
        "div100": f"{raw/100:.2f}",
        "div1000":f"{raw/1000:.3f}",
        # 32-bit-Kombis mit Folgeregister (be = dieses Reg = High-Word)
        "u32_next_be": "", "u32_next_le": "",
        "i32_next_be": "", "i32_next_le": "",
        "f32_next_be": "", "f32_next_le": "",
    }
    if nxt is not None:
        be = ((raw << 16) | nxt) & 0xFFFFFFFF   # dieses Reg = High-Word
        le = ((nxt << 16) | raw) & 0xFFFFFFFF   # Folgereg = High-Word
        d["u32_next_be"] = be
        d["u32_next_le"] = le
        d["i32_next_be"] = be - (1 << 32) if be >= (1 << 31) else be
        d["i32_next_le"] = le - (1 << 32) if le >= (1 << 31) else le
        d["f32_next_be"] = _f32(be)
        d["f32_next_le"] = _f32(le)
    return d


def decode_line(raw, nxt=None):
    """Kompakte Dekodier-Zeile für's Terminal (ein Register, opt. mit Folgereg)."""
    d = decode_all(raw, nxt)
    s = (f"        ├ u16 {d['uint16']} · i16 {d['int16']} · {d['hex']} · "
         f"u8 {d['u8_hi']}/{d['u8_lo']} · bcd {d['bcd']} · "
         f"asc \"{d['ascii_be']}\"/\"{d['ascii_le']}\" · "
         f"÷10 {d['div10']} ÷100 {d['div100']} ÷1000 {d['div1000']}")
    if nxt is not None:
        s += (f"\n        └ +next: u32 {d['u32_next_le']} (le)/{d['u32_next_be']} (be) · "
              f"i32 {d['i32_next_le']}/{d['i32_next_be']} · "
              f"f32 {d['f32_next_le']}/{d['f32_next_be']}")
    return s


def fmt_line(ts, reg, raw):
    ts = ts[-8:]                      # im Terminal nur HH:MM:SS zeigen
    signed = raw - 65536 if raw >= 32768 else raw
    label = tier_name(reg)
    interp = interpret(reg, raw)
    s_str = f" ({signed:6d})" if signed != raw else "        "
    n_str = f"{label:.<32s}"
    i_str = f"= {interp}" if interp else ""
    return f"  {ts}  {reg:5d}  0x{raw:04X}  {raw:6d}{s_str}  {n_str}  {i_str}"


# ═══════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════

def scan_registers(host, port, slave, registers, on_result=None, on_progress=None):
    sock = mb_connect(host, port)
    if not sock:
        print(f"FEHLER: Keine Verbindung zu {host}:{port}", flush=True)
        return {}
    results = {}
    tid = 1
    batches = []
    if registers:
        bs = be = registers[0]
        for reg in registers[1:]:
            if reg == be+1 and (reg-bs) < BATCH_SIZE:
                be = reg
            else:
                batches.append((bs, be)); bs = be = reg
        batches.append((bs, be))
    reg_set = set(registers)
    total_batches = len(batches)

    for bi, (bs, be) in enumerate(batches, 1):
        if stop_flag: break
        count = be - bs + 1
        tid = (tid % 0xFFFF) + 1
        if on_progress:
            on_progress(bi, total_batches, bs, be, len(results))
        if sock is None:
            sock = mb_reconnect(host, port)
            if sock is None: continue
        try:
            sock.sendall(build_req(tid, slave, bs, count))
            resp = recv_response(sock, timeout=3.0, expect_tid=tid)
        except Exception:
            resp = None
            try: sock.close()
            except: pass
            sock = mb_reconnect(host, port)
        vals = parse(resp, count) if resp else None
        if vals is not None:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for i, v in enumerate(vals):
                if bs+i in reg_set:
                    results[bs+i] = (v, ts)
                    if on_result: on_result(bs+i, v, ts)
            time.sleep(DELAY_S)
            continue
        for r in range(bs, be+1):
            if stop_flag: break
            if r not in reg_set: continue
            tid = (tid % 0xFFFF) + 1
            if sock is None:
                sock = mb_reconnect(host, port)
                if sock is None: break
            try:
                sock.sendall(build_req(tid, slave, r, 1))
                resp2 = recv_response(sock, timeout=1.5, expect_tid=tid)
            except Exception:
                resp2 = None
                try: sock.close()
                except: pass
                sock = mb_reconnect(host, port)
            v2 = parse(resp2, 1) if resp2 else None
            if v2 is not None:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                results[r] = (v2[0], ts)
                if on_result: on_result(r, v2[0], ts)
            time.sleep(DELAY_S / 4)
        time.sleep(DELAY_S)

    if sock:
        try: sock.close()
        except: pass
    return results


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

CSV_FIELDS = ["timestamp","Register","raw_uint16","raw_int16","hex","tier","name","interpreted",
              "bin16","u8_hi","u8_lo","i8_hi","i8_lo","ascii_be","ascii_le","bcd",
              "div10","div100","div1000",
              "u32_next_be","u32_next_le","i32_next_be","i32_next_le","f32_next_be","f32_next_le"]

DECODE_KEYS = ("bin16","u8_hi","u8_lo","i8_hi","i8_lo","ascii_be","ascii_le","bcd",
               "div10","div100","div1000",
               "u32_next_be","u32_next_le","i32_next_be","i32_next_le","f32_next_be","f32_next_le")

def main():
    p = argparse.ArgumentParser(
        description="Marstek Venus D — Register-Scanner (Raw-Socket)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=
        "Beispiele:\n"
        "  %(prog)s --host 192.168.1.100 --regs 30005\n"
        "  %(prog)s --host 192.168.1.100 --regs 30000-30040,32200\n"
        "  %(prog)s --host 192.168.1.100 --regs 34002 --watch 5\n"
        "  %(prog)s --host 192.168.1.100 --file regs.txt --out result.csv\n"
        "  %(prog)s --host 192.168.1.100 --regs 30000-49999 --decode-all --out full.csv\n")
    p.add_argument("--host", default=os.environ.get("MARSTEK_HOST"),
                   help="IP des Venus D (Default aus Env MARSTEK_HOST, falls gesetzt)")
    p.add_argument("--port", type=int, default=int(os.environ.get("MARSTEK_PORT", "502") or "502"),
                   help="Modbus-TCP-Port (Default 502 oder Env MARSTEK_PORT)")
    p.add_argument("--slave", type=int, default=int(os.environ.get("MARSTEK_SLAVE", "1") or "1"),
                   help="Modbus Slave/Unit-ID (Default 1 oder Env MARSTEK_SLAVE)")
    p.add_argument("--regs", help="30005 oder 30000-30040 oder 30000,32200,34000-34033")
    p.add_argument("--file", help="Datei mit Registern (# = Kommentar)")
    p.add_argument("--tiers", help="Register nach Konfidenz-Tier aus der Map wählen: "
                   "z.B. 'verm,unb' (vermutet+unbekannt), 'unb', 'ok'. Kombinierbar mit --regs/--file.")
    p.add_argument("--out", help="CSV speichern (mit allen Dekodier-Spalten)")
    p.add_argument("--watch", type=int, metavar="N", help="Alle N Sek wiederholen")
    p.add_argument("--unknown-only", action="store_true",
                   help="Nur vermutete + unbekannte Register (Tier != bekannt)")
    p.add_argument("--regmap", help="Pfad zur Register-Map-CSV (sonst autom. gesucht)")
    p.add_argument("--decode-all", action="store_true",
                   help="Dekodier-Zeile im Terminal für ALLE Register (statt nur Verm:/Unb:)")
    p.add_argument("--no-decode", action="store_true",
                   help="Keine Dekodier-Zeilen im Terminal")
    p.add_argument("--no-progress", action="store_true", help="Keine Fortschrittszeile auf stderr")
    p.add_argument("--delay", type=int, default=150, help="ms zwischen Requests (default 150)")
    args = p.parse_args()

    global DELAY_S
    DELAY_S = args.delay / 1000

    if not args.host:
        p.error("--host nötig (oder Umgebungsvariable MARSTEK_HOST setzen)")
    if not args.regs and not args.file and not args.tiers:
        p.error("--regs, --file oder --tiers nötig")

    # Register-Map laden
    mp = find_regmap(args.regmap)
    if mp:
        cnt = load_regmap(mp)
        print(f"Register-Map geladen: {cnt} Register aus {os.path.basename(mp)}")
    else:
        print("Hinweis: Register-Map-CSV nicht gefunden — nur fest verdrahtete "
              "KNOWN-Register werden benannt (--regmap PATH zum Nachreichen).")

    registers = []
    if args.regs: registers = parse_regs(args.regs)
    if args.file: registers = sorted(set(registers + load_file(args.file)))
    if args.tiers:
        alias = {"ok":"OK","bekannt":"OK","verm":"VERM","vermutet":"VERM",
                 "unb":"UNB","unbekannt":"UNB","unknown":"UNB"}
        want = {alias[t.strip().lower()] for t in args.tiers.split(",")
                if t.strip().lower() in alias}
        if not want:
            print(f"Unbekannte --tiers-Angabe: {args.tiers!r} (erlaubt: ok,verm,unb)"); sys.exit(1)
        if not REGINFO:
            print("--tiers braucht die Register-Map (nicht gefunden, s.o.)."); sys.exit(1)
        picked = [r for r in (set(REGINFO) | set(KNOWN)) if reg_label(r)[0] in want]
        registers = sorted(set(registers) | set(picked))
        print(f"--tiers {args.tiers}: {len(picked)} Register aus der Map gewählt.")
    if not registers:
        print("Keine Register!"); sys.exit(1)

    # Zähl-Übersicht der Tiers im gewählten Bereich
    tiers = {"OK":0,"VERM":0,"UNB":0}
    for r in registers:
        tiers[reg_label(r)[0]] += 1

    print(f"\nMarstek Venus D — Register-Scanner")
    print(f"{'='*72}")
    print(f"Host:      {args.host}:{args.port}  Slave={args.slave}")
    print(f"Register:  {len(registers)} Stück ({registers[0]}–{registers[-1]})")
    print(f"Tiers:     bekannt={tiers['OK']}  Verm={tiers['VERM']}  Unb={tiers['UNB']}")
    if args.watch: print(f"Watch:     alle {args.watch}s")
    print(f"{'='*72}\n", flush=True)

    def on_progress(bi, total, bs, be, found):
        if args.no_progress: return
        print(f"\r    Batch {bi:>4d}/{total}  @ {bs}-{be}   gefunden={found}   ",
              end="", file=sys.stderr, flush=True)

    iteration = 0
    try:
        while True:
            iteration += 1
            if args.watch and iteration > 1:
                print(f"{'─'*72}", flush=True)
            elif args.watch:
                print(f"── Durchlauf {iteration} ── {datetime.now().strftime('%H:%M:%S')} "
                      f"{'─'*36}", flush=True)

            def on_result(reg, raw, ts):
                tier = reg_label(reg)[0]
                if args.unknown_only and tier == "OK":
                    return
                print(fmt_line(ts, reg, raw), flush=True)
                if not args.no_decode and (args.decode_all or tier in ("VERM","UNB")):
                    print(decode_line(raw), flush=True)

            results = scan_registers(args.host, args.port, args.slave, registers,
                                     on_result=on_result, on_progress=on_progress)
            if not args.no_progress:
                print("", file=sys.stderr, flush=True)

            csv_rows = []
            for reg in registers:
                if reg not in results: continue
                raw, ts = results[reg]
                tier = reg_label(reg)[0]
                if args.unknown_only and tier == "OK": continue
                signed = raw - 65536 if raw >= 32768 else raw
                nxt = results.get(reg+1, (None,))[0]
                dec = decode_all(raw, nxt)
                row = {
                    "timestamp": ts, "Register": reg, "raw_uint16": raw,
                    "raw_int16": signed, "hex": f"0x{raw:04X}",
                    "tier": tier, "name": tier_name(reg), "interpreted": interpret(reg, raw),
                }
                row.update({k: dec[k] for k in DECODE_KEYS})
                csv_rows.append(row)

            nr = len(registers) - len(results)
            last_ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n  Gefunden: {len(results)}/{len(registers)}  |"
                  f"  Keine Antwort: {nr}  |  fertig {last_ts}", flush=True)

            if args.out and csv_rows:
                # Immer anhaengen: ein Neustart des Watchers darf ein laufendes
                # Log nicht ueberschreiben. Header nur bei neuer/leerer Datei.
                fresh = (not os.path.exists(args.out)) or os.path.getsize(args.out) == 0
                with open(args.out, "a", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=CSV_FIELDS)
                    if fresh: w.writeheader()
                    w.writerows(csv_rows)
                if iteration == 1:
                    print(f"  CSV: {args.out} ({'neu' if fresh else 'angehaengt'})", flush=True)

            if not args.watch or stop_flag: break
            time.sleep(args.watch)

    except KeyboardInterrupt:
        print(f"\nAbgebrochen nach {iteration} Durchläufen", flush=True)


if __name__ == "__main__":
    main()
