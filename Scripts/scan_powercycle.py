#!/usr/bin/env python3
"""
Marstek Venus Event Scanner
Fokus: Unbekannte und bisher-immer-0 Register bei Zustandswechseln aufdecken.
Keine bekannten Zellspannungen/Temps/Energiezaehler — nur das Unbekannte.

Einsatz:
  - Power-Cycle (Neustart)
  - Batterie vom WR trennen (DC-Schalter)
  - Offgrid/Notstrom aktivieren
  - Force-Mode Wechsel
  - Alles wo sich unbekannte Register aendern koennten

Aufruf:
  python3 scan_powercycle.py --host 192.168.1.100
  python3 scan_powercycle.py --host 192.168.1.100 --interval 2 --out event_scan.csv

Ablauf:
  1. Script starten (scannt sofort in Dauerschleife)
  2. Aktion ausfuehren (Neustart, Batterie trennen, etc.)
  3. Script faengt Zustandswechsel auf
  4. Ctrl+C zum Beenden (CSV wird gespeichert)
"""

import socket, struct, csv, time, sys, argparse, signal, select
from datetime import datetime, timedelta

REGISTERS = [
    # === UNBEKANNTE REGISTER (❓) ===

    # Inverter-Block
    30005,   # backup_voltage (0.1V) — 0 ohne Backup, ~242V mit Backup
    30007,   # backup_power (W) — Backup-Ausgangsleistung, 0 ohne Backup
    30010,   # unknown, immer 0

    # Zwischen MPPT und Leistung
    30030,   # unknown, immer 0
    30031,   # unknown, immer 0
    30032,   # unknown, immer 0
    30033,   # unknown, immer 0
    30034,   # unknown, immer 0
    30035,   # unknown, immer 0

    # Spiegel-Block Luecken
    30101,   # pack1_current_mirror (=34001 wenn Pack1 aktiv)
    30106,   # unknown, immer 0
    30109,   # unknown, immer 0
    30110,   # unknown, immer 0

    # Config-Block
    30211,   # unknown, immer 0
    30212,   # 2 (neue FW) vs 5 (alte FW) — config/pack count?
    30213,   # unknown, immer 0
    30214,   # unknown, immer 0

    # Device-Info Luecken
    31003,   # 0 (neue FW) vs 5 (alte FW) — pack count?
    31004,   # 0 (neue FW) vs 1543 (alte FW)
    31005,   # unknown, immer 0
    31006,   # unknown, immer 0
    31007,   # unknown, immer 0
    31008,   # unknown, immer 0
    31009,   # unknown, immer 0

    # Pack 1-4: immer-0 Register (max_ntc, protection, avg_ntc)
    34007,   # pack1_max_ntc — immer 0, sollte aber Temp haben?
    34008,   # pack1_protect1
    34009,   # pack1_protect2
    34017,   # pack1_avg_ntc — immer 0
    34107,   # pack2_max_ntc
    34108,   # pack2_protect1
    34109,   # pack2_protect2
    34117,   # pack2_avg_ntc
    34207,   # pack3_max_ntc
    34208,   # pack3_protect1
    34209,   # pack3_protect2
    34217,   # pack3_avg_ntc
    34307,   # pack4_max_ntc
    34308,   # pack4_protect1
    34309,   # pack4_protect2
    34317,   # pack4_avg_ntc

    # Pack 5/6/7: nur Status-Register (Zellspannungen weglassen)
    34400,   # pack5_voltage
    34401,   # pack5_current
    34402,   # pack5_soc
    34404,   # pack5_charge_status
    34408,   # pack5_protect1
    34410,   # pack5_bms_version
    34500,   # pack6_voltage
    34501,   # pack6_current
    34502,   # pack6_soc
    34504,   # pack6_charge_status
    34508,   # pack6_protect1
    34510,   # pack6_bms_version
    34600,   # pack7_voltage
    34601,   # pack7_current
    34602,   # pack7_soc
    34604,   # pack7_charge_status
    34608,   # pack7_protect1
    34610,   # pack7_bms_version

    # Alarm/Fault
    36000,   # alarm_status hi
    36001,   # alarm_status lo
    36100,   # fault_status hi — immer 0
    36101,   # fault_status — immer 0
    36102,   # fault_status — immer 0
    36103,   # fault_status lo — hat Werte, aendert sich

    # 37xxx Unbekannte
    37001,   # unknown, immer 0
    37002,   # unknown, immer 0
    37003,   # unknown, immer 0
    37009,   # unknown, immer 0
    37010,   # unknown, immer 0
    37011,   # unknown, immer 0
    37013,   # fault_status_mirror (=36100), Vermutung
    37014,   # fault_status_2_mirror (=36101), Vermutung
    37015,   # unknown, immer 0
    37017,   # unknown, immer 0
    37018,   # unknown, immer 0
    37019,   # unknown, immer 0
    37020,   # unknown, immer 0
    37021,   # unknown, immer 0
    37023,   # unknown, immer 0
    37024,   # unknown, immer 0

    # Control
    42011,   # charge_to_soc — immer 0
    44002,   # max_charge_power — immer 0
    44003,   # max_discharge_power — immer 0

    # === REFERENZ-REGISTER (fuer Kontext/Timing) ===
    30001,   # battery_power
    30006,   # ac_power (Inverter AC-Ausgang)
    30301,   # active_inverter_state (wechselt 1/2/3 bei Backup)
    35100,   # inverter_state
    35111,   # power_level
    37000,   # system_online
    37005,   # system_soc
    42010,   # force_mode
    42021,   # set_discharge_power / Inverter-Limit
]

BATCH_SIZE = 32
DELAY_S    = 0.03

stop_flag = False

def sigint_handler(sig, frame):
    global stop_flag
    print("\n\n  Ctrl+C - speichere CSV und beende...")
    stop_flag = True

signal.signal(signal.SIGINT, sigint_handler)


def make_batches(regs):
    regs = sorted(set(regs))
    batches = []
    start = regs[0]
    prev = regs[0]
    for r in regs[1:]:
        if r - prev > BATCH_SIZE:
            batches.append((start, prev))
            start = r
        prev = r
    batches.append((start, prev))
    return regs, batches


def build_req(tid, slave, reg, count):
    pdu  = struct.pack(">BBHH", slave, 0x03, reg, count)
    mbap = struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu))
    return mbap + pdu


def recv_response(sock, timeout=2.0, expect_tid=None):
    """Liest eine MBAP-Antwort vom Socket.

    Mit expect_tid werden Frames mit fremder Transaction-ID verworfen und es
    wird weitergelesen. Ohne diese Pruefung landet eine verspaetete Antwort
    (nach einem Timeout, oder von einem anderen Client am selben Proxy) beim
    naechsten Request -- dann stehen Werte auf dem falschen Register.

    Belegter Fall 2026-08-22: Register 38003 zeigte dreimal den Wert 118.
    Das war die BMS-Version aus Register 37012, die durch genau diese
    Verschiebung im falschen Slot landete. Siehe
    Methodik_und_Meta/Analyse_Skripte.md.
    """
    resp = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        ready = select.select([sock], [], [], min(remaining, 0.5))
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


def parse(data):
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
    return list(struct.unpack(f">{n}H", data[9:9 + byte_count]))


def tcp_connect(host, port, timeout=3.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(None)
        return s
    except:
        return None


def reconnect(host, port):
    time.sleep(0.5)
    s = tcp_connect(host, port)
    if s is None:
        time.sleep(1.0)
        s = tcp_connect(host, port)
    return s


def do_one_scan(sock, host, port, slave, known_regs, batches):
    found = {}
    tid = int(time.time()) & 0xFFFF
    known_set = set(known_regs)

    for group_start, group_end in batches:
        if stop_flag:
            break
        reg = group_start
        while reg <= group_end and not stop_flag:
            count = min(BATCH_SIZE, group_end - reg + 1)
            tid = (tid % 0xFFFF) + 1

            if sock is None:
                sock = reconnect(host, port)
                if sock is None:
                    reg += count
                    continue

            try:
                sock.sendall(build_req(tid, slave, reg, count))
                resp = recv_response(sock, timeout=2.0, expect_tid=tid)
            except Exception:
                resp = None
                try: sock.close()
                except: pass
                sock = reconnect(host, port)

            vals = parse(resp) if resp else None

            if vals is not None:
                for i, v in enumerate(vals):
                    if (reg + i) in known_set:
                        found[reg + i] = v
            else:
                # Batch fehlgeschlagen → Einzel-Fallback fuer unsere Register
                for r in range(reg, reg + count):
                    if stop_flag or r not in known_set:
                        continue
                    tid = (tid % 0xFFFF) + 1
                    if sock is None:
                        sock = reconnect(host, port)
                        if sock is None:
                            break
                    try:
                        sock.sendall(build_req(tid, slave, r, 1))
                        resp2 = recv_response(sock, timeout=1.0, expect_tid=tid)
                    except Exception:
                        resp2 = None
                        try: sock.close()
                        except: pass
                        sock = reconnect(host, port)
                    v2 = parse(resp2) if resp2 else None
                    if v2 is not None:
                        found[r] = v2[0]
                    time.sleep(DELAY_S / 2)

            reg += count
            time.sleep(DELAY_S)

    return found, sock


def save_csv(output, known_regs, all_scans, timestamps):
    with open(output, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Register"] + timestamps)
        for reg in known_regs:
            row = [reg]
            for scan in all_scans:
                row.append(scan.get(reg, ""))
            w.writerow(row)
    print(f"  CSV: {output} ({len(all_scans)} Scans, {len(known_regs)} Register)")


def main():
    global stop_flag

    p = argparse.ArgumentParser(
        description="Event Scanner — unbekannte Register bei Zustandswechseln aufdecken")
    p.add_argument("--host",     required=True)
    p.add_argument("--port",     default=502, type=int)
    p.add_argument("--slave",    default=1,   type=int)
    p.add_argument("--out",      default="powercycle_scan.csv")
    p.add_argument("--interval", default=3, type=int,
                   help="Sekunden zwischen Scans (default: 3)")
    a = p.parse_args()

    known_regs, batches = make_batches(REGISTERS)
    total_batches = sum((e - s) // BATCH_SIZE + 1 for s, e in batches)
    scan_est = total_batches * DELAY_S

    print(f"\n{'='*60}")
    print(f"Marstek Venus Event Scanner")
    print(f"Fokus: {len(known_regs)} unbekannte/immer-0 Register (mit Einzel-Fallback)")
    print(f"Host:      {a.host}:{a.port}  Slave={a.slave}")
    print(f"Batches:   {len(batches)}  Scan-Zeit: ~{scan_est:.1f}s")
    print(f"Intervall: {a.interval}s")
    print(f"Ausgabe:   {a.out}")
    print(f"{'='*60}")
    print(f"  1. Script laeuft → scannt sofort")
    print(f"  2. Aktion ausfuehren (Neustart, Batterie trennen, etc.)")
    print(f"  3. Script faengt Zustandswechsel auf")
    print(f"  4. Ctrl+C zum Beenden\n")

    sock = tcp_connect(a.host, a.port)
    if sock is None:
        print("  Keine Verbindung — warte auf Geraet...")
        while sock is None and not stop_flag:
            time.sleep(1)
            sock = tcp_connect(a.host, a.port)
    if stop_flag:
        return
    print(f"  Verbunden.\n")

    all_scans = []
    timestamps = []
    scan_nr = 0
    t_start = time.time()
    last_connected = True
    prev_nonzero = set()

    while not stop_flag:
        scan_nr += 1
        ts = datetime.now().strftime("%H:%M:%S")
        t0 = time.time()

        found, sock = do_one_scan(sock, a.host, a.port, a.slave, known_regs, batches)
        dur = time.time() - t0

        all_scans.append(found)
        timestamps.append(ts)

        connected = len(found) > 0
        if connected and not last_connected:
            print(f"  *** GERAET WIEDER ONLINE @ {ts} ***")
        elif not connected and last_connected:
            print(f"  *** VERBINDUNG VERLOREN @ {ts} ***")
        last_connected = connected

        # Nicht-Null Register tracken — NEU aufgetauchte hervorheben
        cur_nonzero = {r for r, v in found.items() if v != 0}
        new_nonzero = cur_nonzero - prev_nonzero
        lost_nonzero = prev_nonzero - cur_nonzero

        state = found.get(35100, "?")
        soc = found.get(37005, "?")

        status = f"  #{scan_nr:4d} {ts}  {len(found):>2}/{len(known_regs)} reg  " \
                 f"{dur:.1f}s  state={state} SOC={soc}%  " \
                 f"non-zero={len(cur_nonzero)}"

        if new_nonzero:
            status += f"  !! NEU: {sorted(new_nonzero)}"
        if lost_nonzero and scan_nr > 1:
            status += f"  -- WEG: {sorted(lost_nonzero)}"

        print(status)

        prev_nonzero = cur_nonzero

        if scan_nr % 5 == 0 or stop_flag:
            save_csv(a.out, known_regs, all_scans, timestamps)

        if stop_flag:
            break

        wait = max(0, a.interval - dur)
        if wait > 0:
            wait_end = time.time() + wait
            while time.time() < wait_end and not stop_flag:
                time.sleep(min(0.3, wait_end - time.time()))

    save_csv(a.out, known_regs, all_scans, timestamps)

    try:
        if sock: sock.close()
    except: pass

    # Zusammenfassung: welche Register waren irgendwann != 0?
    ever_nonzero = {}
    for scan in all_scans:
        for r, v in scan.items():
            if v != 0:
                if r not in ever_nonzero:
                    ever_nonzero[r] = set()
                ever_nonzero[r].add(v)

    print(f"\n{'='*60}")
    print(f"Beendet: {scan_nr} Scans in {timedelta(seconds=int(time.time()-t_start))}")
    print(f"\nRegister die IRGENDWANN != 0 waren:")
    for r in sorted(ever_nonzero):
        vals = sorted(ever_nonzero[r])
        preview = str(vals[:8]) + ("..." if len(vals) > 8 else "")
        print(f"  {r:>5}: {len(vals)} verschiedene Werte — {preview}")
    print(f"\nCSV: {a.out}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
