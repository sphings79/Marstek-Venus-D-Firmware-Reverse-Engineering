#!/usr/bin/env python3
"""
Marstek Venus Continuous Scanner v1
Liest bekannte Register in Dauerschleife mit einstellbarem Intervall.
CSV-Format: Register als Zeilen, jeder Scan-Durchlauf als neue Spalte.

Aufruf:
  python3 scan_continuous.py --host 192.168.1.100 --interval 10
  python3 scan_continuous.py --host 192.168.1.100 --interval 30 --out monitor.csv
  python3 scan_continuous.py --host 192.168.1.100 --interval 5 --regmap map.csv

Ctrl+C speichert die CSV und beendet.
"""

import socket, struct, csv, time, sys, argparse, signal, select
from datetime import datetime, timedelta

BATCH_SIZE = 32
DELAY_S    = 0.05  # schnelleres Polling innerhalb eines Durchlaufs
DEFAULT_MAP = "Marstek_Venus_D_Register_Map_Final_claude_generated.csv"

stop_flag = False

def sigint_handler(sig, frame):
    global stop_flag
    print("\n\n  Ctrl+C - speichere CSV und beende...")
    stop_flag = True

signal.signal(signal.SIGINT, sigint_handler)


def load_register_list(csv_path):
    regs = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            regs.append(int(row["Register"]))
    regs.sort()
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


def recv_response(sock, timeout=3.0):
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
        if len(resp) >= 6:
            length_field = struct.unpack(">H", resp[4:6])[0]
            total_expected = 6 + length_field
            if len(resp) >= total_expected:
                return resp[:total_expected]


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


def tcp_connect(host, port, timeout=5.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(None)
        return s
    except Exception as e:
        print(f"    Connect failed: {e}")
        return None


def reconnect(host, port):
    time.sleep(1.0)
    s = tcp_connect(host, port)
    if s is None:
        time.sleep(2.0)
        s = tcp_connect(host, port)
    return s


def do_one_scan(sock, host, port, slave, known_regs, batches):
    """Ein kompletter Durchlauf aller Register. Gibt (found_dict, sock) zurueck."""
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
                resp = recv_response(sock, timeout=2.0)
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
                # Einzel-Fallback fuer diesen Block
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
                        resp2 = recv_response(sock, timeout=1.0)
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
    """Schreibt CSV: Zeile pro Register, Spalte pro Scan-Zeitpunkt."""
    with open(output, "w", newline="") as f:
        w = csv.writer(f)
        # Header
        w.writerow(["Register"] + timestamps)
        # Daten
        for reg in known_regs:
            row = [reg]
            for scan in all_scans:
                row.append(scan.get(reg, ""))
            w.writerow(row)

    print(f"  CSV gespeichert: {output} ({len(all_scans)} Scans, {len(known_regs)} Register)")


def main():
    global stop_flag

    p = argparse.ArgumentParser(
        description="Kontinuierlicher Scanner — liest bekannte Register in Dauerschleife")
    p.add_argument("--host",     required=True)
    p.add_argument("--port",     default=502, type=int)
    p.add_argument("--slave",    default=1,   type=int)
    p.add_argument("--regmap",   default=DEFAULT_MAP,
                   help=f"Register-Map CSV (default: {DEFAULT_MAP})")
    p.add_argument("--out",      default="continuous_scan.csv")
    p.add_argument("--interval", default=10, type=int,
                   help="Sekunden zwischen Scan-Durchlaeufen (default: 10)")
    a = p.parse_args()

    known_regs, batches = load_register_list(a.regmap)
    total_batches = sum((e - s) // BATCH_SIZE + 1 for s, e in batches)
    scan_duration_est = total_batches * DELAY_S

    print(f"\n{'='*60}")
    print(f"Marstek Venus Continuous Scanner v1")
    print(f"Host:      {a.host}:{a.port}  Slave={a.slave}")
    print(f"Register:  {len(known_regs)} in {len(batches)} Gruppen")
    print(f"Intervall: {a.interval}s (Scan selbst ~{scan_duration_est:.1f}s)")
    print(f"Ausgabe:   {a.out}")
    print(f"Start:     {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}")
    print(f"  Ctrl+C zum Beenden (CSV wird gespeichert)\n")

    if a.interval < scan_duration_est:
        print(f"  WARNUNG: Intervall ({a.interval}s) < Scan-Dauer (~{scan_duration_est:.0f}s)")
        print(f"           Scans laufen direkt hintereinander.\n")

    sock = tcp_connect(a.host, a.port)
    if sock is None:
        print("Keine Verbindung!")
        sys.exit(1)
    print(f"  Verbunden.\n")

    all_scans = []
    timestamps = []
    scan_nr = 0
    t_start = time.time()

    while not stop_flag:
        scan_nr += 1
        ts = datetime.now().strftime("%H:%M:%S")
        t_scan_start = time.time()

        found, sock = do_one_scan(sock, a.host, a.port, a.slave, known_regs, batches)
        scan_dur = time.time() - t_scan_start

        all_scans.append(found)
        timestamps.append(ts)

        # Alle 5 Scans oder bei Ctrl+C speichern
        if scan_nr % 5 == 0 or stop_flag:
            save_csv(a.out, known_regs, all_scans, timestamps)

        elapsed = timedelta(seconds=int(time.time() - t_start))
        print(f"  Scan #{scan_nr:4d} @ {ts}  |  {len(found)}/{len(known_regs)} Register  |  "
              f"{scan_dur:.1f}s  |  Laufzeit {elapsed}")

        if stop_flag:
            break

        # Warten bis naechstes Intervall
        wait = max(0, a.interval - scan_dur)
        if wait > 0:
            # Warten in kleinen Schritten damit Ctrl+C reagiert
            wait_end = time.time() + wait
            while time.time() < wait_end and not stop_flag:
                time.sleep(min(0.5, wait_end - time.time()))

    # Finale CSV
    save_csv(a.out, known_regs, all_scans, timestamps)

    try:
        if sock: sock.close()
    except:
        pass

    print(f"\n{'='*60}")
    print(f"Beendet nach {scan_nr} Scans")
    print(f"Laufzeit: {timedelta(seconds=int(time.time() - t_start))}")
    print(f"CSV:      {a.out}")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
