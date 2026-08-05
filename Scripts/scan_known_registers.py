#!/usr/bin/env python3
"""
Marstek Venus Scanner v8 — Targeted Scan
Liest nur die Register, die in der Register-Map CSV stehen.
~30 Batches statt ~440 Batches = ca. 30× schneller.

Aufruf:
  python3 scan_known_registers.py --host 192.168.1.100 --out full_charge_manual_2200w.csv
  python3 scan_known_registers.py --host 192.168.1.100 --out scan.csv --regmap pfad/zur/map.csv
"""

import socket, struct, csv, time, sys, argparse, signal, select
from datetime import datetime, timedelta

BATCH_SIZE = 32
DELAY_S    = 0.15
DEFAULT_MAP = "Marstek_Venus_D_Register_Map_Final_claude_generated.csv"

stop_flag = False

def sigint_handler(sig, frame):
    global stop_flag
    print("\n\n  Ctrl+C - speichere CSV und beende...")
    stop_flag = True

signal.signal(signal.SIGINT, sigint_handler)


def load_register_list(csv_path):
    """Liest alle Register-Nummern aus der Map-CSV und gruppiert sie in Batches."""
    regs = []
    with open(csv_path, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            regs.append(int(row["Register"]))
    regs.sort()

    # Zusammenhaengende Bereiche finden (Luecke > BATCH_SIZE = neuer Batch)
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
    return list(struct.unpack(f">{n}H", data[9:9 + byte_count]))


def connect(host, port, timeout=5.0):
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
    time.sleep(2.0)
    s = connect(host, port)
    if s is None:
        time.sleep(3.0)
        s = connect(host, port)
    return s


def scan(host, port, slave, regmap_path, output, delay_s):
    global stop_flag

    known_regs, batches = load_register_list(regmap_path)
    total_regs = len(known_regs)
    total_batches = sum(
        (end - start) // BATCH_SIZE + 1 for start, end in batches
    )

    print(f"\n{'='*60}")
    print(f"Marstek Venus Scanner v8 (targeted)")
    print(f"Host:     {host}:{port}  Slave={slave}")
    print(f"Register: {total_regs} bekannte Register in {len(batches)} Gruppen")
    print(f"Batches:  ~{total_batches}")
    print(f"Dauer:    ~{total_batches * delay_s:.0f}s")
    print(f"Ausgabe:  {output}")
    print(f"RegMap:   {regmap_path}")
    print(f"Start:    {datetime.now().strftime('%H:%M:%S')}")
    print(f"{'='*60}\n")

    sock = connect(host, port)
    if sock is None:
        print("Keine Verbindung!")
        sys.exit(1)
    print(f"  Verbunden: {host}:{port}")
    print(f"  Ctrl+C zum Abbrechen (CSV wird gespeichert)\n")

    found    = {}
    ok_batch = 0
    err      = 0
    tid      = 1
    t_start  = time.time()
    batch_nr = 0

    for group_start, group_end in batches:
        if stop_flag:
            break

        reg = group_start
        while reg <= group_end and not stop_flag:
            count = min(BATCH_SIZE, group_end - reg + 1)
            tid   = (tid % 0xFFFF) + 1
            batch_nr += 1

            pct = batch_nr / max(total_batches, 1) * 100
            elapsed = time.time() - t_start

            print(f"  [{pct:5.1f}%] Reg {reg:5d}-{reg+count-1:5d} ({count:2d})  |  "
                  f"gefunden={len(found):4d}  |  "
                  f"{datetime.now().strftime('%H:%M:%S')}")

            if sock is None:
                sock = reconnect(host, port)
                if sock is None:
                    err += 1
                    reg += count
                    continue

            try:
                sock.sendall(build_req(tid, slave, reg, count))
                resp = recv_response(sock, timeout=3.0)
            except Exception:
                resp = None
                try: sock.close()
                except: pass
                sock = reconnect(host, port)

            vals = parse(resp, count) if resp else None

            if vals is not None and len(vals) > 0:
                for i, v in enumerate(vals):
                    if (reg + i) in set(known_regs):
                        found[reg + i] = v
                ok_batch += 1
            else:
                # Fallback: Einzel-Reads
                for r in range(reg, reg + count):
                    if stop_flag:
                        break
                    if r not in set(known_regs):
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
                    v2 = parse(resp2, 1) if resp2 else None
                    if v2 is not None:
                        found[r] = v2[0]
                    else:
                        err += 1
                    time.sleep(delay_s / 4)

            reg += count
            time.sleep(delay_s)

    try:
        if sock: sock.close()
    except:
        pass

    # CSV speichern
    with open(output, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Register","raw_uint16","raw_int16","hex"])
        w.writeheader()
        for r in sorted(found):
            v = found[r]
            w.writerow({"Register": r, "raw_uint16": v,
                        "raw_int16": v if v < 32768 else v - 65536,
                        "hex": f"0x{v:04X}"})

    elapsed_total = time.time() - t_start
    print(f"\n{'='*60}")
    print(f"{'Abgebrochen' if stop_flag else 'Fertig'}:  "
          f"{datetime.now().strftime('%H:%M:%S')}")
    print(f"Erwartet:  {total_regs:,} Register")
    print(f"Gefunden:  {len(found):,} Register")
    missing = set(known_regs) - set(found.keys())
    if missing:
        print(f"Fehlend:   {len(missing)} Register: {sorted(missing)[:10]}...")
    print(f"Batch-OK:  {ok_batch}  Fehler: {err}")
    print(f"Dauer:     {timedelta(seconds=int(elapsed_total))}")
    print(f"CSV:       {output}")
    print(f"{'='*60}")


def main():
    p = argparse.ArgumentParser(
        description="Scannt nur Register aus der bekannten Register-Map CSV")
    p.add_argument("--host",   required=True)
    p.add_argument("--port",   default=502, type=int)
    p.add_argument("--slave",  default=1,   type=int)
    p.add_argument("--regmap", default=DEFAULT_MAP,
                   help=f"Pfad zur Register-Map CSV (default: {DEFAULT_MAP})")
    p.add_argument("--out",    default="marstek_scan.csv")
    p.add_argument("--delay",  default=150, type=int,
                   help="ms zwischen Requests (default: 150)")
    a = p.parse_args()
    scan(a.host, a.port, a.slave, a.regmap, a.out, a.delay / 1000)


if __name__ == "__main__":
    main()
