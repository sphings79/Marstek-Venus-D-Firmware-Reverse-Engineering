#!/usr/bin/env python3
"""
Marstek Venus D — CAN-Frame-Puffer 38000-38014 schnell pollen

Hintergrund
-----------
Die Register 38000-38014 spiegeln eingehende CAN-Frames 0x40-0x43
(Telemetry_Store_EnergyCounters, 0x0802FD38 -- einziger Schreiber des Blocks):

    38000-38003  Frame 0x40  -> SRAM 0x20000168  (8 Byte)
    38004-38006  Frame 0x41  -> SRAM 0x20000170  (6 Byte)
    38007-38010  Frame 0x42  -> SRAM 0x20000176  (8 Byte)
    38011-38014  Frame 0x43  -> SRAM 0x2000017E  (8 Byte)

In bisherigen Scans standen sie fast durchgehend auf 0. Einzige Ausnahme:
38003 zeigte 3x den Wert 118 (0x0076), ausschliesslich beim Entladen.
Die Frames sind also selten -- ein langsamer Vollscan verpasst sie.

Dieses Skript liest nur diese 15 Register in einem einzigen FC03-Block und
protokolliert JEDE Aenderung mit Millisekunden-Zeitstempel.

Aufruf
------
  python3 watch_can_frames_38000.py --host 192.168.1.50 --port 1502
  python3 watch_can_frames_38000.py --interval 0.5 --out entladen.csv

Ctrl+C beendet und schreibt eine Zusammenfassung.
"""

import socket, struct, csv, time, sys, argparse, signal, select
from datetime import datetime

REG_START = 38000
REG_COUNT = 15
FRAMES = [("0x40", 38000, 4), ("0x41", 38004, 3), ("0x42", 38007, 4), ("0x43", 38011, 4)]

stop_flag = False


def sigint_handler(sig, frame):
    global stop_flag
    print("\n  Ctrl+C — beende und speichere ...")
    stop_flag = True


def build_req(tid, slave, reg, count):
    pdu = struct.pack(">BBHH", slave, 0x03, reg, count)
    return struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu)) + pdu


def recv_response(sock, expect_tid, timeout=3.0):
    """Liest einen MBAP-Frame und verwirft Antworten mit fremder Transaction-ID.

    WICHTIG: Ohne diese Pruefung wird eine verspaetete Antwort auf Anfrage N
    als Antwort auf Anfrage N+1 gelesen. Genau dieser Fehler in
    scan_continuous.py / scan_known_registers.py hat 2026-08-22 den
    Phantomwert 38003=118 erzeugt -- in Wahrheit die BMS-Version aus 37012.
    """
    buf = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        if not select.select([sock], [], [], min(remaining, 1.0))[0]:
            continue
        chunk = sock.recv(512)
        if not chunk:
            return None
        buf += chunk
        while len(buf) >= 6:
            total = 6 + struct.unpack(">H", buf[4:6])[0]
            if len(buf) < total:
                break
            frame, buf = buf[:total], buf[total:]
            if struct.unpack(">H", frame[0:2])[0] == expect_tid:
                return frame
            # fremde TID -> verwerfen und weiterlesen


def parse(data):
    if not data or len(data) < 9:
        return None
    fc = data[7]
    if fc & 0x80 or fc != 0x03:
        return None
    bc = data[8]
    n = bc // 2
    if n < 1 or len(data) < 9 + bc:
        return None
    return list(struct.unpack(f">{n}H", data[9:9 + bc]))


def connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect((host, port))
    s.settimeout(None)
    return s


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.1.50")
    p.add_argument("--port", default=1502, type=int)
    p.add_argument("--slave", default=1, type=int)
    p.add_argument("--interval", default=0.25, type=float,
                   help="Sekunden zwischen zwei Lesevorgaengen (Default 0.25)")
    p.add_argument("--out", default=None, help="CSV-Datei (Default: watch_38000_<Zeit>.csv)")
    a = p.parse_args()

    out = a.out or f"watch_38000_{datetime.now():%Y%m%d_%H%M%S}.csv"
    signal.signal(signal.SIGINT, sigint_handler)

    print(f"  Ziel      : {a.host}:{a.port} Slave {a.slave}")
    print(f"  Register  : {REG_START}-{REG_START + REG_COUNT - 1} (ein FC03-Block)")
    print(f"  Intervall : {a.interval}s")
    print(f"  CSV       : {out}")
    print("  Es wird nur bei AENDERUNGEN protokolliert. Ctrl+C beendet.\n")

    rows = []
    prev = None
    tid = 0
    reads = 0
    errors = 0
    hits = 0
    t0 = time.time()
    sock = None

    while not stop_flag:
        try:
            if sock is None:
                sock = connect(a.host, a.port)
                print(f"  [{datetime.now():%H:%M:%S}] verbunden")

            tid += 1
            sock.sendall(build_req(tid, a.slave, REG_START, REG_COUNT))
            vals = parse(recv_response(sock, tid))
            reads += 1

            if vals is None or len(vals) != REG_COUNT:
                errors += 1
                try:
                    sock.close()
                except Exception:
                    pass
                sock = None
                time.sleep(1.0)
                continue

            if vals != prev:
                ts = datetime.now()
                nonzero = [(REG_START + i, v) for i, v in enumerate(vals) if v]
                if nonzero:
                    hits += 1
                row = {"timestamp": ts.strftime("%H:%M:%S.%f")[:-3]}
                for i, v in enumerate(vals):
                    row[str(REG_START + i)] = v
                row["nonzero"] = " ".join(f"{r}=0x{v:04X}({v})" for r, v in nonzero)
                rows.append(row)

                marker = "  <<< TREFFER" if nonzero else "  (zurueck auf 0)"
                print(f"  [{row['timestamp']}] {row['nonzero'] or 'alle 0'}{marker}")
                prev = list(vals)

            time.sleep(a.interval)

        except Exception as e:
            errors += 1
            print(f"  [{datetime.now():%H:%M:%S}] Fehler: {e}")
            try:
                if sock:
                    sock.close()
            except Exception:
                pass
            sock = None
            time.sleep(1.0)

    if sock:
        try:
            sock.close()
        except Exception:
            pass

    cols = ["timestamp"] + [str(REG_START + i) for i in range(REG_COUNT)] + ["nonzero"]
    with open(out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    dur = time.time() - t0
    print(f"\n  Dauer         : {dur/60:.1f} min")
    print(f"  Lesevorgaenge : {reads}   Fehler: {errors}")
    print(f"  Aenderungen   : {len(rows)}   davon mit Wert != 0: {hits}")
    if hits:
        print("\n  Frames mit Treffern:")
        for name, start, cnt in FRAMES:
            regs = [str(start + i) for i in range(cnt)]
            seen = {}
            for r in rows:
                for g in regs:
                    v = int(r[g])
                    if v:
                        seen.setdefault(g, set()).add(v)
            if seen:
                print(f"    Frame {name}: " + ", ".join(
                    f"{g}={sorted(v)}" for g, v in sorted(seen.items())))
    else:
        print("  Kein Frame beobachtet.")
    print(f"\n  CSV: {out}")


if __name__ == "__main__":
    main()
