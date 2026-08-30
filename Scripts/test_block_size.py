#!/usr/bin/env python3
"""
Wie grosse FC03-Bloecke verkraftet der Marstek?

Hintergrund: Die Home-Assistant-Integration gruppiert lueckenlose Register zu
Bloecken (Limit 125). Im Bestand von 1.1.0 wurde nie mehr als 30 am Stueck
gelesen. Die DEV-Register wuerden erstmals einen 44er-Block erzeugen
(46501-46544). Die Scan-Skripte nutzen aus Vorsicht BATCH_SIZE = 32.

Dieses Skript liest denselben Bereich in wachsenden Blockgroessen und prueft
nach jedem Versuch mit einem Liveness-Read, ob die Verbindung noch steht.

Aufruf
------
  python3 test_block_size.py
  python3 test_block_size.py --start 46501 --max 44 --runs 3
"""

import socket, struct, time, sys, argparse, select
from datetime import datetime


def build_req(tid, slave, reg, count):
    pdu = struct.pack(">BBHH", slave, 0x03, reg, count)
    return struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu)) + pdu


def recv_frame(sock, expect_tid, timeout):
    buf = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        if not select.select([sock], [], [], min(remaining, 0.5))[0]:
            continue
        chunk = sock.recv(1024)
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


def read_block(sock, tid, slave, reg, count, timeout):
    t0 = time.time()
    sock.sendall(build_req(tid, slave, reg, count))
    f = recv_frame(sock, tid, timeout)
    dt = time.time() - t0
    if f is None:
        return "TIMEOUT", None, dt
    if len(f) < 9:
        return "SHORT", None, dt
    if f[7] & 0x80:
        return f"EXC-{f[8]}", None, dt
    bc = f[8]
    if len(f) < 9 + bc:
        return "SHORT", None, dt
    return "OK", list(struct.unpack(f">{bc//2}H", f[9:9 + bc])), dt


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
    p.add_argument("--start", default=46501, type=int)
    p.add_argument("--max", dest="mx", default=44, type=int)
    p.add_argument("--live-reg", default=37012, type=int)
    p.add_argument("--runs", default=3, type=int, help="Wiederholungen je Groesse")
    p.add_argument("--timeout", default=10.0, type=float)
    a = p.parse_args()

    sizes = [n for n in (8, 16, 24, 30, 32, 36, 40, a.mx) if n <= a.mx]
    sizes = sorted(set(sizes))

    print(f"  Ziel      : {a.host}:{a.port}")
    print(f"  Bereich   : ab Register {a.start}")
    print(f"  Groessen  : {sizes}, je {a.runs} Durchgaenge")
    print(f"  Liveness  : Register {a.live_reg} nach jedem Versuch\n")

    sock = connect(a.host, a.port)
    tid = 0
    results = {}

    for n in sizes:
        ok = fail = 0
        times = []
        for run in range(a.runs):
            tid = (tid % 0xFFFF) + 1
            try:
                st, vals, dt = read_block(sock, tid, a.slave, a.start, n, a.timeout)
            except Exception as e:
                st, vals, dt = f"ERR({e})", None, 0.0
                try: sock.close()
                except Exception: pass
                sock = connect(a.host, a.port)

            tid = (tid % 0xFFFF) + 1
            try:
                lst, _, _ = read_block(sock, tid, a.slave, a.live_reg, 1, 3.0)
            except Exception:
                lst = "ERR"
            alive = (lst == "OK")

            if st == "OK" and alive:
                ok += 1; times.append(dt)
            else:
                fail += 1

            mark = "ok" if (st == "OK" and alive) else "FEHLER"
            print(f"    {n:3d} Register, Lauf {run+1}: {st:<10} {dt*1000:7.1f} ms  "
                  f"Verbindung {'steht' if alive else 'WEG'}  -> {mark}")

            if not alive:
                try: sock.close()
                except Exception: pass
                time.sleep(1.5)
                sock = connect(a.host, a.port)
            time.sleep(0.3)

        avg = sum(times)/len(times) if times else 0
        results[n] = (ok, fail, avg)
        print(f"    -> {n} Register: {ok}x ok, {fail}x Fehler, Schnitt {avg*1000:.0f} ms\n")

    print("  " + "-"*58)
    print("  Zusammenfassung")
    print(f"  {'Groesse':>8} {'ok':>4} {'Fehler':>7} {'Schnitt':>10}")
    for n, (ok, fail, avg) in results.items():
        print(f"  {n:>8} {ok:>4} {fail:>7} {avg*1000:>8.0f} ms")
    worst = [n for n, (ok, fail, _) in results.items() if fail]
    print()
    if worst:
        print(f"  Problematisch ab: {min(worst)} Register")
        print(f"  Empfehlung: Blockgrenze in coordinator.py unter {min(worst)} setzen.")
    else:
        print(f"  Alle Groessen bis {max(sizes)} fehlerfrei.")


if __name__ == "__main__":
    main()
