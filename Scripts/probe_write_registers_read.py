#!/usr/bin/env python3
"""
Marstek Venus D — welche Register >= 40000 antworten auf einen FC03-Read?

Warum das ungefaehrlich ist
---------------------------
FC03_Read_Handler (0x0801F06C) delegiert jeden Read >= 40000 an
Write_Handler(buf, reg, param_3=0). Jeder Registerzweig prueft param_3 als
ERSTES und kehrt im Lesefall zurueck, bevor irgendeine Aktion laeuft:

    if (param_3 == 0) { ...Wert in den Puffer...; return 0; }   // Gruppe A
    if (param_3 == 0) { return 3; }                             // Gruppe B

Statische Pruefung aller 52 Funktionsaufrufe im Write_Handler (2026-08-22):
kein Befehl und kein EEPROM_Write ist aus dem Lesepfad erreichbar.
Ein Read kostet also weder einen EEPROM-Zyklus noch loest er etwas aus.

Was das Skript unterscheidet
----------------------------
    OK        Register liefert einen Wert   -> Gruppe A, als Sensor nutzbar
    EXC-2/3   Modbus-Exception              -> Gruppe B, reines Schreibregister
    TIMEOUT   keine Antwort
    DEAD      Verbindung danach weg (Liveness-Probe schlaegt fehl)

Nach JEDER Abfrage wird ein bekanntes, stabiles Register gelesen (Default
37012 = BMS-Version). Antwortet das nicht mehr, hat die vorherige Abfrage die
Verbindung gestoert -- das wird protokolliert und das Register markiert.

Aufruf
------
  python3 probe_write_registers_read.py
  python3 probe_write_registers_read.py --from 40000 --to 47500 --out probe.csv
  python3 probe_write_registers_read.py --regmap ../Modbus_RS485_TCP/Marstek_Venus_D_Register_Map_Final_all_register.csv
"""

import socket, struct, csv, time, sys, argparse, signal, select, os
from datetime import datetime

stop_flag = False


def sigint_handler(sig, frame):
    global stop_flag
    print("\n  Ctrl+C — beende und speichere ...")
    stop_flag = True


def build_req(tid, slave, reg, count=1):
    pdu = struct.pack(">BBHH", slave, 0x03, reg, count)
    return struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu)) + pdu


def recv_frame(sock, expect_tid, timeout=2.0):
    """Liefert den MBAP-Frame mit passender Transaction-ID, sonst None."""
    buf = b""
    deadline = time.time() + timeout
    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None
        if not select.select([sock], [], [], min(remaining, 0.5))[0]:
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


def read_one(sock, tid, slave, reg, timeout=2.0):
    """-> (status, wert_oder_None, exception_code_oder_None)"""
    sock.sendall(build_req(tid, slave, reg, 1))
    f = recv_frame(sock, tid, timeout)
    if f is None:
        return "TIMEOUT", None, None
    if len(f) < 9:
        return "SHORT", None, None
    fc = f[7]
    if fc & 0x80:
        return "EXC", None, f[8]
    if fc != 0x03:
        return "FC?", None, None
    bc = f[8]
    if bc < 2 or len(f) < 9 + bc:
        return "SHORT", None, None
    return "OK", struct.unpack(">H", f[9:11])[0], None


def connect(host, port, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    s.settimeout(None)
    return s


def load_candidates(regmap, lo, hi):
    regs = set()
    if regmap and os.path.exists(regmap):
        for row in csv.DictReader(open(regmap, errors="replace")):
            v = (row.get("register") or row.get("Register") or "").strip()
            if v.isdigit() and lo <= int(v) <= hi:
                regs.add(int(v))
    return sorted(regs)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="192.168.1.50")
    p.add_argument("--port", default=1502, type=int)
    p.add_argument("--slave", default=1, type=int)
    p.add_argument("--from", dest="lo", default=40000, type=int)
    p.add_argument("--to", dest="hi", default=47500, type=int)
    p.add_argument("--live-reg", default=37012, type=int,
                   help="Register fuer die Liveness-Probe (Default 37012 = BMS-Version)")
    p.add_argument("--delay", default=0.15, type=float)
    p.add_argument("--regmap",
                   default="../Modbus_RS485_TCP/Marstek_Venus_D_Register_Map_Final_all_register.csv")
    p.add_argument("--out", default=None)
    p.add_argument("--all", action="store_true",
                   help="jedes Register im Bereich testen, nicht nur die aus der Register-Map")
    a = p.parse_args()

    out = a.out or f"probe_read_40000_{datetime.now():%Y%m%d_%H%M%S}.csv"
    signal.signal(signal.SIGINT, sigint_handler)

    cands = (list(range(a.lo, a.hi + 1)) if a.all
             else load_candidates(a.regmap, a.lo, a.hi))
    if not cands:
        print("  Keine Kandidaten gefunden — mit --all den ganzen Bereich testen.")
        return

    print(f"  Ziel        : {a.host}:{a.port} Slave {a.slave}")
    print(f"  Kandidaten  : {len(cands)} Register aus {a.lo}-{a.hi}")
    print(f"  Liveness    : Register {a.live_reg} nach jeder Abfrage")
    print(f"  CSV         : {out}\n")

    sock = connect(a.host, a.port)
    tid = 0
    rows = []
    stats = {}

    # Referenzwert der Liveness-Probe
    tid += 1
    st, live_ref, _ = read_one(sock, tid, a.slave, a.live_reg)
    if st != "OK":
        print(f"  ABBRUCH: Liveness-Register {a.live_reg} antwortet nicht ({st}).")
        return
    print(f"  Liveness-Referenz: {a.live_reg} = {live_ref}\n")

    for n, reg in enumerate(cands, 1):
        if stop_flag:
            break
        tid = (tid % 0xFFFF) + 1
        try:
            st, val, exc = read_one(sock, tid, a.slave, reg)
        except Exception as e:
            st, val, exc = "ERR", None, None
            print(f"  {reg}: Socketfehler {e}")
            try: sock.close()
            except Exception: pass
            sock = connect(a.host, a.port)

        time.sleep(a.delay)

        # Liveness
        tid = (tid % 0xFFFF) + 1
        try:
            lst, lval, _ = read_one(sock, tid, a.slave, a.live_reg, timeout=2.0)
        except Exception:
            lst, lval = "ERR", None
        alive = (lst == "OK")
        if not alive:
            st = "DEAD"
            print(f"  !! {reg}: Verbindung nach der Abfrage gestoert — neu verbinden")
            try: sock.close()
            except Exception: pass
            time.sleep(1.0)
            try:
                sock = connect(a.host, a.port)
            except Exception as e:
                print(f"     Reconnect fehlgeschlagen: {e}")
                break

        rows.append({"register": reg, "status": st,
                     "wert": "" if val is None else val,
                     "hex": "" if val is None else f"0x{val:04X}",
                     "exception": "" if exc is None else exc,
                     "liveness": lval if lval is not None else "",
                     "zeit": datetime.now().strftime("%H:%M:%S")})
        stats[st] = stats.get(st, 0) + 1

        if st == "OK":
            print(f"  [{n:4d}/{len(cands)}] {reg}  OK   {val:6d}  0x{val:04X}")
        elif n % 25 == 0 or st in ("DEAD", "TIMEOUT"):
            print(f"  [{n:4d}/{len(cands)}] {reg}  {st}"
                  + (f" (code {exc})" if exc else ""))

        time.sleep(a.delay)

    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["register", "status", "wert", "hex",
                                           "exception", "liveness", "zeit"])
        w.writeheader()
        w.writerows(rows)

    print("\n  " + "-" * 60)
    print("  Ergebnis:")
    for k in sorted(stats, key=lambda x: -stats[x]):
        print(f"    {k:<10} {stats[k]:4d}")
    ok = [r for r in rows if r["status"] == "OK"]
    if ok:
        print(f"\n  Lesbare Register ({len(ok)}):")
        for r in ok:
            print(f"    {r['register']}  = {r['wert']:>6}  {r['hex']}")
    dead = [r for r in rows if r["status"] == "DEAD"]
    if dead:
        print(f"\n  ACHTUNG — diese Register haben die Verbindung gestoert:")
        for r in dead:
            print(f"    {r['register']}")
    print(f"\n  CSV: {out}")


if __name__ == "__main__":
    main()
