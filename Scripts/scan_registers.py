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
"""

import socket, struct, csv, time, sys, argparse, signal, select
from datetime import datetime

BATCH_SIZE = 32
DELAY_S    = 0.15

stop_flag = False
def sigint_handler(sig, frame):
    global stop_flag
    print("\n  Ctrl+C — beende...")
    stop_flag = True
signal.signal(signal.SIGINT, sigint_handler)


# ═══════════════════════════════════════════════════════════
# Modbus TCP Raw-Socket (aus scan_modbus_batch v7)
# ═══════════════════════════════════════════════════════════

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


def mb_connect(host, port, timeout=5.0):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.settimeout(None)
        return s
    except Exception as e:
        print(f"    Connect failed: {e}")
        return None


def mb_reconnect(host, port):
    time.sleep(1.5)
    s = mb_connect(host, port)
    if s is None:
        time.sleep(2.0)
        s = mb_connect(host, port)
    return s


# ═══════════════════════════════════════════════════════════
# Bekannte Register (aus FW-Analyse, kompakt)
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
    30200:("ems_version","1",""), 30202:("vms_version","1",""), 30204:("bms_version","1",""),
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
# BMS Packs 1-7
_BMS = {0:("bat_volt","0.01","V"),1:("bat_curr","0.1","A"),2:("bat_soc","0.1","%"),
        3:("cycle_cnt","1",""),4:("max_cell_v","0.001","V"),6:("min_cell_v","0.001","V"),
        7:("max_ntc","0.1","°C"),8:("protect1","hex",""),9:("protect2","hex",""),
        10:("bms_ver","1",""),11:("ntc0","0.1","°C"),12:("ntc1","0.1","°C"),
        13:("ntc2","0.1","°C"),14:("ntc3","0.1","°C"),
        15:("mos_ntc","0.1","°C"),16:("env_ntc","0.1","°C"),17:("avg_ntc","0.1","°C")}
for i in range(16): _BMS[18+i] = (f"cell{i+1}","0.001","V")
for p in range(7):
    for o,(n,s,u) in _BMS.items(): KNOWN[34000+p*100+o] = (f"p{p+1}_{n}",s,u)
# Schedules
for s in range(6):
    b = 43100+s*5
    KNOWN.update({b:(f"sched{s+1}_days","hex",""),b+1:(f"sched{s+1}_start","HHMM",""),
                  b+2:(f"sched{s+1}_end","HHMM",""),b+3:(f"sched{s+1}_mode","1","W"),
                  b+4:(f"sched{s+1}_en","1","")})


# ═══════════════════════════════════════════════════════════
# Parsing & Formatting
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


def interpret(reg, raw):
    info = KNOWN.get(reg)
    if not info: return ""
    _, scale, unit = info
    signed = raw - 65536 if raw >= 32768 else raw
    try:
        if scale == "ip": return f"{(raw>>8)&0xFF}.{raw&0xFF}"
        if scale == "hex": return f"0x{raw:04X}"
        if scale == "HHMM": return f"{raw//100:02d}:{raw%100:02d}"
        if scale in ("u32","u32×0.01",""): return ""
        if scale == "-1": return f"{-raw} {unit}"
        s = float(scale)
        val = signed * s if unit in ("W","A","°C") and signed < 0 else raw * s
        return f"{val:.2f} {unit}".strip() if val != int(val) else f"{int(val)} {unit}".strip()
    except: return ""


def format_row(reg, raw):
    signed = raw - 65536 if raw >= 32768 else raw
    info = KNOWN.get(reg)
    name = info[0] if info else ""
    interp = interpret(reg, raw)
    s_str = f" ({signed:6d})" if signed != raw else "        "
    n_str = f"  {name:.<28s}" if name else f"  {'?':.<28s}"
    i_str = f"  = {interp}" if interp else ""
    return f"  {reg:5d}  0x{raw:04X}  {raw:6d}{s_str}{n_str}{i_str}"


# ═══════════════════════════════════════════════════════════
# Scanner
# ═══════════════════════════════════════════════════════════

def scan_registers(host, port, slave, registers):
    sock = mb_connect(host, port)
    if not sock:
        print(f"FEHLER: Keine Verbindung zu {host}:{port}")
        return {}

    results = {}
    tid = 1

    # Batches bilden (max 32 aufeinanderfolgende)
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

    for bs, be in batches:
        if stop_flag: break
        count = be - bs + 1
        tid = (tid % 0xFFFF) + 1

        if sock is None:
            sock = mb_reconnect(host, port)
            if sock is None: continue

        # Batch-Read
        try:
            sock.sendall(build_req(tid, slave, bs, count))
            resp = recv_response(sock, timeout=3.0)
        except Exception:
            resp = None
            try: sock.close()
            except: pass
            sock = mb_reconnect(host, port)

        vals = parse(resp, count) if resp else None

        if vals is not None:
            for i, v in enumerate(vals):
                if bs+i in reg_set:
                    results[bs+i] = v
            time.sleep(DELAY_S)
            continue

        # Fallback: Einzel-Reads
        for r in range(bs, be+1):
            if stop_flag: break
            if r not in reg_set: continue
            tid = (tid % 0xFFFF) + 1

            if sock is None:
                sock = mb_reconnect(host, port)
                if sock is None: break

            try:
                sock.sendall(build_req(tid, slave, r, 1))
                resp2 = recv_response(sock, timeout=1.5)
            except Exception:
                resp2 = None
                try: sock.close()
                except: pass
                sock = mb_reconnect(host, port)

            v2 = parse(resp2, 1) if resp2 else None
            if v2 is not None:
                results[r] = v2[0]
            time.sleep(DELAY_S / 4)

        time.sleep(DELAY_S)

    if sock:
        try: sock.close()
        except: pass
    return results


# ═══════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════

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
        "  %(prog)s --host 192.168.1.100 --regs 30000-30040 --unknown-only\n")
    p.add_argument("--host", required=True, help="IP des Venus D")
    p.add_argument("--port", default=502, type=int)
    p.add_argument("--slave", default=1, type=int)
    p.add_argument("--regs", help="30005 oder 30000-30040 oder 30000,32200,34000-34033")
    p.add_argument("--file", help="Datei mit Registern (# = Kommentar)")
    p.add_argument("--out", help="CSV speichern")
    p.add_argument("--watch", type=int, metavar="N", help="Alle N Sek wiederholen")
    p.add_argument("--unknown-only", action="store_true", help="Nur unbenannte Register")
    p.add_argument("--delay", type=int, default=150, help="ms zwischen Requests (default 150)")
    args = p.parse_args()

    global DELAY_S
    DELAY_S = args.delay / 1000

    if not args.regs and not args.file:
        p.error("--regs oder --file nötig")

    registers = []
    if args.regs: registers = parse_regs(args.regs)
    if args.file: registers = sorted(set(registers + load_file(args.file)))
    if not registers:
        print("Keine Register!"); sys.exit(1)

    print(f"\nMarstek Venus D — Register-Scanner")
    print(f"{'='*65}")
    print(f"Host:      {args.host}:{args.port}  Slave={args.slave}")
    print(f"Register:  {len(registers)} Stück ({registers[0]}–{registers[-1]})")
    if args.watch: print(f"Watch:     alle {args.watch}s")
    print(f"{'='*65}\n")

    iteration = 0
    try:
        while True:
            iteration += 1
            ts = datetime.now().strftime("%H:%M:%S")
            if args.watch and iteration > 1:
                print(f"{'─'*65}")

            results = scan_registers(args.host, args.port, args.slave, registers)

            csv_rows = []
            for reg in registers:
                if reg not in results: continue
                raw = results[reg]
                if args.unknown_only and reg in KNOWN: continue

                signed = raw - 65536 if raw >= 32768 else raw
                info = KNOWN.get(reg)
                name = info[0] if info else "?"
                interp = interpret(reg, raw)

                s_str = f" ({signed:6d})" if signed != raw else "        "
                n_str = f"{name:.<24s}" if name else f"{'?':.<24s}"
                i_str = f"= {interp}" if interp else ""
                print(f"  {ts}  {reg:5d}  0x{raw:04X}  {raw:6d}{s_str}  {n_str}  {i_str}")

                csv_rows.append({
                    "timestamp": ts, "Register": reg, "raw_uint16": raw,
                    "raw_int16": signed, "hex": f"0x{raw:04X}",
                    "name": name, "interpreted": interp,
                })

            nr = len(registers) - len(results)
            if not args.watch:
                print(f"\n  Gefunden: {len(results)}/{len(registers)}  |"
                      f"  Keine Antwort: {nr}  |  {ts}")

            if args.out and csv_rows:
                write_header = (iteration == 1)
                mode = "w" if iteration == 1 else "a"
                with open(args.out, mode, newline="") as f:
                    w = csv.DictWriter(f, fieldnames=list(csv_rows[0].keys()))
                    if write_header:
                        w.writeheader()
                    w.writerows(csv_rows)
                if iteration == 1:
                    print(f"  CSV: {args.out} (append bei watch)")

            if not args.watch or stop_flag: break
            time.sleep(args.watch)

    except KeyboardInterrupt:
        print(f"\nAbgebrochen nach {iteration} Durchläufen")


if __name__ == "__main__":
    main()
