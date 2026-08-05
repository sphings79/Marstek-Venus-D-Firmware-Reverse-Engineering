#!/usr/bin/env python3
"""
Marstek Venus D — TCP Shell Probe (Port 8091)
Testet Text-CLI-Format UND Binary-BLE-Protokoll.

Binary-Protokoll (aus venuscontrol Quellcode):
  [0x73][totalLen][0x23][cmdId][payload...][XOR-Checksum]
  Checksum = XOR aller Bytes außer dem letzten
"""

import socket
import time
import sys

HOST = "192.168.1.100"
PORT = 8091
TIMEOUT = 3.0


# ── Binary-Protokoll Helfer ──────────────────────────────────────────────────

def venus_packet(cmd_id: int, payload: bytes = b"") -> bytes:
    total_len = 1 + 1 + 1 + 1 + len(payload) + 1  # magic+len+0x23+cmd+payload+crc
    buf = bytearray(total_len)
    buf[0] = 0x73          # MAGIC
    buf[1] = total_len
    buf[2] = 0x23          # fixed marker
    buf[3] = cmd_id
    buf[4:4+len(payload)] = payload
    xor = 0
    for b in buf[:-1]:
        xor ^= b
    buf[-1] = xor
    return bytes(buf)


# ── Bekannte Command-IDs (aus VenusConst.ts) ─────────────────────────────────

BINARY_COMMANDS = [
    (0x03, b"",  "STATE — Zustand/Leistung (read-only)"),
    (0x04, b"",  "DEVICE_INFO — Typ/ID/MAC/Versionen (read-only)"),
    (0x0A, b"",  "GET_WORK_MODE_SETTINGS — Arbeitsmodus-Konfiguration (read-only)"),
    (0x1A, b"",  "CT_READINGS — CT-Messwerte (read-only)"),
    (0x42, b"",  "BATTERY_MODULES_STATE — Batterie-Module-Status (read-only)"),
]

# Text-CLI-Befehle (aus Firmware-String-Analyse)
TEXT_COMMANDS = [
    (b"\x03",            "ETX/Ctrl+C — Log-Reset (Firmware-Sonderfall)"),
    (b"get_ver\r\n",     "get_ver (Text-CLI)"),
    (b"wifi_info\r\n",   "wifi_info (Text-CLI)"),
    (b"rtos_status\r\n", "rtos_status (Text-CLI)"),
    (b"err_code\r\n",    "err_code (Text-CLI)"),
    (b"mac_ble\r\n",     "mac_ble (Text-CLI)"),
    (b"ext_info\r\n",    "ext_info (Text-CLI)"),
    # Nur 4 Bytes, kein Zeilenende — testet ob Pattern-Matching direkt auslöst
    (b"rese",            "4-Byte: 'rese' (Pattern für 'reset'?)"),
    (b"getv",            "4-Byte: 'getv' (Pattern für 'get_ver'?)"),
]


# ── Probe-Funktion ────────────────────────────────────────────────────────────

def probe(data: bytes, wait: float = TIMEOUT, label: str = "") -> bytes:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(wait)
        s.connect((HOST, PORT))
        time.sleep(0.15)
        s.sendall(data)
        chunks = []
        deadline = time.time() + wait
        while time.time() < deadline:
            try:
                chunk = s.recv(4096)
                if chunk:
                    chunks.append(chunk)
                    deadline = time.time() + 0.5  # Fenster verlängern wenn Daten kommen
            except socket.timeout:
                break
        s.close()
        return b"".join(chunks)
    except Exception as e:
        return f"ERROR: {e}".encode()


def hexdump(data: bytes) -> str:
    if not data:
        return "  (keine Antwort)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"  {i:04x}  {hex_part}  {ascii_part}")
    return "\n".join(lines)


def banner_check():
    print("\n[BANNER] Verbinden ohne Senden (3s warten):")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((HOST, PORT))
        data = b""
        try:
            data = s.recv(4096)
        except socket.timeout:
            pass
        s.close()
        print(hexdump(data))
    except Exception as e:
        print(f"  ERROR: {e}")


def main():
    print(f"Marstek Venus D Probe — {HOST}:{PORT}\n{'='*60}")

    banner_check()

    # ── Phase 1: Binary-Protokoll ────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("PHASE 1 — Binary-Protokoll [0x73][len][0x23][cmd][payload][xor]")
    print(f"{'─'*60}")

    for cmd_id, payload, label in BINARY_COMMANDS:
        pkt = venus_packet(cmd_id, payload)
        hex_pkt = " ".join(f"{b:02x}" for b in pkt)
        print(f"\n[0x{cmd_id:02X}] {label}")
        print(f"  Sende: {hex_pkt}")
        resp = probe(pkt)
        print(hexdump(resp))
        time.sleep(0.3)

    # ── Phase 2: Text-CLI ────────────────────────────────────────────────────
    print(f"\n{'─'*60}")
    print("PHASE 2 — Text-CLI")
    print(f"{'─'*60}")

    for data, label in TEXT_COMMANDS:
        print(f"\n[TEXT] {label}")
        print(f"  Sende: {repr(data)}")
        resp = probe(data)
        print(hexdump(resp))
        time.sleep(0.3)

    print(f"\n{'='*60}\nFertig.")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        HOST = sys.argv[1]
    main()
