# Marstek Venus D — Modbus TCP Verbindungsreferenz

**Zweck:** Technische Referenz für alle Scanner-Scripts und die HA-Integration.
Dokumentiert die Verbindungsparameter, Protokoll-Eigenheiten und bekannten Fallstricke.

---

## 1. Verbindungsparameter

| Parameter | Wert | Hinweis |
|---|---|---|
| **Protokoll** | Modbus TCP (nicht RTU!) | Direkt über Ethernet/WiFi |
| **IP-Adresse** | `192.168.1.100` | Statisch konfiguriert, lesbar aus Reg 30400–30403 |
| **Port** | `502` | Standard Modbus TCP |
| **Slave/Unit-ID** | `1` | Fest, lesbar aus Reg 41100 |
| **Timeout** | 3–5 Sekunden | Gerät antwortet normalerweise in <500ms |
| **Function Code** | `0x03` (Read Holding) | Lesen aller Register |
| **Function Code** | `0x06` (Write Single) | Einzelregister schreiben |
| **Function Code** | `0x10` (Write Multiple) | Mehrere Register schreiben |

## 2. MBAP Header (Modbus TCP Frame)

```
Request:
┌─────────────┬──────────────┬────────────┬──────────┬─────────┬──────────────┬───────────┐
│ TID (2B)    │ Protocol (2B)│ Length (2B)│ Unit (1B)│ FC (1B) │ Reg Addr (2B)│ Count (2B)│
│ 0x0001      │ 0x0000       │ 0x0006     │ 0x01     │ 0x03    │ z.B. 0x7532  │ 0x0001    │
└─────────────┴──────────────┴────────────┴──────────┴─────────┴──────────────┴───────────┘

Response:
┌─────────────┬──────────────┬────────────┬──────────┬─────────┬────────────┬─────────────┐
│ TID (2B)    │ Protocol (2B)│ Length (2B)│ Unit (1B)│ FC (1B) │ ByteCnt(1B)│ Data (N×2B) │
└─────────────┴──────────────┴────────────┴──────────┴─────────┴────────────┴─────────────┘

Gesamtlänge Response = 6 + Length-Feld  (NICHT 9 + Length - 1!)
```

**MBAP-Bugfix (aus Scanner v7):** Die korrekte Formel für die Gesamtlänge einer
Modbus-TCP-Antwort ist `6 + Length-Feld`. Ältere Implementierungen hatten fälschlicherweise
`9 + Length - 1` verwendet, was zu Parsing-Fehlern führte.

### Python-Implementierung (Raw Socket, KEIN pymodbus)

```python
import socket, struct, select, time

def build_req(tid, slave, reg, count):
    """Baut einen Modbus TCP FC03 Request."""
    pdu  = struct.pack(">BBHH", slave, 0x03, reg, count)
    mbap = struct.pack(">HHH", tid & 0xFFFF, 0, len(pdu))
    return mbap + pdu

def recv_response(sock, timeout=3.0):
    """Empfängt eine vollständige Modbus TCP Antwort."""
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
            return None  # Verbindung geschlossen!
        resp += chunk
        if len(resp) >= 6:
            length_field = struct.unpack(">H", resp[4:6])[0]
            total = 6 + length_field   # KORREKTE Formel
            if len(resp) >= total:
                return resp[:total]

def parse(data, count):
    """Parst FC03-Response zu Liste von uint16-Werten."""
    if not data or len(data) < 9:
        return None
    fc = data[7]
    if fc & 0x80:        # Exception Response
        return None
    if fc != 0x03:
        return None
    byte_count = data[8]
    n = byte_count // 2
    if n < 1 or len(data) < 9 + byte_count:
        return None
    return list(struct.unpack(f">{n}H", data[9:9 + byte_count]))
```

### Warum Raw-Socket statt pymodbus?

- **pymodbus API-Inkompatibilität:** v2.x nutzt `unit=`, v3.x `slave=`, neuere Versionen
  ändern die API erneut. Auf macOS/Homebrew ist die installierte Version unvorhersehbar.
- **Keine Dependency:** Raw-Socket braucht nur Python-Standardbibliothek
- **Volle Kontrolle:** TID-Management, Timeout-Handling, MBAP-Parsing exakt nach Bedarf
- **Getestet:** Scanner v7 mit Raw-Socket ist die einzige zuverlässig funktionierende Variante

## 3. Kritische Geräteeigenheiten

### 3.1 Batch-Size Hard-Limit: 32 Register

```
FC03 mit count ≤ 32:  ✅ Normale Antwort
FC03 mit count > 32:  ❌ KEINE Antwort (Timeout, kein Exception-Code!)
```

Das Gerät gibt bei Überschreitung weder einen Fehler noch eine Exception zurück —
es antwortet einfach **nicht**. Die TCP-Verbindung bleibt offen, aber der Request
wird stillschweigend ignoriert.

**Empfehlung:** `BATCH_SIZE = 32` für alle Scanner.

### 3.2 Verbindungsabbruch nach Exception

```
FC03 auf ungültiges Register → Exception Response (FC 0x83, Code 0x02)
→ Gerät SCHLIESST die TCP-Verbindung!
→ Reconnect erforderlich für nächsten Request
```

**Strategie:** Bei Exception-Response sofort `socket.close()` + Reconnect mit 1.5–2s Pause.
Nicht versuchen, weitere Requests auf dem gleichen Socket zu senden.

### 3.3 Register-Adressierung: DIREKT (kein Offset)

```
PDU-Adresse = Register-Nummer (KEINE 0-basierte Konvertierung!)

Register 30000 → PDU addr = 30000 (0x7530)
Register 34002 → PDU addr = 34002 (0x84D2)
Register 42000 → PDU addr = 42000 (0xA410)
```

**Beweis:** Der TCPRouter im Control-FW (`FUN_0801c088`) vergleicht die rohe PDU-Adresse
direkt mit `descriptor.base_addr` ohne jede Korrektur.

In Python (Raw-Socket): `build_req(tid, 1, 34002, 1)` liest Register 34002.
In pymodbus: `read_holding_registers(34002, 1)` — KEIN `-1` oder `-40001`!

### 3.4 Lückenhafte Register-Bereiche

Der Adressraum ist NICHT durchgehend belegt. Ein Batch-Read über eine Lücke ergibt
eine Exception. Lösung: Bei Exception auf Einzel-Reads fallback.

```
30000-30040:  teilweise belegt (Lücken bei 30008-30009, 30011-30019, etc.)
32000-32999:  nur 6 Register belegt (32105, 32200, 32204, 32300-32302)
34000-34033:  durchgehend belegt (Pack 1)
37000-37025:  teilweise belegt
```

### 3.5 Reconnect-Timing

| Situation | Wartezeit | Retry |
|---|---|---|
| Exception-Response | 1.5–2.0s | Sofort reconnect |
| Timeout (keine Antwort) | 2.0–3.0s | 1× retry, dann skip |
| Socket-Fehler | 2.0s, dann 3.0s | 2 Versuche |
| Request-Intervall | 150ms minimum | Zu schnell → Timeout |

### 3.6 Request-Rate

```
Empfohlen:  150ms zwischen Requests (DELAY_S = 0.15)
Minimum:    100ms (funktioniert, aber gelegentliche Timeouts)
Maximum:    Unbegrenzt (Gerät hat kein Rate-Limit nach oben)
```

## 4. RS485 Write-Zugang (Register ≥ 42000)

Vor dem Schreiben auf Steuerregister (42010–42021) muss der RS485-Modus
mit einem **Unlock-Befehl** aktiviert werden:

```
Register 42000 = 0x55AA  → RS485 Steuerung AKTIV
Register 42000 = 0x55BB  → Alternative Aktivierung
Register 42000 = 0x55EE  → RS485 Steuerung DEAKTIV
```

**Danach schreibbar:**

| Register | Beschreibung | Wertebereich |
|---|---|---|
| 42010 | force_mode | 0=None, 1=Charge, 2=Discharge |
| 42011 | charge_to_soc | 0–100 (%) |
| 42020 | set_charge_power | 0–2500 (W) |
| 42021 | set_discharge_power | 0–2500 (W) |

**Warnung:** Write-Befehle nutzen FC06 (Write Single Register), NICHT FC03.

## 5. Wichtige Scale-Faktoren

| Register | Rohwert-Beispiel | Scale | Ergebnis | Quelle |
|---|---|---|---|---|
| 34002 (SOC) | 146 | **×0.1** | 14.6% | BMS show_soc, FW-verifiziert |
| 30100 (bat_volt) | 5114 | ×0.01 | 51.14V | BMS struct 0x4A |
| 30101 (bat_curr) | -11 (signed!) | ×0.1 | -1.1A | BMS struct 0x4C |
| 32200 (ac_volt) | 2398 | ×0.1 | 239.8V | Telemetrie grid_volt |
| 32204 (ac_freq) | 499 | ×0.1 | 49.9Hz | Telemetrie grid_pf |
| 34018-34033 (cells) | 3116 | ×0.001 | 3.116V | BMS Cell Volt[n] |
| 35000 (env_temp) | 300 | ×0.1 | 30.0°C | Micro ntc_inv |
| 33000-33001 (energy) | u32 | ×0.01 | kWh | Telemetrie chrg_energy |
| 37004 (ac_current) | -498 (signed!) | ×0.01 | -4.98A | Micro grid_cur |

**Achtung signed/unsigned:** Register mit Strom (A), Leistung (W) oder Temperatur (°C)
können negative Werte haben. Rohwert > 32767 → `value = raw - 65536`.

## 6. Local API — NICHT AKTIVIEREN

```
⛔ UDP Port 30000 (Local API) → NICHT aktivieren!
   Dokumentierte Berichte von dauerhaft korrupten Modbus-Registern
   nach Aktivierung. Betrifft auch Werte die nach Device-Reset
   nicht zurückgesetzt werden.
```

## 7. Verfügbare Scanner-Scripts

| Script | Zweck | Dependency |
|---|---|---|
| `scan_registers.py` | Einzelne/flexible Register (auch Vollscan via `--regs 0-65535`), Watch-Modus, CSV-Export | Keine (Raw-Socket) |
| `scan_known_registers.py` | Scannt nur Register aus der bekannten Register-Map-CSV (`--regmap`) | Keine (Raw-Socket) |
| `scan_continuous.py` | Dauerschleife über bekannte Register (`--interval`, default 10s) | Keine (Raw-Socket) |
| `scan_powercycle.py` | Scan über Power-Cycle-Events hinweg | Keine (Raw-Socket) |

**Hinweis (2026-07-15):** Die zuvor hier gelisteten `scan_modbus_batch.py` und `test_batch_limit.py`
existieren nicht (mehr) im Projektordner — vermutlich frühe Prototyp-Namen, die durch obige Scripts
ersetzt wurden. Das Batch-Size-Limit (32 Register, s. 3.1) ist bereits als Fakt dokumentiert und
braucht kein dediziertes Testscript mehr.

## 8. Quick-Start für neuen Scan

```bash
# 1. Vollscan mit aktuellem FW-Stand
python3 scan_registers.py --host 192.168.1.100 --regs 0-65535 --out scan_v149.2.csv

# 2. Bestimmte Register prüfen
python3 scan_registers.py --host 192.168.1.100 --regs 30000-30040,32200,34002

# 3. Unbekannte Register untersuchen
python3 scan_registers.py --host 192.168.1.100 --regs 30002-30005,30028-30036

# 4. Live-Monitoring (z.B. SOC während Laden beobachten)
python3 scan_registers.py --host 192.168.1.100 --regs 34002,30001,32200 --watch 5

# 5. Neuen Registerbereich (z.B. 32000er) gezielt scannen
python3 scan_registers.py --host 192.168.1.100 --regs 32000-32999 --out scan_32k.csv
```

---

*Stand: Juli 2026 | Firmware v149.2 | Gerät: Marstek Venus D (VNSD-0)*
