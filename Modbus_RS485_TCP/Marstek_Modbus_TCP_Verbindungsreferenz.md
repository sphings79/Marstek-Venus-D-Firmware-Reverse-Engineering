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

### 3.7 BMS-Pack-Layout (34000 + pack×100 + offset)

Jeder Batterie-Pack belegt einen 100er-Block (Pack 1 = 34000, Pack 2 = 34100, …,
Pack 7 = 34600). Innerhalb des Blocks:

| Offset | Register (Pack N) | Feld | Scale |
|---|---|---|---|
| +0 | 34N00 | bat_volt | ×0.01 V |
| +1 | 34N01 | bat_curr (signed) | ×0.1 A |
| +2 | 34N02 | bat_soc | **×0.1 %** |
| +3 | 34N03 | cycle_count | ×1 |
| +4 | 34N04 | **charge_status** (0=idle, 3=aktiv laden) | ×1 |
| +5 | 34N05 | **max_cell_v** | ×0.001 V |
| +6 | 34N06 | min_cell_v | ×0.001 V |
| +7 | 34N07 | max_ntc | ×0.1 °C |
| +8/+9 | 34N08/34N09 | protect1 / protect2 (bitmask) | hex |
| +10 | 34N10 | bms_version | ×1 |
| +11…+14 | 34N11–34N14 | ntc0–ntc3 | ×0.1 °C |
| +15/+16/+17 | 34N15–34N17 | mos_ntc / env_ntc / avg_ntc | ×0.1 °C |
| +18…+33 | 34N18–34N33 | cell1–cell16 | ×0.001 V |

> **Korrektur (2026-08-14):** `max_cell_v` liegt auf **Offset +5** (z.B. 34005),
> nicht +4. Offset +4 ist der **charge_status** (Werte 0/3). Ältere Scanner-Stände
> haben `max_cell_v` fälschlich auf +4 gelegt und +5 als „unbekannt" geführt — im
> Live-Scan (`control_150_vns_116.csv`) steht der echte Max-Zellwert eindeutig auf
> +5 (34005=3332 ≈ 3,33 V), während +4 = 0 bzw. 3 ist. Betrifft alle Packs 1–7.
> **Packs 5 und 6 sind seit dem v150/VNS116-Vollscan vollständig bestätigt.**

### 3.8 ASCII-/String-Register (Geräte-Identität)

Die Firmware stellt über den Read-Handler genau **drei** ASCII-Blöcke bereit
(je 2 Zeichen pro Register, big-endian / High-Byte zuerst). Quelle: Ghidra-Analyse
des Read-Handlers (`Scan_Logs/Read_Handler_Register_Map.csv`).

| Register | Feld | Länge | Beispiel-Dekodierung |
|---|---|---|---|
| 30304–30309 | **MAC-Adresse** | 6 Reg | `AABBCCDDEEFF` → `AA:BB:CC:DD:EE:FF` |
| 30350–30355 | **Kommunikationsmodul-FW-Version** | 6 Reg | `202409090159` (Build 2024-09-09 / 0159) ✅ voll gelesen |
| 31000–31009 | **Gerätename** | 10 Reg | `VNSD-0` + Null-Padding |

Dekodierung in Python: `chr((raw>>8)&0xFF) + chr(raw&0xFF)` je Register, in
Registerreihenfolge aneinandergehängt.

> **Bestätigt (2026-08-14):** Der 30350er-Block wurde per gezieltem Read komplett
> gelesen (`Scan_Logs/regs_30350-30355.csv`) und ergibt lückenlos
> `20`+`24`+`09`+`09`+`01`+`59` = **`202409090159`**. Im v150-Vollscan war die
> isolierte 30352-Erfassung um ein Register verschoben (zeigte „24" statt „09") —
> der gezielte Read ist maßgeblich. Merke: bei Einzeltreffern in einem sonst
> lückenhaften Batch-Bereich lieber den ganzen Block gezielt nachlesen
> (`scan_registers.py --regs 30300-30355`).

> **NICHT über Modbus lesbar:** Die 24-stellige **Device-ID** (z. B.
> `<DEVICE_ID>`, Cloud-/App-Feld `di=`) ist **kein** Modbus-Register.
> Der Read-Handler bietet als geräteindividuelle Kennungen nur MAC und Gerätename an;
> die lange Device-ID wird ausschließlich in der Cloud-/MQTT-Telemetrie
> (`di=%s&sn=%s&…`) übertragen und ist nur über App/BLE bzw. den Cloud-Pfad erreichbar.

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
| 34005 (max_cell_v) | 3332 | ×0.001 | 3.332V | BMS, Offset +5 (NICHT +4!) |
| 34006 (min_cell_v) | 3330 | ×0.001 | 3.330V | BMS, Offset +6 |
| 30205 (mppt_version) | 104 | ×1 | v104 | Micro/MPPT-FW, v150-Scan bestätigt |
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
| `scan_registers.py` | Einzelne/flexible Register (auch Vollscan via `--regs 0-65535`), Watch-Modus, CSV-Export, **Live-Ausgabe + Fortschritt** | Keine (Raw-Socket) |
| `scan_known_registers.py` | Scannt nur Register aus der bekannten Register-Map-CSV (`--regmap`) | Keine (Raw-Socket) |
| `scan_continuous.py` | Dauerschleife über bekannte Register (`--interval`, default 10s) | Keine (Raw-Socket) |
| `scan_powercycle.py` | Scan über Power-Cycle-Events hinweg | Keine (Raw-Socket) |

**Hinweis (2026-07-15):** Die zuvor hier gelisteten `scan_modbus_batch.py` und `test_batch_limit.py`
existieren nicht (mehr) im Projektordner — vermutlich frühe Prototyp-Namen, die durch obige Scripts
ersetzt wurden. Das Batch-Size-Limit (32 Register, s. 3.1) ist bereits als Fakt dokumentiert und
braucht kein dediziertes Testscript mehr.

### 7.1 `scan_registers.py` — Verhalten der Ausgabe (Stand 2026-08-14)

- **Live-Ausgabe:** Jeder gefundene Wert wird **sofort beim Lesen** auf `stdout`
  gedruckt (vorher erst nach dem kompletten Scan — bei großen Bereichen minutenlang
  gar keine Ausgabe). Zusätzlich läuft eine einzeilige Fortschrittsanzeige auf
  `stderr` (`Batch x/y @ von-bis  gefunden=n`), die auch während Timeout-Lücken
  weiterläuft. Abschaltbar mit `--no-progress`.
- **Zeitstempel:** Die `timestamp`-Spalte in der CSV enthält jetzt den Zeitpunkt,
  zu dem das jeweilige Register **tatsächlich abgefragt** wurde (pro Batch erfasst) —
  nicht mehr einen einzigen Zeitstempel vom Ende bzw. Abbruch des Laufs. Bei langen
  Scans steigt die Uhrzeit also über die Zeilen an.
- **Umleiten:** Für ein sauberes Live-Log ohne den `stderr`-Fortschritt:
  `python3 scan_registers.py … 2>/dev/null` oder mit `--no-progress`. Für ein
  vollständiges Protokoll: `python3 scan_registers.py … | tee scan.log`.

### 7.2 `scan_registers.py` — Namen, Tiers & Voll-Dekodierung (Stand 2026-08-14b)

- **Vollständige Namen aus der Register-Map:** Das Script lädt beim Start
  automatisch `Marstek_Venus_D_Register_Map_Final_all_register.csv` (Suche im
  Script-Ordner, `../Modbus_RS485_TCP/` und CWD; override mit `--regmap PATH`) und
  labelt damit **alle** dokumentierten Register — nicht mehr nur den fest
  verdrahteten Fallback-Satz. Ohne Map läuft es weiter, benennt dann aber nur die
  eingebauten KNOWN-Register.
- **Konfidenz-Tiers im Output:** bekannte/verifizierte Register erscheinen mit
  klarem Namen, **vermutete mit Präfix `Verm:`**, **unbekannte mit `Unb:`**
  (abgeleitet aus der Confidence-Spalte der Map: ✅/pack-pattern → bekannt,
  🔍/📊/scan → Verm, ❓/🆕/`unknown_*` → Unb). Der Kopf zeigt die Tier-Zählung des
  Bereichs. `--unknown-only` zeigt nur noch Verm + Unb.
- **Host/Port/Slave konfigurierbar:** `--port` (Default 502), `--host`, `--slave`.
  Alle drei haben zusätzlich einen Env-Default, damit man sie nicht bei jedem Aufruf
  tippen muss: `MARSTEK_HOST`, `MARSTEK_PORT`, `MARSTEK_SLAVE`. Ein CLI-Flag
  überschreibt die Env-Variable. Beispiel: `export MARSTEK_HOST=192.168.1.100`
  dann genügt `python3 scan_registers.py --tiers verm,unb --out unklar.csv`.
- **Gezielt nach Tier scannen (`--tiers`):** wählt die Register direkt aus der Map,
  ohne Registerbereich anzugeben. `--tiers unb` = nur die unbekannten, `--tiers
  verm,unb` = alle nicht-final-bestätigten (aktuell ~130), `--tiers verm` = nur die
  vermuteten. Kombinierbar mit `--regs`/`--file` (Vereinigung). Ideal, um genau die
  offenen Register zu beobachten — am besten mit `--watch` unter wechselnder Last.
- **Voll-Dekodierung zum Erahnen (alle FW-Typen):** Für jeden Wert werden alle
  Typen berechnet, die auch der FW-`Read_Serializer` kennt —
  `u8(hi/lo) · i8(hi/lo) · u16 · i16 · hex · bin · ASCII(BE/LE) · BCD · ÷10 ÷100 ÷1000`
  sowie **mit dem Folgeregister** die 32-Bit-Kombis `u32 · i32 · float32` in beiden
  Wortreihenfolgen (`*_next_be` = dieses Register als High-Word, `*_next_le` =
  Folgeregister als High-Word). Die `f32`-Spalten filtern unplausible Bitmuster
  (NaN/inf/absurde Größenordnung) auf `-` heraus, sodass ein echtes Float-Paar
  sofort mit einem sinnvollen Wert auffällt. Im Terminal erscheint die Dekodier-Zeile
  standardmäßig bei `Verm:`/`Unb:`-Registern (`--decode-all` für alle, `--no-decode`
  aus); in der **CSV sind alle Dekodier-Spalten immer enthalten**. So erkennt man bei
  unbekannten Registern das Muster direkt: `u32_next_le` bei 33000/33001 = kWh-Zähler,
  `f32_next_le` bei einem Register-Paar = ein IEEE754-Messwert, `ascii_be` = ein String.

> **Hinweis zur Firmware (2026-08-14):** Der Modbus-FC03-Read wird über eine zur
> Laufzeit aufgebaute Descriptor-Tabelle (SRAM 0x20000354) und `Read_Serializer`
> bedient; jedes Register hat dort einen Typ (u8/u16/u32/i8/i16/i32/float/ASCII) +
> Skala + Quellzeiger, und der Serializer **kopiert nur die Registerbreite** — breite/
> float-Quellen werden also auf 16 Bit abgeschnitten (erklärt z. B. den Entladewert
> von 32101). Die Tabelle wird beim Boot aus einer kodierten Flash-Init-Struktur
> (~0x0805dcb0) entpackt; die exakte Register→Typ-Zuordnung ist statisch nicht
> trivial extrahierbar (sie stünde fertig nur in der Live-SRAM-Tabelle). Deshalb die
> Voll-Dekodierung im Scanner: sie ersetzt die fehlende Typ-Info durch „alle Varianten
> anzeigen".

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

# 6. NUR die unbekannten + vermuteten Register (aus der Map gewählt) — mit Voll-Dekodierung
python3 scan_registers.py --host 192.168.1.100 --tiers verm,unb --out unklar.csv

# 7. Nur die komplett unbekannten, live unter Last beobachten (welche Werte sich ändern = interpretierbar)
python3 scan_registers.py --host 192.168.1.100 --tiers unb --watch 10 --out unklar_watch.csv
```

---

*Stand: 2026-08-14 | Firmware Control v150 / VNS v116 / BMS v118 | Gerät: Marstek Venus D (VNSD-0)*

*Änderungen 2026-08-14: BMS-Pack-Layout korrigiert (max_cell_v auf Offset +5, charge_status auf +4),
Packs 5+6 bestätigt, 30205 = mppt_version bestätigt, `scan_registers.py` mit Live-Ausgabe + echten
Abfrage-Zeitstempeln.*

---

## Maximale FC03-Blockgröße (gemessen 2026-08-22)

Die Scan-Skripte benutzen `BATCH_SIZE = 32`, die Home-Assistant-Integration
gruppiert bis 125. Getestet war der Bereich dazwischen nie. Messung an
Control v150 über `Scripts/test_block_size.py`, Bereich ab Register 46501,
je drei Durchgänge mit Liveness-Probe auf 37012 nach jedem Versuch:

| Register im Block | Ergebnis | Schnitt |
|---|---|---|
| 8 | 3× ok | 15 ms |
| 16 | 3× ok | 6 ms |
| 24 | 3× ok | 26 ms |
| 30 | 3× ok | 6 ms |
| 32 | 3× ok | 8 ms |
| 36 | 3× ok | 5 ms |
| 40 | 3× ok | 26 ms |
| 44 | 3× ok | 7 ms |

**Kein Fehler, kein Verbindungsabbruch bis 44 Register.**

Bemerkenswert: Die Antwortzeit wächst **nicht** mit der Blockgröße — 44 Register
brauchen 7 ms, 8 Register 15 ms. Die Ausreißer bei 24 und 40 (je 26 ms) sind
Netzwerk-Jitter, kein Größeneffekt. Der begrenzende Faktor ist die
Round-Trip-Zeit, nicht die Nutzlast.

`BATCH_SIZE = 32` in den Scan-Skripten ist damit eine Vorsichtsmaßnahme, keine
Gerätegrenze. Für die Integration bleibt die Gruppierung bei 125 unbedenklich;
grössere Bloecke als 44 sind allerdings weiterhin ungeprüft.
