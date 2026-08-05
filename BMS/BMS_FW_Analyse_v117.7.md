# Marstek Venus D — BMS Firmware Analyse
## `20251010135647565eb2036.bin`

**Firmware:** BMS v117.7 (OTA `firmwareType: bms`) — **Korrektur 2026-07-09:** Dateiname/Titel nannte fälschlich "v177.7" (Tippfehler in ursprünglicher OTA-Metadaten-Vermutung, s. Abschnitt 10.3). Der hardcoded Versionswert im Binary (`0x499` = 1177) und der Live-Modbus-Scan nach dem BMS-Upgrade (Register 30204/34010 etc. = 1177) bestätigen übereinstimmend **v117.7**.  
**Analysedatum:** 06.07.2026  
**Methode:** Statische Analyse (Ghidra + ReVa MCP)  
**Status:** Erweiterte Analyse — Task-Architektur, SOC, CAN, RS485, KA495XX SPI-Treiber, Protect-Bitmasks, OTA-Update dekodiert

---

## 1. Binary-Fingerprint

Live aus Ghidra verifiziert (Stand 2026-07-15). Ein Vergleich mit den anderen fünf analysierten
Firmware-Images (Control 149.2/147, VNS 116/115, BMS 118) steht in der Projekt-`README.md`.

| Eigenschaft | Wert |
|---|---|
| Datei | `20251010135647565eb2036.bin` |
| Version | 117.7 |
| Größe | 106.496 B (0x1A000, 104 KB) |
| Architektur | ARM Cortex-M4F, Thumb-2, Little-Endian |
| Flash-Bereich | `0x08000000–0x08019FFF` |
| Initial SP | `0x2000CB90` (~52 KB SRAM) |
| Reset Handler | `0x08002A6D` |
| Funktionen | 552 / 552 benannt (100 %) |
| Strings | 260 |
| Compiler | RVDS/Keil ARM |
| RTOS | FreeRTOS (`heap_4`, `ARM_CM4F`-Port) |
| Crypto | — (keine) |
| Zellmonitoring | KA495XX (BMIC) |
| Kommunikation | CAN + RS485 |

---

## 2. FreeRTOS-Tasks (10 Tasks)

| Task | Name | Funktion |
|---|---|---|
| `RTOS_vTaskLED` | LED | Status-LED-Steuerung |
| `RTOS_vTaskKeyScan` | KeyScan | Taster/Knopf-Abfrage |
| `RTOS_vTaskCanRec` | CAN Receive | CAN-Bus Empfang (→ Inverter/Control) |
| `RTOS_vTaskCanSend` | CAN Send | CAN-Bus Senden |
| `RTOS_vTaskRS485Comm` | RS485 | RS485-Kommunikation |
| **`RTOS_vTaskSocAlgorithm`** | **SOC** | **SOC-Berechnung** (eigener Task!) |
| **`RTOS_vTaskProtectCheck`** | **Protection** | **Batterieschutz-Prüfung** |
| `RTOS_vTaskControlLogic` | Control | Lade-/Entlade-Steuerung |
| `RTOS_vTaskDataSave` | DataSave | Persistente Datenspeicherung (Flash/EEPROM) |
| **`RTOS_vTaskKA495XX`** | **BMIC** | **KA495XX Zellmonitoring-IC Treiber** |

**Besonderheiten:**
- SOC hat einen **eigenen dedizierten Task** (`vTaskSocAlgorithm`) — nicht inline berechnet
- Schutzlogik ebenfalls eigener Task (`vTaskProtectCheck`)
- KA495XX ist der Zellmonitoring-IC (ähnlich BQ769x0 / ISL94202)

---

## 3. Batterie-Messwerte & BMIC-Struktur

Aus Debug-Ausgabe-Strings extrahiert:

### 3.1 Pack-Level-Messwerte

| Format-String | Variable | Einheit | Bemerkung |
|---|---|---|---|
| `BBat Volt:%0.01fV` | bat_voltage | V | Pack-Gesamtspannung (Float) |
| `Bat Curr:%0.1fA` | bat_current | A | Pack-Strom (Float, 0.1A Auflösung) |
| `Bat Soc:%.1f` | bat_soc | % | SOC (Float, 0.1% Auflösung!) |
| `Cyc Cnt:%d` / `Cycle Count:%d` | cycle_count | — | Zyklen-Zähler |
| `Soh:%.1f` | soh | % | State of Health |
| `Total Cap:%.1f kwh` | total_capacity | kWh | Gesamtkapazität |

### 3.2 Zell-Messwerte

| Format-String | Variable | Beschreibung |
|---|---|---|
| `Cell Volt:` | cell_voltages[] | 16 Einzelzell-Spannungen |
| `Cell NTC:` | cell_ntc[] | Zell-Temperatursensoren |
| `Max Cell:%d  Min Cell:%d` | max_cell / min_cell | Zellspannungs-Extrema (mV) |

### 3.3 Temperatur-Sensoren (NTC)

| Format-String | Variable | Beschreibung |
|---|---|---|
| `Max NTC:%d  Min NTC:%d Ave NTC:%d` | max/min/avg_ntc | Pack-Temperatur-Statistiken |
| `MOS NTC:%d  ENV NTC:%d` | mos_ntc / env_ntc | MOSFET-Temperatur / Umgebung |

### 3.4 MOSFET-Status

| Format-String | Variable | Beschreibung |
|---|---|---|
| `Chg Mos:%d  Dsg Mos:%d` | chg_mos / dsg_mos | Lade-/Entlade-MOSFET Status |
| `Chg_MOS_CMD:%d` | chg_mos_cmd | Lade-MOSFET Kommando |
| `Dsg_MOS_CMD:%d` | dsg_mos_cmd | Entlade-MOSFET Kommando |

### 3.5 Schutzstatus

| Format-String | Variable | Beschreibung |
|---|---|---|
| `Protect1:%d  Protect2:%d` | protect1 / protect2 | Schutz-Bitmasks |

### 3.6 BMIC (Battery Monitor IC) Interna

| Format-String | Variable | Einheit | Beschreibung |
|---|---|---|---|
| `BMIC_Info.lBatPackFastCur_mA:%d` | fast_current | mA | Schnelle Strommessung |
| `BMIC_Info.lBatPackCur_100uA:%d` | precise_current | 100µA | Präzise Strommessung (Coulomb-Counting) |

---

## 4. SOC-Algorithmus (vollständig dekodiert)

Orchestrator: `SOC_Algorithm_Orchestrator` (346 Bytes), aufgerufen aus `RTOS_vTaskSocAlgorithm` via `SOC_Algorithm_Entry`.

### 4.1 Architektur-Überblick

```
                   ┌─────────────────────────┐
                   │  RTOS_vTaskSocAlgorithm  │
                   └────────────┬─────────────┘
                                │
                   ┌────────────▼─────────────┐
                   │   SOC_State_Detect         │
                   │   Zustandserkennung       │
                   │   → 1=Laden 2=Entladen    │
                   │   → 3=Idle                │
                   └────────────┬─────────────┘
                     ┌──────────┼──────────┐
                     ▼          ▼          ▼
              ┌──────────┐ ┌──────────┐ ┌──────────────────┐
              │ Laden    │ │ Entladen │ │ Idle (State 3)   │
              │ State 1  │ │ State 2  │ │                  │
              └────┬─────┘ └────┬─────┘ │ OCV-Korrektur    │
                   │            │       │ OCV_Correction   │
              ┌────▼────────────▼────┐  │                  │
              │ Coulomb_Counting     │  │ Nach ~1h Idle:   │
              │ Coulomb Counting     │  │ Voll-Kalibrierung│
              │ (Strom × Zeit)       │  │ Full_Recalibration│
              └────┬─────────────────┘  └────────┬─────────┘
                   │                             │
              ┌────▼─────────────────────────────▼──┐
              │ SOC_Smoothing — SOC-Glättung         │
              │ real_soc → show_soc (Smoothing)      │
              └────┬────────────────────────────────┘
                   │
              ┌────▼─────────────────────────────────┐
              │ Max_Charge_Current_Calc — Max Charge Current     │
              │ Max_Discharge_Current_Calc — Max Discharge Current  │
              └──────────────────────────────────────┘
```

### 4.2 Coulomb Counting (`Coulomb_Counting`, 334 Bytes)

**Kernformel:**
```
delta_soc = (current × time_ms) / (1800 × capacity_factor)
```

**Schritt-für-Schritt-Berechnung:**
1. `capacity_factor` = `Capacity_Factor_Calc(param_1 + 0x28)` → Kapazitätsfaktor (float)
2. `current` = `*(short *)(param_1 + 0x3E)` → Strom aus BMIC (0.1A Einheiten)
3. Guard: Wenn `capacity == 0` oder `current == 0x7FFF` → Return 0 (ungültig)
4. 64-bit Multiplikation: `raw = current × time_delta_ms`
5. Division: `raw / 36` (Zeitbasis-Konvertierung)
6. SOC-Delta: `delta = raw_coulombs / (50.0 × capacity_factor)`
7. **Remainder-Akkumulator** (`_DAT_200029E0`, float):
   - Sammelt Sub-Integer-Reste auf
   - Bei `remainder ≥ 1.0` → `delta += 1`, `remainder -= 1.0`
   - Bei `remainder ≤ -1.0` → `delta -= 1`, `remainder += 1.0`
   - **Verhindert Rundungsdrift** über lange Zeiträume

**Outputs:**
- `*param_4` = Roh-Coulomb-Zähler (für Energieberechnung)
- `*param_5` = SOC-Delta (Integer, wird zu `real_soc` addiert)
- `*param_6` = Energie-Delta (Wh)

### 4.3 Zustandsabhängige Pfade

| Zustand | Funktionen | Beschreibung |
|---|---|---|
| **1 = Laden** | `Coulomb_Counting` → `SOC_Smoothing` → `Charge_SOC_Integration` → `Charge_Energy_Calc` | Coulomb-Count + Lade-SOC-Integration + Energieberechnung |
| **2 = Entladen** | `Coulomb_Counting` → `SOC_Smoothing` → `Discharge_SOC_Integration` → `Discharge_Energy_Calc` | Coulomb-Count + Entlade-SOC-Integration + Energieberechnung |
| **3 = Idle** | `OCV_Correction` → `OCV_Voltage_To_Index` → (1h) → `Full_Recalibration` | OCV-Korrektur + (nach ~1h) Voll-Kalibrierung |

### 4.4 OCV-Kalibrierung (Idle-Zustand)

- Nach **~1 Stunde Idle** (Timer: 3.599.999 ms) wird die SOC-Kalibrierung getriggert
- `OCV_Correction` → Berechnet SOC aus **Open Circuit Voltage** (Ruhespannung)
- `OCV_Voltage_To_Index` → **Lookup-Tabelle** Spannung → SOC (im Flash gespeichert)
- `Full_Recalibration` → **Vollständige Rekalibrierung** unter Nutzung von Zellspannungs-Schwellwerten
  aus Flash-Tabelle bei `0x0801B79C` (Charge-Threshold) / `0x0801B832` (Discharge-Threshold)

### 4.5 SOC SRAM-Map (0x20004A38–0x20004A78)

Aus `soc_algorithm_dump` (`soc_algorithm_dump`, 106 Bytes) extrahiert:

| SRAM | Variable | Typ | Scale | Beschreibung |
|---|---|---|---|---|
| `0x20004A38` | **real_soc** | u32 | **÷10000** | Berechneter SOC (Coulomb-basiert) |
| `0x20004A3C` | **show_soc** | u32 | **÷10000** | Angezeigter SOC (geglättet) |
| `0x20004A40` | max_soc | u32 | ÷10000 | Maximaler SOC |
| `0x20004A44` | min_soc | u32 | ÷10000 | Minimaler SOC |
| `0x20004A48` | target_soc | u32 | ÷10000 | Ziel-SOC (Kalibrierung) |
| `0x20004A5C` | cycle_count | u32 | ×1 | Zyklen-Zähler |
| `0x20004A60` | soh | u32 | ÷10 | State of Health (%) |
| `0x20004A64` | total_capacity | u32 | ÷10 | Kapazität (kWh) |
| `0x20004A68` | max_chg_current | u16 | ÷10 | Max. Ladestrom (A) |
| `0x20004A6A` | max_dsg_current | u16 | ÷10 | Max. Entladestrom (A) |
| `0x20004A6C` | max_cell_volt | u16 | mV | Höchste Zellspannung |
| `0x20004A6E` | min_cell_volt | u16 | mV | Niedrigste Zellspannung |
| `0x20004A70` | avg_temp | i16 | °C | Durchschnitts-Temperatur |
| `0x20004A72` | max_temp | i16 | °C | Max. Temperatur |
| `0x20004A74` | min_temp | i16 | °C | Min. Temperatur |
| `0x20004A76` | current | i16 | ÷10 → A | Aktueller Strom |
| `0x20004A78` | tail_voltage | u16 | ÷10 → V | Tail-Spannung (Lade-Ende) |
| `0x20004B1C` | full_flag | u32 | Bit0 | Vollladungs-Erkennung |

### 4.6 SOC-Konvertierungskette (real_soc → Modbus)

```
64-bit Double (interne Berechnung, sub-0.01% Präzision)
  ↓ Quantisierung
u32 real_soc @ 0x20004A38 (÷10000, z.B. 146000 = 14.6%)
  ↓ Glättung/Filterung (SOC_Smoothing)
u32 show_soc @ 0x20004A3C (÷10000, geglättet)
  ↓ Division durch 1000
u16 @ 0x20004A14 (÷10, für CAN TX — Wert 146 = 14.6%)
  ↓ CAN Bus (PF=1, Bytes 6-7)
Micro-MCU SRAM 0x20003981
  ↓ Telemetrie-Block Offset 0x0E (via Per-Pack-Struct)
Control-MCU SRAM 0x20014E90+Descriptor-Offset
  ↓ Modbus Descriptor-Tabelle
**Register 34002** (Scale ×0.1 → 146 = 14.6%)
```

**Erkenntnis für HA-Integration:** Der SOC-Wert im Modbus-Register ist `show_soc`, nicht `real_soc`.
Nach Lade-/Entladepausen kann `show_soc` für einige Sekunden "hängenbleiben", weil die
Glättungsfunktion den Wert nur langsam nachführt. Dies ist **kein Bug**, sondern gewolltes Verhalten
zur Vermeidung von SOC-Sprüngen in der Benutzeranzeige.

### 4.7 OCV-Lookup-Tabelle & Kalibrier-Flash

> Alle Kalibrierdaten liegen im Flash-Bereich `0x0801B73C`–`0x0801BA48+`, **jenseits des
> FW-Binaries** (endet bei `0x08019FFF`). Die Daten sind fabrik-kalibriert, zellchemie-spezifisch
> und werden bei FW-Updates nicht überschrieben.

#### Quick-OCV-Tabelle (`Quick_OCV_Lookup`)

**Adresse:** `0x0801B73C`–`0x0801B773` (56 Bytes)
**Format:** 7 Einträge × 8 Bytes = `[voltage_index (u32)] [soc_value (u32)]`

```
Algorithmus:
  1. Zellspannung → Index via OCV_Voltage_To_Index: index = voltage / 51.2
  2. Suche ersten Eintrag wo index <= voltage_threshold
  3. Lineare Interpolation zwischen benachbarten Einträgen:
     soc = soc[n-1] + (soc[n] - soc[n-1]) × (index - volt[n-1]) / (volt[n] - volt[n-1])
  4. Ergebnis × 10000 → u32 SOC (÷10000 = %)
```

**Aufrufkette:** Idle-Timer (1h) → `OCV_Correction` → `OCV_Voltage_To_Index` (index) → `Quick_OCV_Lookup` (lookup)

#### Haupt-OCV-Kalibriertabelle (`Full_OCV_Lookup`)

**Adresse:** `0x0801B774`–`0x0801B845` (210 Bytes)
**Format:** 21 Einträge × 10 Bytes = 5 × u16 pro Zeile

```
Zeile (10 Bytes):
  ┌──────────┬────────────┬────────────┬────────────┬────────────┐
  │ SOC (u16)│ Volt_Chg   │ Volt_Dsg   │ Volt_Idle  │ Volt_Col4  │
  │ Offset+0 │ Offset+2   │ Offset+4   │ Offset+6   │ Offset+8   │
  └──────────┴────────────┴────────────┴────────────┴────────────┘
  × 21 Zeilen (vermutl. 0%, 5%, 10%, ..., 100%)
```

**4 Spannungs-Spalten** für verschiedene Betriebsmodi:
- **Spalte 1** (param_2=1): Lade-OCV-Kurve (höhere Spannung bei gleichem SOC)
- **Spalte 2** (param_2=2): Entlade-OCV-Kurve (niedrigere Spannung bei gleichem SOC)
- **Spalte 3** (param_2=3): Ruhe/Idle-OCV-Kurve
- **Spalte 4** (param_2=4): Reserve/Kalibrierung

**Interpolation:** Identisch zur Quick-Tabelle, aber mit Moduswahl über `param_2`.

#### Temperatur-Strom-Limit-Matrizen

**Temperatur-Index-Tabelle:** `0x0801B846`
- Zugriff: `Temperature_Index_Lookup(0, &index, temperature/10, 0x801B846)`
- Konvertiert Temperatur (°C÷10) → Matrix-Zeilenindex

**Lade-Temperatur-Bereiche:** `0x0801B86A`
- Format: u16-Array, Schwellwerte für Temperaturzonen
- Zugriff: `*(u16)(zone * 2 + 0x801B86A)`

**Ladestrom-Matrix:** `0x0801B884`
- Format: 2D-Matrix, Stride 0x18 (24 Bytes/Zeile = 12 × u16)
- Zugriff: `temp_index * 0x18 + 0x801B884 + soc_zone * 2`
- Ergebnis: max. erlaubter Ladestrom für Temperatur × SOC-Bereich

**Entladestrom-Temperatur-Tabelle:** `0x0801BA34`
- Separate Temperatur-Indexierung für Entlade-Limits

**Entladestrom-Matrix:** `0x0801BA48`
- Format: 2D-Matrix, Stride 10 (5 × u16 pro Zeile)
- Zugriff: `temp_index * 10 + 0x801BA48 + soc_zone * 2`
- Ergebnis: max. erlaubter Entladestrom

#### Vollständiges Kalibrier-Flash-Layout

```
0x0801B73C ┌───────────────────────────────────────────┐
           │ Quick OCV Table (7 × 8 = 56 Bytes)       │
0x0801B774 ├───────────────────────────────────────────┤
           │ Full OCV Table (21 × 10 = 210 Bytes)     │
           │  └── 4 Spalten: Chg/Dsg/Idle/Reserve     │
0x0801B846 ├───────────────────────────────────────────┤
           │ Temperature Index Table                    │
0x0801B86A ├───────────────────────────────────────────┤
           │ Charge Temperature Ranges                  │
0x0801B884 ├───────────────────────────────────────────┤
           │ Charge Current Limit Matrix (24B/row)     │
0x0801BA34 ├───────────────────────────────────────────┤
           │ Discharge Temperature Index                │
0x0801BA48 ├───────────────────────────────────────────┤
           │ Discharge Current Limit Matrix (10B/row)  │
           └───────────────────────────────────────────┘
```

> **Zum Auslesen der Werte:** Flash-Dump via SWD/JTAG-Probe oder über die Debug-Shell
> (UART CMD `bat_data` zeigt einige SOC-Werte). Alternativ: RS485 CMD 0x2E sendet 84 Bytes
> Per-Pack-Daten, die möglicherweise Kalibrierungsparameter enthalten.

### 4.8 SOC-Kalibrierung bei Multi-Pack Round-Robin-Betrieb

Das Venus D lädt/entlädt die Packs im **Round-Robin-Verfahren** — jeweils ~10% pro Pack,
dann Rotation zum nächsten. Die Frage ist: wie bleibt der SOC trotzdem kalibriert?

#### Pro-Pack-Unabhängigkeit

Jeder BMS-Pack läuft seine **eigene `RTOS_vTaskSocAlgorithm`-Instanz**. Es gibt keinen
zentralen SOC-Koordinator. Während ein Pack aktiv ist, zählt sein BMIC Coulombs;
die anderen Packs sind im Idle-State (State 3) und warten.

#### 4 Kalibrier-Mechanismen

**1. Coulomb-Counting mit Remainder-Akkumulator (primär)**
- Der Float-Rest (`_DAT_200029E0`) wird über beliebig viele kurze Zyklen aufaddiert
- Selbst bei 30-Sekunden-Rotationen geht kein Bruchteil verloren
- BMIC-Auflösung: 100µA → bei 10A Last = 0.001% Auflösung pro Messung
- **Round-Robin ist kein Problem** — jeder Pack zählt seine eigenen As unabhängig

**2. Full-Flag-Anker (100%-Reset)**
- Wenn `show_soc > 99.4%` UND `full_flag` gesetzt → SOC gecapped auf 1000 (= 100.0%)
- Code in `PerPack_Struct_Builder` Zeile 40–43: `if (show_soc > 0x3E2 && full_flag) → soc = 1000`
- Jeder volle Ladezyklus ist ein Reset-Punkt
- Round-Robin: jeder Pack erreicht irgendwann 100% und kalibriert sich dort

**3. Nächtliche OCV-Kalibrierung (sekundär)**
- Trigger: 1 Stunde kontinuierliches Idle (Timer: 3.599.999 ms)
- Nachts (kein Solar, kein Verbrauch) gehen alle Packs gleichzeitig in Idle
- Die 4 OCV-Spalten berücksichtigen den vorherigen Betriebszustand
- 21 Stützpunkte mit linearer Interpolation

**4. Tail-Voltage-Erkennung**
- `tail_voltage` (`0x20004A78`) erkennt das Ende der Ladekurve
- Wenn Strom bei hohem SOC exponentiell abfällt → zweiter 100%-Anker
- Unabhängig vom Full-Flag

#### Schwachstelle: LiFePO4 Mittelbereich

Die OCV-Kurve von LiFePO4-Zellen ist im Bereich 20–80% extrem flach (~3.2V ± 20mV).
Selbst mit 21-Punkt-Tabelle und 4 Modi-Spalten ist die Spannungs→SOC-Auflösung dort gering.

**Konsequenz:** Wenn ein Pack über Wochen nie 100% oder 0% erreicht (weil die Rotation ihn
zwischen 30–70% hält), kann der Coulomb-Zähler langsam driften. Die nächtliche OCV-Korrektur
fängt das teilweise auf, aber die Korrektur-Genauigkeit im Mittelbereich ist begrenzt.

**Beobachtbarer Effekt:** Packs zeigen manchmal leicht unterschiedliche SOC-Werte trotz
gleicher Energiemenge — das ist **kein Bug**, sondern eine inhärente Limitation des
Coulomb-Counting bei flacher Spannungskurve ohne regelmäßige Vollladungs-Kalibrierung.

### 4.9 Round-Robin-Mechanismus (aus FW verifiziert)

> Die Rotation wird **nicht** vom BMS selbst gesteuert. Jeder BMS-Pack ist ein passiver
> Empfänger von Aktivierungs-Kommandos. Die Orchestrierung liegt bei der Micro/Inverter-MCU,
> die über CAN-Kommandos einzelne Packs adressiert.

#### Pack-Modus-Register (`DAT_200028CA`)

| Wert | Modus | Beschreibung |
|------|-------|-------------|
| 0 | **Idle** | MOSFETs aus, Pack wartet auf Aktivierung |
| 1 | **Transitional** | Übergangszustand (Handoff zum nächsten Pack) |
| 2 | **Active** | MOSFETs ein, Pack lädt/entlädt aktiv |
| 3 | **Shutdown** | Schlafmodus (Watchdog-Timeout) |
| 4 | **Error** | Fehlerzustand (erzwungener Stop) |

#### CAN-Kommando-basierte Pack-Aktivierung (`CAN_CMD_Pack_Activation`)

**Adress-Matching (Zeile 19–20):**
```c
if (((uVar2 & 0xFFF) >> 8 == DAT_200041B6) ||   // Match eigene Adresse
    ((uVar2 & 0xFFF) >> 8 == 0xF) ||              // Broadcast (0xF)
    ((uVar2 & 0xFFF) >> 8 == 0))                   // Broadcast (0x0)
```

Die CAN-Nachricht enthält die **Ziel-Pack-Adresse** in Bits 8–11 der Daten.
Die Micro-MCU kann damit gezielt einzelne Packs ansprechen.

**Aktivierung (CAN CMD 6):**
```c
if (bVar1 == 6) {
    if (DAT_200028CA == 0 && DAT_200028E3 < 11) {
        DAT_200028CA = 2;    // Idle → Active!
    }
}
```
Guard: Nur wenn Pack im Idle-Modus UND weniger als 11 Fehler-Events.

**Handoff zum nächsten Pack (CAN CMD 3):**
```c
if (DAT_200028CA == 2 &&                              // Pack ist aktiv
    *(byte*)(param_1 + 0xB) == DAT_200041B6 + 1) {   // Daten-Byte = NÄCHSTE Pack-Adresse
    DAT_200028D9 = 1;                                  // "Ready for handoff" Flag
}
```
Das Daten-Byte der CAN-Nachricht enthält die Adresse des **nächsten** Packs.
Der aktuelle Pack setzt ein Bereitschafts-Flag und bereitet die MOSFET-Abschaltung vor.

#### Vollständiger Round-Robin-Flow

```
Micro-MCU (Inverter) orchestriert den Zyklus:

1. CAN CMD 6 → Pack 1 (Addr-Match)     Pack 1: Idle → Active (MOSFETs EIN)
   Pack 2-6: bleiben Idle                     ↓ Laden/Entladen für ~10% SOC
                                               ↓
2. CAN CMD 3 → Pack 1 (data=Pack2-Addr) Pack 1: DAT_200028D9 = 1 (Handoff-Ready)
                                               ↓ MOSFET-Abschaltung vorbereiten
                                               ↓
3. CAN CMD 6 → Pack 2 (Addr-Match)     Pack 2: Idle → Active (MOSFETs EIN)
   Pack 1: Active → Idle                      ↓ Laden/Entladen für ~10% SOC
                                               ↓
4. CAN CMD 3 → Pack 2 (data=Pack3-Addr) Pack 2: Handoff-Ready
                                               ↓
5. ... (wiederholt für alle Packs)             ↓
                                               ↓
N. CAN CMD 3 → Pack 6 (data=Pack1-Addr) Pack 6: Handoff → zurück zu Pack 1
```

#### Architektur-Erkenntnis

```
Control-MCU (EMS)
  │ RS485: "Lade mit 2000W"
  ↓
Micro-MCU (Inverter)
  │ Entscheidet: welcher Pack, wann wechseln
  │ CAN CMD 6: Pack N aktivieren
  │ CAN CMD 3: Pack N → Pack N+1 Handoff
  ↓
BMS Master (Pack 1)
  │ RS485 CMD 0x29: Weiterleitung an Slaves
  ↓
BMS Slaves (Pack 2-7)
  │ MOSFET ein/aus gemäß Modus
  ↓
Batterie-Packs (physisch am DC-Bus)
```

> **Die Micro-MCU ist der Rotations-Orchestrator.** Sie entscheidet, wann ein Pack
> genug geladen/entladen hat und aktiviert den nächsten. Die Control-MCU gibt nur
> die Gesamt-Leistung vor; die Pack-Selektion ist Aufgabe der Micro-MCU.

#### Verifizierte Timer (aus Micro-FW `FUN_0800d834`)

| Timer | SRAM | Timeout | Funktion |
|---|---|---|---|
| Haupt-Zyklus | `0x20000470` | 3600s (60 Min) | Richtungsentscheidung: SOC<50%→Laden, SOC≥50%→Entladen |
| Entlade-Sub | `0x20000472` | 600s (10 Min) | CAN-Update an BMS während Entladung |
| Lade-Sub | `0x20000474` | 600s (10 Min) | CAN-Update an BMS während Ladung |

#### Auswirkung auf PV-Einspeisung

Die Strom-Limit-Matrix im Kalibrier-Flash (`0x0801B884`, 2D: Temperatur × SOC-Zone)
reduziert den erlaubten Ladestrom progressiv bei steigendem SOC. Da der Venus D nur
**einen bidirektionalen Leistungspfad** hat (kein separater PV→Grid-Pfad), führt die
BMS-Drosselung dazu, dass PV-Leistung ab ~90% SOC zunehmend gedrosselt wird:

```
SOC  50% → charge_current_limit = 50A → Inverter: -2500W → PV voll genutzt
SOC  80% → charge_current_limit = 30A → Inverter: -1500W → PV teilweise gedrosselt
SOC  95% → charge_current_limit = 5A  → Inverter: -250W  → PV stark gedrosselt
SOC 100% → charge_current_limit = 0A  → Inverter: 0W     → PV komplett gedrosselt
→ Richtungswechsel nach Timer → Entladen → PV fließt wieder ins Grid
```

> Detaillierte Analyse der DC-Bus-Architektur und PV-Verhalten: siehe
> `Micro_Inverter_FW_Analyse_vd_inv_app_0116.md`, Sektion 12.7

---

## 5. Schutzlogik & Protect-Bitmasks (vollständig dekodiert)

### 5.1 Protect-Register Architektur

```
Protection-Checker Tasks  →  3 Status-Bytes  →  2 Bitmask-Builder  →  Per-Pack Struct  →  CAN TX
                              DAT_200028C1        Protect1_Bitmask_Builder  0x2000420C          PF=4
                              DAT_200028C2        Protect2_Bitmask_Builder  0x2000420E          Bytes 0-3
                              DAT_200028C3
```

**Status-Bytes (Schutz-Quellen):**
- `DAT_200028C1` — Strom-Schutz (gesetzt von `Current_Protection_Checker`, 544 Bytes)
- `DAT_200028C2` — Spannungs-/Strom-Schutz (gesetzt von `Voltage_Temp_Protection_Checker`)
- `DAT_200028C3` — Temperatur-Schutz (gesetzt von `HW_Overcurrent_Protection`)

### 5.2 Protect1 Bitmask (`Protect1_Bitmask_Caller` → `Protect1_Bitmask_Builder`)

| Bit | Wert | Source | Verifiziert aus | Schutzart |
|-----|------|--------|----------------|-----------|
| 0 | 0x0001 | C1 bit 5 | BMIC/KA495XX HW-Register | **Zell-Überspannung (Cell OVP)** |
| 1 | 0x0002 | C1 bit 6 | BMIC/KA495XX HW-Register | **Zell-Unterspannung (Cell UVP)** |
| 2 | 0x0004 | C1 bit 1 | `Current_Protection_Checker`: `current > DAT_200049C8` | **Lade-Überstrom L2 (Charge OCP)** |
| 3 | 0x0008 | C1 bit 0 | `Current_Protection_Checker`: `|current| > DAT_200049B8` | **Entlade-Überstrom L2 (Discharge OCP)** |
| 4 | 0x0010 | C2 bit 5 | `Voltage_Temp_Protection_Checker`: `max_cell_ntc > DAT_20004978` (Laden aktiv) | **Lade-Übertemperatur (Charge OTP)** |
| 5 | 0x0020 | C2 bit 6 | `Voltage_Temp_Protection_Checker`: `max_cell_ntc < threshold` (Laden aktiv) | **Lade-Untertemperatur (Charge UTP)** |
| 6 | 0x0040 | C2 bit 3 | `Voltage_Temp_Protection_Checker`: `max_cell_ntc > threshold` (Entladen aktiv) | **Entlade-Übertemperatur (Discharge OTP)** |
| 7 | 0x0080 | C2 bit 4 | `Voltage_Temp_Protection_Checker`: `max_cell_ntc < threshold` (Entladen aktiv) | **Entlade-Untertemperatur (Discharge UTP)** |
| 8 | 0x0100 | C2 bit 0 | `Voltage_Temp_Protection_Checker`: `mos_ntc > DAT_20004958` | **MOS-Übertemperatur (MOS OTP)** |
| 9 | 0x0200 | C1 bit 2 | `voltage_protection_check`: GPIOC.2=LOW + GPIOC.1=HIGH | **Kurzschluss HW (SCP, 25× Debounce!)** |
| 10 | 0x0400 | C3 bit 7 | `HW_Overcurrent_Protection`: GPIOD.5=LOW + `current > 3A` | **HW Lade-Überstrom + Relais** |
| 11 | 0x0800 | C3 bit 6 | `HW_Overcurrent_Protection`: GPIOC.1=LOW + `current < -3A` | **HW Entlade-Überstrom + Relais** |

### 5.3 Protect2 Bitmask (`Protect2_Bitmask_Builder`)

| Bit | Wert | Source | Verifiziert aus | Schutzart |
|-----|------|--------|----------------|-----------|
| 9 | 0x0200 | C3 bit 5 | `HW_Overcurrent_Protection`: MOS/ENV NTC >150.1°C oder <-30.1°C | **NTC Über-Bereich (Sensor-Fehler)** |
| 11 | 0x0800 | C3 bit 3 | — (Setter nicht identifiziert) | **Temperatur-Schutz Stufe 3** |
| 12 | 0x1000 | C2 bit 2 | `Voltage_Temp_Protection_Checker`: `env_ntc > DAT_20004940` | **Umgebungs-Übertemperatur (ENV OTP)** |
| 14 | 0x4000 | `DAT_20002901` ≠ 0 | Direkt geprüft | **Kommunikationsfehler** |
| 15 | 0x8000 | `DAT_20002A0F/10` ≠ 0 | Direkt geprüft | **Kritischer Fehler / Error-Lock** |

### 5.4 2-Stufen-Schutzsystem

```
Stufe 1: WARNUNG (C5/C6 → Warning-Register via Warning_Bitmask_Builder)
  → Schwellwerte niedriger, kürzere Timeouts
  → Setzt nur Warn-Flags, kein MOSFET-Abschalten

Stufe 2: SCHUTZ (C1/C2/C3 → Protect1/2 via Protect1_Bitmask_Caller/Protect2_Bitmask_Builder)
  → Schwellwerte höher, längere Timeouts
  → Schaltet Lade-/Entlade-MOSFETs ab
  → Bei Kurzschluss: Hardware-Abschaltung via KA495XX GPIO
```

**Verified Temperature Thresholds (aus `Voltage_Temp_Protection_Checker`):**

| SRAM (Threshold) | Messwert-Quelle | Schutzart | Für C-Byte |
|---|---|---|---|
| `0x20004954` | MOS NTC (`0x200041D6`) | MOS Übertemp SET (L1) | C5 |
| `0x20004958` | MOS NTC | MOS Übertemp SET (L2) | C2 bit 0 |
| `0x2000495C` | MOS NTC | MOS Übertemp CLEAR | Recovery |
| `0x2000493C` | ENV NTC (`0x200041D8`) | ENV Übertemp SET (L1) | C6 |
| `0x20004940` | ENV NTC | ENV Übertemp SET (L2) | C2 bit 2 |
| `0x20004944` | ENV NTC | ENV Übertemp CLEAR | Recovery |
| `0x20004948` | ENV NTC | ENV Untertemp SET (L1) | C6 |
| `0x2000494C` | ENV NTC | ENV Untertemp SET (L2) | C2 bit 1 |
| `0x20004950` | ENV NTC | ENV Untertemp CLEAR | Recovery |
| `0x20004978` | Max Cell NTC (`0x200041C8`) | Cell Lade-Übertemp | C2 bit 5 |

**Verified Current Thresholds (aus `Current_Protection_Checker`):**

| SRAM (Threshold) | Messwert-Quelle | Schutzart | Für C-Byte |
|---|---|---|---|
| `0x200049B6` | Pack-Strom (`0x20004202`) | Entlade-Überstrom L1 | C6 bit 6 |
| `0x200049B8` | Pack-Strom | Entlade-Überstrom L2 | C1 bit 0 |
| `0x200049BA` | Pack-Strom | Entlade-Überstrom L3 | C1 bit 0 |
| `0x200049C2` | — | Entlade-Überstrom Recovery | Recovery |
| `0x200049C6` | Pack-Strom | Lade-Überstrom L1 | C6 bit 7 |
| `0x200049C8` | Pack-Strom | Lade-Überstrom L2 | C1 bit 1 |
| `0x200049CA` | Pack-Strom | Lade-Überstrom L3 | C1 bit 1 |
| `0x200049D2` | — | Lade-Überstrom Recovery | Recovery |

### 5.5 Unterspannungsschutz-Flow

Aus Debug-Strings und `Current_Protection_Checker`/`Voltage_Temp_Protection_Checker`:

```
g_u16UvMinVolt fällt unter Schwelle
  → g_u8UvChgIndex++ (Stufenzähler)
  → Wenn Grenzwert erreicht:
      g_u8UvpAllowCutDmosFlag = 1
      → Entlade-MOSFET wird abgeschaltet (Dsg_MOS_CMD = 0)
      → "error lock set" → Dauerhafter Fehlerzustand
      → Reset nur über "error lock reset" oder Power-Cycle
```

### 5.6 Per-Pack Struct Befüllung (`PerPack_Struct_Builder`, 580 Bytes)

Zusätzliche Erkenntnisse aus der Struct-Builder-Funktion:

| Struct-Offset | Quelle | Konvertierung | Beschreibung |
|---|---|---|---|
| 0x0E (SOC) | `_DAT_20004AD0` (show_soc u16) | direkt | Cap bei 1000 (=100%) wenn >994 UND full_flag |
| 0x10 (MOSFET) | `DAT_20004B1C` Bits 2-3 | Bit-Mapping | Charge(Bit1)/Discharge(Bit0) Status |
| 0x10 (MOSFET) | `DAT_200028C1` Bits 5-6 | Bits 2-3 | OV/UV Protection aktiv |
| 0x10 (MOSFET) | GPIO `0x40010C00` Bit 1 | Bit 4 | Hardware-MOSFET-Status |
| 0x10 (MOSFET) | GPIO `0x40011000` Bit 5 | Bit 5 | Hardware-MOSFET-Status |
| 0x4A (Bat Volt) | `_DAT_200040B4` | **÷10** | Quelle in mV, Ziel in 0.01V |
| 0x4C (Bat Curr) | `_DAT_2000406C` | **÷1000** | Quelle in µA (BMIC), Ziel in 0.1A |
| 0x54 (Version) | Hardcoded `0x499` | — | **= 1177 → Version 117.7** |

---

## 6. CAN-Protokoll (vollständig dekodiert)

> Die CAN-TX-Daten bei `0x20004Axx` sind eine **Aggregation** über alle Packs.
> Die per-Pack-Rohdaten liegen in der Cell-Data-Struct (Sektion 6.0).

Alle TX-Funktionen (`CAN_TX_PF1_PackMeasurements`–`CAN_TX_PF4_ProtectWarnings`) und der RX-Handler (`CAN_RX_Handler`)
wurden dekompiliert. Sender-Orchestrierung: `CAN_TX_Orchestrator` ruft alle 4 TX-Funktionen sequentiell auf.

### 6.0 Per-Pack Datenstruktur (96 Bytes / 0x60)

Aus der Debug-Dump-Funktion `bms_data_printf` (`bms_data_printf`, 770 Bytes) extrahiert.
Iteriert über `pack_count` (`DAT_200028DB`) Packs.

**Struct-Base:** `0x200041B6 + pack_index × 0x60`

| Offset | SRAM (Pack 0) | Typ | Scale | Debug-Name | Beschreibung |
|--------|--------------|------|-------|------------|-------------|
| 0x00 | `0x200041B6` | u8 | — | Addr | Pack-Adresse/ID |
| 0x01 | `0x200041B7` | u8 | — | Online | Verbindungs-Status (0/1) |
| 0x02 | `0x200041B8` | 12B | — | (UID) | Board-UID aus OTP `0x1FFFF270` |
| 0x0E | `0x200041C4` | **u16** | **÷10** | **Bat Soc** | **SOC (0.1% Einheiten!)** |
| 0x10 | `0x200041C6` | u8 | bits | Chg/Dsg Mos | Bit5=Charge, Bit4=Discharge MOSFET |
| 0x12 | `0x200041C8` | i16 | °C | Max NTC | Max. Temperatur |
| 0x14 | `0x200041CA` | i16 | °C | Min NTC | Min. Temperatur |
| 0x16 | `0x200041CC` | i16[5] | °C | Cell NTC[0–4] | 5 Temperatursensoren (10 Bytes) |
| 0x20 | `0x200041D6` | i16 | °C | MOS NTC | MOSFET-Temperatur |
| 0x22 | `0x200041D8` | i16 | °C | ENV NTC | Umgebungstemperatur |
| 0x24 | `0x200041DA` | u16 | — | Cyc Cnt | Zyklen-Zähler |
| 0x26 | `0x200041DC` | **u16[16]** | **mV** | **Cell Volt[0–15]** | **16 Einzelzell-Spannungen (32B)** |
| 0x46 | `0x200041FC` | u16 | mV | Max Cell | Höchste Zellspannung |
| 0x48 | `0x200041FE` | u16 | mV | Min Cell | Niedrigste Zellspannung |
| 0x4A | `0x20004200` | u16 | **÷100→V** | Bat Volt | Pack-Spannung (0.01V) |
| 0x4C | `0x20004202` | i16 | **÷10→A** | Bat Curr | Pack-Strom (0.1A) |
| 0x4E | `0x20004204` | i16 | °C | Ave NTC | Durchschnitts-Temperatur |
| 0x50–0x53 | `0x20004206` | 4B | — | — | (Lücke, unbekannt) |
| 0x54 | `0x2000420A` | u16 | — | Version | BMS-Pack-FW-Version |
| 0x56 | `0x2000420C` | u16 | bits | Protect1 | Schutz-Bitmask 1 |
| 0x58 | `0x2000420E` | u16 | bits | Protect2 | Schutz-Bitmask 2 |
| 0x5A–0x5F | — | 6B | — | — | (Padding) |

**Scale-Faktoren aus Debug-Print-Konvertierungen bestätigt:**
- SOC: `VectorUnsignedToFloat(raw) / 10.0` → **Scale ×0.1** (bestätigt Modbus Reg 34002!)
- Bat Volt: `VectorUnsignedToFloat(raw) / 100.0` → **Scale ×0.01**
- Bat Curr: `VectorSignedToFloat(raw) / 10.0` → **Scale ×0.1**
- Cell Volt: direkt in mV (kein Divisor) → **Scale ×0.001** für Volt

**Multi-Pack-Speicher (bis 8 Packs):**
```
Pack 0: 0x200041B6 – 0x20004215
Pack 1: 0x20004216 – 0x20004275
Pack 2: 0x20004276 – 0x200042D5
  ...
Pack 7: 0x200044B6 – 0x20004515
→ Aggregierte CAN-TX-Daten: 0x20004A0C – 0x20004A32
```

### 6.0.1 Vermutete Zuordnung Struct → Modbus-Register

| Struct-Offset | Feld | Pack 1 Reg | Pack 2 Reg | Scale |
|---|---|---|---|---|
| 0x4A (Bat Volt) | pack_voltage | **34000** | **34100** | ×0.01 |
| 0x4C (Bat Curr) | pack_current | **34001** | **34101** | ×0.1 |
| 0x0E (Bat Soc) | pack_soc | **34002** | **34102** | **×0.1** |
| 0x24 (Cyc Cnt) | cycle_count | **34003** | **34103** | ×1 |
| 0x54 (Version) | bms_version | **34010** | **34110** | ×1 |
| — (Cell NTC 0-3, MOS/ENV/Avg NTC) | cell_ntc_0..3, mos_ntc, env_ntc, avg_ntc | **34011–34017** | **34111–34117** | ÷10 °C |
| 0x26 (Cell[0]) | cell_volt_1 | **34018** | **34118** | ×0.001 |
| 0x28 (Cell[1]) | cell_volt_2 | **34019** | **34119** | ×0.001 |
| ... | ... | ... | ... | ... |
| 0x44 (Cell[15]) | cell_volt_16 | **34033** | **34133** | ×0.001 |
| — (Msg 1, undokumentiert, s. §6.1) | charge_status | **34004** | **34104** | ×1 |
| 0x46 (Max Cell) | max_cell_volt | **34005** | **34105** | ×0.001 |
| 0x48 (Min Cell) | min_cell_volt | **34006** | **34106** | ×0.001 |
| 0x12 (Max NTC) | max_ntc | **34007** | **34107** | ×1 |
| 0x14 (Min NTC) | min_ntc | *(kein eigenes Modbus-Register — s. Korrektur unten)* | | ×1 |

> **Korrektur (2026-07-10, per Ghidra + Live-Scan-CSV verifiziert):** Die Register 34004–34007 waren
> fälschlich um 1 verschoben (34004?=max_cell, 34005?=min_cell, 34006?=max_ntc, 34007?=min_ntc — alles
> unsicher markiert). Ursache: Der CAN-Sender `CAN_TX_PerPack_10Msgs` (`0x08005af0`) sendet zwischen
> Msg 0 (`0x1820AAxx`) und Msg 2 (`0x1822AAxx`) noch eine bisher **undokumentierte Msg 1** (`0x1821AAxx`,
> Struct-Offsets 0x50/0x52/0x10 + ein aus `bat_curr` berechnetes Lade-/Entlade-Flag). Diese belegt
> Register 34004 — dazu passt exakt der Live-Scan-Befund für 34004 (`pack1_charge_status`,
> „=3 genau wenn Pack aktiv lädt, =0 wenn idle. Nicht Spannungsdelta!"). Dadurch verschiebt sich
> Msg 2 (max_cell_volt/min_cell_volt/max_ntc) um je ein Register nach hinten auf 34005–34007;
> für „min_ntc" (Msg 2 Byte 6-7, Offset 0x14) existiert laut CSV **kein** eigenes Modbus-Register
> (34008/34009 sind bereits eindeutig protect1/protect2 aus Msg 3, dort keine Verschiebung nötig).

> **Korrektur (2026-07-10, per Ghidra + Live-Scan-CSV verifiziert):** Ursprünglich wurden die 16 Zellspannungen
> hier fälschlich auf 34011–34026 gemappt (Off-by-7-Fehler). Der Live-Scan (`Marstek_Venus_D_Register_Map_Final_claude_generated.csv`,
> ✅ FW-verified) zeigt eindeutig: 34011–34017 enthalten die 7 NTC-Temperaturwerte (Werte im Bereich 190–400,
> passend zu ÷10°C), während 34018–34033 die 16 Zellspannungen enthalten (Werte im Bereich 3190–3400,
> passend zu ×0.001V für Li-Ion-Zellen). `BLE_Modbus_CrossReference.md` hatte den korrekten Offset (34018–34033)
> bereits dokumentiert; diese Datei war die abweichende/falsche Quelle.

### 6.1 BMS → Inverter (TX, Extended Frame)

CAN-ID-Format: `0x18 0x PF AA 01` — BMS (Adresse `0xAA`) sendet an Inverter (Adresse `0x01`).

#### PF=1: Pack-Messwerte (`0x1801AA01`) — `CAN_TX_PF1_PackMeasurements`

| Byte | BMS SRAM | Typ | Inhalt |
|------|----------|-----|--------|
| 0–1 | `0x20004A0C` | u16 | **bat_voltage** (Pack-Spannung, 0.01V) |
| 2–3 | `0x20004A0E` | i16 | **bat_current** (Pack-Strom, 0.01A) |
| 4–5 | `0x20004A10` | i16 | **max_temperature** (°C) |
| 6–7 | `0x20004A14` | u16 | **soc** (Scale 0.1%, Show-SOC!) |

#### PF=2: Kapazität & Pack-Info (`0x1802AA01`) — `CAN_TX_PF2_Capacity`

| Byte | BMS SRAM | Typ | Inhalt |
|------|----------|-----|--------|
| 0–1 | berechnet | u16 | **design_capacity** = (pack_count+1) × cell_cap × 512 / 10 |
| 2 | `0x200028DB` +1 | u8 | **pack_count** + 1 |
| 3–4 | `0x200028DC` | u16 | (unbekannt, u16) |
| 5 | `0x20002A11` +1 | u8 | (Counter + 1) |
| 6 | `0x200028E0` | u8 | (Konfigwert, über CAN CMD 0x1003 setzbar) |
| 7 | `0x200028D0` | u8 | (Status-Byte) |

> **Kapazitäts-Berechnung:** `(DAT_200028DB + 1) * _DAT_20004AE4 * 0x200 / 10`
> wobei `_DAT_20004AE4` die Zell-/Modulkapazität ist und `0x200 = 512` ein Skalierungsfaktor.

#### PF=3: Lade-/Entlade-Limits (`0x1803AA01`) — `CAN_TX_PF3_ChargeDischargeLimits`

| Byte | BMS SRAM | Typ | Inhalt |
|------|----------|-----|--------|
| 0–1 | `0x20004A16` | u16 | **charge_voltage_limit** (max 0x261 = 609 → capped!) |
| 2–3 | `0x20004A18` / 0xFA | u16 | **charge_current_limit** (250 bei Fehler) |
| 4–5 | `0x20004A1C` / 0 | u16 | **discharge_current_limit** (0 bei Fehler) |
| 6 | `0x20002A6C` | u8 | **cell_status_flags** (Bit0: alle Zellen voll, Bit1: Zelle bei 0) |
| 7 | berechnet | u8 | **combined_flags** (Bit0: FUN_058A4 Ergebnis, Bit1: charge_mode==2 && !flag) |

**Cell-Voltage-Scan-Logik (Zeilen 23–30):**
```
Für jede Zelle (0..pack_count):
  if cell_voltage == 1000 → full_count++
  if cell_voltage == 0    → empty_count++
→ Bit0 von cell_status_flags = (full_count >= pack_count)
```
Zell-Daten-Struct: `DAT_200041C4 + cell_index * 0x60` (96 Bytes pro Zelle/Modul!)

#### PF=4: Schutz & Warnungen (`0x1804AA01`) — `CAN_TX_PF4_ProtectWarnings`

| Byte | BMS SRAM | Typ | Inhalt |
|------|----------|-----|--------|
| 0–1 | `0x20004A30` | u16 | **protect1** (Schutz-Bitmask 1) |
| 2–3 | `0x20004A32` | u16 | **protect2** (Schutz-Bitmask 2) |
| 4–5 | — | u16 | (reserviert, immer 0) |
| 6 | `0x20002894` | u8 | **warn_byte** |
| 7 | `0x20002A71` | u8 | **status_flag** |

### 6.2 Inverter/Control → BMS (RX) — `CAN_RX_Handler`

CAN-ID-Formate:
- `0x10 PF 01 AA` — Direkte Kommandos an BMS (Adresse `0xAA`)
- `0x18 01 xx AA` — Relayed/Periodische Nachrichten

#### Direkte Kommandos (`0x10xxyyAA`)

| CAN-ID | PF | Handler | Beschreibung |
|--------|------|---------|-------------|
| `0x100101AA` | 01 | `CAN_CMD_01_Handler(byte)` | Einzel-Byte-Kommando |
| `0x100201AA` | 02 | `CAN_CMD_02_Handler(byte)` | Einzel-Byte-Kommando (anderer Handler) |
| `0x100301AA` | 03 | `DAT_200028E0 = byte` + `KA495XX_Write_Balancing_Register()` | Konfigwert setzen |
| `0x100401AA` | 04 | `CAN_CMD_04_Handler(data_ptr)` | Multi-Byte-Daten-Handler |
| `0x100501AA` | 05 | `DAT_20002A70 = 1` (nur wenn byte==1) | Einfaches Flag setzen |

#### Relay/Periodic (`0x1801xxAA`)

| CAN-ID | PS | Beschreibung |
|--------|------|-------------|
| `0x180101AA` | 01 | Invoke Periodic-Send mit Adressbyte |
| `0x180102AA` | 02 | Invoke Periodic-Send (von Inverter) |
| `0x180103AA` | 03 | Invoke Periodic-Send |
| `0x180104AA` | 04 | Invoke Periodic-Send |
| `0x180106AA` | 06 | Invoke Periodic-Send |
| `0x1801FFAA` | FF | **FW-Update-Trigger**: `DAT_20002A72=1`, Pack-ID=data[1] |

### 6.3 CAN-Adressierung

| Adresse | Bedeutung |
|---|---|
| `0x01` | Inverter (Micro-MCU) |
| `0xAA` | BMS (Standard-Adresse) |
| `0xFF` | Broadcast / FW-Update |

### 6.4 BMS SRAM-Zusammenfassung (CAN-relevante Adressen)

| SRAM | Variable | Quelle | Beschreibung |
|---|---|---|---|
| `0x20004A0C` | bat_voltage | ADC/BMIC | Pack-Spannung (u16) |
| `0x20004A0E` | bat_current | ADC/BMIC | Pack-Strom (i16) |
| `0x20004A10` | max_temperature | NTC-Scan | Max. Temperatur (i16) |
| `0x20004A14` | show_soc | SOC-Task | Angezeigter SOC (u16, ×0.1%) |
| `0x20004A16` | charge_volt_limit | Protection | Ladespannungs-Grenze (u16, max 609) |
| `0x20004A18` | charge_curr_limit | Protection | Ladestrom-Grenze (u16) |
| `0x20004A1C` | discharge_curr_limit | Protection | Entladestrom-Grenze (u16) |
| `0x20004A24` | cell_count | Config | Anzahl Zellen/Module |
| `0x20004A30` | protect1 | Protection | Schutz-Bitmask 1 (u16) |
| `0x20004A32` | protect2 | Protection | Schutz-Bitmask 2 (u16) |
| `0x20004AE4` | cell_capacity | Config | Zell-/Modulkapazität |
| `0x200041C4` | cell_data[0] | BMIC | Zell-Daten-Array (96B pro Zelle!) |
| `0x200028DB` | pack_count | Config | Anzahl zusätzliche Packs (total = +1) |
| `0x200028DC` | pack_online_mask | Watchdog | Bitmask online Packs (Bit pro Pack) |
| `0x200028E0` | config_value | CAN CMD 03 | Über CAN setzbarer Konfigwert |
| `0x20002894` | warn_byte | Protection | Warnungs-Byte |
| `0x20002A6C` | cell_status_flags | berechnet | Bit0: alle voll, Bit1: leere Zelle |
| `0x20002A71` | status_flag | Control | Allgemeines Status-Flag |

### 6.5 Multi-Pack Per-Pack CAN-Protokoll (vollständig dekodiert)

> **Neu.** Sender-Funktion `CAN_TX_PerPack_10Msgs` (1.868 Bytes!) sendet **10 CAN-Nachrichten pro Pack**.
> Aufgerufen von `CAN_TX_Orchestrator`: bei `param_1 == 0xFF` (Broadcast) für alle Packs,
> sonst für einen einzelnen Pack.

#### CAN-ID-Kodierung

```
CAN-ID = 0x18 [MsgGroup] AA [PackID]

PackID:  1-basiert (1 = Pack 1, 2 = Pack 2, ... max 9)
MsgGroup: 0x20-0x23 = Pack-Übersicht (4 Nachrichten)
          0x30-0x33 = Zell-Spannungen (4 Nachrichten × 4 Zellen = 16 Zellen)
          0x40-0x41 = Temperaturen (2 Nachrichten)
AA:      BMS-Adresse (fest 0xAA)
```

**Beispiele:**
- Pack 1 Übersicht Msg 0: `0x1820AA01`
- Pack 1 Zellen 0–3:     `0x1830AA01`
- Pack 2 Übersicht Msg 0: `0x1820AA02`
- Pack 3 Zellen 12–15:   `0x1833AA03`

#### 10 CAN-Nachrichten pro Pack

**Msg 0 — Pack-Übersicht (`0x1820AA0x`):**

| Byte | Struct-Offset | Inhalt | Scale |
|------|---------------|--------|-------|
| 0–1 | 0x4A | **bat_volt** (Pack-Spannung) | ×0.01 V |
| 2–3 | 0x4C | **bat_curr** (Pack-Strom) | ×0.1 A |
| 4–5 | 0x0E | **bat_soc** (SOC) | ×0.1 % |
| 6–7 | 0x24 | **cycle_count** | ×1 |

**Msg 1 — Limits & Status (`0x1821AA0x`):**

| Byte | Struct-Offset / Quelle | Inhalt |
|------|------------------------|--------|
| 0–1 | `_DAT_20004A16` (global) | **charge_volt_limit** |
| 2–3 | 0x50 | **field_0x50** (unknown, `DAT_20004206`) |
| 4–5 | 0x52 | **field_0x52** (unknown, `DAT_20004208`) |
| 6 | 0x10 (Bits) | MOSFET-Status (Bit0: OV_active, Bit1: UV_active) |
| 7 | berechnet | Lade-/Entladerichtung: 0=Idle, 1=Laden (>5), 2=Entladen (<-5) |

**Msg 2 — Zell-Extrema & Temperatur (`0x1822AA0x`):**

| Byte | Struct-Offset | Inhalt | Scale |
|------|---------------|--------|-------|
| 0–1 | 0x46 | **max_cell_volt** | mV |
| 2–3 | 0x48 | **min_cell_volt** | mV |
| 4–5 | 0x12 | **max_ntc** | °C |
| 6–7 | 0x14 | **min_ntc** | °C |

**Msg 3 — Schutz & Version (`0x1823AA0x`):**

| Byte | Struct-Offset | Inhalt |
|------|---------------|--------|
| 0–1 | 0x56 | **protect1** (Bitmask, s. Sektion 5.2) |
| 2–3 | 0x58 | **protect2** (Bitmask, s. Sektion 5.3) |
| 4–5 | 0x5A | **field_0x5A** (`DAT_20004210`) |
| 6–7 | 0x54 | **version** (z.B. 0x499 = v117.7) |

**Msg 4–7 — 16 Zell-Spannungen (`0x1830AA0x` – `0x1833AA0x`):**

| CAN-ID | Byte 0–1 | Byte 2–3 | Byte 4–5 | Byte 6–7 |
|--------|----------|----------|----------|----------|
| `0x1830` | **Cell[0]** (0x26) | **Cell[1]** (0x28) | **Cell[2]** (0x2A) | **Cell[3]** (0x2C) |
| `0x1831` | **Cell[4]** (0x2E) | **Cell[5]** (0x30) | **Cell[6]** (0x32) | **Cell[7]** (0x34) |
| `0x1832` | **Cell[8]** (0x36) | **Cell[9]** (0x38) | **Cell[10]** (0x3A) | **Cell[11]** (0x3C) |
| `0x1833` | **Cell[12]** (0x3E) | **Cell[13]** (0x40) | **Cell[14]** (0x42) | **Cell[15]** (0x44) |

Alle Zellspannungen in **mV** (Scale ×0.001 für Volt).

**Msg 8 — NTC-Temperaturen (`0x1840AA0x`):**

| Byte | Struct-Offset | Inhalt |
|------|---------------|--------|
| 0–1 | 0x16 | **ntc[0]** (Cell NTC 0) |
| 2–3 | 0x18 | **ntc[1]** (Cell NTC 1) |
| 4–5 | 0x1A | **ntc[2]** (Cell NTC 2) |
| 6–7 | 0x1C | **ntc[3]** (Cell NTC 3) |

**Msg 9 — Erweiterte Temperaturen (`0x1841AA0x`):**

| Byte | Struct-Offset | Inhalt |
|------|---------------|--------|
| 0–1 | 0x4E | **avg_temp** (Durchschnitt) |
| 2–3 | 0x22 | **env_ntc** (Umgebung) |
| 4–5 | 0x20 | **mos_ntc** (MOSFET) |
| 6–7 | — | (Padding, 0) |

#### Multi-Pack-Adressierung

| Parameter | SRAM | Beschreibung |
|---|---|---|
| `DAT_200028DB` | pack_count | Anzahl **zusätzlicher** Packs (0 = nur Master) |
| `_DAT_200028DC` | pack_online_mask | Bitmask: Bit n = Pack n online |
| Struct-Basis | `0x200041B6 + (pack_id - 1) × 0x60` | Per-Pack Struct (1-basiert) |
| Max Packs | 9 | `if (param_1 != 0 && param_1 < 10)` |
| Broadcast | `0xFF` | Sendet für alle Packs |

**Pack-Online-Watchdog** (aus `Pack_Online_Watchdog`):
- Für jeden Pack (1..pack_count): Timer bei `0x20004B20 + pack × 2`
- Timeout: 19.999 ms (~20s) → Pack wird als offline markiert
- `_DAT_200028DC &= ~(1 << pack)` → Bit gelöscht
- `*(0x200041B7 + pack × 0x60) = 0` → Online-Flag in Struct gelöscht

#### Mapping Per-Pack CAN → Modbus-Register

Die Control-MCU empfängt die Per-Pack-Nachrichten und mapped sie auf Modbus-Register
nach dem Schema `34000 + pack_index × 100 + field_offset`:

| CAN Msg | CAN-ID Pack 1 | Modbus Pack 1 | Modbus Pack 2 | Inhalt |
|---|---|---|---|---|
| Msg 0 B0-1 | `0x1820AA01` | **34000** | **34100** | bat_volt |
| Msg 0 B2-3 | | **34001** | **34101** | bat_curr |
| Msg 0 B4-5 | | **34002** | **34102** | bat_soc |
| Msg 0 B6-7 | | **34003** | **34103** | cycle_count |
| Msg 1 (undok.) | `0x1821AA01` | **34004** | **34104** | charge_status (Lade-/Entlade-Flag, s. Korrektur §6.0.1) |
| Msg 2 B0-1 | `0x1822AA01` | **34005** | **34105** | max_cell |
| Msg 2 B2-3 | | **34006** | **34106** | min_cell |
| Msg 2 B4-5 | | **34007** | **34107** | max_ntc |
| Msg 2 B6-7 | | *(kein Register)* | | min_ntc |
| Msg 3 B0-1 | `0x1823AA01` | **34008** | **34108** | protect1 |
| Msg 3 B2-3 | | **34009** | **34109** | protect2 |
| Msg 3 B6-7 | | **34010** | **34110** | version |
| Msg 4 B0-1 | `0x1830AA01` | **34018** | **34118** | cell[0] |
| Msg 4 B2-3 | | **34019** | **34119** | cell[1] |
| ... | | ... | ... | ... |
| Msg 7 B6-7 | `0x1833AA01` | **34033** | **34133** | cell[15] |

> **Korrektur (2026-07-10):** Offset war fälschlich 34011–34026 (s. Anmerkung in §6.0.1). Register
> 34011–34017 sind stattdessen die NTC-Temperaturwerte, s. korrigierte Tabelle oben.

---

## 7. RS485-Protokoll (vollständig dekodiert)

Dispatcher: `RS485_Dispatcher` (1.614 Bytes, 346 Zeilen). Wird von den RX-Handlern
beider RS485-UARTs aufgerufen (USART2 `0x40004400` = Haupt-Bus, UART4 `0x40004C00` = Inter-Pack,
s. §7.3) — **Korrektur 2026-07-10:** ist NICHT an USART1/`0x40013000` gebunden; diese Adresse ist
laut Ghidra eindeutig SPI1 (KA495XX-Anbindung, s. §8.1), nicht USART1.

### 7.1 Frame-Format

```
┌──────┬────────┬─────────┬──────────┬──────────────┬──────────┐
│ Sync │ Length │ Command │ Address  │ Data[0..N-1] │ Checksum │
│ 's'  │ u8     │ u8      │ u8       │ var          │ u8       │
│ 0x73 │ 4-1024 │ 0x00-   │ PackID / │              │ XOR/Sum  │
│      │        │  0x34   │ 0xFF=BC  │              │          │
└──────┴────────┴─────────┴──────────┴──────────────┴──────────┘
```

- **Sync:** `'s'` (0x73) — fest
- **Length:** Gesamtlänge (4–1024 Bytes)
- **Command:** Kommando-ID (0x00–0x34)
- **Address:** Pack-Adresse (`DAT_200041B6`), `0xFF` = Broadcast, `0xFE` = Broadcast Typ 2
- **Checksum:** Verifiziert via `LIB_XOR_Checksum` (letzte Byte = berechneter Wert)

Antwort-Frame via `RS485_Send_Response(port, source_addr, cmd, data_ptr, data_len)`.

### 7.2 Kommando-Tabelle

#### Status-Abfragen (Read)

| CMD | Hex | Response-Len | Inhalt | Beschreibung |
|-----|-----|-------------|--------|-------------|
| 0 | 0x00 | 6 B | GPIO-Status + `_DAT_200040D8` (u32) | MOSFET/Hardware-Status |
| 1 | 0x01 | 1 B | `0x41` ('A') | Alive-Ping (ACK) |
| 7 | 0x07 | 1 B | `0x00` | Simple Status (immer 0) |
| 8 | 0x08 | 1 B | GPIO GPIOC Bit 13 | Pin-Zustand lesen |
| 9 | 0x09 | 6 B | `DAT_200028C1`–`C6` | **Protection-Status-Bytes** (6 Bytes!) |

#### Batterie-Daten (Read)

| CMD | Hex | Response-Len | Inhalt | Beschreibung |
|-----|-----|-------------|--------|-------------|
| 24 | 0x18 | 4 B | `DAT_20004070` | BMIC-Rohdaten |
| 25 | 0x19 | 34 B | 32B Zellspannungen + 2B Status | **16 Zellspannungen** (u16 × 16, mV) |
| 26 | 0x1A | 14 B | 5×NTC÷10 + MOS÷10 + ENV÷10 | **Alle Temperaturen** (7 Werte, ÷10→°C) |
| 27 | 0x1B | 1 B | `SOC ÷ 10` (0–100) | **Quick-SOC** (1 Byte!) |
| 44 | 0x2C | 10 B | `DAT_20003C64` (3×u32 + u16) | Energiezähler-Daten |

#### Pack-Daten-Transfer (Bidirektional)

| CMD | Hex | Len | Inhalt | Beschreibung |
|-----|-----|-----|--------|-------------|
| 41 | 0x29 | **97 B** | Addr + 96B Per-Pack-Struct | **Voll-Struct-Transfer** zwischen Packs |
| 46 | 0x2E | **85 B** | Addr + 84B Detail-Daten | **Per-Pack Detail-Dump** (via `RS485_Pack_Telemetry_Response`) |
| 48 | 0x30 | **45 B** | Addr + 44B aggregierte CAN-Daten | **CAN-TX-Daten-Dump** (ab `0x20004A0C`) |

> **CMD 0x29** ist das Herzstück der Inter-Pack-Kommunikation: der Master-BMS
> empfängt die vollständige 96-Byte-Struct jedes Slave-Packs und speichert sie bei
> `DAT_200041B6 + (pack_id - 1) × 0x60`. So hat der Master stets ein aktuelles
> Abbild aller angeschlossenen Packs.

> **CMD 0x30** sendet die aggregierten CAN-TX-Daten (44 Bytes ab `0x20004A0C`)
> — vermutlich die Antwort, die die Control-MCU periodisch abfragt.

#### Konfiguration (Read/Write)

| CMD | Hex | R/W | Inhalt | Beschreibung |
|-----|-----|-----|--------|-------------|
| 15 | 0x0F | R/W | `DAT_200028BC` (1 B) | Konfig-Byte lesen/schreiben |
| 30 | 0x1E | Write | 2B → `DAT_200049F2` | Parameter schreiben |
| 31 | 0x1F | Read | 2B ← `DAT_200049F2` | Parameter lesen |
| 32 | 0x20 | Write | 2B → `DAT_20004A06` | Parameter schreiben |
| 33 | 0x21 | Read | 2B ← `DAT_20004A06` | Parameter lesen |
| 36 | 0x24 | Write | 1B SOC (0–100) | **SOC manuell setzen** |
| 37 | 0x25 | Write | 1B DOD-Wert | DOD setzen (nur wenn `DAT_200028CA == 1`) |
| 45 | 0x2D | Write | 10B → `DAT_20003C64` | Energiezähler schreiben |
| 49 | 0x31 | Write | 1B → Mode-Set | Modus setzen (Relay zu anderem Port) |

#### Steuerung & System

| CMD | Hex | Beschreibung |
|-----|-----|-------------|
| 2 | 0x02 | **HARD RESET** (DSB + Endlosschleife → Watchdog-Reset) |
| 5 | 0x05 | FW-Update Init (Magic `0xA1` + `0xB1` bei Byte 4-5) |
| 6 | 0x06 | Multi-Pack-State Reset (nur Master, Addr=1) |
| 10 | 0x0A | Flash-Operation: 1=FW-Update, sonst=Data-Save |
| 14 | 0x0E | Pack-Adresse zuweisen |
| 52 | 0x34 | Hardware-Test: GPIO-Toggle + 80ms Verzögerung |

### 7.3 UART-Zuordnung

| Peripherie | SRAM-Handle | Funktion | Baudrate |
|---|---|---|---|
| USART1 (`0x40013800`) | — | **Debug-Shell** (letter-shell) | — |
| USART2 (`0x40004400`) | `0x20002BC4` | **RS485 Haupt-Bus** (→ Micro/Inverter MCU) | 9600 baud |
| UART4 (`0x40004C00`) | `0x200033EC` | **RS485 Inter-Pack** (→ BMS Slaves) | 9600 baud |

> **Korrektur (2026-07-10, Ghidra-verifiziert):** USART1 war fälschlich mit `0x40013000` dokumentiert —
> das ist nachweislich die SPI1-Basisadresse (s. §8.1, KA495XX-Treiber: `SPI1_Init`, `HAL_SPI1_TransmitReceive_Byte`
> etc. referenzieren `0x40013000` explizit und ausschließlich). Der generische USART-Init-Code
> (`USART_Init_Config`/`USART_SPI_Clock_Reset`) akzeptiert `0x40013800` als gültige USART-Basisadresse —
> das ist die korrekte USART1-Adresse (Standard-STM32-Peripherie-Layout, passt auch zu USART1=`0x40013800`
> in der Micro-Inverter-FW, s. `Micro_Inverter_FW_Analyse_vd_inv_app_0116.md`).

> **Korrektur:** `0x40004C00` ist auf STM32F4xx **UART4**, nicht USART3 wie zuvor dokumentiert.
> UART4 RX-Handler (`UART4_RX_Process`) prüft auf 's'-Marker und dispatcht an `RS485_Dispatcher(3)`.

### 7.4 Inter-Pack-Kommunikation (Master↔Slave)

```
        USART2 (RS485 Haupt-Bus, 9600 baud)
Master BMS ◄══════════════════►  Micro-MCU (Inverter)
(Pack 1)                            │
  │                                 └──► Control-MCU (→ Modbus TCP)
  │
  │  CAN-Bus (500 kbit/s)
  ├──────────────► Micro-MCU (parallel zu RS485)
  │
  │  UART4 (RS485 Inter-Pack, 9600 baud)
  ├══════════════════► Slave BMS Pack 2
  ├══════════════════► Slave BMS Pack 3
  ├══════════════════► ...
  └══════════════════► Slave BMS Pack 7
```

**Flow:**
1. Master-BMS pollt Slave-Packs über RS485 CMD `0x29` (→ 96-Byte Struct)
2. Master aggregiert alle Pack-Daten in `0x20004Axx` (CAN-TX-Puffer)
3. Master sendet über CAN (PF 1-4 aggregiert + Per-Pack Msg 0-9)
4. Micro-MCU leitet an Control-MCU weiter (Telemetrie-Block)
5. Control-MCU exponiert als Modbus-Register

| Variable | Beschreibung |
|---|---|
| `g_u8UpgradeFlag` | FW-Upgrade aktiv |
| `g_u8UpdateFinishFlag` | Update abgeschlossen |
| `g_u8ProhibitCommFlag` | Kommunikation während Update gesperrt |
| `u8FactoryFlag` | Werksmodus-Flag |
| `Force Index:%d` | Erzwungener Update-Index |

---

## 8. KA495XX SPI-Treiber (vollständig dekodiert)

### 8.1 Hardware-Anbindung

| Parameter | Wert |
|---|---|
| SPI-Peripherie | SPI1 (`0x40013000`) |
| Chip-Select | GPIOB Pin 4 (Software-CS) |
| Chip-Typ | "KA495XX" (Korea Analog Semiconductor) — exakter Typ nur per PCB bestimmbar |
| RTOS-Task | `RTOS_vTaskKA495XX` → `RTOS_vTaskKA495XX` → `KA495XX_Main_StateMachine` (State Machine) |

### 8.2 SPI-Protokoll

**Single-Register-Read** (`KA495XX_SPI_Read_Single_Reg`, 230B):

```
TX: [0xE1] [(reg & 0x7F) << 1] [CRC]    (3 Bytes)
RX: [Status] [Data_Hi] [Data_Lo]          (3 Bytes, 16-bit Wert)
```

- Command-Byte `0xE1` = Read-Befehl (konstant)
- Adressierung: 7-bit Register-Adresse, links-shifted um 1 Bit
- CRC wird über Command + Adress-Byte berechnet
- CS (GPIOB.4): Low vor TX, High nach RX

**Bulk-Register-Read** (`KA495XX_SPI_Bulk_Read`, 314B):

```
TX: [0xE1] [(start_reg & 0x7F) << 1 | 0x01] [CRC] [0x00...]    (4+ Bytes)
RX: [N × 2 Bytes Daten] [CRC]
```

- Bit 0 des Adress-Bytes = Burst-Flag
- Typischer Aufruf: `(1, 0x59)` = ab Register 1, 89 Register lesen (178 Daten-Bytes)

### 8.3 Register-Map (partiell dekodiert)

Aus `KA495XX_Read_CellVoltages_And_Temps` (674B) — Zell-/Temperatur-/Strom-Readout:

| Register | Inhalt | Anzahl | Bemerkung |
|---|---|---|---|
| 0x1C | Status/WDT | 1 | Bit 7 = Conversion-Complete Flag |
| 0x28–0x37 | Zellspannungen | 16 | cell_volt[0..15], je 16-bit |
| 0x3E | Temperatur-Sensor 1 | 1 | NTC |
| 0x44 | Temperatur-Sensor 2 | 1 | NTC |
| 0x47 | Pack-Strom | 1 | Coulomb-Counting-Eingang |
| 0x49 | Temperatur-Sensor 3 | 1 | NTC |
| 0x4A | Temperatur-Sensor 4 | 1 | NTC |
| 0x4B | Temperatur-Sensor 5 | 1 | NTC |
| 0x58–0x59 | Strom-Kalibrierung | 2 | Offset/Gain? |

### 8.4 Task State Machine (15 States)

`KA495XX_Main_StateMachine` (186B) — Hauptschleife, aufgerufen aus `RTOS_vTaskKA495XX`:

| State | Aktion | Funktion |
|---|---|---|
| 0 | Init + Status-Clear | `APP_Clear_SOC_Accumulator_Arrays` + `KA495XX_ClearMinMaxArrays` + `KA495XX_Check_And_Clear_Watchdog` (Reg 0x1C WDT) |
| 1, 3, 5, 7, 9, 11 | ADC-Konversion starten | `KA495XX_ADC_Conversion_Trigger` (Trigger + Warte auf Conversion-Complete) |
| 2, 4, 6, 8, 10, 12 | Zell-Readout | `KA495XX_Read_CellVoltages_And_Temps` (16 Zellspannungen + 5 Temperaturen + Strom) |
| 13 | Datenverarbeitung | `KA495XX_Compute_ADC_Offsets` + `KA495XX_Scale_To_Millivolts` + `KA495XX_Compute_Power_And_Energy` + `NTC_Convert_Active_Sensors` → Mittelwerte, dann `PerPack_Struct_Builder` |
| 14 | Maintenance | `KA495XX_Read_Status_And_Check_Balancing` (Bulk-Dump 89 Reg) + `KA495XX_Read_Fault_Status` (Balancing) + Diagnostik |
| Default | Reset | 100ms Delay (`LIB_vTaskDelayWithAssert`), zurück zu State 0 |

**6 ADC-Zyklen pro Durchlauf** (States 1–12): Jeder Zyklus triggert eine ADC-Konversion und liest die Ergebnisse. Die 6 Samples werden in State 13 gemittelt — effektive Rauschunterdrückung.

**Zykluszeit:** ~600ms ADC + Verarbeitung + 100ms Delay ≈ **~700ms pro komplettem Messzyklus**.

---

## 8b. BMS OTA Firmware-Update (dekodiert)

### Trigger-Sequenz

```
1. CAN RX (ID 0x1801FFAA)
   └── CAN_RX_Handler (CAN_RX_Handler, Zeile 52-59)
       └── Setzt DAT_20002a72 (Dead-Flag) → OTA-Bereitschaft

2. RS485 CMD 0x05 (Magic-Bytes)
   └── RS485_Dispatcher (Zeilen 111-122)
       ├── Byte[4] == 0xA1 → setzt DAT_20002831 (OTA Unlock)
       └── Byte[4] == 0xB1 → alternative OTA-Freischaltung

3. OTA Precondition Manager (OTA_Precondition_Manager, 342B)
   └── State Machine via DAT_200028ad
       └── Prüft Unlock-Flag, bereitet Flash vor
```

### Flash-Writer (`BMS_OTA_Flash_Writer`, 910B)

| Sub-CMD | Funktion | Details |
|---|---|---|
| 0 | **Init** | Flash Unlock, Sektor ab `0x0801E000` löschen |
| 1 | **Data** | 8 Bytes pro Paket schreiben (Double-Word-Aligned) |
| 2 | **Verify** | CRC/Prüfsumme über geschriebenen Bereich |

**Ziel-Adresse:** `0x0801E000` — liegt **außerhalb** des aktuellen App-Bereichs (`0x08000000–0x08019FFF`), vermutlich Staging-Bereich für neuen Bootloader oder Second-Stage.

> **Sicherheitsrelevant:** OTA erfordert sowohl CAN-Trigger (Dead-Flag) als auch RS485 Magic-Bytes — Dual-Channel-Authentifizierung.

---

## 9. Debug-Shell (UART)

Gleiche letter-shell-Bibliothek wie Micro-FW (mit "default user", Passwort vermutlich leer).

### Shell-Befehle

| Befehl | Beschreibung |
|---|---|
| `bat_data` | BMS-Daten ausgeben (`BMS_Data_Printf`) |
| `set_soc` | SOC manuell setzen (`Set_BMS_Soc`) |
| `set_dod` | Depth of Discharge setzen (`Set_BMS_DOD`) |
| `checkout_rs485` | RS485-Modus konfigurieren (`Set_Rs485_Mode`) |
| `force` | Erzwungene Aktion |
| `clear` | Konsole löschen |
| `help` | Befehlsliste anzeigen |

### Debug-Ausgabe-Blöcke

**Block 1 — Online-Status:**
```
Online:%d
Version:%d
```

**Block 2 — Pack-Übersicht:**
```
BBat Volt:%0.01fV
Bat Curr:%0.1fA
Bat Soc:%.1f
Cyc Cnt:%d
Chg Mos:%d  Dsg Mos:%d
Max NTC:%d  Min NTC:%d Ave NTC:%d
MOS NTC:%d  ENV NTC:%d
Max Cell:%d  Min Cell:%d
Cell NTC: [16 Werte]
Cell Volt: [16 Werte]
Protect1:%d  Protect2:%d
```

**Block 3 — SOC-Details:**
```
Max Vol:%d  Min Vol:%d
Ave Temp:%d  Max Temp:%d  Min Temp:%d
Current:%.1f
Tal Vol:%.1f
FMax Soc:%lf  Min Soc:%lf
Real Soc:%lf  Tar Soc:%lf  Show Soc:%lf
Full Flag:%d
Soh:%.1f
Total Cap:%.1f kwh
Max Chg Cur:%.1f  Max Dsg Cur:%.1f
Cycle Count:%d
```

---

## 10. Relevanz für Modbus-Register (34000–34600)

Die BMS-Daten werden über das Per-Pack CAN-Protokoll (Sektion 6.5, 10 Nachrichten pro Pack)
an die Micro-MCU und von dort an die Control-MCU gesendet, die sie als Modbus-Register exponiert.

### 10.1 Bestätigte Register-Zuordnung (aus Live-Scan + FW-Analyse)

| CAN Msg | Struct-Offset | BMS Variable | Pack 1 | Pack 2 | Scale | Bestätigt? |
|---|---|---|---|---|---|---|
| Msg 0 B0-1 | 0x4A | bat_voltage | **34000** | **34100** | ×0.01→V | ✅ Scan: 5114=51.14V |
| Msg 0 B2-3 | 0x4C | bat_current | **34001** | **34101** | ×0.1→A | ✅ Scan: 0 |
| Msg 0 B4-5 | 0x0E | **show_soc** | **34002** | **34102** | **×0.1→%** | ✅ Scan: 146=14.6% |
| Msg 0 B6-7 | 0x24 | cycle_count | **34003** | **34103** | ×1 | ✅ Scan: 19 |
| Msg 1 B6-7 (undok.) | — | charge_status | **34004** | **34104** | ×1 | ✅ Bestätigt (Live-Scan-CSV: „=3 bei aktivem Laden, =0 bei idle") |
| Msg 2 B0-1 | 0x46 | max_cell_volt | **34005** | **34105** | ×0.001→V | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 2 B2-3 | 0x48 | min_cell_volt | **34006** | **34106** | ×0.001→V | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 2 B4-5 | 0x12 | max_ntc | **34007** | **34107** | ×1→°C | ✅ Bestätigt (Live-Scan-CSV, Wert konstant 0) |
| Msg 2 B6-7 | 0x14 | min_ntc | *(kein Modbus-Register)* | | ×1→°C | — |
| Msg 3 B0-1 | 0x56 | protect1 | **34008** | **34108** | Bitmask | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 3 B2-3 | 0x58 | protect2 | **34009** | **34109** | Bitmask | ✅ Bestätigt (Live-Scan-CSV + Entlade-Test) |
| Msg 3 B6-7 | 0x54 | bms_version | **34010** | **34110** | ×1 | ✅ Bestätigt (v116/v117.7) |
| Msg 4-7 | 0x26-0x44 | cell_volt[0–15] | **34018–34033** | **34118–34133** | ×0.001→V | ✅ Bestätigt (Live-Scan-CSV, korrigiert 2026-07-10) |
| Msg 8 | 0x16-0x1C | ntc[0–3] | **34011–34014** | **34111–34114** | ÷10→°C | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 9 B0-1 | 0x4E | avg_temp | **34017** | **34117** | ÷10→°C | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 9 B2-3 | 0x22 | env_ntc | **34016** | **34116** | ÷10→°C | ✅ Bestätigt (Live-Scan-CSV) |
| Msg 9 B4-5 | 0x20 | mos_ntc | **34015** | **34115** | ÷10→°C | ✅ Bestätigt (Live-Scan-CSV) |

> **Korrektur (2026-07-10):** Cell-Voltage-Offset war fälschlich 34011–34026 (Off-by-7-Fehler, verwechselt
> mit dem NTC-Block). Register-Zuordnung jetzt anhand `Marstek_Venus_D_Register_Map_Final_claude_generated.csv`
> (✅ FW-verified) korrigiert und die zuvor offenen NTC-Register (Msg 8/9) ergänzt.
>
> **Korrektur 2 (2026-07-10, per Ghidra-Dekompilierung von `CAN_TX_PerPack_10Msgs`, `0x08005af0`,
> gegen Live-Scan-CSV verifiziert):** 34004–34007 waren ebenfalls um 1 verschoben (max_cell_volt
> fälschlich bei 34004 statt 34005 usw.). Ursache: Zwischen Msg 0 und Msg 2 sendet der BMS-CAN-Stack
> eine bisher undokumentierte **Msg 1** (`0x1821AAxx`) mit u.a. einem aus `bat_current` berechneten
> Lade-/Entlade-Flag — dieses belegt Register 34004, exakt passend zum Live-Scan-Befund für
> `pack1_charge_status` (CSV-Notiz: „=3 genau wenn Pack aktiv lädt, =0 wenn idle. Nicht Spannungsdelta!").
> Msg 1 hat noch 3 weitere, bislang nicht Modbus-zugeordnete Felder (Struct-Offsets 0x50, 0x52, 0x10),
> die hier nicht weiter aufgelöst wurden. Für „min_ntc" (Msg 2 Byte 6-7, Offset 0x14) existiert laut
> CSV kein separates Register — 34008/34009 sind eindeutig protect1/protect2 (Msg 3), keine weitere
> Verschiebung dorthin.

### 10.2 SOC-Konvertierungskette (bestätigt)

```
BMS: double real_soc (64-bit FP, sub-0.01% Präzision)
  → u32 ÷10000 (4 Dezimalstellen intern)
  → Glättung → u32 show_soc ÷10000
  → Cap bei 100.0% (wenn >99.4% UND full_flag)
  → u16 ÷10 (für CAN TX, Wert z.B. 146 = 14.6%)
  → CAN Msg 0 Bytes 4-5 (PF=1 aggregiert + Per-Pack)
  → Micro-MCU → Control-MCU
  → Modbus Register 34002 (Scale ×0.1)
```

### 10.3 Version-Hinweis

Die im Binary hardcoded Version ist `0x499` = **1177** (dezimal), was **v117.7** entspricht.
Die Dateiname-Version v177.7 weicht davon ab — war ein Tippfehler/Vermutungsfehler bei
der ursprünglichen Benennung, nicht eine andere Firmware.

> **Hinweis (ursprünglich):** Die Version v117.7 ist neuer als die v116, die im Live-Scan erscheint.
> Register 34010 zeigt den hardcoded Wert der tatsächlich installierten BMS-FW.

> **✅ Bestätigt 2026-07-09:** Nach dem BMS-OTA-Update auf dem Live-Gerät zeigt der Modbus-Scan
> (`nach_bms_upgrade_auf_117_7_fw.csv`) exakt den hier vorhergesagten Wert: Register 30204
> (bms_version), 34010/34110/34210/34310/34410/34510 (pack1–6_bms_version) und 37012 (Mirror)
> stehen jetzt alle auf **1177 = v117.7** — identisch mit dem hardcoded `0x499` in dieser Binary.
> Damit ist zweifelsfrei bestätigt: Diese analysierte Binary (`20251010135647565eb2036.bin`)
> ist genau die Firmware, die per OTA ausgerollt wurde, und der korrekte Versionsstand ist
> **v117.7** (nicht v177.7). Nebenbefund: Das Versions-Register kodiert offenbar ab der ersten
> Nachkommastelle als Rohwert×10 (zuvor bei ganzzahligem v116 war der Rohwert einfach 116) —
> das gleiche Muster wie bei ems_version (30200) beim Sprung auf Control-FW v149.2 (Rohwert 1492).

---

## 11. Offene Fragen

### Erledigt in dieser Session:

| # | Thema | Status |
|---|---|---|
| ~~1~~ | CAN-Protokoll | ✅ TX (PF 1-4) + RX + Per-Pack (10 Msg) vollständig dekodiert |
| ~~2~~ | SOC-Algorithmus | ✅ Coulomb-Counting + OCV-Kalibrierung + show_soc-Glättung |
| ~~3~~ | Protect1/Protect2 Bitmasks | ✅ 12+5 Bits dekodiert, Setter-Funktionen verifiziert, Schwellwerte identifiziert |
| ~~4~~ | Multi-Pack-Adressierung | ✅ CAN-ID `0x18[MsgGrp]AA[PackID]`, max 9 Packs, 20s Watchdog |
| ~~5~~ | KA495XX / Cell Data Struct | ✅ 96-Byte Struct mit 22 Feldern, Scale-Faktoren bestätigt |
| ~~6~~ | **RS485-Protokoll** | ✅ 34 Kommandos dekodiert, Frame-Format, Inter-Pack-Architektur |
| ~~7~~ | KA495XX SPI-Treiber | ✅ SPI1 Protokoll (0xE1 Cmd, 7-bit Addr, CRC), Register-Map partiell, 15-State Task Machine |
| ~~8~~ | C3 bit 3 Setter | ✅ Dead Code — kein Setter in gesamter FW, Protect2[11] nie aktiviert |
| ~~9~~ | C1 bits 5/6 Setter | ✅ Dead Code — nie per Software gesetzt. HW OVP/UVP vermutlich via GPIO direkt |
| ~~10~~ | FW-Update Sequenz | ✅ CAN 0x1801FFAA (Dead-Flag) + RS485 CMD 0x05 (0xA1/0xB1 Magic) + Flash Writer 0x0801E000 |
| ~~11~~ | UART4 (ex "USART3") | ✅ Inter-Pack RS485 Bus für BMS Slave-Kommunikation, 9600 baud, UART4 (nicht USART3) |

### Noch offen:

| # | Thema | Priorität | Nächster Schritt |
|---|---|---|---|
| 1 | **Shell-Passwort** | Niedrig | Vermutlich leer (gleiche letter-shell wie Micro-FW), UART testen — **blockiert, benötigt Live-Gerät** |
| 2 | **SOC OCV-Lookup-Tabelle** | Mittel | Flash `0x0801B79C`/`0x0801B832` → Spannungskurve extrahieren — benötigt Flash-Dump (Binary endet bei `0x08019FFF`) — **blockiert, benötigt physischen Flash-Dump** |
| 3 | **KA495XX exakter Chip-Typ** | Niedrig | Nur per PCB-Inspektion oder SPI-Sniffing bestimmbar — FW-seitig vollständig analysiert — **blockiert, erneut geprüft 2026-07-10 (s. 11a), kein weiterer statischer Hebel** |

---

## 11a. SRAM 0x2000493C–0x200049B4 — Register Function Codes (Ergänzung 2026-07-10)

Statische Ghidra-Analyse zur Klärung des Punkts aus `AES_Crypto_Stack_Analyse.md`. **Korrektur der ursprünglichen Annahme:** Die Region ist kein BMIC/SPI-Register-Codeblock, sondern Teil eines größeren **RS485-Schutzparameter-Konfigurationsblocks** (`0x20004938`–`0x20004A0C`, 212 Bytes gesamt), adressiert über RS485-Kommandos **0x11 (Read)** / **0x12 (Write)** mit einer Gruppen-ID-Bitmaske im Frame-Header (`[GroupCode(u16)][GroupCode wiederholt][Daten...]`). Persistierung in **EEPROM Offset 600** (212 Bytes).

**Kernfunktionen:**
- `RS485_Register_Read_Handler` (0x08007778) / `RS485_Register_Write_Handler` (0x08007d24) — Dispatch nach Gruppen-ID, Write-Pfad ruft nach dem Setzen `LIB_Checksum_Ones_Complement` + `I2C_EEPROM_Write_WithMutex(&DAT_20004938, 600, 0xd4)`
- `BMS_Config_Params_Factory_Reset` (0x08008120) — Default-Werte aller Gruppen
- `BMS_Config_Params_Load_Or_Default` (0x08007460) — EEPROM-Load beim Boot
- `Voltage_Temp_Protection_Checker` (0x080098b8) — Haupt-Konsument der Temperatur-Gruppen

| GroupID | SRAM-Range | Bedeutung (Konfidenz) |
|---|---|---|
| `0x04` | `0x2000493C–0x20004952` | **Hoch.** ENV-NTC-Temperaturschutz: OT_L1 (60.0°C/3000ms), OT_L2 (65.0°C), OT_Recovery (60.0°C), UT_L1 (-25.0°C), UT_L2 (-30.0°C), UT_Recovery (-25.0°C) |
| `0x08` | `0x20004954–0x2000495E` | **Hoch.** MOS-NTC-Temperaturschutz: Trigger1 (90.0°C/3000), Trigger2 (115.0°C/3000), Recovery (85.0°C/3000) |
| `0x01` | `0x20004960–0x20004976` | **Hoch.** Zell-Temperaturschutz Entladerichtung (6 Trigger/Delay-Paare, OT/UT L1/L2 + Recovery) |
| `0x02` | `0x20004978–0x2000498E` | **Hoch.** Zell-Temperaturschutz Laderichtung (symmetrisch zu Gruppe 0x01) |
| `0x40` | `0x20004996–0x200049A4` | **Hoch (aufgelöst 2026-07-14).** Cell-Overvoltage-Protection. Kein Checker in v117.7 selbst (bestätigt: Konstante 3800mV kommt in 117.7 nirgends vor) — **Konsument existiert erst ab BMS-FW v118** (`FUN_0800a584`, s. `BMS_FW_Analyse_v118.md` Abschnitt 4.6), dort temperaturkompensiert (Schwellen abhängig von Ave-NTC-Vorzeichen) |
| `0x10` | `0x200049A6–0x200049B4` | **Hoch (aufgelöst 2026-07-14).** Cell-Undervoltage-Protection — gleicher Befund wie Gruppe `0x40`: Konsument erst ab v118, in 117.7 nachweislich ungenutzt |
| `0x80` | 1×u16 | **Niedrig.** Kein Write-Handler-Zweig — vermutlich Status/Reserve |
| `0x100` | `0x200049B6–0x200049C4` | **Hoch (aufgelöst 2026-07-14).** Nicht Balance/SOC, sondern **Lade-Überstromstufen** — Konsument ist das bereits bekannte `Current_Protection_Checker` (0x08008420), unverändert in v118 vorhanden |
| `0x200` | `0x200049C6–0x200049D4` | **Hoch (aufgelöst 2026-07-14).** **Entlade-Überstromstufen**, Gegenstück zu `0x100`, ebenfalls `Current_Protection_Checker` |
| `0x400` | `0x200049D6–0x200049DA` | **Niedrig.** 3 Werte, zu klein für sichere Zuordnung — auch in v118 weiterhin ohne identifizierten Konsumenten |

**BMIC_Info-Struct:** Existiert nur als Debug-Print-String (`" BMIC_Info.lBatPackFastCur_mA:%d\r\n"` @ 0x08013227, `"BMIC_Info.lBatPackCur_100uA:%d\r\n"` @ 0x0801324c), keine formale Ghidra-Struktur (0 Structures im Image — RVDS-Release-Build ohne DWARF). Die referenzierten Felder (`0x2000406c`, `0x20004070`) werden von `KA495XX_Compute_Power_And_Energy` (0x08015360) beschrieben. Druckende Funktion `UndefinedFunction_08013124` (Aufrufer: `Debug_Print_Device_UIDs` 0x080130f4) ist noch unbenannt.

**Fazit (aktualisiert 2026-07-14 beim BMS-v118-Diff):** Alle Gruppen bis auf `0x80`/`0x400` sind jetzt mit hoher Konfidenz geklärt. Gruppen 0x01/0x02/0x04/0x08 (Temperaturschutz) waren schon in 117.7 aktiv konsumiert. Gruppen 0x100/0x200 sind keine Balance-/SOC-Werte, sondern Lade-/Entlade-Überstromstufen (`Current_Protection_Checker`, unverändert seit 117.7). Gruppen 0x40/0x10 (Cell-OVP/UVP) hatten in 117.7 tatsächlich **keinen** Konsumenten — die Logik dafür (`FUN_0800a584`, temperaturkompensiert) wurde erst mit **BMS-FW v118** nachgerüstet, s. `BMS_FW_Analyse_v118.md` Abschnitt 4.6. `0x80`/`0x400` bleiben ungeklärt (zu wenig Daten / kein Konsument in beiden Versionen).

**Nebenbefund (2026-07-14):** Die bislang unbenannte `UndefinedFunction_08013124` (Aufrufer: `Debug_Print_Device_UIDs`, 0x080130f4) gibt einen Debug-Status-Dump aus (`g_u8ProhibitCommFlag`, `g_u8UpgradeFlag`, `g_u8UpdateFinishFlag`, BMIC-Ströme, Werksflag, `g_u8EmsChgDsgFlg`). War in Ghidra nur als temporärer Undefined-Function-Stub (1 Byte) vorhanden — mit `create-function` formal angelegt (korrekte Größe: 0x08013124–0x080131af, 140 Bytes) und als **`Debug_Print_System_Status_Flags`** benannt (Dubletten-Check per Namensähnlichkeitssuche negativ). Gehört zum Debug-Cluster, der in v118 komplett entfernt wurde (s. `BMS_FW_Analyse_v118.md` Abschnitt 3.2) — für 117.7-Vollständigkeit trotzdem hier vermerkt und benannt.

---

## 12. Vollständige Funktionsliste (540/540 — 100%)

Stand: 06.07.2026

### SoftFloat — Software Floating Point (15 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08000290` | `SoftFloat_Uint64_Divide` | 98B | 64-bit unsigned Division |
| `0x080002f2` | `SoftFloat_Int64_Divide` | 98B | 64-bit signed Division (Wrapper) |
| `0x08000420` | `__adddf3` | 322B | IEEE 754 double Addition |
| `0x08000562` | `SoftFloat_Add_Double` | 6B | Wrapper für __adddf3 |
| `0x0800056e` | `__muldf3` | 228B | IEEE 754 double Multiplikation |
| `0x08000652` | `__divdf3` | 252B | IEEE 754 double Division |
| `0x08000730` | `SoftFloat_UInt_To_Double` | 26B | uint → double Konvertierung |
| `0x0800074a` | `SoftFloat_Double_To_Int_Low` | 50B | double → int (unterer Teil) |
| `0x0800077c` | `SoftFloat_Float_To_Double` | 38B | float → double Promotion |
| `0x080007a4` | `SoftFloat_Negate_If_Positive` | 48B | Vorzeichen-Negation wenn positiv |
| `0x08000800` | `SoftFloat_Shift_Left_64` | 30B | 64-bit Links-Shift |
| `0x0800081e` | `SoftFloat_Shift_Right_64` | 32B | 64-bit Rechts-Shift |
| `0x0800083e` | `SoftFloat_Arith_Shift_Right_64` | 36B | 64-bit arithmetischer Rechts-Shift |
| `0x08000862` | `SoftFloat_RoundToInt` | 60B | Runden auf Ganzzahl |
| `0x080008bc` | `__aeabi_dmul_normalize` | 156B | double-Multiplikation Normalisierung |
| `0x08000958` | `SoftFloat_Double_To_Int_Store` | 48B | double → int mit Speicherung |
| `0x080009ac` | `SoftFloat_Round_To_Even` | 18B | Banker's Rounding |
| `0x080009be` | `SoftFloat_Pack_Float_Result` | 92B | Float-Ergebnis packen |
| `0x0800e46c` | `float_round_to_int` | 154B | Float runden auf int |

### LIB — Bibliothek / Utility (34 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08000354` | `LIB_Memcpy_Aligned` | 36B | Aligned memcpy |
| `0x08000378` | `LIB_Memset` | 14B | memset |
| `0x08000386` | `LIB_Memset_Zero` | 4B | memset(0) Shortcut |
| `0x0800038a` | `LIB_Memset_ReturnDst` | 18B | memset mit Rückgabe dst |
| `0x0800039c` | `LIB_Strstr` | 36B | strstr |
| `0x080003c0` | `LIB_strncpy` | 24B | strncpy |
| `0x080003d8` | `LIB_Strlen` | 14B | strlen |
| `0x080003e6` | `LIB_strcmp` | 28B | strcmp |
| `0x080007d4` | `LIB_Unsigned_Divide` | 44B | Software-Divisions-Loop |
| `0x08000a1a` | `LIB_Decompress_RLE` | 86B | RLE-Dekompression |
| `0x08001b58` | `LIB_XOR_Checksum` | 28B | XOR-Prüfsumme |
| `0x0800898c` | `LIB_Checksum_Ones_Complement` | 32B | Einerkomplement-Prüfsumme |
| `0x0800adc0` | `LIB_CRC16_Modbus_Calc` | 56B | CRC16-Modbus Berechnung |
| `0x080101b4` | `LIB_Saturated_Add_Unsigned` | 44B | Saturierte Addition (0..1000000) |
| `0x080107e4` | `LIB_RingBuffer_Advance_WritePtr` | 42B | Ringpuffer Write-Pointer vorrücken |
| `0x0801097e` | `LIB_Queue_Init_Static` | 42B | Statische Queue initialisieren |
| `0x08010b24` | `LIB_vPortFree_InsertBlock` | 96B | Heap-Block einfügen bei Free |
| `0x08010b8c` | `LIB_FreeRTOS_Timer_Check_Overflow` | 80B | Timer-Overflow prüfen |
| `0x08010bfe` | `LIB_RingBuffer_Is_Empty` | 30B | Ringpuffer leer? |
| `0x08011bba` | `LIB_HexChar_To_Nibble` | 54B | Hex-Zeichen → 4-bit Wert |
| `0x08012568` | `LIB_String_Match_Length` | 44B | Prefix-Übereinstimmungslänge |
| `0x08012594` | `LIB_Strcpy_U16` | 24B | String-Kopie mit u16-Limit |
| `0x08012712` | `LIB_Uint32_To_HexString` | 56B | uint32 → Hex-String |
| `0x08014258` | `LIB_Delay_Loop_Byte` | 30B | Delay-Schleife (Byte-basiert) |
| `0x080148c0` | `LIB_LinkedList_Remove_Node` | 40B | Doubly-Linked-List Knoten entfernen |
| `0x080161cc` | `LIB_Delay_Loop_Short` | 28B | Kurze Delay-Schleife |
| `0x080161e8` | `LIB_LinkedList_Init` | 26B | Linked List initialisieren |
| `0x08016202` | `LIB_FreeRTOS_Clear_ListItem_Value` | 6B | ListItem-Wert löschen |
| `0x08016208` | `LIB_LinkedList_Insert_Sorted` | 52B | Sortiertes Einfügen |
| `0x0801623c` | `LIB_List_InsertBefore` | 24B | Vor Element einfügen |
| `0x08016254` | `LIB_vPortEnterCritical` | 94B | Critical Section betreten |
| `0x08016730` | `LIB_vTaskDelayWithAssert` | 100B | vTaskDelay mit Assert |
| `0x08016bf8` | `LIB_FreeRTOS_Inc_SchedulerSuspended` | 12B | Scheduler-Suspend-Zähler++ |
| `0x08016fd8` | `LIB_xQueueCreateStatic` | 106B | Statische Queue erstellen |
| `0x08017ac4` | `LIB_xTaskCreate` | 96B | FreeRTOS Task erstellen |
| `0x0800d43c` | `LIB_TestBitMask_U16` | 26B | Bitmask-Test (u16) |
| `0x0800ed54` | `LIB_Printf_Pad_Spaces` | 36B | Printf: Leerzeichen-Padding |
| `0x0800ed78` | `LIB_Printf_Pad_Char` | 46B | Printf: Zeichen-Padding |

### HAL — Hardware Abstraction Layer (75 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08000264` | `HAL_Get_CurrentIRQ_Number` | 6B | Aktuelle IRQ-Nummer lesen |
| `0x08000a70` | `HAL_UART_Clear_IDLEIE` | 10B | UART IDLE-Interrupt aus |
| `0x08000a7a` | `HAL_UART_Set_Address_Mask` | 8B | UART Adressmaske setzen |
| `0x08000af0` | `GPIO_Set_AF_And_Pin_Mapping` | 200B | AF-Pins konfigurieren |
| `0x08000bb8` | `HAL_Set_Pin_Bit0_With_Delay` | 36B | Pin setzen mit Delay |
| `0x08000bdc` | `HAL_GPIO_Set_AF_Mode` | 22B | GPIO Alternate Function Modus |
| `0x08000bf2` | `HAL_SPI_Is_TX_Complete` | 26B | SPI TX fertig? |
| `0x08000c0c` | `HAL_UART_Get_BRR_Low16` | 8B | UART Baudrate untere 16 Bit |
| `0x08000c14` | `HAL_Check_Bits_U32` | 18B | Bit-Prüfung (u32) |
| `0x08000c26` | `HAL_DMA_Check_ISR_Flag` | 18B | DMA ISR-Flag prüfen |
| `0x08000c38` | `HAL_CAN_Init_Registers` | 80B | CAN-Register initialisieren |
| `0x08000c90` | `HAL_UART_Set_IDLEIE` | 10B | UART IDLE-Interrupt an |
| `0x08000c9a` | `HAL_SPI_Set_Error_Flag_And_Delay` | 28B | SPI Error-Flag + Delay |
| `0x08000d70` | `CAN_Build_Arbitration_ID` | 106B | CAN Arbitration-ID bauen |
| `0x0800120c` | `HAL_DMA_Transfer_Single` | 66B | Einzel-DMA-Transfer |
| `0x08001640` | `HAL_Get_DMA_Channel_Struct` | 42B | DMA-Kanal-Struct holen |
| `0x0800167c` | `GPIO_Init_Generic` | 136B | Generische GPIO-Init |
| `0x08001720` | `GPIO_Init_All_Pins` | 312B | Alle GPIO-Pins initialisieren |
| `0x08001870` | `GPIO_Init_Output_PP_50MHz` | 148B | Push-Pull Output 50MHz |
| `0x08001920` | `HAL_GPIO_ReadInputBit_Wrapper` | 16B | GPIO Input lesen (Wrapper) |
| `0x08001930` | `GPIO_Init_Input_Floating` | 148B | Floating Input konfigurieren |
| `0x080019e0` | `HAL_GPIO_ReadOutputBit_Wrapper` | 16B | GPIO Output lesen (Wrapper) |
| `0x080019f0` | `HAL_GPIO_Write_Pin` | 30B | GPIO Pin setzen/löschen |
| `0x08001a18` | `GPIO_DeInit_And_CAN_NVIC_Init` | 300B | GPIO DeInit + CAN NVIC |
| `0x08001f1c` | `HAL_Delay_Short_30Cycles` | 14B | ~30 Zyklen Delay |
| `0x08002d04` | `HAL_TIM_OC_Reconfigure` | 52B | Timer Output Compare umkonfigurieren |
| `0x08002e6c` | `HAL_I2C_Clock_Reset` | 50B | I2C Clock-Reset |
| `0x08002ea4` | `HAL_Set_Bit16_U32` | 22B | Bit 16 in u32 setzen |
| `0x08002eba` | `HAL_Set_Clear_Bits_Offset14` | 18B | Bits setzen/löschen (Offset 14) |
| `0x08002fe0` | `HAL_I2C_Struct_Init_Default` | 32B | I2C-Struct Default-Werte |
| `0x08004d84` | `HAL_DBGMCU_APB1_FreezeBitSet` | 26B | Debug MCU APB1 Freeze |
| `0x080051d4` | `HAL_OneWire_Read_Byte` | 106B | OneWire Byte lesen |
| `0x080062e0` | `HAL_GPIO_PortB_Reset_All` | 28B | GPIO Port B komplett Reset |
| `0x0800649c` | `HAL_FLASH_Set_CR_Bits` | 12B | Flash CR-Register Bits setzen |
| `0x080064ac` | `HAL_Flash_Program_Word_2` | 78B | Flash Word programmieren (Variante 2) |
| `0x08006500` | `HAL_Flash_Get_Status` | 76B | Flash Status abfragen |
| `0x08006550` | `HAL_FLASH_Enable_PrefetchBuffer` | 14B | Flash Prefetch aktivieren |
| `0x08006564` | `HAL_Flash_Program_Word` | 82B | Flash Word programmieren |
| `0x080065bc` | `HAL_FLASH_Write_KEY2` | 12B | Flash Unlock KEY2 |
| `0x0800663c` | `HAL_NVIC_Set_Priority_Field` | 60B | NVIC Priorität setzen |
| `0x0800667c` | `AFIO_Remap_Configure` | 554B | AFIO-Remap konfigurieren |
| `0x080068b0` | `GPIO_Init_Pin` | 278B | Einzelnen GPIO-Pin init |
| `0x080069c6` | `HAL_GPIO_ReadInputBit` | 18B | GPIO Input-Bit lesen |
| `0x080069d8` | `HAL_GPIO_ReadOutputBit` | 18B | GPIO Output-Bit lesen |
| `0x08006a3c` | `HAL_Read_Unique_Device_ID` | 78B | STM32 Unique ID lesen |
| `0x0800b038` | `HAL_IWDG_Start` | 10B | Watchdog starten |
| `0x0800b048` | `HAL_I2C_Check_StatusFlag` | 20B | I2C Status-Flag prüfen |
| `0x0800b060` | `HAL_IWDG_Refresh` | 10B | Watchdog füttern |
| `0x0800b02c` | `HAL_IWDG_Set_Prescaler` | 6B | Watchdog Prescaler |
| `0x0800b070` | `HAL_IWDG_Set_Reload` | 6B | Watchdog Reload-Wert |
| `0x0800b07c` | `HAL_IWDG_Write_KR` | 6B | Watchdog Key-Register |
| `0x0800bb0c` | `HAL_NVIC_EnableIRQ_WithPriority` | 100B | IRQ aktivieren mit Priorität |
| `0x0800bb7c` | `HAL_NVIC_SystemReset` | 10B | System-Reset auslösen |
| `0x0800bb90` | `HAL_Enter_Sleep_Mode` | 62B | Sleep-Modus betreten |
| `0x0800bcf8` | `HAL_RCC_DisablePLLSAI` | 24B | PLL-SAI deaktivieren |
| `0x0800bd14` | `HAL_RCC_Set_PREDIV1` | 18B | RCC PREDIV1 setzen |
| `0x0800bd2c` | `HAL_RCC_Set_ADC_Prescaler` | 30B | ADC Prescaler setzen |
| `0x0800bd50` | `HAL_RCC_Set_ADC_Prescaler_2` | 18B | ADC Prescaler (Variante 2) |
| `0x0800bd68` | `HAL_RCC_CSR_BitSet` | 26B | RCC CSR Register Bit |
| `0x0800bd88` | `HAL_RCC_CFGR2_BitSet` | 26B | RCC CFGR2 Register Bit |
| `0x0800bda8` | `HAL_RCC_BDCR_BitSet` | 26B | RCC BDCR Register Bit |
| `0x0800bdc8` | `HAL_RCC_AHBRSTR_BitSet` | 26B | RCC AHB Reset Bit |
| `0x0800bde8` | `HAL_RCC_APB1ENR_BitSet` | 26B | RCC APB1 Clock Enable |
| `0x0800be08` | `RCC_GetClockFrequencies` | 240B | Clock-Frequenzen berechnen |
| `0x0800bf14` | `HAL_RCC_Get_Flag_Status` | 56B | RCC Flag-Status lesen |
| `0x0800c22c` | `HAL_Set_Bit6_U16` | 24B | Bit 6 in u16 setzen |
| `0x0800c244` | `HAL_SPI_Reset_Peripheral` | 76B | SPI-Peripherie zurücksetzen |
| `0x0800c29c` | `HAL_SPI_Check_StatusFlag` | 18B | SPI Status-Flag prüfen |
| `0x0800c2ae` | `HAL_SPI_Get_DR` | 6B | SPI Datenregister lesen |
| `0x0800c2b4` | `HAL_SPI_Set_DR` | 4B | SPI Datenregister schreiben |
| `0x0800c2b8` | `HAL_DMA_Apply_Channel_Config` | 60B | DMA-Kanal konfigurieren |
| `0x0800c2f4` | `RCC_Clock_Init` | 218B | RCC Clock-Baum initialisieren |
| `0x0800cf92` | `HAL_TIM_Set_Clear_DIER_Bits` | 18B | Timer DIER Bits setzen/löschen |
| `0x0800d084` | `HAL_Set_Bit0_U32` | 22B | Bit 0 in u32 setzen |
| `0x0800d0a0` | `HAL_Check_IRQ_Flag_And_Enable` | 34B | IRQ-Flag prüfen und aktivieren |
| `0x0800d0c4` | `TIM_Base_Init` | 314B | Timer Basis-Initialisierung |
| `0x0800d278` | `RS485_Send_Response` | 102B | RS485 Antwort senden |
| `0x0800d2f0` | `HAL_TIM_Write_ARR_Inverted` | 18B | Timer ARR invertiert schreiben |
| `0x0800d302` | `HAL_NVIC_Set_Bit_By_IRQn` | 74B | NVIC Bit per IRQ-Nummer |
| `0x0800d424` | `HAL_TIM_Set_Bit13_CR2` | 24B | Timer CR2 Bit 13 setzen |
| `0x0800d456` | `HAL_Check_IRQ_Pending` | 84B | Pending IRQ prüfen |
| `0x0800d798` | `HAL_Flash_Write_Config_Block` | 74B | Config-Block in Flash schreiben |
| `0x0800e3cc` | `CLI_Printf_Wrapper` | 22B | Printf-Wrapper für CLI |
| `0x0800e3ec` | `HAL_System_Reset_DSB_Loop` | 56B | System-Reset (DSB + Loop) |
| `0x0800e42c` | `HAL_System_Reset_DSB_Loop2` | 56B | System-Reset Variante 2 |
| `0x0800f31a` | `HAL_Delay_Us` | 30B | Mikrosekunden-Delay |
| `0x08014240` | `HAL_GPIO_Read_Pin_PB6` | 20B | GPIO PB6 lesen |
| `0x08015ffc` | `HAL_GPIO_Set_ChargeEnable_Pin` | 28B | Charge-Enable Pin steuern |
| `0x080020a4` | `HAL_I2C_Bitbang_Start_Sequence` | 42B | I2C Start-Kondition (Bitbang) |
| `0x0800254c` | `HAL_I2C_Bitbang_SCL_Low_Short` | 40B | I2C SCL Low kurz |
| `0x0800257c` | `HAL_I2C_Bitbang_SCL_Low_Long` | 40B | I2C SCL Low lang |
| `0x08002000` | `HAL_SPI_BitBang_Write_Byte` | 98B | SPI Bitbang Byte senden |
| `0x080026b4` | `HAL_SPI1_TransmitReceive_Byte_2` | 12B | SPI1 TX/RX (Variante 2) |
| `0x080026c0` | `HAL_SPI1_TransmitReceive_Byte` | 54B | SPI1 TX/RX Byte |
| `0x08005244` | `SPI_Bitbang_Send_Byte` | 114B | SPI Bitbang Senden |
| `0x08002cbe` | `HAL_RingBuffer_Write` | 70B | Ringpuffer schreiben |

### INIT — Initialisierung (18 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08001d8c` | `System_Init_Main` | 278B | Haupt-System-Initialisierung |
| `0x08001eb8` | `INIT_All_Peripherals` | 40B | Alle Peripherie initialisieren |
| `0x080011e4` | `INIT_GPIO_SPI_CS_Pins` | 28B | SPI Chip-Select Pins |
| `0x080014b4` | `INIT_I2C2_GPIO` | 30B | I2C2 GPIO-Pins |
| `0x08001f2c` | `INIT_I2C_EEPROM_GPIO` | 78B | I2C EEPROM GPIO-Pins |
| `0x080020d4` | `INIT_GPIO_PortC_Pins10_11` | 22B | Port C Pin 10/11 |
| `0x08002500` | `INIT_GPIOD_SPI_Pins` | 70B | GPIO-D SPI-Pins |
| `0x080025c4` | `INIT_SPI1_GPIO_Pins` | 76B | SPI1 GPIO-Pins |
| `0x08002878` | `INIT_CAN_Filter_Config` | 102B | CAN-Filter konfigurieren |
| `0x0800298c` | `INIT_RS485_UART_Structs` | 98B | RS485 UART-Structs |
| `0x08002ba0` | `INIT_USART_And_SPI_GPIO_Deinit` | 64B | USART/SPI GPIO DeInit |
| `0x08002cae` | `INIT_USART_All` | 16B | Alle USARTs initialisieren |
| `0x0800afe4` | `INIT_EXTI_And_Timer_IRQ` | 70B | EXTI + Timer IRQs |
| `0x08010abc` | `INIT_FreeRTOS_Timers` | 70B | FreeRTOS Timer-System |
| `0x080108dc` | `INIT_FreeRTOS_Heap_Metadata` | 98B | FreeRTOS Heap-Metadaten |
| `0x08001d28` | `INIT_TIM2_TIM3_NVIC_And_Reset` | 96B | TIM2/TIM3 NVIC + Reset |
| `0x08005160` | `INIT_KA495XX_SPI_GPIO` | 40B | KA495XX SPI GPIO-Pins |
| `0x08015e14` | `INIT_KA495XX_Subsystem` | 74B | KA495XX Subsystem-Init |

### FATFS — Dateisystem (16 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08000402` | `FATFS_Compare_Strings` | 30B | String-Vergleich |
| `0x080125ac` | `FATFS_Dir_Entry_Match` | 266B | Verzeichniseintrag matchen |
| `0x08012338` | `FATFS_DiskIO_Dispatch` | 174B | Disk I/O Dispatcher |
| `0x080124a8` | `FATFS_PutNumeric` | 158B | Numerischen Wert schreiben |
| `0x08011f4c` | `FATFS_File_Init` | 142B | Datei initialisieren |
| `0x080123e6` | `FATFS_Find_Dir_Entry` | 122B | Verzeichniseintrag suchen |
| `0x08011ed2` | `FATFS_Dir_Entry_Advance` | 122B | Zum nächsten Eintrag |
| `0x0801182c` | `FATFS_Process_Filename_Entry` | 108B | Dateinamen-Eintrag verarbeiten |
| `0x08011680` | `FATFS_Check_File_Access_Permission` | 54B | Dateizugriff prüfen |
| `0x08011648` | `FATFS_Validate_And_Init_File` | 52B | Datei validieren + init |
| `0x08011bf0` | `FATFS_Get_Data_Pointer` | 48B | Daten-Pointer holen |
| `0x08011c70` | `FATFS_Find_Active_FileObj` | 48B | Aktives File-Objekt finden |
| `0x0800d700` | `FATFS_Init_Log_File_If_Needed` | 46B | Log-Datei init bei Bedarf |
| `0x08011acc` | `FATFS_Find_And_Open_Dir_Entry` | 36B | Eintrag suchen + öffnen |
| `0x08011610` | `FATFS_Register_Mount_Slot` | 34B | Mount-Slot registrieren |
| `0x08010be4` | `FATFS_Is_Queue_Empty` | 26B | Queue leer? |
| `0x08011408` | `FATFS_IncrementRefCount` | 26B | Referenzzähler++ |
| `0x080120c4` | `FATFS_DecrementAndNotify` | 26B | Referenzzähler-- + Notify |
| `0x08011098` | `FATFS_Count_Erased_Bytes_Div4` | 22B | Gelöschte Bytes zählen |
| `0x08011818` | `FATFS_Process_And_Mark_Entry` | 20B | Eintrag verarbeiten + markieren |

### CLI — Letter-Shell Debug-Konsole (28 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08011cf8` | `LetterShell_Key_Processor` | 232B | Tasteneingabe-Verarbeitung |
| `0x08011fec` | `CLI_Line_Insert_Char` | 212B | Zeichen in Zeile einfügen |
| `0x0801170c` | `CLI_Delete_Char` | 218B | Zeichen löschen |
| `0x08011e10` | `CLI_History_Navigate` | 194B | Kommando-History navigieren |
| `0x08012138` | `CLI_Print_Command_Entry` | 194B | Kommandoeintrag ausgeben |
| `0x08011af0` | `CLI_Native_Function_Call` | 194B | Native Funktion aufrufen |
| `0x08012224` | `CLI_Parse_Arguments` | 142B | Argumente parsen |
| `0x080122b2` | `CLI_Strip_Quotes_From_Args` | 104B | Anführungszeichen entfernen |
| `0x08012898` | `CLI_Print_Return_Value` | 104B | Rückgabewert ausgeben |
| `0x080127c4` | `CLI_Cmd_FindFile` | 98B | FindFile-Kommando |
| `0x080118a0` | `CLI_Detect_Number_Base` | 88B | Zahlenbasis erkennen (hex/dec) |
| `0x08012768` | `CLI_Output_Line_WithLimit` | 88B | Zeilenausgabe mit Limit |
| `0x08011a2c` | `CLI_Parse_Token_Value` | 86B | Token-Wert parsen |
| `0x080126bc` | `CLI_Int_To_DecString` | 86B | Int → Dezimal-String |
| `0x08012830` | `CLI_Print_Command_Help` | 84B | Kommando-Hilfe |
| `0x08011ca4` | `CLI_Get_Variable_Value_By_Type` | 78B | Variablenwert nach Typ |
| `0x08011c20` | `CLI_Get_Value_String_By_Type` | 76B | Wert-String nach Typ |
| `0x080118f8` | `CLI_Parse_Escape_Char` | 70B | Escape-Zeichen parsen |
| `0x080120ec` | `CLI_List_Commands` | 70B | Kommandoliste ausgeben |
| `0x08012460` | `CLI_Register_Command_Table` | 66B | Kommandotabelle registrieren |
| `0x08011a82` | `CLI_Parse_Quoted_String` | 74B | Quoted String parsen |
| `0x08012924` | `CLI_Write_String_Via_Callback` | 48B | String über Callback ausgeben |
| `0x0800c43c` | `CLI_Process_RX_Buffer` | 38B | RX-Puffer verarbeiten |
| `0x080116d4` | `CLI_Pad_Spaces_And_Set_Cursor` | 40B | Leerzeichen-Padding + Cursor |
| `0x080117e8` | `CLI_Send_Repeated_Char` | 28B | Zeichen wiederholt senden |
| `0x08012208` | `CLI_Clear_Flag_And_Insert_Char` | 28B | Flag löschen + Zeichen einfügen |
| `0x0801089e` | `CLI_Get_Free_Args` | 20B | Freie Argumente holen |
| `0x0801088c` | `CLI_Free_Command` | 18B | Kommando freigeben |
| `0x080116fc` | `CLI_Backspace` | 16B | Backspace |
| `0x08011638` | `CLI_Delete_Forward` | 14B | Vorwärts löschen |
| `0x0801274a` | `CLI_History_Up` | 14B | History hoch |
| `0x08012758` | `CLI_Write_Callback_1Byte` | 14B | 1 Byte über Callback |
| `0x0801231a` | `CLI_TxBuffer_Send_Next_Byte` | 30B | TX-Puffer nächstes Byte |
| `0x08011de4` | `CLI_Cmd_Dispatch_By_Argc` | 44B | Dispatch nach Argc |
| `0x080120de` | `CLI_Show_Help` | 12B | Hilfe anzeigen |

### RTOS — FreeRTOS Kernel (20 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08017738` | `xQueueSemaphoreTake` | 494B | Semaphore nehmen |
| `0x0801719c` | `xQueueGenericSend` | 476B | Generisches Queue-Senden |
| `0x0801754c` | `xQueueReceive` | 398B | Queue empfangen |
| `0x08011210` | `pvPortMalloc` | 340B | Heap-Allokation |
| `0x08017b50` | `xTaskIncrementTick` | 300B | Tick-Zähler inkrementieren |
| `0x080173d4` | `xQueueSendFromISR` | 290B | Queue-Senden aus ISR |
| `0x08016958` | `vTaskPriorityDisinheritAfterTimeout` | 260B | Priority-Disinherit nach Timeout |
| `0x08018038` | `xTaskResumeAll` | 240B | Alle Tasks resumieren |
| `0x08017d18` | `xTaskPriorityDisinherit` | 218B | Priority-Disinherit |
| `0x080109a8` | `prvInitialiseNewTask` | 204B | Neuen Task initialisieren |
| `0x08017e74` | `vTaskPriorityInherit` | 186B | Priority-Inherit |
| `0x08016410` | `vPortFree` | 172B | Heap-Freigabe |
| `0x080170ac` | `xQueueGenericReset` | 160B | Queue zurücksetzen |
| `0x080179bc` | `xTaskCheckForTimeOut` | 160B | Timeout-Prüfung |
| `0x08010680` | `prvAddTaskToReadyList` | 156B | Task in Ready-Liste |
| `0x0801825c` | `xTimerGenericCommand` | 140B | Timer-Kommando senden |
| `0x08017f3c` | `xTaskRemoveFromEventList` | 142B | Task aus Event-Liste |
| `0x08016598` | `vPortValidateInterruptPriority` | 136B | Interrupt-Priorität validieren |
| `0x08016c08` | `vTaskSwitchContext` | 134B | Kontextwechsel |
| `0x08010c1c` | `prvTimerCallback_Handler` | 128B | Timer-Callback Handler |
| `0x0801080e` | `prvCopyDataToQueue` | 126B | Daten in Queue kopieren |
| `0x08011192` | `prvUnlockQueue` | 126B | Queue entsperren |
| `0x08010f94` | `prvTimerProcessExpired` | 170B | Abgelaufene Timer verarbeiten |
| `0x08016350` | `RTOS_vPortExitCritical` | 74B | Critical Section verlassen |
| `0x08016820` | `RTOS_vTaskPlaceOnEventList` | 66B | Task auf Event-Liste |
| `0x080168b8` | `RTOS_vTaskPlaceOnEventListRestricted` | 74B | Event-Liste (restricted) |
| `0x08010f34` | `RTOS_Update_Current_TCB_Runtime` | 42B | TCB Runtime aktualisieren |
| `0x08010f68` | `RTOS_Check_Tick_Overflow` | 40B | Tick-Overflow prüfen |
| `0x08011428` | `RTOS_Init_Task_Stack_Frame` | 38B | Task-Stack-Frame init |
| `0x080148e8` | `RTOS_Get_Task_Stack_Watermark` | 34B | Stack-Watermark abfragen |
| `0x08016fb4` | `RTOS_Create_Binary_Semaphore` | 34B | Binäre Semaphore erstellen |
| `0x08010960` | `RTOS_Semaphore_Init_And_Give` | 30B | Semaphore init + geben |

### APP — BMS Applikationslogik (35 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08007460` | `BMS_Config_Params_Load_Or_Default` | 788B | Config laden oder Defaults |
| `0x0800702c` | `bms_data_printf` | 770B | BMS-Daten Debug-Ausgabe |
| `0x08008120` | `BMS_Config_Params_Factory_Reset` | 728B | Config auf Werkseinstellung |
| `0x08009f70` | `PerPack_Struct_Builder` | 580B | Per-Pack Struct aufbauen |
| `0x08000f98` | `Pack_Online_Watchdog` | 374B | Pack-Online Watchdog (20s) |
| `0x080142c0` | `SOC_Display_And_FullFlag_Update` | 318B | SOC-Anzeige + Full-Flag |
| `0x08012e4c` | `Debug_Print_Task_Stack_Usage` | 304B | Task-Stack-Nutzung ausgeben |
| `0x080056c0` | `Pack_LowVoltage_Balancer` | 252B | Pack-Balancing bei Niedrigspannung |
| `0x08004c6c` | `Pack_MasterSelect_Monitor` | 224B | Master-Pack Auswahl-Monitor |
| `0x08002198` | `System_Reset_And_Halt` | 136B | System Reset und Halt |
| `0x08000a84` | `APP_DMA_Channel_Mode_Switch` | 90B | DMA-Kanal Modus umschalten |
| `0x08000cd4` | `APP_CAN_RX_Task_Process` | 98B | CAN RX Task verarbeiten |
| `0x08008784` | `APP_Pack_Discovery_Init` | 94B | Pack-Erkennung initialisieren |
| `0x0800c7f4` | `APP_Get_Protection_Status_Byte` | 88B | Protection Status Byte holen |
| `0x080157cc` | `APP_Clear_SOC_Accumulator_Arrays` | 80B | SOC-Akkumulator-Arrays löschen |
| `0x080086a4` | `APP_Read_Flash_Boot_Count_Validated` | 78B | Boot-Counter aus Flash lesen |
| `0x08006cc8` | `APP_Get_Packs_Charging_Bitmask` | 70B | Lade-Bitmask aller Packs |
| `0x08005854` | `APP_Get_Effective_SOC_Display` | 62B | Effektiven Anzeige-SOC holen |
| `0x08006b54` | `APP_Calc_Pack_SOC_From_Voltage` | 62B | SOC aus Spannung berechnen |
| `0x08014ec0` | `APP_CAN_Reset_Counters_Init` | 62B | CAN-Zähler zurücksetzen |
| `0x08006c00` | `APP_Get_Packs_Charging_Bitmask_2` | 60B | Lade-Bitmask (Variante 2) |
| `0x08006c48` | `APP_Get_Packs_Discharging_Bitmask` | 60B | Entlade-Bitmask aller Packs |
| `0x08015a3c` | `APP_Shutdown_Countdown_Tick` | 64B | Shutdown-Countdown |
| `0x080065fc` | `APP_Factory_Reset_And_Reboot` | 64B | Factory Reset + Neustart |
| `0x08014200` | `APP_CAN_Send_With_Validation` | 64B | CAN senden mit Validierung |
| `0x08013ec4` | `APP_CAN_Verify_Config_Table` | 60B | CAN Config-Tabelle prüfen |
| `0x08006a94` | `APP_Set_Pack_MOS_Status_Flags` | 50B | Pack MOS-Status setzen |
| `0x08006c90` | `APP_Calc_Pack_SOC_Percent_Rounded` | 50B | SOC % gerundet berechnen |
| `0x0801427c` | `APP_CAN_Clamp_And_Scale_Temperature` | 48B | Temperatur klemmen + skalieren |
| `0x080097bc` | `APP_Toggle_Precharge_Pin` | 42B | Precharge-Pin umschalten |
| `0x080097f0` | `APP_Check_And_Clear_Wakeup_Flag` | 46B | Wakeup-Flag prüfen + löschen |
| `0x0800a4e8` | `APP_Periodic_600_Tick_Callback` | 38B | Periodischer 600-Tick Callback |
| `0x080083fc` | `APP_Config_Checksum_And_Save` | 30B | Config-Prüfsumme + Speichern |
| `0x080089ac` | `APP_Clear_ErrorCounters` | 24B | Fehlerzähler löschen |
| `0x0800872a` | `APP_Swap_Params_And_Call` | 20B | Parameter tauschen + aufrufen |
| `0x08000cb8` | `APP_Clear_SPI_BusyFlag` | 10B | SPI Busy-Flag löschen |
| `0x08000cc8` | `APP_Clear_CAN_ErrorCounter` | 8B | CAN-Fehlerzähler löschen |
| `0x0800f9a4` | `APP_Get_RS485_Address` | 8B | RS485-Adresse lesen |
| `0x0801049c` | `APP_Set_CLI_DefaultHandler` | 8B | CLI Default-Handler setzen |
| `0x080104dc` | `APP_Clear_CLI_OutputLength` | 8B | CLI Output-Länge löschen |
| `0x080161c0` | `APP_Set_ChargeDischargeState` | 8B | Lade/Entlade-Zustand setzen |
| `0x08016814` | `APP_Set_NeedYield_Flag` | 8B | NeedYield-Flag setzen |
| `0x080142b4` | `APP_Get_SOC_AccumulatedEnergy` | 6B | Akkumulierte Energie lesen |
| `0x08006d1c` | `APP_Get_PackFaultStatus` | 6B | Pack-Fehlerstatus lesen |
| `0x0800edec` | `APP_Get_ProtectFlags_Byte` | 6B | Protection-Flags Byte |
| `0x08017b24` | `APP_Get_Calibration_Status` | 24B | Kalibrations-Status |
| `0x08017b44` | `APP_Get_SystemTickCounter` | 6B | System-Tick-Zähler |
| `0x080167fc` | `APP_Get_PackVoltage_Current` | 14B | Pack-Spannung/Strom lesen |
| `0x080058a4` | `APP_Is_Flag_2A6D_Set` | 14B | Flag 0x2A6D gesetzt? |
| `0x0800edd8` | `APP_Is_Not_Initialized_4043` | 14B | Init-Flag 0x4043 prüfen |
| `0x0800edf8` | `APP_Is_Flag_4015_Set` | 14B | Flag 0x4015 gesetzt? |
| `0x08014004` | `APP_Is_Both_Conditions_Met` | 26B | Beide Bedingungen erfüllt? |
| `0x0800ee0c` | `APP_Try_Acquire_Lock` | 38B | Lock versuchen zu erwerben |
| `0x0800d78c` | `APP_vTaskDelayUntil_Wrapper` | 12B | vTaskDelayUntil Wrapper |
| `0x08010168` | `APP_Get_Pack_Summary_Data` | 68B | Pack-Zusammenfassung holen |
| `0x080058b8` | `APP_Find_Pack_With_Highest_SOC` | 66B | Pack mit höchstem SOC |
| `0x0800598c` | `APP_Find_Pack_With_Lowest_SOC` | 66B | Pack mit niedrigstem SOC |
| `0x0800b8c0` | `APP_Accumulate_Idle_Charge_Counter` | 76B | Idle-Ladezähler akkumulieren |
| `0x08006ec8` | `BMS_Check_FullCharge_Condition` | 158B | Vollladungs-Bedingung prüfen |

### CAN — CAN-Bus Protokoll (30 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08005af0` | `CAN_TX_PerPack_10Msgs` | 1868B | 10 CAN-Nachrichten pro Pack |
| `0x0800c46c` | `CAN_TX_BMS_Status_Reporter` | 888B | BMS-Status CAN-Report |
| `0x0800b388` | `CAN_Unpack_Pack_Activation_Data` | 850B | Pack-Aktivierung auspacken |
| `0x0800c8bc` | `CAN_RX_Command_Dispatcher` | 324B | CAN RX Kommando-Dispatcher |
| `0x0800b704` | `CAN_CMD_Pack_Activation` | 392B | Pack-Aktivierungs-Kommando |
| `0x080053d8` | `CAN_TX_PF2_Capacity` | 124B | TX Frame: Kapazität |
| `0x08005474` | `CAN_TX_PF3_ChargeDischargeLimits` | 318B | TX Frame: Lade-/Entladegrenzen |
| `0x08002d3c` | `CAN_FilterBank_Configure` | 258B | Filter-Bank konfigurieren |
| `0x08003000` | `CAN_RxMailbox_Read` | 240B | RX-Mailbox lesen |
| `0x080030f0` | `CAN_TxMailbox_Write` | 294B | TX-Mailbox schreiben |
| `0x080026fc` | `TIM_PWM_Configure_Channel` | 344B | PWM-Kanal konfigurieren |
| `0x080059dc` | `CAN_RX_Handler` | 222B | CAN RX Handler |
| `0x0800b920` | `CAN_Pack_Activation_Config_Receive` | 178B | Pack-Aktivierung Config empfangen |
| `0x0800ca88` | `CAN_TX_Send_Status_Response` | 146B | Status-Antwort senden |
| `0x08005908` | `CAN_Find_Closest_Pack_To_50pct` | 120B | Pack nächst an 50% SOC |
| `0x08005640` | `CAN_CMD_04_Handler` | 116B | CAN Kommando 0x04 |
| `0x0800536c` | `CAN_TX_PF1_PackMeasurements` | 94B | TX Frame: Messwerte |
| `0x0800c850` | `CAN_RX_System_Command_Handler` | 88B | System-Kommando Handler |
| `0x080055d4` | `CAN_TX_PF4_ProtectWarnings` | 88B | TX Frame: Schutz-Warnungen |
| `0x080057dc` | `CAN_CMD_01_Handler` | 88B | CAN Kommando 0x01 |
| `0x0800ca2c` | `CAN_Handle_Pack_Mode_Command` | 74B | Pack-Modus Kommando |
| `0x08005320` | `CAN_TX_Orchestrator` | 72B | TX Orchestrator |
| `0x08001344` | `CAN_Send_Data_Frame` | 64B | Datenframe senden |
| `0x08000e50` | `CAN_Send_Status_Message` | 74B | Statusnachricht senden |
| `0x08000f58` | `CAN_Send_Broadcast_Message` | 58B | Broadcast senden |
| `0x08006470` | `CAN_Set_Notify_Flag_And_Send` | 44B | Notify-Flag + Senden |
| `0x080065d4` | `CAN_Send_With_Retry` | 38B | Senden mit Retry |
| `0x08008674` | `CAN_Load_Or_Init_Config_Value` | 42B | Config laden oder init |
| `0x08002e44` | `CAN_RxFIFO0_Read_And_Set_Flag` | 28B | RX FIFO0 lesen + Flag |
| `0x080129c4` | `CAN_Set_Config_Value` | 16B | Config-Wert setzen |
| `0x0800f8b0` | `CAN_Extract_StdId_From_ExtId` | 10B | StdId aus ExtId extrahieren |
| `0x0800d574` | `CAN_Get_DLC` | 10B | DLC lesen |
| `0x0800d57e` | `CAN_Set_DLC` | 8B | DLC setzen |
| `0x080069ea` | `CAN_Set_TxMailbox_TDLR` | 4B | TX-Mailbox Daten Low |
| `0x080069ee` | `CAN_Set_TxMailbox_TIR` | 4B | TX-Mailbox Identifier |
| `0x0800d228` | `CAN_Set_TxMailbox_TDHR` | 6B | TX-Mailbox Daten High |
| `0x0800cf8c` | `CAN_Set_FilterMask_Inverted` | 6B | Filtermaske invertiert |
| `0x0800d09a` | `CAN_Get_RxFIFO_Data_Low` | 6B | RX FIFO Daten Low |
| `0x0800d21c` | `CAN_Set_FilterBank_FR1` | 4B | Filterbank Register 1 |
| `0x0800d220` | `CAN_Set_FilterBank_FR2` | 4B | Filterbank Register 2 |
| `0x0800d224` | `CAN_Set_FilterBank_FR3` | 4B | Filterbank Register 3 |
| `0x08005ae4` | `CAN_CMD_02_Handler` | 12B | CAN Kommando 0x02 |

### RS485 — RS485 Kommunikation (16 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800d804` | `RS485_Dispatcher` | 1614B | RS485 Haupt-Dispatcher |
| `0x08007778` | `RS485_Register_Read_Handler` | 1438B | Register-Lese-Handler |
| `0x08007d24` | `RS485_Register_Write_Handler` | 1004B | Register-Schreib-Handler |
| `0x0800fba4` | `RS485_Pack_Telemetry_Response` | 296B | Pack-Telemetrie Antwort |
| `0x08002a24` | `USART2_UART4_Init` | 360B | USART2/UART4 Init |
| `0x08002bec` | `UART_IRQ_Handler` | 194B | UART IRQ Handler |
| `0x08002234` | `USART2_RX_Process` | 170B | USART2 RX Verarbeitung |
| `0x080022fc` | `UART4_RX_Process` | 134B | UART4 RX Verarbeitung (Inter-Pack) |
| `0x0800b088` | `RS485_Protocol_Byte_Receiver` | 120B | Protokoll Byte-Empfänger |
| `0x0800b10c` | `RS485_Build_And_Send_Frame` | 112B | Frame bauen + senden |
| `0x0800adf8` | `RS485_Process_RX_Command` | 110B | RX-Kommando verarbeiten |
| `0x08002420` | `Parse_Checkout_RS485_Config` | 106B | RS485 Config parsen |
| `0x0800d278` | `RS485_Send_Response` | 102B | Antwort senden |
| `0x08002138` | `RS485_Send_Packet_Bus1` | 96B | Paket auf Bus 1 senden |
| `0x080024a0` | `RS485_Send_Packet_Bus3` | 96B | Paket auf Bus 3 senden |
| `0x0800af74` | `RS485_Send_Error_Response_If_Pending` | 72B | Fehlerantwort wenn pending |
| `0x08015ba4` | `RS485_Reset_Transceiver` | 40B | Transceiver zurücksetzen |
| `0x0800ee38` | `RS485_Send_Bytes` | 38B | Bytes senden |
| `0x0800d4ac` | `USART_Init_Config` | 188B | USART-Konfiguration |
| `0x0800d34c` | `USART_SPI_Clock_Reset` | 186B | USART/SPI Clock Reset |
| `0x0800cfa4` | `TIM_Clock_Reset` | 196B | Timer Clock Reset |

### I2C_EEPROM — EEPROM Zugriff (13 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08002ecc` | `I2C_Config_Apply` | 276B | I2C-Konfiguration anwenden |
| `0x0800150c` | `I2C1_Init` | 292B | I2C1 initialisieren |
| `0x08001388` | `SPI2_And_I2C1_Init` | 284B | SPI2 + I2C1 Init |
| `0x08004da4` | `I2C_EEPROM_Read` | 148B | EEPROM lesen |
| `0x08004e38` | `I2C_EEPROM_Write` | 150B | EEPROM schreiben |
| `0x08008fd4` | `I2C_EEPROM_Format_EventLog` | 94B | Event-Log formatieren |
| `0x080063c0` | `I2C_EEPROM_Read_WithMutex` | 84B | Lesen mit Mutex |
| `0x08006418` | `I2C_EEPROM_Write_WithMutex` | 84B | Schreiben mit Mutex |
| `0x080103d0` | `EEPROM_EventLog_GetSlotAddrs` | 82B | Event-Log Slot-Adressen |
| `0x08001fb8` | `I2C_EEPROM_Read_Byte_BitBang` | 68B | Byte lesen (Bitbang) |
| `0x08002068` | `I2C_EEPROM_Read_Byte_Sequence` | 56B | Byte-Sequenz lesen |
| `0x08001ee0` | `I2C_EEPROM_Write_Byte_Sequence` | 56B | Byte-Sequenz schreiben |
| `0x08001f84` | `I2C_EEPROM_Stop_Condition` | 46B | Stop-Kondition |
| `0x080020f0` | `I2C_EEPROM_Read_ACK_BitBang` | 66B | ACK lesen (Bitbang) |
| `0x0800f8e4` | `I2C_EEPROM_Send_Byte_Wait` | 44B | Byte senden + warten |
| `0x0800f8ba` | `I2C_EEPROM_Calc_Checksum` | 42B | EEPROM Prüfsumme |
| `0x080051b8` | `I2C_EEPROM_Write_7Bytes` | 28B | 7 Bytes schreiben |

### KA495XX — BMIC Zellmonitoring SPI-Treiber (35 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x080150ac` | `KA495XX_Read_CellVoltages_And_Temps` | 674B | Zellspannungen + Temperaturen lesen |
| `0x08014c54` | `KA495XX_Cell_Balance_StateMachine` | 612B | Cell-Balancing State Machine |
| `0x08014f0c` | `KA495XX_Compute_ADC_Offsets` | 398B | ADC-Offsets berechnen |
| `0x0801550c` | `KA495XX_Scale_To_Millivolts` | 390B | Skalierung → Millivolt |
| `0x08015bd4` | `KA495XX_Read_Fault_Status` | 340B | Fehler-Status lesen |
| `0x0801491c` | `KA495XX_SPI_Bulk_Read` | 314B | SPI Bulk-Read |
| `0x08015360` | `KA495XX_Compute_Power_And_Energy` | 306B | Leistung + Energie berechnen |
| `0x08014510` | `KA495XX_Encode_OVP_UVP_OCD_Thresholds` | 284B | Schwellwerte kodieren |
| `0x08015ed4` | `KA495XX_Register_Init` | 260B | Register initialisieren |
| `0x08014b5c` | `KA495XX_Cell_Balance_Decision` | 232B | Balancing-Entscheidung |
| `0x08014410` | `KA495XX_SPI_Read_Single_Reg` | 230B | SPI Einzel-Register lesen |
| `0x0801475c` | `KA495XX_Encode_Protection_Config` | 226B | Schutz-Config kodieren |
| `0x080160c8` | `KA495XX_ADC_Conversion_Trigger` | 230B | ADC-Wandlung auslösen |
| `0x08015824` | `KA495XX_Init_Default_Params` | 214B | Default-Parameter setzen |
| `0x08015d34` | `KA495XX_Compute_Calibration_Factor` | 202B | Kalibrierfaktor berechnen |
| `0x08015914` | `KA495XX_Main_StateMachine` | 186B | Haupt-State-Machine (15 States) |
| `0x08013f44` | `KA495XX_Read_Temperature_Sensors` | 188B | Temperatursensoren lesen |
| `0x080146a8` | `KA495XX_Encode_OCSC_Config` | 174B | OCSC-Config kodieren |
| `0x08015af8` | `KA495XX_Init_Sequence` | 168B | Init-Sequenz |
| `0x0801572c` | `KA495XX_ClearMinMaxArrays` | 150B | Min/Max-Arrays löschen |
| `0x0801401e` | `KA495XX_WriteProtectionRegs` | 150B | Schutz-Register schreiben |
| `0x08014174` | `KA495XX_Cell_Balance_Config` | 126B | Balancing konfigurieren |
| `0x08015a80` | `KA495XX_Wakeup_Sequence` | 114B | Aufwach-Sequenz |
| `0x080156b0` | `KA495XX_Cell_Balance_Check` | 110B | Balancing-Check |
| `0x08014634` | `KA495XX_Pack_Config_Bitfield` | 112B | Pack-Config Bitfeld |
| `0x08015e70` | `KA495XX_Verify_Config_Registers` | 96B | Config-Register verifizieren |
| `0x08014a6c` | `KA495XX_SPI_Write_Register` | 92B | SPI Register schreiben |
| `0x080159e4` | `KA495XX_Poll_Watchdog_Flag` | 84B | Watchdog-Flag pollen |
| `0x0801601c` | `KA495XX_Build_Balancing_Bitmask` | 76B | Balancing-Bitmask bauen |
| `0x08016078` | `KA495XX_Handle_Fault_Flags` | 72B | Fault-Flags behandeln |
| `0x08014ad0` | `KA495XX_SPI_Write_Masked_Register` | 72B | SPI Masked-Write |
| `0x08014b18` | `KA495XX_Check_And_Clear_Watchdog` | 66B | Watchdog prüfen + löschen |
| `0x08013f04` | `KA495XX_Check_Fault_Registers` | 64B | Fault-Register prüfen |
| `0x08009828` | `KA495XX_Write_Error_Lock_Register` | 58B | Error-Lock schreiben |
| `0x08009868` | `KA495XX_Check_Error_Lock_Status` | 60B | Error-Lock Status prüfen |
| `0x080086f2` | `KA495XX_Write_Balancing_Register` | 56B | Balancing-Register schreiben |
| `0x0800505c` | `KA495XX_SPI_Send_Sleep_Command` | 44B | Sleep-Kommando senden |
| `0x080052bc` | `KA495XX_SPI_Read_Register` | 42B | SPI Register lesen |
| `0x080052ec` | `KA495XX_SPI_Write_Register_2` | 42B | SPI Register schreiben (V2) |
| `0x0800518c` | `KA495XX_SPI_Read_All_Registers` | 38B | Alle Register lesen |
| `0x080032d4` | `KA495XX_Check_Tick_Overflow` | 30B | Tick-Overflow prüfen |
| `0x08015fd8` | `KA495XX_Read_Status_And_Check_Balancing` | 28B | Status + Balancing prüfen |
| `0x080089d8` | `KA495XX_Reset_And_Init` | 8B | Reset + Init |
| `0x08014a60` | `KA495XX_SPI_BulkRead_Reg0x59` | 12B | Bulk-Read Register 0x59 |
| `0x08014500` | `KA495XX_Get_Register` | 10B | Register-Wert holen |
| `0x08014910` | `KA495XX_Set_Register` | 8B | Register-Wert setzen |
| `0x08014110` | `KA495XX_Comm_Error_Check_Bit1` | 94B | Comm-Fehler Bit 1 prüfen |
| `0x080140b4` | `KA495XX_Comm_Error_Check_Bit0` | 88B | Comm-Fehler Bit 0 prüfen |

### SOC — State of Charge Algorithmus (30 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x080098b8` | `Voltage_Temp_Protection_Checker` | 1600B | Spannungs-/Temp-Schutz |
| `0x08013520` | `SOC_Algorithm_Orchestrator` | 346B | SOC-Algorithmus Orchestrator |
| `0x0800f338` | `Coulomb_Counting` | 334B | Coulomb-Counting |
| `0x08013318` | `SOC_Clamp_And_Store` | 312B | SOC klemmen + speichern |
| `0x0800f5f8` | `Discharge_SOC_Integration` | 370B | Entlade-SOC-Integration |
| `0x0800ef40` | `Charge_Energy_Calc` | 296B | Lade-Energieberechnung |
| `0x0800f490` | `Discharge_Energy_Calc` | 296B | Entlade-Energieberechnung |
| `0x0800f1a8` | `Charge_SOC_Integration` | 256B | Lade-SOC-Integration |
| `0x0800f7b8` | `SOC_Voltage_Drop_Compensator` | 244B | Spannungsabfall-Kompensation |
| `0x080104e8` | `SOC_Init_Capacity_Params` | 242B | Kapazitätsparameter init |
| `0x0800ee60` | `SOC_Energy_Calibration_Update` | 214B | Energie-Kalibrierung |
| `0x0800f0b4` | `SOC_Charge_Interpolation` | 232B | Lade-Interpolation |
| `0x0801369c` | `SOC_EEPROM_LoadCalibration` | 204B | Kalibrierung aus EEPROM laden |
| `0x080101e4` | `Full_OCV_Lookup` | 204B | Volle OCV-Tabelle |
| `0x0800fade` | `SOC_Current_Bracket_Lookup` | 198B | Strom-Bracket-Lookup |
| `0x08011558` | `SOC_Set_From_External` | 174B | SOC extern setzen |
| `0x08010320` | `Temperature_Index_Lookup` | 174B | Temperatur-Index-Lookup |
| `0x0800fdf0` | `Max_Charge_Current_Calc` | 220B | Max Ladestrom berechnen |
| `0x0800fee8` | `Max_Discharge_Current_Calc` | 236B | Max Entladestrom berechnen |
| `0x0800fd3c` | `SOC_LoadCalibration_Float` | 166B | Kalibrierung als Float laden |
| `0x08013c90` | `SOC_EEPROM_SaveIfChanged` | 154B | Bei Änderung in EEPROM speichern |
| `0x080114c4` | `Quick_OCV_Lookup` | 142B | Schnelle OCV-Tabelle |
| `0x08013d98` | `SOC_Coulomb_Count_Tick` | 284B | Coulomb-Count Tick |
| `0x08009f70` | `PerPack_Struct_Builder` | 580B | Per-Pack Struct aufbauen |
| `0x0800f9d8` | `SOC_State_Detect` | 126B | SOC-Zustand erkennen (Laden/Entladen/Idle) |
| `0x080105e8` | `SOC_Update_Accumulator` | 124B | Akkumulator aktualisieren |
| `0x080100f4` | `SOC_Calc_Percentage_From_Range` | 112B | Prozent aus Bereich berechnen |
| `0x0801042c` | `SOC_Calc_Percentage_Inverse` | 108B | Prozent invers berechnen |
| `0x08013844` | `soc_algorithm_dump` | 106B | SOC-Algorithmus Debug-Dump |
| `0x080137dc` | `SOC_Save_To_EEPROM` | 94B | SOC in EEPROM speichern |
| `0x08013d44` | `SOC_Init_From_OCV_Lookup` | 84B | SOC aus OCV-Tabelle init |
| `0x08013460` | `SOC_Check_Temperature_Current_Reset` | 78B | Temp/Strom Reset-Prüfung |
| `0x080134ae` | `SOC_Calculate_OCV_From_Voltage` | 64B | OCV aus Spannung berechnen |
| `0x0800fa74` | `OCV_Voltage_To_Index` | 78B | Spannung → OCV-Index |
| `0x080102b4` | `OCV_Correction` | 44B | OCV-Korrektur |
| `0x080102e4` | `Capacity_Factor_Calc` | 44B | Kapazitätsfaktor berechnen |
| `0x0800f078` | `SOC_Smoothing` | 60B | SOC-Glättung |
| `0x080134f0` | `SOC_Algorithm_Entry` | 38B | SOC-Algorithmus Einstieg |
| `0x0800f2f4` | `SOC_Init_And_Load_Calibration` | 38B | Init + Kalibrierung laden |
| `0x0800f2b8` | `SOC_Set_NearFull_Threshold_990000` | 54B | Fast-Voll-Schwelle (99%) |
| `0x0800f914` | `SOC_Set_Full_Charge_1000000` | 60B | Voll-Lade-Schwelle (100%) |
| `0x0800f95c` | `SOC_Set_Empty_Discharge_Zero` | 60B | Leer-Schwelle (0%) |
| `0x0800f778` | `SOC_Set_LowSOC_Threshold_10000` | 58B | Niedrig-SOC-Schwelle (1%) |
| `0x0800f5c8` | `SOC_Init_Capacity_And_Percentages` | 42B | Kapazität + Prozente init |
| `0x0800fcdc` | `SOC_Check_Max_Capacity_Valid` | 44B | Max-Kapazität gültig? |
| `0x0800fd0c` | `SOC_Check_Min_Capacity_Valid` | 44B | Min-Kapazität gültig? |
| `0x0800f9bc` | `SOC_Get_Charge_Current_If_SOC_Above_8` | 20B | Ladestrom wenn SOC > 8% |
| `0x0800fa60` | `SOC_Select_Threshold_3700_3600` | 18B | Schwelle 3700/3600 mV |
| `0x0800facc` | `SOC_Select_Threshold_2420_2750` | 18B | Schwelle 2420/2750 mV |
| `0x08013798` | `SOC_Read_Flash_Cycle_Counters` | 64B | Zykluszähler aus Flash |
| `0x0801376c` | `SOC_Init_Params_To_Invalid` | 42B | Parameter auf ungültig init |
| `0x08016cec` | `Full_Recalibration` | 66B | Vollständige Rekalibrierung |
| `0x08011940` | `str_to_float` | 232B | String → Float Konvertierung |

### Protect — Batterieschutz (8 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08008420` | `Current_Protection_Checker` | 544B | Stromschutz-Prüfer |
| `0x080087f4` | `HW_Overcurrent_Protection` | 366B | HW-Überstromschutz |
| `0x0800b180` | `Warning_Bitmask_Builder` | 170B | Warnung-Bitmask aufbauen |
| `0x0800b280` | `Protect1_Bitmask_Caller` | 170B | Protect1 Bitmask (Caller) |
| `0x0800b230` | `Protect1_Bitmask_Builder` | 76B | Protect1 Bitmask aufbauen |
| `0x0800b330` | `Protect2_Bitmask_Builder` | 72B | Protect2 Bitmask aufbauen |
| `0x08014844` | `Protect_Update_NTC_MinMax` | 102B | NTC Min/Max aktualisieren |
| `0x08012b64` | `Protect_Set_Error_Lock` | 68B | Fehler-Sperre setzen |
| `0x0800933c` | `Protect_Debounce_Counter_A` | 42B | Entprell-Zähler A |
| `0x08009366` | `Protect_Debounce_Counter_B` | 42B | Entprell-Zähler B |
| `0x08009548` | `voltage_protection_check` | 38B | Spannungsschutz-Check |
| `0x0800f9b0` | `Protect_Get_MaxChgCurrent_Div10` | 6B | Max Ladestrom ÷ 10 |

### NTC — Temperatursensoren (6 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800b9e8` | `NTC_Lookup_Table_1` | 282B | NTC Lookup-Tabelle 1 |
| `0x0800bbd8` | `NTC_Lookup_Table_2` | 282B | NTC Lookup-Tabelle 2 |
| `0x08001254` | `ADC_Read_NTC_Temperature_Ch9` | 106B | ADC NTC Kanal 9 lesen |
| `0x080012cc` | `ADC_Read_NTC_Temperature_Ch2` | 106B | ADC NTC Kanal 2 lesen |
| `0x08011454` | `NTC_Calculate_Temperature` | 104B | Temperatur berechnen |
| `0x080154b4` | `NTC_Convert_Active_Sensors` | 76B | Aktive Sensoren konvertieren |
| `0x080069f4` | `NTC_ADC_To_Temperature` | 68B | ADC-Wert → Temperatur |
| `0x08008fa0` | `NTC_Count_Out_Of_Range_Sensors` | 46B | Out-of-Range Sensoren zählen |
| `0x08001144` | `ADC_DMA_Init` | 148B | ADC DMA initialisieren |

### OTA — Firmware Update (7 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800df0c` | `BMS_OTA_Upgrade_StateMachine` | 1128B | OTA Upgrade State Machine |
| `0x0800a9f8` | `BMS_OTA_Flash_Writer` | 910B | OTA Flash-Writer |
| `0x0800a1d8` | `RS485_OTA_Flash_Handler` | 728B | RS485 OTA Flash Handler |
| `0x0800cbe0` | `OTA_Precondition_Manager` | 342B | OTA Vorbedingungen prüfen |
| `0x0800ae70` | `OTA_PreCharge_Relay_Sequence` | 242B | OTA Precharge-Relay Sequenz |
| `0x08001b74` | `OTA_Heartbeat_And_Relay_Sequence` | 202B | OTA Heartbeat + Relay |
| `0x08006acc` | `OTA_Validate_FW_Version` | 124B | FW-Version validieren |
| `0x0800d5f4` | `Flash_Erase_Range` | 124B | Flash-Bereich löschen |
| `0x0800d674` | `Flash_Write_Words` | 130B | Words in Flash schreiben |
| `0x0800eda8` | `OTA_Set_Reboot_Params` | 34B | Reboot-Parameter setzen |

### Sonstige (9 Funktionen)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800e678` | `vprintf` | 1696B | Printf-Implementierung |
| `0x0800e514` | `__dtoa_engine` | 334B | Double-to-ASCII Engine |
| `0x0800cb24` | `Precharge_StateMachine` | 162B | Precharge State Machine |
| `0x0800632c` | `EXTI_Config` | 142B | EXTI-Interrupt konfigurieren |
| `0x08004ece` | `RTC_Read_DateTime` | 246B | RTC Datum/Uhrzeit lesen |
| `0x0800508c` | `RTC_Set_DateTime_BCD` | 212B | RTC setzen (BCD-Format) |
| `0x08004fc4` | `INIT_RTC_And_DateTime` | 50B | RTC initialisieren |
| `0x08001c4c` | `TIM2_TIM3_Init` | 208B | Timer 2/3 initialisieren |
| `0x080089e0` | `RTOS_vTaskKA495XX` | 156B | FreeRTOS KA495XX Task |
| `0x08003dc4` | `HAL_GPIO_Control_Switch` | 90B | GPIO Steuer-Switch |

---

*Erstellt via Ghidra + ReVa MCP — Statische Analyse ohne Live-Gerät*
