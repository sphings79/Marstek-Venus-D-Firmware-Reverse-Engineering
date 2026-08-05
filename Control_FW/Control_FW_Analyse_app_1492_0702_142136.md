# Marstek Venus D — Modbus Reverse Engineering Dokumentation
## Vollständige Analyse-Dokumentation — Venus D (VNSD-0) v3 (Juli 2026)

**Gerät:** Marstek Venus D (`VNSD-0`), STM32 ARM Cortex-M, FreeRTOS, 6 Batterie-Packs  
**Firmware (aktuell):** `VNSD-0_app_1492_0702_142136.bin` — Version **149.2** (Juli 2026)  
**Ziel:** Vollständige Modbus-Register-Map für die Home Assistant Integration `marstek_venus_modbus`  
**Status:** Register-Map des Geräts vollständig live-gescannt (89 Read + 41 Write, Adressraum 0–65535). Firmware 149.2 statisch analysiert — Modbus-Handler, Descriptor-Struktur und Eintrags-Format rekonstruiert (**246 Descriptor-Einträge**). Cloud-API & OTA-Infrastruktur analysiert (9 MCU-Komponenten). Descriptor-Tabelle wird zur Laufzeit aufgebaut → Registernummern nur per Live-Scan enumerierbar (firmwareseitig bewiesen, s. Abschnitt 0.3). **Inverter-Telemetrie-Brücke vollständig dekodiert** — alle 20 Felder des 48-Byte-Blocks mit Klartext-Namen, Einheiten und SRAM-Adressen beider MCUs (s. Abschnitt 0.6). **Dual-MCU-Architektur**, DC-Bus-Topologie, Pack-Rotation und PV-Verhalten dokumentiert (s. Abschnitt 0.7). **Cloud-Telemetrie-Feldnamen** aller 9 Report-Typen aus FW-Strings dekodiert (s. Abschnitt 11.8). WiFi/BLE-Modul als **Quectel FC41D** identifiziert. **RS485 RTU Modbus-Interface** als vollständiger paralleler Stack entdeckt (CRC16, Slave-Adr-Prüfung, FC03/FC06/FC10+Broadcast, s. Abschnitt 2.1). **Write-Handler statisch dekompiliert** — ~50 Write-Register aus Code extrahiert, davon viele **write-only** (unsichtbar im FC03-Batch-Scan, s. Abschnitt 7.6).

> **Fokus:** Diese Dokumentation betrachtet ausschließlich den **Venus D (VNSD-0)**.

---

## Inhaltsverzeichnis

1. [Hardware & Firmware-Architektur](#1-hardware--firmware-architektur)
2. [Modbus-Protokoll-Details](#2-modbus-protokoll-details)
3. [Descriptor-Tabelle (Interne Struktur)](#3-descriptor-tabelle-interne-struktur)
4. [Bekannte Flash-Adressen (Ghidra)](#4-bekannte-flash-adressen-ghidra)
5. [Bekannte SRAM-Adressen](#5-bekannte-sram-adressen)
6. [Bestätigte Read-Register (30000–39999)](#6-bestätigte-read-register-30000-39999)
7. [Bestätigte Write-Register (40000–49999)](#7-bestätigte-write-register-40000-49999)
8. [Kritische Besonderheiten](#8-kritische-besonderheiten)
9. [MQTT-Feldnamen → Register-Mapping](#9-mqtt-feldnamen--register-mapping)
10. [Marstek Local API — Parallelprotokoll & Cross-Validierung](#10-marstek-local-api--parallelprotokoll--cross-validierung)
11. [Marstek Cloud API & OTA-Infrastruktur](#11-marstek-cloud-api--ota-infrastruktur)
12. [Offene Punkte & nächste Schritte](#12-offene-punkte--nachste-schritte)
13. [Ghidra-Detailanalysen: Interessante Funde](#13-ghidra-detailanalysen-interessante-funde)

> **Ausgelagerte Dokumentation:**
> - [Analyse_Skripte.md](Analyse_Skripte.md) — Scan-, FW-Analyse- und Ghidra-Skripte
> - [Reverse_Engineering_Methodik.md](Reverse_Engineering_Methodik.md) — FW beschaffen, Ghidra-Setup, Methodik
> - [Ghidra_Analyse_Erkenntnisse.md](Ghidra_Analyse_Erkenntnisse.md) — Falsch/korrekt identifizierte Funktionen, Falsche Fährten

---

> **Hinweis:** Diese Dokumentation wurde für die Veröffentlichung anonymisiert.
> Gerätespezifische Werte (UID, MAC, Seriennummer, IP) wurden durch Platzhalter ersetzt.
> Die technischen Inhalte (Register-Map, Protokoll-Details, Firmware-Analyse) sind vollständig.

## Binary-Fingerprint

Live aus Ghidra verifiziert (Stand 2026-07-15). Ein Vergleich mit den anderen fünf analysierten
Firmware-Images (Control 147, VNS 116/115, BMS 118/117.7) steht in der Projekt-`README.md`.

| Eigenschaft | Wert |
|---|---|
| Datei | `VNSD-0_app_1492_0702_142136.bin` |
| Version | 149.2 (aktuell) |
| Größe | 385.024 B (0x5E000, 376 KB) |
| Architektur | ARM Cortex-M4F, Thumb-2, Little-Endian |
| Flash-Bereich | `0x08000000–0x0805DFFF` |
| Initial SP | `0x2001F7D8` (~128 KB SRAM) |
| Reset Handler | `0x08004A71` |
| Funktionen | 1618 / 1622 benannt (99,8 %) |
| Strings | 1743 |
| Compiler | GCC |
| RTOS | FreeRTOS (`heap_4`, `ARM_CM4F`-Port) |
| Crypto | mbedTLS 2.28.10 |
| Kommunikation | WiFi + Ethernet (CH395) + RS485 + CAN |

---

## 0. Firmware 149.2 — Aktueller Stand (Juli 2026)

> Dieser Abschnitt fasst die statische Analyse der **aktuellen** Firmware
> `VNSD-0_app_1492_0702_142136.bin` (149.2) zusammen. Die Abschnitte 1–12 und die
> Anhänge darunter enthalten die **vollständige akkumulierte RE-Analyse** des Geräts
> (Protokoll, Register-Map, Local API, Cloud/OTA, Local-Update-Verfahren).
> Skripte, Methodik und Ghidra-Erkenntnisse sind in separate Dokumente ausgelagert
> (s. Inhaltsverzeichnis). Wo firmware-spezifische Adressen/Zahlen genannt werden, gilt für 149.2
> dieser Abschnitt 0 als maßgeblich.

### 0.1 Firmware-Eckdaten

```
Datei:      VNSD-0_app_1492_0702_142136.bin
Größe:      385.024 Bytes
Flash:      0x08000000 – 0x0805DFFF
Reset-Vec:  0x08004A70   (IVT @0x08000004 = 0x08004A71 → belegt Link-Basis 0x08000000)
Initial-SP: 0x2001F7D8   (IVT @0x08000000)
Ghidra:     ARM:LE:32:Cortex, 1.615 Funktionen (Stand Juli 2026)
```

> **Ghidra-Import Pflichtschritt:** Image wird per Default auf `0x00000000` geladen — dann
> lösen keine absoluten Pointer auf. **Vor der Analyse: Image-Basis auf `0x08000000` setzen
> (Memory Map → Set Image Base) und Auto-Analyse erneut laufen lassen.**

### 0.2 Modbus-Handler & Descriptor-Tabelle (149.2)

| Funktion (149.2) | Rolle |
|---|---|
| `FUN_0801e43c` | Dispatcher (FC-Auswahl; FC `0x03` → Read-Handler) |
| `FUN_0801eaa4` | FC03-Read-Handler (Descriptor-Iteration) |
| `FUN_0804fe20` | Read-Serializer (Typ-/Scale-Konvertierung) |
| `FUN_08050f20` | Write-Handler (Register ≥ 40000) |

```
Descriptor-Basis:  0x20000354 (SRAM)   Einträge: 246 (0xF6)   Stride: 12 Byte
Tabellen-Ptr:      DAT_0801EC30 (=0x20000354); 2. Referenz @0x08029F50 (RS485-Router)
Read/Write-Split:  Register 40000        Max. Count: 0x7D = 125 (Transport: 32er-Batch)
Dual-Interface:    TCP (:502) + RS485 RTU — beide nutzen denselben Serializer/Write-Handler
```

**Eintrags-Format (12 Byte, verifiziert aus Serializer `FUN_0804fe20`):**
`+0` u16 Register (direkt) · `+4` u32 Live-Pointer · `+8` Typ · `+9` low-nibble = Elementgröße ·
`+10` Scale · `+11` Count. Registerbereich pro Eintrag: `reg_start + (byte9 & 0xF) × byte11 / 2`.

**Typ-Codes:** `01`=u8, `02`=u16, `04`=u32 · high-nibble `1`=signed (`11`=i8, `12`=i16, `14`=i32) ·
`24`=float (IEEE-754) · `31`=ASCII (memcpy direkt, kein Scale).

**Scale-Codes (Integer-Typen):** `0`=×1 · `1`=×10 · `2`=×100 · `3`=÷10 · `4`=÷100 · `5`=negate.
**Scale-Codes (Float-Typen):** `0`=×1 · `1`=×10 · `2`=×100 · `3`=×0.1 · `4`=×0.01
(Float-Konstanten @ `0x0805009C`/`A0`/`A4`; Konvertierung via `VectorFloatToUnsigned`).

**FC03-Read-Flow (149.2):**
1. `FUN_0801eaa4` (FC03_Read_Handler) prüft `reg < 40000` → Descriptor-Table-Lookup
2. Iteriert 246 Einträge (0xF6, stride 0xC) ab `LiteralPool_DescriptorBasePtr` (0x20000354)
3. Matching-Eintrag → `FUN_0804fe20` (Read_Serializer) konvertiert SRAM-Daten → Modbus-Response
4. `reg >= 40000` → Delegation an Write-Handler mit `param3=0` (Lese-Modus)
5. Spezialfall: Zugriff auf 38000–39014 setzt Flag bei SRAM 0x20000EE5

> **Siehe auch:** `Read_Handler_Register_Map.csv` — vollständige Read-Register-Map (194 Register,
> konsolidiert aus Scan-Daten, FW-Verifikation und Pack-Muster-Extrapolation).

> **Neu in 149.2:** Ein Lese-Zugriff im Bereich **38000–39014** (`0x9867`) setzt ein
> Zustandsflag bei SRAM `0x20000EE5`.

### 0.3 Beweis: Descriptor-Tabelle wird zur Laufzeit gebaut

Die 246 Registernummern sind aus dem Flash **nicht statisch enumerierbar** (erschöpfende Suche):
(1) kein aufsteigendes Register-Array im Flash (nur False-Positive `0x08036C10`),
(2) keine dichten Register-`MOVW`-Immediates (Spitzenreiter Write-Handler `FUN_08050f20`, nur 27 Konstanten),
(3) nur **2** Code-Referenzen auf die Basis `0x20000354` — beide Reader, **kein** Builder,
(4) kein `.data`-Template (Pointer-Signatur @+2/+4/+6/+8 in CCM+SRAM negativ; `_sidata+0x354` negativ),
(5) 0xF6 (246) als Literal nur in den 2 Readern, nicht im Builder,
(6) 36 `add rx, ry, ry, lsl #1` Kandidaten (stride-3×4 Muster) analysiert — keine Matches,
(7) Init-Tabelle bei `0x08055158` (24B-Einträge) referenziert nur SRAM 0x20000000–0x20000028,
(8) Cloud-Telemetrie Format-Strings liegen bei `0x0805EC04` — **außerhalb des geladenen Binaries**
    (Flash endet bei 0x0805DFFF), d.h. in separater Flash-Partition.

⇒ Der Builder empfängt die Tabellen-Basis **als Parameter** (kein Literal-Pool-Zugriff) und die
Registernummern/SRAM-Pointer kommen aus einer **separaten Flash-Datenpartition** jenseits des
Applikations-Images. Enumeration nur per **Live-Scan** oder **Emulation**.

### 0.4 Krypto, Cloud & Telemetrie (149.2)

- **mbedTLS 2.28.10** (SDK-Pfade `..\SDK\mbedtls_2.28.10\library\...`) — für AES-Key-Extraktion
  des `setVenusDReporting`-Payloads die `mbedtls_aes_setkey_enc`-Call-Sites tracen.
- Reporting-Endpoint: `http://%s.hamedata.com/prod/api/v1/setVenusDReporting?v=%s`.
- Payload-Schema (AES-Klartext) 70+ Felder, u. a. `…&bke=%s&bkd=%s&ip=%s&bt_p=%s&ival=%d&soh=%d`.
- 16-Zellen bestätigt (`b_vo1…b_vo16`); BMS via J1939-PGN (`pgn_1801/1802`); SOC-Scale 0.1
  (`bat_soc(0.1)=%d`); 4 PV-Strings.

### 0.5 OTA-Status-Update & Micro-Komponente

> **Aktualisierung ggü. früherem Stand:** Der VNSD-0 ist inzwischen **im OTA-System gelistet**
> (frühere Leer-Antwort überholt). Verfügbar: **`control` v149** und **`micro` v116**.

| Komponente | Rolle | Datei | Status |
|---|---|---|---|
| `control` | EMS / Haupt-MCU | `VNSD-0_app_1492_0702_142136.bin` (149.2) | ✅ analysiert |
| `micro` | Inverter-Co-Prozessor (`vd_inv_app`) | `vd_inv_app_0116_0702_ota_163439.bin` (116) | ✅ analysiert (eigene Doku) |

Der `micro`-Baustein ist ein **separater** Wechselrichter-Controller (ARM Cortex-M4F, RVDS/Keil,
FreeRTOS, ~40 KB SRAM). Vollständige Analyse in separatem Dokument:
`Micro_Inverter_FW_Analyse_vd_inv_app_0116.md`.

### 0.6 Inverter-Telemetrie — CAN/RS485-Brücke zur Modbus-Registern

> **Neu in v2.** Der vollständige Datenfluss von den Inverter-Sensoren zu den Modbus-Registern
> wurde aus beiden Firmwares rekonstruiert.

**Architektur:**
```
Micro-MCU ADC-Sensoren
    ↓ (FP-Kalibrierung, RMS-Berechnung)
Micro-MCU SRAM (0x200018xx float → int16 × Scale)
    ↓ (build_telemetry_block @ FUN_08001560)
48-Byte Telemetrie-Block (Micro SRAM 0x200038E8)
    ↓ (CAN CMD 0x10 / RS485)
Control-MCU SRAM: 0x20014E90  (Inverter-Daten-Struct)
    ↓ (Modbus Descriptor-Tabelle, Pointer → 0x20014E90+offset)
Modbus TCP Port 502 (FC03 Read)
```

**Debug-Dump:** `FUN_08035ffc` im Control-FW druckt alle 20 Telemetrie-Felder mit Klartext-Namen.
Drei weitere Blöcke (Version @ `0x2000015C`, Status @ `0x20000144`) werden ebenfalls exponiert.

#### Vollständige Telemetrie-Block-Zuordnung (48 Bytes)

| Offset | Bytes | Control-FW Feldname | Einheit | Typ | Micro-FW Source SRAM | Chinesisch |
|--------|-------|---------------------|---------|-----|---------------------|------------|
| 0x00 | 1 | **inv_state** | — | byte | `0x2000046D` (ctl_status) | — |
| 0x01 | 1 | **buz_state** | — | byte | (immer 0) | — |
| 0x02 | 1 | **chrg_flag** | — | byte | `0x200002B3` (grid_connected) | — |
| 0x03 | 1 | **back_func** | — | byte | `0x20003E03` (backup_mode) | — |
| 0x04 | 4 | **warn_code** | — | u32 | `0x200019FC` (war1) | — |
| 0x08 | 4 | **error_code1** | — | u32 | `0x200019F4` (err1) | — |
| 0x0C | 4 | **error_code2** | — | u32 | `0x200019F8` (err2) | — |
| 0x10 | 2 | **grid_volt** | 0.1 V | u16 | `0x200018E4` (grid_voltage_rms) | 电网电压有效值 |
| 0x12 | 2 | **grid_pf** | 0.1 Hz | u16 | `0x200002F0` (grid_frequency) | 捕获频率 |
| 0x14 | 2 | **off_grid_volt** | 0.1 V | u16 | `0x200018BC` (offgrid_voltage_rms) | 离网电压有效值 |
| 0x16 | 2 | **grid_permit** | — | u16 | `0x200002AB` | — |
| 0x18 | 2 | **grid_sample_power** | 1 W | i16 | `0x200018F0` (actual_power) | 实际功率 |
| 0x1A | 2 | **off_grid_power** | 1 W | i16 | `0x200018C8` (output_power) | 发出功率 |
| 0x1C | 2 | **bat_sample_power** | 1 W | i16 | `0x20000E00` | — |
| 0x1E | 2 | **bat_sample_volt** | 0.1 V | i16 | `0x20000E10` (bat_vol_avg) | — |
| 0x20 | 2 | **env_temp** | 0.1 °C | i16 | `0x20000E30` (ntc_inv) | — |
| 0x22 | 2 | **radiator_temp** | 0.1 °C | i16 | `0x20000E34` (ntc_mppt) | — |
| 0x24 | 2 | **max_power** | W | i16 | `0x2000030C` | — |
| 0x26 | 2 | **min_power** | W | i16 | `0x20000310` | — |
| 0x28 | 4 | **chrg_energy** | 1 Wh | u32 | `0x20003E83` (daily_charge) | 日充电 |
| 0x2C | 4 | **dischrg_energy** | 1 Wh | u32 | `0x20003E87` (daily_discharge) | 日放电 |

#### Control-FW SRAM-Mapping (Pointer → Modbus)

Basis: `0x20014E90` (34 Referenzen in der Control-FW). Alle Modbus-Descriptor-Entries
für Inverter-Daten zeigen als Live-Value-Pointer direkt in diese Struct:

| Control SRAM | = Base + | Telemetrie-Feld | Vermutetes Modbus-Register |
|---|---|---|---|
| `0x20014EA0` | +0x10 | grid_volt (0.1V) | **32200** |
| `0x20014EA2` | +0x12 | grid_pf (0.1Hz) | **32204** |
| `0x20014EA4` | +0x14 | off_grid_volt (0.1V) | **32300** |
| `0x20014EA8` | +0x18 | grid_sample_power (W) | **32100** (?) |
| `0x20014EAA` | +0x1A | off_grid_volt_mirror (0.1V) | **32301** — **Korrektur:** Spannungs-Duplikat von 32300, nicht Leistung, s. Vermutungen_Register_Analyse.md |
| `0x20014EAC` | +0x1C | bat_sample_power (W) | **32102** (?) |
| `0x20014EAE` | +0x1E | bat_sample_volt (0.1V) | in Scan als 34000-range? |
| `0x20014EB0` | +0x20 | env_temp (0.1°C) | **35000–35002** |
| `0x20014EB2` | +0x22 | radiator_temp (0.1°C) | **35003–35005** |
| `0x20014EB8` | +0x28 | chrg_energy (Wh) | **33000** (u32, 2 Register) |
| `0x20014EBC` | +0x2C | dischrg_energy (Wh) | **33004** (u32, 2 Register) |

> **Hinweis:** Die genauen Modbus-Registernummern werden durch die Runtime-Descriptor-Tabelle
> bestimmt. Die „vermuteten" Nummern stammen aus dem Live-Scan (`scan_komplett.csv`) und dem
> marstek2mqtt-Referenzprojekt. Eine definitive Bestätigung erfordert entweder einen gezielten
> Scan der einzelnen Register oder Emulation der Descriptor-Builder-Routine.

#### Status-Block (8 Bytes, `0x20000144`)

| Offset | Typ | Name | Beschreibung |
|---|---|---|---|
| 0x00 | byte | work_mode | 0=Normal, 1=Test, 4=Update, 0xC=Factory |
| 0x01 | byte | sleep_flag | Schlafmodus-Flag |
| 0x02 | byte | bat_mode | Batteriemodus |
| 0x04 | u16 | max_charge_power | Max. Ladeleistung (≤2500 W) |
| 0x06 | u16 | max_discharge_power | Max. Entladeleistung (≤2500 W) |

#### Version-Block (4 Bytes, `0x2000015C`)

| Offset | Typ | Name |
|---|---|---|
| 0x00 | byte | hard_ver |
| 0x01 | byte | soft_ver (= 116 für vd_inv v116) |
| 0x02 | byte | boot_ver |
| 0x03 | byte | dev_state |

### 0.7 System-Architektur & Betriebsverhalten (Neu in v3)

> **Cross-FW-Erkenntnisse** aus der Analyse aller drei Firmwares (Control, Micro, BMS).
> Details in den jeweiligen FW-spezifischen Dokumentationen.

#### Dual-MCU-Architektur

```
┌─────────────────────────────┐    RS485/UART     ┌─────────────────────────────┐
│  CONTROL-MCU (EMS)          │◄═════════════════►│  MICRO-MCU (Inverter)       │
│  STM32F4, ~128KB SRAM       │                   │  STM32F4, ~40KB SRAM        │
│  GCC, FreeRTOS              │                   │  RVDS/Keil, FreeRTOS        │
│                             │                   │                             │
│  WiFi (FC41D) + Ethernet    │                   │  LLC-Wandler (DC-DC)        │
│  Modbus TCP :502            │                   │  H-Brücke (DC-AC)           │
│  MQTT Cloud                 │                   │  MPPT (PV-Regler)           │
│  BLE                        │                   │  CAN → BMS-Packs            │
│  mbedTLS                    │                   │                             │
└─────────────────────────────┘                   └──────────────┬──────────────┘
                                                                 │ CAN-Bus
                                                  ┌──────────────▼──────────────┐
                                                  │  BMS-Master (Pack 1)        │
                                                  │  STM32F3, ~52KB SRAM        │
                                                  │  RVDS/Keil, FreeRTOS        │
                                                  │  KA495XX Zellmonitoring     │
                                                  │  RS485 → Slave-Packs 2-7   │
                                                  └─────────────────────────────┘
```

**Kommunikationskette:**
- Control → Micro: RS485/UART (Leistungs-Sollwert, Modi)
- Micro → BMS: CAN-Bus (`0x40xx/41xx` intern + `0x180xAA01` BMS-Protokoll)
- BMS Master → Slaves: RS485 (96-Byte Struct-Transfer, CMD 0x29)
- Control → Cloud: MQTT über WiFi/Ethernet (TLS, mbedTLS)
- Control → HA: Modbus TCP Port 502

#### DC-Bus-Topologie (ein Inverter, ein Leistungspfad)

```
PV-Panels ──→ MPPT ──→ DC-Bus (~400V) ←── LLC-Wandler ←── Batterie-Packs
                            │                                 (parallel)
                       H-Brücke (DC-AC)
                            │
                       AC-Grid (Hausnetz)
```

**Kritische Einschränkung:** Der Venus D hat nur **einen bidirektionalen Leistungspfad**.
Es gibt nur einen `set_inverter_power(float)` Aufruf (Bootloader-Funktion `0x10000160`):
- **Negativ** → Laden (PV/Grid → Batterie)
- **Positiv** → Entladen (Batterie → Grid, PV fließt ebenfalls ins Grid)
- **Null** → Inverter aus (PV wird komplett gedrosselt)

Dies ist KEIN echter Hybrid-Wechselrichter (wie Fronius/SMA mit separaten PV→Grid und
PV→Batterie Pfaden). Konsequenz: PV kann nicht gleichzeitig laden UND ins Netz einspeisen.

#### Beobachtetes PV-Drosselungsverhalten

Bei steigendem SOC reduziert die BMS-Strom-Limit-Matrix (`0x0801B884`, 2D: Temperatur × SOC)
den erlaubten Ladestrom progressiv. Da nur ein Leistungspfad existiert, wird PV gedrosselt:

```
SOC  50% → charge_limit hoch   → Inverter: -2500W → PV voll genutzt
SOC  90% → charge_limit sinkt  → Inverter: -1000W → PV teilweise gedrosselt
SOC  99% → charge_limit minimal → Inverter: -100W  → PV fast komplett gedrosselt
SOC 100% → charge_limit = 0    → Inverter: 0W     → PV komplett gedrosselt
→ Richtungswechsel → Entladen → PV fließt wieder ins Grid
```

#### Pack-Rotation (Round-Robin)

Die Micro-MCU orchestriert die Pack-Selektion über CAN-Kommandos an die BMS-Packs:
- **CAN CMD 6** → aktiviert einen Pack (Adress-basiert, MOSFET ein)
- **CAN CMD 3** → Handoff zum nächsten Pack (data = nächste Pack-Adresse)

Timer (aus Micro-FW Mode 3):
- Haupt-Zyklus: **3600s (60 Min)** — SOC-basierte Richtungsentscheidung
- Sub-Timer: **600s (10 Min)** — CAN-Update an BMS

Die Control-MCU gibt nur den Gesamt-Leistungs-Sollwert vor (CAN CMD 0x01);
die Pack-Selektion im Normalmodus (Mode 0/1/2) wird vermutlich ebenfalls in der
Control-FW gesteuert — dieser Scheduler ist noch nicht identifiziert.

#### Separate FW-Dokumentationen

| Firmware | Dokument | Schlüssel-Inhalte |
|---|---|---|
| Control v149.2 | (dieses Dokument) | Modbus-Handler, Descriptor-Tabelle, Telemetrie-Empfang |
| Micro/Inverter v116 | `Micro_Inverter_FW_Analyse_vd_inv_app_0116.md` | CAN-Protokoll, Telemetrie-Builder, Lade-/Entlade-Steuerung, DC-Bus |
| BMS v117.7 | `BMS_FW_Analyse_v117.7.md` | SOC-Algorithmus, Cell-Struct, Protect-Bitmasks, RS485, Round-Robin |

---

## 1. Hardware & Firmware-Architektur

### MCU & Betriebssystem

```
MCU:        STM32 (ARM Cortex-M, Thumb-2, Little-Endian)
OS:         FreeRTOS
Flash:      0x08000000 – 0x0805DFFF  (385.024 Bytes)
SRAM:       0x20000000 – 0x2001FFFF  (128 KB)
Ext-RAM:    0x60000000 – 0x6001FFFF  (CH395Q oder ähnlich, für Netzwerkpuffer)
```

### Firmware-Binary-Eigenschaften

```
Datei:      VNSD-0_app_1492_0702_142136.bin
Größe:      385.024 Bytes
IVT:        0x08000000  (Interrupt Vector Table, ARM-Standard)
Reset-Vec:  0x08004A70  (aus IVT+4: 0x08004A71)
Initial-SP: 0x2001F7D8  (aus IVT+0)
```

### Subsysteme

| Komponente | Beschreibung |
|---|---|
| CH395Q | Ethernet-Controller (SPI → Modbus TCP Port 502) |
| FC41D | WiFi 802.11b/g/n + BLE 5.0 (UART AT-Befehle) |
| RS485 | 47.400 Baud, Modbus RTU → Inverter/EMS |
| mbedTLS | Version **2.28.10** — AES-128/256, RSA, ECDH secp256r1 (Cloud-TLS + Telemetrie-Verschlüsselung) |
| MQTT | Gerät kommuniziert mit `eu.hamedata.com` |

### Kommunikationskanäle (vollständig)

Das Gerät exponiert **fünf Protokoll-Stacks** (Modbus TCP und RS485 RTU teilen sich
den Backend-Handler). Für die HA-Integration wird **ausschließlich Modbus TCP** verwendet:

| Kanal | Port / Medium | Protokoll | Status für HA |
|---|---|---|---|
| **Modbus TCP** | :502 (Ethernet/WiFi) | Modbus FC03/FC06/FC16 | ✅ Aktiv nutzen |
| **RS485 RTU** | UART 47400 Baud | Modbus RTU FC03/FC06/FC10 | ℹ️ Paralleler Stack (s. 2.1) |
| **Local API** | UDP :30000 (WiFi) | JSON-RPC | ⛔ NICHT aktivieren (s. Abschnitt 10) |
| **BLE** | Bluetooth LE | HM-Protokoll (0x23-Frames) | ℹ️ Nur Monitoring-Tool rweijnen |
| **Cloud/MQTT** | TCP :8883 TLS | MQTT → `eu.hamedata.com` | ❌ Kein lokaler Zugriff |

### FreeRTOS-Tasks (aus String-Analyse)

```
Task_Modbus_tcp    - Modbus TCP Server (Port 502)
ch395              - Ethernet-Controller
fc41d              - WiFi/BLE-Modul (Quectel FC41D, bestätigt via OTA-String "FC41D_OTA.rbl")
ch_mqtts           - MQTT-Client (Cloud)
rs485              - RS485/Modbus RTU
ems                - Energy Management System
udp                - UDP-Listener → Local API (Port 30000, JSON-RPC)
```

> **Hinweis zu `udp`-Task:** Früher als "Discovery auf Port 8899" erfasst.
> Nach Analyse der offiziellen Local API Doku (REV 0.5) ist der Default-Port 30000.
> Dieser Task implementiert den Local API JSON-RPC Daemon.
> **Aktivierung verursacht Modbus-Fehler — siehe Abschnitt 10.**

---

## 2. Modbus-Protokoll-Details

### Verbindung

```
Protokoll:    Modbus TCP
Port:         502
Slave-ID:     1
Max. Request: 32 Register pro Read-Request (Modbus-Standard)
```

### Register-Adressierung

**Wichtig:** Marstek verwendet **direkte Adressierung** — die Modbus-PDU-Adresse entspricht exakt der sichtbaren Register-Nummer. Es gibt keinen Offset in irgendeiner Richtung.

```
User-Register 30000  →  PDU-Adresse 30000  (0x7530)   ← kein -1
User-Register 34002  →  PDU-Adresse 34002  (0x84D2)   ← kein -1
Grenze Read/Write:   40000 (0x9C40)
```

> **Beweis aus TCPRouter.c (Decompilat):**
> `uVar6 = CONCAT11(param_1[0], param_1[1])` → rohe PDU-Adresse, unverändert.
> `if (uVar6 < descriptor.base_addr)` → direkter Vergleich, kein Offset.
> `Serializer.c`: `offset = PDU_addr - base_addr` → bei Reg 30000 und `base_addr=30000` ist Offset=0. ✅
>
> **Unterschied zu Standard-Modbus:** Im klassischen Modbus-Standard gilt
> „Register 1 = PDU-Adresse 0" (User-Nummer minus 1). Marstek ignoriert diese
> Konvention vollständig. pymodbus-Aufruf: `read_holding_registers(30000)` → korrekt.

### Register-Bereiche

| Bereich | Typ | Beschreibung | Status |
|---|---|---|---|
| 0 – 29.999 | – | Leer | ✅ Gescannt — **keine Register vorhanden** |
| 30.000 – 39.999 | Read | Sensor-/Status-Daten | ✅ 89 Register bestätigt |
| 40.000 – 49.999 | Write | Steuerregister | ✅ 41 Register bestätigt |
| 50.000 – 65.535 | – | Leer | ✅ Gescannt — **keine Register vorhanden** |

> **Fazit:** Der vollständige Modbus-Adressraum (0–65535) wurde gescannt.
> Alle Register des Geräts befinden sich ausschließlich im Bereich 30000–49999.
> Die Bereiche 0–29999 und 50000–65535 liefern keine Antworten.

### Routing-Logik (aus Dekompilation, 149.2)

```c
// Dispatcher FUN_0801e43c → FC03 Read-Handler FUN_0801eaa4:
if (uVar6 >= 40000)  →  Write-Handler  (FUN_08050f20)
if (uVar6 < 40000)   →  Read-Serializer (FUN_0804fe20)

// Tabellen-Iteration (FUN_0801eaa4):
for (uVar4 = 0; uVar4 < 246; uVar4++) {
    // Vergleicht angefragte Adresse mit Tabellen-Einträgen
    (&DAT_20000354)[uVar4 * 6]  // ushort* Zugriff = 12 Bytes/Eintrag
}
```

### 2.1 RS485 RTU Modbus-Interface (Parallel-Stack)

> **Neu in v3.1.** Neben dem TCP-Stack existiert ein vollständiger **RS485 RTU Modbus-Stack**,
> der dieselbe Descriptor-Tabelle und denselben Write-Handler nutzt.

**Entdeckung:** Über Cross-References auf die zweite Descriptor-Tabellen-Referenz
(`DAT_08029F50` bei `0x08029F50`) wurde der RS485-Router gefunden. Dieser Stack
ist komplett unabhängig vom TCP-Server und läuft auf dem FreeRTOS-Task `rs485`.

**Architektur:**

```
UART-Empfang (FUN_080541f8)
    ↓
RS485_RTU_Frame_Dispatcher (0x0801e6b0)
    ├─ CRC16-Prüfung (Modbus_CRC16_Calculate @ 0x0801e678)
    ├─ Slave-Adresse abgleichen (inline, kein separater Aufruf)
    └─ FC-Routing:
         FC03 → RS485_RTU_Modbus_Router (0x08029df8)
                 ├─ Reg < 40000 → Read_Serializer (0x0804fe20)  ← identisch mit TCP
                 └─ Reg ≥ 40000 → Write_Handler (0x08050f20)    ← identisch mit TCP
         FC06 → RS485_FC06_WriteSingle_Handler (0x08029f54)
         FC10 → RS485_FC10_WriteMultiple_Handler (0x0802a028)
         Broadcast (Addr 0):
              FC06 → RS485_Broadcast_FC06_WriteSingle (0x08029fe0)
              FC10 → RS485_Broadcast_FC10_WriteMultiple (0x0802a108)
    ↓ Antwort
RS485_UART_Send (0x080072a0)
```

**Besonderheiten:**

- **Shared Backend:** RS485 und TCP nutzen denselben Read-Serializer (`FUN_0804fe20`)
  und Write-Handler (`FUN_08050f20`). Alle über TCP erreichbaren Register sind
  auch über RS485 erreichbar und umgekehrt.
- **Broadcast-Support:** Slave-Adresse 0 wird als Broadcast erkannt — FC06/FC10
  werden ausgeführt, aber keine Antwort gesendet.
- **CRC16:** Standard-Modbus-CRC16 in `Modbus_CRC16_Calculate` (`0x0801e678`).
- **Spezial-Flags:** Im Dispatcher:
  - Flag `0x01` bei `DAT_0801e87c` → `System_Reboot` (`0x08029c78`)
  - Flag `0x02` → `Factory_Reset` (`0x0800b724`)
  - `FUN_08050524(5)` wird bei bestimmten Fehlerzuständen aufgerufen
- **Sonderbereich 38000–39014:** Ein Lese-Zugriff über RS485 in diesem Bereich
  setzt ebenfalls das Flag bei `DAT_08029f4c` (analog zum TCP-Flag bei `0x20000EE5`).

**TCP-Dispatcher (Vergleich):**

Der TCP-Dispatcher (`FUN_0801e43c`) hat ebenfalls dedizierte FC06/FC10-Handler:

| Adresse | Funktion |
|---|---|
| `0x0801e880` | `TCP_FC06_WriteSingle_Handler` |
| `0x0801e904` | `TCP_FC06_WriteSingle_Handler_B` |
| `0x0801e94c` | `TCP_FC10_WriteMultiple_Handler` |
| `0x0801ea0c` | `TCP_FC10_WriteMultiple_Handler_B` |

---

## 3. Descriptor-Tabelle (Interne Struktur)

Die Tabelle wird zur **Laufzeit im SRAM aufgebaut** und existiert nicht als statische Flash-Struktur.

### SRAM-Position

```
Adresse:     0x20000354 (SRAM)
Einträge:    246 (0xF6)
Größe:       246 × 12 = 2.952 Bytes (bis 0x20000EDC)
```

### Eintrag-Format (12 Bytes)

```c
struct RegisterDescriptor {     // 12 Bytes pro Eintrag
    uint16_t  base_addr;        // [0:2]  Direkte PDU-Adresse (= User-Register-Nummer, kein Offset)
    uint16_t  padding;          // [2:4]  unbekannt/padding
    uint32_t* data_ptr;         // [4:8]  SRAM-Zeiger auf Rohdaten
    uint8_t   data_type;        // [8]    Datentyp
    uint8_t   reg_size;         // [9]    Größe in Registern (& 0x0F)
    uint8_t   scale;            // [10]   Skalierungscode
    uint8_t   count;            // [11]   Anzahl Elemente
};
```

### Datentyp-Codes

| Code | Typ | Größe |
|---|---|---|
| 0x01 | uint8 | 1 Byte |
| 0x02 | uint16 | 2 Bytes |
| 0x04 | uint32 | 4 Bytes |
| 0x11 | int8 | 1 Byte |
| 0x12 | int16 | 2 Bytes |
| 0x14 | int32 | 4 Bytes |
| 0x24 | float32 | 4 Bytes |
| 0x31 | ASCII | variabel |

### Skalierungs-Codes

| Code | Bedeutung | Beispiel |
|---|---|---|
| 0x00 | × 1 | Rohwert direkt |
| 0x01 | × 10 | Rohwert × 10 |
| 0x02 | × 100 | Rohwert × 100 |
| 0x03 | ÷ 10 (= × 0.1) | Rohwert 3116 → 311.6 |
| 0x04 | ÷ 100 (= × 0.01) | Rohwert 5012 → 50.12 V |
| 0x05 | negieren | Rohwert × −1 |

### Serializer-Logik (aus Serializer.c)

```c
// Float-Typ ($=0x24):
local_3c = *(float *)(data_ptr + element_index * 4);
// Skalierung anwenden...
// Andere Typen:
case 0x02: local_38 = *(ushort*)(data_ptr + offset);
case 0x12: local_38 = *(short*)(data_ptr + offset);
case 0x14: local_38 = *(uint*)(data_ptr + offset);
// Scale switch:
case 0x03: local_38 = local_38 / 10;
case 0x04: local_38 = local_38 / 100;
case 0x05: local_38 = -local_38;
```

---

## 4. Bekannte Flash-Adressen (Ghidra)

| Flash-Adresse | Funktion / Label | Beschreibung |
|---|---|---|
| `0x08000000` | IVT | Interrupt-Vektortabelle |
| `0x08004A70` | Reset-Vec | Reset-Handler (149.2) |
| **Modbus TCP** | | |
| `0x0801e43c` | Modbus_Dispatcher | **TCP Dispatcher** (FC-Routing, 149.2) |
| `0x0801eaa4` | FC03_Read_Handler | **FC03 Read-Handler** (Descriptor-Iteration) |
| `0x0804fe20` | Read_Serializer | **Read-Serializer** (Typ-/Scale-Konvertierung) |
| `0x08050f20` | Write_Handler | **Write-Handler** (Register ≥ 40000, 3958 Bytes, 942 Zeilen) |
| `0x0801e880` | TCP_FC06_WriteSingle_Handler | TCP FC06 Write Single |
| `0x0801e904` | TCP_FC06_WriteSingle_Handler_B | TCP FC06 Write Single (Variante B) |
| `0x0801e94c` | TCP_FC10_WriteMultiple_Handler | TCP FC10 Write Multiple |
| `0x0801ea0c` | TCP_FC10_WriteMultiple_Handler_B | TCP FC10 Write Multiple (Variante B) |
| **RS485 RTU** | | |
| `0x0801e6b0` | RS485_RTU_Frame_Dispatcher | UART→CRC→Slave-Adr→FC-Routing |
| `0x0801e678` | Modbus_CRC16_Calculate | CRC16 Berechnung/Prüfung |
| `0x08029df8` | RS485_RTU_Modbus_Router | RS485 Read/Write-Dispatcher (246 Einträge) |
| `0x08029f54` | RS485_FC06_WriteSingle_Handler | RS485 FC06 Write Single |
| `0x0802a028` | RS485_FC10_WriteMultiple_Handler | RS485 FC10 Write Multiple |
| `0x08029fe0` | RS485_Broadcast_FC06_WriteSingle | RS485 Broadcast FC06 (Addr 0) |
| `0x0802a108` | RS485_Broadcast_FC10_WriteMultiple | RS485 Broadcast FC10 (Addr 0) |
| `0x080072a0` | RS485_UART_Send | RS485 UART-Antwort senden |
| **System** | | |
| `0x08029c78` | System_Reboot | NVIC-Reset via SCB_AIRCR (50ms Delay) |
| `0x0800b724` | Factory_Reset | Werksreset |
| **Descriptor / Scale** | | |
| `0x0801EC30` | Literal-Pool | Tabellen-Basis-Pointer → `0x20000354` |
| `0x08029F50` | Literal-Pool | 2. Descriptor-Ptr (RS485-Router) |
| `0x0805009C` | Scale-Konst. | IEEE-754: 100.0 (Scale-Code 2) |
| `0x080500A0` | Scale-Konst. | IEEE-754: 0.1 (Scale-Code 3) |
| `0x080500A4` | Scale-Konst. | IEEE-754: 0.01 (Scale-Code 4) |

### Wichtige Fehlidentifikationen

> ⚠️ `FUN_080128a0` (enthält MOVW #0x7530) ist **kein** Descriptor-Init!
> Es ist ein JSON-Config-Parser. Der Wert 0x7530 = 30.000 ist dort ein **Standard-API-Port**, nicht eine Register-Adresse.

> ⚠️ `FUN_0801bcb0` ist der **RS485/RTU Paket-Handler**, nicht die Descriptor-Initialisierung.

---

## 5. Bekannte SRAM-Adressen

Aus WriteHandler.c dekompiliert:

| SRAM-Adresse | Variable | Bedeutung |
|---|---|---|
| `0x20000133` | `DAT_20000133` | Modbus Slave-Adresse |
| `0x20000156` | `_DAT_20000156` | Max Entladeleistung (short) |
| `0x20000158` | `DAT_20000158` | Max Ladeleistung (short) |
| `0x2000027c` | `DAT_2000027c` | RS485-Steuerung aktiv (0/1/2) |
| `0x200002ec` | `DAT_200002ec` | Reset-Kommando-Status |
| `0x200002ed` | `DAT_200002ed` | Betriebsmodus (work_mode) |
| `0x200002ee` | `DAT_200002ee` | Lade-Ziel-SOC |
| `0x200002f0` | `DAT_200002f0` | Entlade-Leistungsvorgabe (short) |
| `0x200002f2` | `DAT_200002f2` | Lade-Leistungsvorgabe (short) |
| `0x20000354` | `DAT_20000354` | **Descriptor-Tabellen-Basis** |
| `0x20014b6c` | `DAT_20014b6c` | Backup/UPS-Funktion aktiv |
| `0x20014b6d` | `DAT_20014b6d` | Betriebsmodus intern |
| `0x20014b6f..` | Schedule-Daten | Zeitplan-Enable-Bytes |
| `0x20014c25..` | Schedule-Times | Zeitplan-Start/Ende/Power |

---

## 6. Bestätigte Read-Register (30000–39999)

**Scan-Datum:** Mai 2026 | **Gerät:** Marstek Venus D, 6 Batterie-Packs  
**Bedingung:** PV nicht angeschlossen (MPPT-Werte = Leerlauf ~9.9V)

### 6.1 Leistung & AC-Netz

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30001 | battery_power | int16 | 1 | W | 65525 | −11 W (Entladung) |
| 30006 | ac_power | int16 | 1 | W | 0 | 0 W |
| 32200 | ac_voltage | uint16 | 0.1 | V | 2398 | 239.8 V |
| 32204 | ac_frequency | int16 | 0.1 | Hz | 499 | 49.9 Hz |
| 32300 | ac_offgrid_voltage | uint16 | 0.1 | V | 3 | 0.3 V (Offgrid aus) |
| 32301 | ac_offgrid_voltage_2 | uint16 | 0.1 | V | 3 | 0.3 V — **Korrektur:** ist Spannung, nicht Strom (Duplikat/Mirror von 32300, identisch in allen 28 Scans, s. Vermutungen_Register_Analyse.md) |
| 32302 | ac_offgrid_power | int32 | 1 | W | 0 | 0 W (2 Register) |
| 37004 | grid_power_setpoint | int16 | 1 | W | 65038 | −498 W — **Korrektur:** kein Strom-Register; nahezu wertgleich mit 30006 (Watt-Größenordnung), reagiert bei Setpoint-Wechsel ~1 Scan-Zyklus schneller (vermutlich interner Soll-/Regelwert), s. Vermutungen_Register_Analyse.md |

### 6.2 MPPT / PV-Eingänge

| Register | Name | Typ | Scale | Einheit | Hinweis |
|---|---|---|---|---|---|
| 30020 | mppt1_voltage | uint16 | 0.1 | V | Leerlauf = 9.9V bei nicht angeschlossenem PV |
| 30021 | mppt2_voltage | uint16 | 0.1 | V | dto. |
| 30022 | mppt3_voltage | uint16 | 0.1 | V | dto. |
| 30023 | mppt4_voltage | uint16 | 0.1 | V | dto. |
| 30024 | mppt1_current | uint16 | 0.1 | A | |
| 30025 | mppt2_current | uint16 | 0.1 | A | |
| 30026 | mppt3_current | uint16 | 0.1 | A | |
| 30027 | mppt4_current | uint16 | 0.1 | A | |
| 30037 | mppt1_power | uint16 | 0.1 | W | |
| 30038 | mppt2_power | uint16 | 0.1 | W | |
| 30039 | mppt3_power | uint16 | 0.1 | W | |
| 30040 | mppt4_power | uint16 | 0.1 | W | |

### 6.3 Batterie Pack 1

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30100 | battery_voltage | uint16 | 0.01 | V | 5012 | 50.12 V |
| 30101 | battery_current | int16 | 0.1 | A | 0 | 0.0 A |
| 32105 | battery_total_energy | uint16 | 0.001 | kWh | 5120 | 5.120 kWh |
| 34002 | battery_soc | uint16 | **0.1** | % | 109 | **10.9 %** ⚠️ |
| 34003 | battery_cycle_count | uint16 | 1 | – | 14 | 14 Zyklen |
| 34010 | battery_1_bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version pro Pack) |
| 34018 | battery_1_cell_1_voltage | int16 | 0.001 | V | 3116 | 3.116 V |
| 34019 | battery_1_cell_2_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34020 | battery_1_cell_3_voltage | int16 | 0.001 | V | 3113 | 3.113 V |
| 34021 | battery_1_cell_4_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34022 | battery_1_cell_5_voltage | int16 | 0.001 | V | 3113 | 3.113 V |
| 34023 | battery_1_cell_6_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34024 | battery_1_cell_7_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34025 | battery_1_cell_8_voltage | int16 | 0.001 | V | 3119 | 3.119 V |
| 34026 | battery_1_cell_9_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34027 | battery_1_cell_10_voltage | int16 | 0.001 | V | 3116 | 3.116 V |
| 34028 | battery_1_cell_11_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34029 | battery_1_cell_12_voltage | int16 | 0.001 | V | 3117 | 3.117 V |
| 34030 | battery_1_cell_13_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34031 | battery_1_cell_14_voltage | int16 | 0.001 | V | 3112 | 3.112 V |
| 34032 | battery_1_cell_15_voltage | int16 | 0.001 | V | 3114 | 3.114 V |
| 34033 | battery_1_cell_16_voltage | int16 | 0.001 | V | 3113 | 3.113 V |

### 6.4 Batterie Pack 2 (inferiert, +100er Block)

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 34100 | battery_2_voltage | uint16 | 0.01 | V | 5125 | 51.25 V |
| 34102 | battery_2_soc | uint16 | 0.1 | % | 120 | 12.0 % |
| 34103 | battery_2_cycle_count | uint16 | 1 | – | 13 | 13 |
| 34105 | battery_2_max_cell_voltage | uint16 | 0.001 | V | 3205 | 3.205 V |
| 34106 | battery_2_min_cell_voltage | uint16 | 0.001 | V | 3203 | 3.203 V |
| 34110 | battery_2_bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version, nicht Temperatur!) |
| 34111 | battery_2_max_cell_temp | int16 | 0.1 | °C | 235 | 23.5 °C |
| 34118–34133 | battery_2_cell_1..16_voltage | int16 | 0.001 | V | ~3203–3205 | ~3.2 V |

### 6.5 Temperaturen

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 35000 | internal_temperature | int16 | 0.1 | °C | 300 | 30.0 °C |
| 35001 | internal_mos1_temperature | int16 | 0.1 | °C | 313 | 31.3 °C |
| 35002 | internal_mos2_temperature | int16 | 0.1 | °C | 312 | 31.2 °C |
| 35010 | max_cell_temperature | int16 | 0.1 | °C | 216 | 21.6 °C |

### 6.6 Status & Alarms

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 35100 | inverter_state | uint16 | 1 | – | 2 | Zustandscode 2 |
| 36000 | alarm_status | uint32 | 1 | Bitmask | 0 | Kein Alarm (2 Register) |
| 36100 | fault_status | uint64 | 1 | Bitmask | 2388 | Fehler-Bits (4 Register) |
| 37007 | max_cell_voltage | uint16 | 0.001 | V | 3339 | 3.339 V |
| 37008 | min_cell_voltage | uint16 | 0.001 | V | 3337 | 3.337 V |
| 37012 | bms_version | uint16 | 1 | – | 116 | **v116** (BMS-Version, Systemebene) |

### 6.7 Energie-Zähler

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 33000 | total_charging_energy | uint32 | 0.01 | kWh | (2 Register) | 63.62 kWh |
| 33002 | total_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |
| 33004 | total_daily_charging_energy | uint32 | 0.01 | kWh | 0 | 0 kWh |
| 33006 | total_daily_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |
| 33008 | total_monthly_charging_energy | uint32 | 0.01 | kWh | 0 | 0 kWh |
| 33010 | total_monthly_discharging_energy | int32 | 0.01 | kWh | 0 | 0 kWh |

### 6.8 Firmware & Geräteinformation

| Register | Name | Typ | Scale | Einheit | Scan-Wert | Interpreted |
|---|---|---|---|---|---|---|
| 30200 | ems_version | uint16 | 1 | – | 147 | v147 |
| 30202 | vns_version | uint16 | 1 | – | 115 | v115 (**Korrektur:** OTA-bestätigt VNS, nicht VMS) |
| 30204 | bms_version | uint16 | 1 | – | 116 | v116 |
| 30300 | wifi_status | uint16 | 1 | – | 1 | Verbunden |
| 30301 | active_inverter_state | uint16 | 1 | – | 3 | **Korrektur:** NICHT bluetooth_status (durch Backup-Test-Verhalten widerlegt) — wechselt im Backup-Test 1→2→3→2→3, korreliert lose mit Pack-Rotation; genaue Funktion noch unklar, s. Vermutungen_Register_Analyse.md |
| 30302 | cloud_status | uint16 | 1 | – | 0 | Nicht verbunden |
| 30303 | wifi_signal_strength | uint16 | −1 | dBm | 50 | −50 dBm |
| 30304–30309 | mac_address | ASCII | – | – | – | AA:BB:CC:DD:EE:FF |
| 30350–30355 | comm_module_firmware | ASCII | – | – | – | 20240909_0159 |
| 31000–31009 | device_name | ASCII | – | – | – | VNSD-0 |

---

## 7. Bestätigte Write-Register (40000–49999)

### 7.1 Basis-Steuerung

| Register | Name | Typ | Beschreibung | Scan-Wert |
|---|---|---|---|---|
| 41000 | reset_device | uint16 | Geräte-Reset (0x55AA=BMS reset, 0xAA11=tieferer Reset) | 0 |
| 41100 | modbus_address | uint16 | Modbus Slave-Adresse (1–127) | 1 |
| 41200 | backup_function | uint16 | Backup/UPS-Funktion (0=aus, 1=ein) | 1 |

### 7.2 RS485-Steuerungsmodus

> ⚠️ **Pflicht:** Register 42000 = 0x55AA (21930) muss zuerst geschrieben werden, bevor 42010–42021 wirken!

| Register | Name | Typ | Beschreibung | Scan-Wert |
|---|---|---|---|---|
| 42000 | rs485_control_mode | uint16 | 0x55AA = RS485-Steuerung aktiv | 21930 (aktiv!) |
| 42010 | force_mode | uint16 | 0=Keine Vorgabe, 1=Laden, 2=Entladen | 0 |
| 42011 | charge_to_soc | uint16 | Ziel-SOC (0–100%) | 100 |
| 42020 | set_charge_power | uint16 | Lade-Leistungsvorgabe (W, max 2500) | 0 |
| 42021 | set_discharge_power / inverter_power_limit | uint16 | Entlade-Leistungsvorgabe (W, max 2500); im Backup-Load-Test durchgängig konstant bei **2200W beobachtet = maximale Inverter-Ausgangsleistung** (erklärt, warum 30006 nie über ~2209W geht), s. Vermutungen_Register_Analyse.md | 0 |

### 7.3 Betriebsmodus

| Register | Name | Typ | Werte | Scan-Wert |
|---|---|---|---|---|
| 43000 | user_work_mode | uint16 | 0=Eigenverbrauch, 1=Anti-Einspeisung, 2=Handel | 1 |

### 7.4 Zeitplanung (6 Slots à 5 Register)

Jeder Slot (1–6) belegt Register `43100 + (slot-1)*5` bis `43104 + (slot-1)*5`:

| Offset | Name | Typ | Beschreibung |
|---|---|---|---|
| +0 | schedule_N_days | uint16 | Wochentage-Bitmask (Bit0=Mo, Bit6=So) |
| +1 | schedule_N_start | uint16 | Startzeit als HHMM (z.B. 0800 = 08:00) |
| +2 | schedule_N_end | uint16 | Endzeit als HHMM |
| +3 | schedule_N_mode | int16 | Leistung in W (−2500 bis +2500; negativ=Laden) |
| +4 | schedule_N_enabled | uint16 | 0=deaktiviert, 1=aktiv |

**Slot-Adressen:**

| Slot | Tage | Start | Ende | Mode | Enable |
|---|---|---|---|---|---|
| 1 | 43100 | 43101 | 43102 | 43103 | 43104 |
| 2 | 43105 | 43106 | 43107 | 43108 | 43109 |
| 3 | 43110 | 43111 | 43112 | 43113 | 43114 |
| 4 | 43115 | 43116 | 43117 | 43118 | 43119 |
| 5 | 43120 | 43121 | 43122 | 43123 | 43124 |
| 6 | 43125 | 43126 | 43127 | 43128 | 43129 |

### 7.5 Hardware-Limits (Read-only in Write-Bereich)

| Register | Name | Typ | Einheit | Scan-Wert |
|---|---|---|---|---|
| 44002 | max_discharge_power | uint16 | W | 2500 |
| 44003 | max_charge_power | uint16 | W | 2500 |

**Korrektur:** Vorherige Version dieser Tabelle hatte 44002/44003 vertauscht. Die
Zuordnung ist gemäß Write-Handler-Dekompilierung (Abschnitt 7.6) und SRAM-Tabelle
(Abschnitt 5): 44002 → SRAM `0x20000156` → max_discharge_power, 44003 → SRAM
`0x20000158` → max_charge_power.

### 7.6 Write-Handler — Vollständige statische Analyse (Neu in v3.1)

> **Quelle:** Dekompilierung von `FUN_08050f20` (Write_Handler), 3958 Bytes, 942 Zeilen Decompiler-Output.
> Viele dieser Register sind **write-only** — sie liefern Error-Code 2 bei FC03-Leseversuch
> (`param_3 == 0 → return 2`). Das erklärt, warum der FC03-Batch-Scan nur 41 Write-Register fand,
> obwohl die Descriptor-Tabelle 246 Einträge hat.

**Übersicht aller aus dem Code extrahierten Write-Register:**

| Register | SRAM-Ziel | Funktion | Write-only? | Persistence |
|---|---|---|---|---|
| **40000** | `DAT_080517a4` | RS485-Unlock (0x55AA=enable, 0x55A1–A6=Alt-Modi) | ✅ Ja | SRAM |
| **41000** | `DAT_080517a8` | Kommando (0x55AA→1, 0xAA11→2) | ✅ Ja | SRAM |
| **41100** | `0x20000133` | Modbus Slave-Adresse setzen | Nein | SRAM |
| **41200** | `0x20014b6c` | Backup/UPS enable | Nein | EEPROM 0x300 |
| **41500–41515** | Array | Zeitplan-Zeiteinstellungen (u16 Array) | ✅ Ja | SRAM |
| **41600–41631** | Array | Zeitplan-Leistungseinstellungen (u16 Array) | ✅ Ja | SRAM |
| **42011** | `0x200002ee` | charge_target_soc (13–100%) | Nein | SRAM |
| **42020** | `0x200002f0` | discharge_power_limit (max 2500W) | Nein | SRAM |
| **43100–43129** | `0x20014b6f+` | Zeitplan-Slots (6×5 Reg, 10-Byte-Struct) | Nein | EEPROM 0x36BF+ |
| **43492** | Status-Flag | OTA/Update-Status (0x55AA/0x55BB/0x55FF) | ✅ Ja | SRAM |
| **43502** | `0x200002ed` | work_mode (0=Eigenverbrauch, 1=Anti, 2=Handel) | Nein | SRAM |
| **43513** | `0x200002f2` | charge_power_limit (max 2500W) | Nein | SRAM |
| **44002** | `0x20000156` | max_discharge_power (max 2500W) | Nein | SRAM |
| **44003** | `0x20000158` | max_charge_power (max 2500W) | Nein | SRAM |
| **44492** | EEPROM 0x301 | Inverter-Modus (0/1/2) | ✅ Ja | EEPROM 0x301 |
| **45000–45022** | diverse | Befehls-Register: Reboot, Reset, SMR, Power-Set, GPIO | ✅ Ja | SRAM |
| **45023–45029** | GPIO | HW-Debug (GPIO, SMR, Relais, WiFi-Reset) | ✅ Ja | SRAM |
| **45030** | Flag | BLE enable/disable | ✅ Ja | SRAM |
| **45031** | SMR-Relay | SMR Relay Control mit Retry | ✅ Ja | SRAM |
| **45539–45541** | ADC | BCD-Versionsnummer lesen (ADC-Messung) | ✅ Ja | SRAM |
| **45597** | Status | Read-only Status-Abfrage | Nein | SRAM |
| **46000** | EEPROM | OTA-Command (0x5100→EEPROM, diverse Modes) | ✅ Ja | EEPROM |
| **46500–46544** | EEPROM | 8-Byte-Structs, EEPROM-persistent, 3 Reg/Entry | ✅ Ja | EEPROM |
| **47400** | Debug | Debug-Register (R: 0xAABB, W: debug_printf) | Nein | SRAM |

> **⚠️ Diskrepanz Reg 40000 vs. 42000 (RS485-Unlock):**
> Der dekompilierte Write-Handler zeigt **Reg 40000** als den RS485-Unlock-Handler
> (0x55AA-Prüfung). Die bisherige Dokumentation und Live-Tests nutzen **Reg 42000**.
> Mögliche Erklärung: Reg 40000 ist write-only (Error 2 bei FC03) und wurde daher
> im Batch-Scan nie gefunden. In der Praxis funktioniert Reg 42000 — möglicherweise
> existiert ein zweiter Codepfad (z.B. über unrecovered Jump-Tables im Write-Handler),
> oder die Live-Dokumentation bezieht sich auf ein anderes Register mit derselben
> Unlock-Semantik. **Beide Varianten müssen per Live-Test verifiziert werden.**

**Zeitplan-Struct (10 Bytes, 6 Slots @ Reg 43100–43129):**

```c
struct ScheduleSlot {    // 10 Bytes, SRAM ab 0x20014b6f
    uint8_t  enable;     // +0: 0=deaktiviert, 1=aktiv
    uint16_t start_time; // +1: Startzeit (HHMM)
    uint16_t end_time;   // +3: Endzeit (HHMM)
    int16_t  power;      // +5: Leistung in W (negativ=Laden)
    uint8_t  mode;       // +7: Modus
    uint8_t  reserved[2];// +8: Padding
};
// EEPROM-Persistenz ab Offset 0x36BF
```

---

## 8. Kritische Besonderheiten

### 8.1 battery_soc Scale-Faktor (Reg 34002)

```
⚠️ Scale = 0.1  (NICHT 1!)
Rohwert 109 → 10.9%  (NICHT 109%)
```

### 8.2 Multi-Register-Werte

```python
# uint32 lesen (Energie-Zähler): 2 Register kombinieren
value = (reg_hi << 16) | reg_lo
kWh = value * 0.01

# uint64 lesen (fault_status): 4 Register kombinieren
value = (r0 << 48) | (r1 << 32) | (r2 << 16) | r3

# ASCII lesen (mac_address, device_name):
# Jedes Register = 2 ASCII-Zeichen (Big-Endian)
char1 = raw >> 8
char2 = raw & 0xFF
```

| Register | Anzahl | Typ | Kombination |
|---|---|---|---|
| 30304–30309 | 6 | ASCII | MAC-Adresse (12 Zeichen) |
| 30350–30355 | 6 | ASCII | Modul-Firmware |
| 31000–31009 | 10 | ASCII | Gerätename (20 Zeichen) |
| 32302–32303 | 2 | int32 | Offgrid-Leistung |
| 33000–33001 | 2 | uint32 | Lade-Energie gesamt |
| 33002–33003 | 2 | int32 | Entlade-Energie gesamt |
| 36000–36001 | 2 | uint32 | Alarm-Statusbits |
| 36100–36103 | 4 | uint64 | Fehler-Statusbits |

### 8.3 RS485-Steuerungssequenz

```python
# Reihenfolge ZWINGEND:
# 1. RS485-Steuerung aktivieren
client.write_register(42000, 0x55AA, slave=1)  # = 21930

# 2. Modus setzen (1 Sekunde warten)
import time; time.sleep(1)
client.write_register(42010, 1, slave=1)  # Laden erzwingen

# 3. Leistung setzen
client.write_register(42020, 2000, slave=1)  # 2000W laden
```

### 8.4 Vorzeichen-Konventionen

| Register | Positiv | Negativ |
|---|---|---|
| 30001 battery_power | Laden | Entladen |
| 37004 grid_power_setpoint | Einspeisung | Netzbezug |
| 30303 wifi_signal | Roh negieren! (raw×−1) | – |

---

## 9. MQTT-Feldnamen → Register-Mapping

Gefunden im Flash-String-Pool bei `0x08018000`.
Die Spalte *Local API* zeigt das äquivalente Feld aus der offiziellen
Marstek Local API REV 0.5 — als zusätzliche Verifikationsquelle:

| MQTT-Feld | Register | Beschreibung | Local API Äquivalent |
|---|---|---|---|
| `bat_soc` | 34002 | Batterie SOC (Scale 0.1!) | `ES.GetStatus.bat_soc` / `Bat.GetStatus.soc` |
| `bat_temp` | 35000 | Batterietemperatur | `Bat.GetStatus.bat_temp` |
| `bat_cap` / `bat_capacity` | – | Batteriekapazität | `Bat.GetStatus.bat_capacity` (aktuell) / `rated_capacity` (Nenn) |
| `ongrid_power` | 30006 | Netzleistung (AC) | `ES.GetStatus.ongrid_power` |
| `offgrid_power` | 32302 | Offgrid-Leistung | `ES.GetStatus.ogrid_power` |
| `pv_power` | MPPT-Summe | PV-Gesamtleistung | `ES.GetStatus.pv_power` / `PV.GetStatus.pv_power` |
| `total_pv_energy` | – (offen) | PV-Gesamtenergie | `ES.GetStatus.total_pv_energy` |
| `total_grid_output_energy` | 33002–33003 | Gesamteinspeisung | `ES.GetStatus.total_grid_output_energy` |
| `total_grid_input_energy` | 33000–33001 | Gesamtbezug | `ES.GetStatus.total_grid_input_energy` |
| `total_load_energy` | – (offen) | Verbraucher-Energie | `ES.GetStatus.total_load_energy` |
| `work_mode` | 43000 | Betriebsmodus | `ES.GetMode.mode` ("Auto"/"Manual"/"AI"/"Passive") |
| `tol_charge` | 33000 | Gesamte Ladeenergie | `ES.GetStatus.total_grid_input_energy` |
| `tol_discharge` | 33002 | Gesamte Entladeenergie | `ES.GetStatus.total_grid_output_energy` |
| `connect` / `disconnect` | 30300/30302 | Verbindungsstatus | `Wi.GetStatus` / `BLE.GetStatus` |
| `ble_mac` | 30304 | Bluetooth MAC | `Marstek.GetDevice.ble_mac` |
| `wifi_mac` | 30304 | WiFi MAC | `Marstek.GetDevice.wi_mac` |
| `wifi_name` | – | SSID | `Marstek.GetDevice.wi_name` / `Wi.GetStatus.ssid` |

---

## 10. Marstek Local API — Parallelprotokoll & Cross-Validierung

> **⛔ WARNUNG — NICHT AKTIVIEREN:**
> Mehrere Nutzerberichte belegen, dass das Aktivieren der Marstek Local API
> zu dauerhaft falschen oder eingefrorenen Modbus-Registerwerten führt.
> Der Fehler tritt auch nach Geräte-Reset oder Deaktivierung der API nicht zurück.
> Ursache ist ein geteilter interner Zustand (Mutex / SRAM-Pointer) zwischen
> dem Modbus-TCP-Task und dem UDP-JSON-Task im FreeRTOS-Scheduler.
> Das offizielle Dokument warnt selbst: *"some native functions of the device
> may be disabled to avoid command conflicts".*
>
> **Die Local API wird für die HA-Integration nicht verwendet.**
> Sie dient hier ausschließlich als Referenzquelle zur Verifikation
> unserer Modbus-Register-Bedeutungen.

### 10.1 Protokoll-Übersicht (Referenz)

| Eigenschaft | Wert |
|---|---|
| Dokument | Marstek Device Open API REV 0.5 (Draft, 04.07.2025) |
| Transport | UDP, Unicast und Broadcast |
| Port | Standard 30000, konfigurierbar (Empfehlung: 49152–65535) |
| Format | JSON-RPC (Methode + params → result) |
| Aktivierung | Marstek APP oder BLE-Befehl 0x28 — **beides vermeiden** |
| Authentifizierung | Keine (rein lokal, kein Token) |

### 10.2 Verfügbare Methoden (Referenz)

| Methode | Funktion | Typ |
|---|---|---|
| `Marstek.GetDevice` | Gerät im LAN entdecken | Read |
| `Wi.GetStatus` | WiFi-Status und Netzwerk-Info | Read |
| `BLE.GetStatus` | Bluetooth-Verbindungsstatus | Read |
| `Bat.GetStatus` | Batterie SOC, Temp, Kapazität, Fehlercode | Read |
| `PV.GetStatus` | PV-Leistung, Spannung, Strom | Read |
| `ES.GetStatus` | Energie-Systemstatus (Leistungen, Zähler) | Read |
| `ES.GetMode` | Aktuellen Betriebsmodus lesen | Read |
| `ES.SetMode` | Betriebsmodus setzen (Auto/AI/Manual/Passive) | **Write** |

### 10.3 Cross-Validierung: Local API ↔ Modbus-Register

Die folgenden Verknüpfungen wurden durch Abgleich der API-Beispielwerte
(REV 0.5) mit unseren Modbus-Scan-Ergebnissen ermittelt. Alle Übereinstimmungen
bestätigen die Korrektheit unserer RE-Ergebnisse.

| Local API Feld | Modbus Reg. | Scale | Verifikation |
|---|---|---|---|
| `ES.GetStatus.bat_soc` = 98 | **34002** battery_soc | ×0.1 → raw=980 | ✅ **Scale 0.1 offiziell bestätigt** |
| `ES.GetStatus.bat_power` = 501 W | **30001** battery_power | ×1 (int16) | ✅ Bedeutung bestätigt |
| `ES.GetStatus.ongrid_power` = 100 W | **30006** ac_power | ×1 (int16) | ✅ Bedeutung bestätigt |
| `ES.GetStatus.ogrid_power` = 0 W | **32302–32303** offgrid_power | int32 | ✅ Bedeutung bestätigt |
| `ES.GetStatus.pv_power` = 0 W | **30037–30040** mppt*_power | ×0.1, Summe | ✅ (PV nicht angeschlossen) |
| `ES.GetStatus.total_grid_input_energy` = 3273 Wh | **33000–33001** uint32 | ×0.01 kWh | ✅ Einheit Wh bestätigt |
| `ES.GetStatus.total_grid_output_energy` = 2548 Wh | **33002–33003** uint32 | ×0.01 kWh | ✅ Einheit Wh bestätigt |
| `Bat.GetStatus.soc` = 90 | **34002** battery_soc | ×0.1 → raw=900 | ✅ Zweite Bestätigung Scale 0.1 |
| `Bat.GetStatus.bat_temp` = 25.0 °C | **35000** internal_temperature | ×0.1 → raw=250 | ✅ Scale 0.1 für Temp bestätigt |
| `Bat.GetStatus.rated_capacity` = 5120 Wh | **35110 / 35111** (candidat) | ×1 Wh | ⚠️ Register noch nicht eindeutig gemappt |
| `Bat.GetStatus.error_code` = "0x430" | **36100–36103** fault_status | bitmask | ⚠️ Bit-Mapping noch offen |
| `PV.GetStatus.pv_voltage` = 40.0 V | **30020–30023** mppt*_voltage | ×0.1 → raw=400 | ✅ Scale 0.1 bestätigt |

### 10.4 Modus-Mapping: API ↔ Modbus

| Local API `ES.SetMode.mode` | Modbus Reg. 43000 | Modbus Steuerregister | Bedeutung |
|---|---|---|---|
| `"Auto"` | `0` (Eigenverbrauch) | – | Automatischer Eigenverbrauch |
| `"AI"` | kein direktes Äquivalent | – | KI-gesteuerter Modus (Cloud-Funktion) |
| `"Manual"` + `manual_cfg` | `1` (Anti-Feed-In) + Zeitpläne | 43100–43129 | Zeitgesteuerte Lade-/Entladeplanung |
| `"Passive"` + `power` + `cd_time` | force_mode 42010=1 oder 2 + 42020/42021 | – | Einmaliges Laden/Entladen mit Zeitlimit |

> **Hinweis zu "Passive":** Der Parameter `cd_time` (Countdown in Sekunden) hat
> kein direktes Modbus-Äquivalent in unseren gescannten Registern.
> Er wird vermutlich intern durch den EMS-Task verwaltet und ist über
> Modbus nicht lesbar/setzbar. Für HA-Automatisierungen ist die
> force_mode-Steuerung via Modbus (42010 + 42020/42021) vollwertig.

### 10.5 Neue Register-Kandidaten aus API-Feldern

Diese API-Felder haben noch kein bestätigtes Modbus-Äquivalent:

| API Feld | Typ | Kandidat-Register | Begründung |
|---|---|---|---|
| `ES.GetStatus.total_pv_energy` | Wh | 33004–33005? | Analog zu grid_input/output Pattern |
| `ES.GetStatus.total_load_energy` | Wh | 33006–33007? | Weiterer uint32-Zähler im 33000er-Block |
| `Bat.GetStatus.rated_capacity` | Wh (5120) | 35110 oder 35111 | raw=576→57.6? Nein. Oder direkt 5120? |
| `Bat.GetStatus.bat_capacity` | Wh (aktuell) | 34008? | Verbleibende Kapazität in Wh |
| `ES.GetStatus.bat_cap` | Wh gesamt | 30003 oder 30004? | 30004=2364 passt nicht; 5120 noch nicht gesehen |

---

## 11. Marstek Cloud API & OTA-Infrastruktur

### 11.1 Analyse-Tool

Das Open-Source-Tool **marstek-fw-checker** (von Remko Weijnen, GitHub: `rweijnen/marstek-fw-checker`)
wurde zur Analyse der Marstek-Cloud-API verwendet. Es läuft als statische Webseite
mit Netlify-Functions als CORS-Proxy und erlaubt Login, Geräteabfrage und OTA-Check.

```bash
# Lokaler Start (kein Netlify nötig für Basis-Funktion):
cd marstek-fw-checker-master/
python -m http.server 8000
```

### 11.2 Cloud-API-Endpunkte (aus Script-Analyse)

| Endpunkt | Pfad | Zweck |
|---|---|---|
| Authentifizierung | `/app/Solar/v2_get_device.php` | Login + Geräteliste (MD5-Passwort) |
| Gerätliste (detail) | `/ems/api/v1/getDeviceList` | Detailierte Gerätedaten inkl. Versionen |
| OTA Standard | `/ems/api/v2/checkSmallBalconyOTA` | Firmware-Check für Venus-Geräte |
| OTA CT-Geräte | `/ems/api/v1/checkAcCoupleOta` | Firmware-Check für HME-3/HME-4 |
| Einstellungen | `/ems/api/v1/getAdvance` | Erweiterte Geräteeinstellungen |

**Basis-URL (EU):** `https://eu.hamedata.com`

### 11.3 OTA-Request-Parameter (für VNSD-0)

Das Tool sendet `m=100` als Baseline-Version, um alle verfügbaren
Firmware-Einträge zu erhalten. Der vollständige Request für den Venus D:

```
GET https://eu.hamedata.com/ems/api/v2/checkSmallBalconyOTA
    ?uid=<devid>
    &device_type=VNSD-0
    &m=100
    &sbv=0
    &mppt=0
    &inv=0
    &click=false
    &lang=English
    &is_fourDigit={"control":false,"bms":false,"micro":false,"mppt":false}
    &token=<auth-token>
    &mailbox=<email>
```

**Ergebnis für VNSD-0 (Stand Juli 2026):** VNSD-0 ist inzwischen **im OTA-System gelistet**.
Verfügbar: **`control` v149** und **`micro` v116**. Frühere Dokumentation (Mai 2026) meldete
eine leere Antwort — die Server-Einträge für VNSD-0 wurden seitdem hinzugefügt.

**Staged Rollout:** Die OTA-Verteilung erfolgt in Wellen. Selbst für
unterstützte Gerätetypen erhalten nicht alle Geräte
gleichzeitig Firmware-Updates — abhängig von Gerätealter, Region und
möglicherweise `dlock`-Status.

### 11.4 Vollständige MCU-Komponenten-Matrix (OTA API)

Der `/ems/api/v2/checkSmallBalconyOTA`-Response enthält **9 Komponenten-Felder**.
Der vollständige Response für VNSD-0 (18.05.2026) lautet:

```json
{
  "code": 1,
  "show": 0,
  "msg": "success",
  "data": {
    "control":   "",
    "bms":       "",
    "mppt":      "",
    "micro":     "",
    "dcdc":      "",
    "bms_pack1": "",
    "bms_pack2": "",
    "led":       "",
    "charger":   ""
  }
}
```

> **Neu gegenüber Rev 7:** Die Felder `dcdc`, `led` und `charger` waren bisher
> nicht dokumentiert. Sie wurden durch Auswertung des vollständigen Raw-API-Response
> identifiziert.

Für VNSD-0 sind `control` (v149) und `micro` (v116) verfügbar; die übrigen Felder bleiben leer.

#### Vollständige Komponenten-Tabelle aller 9 API-Felder

| API-Feld | MCU / Subsystem | Beschreibung | VNSD-0 (Juli 2026) |
|---|---|---|---|
| `control` | EMS-Hauptcontroller | Energy Management, Modbus TCP, WiFi | **v149** |
| `bms` | BMS-Hauptcontroller | Battery Management System (alle Packs) | – (leer) |
| `micro` | Inverter-MCU | Wechselrichter-Controller | **v116** |
| `mppt` | MPPT-Controller | Solarladeregler | – (leer) |
| `dcdc` | DC/DC-Konverter-MCU | Bidirektionaler DC/DC-Wandler | – (leer) |
| `bms_pack1` | Pack-1-BMS | Individuelle Pack-1-Firmware | – (leer) |
| `bms_pack2` | Pack-2-BMS | Individuelle Pack-2-Firmware | – (leer) |
| `led` | LED-Controller | Statusanzeige-MCU / LED-Steuerung | – (leer) |
| `charger` | Lade-Controller | AC-Lader / Netzladegerät | – (leer) |

> **Hinweis zu `bms_pack1`/`bms_pack2`:** Pack-individuelle OTA-Felder werden serverseitig
> nicht befüllt, obwohl das Gerät mehrere Packs unterstützt.

#### `is_fourDigit` Parameter — Bedeutung für Versionsregister

Der Request enthält:
```json
"is_fourDigit": {"control": false, "bms": false, "micro": false, "mppt": false}
```

Dieses Flag zeigt, ob die jeweilige Komponente eine 4-stellige Versionsnummer hat.
Aktuell meldet das Gerät überall `false` (3-stellige Versionen: 147, 116, 115).
Wenn eine neue Firmware-Generation auf 4-stellige Nummern (z. B. 1001) wechselt,
wird dieses Flag `true` — nützlich als Indikator für Major-Updates.

> **Sicherheitshinweis:** Auth-Token (`token=`) und E-Mail-Adresse stehen im
> Klartext in der OTA-Request-URL. Logs, die diese URL enthalten, sollten vor
> der Weitergabe bereinigt werden.

### 11.5 Cloud Device Record — Marstek Venus D

Vollständiger API-Response für das analysierte Gerät (`/ems/api/v1/getDeviceList`):

```json
{
  "devid":        "<DEVICE_UID>",
  "name":         "MST_VNSD_xxxx",
  "sn":           "MVDxxxxxxxxxx",
  "mac":          "xxxxxxxxxxxx",
  "type":         "VNSD-0",
  "access":       "1",
  "bluetooth_name": "MST_VNSD_xxxx",
  "date":         "2026-04-21 11:20:08",
  "id":           <CLOUD_ID>,
  "dlock":        "Y",
  "timeZone":     "Europe/Berlin",
  "version":      "147",
  "soc":          80,
  "battery_num":  1,
  "status":       1,
  "isVppDevice":  "N"
}
```

### 11.7 Analyse des Device Records

| Feld | Wert | Bedeutung / Auffälligkeit |
|---|---|---|
| `type` | `VNSD-0` | Bestätigt Gerätetyp |
| `version` | `"147"` | **Control/EMS-Firmware** (nicht BMS) — identisch mit Reg 30200 |
| `soc` | `80` | Cloud-SoC zum Abfrage-Zeitpunkt (von Gerät gemeldet) |
| `battery_num` | `1` | ⚠️ Cloud meldet nur 1 Pack, obwohl 2 verbaut |
| `dlock` | `"Y"` | **Device Lock aktiv** — könnte OTA-Update blockieren |
| `salt` | `"d1f1900057185ec9,d1f1900057185ec9"` | Zwei identische Werte kommagetrennt — evtl. je ein Salt pro Pack |
| `date` | `2026-04-21` | Registrierungsdatum (Gerät relativ neu) |
| `isVppDevice` | `"N"` | Kein Virtual Power Plant / Aggregator |
| `status` | `1` | Online |

**Zu `battery_num: 1`:** Die Cloud sieht nur einen Pack, obwohl beide Packs
per Modbus lesbar sind (Register 34000 und 34100). Wahrscheinlich meldet das
Gerät im MQTT-Heartbeat nur den primären Pack — oder die Cloud-Logik
zählt das Gerät selbst als "Batterie Unit 1".

**Zu `dlock: "Y"`:** Device Lock ist ein unbekanntes Flag, das vermutlich
von Marstek serverseitig gesetzt wird. Mögliche Bedeutungen: Support-Hold,
bekannte Inkompatibilität der aktuellen Firmware mit dem Update,
oder generelle Sperre für nicht-offizielle Gerätetypen im OTA-System.

---

### 11.8 OTA-Komponenten → Modbus-Versionregister-Mapping

Die 9 API-Komponenten lassen sich teilweise auf Modbus-Register zurückführen.
Das Muster im 30200er-Block ist: pro MCU ein Register-Paar (Main + Sub-Version).

#### Bestätigte Zuordnungen

| Register | Wert | API-Feld | Beschreibung |
|---|---|---|---|
| **30200** | 147 | `control` | EMS-Firmware-Version (Hauptversion) ✅ bestätigt |
| 30201 | 18 | `control`? | EMS-Sub-/Patch-Version (direkt neben 30200) |
| **30202** | 115 | — | VNS-Firmware-Version (kein eigenes API-Feld) — **Korrektur:** OTA-bestätigt VNS, nicht VMS |
| 30203 | 106 | — | VNS-Sub-Version |
| **30204** | 116 | `bms` | BMS-Firmware-Version ✅ bestätigt |
| **30205** | 104 | `mppt`? | **mppt_version** (MPPT-Firmware-Version) ✅ OTA-bestätigt — **Korrektur:** vorher fälschlich als `bms_version_sub` geführt; OTA-Screenshot zeigt 4 FW-Komponenten (EMS/VNS/MPPT/BMS), 30205=104 entspricht MPPT:104, s. Vermutungen_Register_Analyse.md |

#### Fehlende Komponenten im Scan

Register 30206–30209 existieren **nicht** im Scan (Gerät hat dort keine Daten
geliefert — entweder nicht vorhanden oder Wert = 0 und kein Response).

| Register (hypothetisch) | Mögliches API-Feld | Status |
|---|---|---|
| 30206/30207 | `mppt` | Nicht im Scan — MPPT wahrscheinlich nicht verbaut |
| 30208/30209 | `dcdc` / `micro` | Nicht im Scan |

> **Schlussfolgerung:** `dcdc`, `led` und `charger` sind entweder:
> (a) Sub-Komponenten ohne eigene Modbus-Versionsregister, oder
> (b) ihre Register liegen außerhalb des 30200er-Blocks (z. B. 37000er-Bereich).
> **Offen:** Register 37006 = 192 ist unerklärt — könnte DCDC-Version sein.
> **Scan-Lücke schließen:** 30206–30209 manuell nachlesen (single-register,
> timeout 500 ms), um `mppt`/`dcdc`-Register zu bestätigen oder auszuschließen.

#### LED-Steuerung via Modbus

Der `led`-Eintrag in der OTA-API korrespondiert mit bekannten
Modbus-Write-Funktionen aus der Binary-Analyse:

| Funktion (aus Binary) | Chinesisch | Modbus-Äquivalent |
|---|---|---|
| `ctrl_led_light` | 控制led灯亮度 | Schreibbefehl (40000er-Bereich, unbekannte Adresse) |
| `led_continue_ctrl` | 控制类型 | LED dauerhaft: 0=an; 1=aus + Dauer ms |
| `Led.Ctrl` | — | Übergeordnetes MQTT-Topic |

> Die genauen Modbus-Adressen für LED-Control sind noch nicht im 40000er-Scan
> identifiziert — wahrscheinlich im ungescannten Bereich 44004–49999.

### 11.8 Cloud-Telemetrie-Feldnamen (aus FW-Strings, Ghidra)

Die FW enthält im Datenbereich (0x0805A000+) alle Format-Strings für die Cloud-Reports.
Der Haupt-Format-String für `setVenusDReporting` liegt bei 0x0805EC04 (jenseits des
geladenen Binary — wahrscheinlich Extended-Flash-Data). Die übrigen Format-Strings
sind im Binary vorhanden und vollständig dekodiert:

#### Report-Typ 1: Haupt-Telemetrie (`setVenusDReporting`)
Format-String bei 0x0805a404 (485 Bytes):
```
di=%s       → device_id (String)
sn=%s       → serial_number (String)
to=%d       → total_output (Energy)
td=%d       → total_discharge
ed=%d       → energy_daily
em=%d       → energy_monthly
gd=%d       → grid_daily
gm=%d       → grid_monthly
wm=%d       → work_mode
gy=%d       → grid_yield
gp=%d       → grid_power
go=%d       → grid_offset/output
gt=%d       → grid_total
gf=%d       → grid_frequency
gv=%d       → grid_voltage
ct=%d       → ct_value (Current Transformer)
bs=%d       → battery_soc
bp=%d       → battery_power
eb=%lx      → energy_battery (hex u32)
dn=%d       → device_number
bu=%d       → battery_usage
t1=%d       → temp_1 (Inverter NTC)
t2=%d       → temp_2
t3=%d       → temp_3
vc=%s       → version_control (String)
tc=%s       → time_config (String)
dt=%d-%02d-%02d %02d:%02d:%02d → datetime
no=%d       → number/count
e1=%llx     → energy_1 (64-bit hex)
ws=%d       → wifi_status
mt=%d       → meter_type
ty=%d       → type
sv=%d       → software_version
mc=%d       → meter_config
md=%d       → mode
sc=%d       → state_code
ci=%d       → charge_current
ri=%d       → rated_current
bv=%d       → battery_voltage
bi=%d       → battery_current
pb=%d       → pv_battery (power)
ds=%d       → discharge_status
ph=%d       → phase
bt=%d       → battery_temp
mq=%d       → mqtt_status
cy=%d       → cycle_count
cw=%d       → charge_watt
cp=%s       → charge_plan (String)
bm=%d       → bms_mode
ce=%s       → cert_info (String)
up=%d       → uptime
ap=%d       → ap_mode
nt=%d       → network_type
iv=%d       → inverter_version
et=%lx      → energy_total (hex u32)
ea=%lx      → energy_accumulated (hex u32)
pv=%s       → pv_info (String)
sk=%s       → secret_key (String)
mv=%d       → micro_version
me=%lx      → micro_energy (hex u32)
ma=%lx      → micro_accumulated (hex u32)
fu=%s       → firmware_url (String)
ms=%s       → mac_string (String)
im=%s       → imei (String)
hd=%s       → hardware_id (String)
pw=%d       → power_watt
bl=%d       → backup_level
as=%d       → auto_switch
bke=%s      → backup_energy (String)
bkd=%s      → backup_data (String)
ip=%s       → ip_address (String)
bt_p=%s     → battery_pack_info (String)
ival=%d     → interval
soh=%d      → state_of_health
```

#### Report-Typ 2: BMS Per-Pack (0x0805a9d4, 354 Bytes)
```
cd=%d       → command/report_code
b_ver=%d    → BMS Version
b_chv=%d    → charge_voltage (max)
b_rci=%d    → rated_charge_current
b_rdi=%d    → rated_discharge_current
b_soc=%d    → SOC (÷10!)
b_soh=%d    → SOH
b_cap=%d    → capacity
b_vol=%d    → voltage
b_cur=%d    → current
b_tem=%d    → temperature
b_chf=%d    → charge_flag
b_slf=%d    → sleep_flag
b_cpc=%d    → charge_protect_count (cycles)
b_err=%d    → error_bitmask
b_war=%d    → warning_bitmask
b_ret=%d    → return_energy (charge total)
b_ent=%d    → energy_total (discharge)
b_mot=%d    → mos_temperature
b_tp1..4=%d → cell_temp_1..4
b_vo1..16=%d → cell_voltage_1..16
```

#### Report-Typ 3: EMS-Status (0x0805ac80, 845 Bytes)
```
cd, tot_i, tot_o, ele_d, ele_m, grd_d, grd_m, inc_d, inc_m,
grd_f, grd_o, grd_t, gct_s, cel_s, cel_p, cel_c,
err_t (hex), err_a (hex), dev_n, grd_y, wor_m,
tim_0..9 (je 7 Pipe-separierte Werte = 10 Zeitslots × 7 Parameter),
cts_m, bac_u, tra_a, tra_i, tra_o, htt_p,
prf_s, inc_a, set_v, mcp_w, mdp_w, ct_t, phase_t, dchrg_t,
bms_v, fc_v (String), wifi_n (String), seq_s, ctrl_r,
par, gen, ble, shelly_p, c_ratio, udp, api, net, port,
inv_v, id (5 Pipe-sep.), lk, bp, ei (hex64), eb (hex32),
rp, gp, vp, bl, dod, bl_p, led, as, lf, pl, soh
```

#### Report-Typ 4: BMS Multi-Pack Summary (0x0805ab38, 226 Bytes)
```
cd, BMS: num, mask, idx, charge_pow, discharge_pow,
soc1..6, state1..6, temp1..6 (6 Packs × 3 Felder)
```

#### Report-Typ 5: Meter (0x0805ac1c, 96 Bytes)
```
cd, meter: type, real_tol_power, real_power1..3, err_flag
```

#### Report-Typ 6: RS485/Inverter (0x0805afd0, 107 Bytes)
```
cd, 485_a, grd_f, grd_v, grd_a, temp_1..5, 485_c, ssl
```

#### Report-Typ 7: MPPT/PV (0x0805b1d0, 209 Bytes)
```
cd, state, err, war, temp,
pv1v/pv1c/pv1p .. pv4v/pv4c/pv4p (4 MPPT-Strings × V/C/P),
pve, pvs, pow, capd, capm, capy, batv, batc, basev, pev
```

#### Report-Typ 8: OTA URL Info (0x0805b360, 237 Bytes)
```
cd, type1..4, mod1..4, size1..4, crc1..4, ver1..4, len1..4, url1..4
(4 Firmware-Slots mit je type/mod/size/crc/ver/url_len/url)
```

#### Report-Typ 9: Extended MPPT Append (0x0805b450, 93 Bytes)
```
%.*s (vorangehender Report), mppt, pv1..4 (je V|P),
pack (4 Pipe-sep.), pv (2 Pipe-sep.), fu (2 Pipe-sep.), em (hex)
```

> **Erkenntnis:** Die Format-Strings enthalten KEINE JSON-Struktur sondern
> URL-Query-Parameter (`key=value&key=value` bzw. `key=%d,key=%d`).
> Die AES-Verschlüsselung im `setVenusDReporting` betrifft den gesamten
> Payload (nach Base64-Encoding).

---

## 11b. Ghidra — Vollständige Funktionsliste

> **Hinweis (2026-07-09):** Diese Sektion enthielt bis Juli 2026 eine frühe Teil-Funktionsliste
> (168 von 1615 Funktionen, Stand "FW v148" — bereits das Label war veraltet gegenüber 149.2).
> Sie wurde **entfernt**, weil sie mit der inzwischen vollständigen und laufend korrigierten
> Function-Tracking-Doku nicht mehr synchron war und teils widersprüchliche Adress/Namen-Zuordnungen
> enthielt (u. a. `0x0802a4ec` war hier fälschlich weiterhin als `cJSON_CreateObject` gelistet, obwohl
> die Funktion tatsächlich `cJSON_InitHooks` ist — s. Batch 18 in
> [Ghidra_Analyse_Erkenntnisse.md](Ghidra_Analyse_Erkenntnisse.md) und
> [Control_FW_Naming_Batch_History.md](Control_FW_Naming_Batch_History.md)).
>
> **Maßgeblich für Funktionsnamen/Adressen ist ausschließlich
> [Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md)**
> (thematisch geordnet; das frühere chronologische Batch-Log wurde am 2026-07-11 gelöscht, s.
> [Control_FW_Naming_Batch_History.md](Control_FW_Naming_Batch_History.md)).

## 12. Offene Punkte & nächste Schritte

### 12.1 Register-Adressraum — Status

| Bereich | FC03-Scan | Statische Analyse | Status |
|---|---|---|---|
| 0 – 29.999 | ✅ leer | — | abgeschlossen |
| 30.000 – 39.999 | ✅ 89 Register | — | abgeschlossen |
| 40.000 – 49.999 | 41 per FC03 | **~50+ aus Write-Handler** | ⚠️ erweitert |
| 50.000 – 65.535 | ✅ leer | — | abgeschlossen |

> **Wichtig:** Der FC03-Batch-Scan fand nur 41 Write-Register, weil viele Register
> **write-only** sind (Error-Code 2 bei FC03-Lesezugriff). Die statische Analyse des
> Write-Handlers (`FUN_08050f20`) hat ~50+ zusätzliche Register aufgedeckt
> (s. Abschnitt 7.6), darunter Befehls-Register (45000–45031), OTA-Kommandos (46000),
> EEPROM-Structs (46500–46544) und ein Debug-Register (47400).

### 12.2 Offene Register aus Local API Abgleich (Priorität hoch)

Folgende API-Felder haben noch kein bestätigtes Modbus-Register.
Da der vollständige Adressraum gescannt ist, befinden sich diese
Register — sofern vorhanden — im bekannten Bereich 30000–49999:

| API-Feld | Erwarteter Wert | Kandidat-Register | Nächster Schritt |
|---|---|---|---|
| `ES.GetStatus.total_pv_energy` | Wh-Zähler | 33004–33005 | Bei PV-Betrieb prüfen |
| `ES.GetStatus.total_load_energy` | Wh-Zähler | 33006–33007 | Prüfen |
| `Bat.GetStatus.bat_capacity` | aktuell verfügbare Wh | 34008? 34009? | Gezielte Einzellesung |
| `ES.GetStatus.bat_cap` | Nenn-Kapazität (5120 Wh) | 35110 oder 35111 | Rohwert 576 ≠ 5120 → anderer Scale? |
| `Bat.GetStatus.error_code` | "0x430" als String | 36100–36103 | Bitmask-Mapping fehlt |
| `ES.GetMode.mode` String | "Auto"/"Manual" etc. | 43000 | Enum-Zuordnung 0→Auto, 1→? verifizieren |

### 12.2a OTA-Komponenten ohne Modbus-Zuordnung (Priorität mittel)

Drei neu identifizierte OTA-Felder (`dcdc`, `led`, `charger`) haben noch
keine bestätigten Modbus-Versionsregister:

| OTA-Feld | Hypothese | Kandidat-Register | Nächster Schritt |
|---|---|---|---|
| `dcdc` | DC/DC-Wandler-Firmware-Version | 30206/30207? | Einzellesung; im Scan nicht vorhanden |
| `led` | LED-Controller-Firmware-Version | 30208/30209? | Einzellesung; im Scan nicht vorhanden |
| `charger` | AC-Lader-Firmware-Version | unbekannt | Kein Kandidat bekannt |
| LED-Write-Befehl | `ctrl_led_light` aus Binary | 44xxx? | 40000er-Scan ab 44004 nachholen |
| DCDC-Statusregister | Leistung / Wirkungsgrad | 37006 = 192? | Einzellesung verifizieren |

```python
# Scan-Lücke 30206-30209 schließen (single-register, timeout 500ms)
from pymodbus.client import ModbusTcpClient
import time

c = ModbusTcpClient("192.168.X.X", port=502, timeout=0.5)
c.connect()
for reg in [30206, 30207, 30208, 30209, 37006]:
    try:
        r = c.read_holding_registers(reg, 1, slave=1)
        if not r.isError():
            print(f"Reg {reg}: {r.registers[0]}")
        else:
            print(f"Reg {reg}: Error (nicht vorhanden)")
    except Exception as e:
        print(f"Reg {reg}: Exception → {e}")
    time.sleep(0.1)
c.close()
```

### 12.3 Descriptor-Tabelle (246 Einträge) — noch nicht extrahiert

Die Tabelle bei SRAM `0x20000354` wurde live durch den Batch-Scan
empirisch erschlossen (413 Register). Für die exakten Datentyp- und
Scale-Informationen aller 246 Einträge wäre eine direkte Extraktion sinnvoll:

```
Mögliche Ansätze:
1. JTAG/SWD: 2952 Bytes ab 0x20000354 bei laufendem Gerät lesen
2. Unicorn-Emulation: Binary emulieren bis SRAM initialisiert
3. Ghidra: Router-Caller über References-to-DAT_20000354 finden
```

Ghidra-Anleitung:
```
1. FUN_0801c088 (Router) in Ghidra öffnen (G → 1c088)
2. F5 (Decompiler)
3. Rechtsklick auf 'DAT_20000354'
4. References → Show References to Address
5. WRITE-Referenzen → das ist die Init-Funktion
```

### 12.4 Bekannte Register-Lücken

Aus dem Descriptor-Table-Schema (246 Einträge), 413 gescannten Registern
(in 89 Read + 41 Write-Gruppen) und ~50+ statisch extrahierten Write-Registern
(s. 7.6) verbleiben noch offene Punkte:

- **33004–33011**: Weitere Energie-Zähler (total_pv_energy, total_load_energy)
- **34008–34009**: Aktuelle Batterie-Kapazität in Wh (bat_capacity)
- **30000–30010**: Erste Register noch nicht vollständig dekodiert (30000=509 unerklärt)
- Erweiterte Alarm/Fehler-Codes mit Bit-Definitionen

### 12.5a Offene Verifizierungen aus statischer Analyse (Priorität hoch)

| Thema | Details | Nächster Schritt |
|---|---|---|
| **Reg 40000 vs. 42000** | Code zeigt 40000 als RS485-Unlock (0x55AA), Doku/Live nutzt 42000 | FC06-Write auf 40000 mit 0x55AA testen |
| **Reg 41500–41631** | Zeitplan-Arrays (bisher undokumentiert) | Zeitplan setzen, dann Register lesen |
| **Reg 45000–45031** | Befehls-Register (Reboot, SMR, GPIO) — **gefährlich!** | Nur nach Backup testen |
| **Reg 46000** | OTA-Kommando-Register | **NICHT testen** ohne OTA-Image |
| **Reg 46500–46544** | EEPROM-Structs (Funktion unbekannt) | Lesen/Schreiben nach Backup |
| **Reg 47400** | Debug (liest 0xAABB, schreibt debug_printf) | Harmlos, lesen testen |

### 12.5 Verifikations-Code für kritische Register

```python
from pymodbus.client import ModbusTcpClient

c = ModbusTcpClient("192.168.1.XXX", port=502)
c.connect()

# SOC (Scale 0.1!) — durch Local API REV 0.5 bestätigt
raw = c.read_holding_registers(34002, 1, slave=1).registers[0]
print(f"SOC Pack1: {raw * 0.1:.1f}%")

# SOC Pack2
raw2 = c.read_holding_registers(34102, 1, slave=1).registers[0]
print(f"SOC Pack2: {raw2 * 0.1:.1f}%")

# Netzspannung
v = c.read_holding_registers(32200, 1, slave=1).registers[0]
print(f"Netz: {v * 0.1:.1f} V")

# uint32 Ladeenergie (total_grid_input_energy)
hi = c.read_holding_registers(33000, 1, slave=1).registers[0]
lo = c.read_holding_registers(33001, 1, slave=1).registers[0]
print(f"Netzbezug gesamt: {((hi << 16) | lo) * 0.01:.2f} kWh")

# uint32 Entladeenergie (total_grid_output_energy)
hi2 = c.read_holding_registers(33002, 1, slave=1).registers[0]
lo2 = c.read_holding_registers(33003, 1, slave=1).registers[0]
print(f"Einspeisung gesamt: {((hi2 << 16) | lo2) * 0.01:.2f} kWh")

c.close()
```

---

## 13. Ghidra-Detailanalysen: Interessante Funde

Vertiefte Analysen einzelner Punkte aus der "Interessante Funde"-Liste in
`Control_FW_Function_Tracking_new.md`. Jeder Unterabschnitt geht über die grobe
Batch-Benennung hinaus (Cross-Referenzen, Datenstrukturen, Sicherheitsbewertung).

### 13.1 CAN-Bus Protokoll (Punkt #4)

**Funktionen:** `CAN_ReadMailbox` (0x08002a20), `CAN_SetupTxMailbox` (0x08002b10),
`CAN_Detect_Mismatched_Nodes` (0x08004418), `CAN_Update_StateMachine` (0x080045dc)

Zusätzlich identifizierte, verwandte Funktionen:

| Adresse | Name |
|---|---|
| `0x0802dfd4` | `CAN_RxMailbox_Handler` (ISR-nahe Empfangsroutine) |
| `0x08002000` | `USART_SendData` (**fehlbenannt** — ruft intern nur `CAN_SetupTxMailbox` auf, keinerlei USART-Zugriff) |
| `0x080056b4` | `CAN_Select_Master_Node` |
| `0x08005418` | `CAN_Node_Data_Reset` |
| `0x0800557c` | `CAN_Parallel_Inverter_Sync` |
| `0x08027224` | `CAN_Update_Init` (State 0) |
| `0x080272e0` | `CAN_Update_Erase` (State 1) |
| `0x08027074` | `CAN_Update_SendData` (State 2) |
| `0x08026f08` | `CAN_Update_HandleResponse` (State 3) |
| `0x080271a4` | `CAN_Update_Success` (State 4) |
| `0x080271e4` | `CAN_Update_Failed` (State 5) |
| `0x080049a4` | `CAN_Update_Check_Retry_Limit` |
| `0x080358ec` | `CAN_Battery_Telemetry_Debug_Print` (PGN 1801–1804, 1007) |

**Zweck:** Zweiter Kommunikationskanal (STM32 bxCAN1, Peripherie-Basis `0x40006400`,
Registeroffsets 1:1 aus dem STM32-Referenzhandbuch bestätigt) neben RS485/Modbus.
Genutzt für (1) Parallelbetrieb-Synchronisation mehrerer Batterie-/Wechselrichter-Nodes
(`CAN_Select_Master_Node`, `CAN_Parallel_Inverter_Sync`, J1939-artige Telemetrie mit
PGN 1801–1804/1007) und (2) ein Remote-Firmware-Update-Protokoll für CAN-Nodes
(`CAN_Update_StateMachine`).

**Frame-Format:** `CAN_ReadMailbox`/`CAN_SetupTxMailbox` sind generische bxCAN-HAL-Routinen
(kein proprietäres Bit-Layout), unterstützen Standard- (11 Bit) und Extended-ID (29 Bit).
Gemeinsame Nachrichten-Struktur (Stack, 0x14 Byte):

```c
struct CAN_Message {
    uint32_t std_id;   // +0x00, gültig wenn IDE==0
    uint32_t ext_id;   // +0x04, gültig wenn IDE==1
    uint8_t  ide;       // +0x08
    uint8_t  rtr;        // +0x09
    uint8_t  dlc;         // +0x0A (0-15)
    uint8_t  data[8];      // +0x0B..0x12
};
```

`CAN_RxMailbox_Handler` liest per FIFO0 und übergibt Nachrichten an eine FreeRTOS-Queue
(`*DAT_0802e000`); der Consumer-Task dieser Queue wurde nicht identifiziert (offene Frage).

**State-Machine (`CAN_Update_StateMachine`, läuft jeden Hauptschleifen-Tick via
`App_MainLoopDispatcher`):** Session-Struct bei RAM `0x20015320`. Guard: FSM läuft nur,
wenn Master-Node-Index (`0x20000282`) < 3.

| State | Funktion | Bedeutung |
|---|---|---|
| 0 | `CAN_Update_Init` | Puffer nullen, Ziel-Firmware wählen, **`Inverter_StopOutput()`**, Start-Log |
| 1 | `CAN_Update_Erase` | Erase-Info senden, 10-Tick-Delay |
| 2 | `CAN_Update_SendData` | FW-Block aus QSPI lesen, CRC berechnen, blockweise senden |
| 3 | `CAN_Update_HandleResponse` | Node-Antwort auswerten (1=weiter, 2=Retry, 3=Fehler→State 1, 0=Poll) |
| 4 | `CAN_Update_Success` | Log, Reset auf Master-Index `0xFF` |
| 5 | `CAN_Update_Failed` | Log, Reset auf Master-Index `0xFF` |

20-Tick-Timeout erzwingt bei Ablauf sofort State 5 (unabhängig vom aktuellen State); Retry
> 25 erzwingt ebenfalls State 5. Ein zweiter, 5-Tick-Timeout existiert zusätzlich in State 3
für den "keine Antwort"-Zweig.

**Node-Mismatch-Erkennung:** Vergleicht bis zu N Node-Adressen (Stride 0x60 Byte) gegen die
eigene Referenzadresse. Erwartet genau 1 abweichenden Peer (Normalfall); 0 oder >1
abweichende Peers gelten als Fehler. Trigger-Flag (`DAT_0800447c`) und Konsument des
Fehler-Ergebnisses nicht gefunden.

**Sicherheitsbewertung:** Keine Authentifizierung/Signaturprüfung auf CAN-Ebene; die CRC im
Update-Pfad schützt nur die Übertragung, nicht die Authentizität des Absenders. Der
Update-Zyklus ruft in State 0 `Inverter_StopOutput()` auf — bei physischem CAN-Bus-Zugriff
erscheinen gefälschte Statusantworten (Erfolg vortäuschen, Retry-Schleifen erzwingen,
Update dauerhaft blockieren/DoS) plausibel. Vollständige Codeausführung über diesen Pfad
konnte anhand der analysierten Funktionen nicht nachgewiesen werden. Vertrauensmodell setzt
ein physisch abgesichertes, internes CAN-Netz voraus.

**Auffälligkeit:** `Modbus_SendResponse` (0x0802c060) ruft `USART_SendData` (0x08002000)
auf, das trotz seines Namens ausschließlich CAN-Mailboxen befüllt — keine USART-Register
werden berührt. Historische Fehlbenennung oder bewusste Dual-Transport-Architektur (Modbus
zusätzlich auf CAN gespiegelt)? Ungeklärt, siehe auch 13.2/13.3.

**Offene Fragen:** Trigger von `DAT_0800447c`; Konsument des Mismatch-Fehler-Flags;
FreeRTOS-Queue-Consumer der CAN-RX-Daten; genaue Feldbedeutung der Node-Array-Einträge
(`0x200152F0`); Ursprung/Trigger des Firmware-Update-Zyklus.

**Nachtrag (Vertiefung):**

1. **Trigger `DAT_0800447c`:** Kein eigenständiges RAM-Flag, sondern ein Flash-Literal-Pool-
Wort in `CAN_Detect_Mismatched_Nodes`, das schlicht den Pointer `0x20000282` enthält —
denselben Master-Node-Index, der bereits als FSM-Guard bekannt war. Der Code dereferenziert
ihn (`*DAT_0800447c` == `*0x20000282`); die Mismatch-Prüfung läuft nur, wenn der
Master-Node-Index exakt `1` ist (BMS-Slot).

2. **Konsument des Mismatch-Fehler-Flags** (Struktur `0x2000027a`, von
`CAN_Detect_Mismatched_Nodes` beschrieben — `+0x00` Fehlerbyte, `+0x01` Index letzter
Mismatch, `+0x02` Node-Count, `+0x06` Referenz-ID): **`CAN_Parallel_Inverter_Sync`** liest
Byte0. Bei `0` (genau 1 Mismatch = Normalfall) Fast-Path: Node-Index (`+0x01`) indiziert
direkt in Tabelle `0x20014e3c`, Werte werden nach `0x20014e24+8/+0xc` übernommen. Bei `!=0`
(0 oder >1 Mismatches) läuft der bereits dokumentierte Maximum-Fallback über die Byte+6-Felder
von `0x20014e3c`, gesteuert vom Update-Session-State (`0x20015320+0x12`: State 2/3 aus
`CAN_Update_StateMachine`). Zweiter Leser: `Register_WriteCategory0xCE` (0x080265f0) nutzt
Byte0 als Bedingung für einen Sequenznummer-Reset beim CAN-Update-Registerschreiben.

3. **FreeRTOS-Queue-Consumer identifiziert:** `CAN_RxQueue_DrainAndDispatch` (0x080292d4) —
liest den Queue-Handle aus RAM `0x200000e8` (per xQueueReceive, intern fehlbenannt als
`Modbus_Response_Builder`, 1000-Tick-Timeout), entnimmt bis zu 64 Frames pro Aufruf, dispatcht
jedes über `CAN_FrameDispatcher`, danach `vTaskDelay(1)`. Eigener Caller (Task-Entry-Point /
xTaskCreate-Stelle) von Ghidra nicht auflösbar (0 Xrefs) — vermutlich per Funktionszeiger
registriert, analog zu anderen unauflösbaren Task-Zuordnungen (siehe 13.5).

4. **Node-Array `0x200152F0`** (Stride 0x10, 3 Slots mppt/bms/venus): `+0x00`/`+0x01` =
Statuswerte (gültig nur im Bereich 2–4); `+0x02` = Online-Flag (≠0); `+0x04` (nur für
Slot 1/BMS ausgelesen, als 16-Bit) = Referenz-/Vergleichs-ID, verglichen in
`CAN_Detect_Mismatched_Nodes` gegen die Gerätetabelle `0x20014fa8` (`+0x1e` je Slot). Bei
Nichterfüllung wird der komplette 0x10-Byte-Slot genullt (`CAN_Select_Master_Node`). Schreiber
der Online-/Statusbytes selbst weiterhin nicht lokalisiert.

5. **Ursprung/Trigger des Update-Zyklus:** Kein expliziter "Start-Befehl" gefunden. Die FSM
(`CAN_Update_StateMachine`) läuft unbedingt jeden Tick über `App_MainLoopDispatcher` und ruft
selbst zuerst `CAN_Select_Master_Node()` auf — diese prüft bei jedem Tick alle 3 Node-Slots
und übernimmt automatisch denjenigen mit gültigem Online-Flag + Statuswerten 2–4 als Master
(`0x20000282` = Slot-Index). Der Zyklus "startet" also datengetrieben, sobald ein Peer sich
als online meldet, nicht durch ein separates Kommando. Beendigung/Reset erfolgt über
`CAN_Node_Data_Reset` (setzt Index auf `0xFF`) aus State 4/5.

6. **`USART_SendData`/`CAN_SendMessage`** (0x08002000) vollständig dekompiliert (14 Byte
Gesamtgröße): Die Funktion besteht aus genau einem Aufruf `CAN_SetupTxMailbox(DAT_08002010,
param_1)` — kein bedingter Zweig, keine USART-Register-Zugriffe, kein Platz für einen zweiten
Codepfad. Eindeutig eine historische Fehlbenennung (die Funktion trägt im aktuellen
Ghidra-Stand bereits den Namen `CAN_SendMessage`), **keine** bewusste
Dual-Transport-Architektur.

### 13.1b CAN Message-ID-Struktur (Ergänzung 2026-07-10)

Statische Ergänzung zum offenen Punkt "CAN-Bus Message IDs und Arbitration vollständig
dokumentieren" aus `AES_Crypto_Stack_Analyse.md`. Alle intern ausgewerteten Nachrichten sind
**Extended-Frames** (29-bit ID) — die 11-bit Standard-ID wird nirgends gefiltert/gebraucht.

**Bit-Layout der Extended-ID** (Struct-Offset +0x04 im CAN_Message):

| Bit-Range | Feldname | Bedeutung |
|---|---|---|
| [7:0] | `RegKat` | Register-Kategorie-Byte des internen Register-Protokolls (0x01, 0x03, 0x06, 0x07, 0x10–0x14, 0x40–0x43, 0x54, 0xC1, 0xC2, 0xC3, 0xCB, 0xCE, 0xFE, 0xFF) |
| [11:8] | `Node` | Node-/Kanal-Index |
| [15:12] | `Sub` | Sub-Feld (bei CAN-Update: 0=EraseInfo, 1=Data, 2=Status) |
| [19:16] | — | nur bei Klasse 3 + RegKat 0xCE: Tabellenindex 1–8 für `CAN_ParallelInverterDataParser` |
| [23:20] | `Klasse` | 2=Modbus-Response, 3=Parallel-Inverter/Update-Data, 4=Telemetry-Register, 0xA (kombiniert mit Bits[15:8]==0xAA) = 0xAA-Inter-Device-Protokoll |
| [28:24] | — | Zusatzdiskriminator (Tabellenspalten-Wahl in `CAN_ParallelInverterDataParser`) |

**RX-Dispatch** (`CAN_FrameDispatcher`, 0x0802e698): Klasse 4 + Sub 0 → `Telemetry_Register_Dispatcher` (0x0802f1c0); Klasse 2 + Sub 0 → `Modbus_ResponseDispatch` (0x0802ea54); sonst → `Protocol_AA_CommandDispatch` (0x0802efac).

| Klasse | RegKat | Handler |
|---|---|---|
| 4 | 0x10–0x14 | `Protocol_AA_SetChannelData`/`_SetSystemParams`/`_SetDeviceParams`/`_EnqueueCommand`/`_SetExtendedParams` |
| 4 | 0x40–0x43 | `Telemetry_Store_EnergyCounters` |
| 4 | 0xC1/0xCB/0xCE/0x54 | `Telemetry_Store_RegC1`/`_RegCB`/`_RegCE_ByChannel`/`_Reg54` |
| 4 | 0xC3 | `Protocol_AA_RS485Forward` |
| 2 | 0x03/0xCB/0xCE/0xFE/0xFF | `Modbus_StoreRegisterSlot`/`_StoreWithHandshake`/`_StoreDualSlot`/`_StoreValue16`/`_StorePairSlot` |
| 3 | 0xCE, Idx 1–8 | `CAN_ParallelInverterDataParser` → Tabelle 0x20014e3c |
| 3 | 0x06, Sub 3 | `CAN_ParallelInverterDataParser` → Flag `*0x20000f10=1` |
| 0xA (0xAA-Protokoll) | Byte0 < 9 | `Protocol_AA_CommandDispatch` → RAM-Tabelle 0x2000018c (17×8 Byte) |

**TX-Assemblierung:** `Register_PackDescriptor(RegKat, Node, Sub, x)` (0x08032348, 43 Aufrufer) baut `Bits[7:0]|Node<<8|Sub<<12`; genutzt u. a. von `Register_WriteCategory0xCE` (Kat 0xCE, Sub 0/1/2 aus `CAN_Update_WriteEraseInfo/Data/Status`).

**Zusatzfund:** `CAN_SendWorkModeFrame` (0x0802c5b0) und `CAN_SyncChangedRegisters` (0x0802c5d8) rufen trotz CAN-Namens intern nur `I2C_BitBang_WriteBytes` auf, kein bxCAN-Zugriff — weiterer Beleg für "Name ≠ tatsächlicher Transport", analog zu §13.6.

**Bleibt blockiert (nur live/statisch nicht auflösbar):**
1. **0xAA-Kommandotabelle** (RAM 0x2000018c, 17×8 Byte): Ghidra-Projekt bildet nur den Flash-Bereich ab, RAM ist nicht gemappt, keine Schreib-Xref im Image auffindbar — Command-IDs/Handler-Pointer nur per Live-RAM-Dump oder CAN-Sniffing klärbar.
2. **Zusammensetzung von Bits[23:20] ("Klasse") auf TX-Seite:** `Register_PackDescriptor` setzt dieses Feld nicht; der Consumer der TX-Queue (RAM 0x200000ec) wurde nicht gefunden (0 Xrefs).
3. **Arbitrierungspriorität bei Bus-Konflikt:** reine bxCAN-Hardwareeigenschaft (niedrigste ID gewinnt), keine Software-Prioritätslogik im Code — nur per Bus-Messung verifizierbar.

### 13.2 Network Protocol Dispatcher (Punkt #5)

**Funktion:** `Network_ProtocolDispatcher` (0x08003d40, 132 Byte, 4 Callees)

**Zentrales Ergebnis — verifiziert toter Code:** Die "0 Caller"-Beobachtung aus der
Grobanalyse wurde bestätigt und vertieft. Das komplette Flash-Image (0x08000000–0x0805dfff)
wurde byteweise nach der Zieladresse durchsucht — als Little-Endian-Pointer (`40 3D 00 08`),
als Pointer mit gesetztem Thumb-Bit (`41 3D 00 08`) und als MOVW/MOVT-Immediate-Paar
(`0x3d40`/`0x3d41`): **0 Treffer in allen drei Fällen.** Kein Fallthrough von der
vorherigen Funktion (`CH395_HardwareReset` endet mit echtem `pop {r4,pc}`-Return). Die
Funktion hat zudem keinen Parameter, was auch gegen einen FreeRTOS-Task-Entry-Point
spricht. Auch die 3 dispatchten Handler haben jeweils nur genau einen Caller: den
Dispatcher selbst. **Die gesamte Kette ist im Firmware-Build v149.2 statisch nicht
erreichbar.**

**Dispatcher-Logik:** Prüft CH395-Link-Status (`0x2001adb0+6/+7`) und ein Modell-/Work-Mode-
Byte (`0x20014cfc+0x68`, systemweit z.B. auch von `MQTT_JSON_RPC_Dispatcher` und
`WorkMode_State_Machine` genutzt), schließt bestimmte Gerätemodelle aus, dispatcht dann
per Mode-Byte (`0x2001a82c+1`):

| Mode | Handler | Rekonstruierter Zweck |
|---|---|---|
| 0 | `FUN_08017dc0` | CH395-UDP-Socket konfigurieren (Quellport 22222, Zielport 12345 bzw. modellabhängig) inkl. Broadcast-Adressberechnung — lokale Discovery/Query für ein Energiemessgerät |
| 1 | `Network_HeartbeatHandler` (0x08026114) | Socket öffnen; Erfolg → Mode 2, Fehler → Fehlerzähler +10 |
| 2 | `Ethernet_SendStatusTelemetry` (0x0802c438) | Sendet **JSON-RPC-Request** `{"id":%d,"method":"EM.GetStatus"/"EM1.GetStatus","params":{"id":0}}` an ein lokales Gerät — **kein** Cloud-Telemetrie-Report trotz Namens |

Fehlerzähler bei `0x2001a82c+2`; überschreitet er 60 (0x3c), wird Mode auf 0 zurückgesetzt
(Zyklus-Neustart). Bedeutung des CH395-Link-Gate-Bytes (`+6/+7`) sowie dessen schreibende
Stelle nicht gefunden.

**Bemerkenswert:** Eine strukturell identische Schwesterfunktion `Modem_SendStatusTelemetry`
(0x0802c29c) für den Quectel/AT-Kommando-Pfad existiert ebenfalls und hat **ebenfalls 0
Caller** — das komplette "EM-Status-Poll"-Feature (Ethernet- *und* Modem-Variante) ist in
v149.2 vollständig unbenutzt/unreachable.

**Sicherheitsbewertung:** CH395-Empfangspuffer ist gegen Überlauf abgesichert
(1023-Byte-Grenzprüfung vor `CH395_ReadRecvBuf`). `AT_Response_Parser` maskiert kopierte
Länge mit `& 0xff` (passt in 256-Byte-Stack-Puffer) — wirkt eher zufällig als als bewusster
Bounds-Check, sollte bei Gelegenheit vertieft geprüft werden. Da der komplette Pfad toter
Code ist, besteht aktuell **keine aktive Angriffsfläche**.

**Namensvorschläge (nicht angewendet):**

| Alt | Vorschlag | Begründung |
|---|---|---|
| `FUN_08017dc0` | `CH395_UDP_MeterQuerySocket_Setup` | UDP-Socket-Setup für lokale EM-Abfrage |
| `Ethernet_SendStatusTelemetry` | `Ethernet_EM_PollStatus` | Sendet JSON-RPC `EM.GetStatus`, keine Cloud-Telemetrie |
| `Modem_SendStatusTelemetry` | `Modem_EM_PollStatus` | Analoge Funktion, AT-Pfad, ebenfalls 0 Caller |
| `Network_ProtocolDispatcher` | Kommentar `[DEAD CODE — 0 Caller verifiziert, Stand v149.2]` | Name bleibt sachlich korrekt |

**Offene Fragen:** Tatsächlicher Aufrufmechanismus in älteren/zukünftigen FW-Varianten mit
CH395-Bestückung; Bedeutung des Link-Gate-Bytes; ob `0x20014cfc+0x68` exakt der
Device-Model-Code ist; Robustheit von `AT_Response_Parser` (0x0802e35c) gegen manipulierte
Antworten.

**Nachtrag (Vertiefung):**

**1) Link-Gate-Byte (`0x2001adb0+6/+7`):** Per Cross-Referenz-Analyse (`find-cross-
references`) identifiziert als Teilbereich eines CH395-Netzwerkstatus-Blocks bei RAM
`0x2001adb0`. Feld `+1` ist ein Verbindungstyp-/IP-gültig-Flag, das u.a. von
`CH395_PHY_StatusHandler` (0x08032650) geschrieben wird — bei PHY-Event "disconnected"
(`param_1==1`) wird `+0`=1 (Status) und `+1`=0 gesetzt (`s_PHY_DISCONN`-Log). Feld
`+5..+8` ist ein 4-Byte-Wert, der in `Cloud_Report_FillDeviceInfo` (0x0801c398) und
`Cloud_Reporting_setVenusDReporting` (0x08016764) als `"%02d-%02d-%02d-%02d"` formatiert
wird (MAC-/Seriennummern- oder IP-artiger Wert) und in `CH395_Reset_And_Reinit`
(0x08029964) bei jedem CH395-Reset mit `memset(base+5, 0x14)` komplett auf 0 gesetzt wird
(zusammen mit `+1`=0). Damit ist die "Link-Gate"-Prüfung in `Network_ProtocolDispatcher`
(`+6 != 0 || +7 != 0`) präziser beschrieben als: **"sind 2 der 4 IP-/Seriennummer-Bytes
ungleich Null"** — ein Heuristik-Check, ob dem CH395-Modul bereits eine gültige
Adresse/Kennung zugewiesen wurde, nicht ein reiner PHY-Link-up-Flag. Die genaue
schreibende Stelle für `+5..+8` (also wer die IP/Kennung tatsächlich befüllt, außerhalb
des Reset-Löschens) wurde weiterhin nicht gefunden — vermutlich Teil der CH395-DHCP-/
Socket-Setup-Kette, die hier nicht vollständig verfolgt wurde.

**2) `0x20014cfc+0x68` = Device-Model-Code — verifiziert:** `find-cross-references` auf
RAM `0x20014d64` (= `0x20014cfc+0x68`) zeigt als einen der Leser die Funktion
`Config_Get_DeviceModelCode` (0x08006990), die **exakt diese Adresse** dreifach abfragt:
```
uVar1 = 0x3f2;
if (*(char *)(DAT_080069d8 + 0x6d) == -0x56) { uVar1 = *(undefined2 *)(DAT_080069d8 + 0x6e); }
else if (*(char *)(DAT_080069d8 + 0x68) == '\x01') { uVar1 = 0x3f2; }
else if (*(char *)(DAT_080069d8 + 0x68) == '\x05') { uVar1 = 0x8ae; }
else if (*(char *)(DAT_080069d8 + 0x68) == '\x06') { uVar1 = 0x8af; }
```
(`DAT_080069d8` verifiziert per `read-memory` == `0x20014cfc`). Damit ist bestätigt: Byte
`+0x68` ist der Modell-Auswahlbyte, aus dem `Config_Get_DeviceModelCode` einen
16-Bit-Modellcode (0x3f2/0x8ae/0x8af, ggf. überschrieben durch ein Override-Byte bei
`+0x6d`==0xAA) ableitet — die Bezeichnung als "Device-Model-Code-Byte" in der
Grobanalyse ist korrekt, exakter: es ist der **Rohindex**, aus dem der eigentliche
16-Bit-Modellcode erst per Lookup entsteht.

**3) `AT_Response_Parser` (0x0802e35c) Robustheit — Befund mit Einschränkung:** Volle
Dekompilation (159 Zeilen) analysiert. Die Funktion nutzt einen 256-Byte-Stack-Puffer
(`auStack_1b0`) und ein 32-Element-Array (`local_b0`, 128 Byte) für bis zu 32
Tokenpointer. Kritische Stelle:
```
uVar7 = (iVar6 - iVar4) + 3U & 0xff;               // Gesamtlänge, auf 0-255 maskiert
...
local_2c = iVar6 - iVar4 & 0xff;                   // Offset des '|'-Trenners, ebenfalls 0-255
strncpy(auStack_1b0, iVar6, (uVar7 - local_2c) + -3);
```
Beide Werte sind einzeln auf 0–255 begrenzt (`& 0xff`), **aber die Differenz `uVar7 -
local_2c` wird vor der Maskierung nicht auf Unterlauf geprüft.** Wenn eine (in der
AT-Antwort vom Modem/Netzbetreiber kontrollierbare) Eingabe `local_2c > uVar7 - 3`
erzeugt, unterläuft die `uint`-Subtraktion und ergibt einen Wert nahe `0xFFFFFFFF`, der
direkt als Kopierlänge an `strncpy` übergeben wird — ein potenzieller
**Stack-Buffer-Overflow durch Integer-Underflow**, nicht durch die vermutete
Zufalls-Absicherung via `& 0xff` verhindert. **Praktische Angriffsfläche aktuell jedoch
nicht gegeben:** `AT_Response_Parser` wird ausschließlich über `Modem_Response_Dispatch`
(0x08026b40) aufgerufen, dessen einzige zwei Caller wiederum `Modem_SendStatusTelemetry`
(0x0802c29c) und `Ethernet_SendStatusTelemetry` (0x0802c438) sind — genau die bereits als
**0-Caller-toter-Code** identifizierten EM-Status-Poll-Funktionen aus diesem Abschnitt.
Der potenzielle Overflow ist damit in Firmware v149.2 statisch unerreichbar, sollte aber
bei Reaktivierung dieses Codepfads (z.B. in Varianten mit aktivem Modem-Statuspolling)
vor Freigabe gefixt werden.

### 13.3 UART Packet Parser (Punkt #6)

**Funktionen:** `UART_Packet_Receive_Parse` (0x0800468c), `Serial_Packet_Validate`
(0x08004844), zusätzlich analysiert: `Serial_Command_Dispatch` (0x08025eb2),
`FUN_08013f24` (XOR-Checksum-Helper), `BLE_SendFramedNotification` (0x08025f94),
`BLE_Cmd_SystemReboot` (0x0802eacc), `BLE_Cmd_OTA_Init` (0x0802e86c),
`BLE_Cmd_OTA_WriteSetup` (0x0802e900), `BLE_OTA_WriteDataChunk` (0x0802ed04),
`BLE_Cmd_OTA_Validate` (0x0802e78c).

**Korrektur zur Grobanalyse:** `UART_Packet_Receive_Parse` ist **kein UART-Treiber**. Die
Funktion arbeitet ausschließlich über `CH395_SPI_WriteCmd`, `CH395_GetRecvLen`,
`CH395_ReadRecvBuf` — Treiberfunktionen des WCH-CH395-SPI-Ethernet-Controllers. Es handelt
sich um einen Netzwerk-Empfangsparser über SPI, nicht um einen physischen UART-Parser. Das
tatsächliche "Serial"-Protokoll mit XOR-Checksumme ist die Kette
`Serial_Command_Dispatch` → `Serial_Packet_Validate` → `BLE_Cmd_*`.

**A) CH395-Empfangspuffer-Parser (`UART_Packet_Receive_Parse`)**

Kompaktierender linearer Puffer (RAM `0x2001af8c`, 0x802 Byte, kein klassischer Ringpuffer):
neue Daten werden an `length` angehängt, Overflow (`0x800-length < neue_Bytes`) verwirft
den gesamten Puffer + CH395-SPI-Reset. Nach Frame-Extraktion werden Restbytes per memcpy
nach vorne verschoben. Idle-Zähler im letzten Byte (0x64 = "tot", Verbindung als beendet
gewertet).

| Typ-Byte | Bedeutung | Wirkung |
|---|---|---|
| `0x18` (doppelt) | Abbruch/Cancel | Signal -1 an Aufrufer, Puffer geleert |
| `0x01` | Kleines Paket, 128B Payload | Frame extrahiert, Redundanzcheck (invertiertes Byte-Paar); **kein statisch auffindbarer Weiterverarbeitungs-Handler** |
| `0x02` | Großes Paket, 1024B Payload | wie Typ 1, passt zum Muster Config-Chunk vs. Firmware-Chunk |
| `0x04` | No-Op/Bestätigung | Puffer geleert, Rückgabe 0 |
| `0x41`/`0x61` | Moduswechsel/Trigger | Puffer geleert, Rückgabe 1 |

Redundanzcheck bei Typ 1/2: nur `hdr_a == (hdr_b ^ 0xFF)` (zwei Header-Bytes), **keine**
XOR-Summe über die gesamten Payload-Daten trotz gegenteiliger Vorab-Einschätzung.

**B) Serial-Kommandoprotokoll (`Serial_Packet_Validate` / `Serial_Command_Dispatch`)**

Frame: `['s'][len:2 BE][cmd:1][0x10][payload...][xor_checksum:1]`, max. 138 Byte
Gesamtlänge. Checksumme = XOR über alle Bytes ohne das Checksum-Byte selbst
(`FUN_08013f24`, generischer XOR-Helper, auch von `AT_Response_Parser` u.a. genutzt).

| Cmd | Bedeutung | Handler | Wirkung |
|---|---|---|---|
| `0x23` | System-Reboot | `BLE_Cmd_SystemReboot` | `Inverter_BeginShutdown(1)`, Timer stoppen, Reboot-Flag setzen — **löst geräteweiten Reboot aus** |
| `0x3a` | OTA Init/Slot-Wahl | `BLE_Cmd_OTA_Init` | OTA-Statusstruktur init, Ziel-Offset/Modell übernehmen |
| `0x50` | OTA Write-Setup | `BLE_Cmd_OTA_WriteSetup` | Ziel-Adresse/Größe übernehmen, Flash vorbereiten |
| `0x51` | OTA Datenblock | `BLE_OTA_WriteDataChunk` | **128 Byte Payload direkt per `Flash_Write_Protected` in externen SPI-Flash schreiben** |
| `0x52` | OTA Validate/Commit | `BLE_Cmd_OTA_Validate` | Modell-ID/Länge/CRC prüfen, Image als gültig markieren |

Alle Handler antworten über `BLE_SendFramedNotification` → GATT-Notify, was für eine
**BLE-Verbindung** als Transportweg spricht. Bei Validierungsfehler: Paket wird
stillschweigend verworfen, kein Logging, kein Rate-Limiting.

**Aufrufer/physische Schicht:** Für beide Funktionen kein statisch auflösbarer Aufrufer
gefunden (`callerCount: 0`) — vermutlich zur Laufzeit registrierter Funktionszeiger
(CH395-Socket-Callback bzw. BLE-GATT-Write-Callback). `Comm_Status_Flags_Reset`, das
`Serial_Command_Dispatch` bei jedem gültigen Paket aufruft, wird auch von
`CAN_Update_StateMachine` (13.1) verwendet — Serial/BLE-Protokoll und CAN-Update teilen
denselben OTA-Watchdog-/Statusmechanismus. Verhältnis zur separaten Funktion
`BLE_Recv_Cmd_Dispatcher` (0x08007f58, 6732 Byte, ebenfalls 0 Caller) ungeklärt — evtl.
parallele/ältere Protokollgeneration.

**Sicherheitsbewertung:** Keine Authentifizierung in beiden Pfaden. XOR-Checksumme schützt
nur gegen Übertragungsfehler, nicht gegen gezielte Manipulation. **Reboot (`0x23`) und
kompletter Firmware-Flash-Ablauf (`0x3a`→`0x50`→`0x51`→`0x52`) sind ausschließlich durch
Magic-Byte + XOR-Checksumme + CRC-Integritätsprüfung geschützt — keine
Authentizitätsprüfung.** Sofern der zugrundeliegende BLE-GATT-Kanal ohne Pairing/Bonding
erreichbar ist, ist das ein kritischer Angriffsvektor (nicht authentifizierter Reboot und
Firmware-Flash). Exaktes Schutzniveau hängt von der (hier nicht analysierten)
BLE-Sicherheitskonfiguration ab.

**Offene Fragen:** Tatsächlicher Aufrufmechanismus/Callback-Registrierung; Weiterverarbeitung
der Typ-1/2-Pakete in `UART_Packet_Receive_Parse`; Verhältnis zu `BLE_Recv_Cmd_Dispatcher`;
UART-Bridge vs. direkt integrierter BLE-Stack; BLE-Pairing/Bonding-Konfiguration; Bounds-
Checks der Ziel-Flash-Adresse in `BLE_Cmd_OTA_WriteSetup`.

**Nachtrag (Vertiefung):**

**KRITISCHER SICHERHEITSBEFUND — kein Bounds-Check der Ziel-Flash-Adresse im gesamten
BLE-OTA-Schreibpfad.** Vollständige Ketten-Analyse (`get-decompilation`, volle Funktionen)
von `BLE_Cmd_OTA_WriteSetup` (0x0802e900, 68 Byte) → `OTA_Flash_Prepare_ByTarget`
(0x0802f730) → `BLE_OTA_WriteDataChunk` (0x0802ed04, 240 Byte) → `Flash_Write_Protected`
(0x0802b774) → `SPI_Flash_QuadPageProgram`:

- Alle drei OTA-Handler (`BLE_Cmd_OTA_Init` 0x0802e86c, `BLE_Cmd_OTA_WriteSetup`
  0x0802e900, `BLE_OTA_WriteDataChunk` 0x0802ed04) referenzieren **denselben** globalen
  OTA-Statusblock, verifiziert per `read-memory`: alle vier `DAT_`-Literale (0x0802e8fc,
  0x0802e948, 0x0802edf8, 0x0802f7ac) enthalten identisch `63 9D 01 20` = RAM-Adresse
  `0x20019d63`.
- `BLE_Cmd_OTA_WriteSetup`: `*(struct+0xc) = *(param_1+5)` (Ziel-Offset) und
  `*(struct+8) = *(param_1+9)` (Größe) werden **ungeprüft** aus dem BLE-Paket übernommen —
  keinerlei Range-Check gegen Slotgröße oder gültigen Adressbereich.
- `OTA_Flash_Prepare_ByTarget` setzt nur den Slot-**Basis**-Offset abhängig vom Modell-Byte
  (`struct+1`): EMS→`0x80000`, MPPT→`0x100000`, BMS→`0x180000`, VNS→`0x200000`, und ruft
  `Flash_ReadWrite_Transaction(base, 0x7d000)` (vermutlich Erase) — **nur einmalig pro
  Session** (`if (struct+0x14 == 0)`).
- `BLE_OTA_WriteDataChunk`, Kernzeilen:
  ```
  *(struct+0x14) = *(param_1+5);                         // Chunk-Offset, Angreifer-kontrolliert
  if ((*(struct+0x18) == *(struct+0x14)) || (*(struct+0x18) == 0)) {
      ...
      Flash_Write_Protected(param_1+9, *(struct+0x10) + *(struct+0x14), 0x80);
      *(struct+0x18) = *(struct+0x18) + 0x80;
  }
  ```
  Die einzige "Prüfung" ist ein Soft-Sequenz-Abgleich gegen den internen Lauf-Zähler
  `struct+0x18` — **kein Bounds-Check gegen die Slotgröße `0x7d000` oder einen gültigen
  Adressbereich.** Die OR-Bedingung `struct+0x18 == 0` hebelt selbst diesen Sequenzcheck
  vollständig aus: `struct+0x18` wird durch `BLE_Cmd_OTA_Init` bei jedem Aufruf mit
  neuer Modell-ID/Version auf 0 zurückgesetzt (`memset(struct, 0x3c)` in
  `BLE_Cmd_OTA_Init`, 0x0802e86c). Ein Angreifer kann also **beliebig oft** `0x3a`
  (Init, mit wechselnder Modell-ID) gefolgt von genau einem `0x51`-Paket (Datenblock) mit
  frei gewähltem 32-Bit-Offset in `param_1+5` senden und dabei jedes Mal 128 Byte
  Nutzdaten an `slot_base + beliebiger_Offset` schreiben.
- `Flash_Write_Protected` (0x0802b774) und `SPI_Flash_QuadPageProgram` führen **ebenfalls
  keine** Adress-/Bounds-Validierung durch — nur Mutex-Locking und Seitengrenzen-Splitting
  für die SPI-Schreiboperation selbst.

**Ergebnis:** Der komplette Pfad `0x3a`→`0x51` (BLE-Kommando, siehe Frame-Format in Teil B)
stellt eine **primitive für beliebiges Schreiben an praktisch jede Adresse im externen
SPI-Flash-Chip** dar (Ziel = fester Modell-Basisoffset + voll Angreifer-kontrollierter
Offset, keine obere/untere Grenzprüfung, kein Vorzeichen-Check). Betroffen sind potenziell
alle vier Firmware-/Modell-Slots (EMS/MPPT/BMS/VNS) sowie angrenzende Flash-Bereiche
außerhalb des mit `0x7d000` Byte nominell vorbereiteten (gelöschten) Slots. Da laut
Sicherheitsbewertung in Teil B **keine Authentifizierung** auf dem Serial/BLE-Kommandopfad
existiert und der Schutz nur aus Magic-Byte + XOR-Checksumme + späterer CRC-Prüfung beim
Commit (`0x52`) besteht, ist dies bei erreichbarem BLE-GATT-Kanal (ohne Pairing/Bonding)
ein **kritischer, aus der Ferne ausnutzbarer Flash-Corruption/Firmware-Manipulations-
Angriffsvektor** — unabhängig davon, ob der CRC-Commit-Check (`0x52`) am Ende greift, da
der eigentliche Schreibvorgang bereits vorher erfolgt ist und beliebige Flash-Inhalte
(auch außerhalb des OTA-Image-Bereichs, z.B. Konfigurationsdaten) überschreiben kann.

Zu den übrigen offenen Fragen: `UART_Packet_Receive_Parse` (CH395-SPI-Empfangsparser) hat
laut `find-cross-references` weiterhin **0 statisch auflösbare Caller** — der Aufruf
erfolgt nachweislich nicht über einen im Flash-Image auffindbaren direkten Funktionsaufruf,
sondern vermutlich über einen zur Laufzeit registrierten Funktionszeiger (Socket-Rx-Callback
der CH395-Treiber-Infrastruktur), analog zu den bereits in 13.3 Teil B beschriebenen
BLE-Handlern. Für Typ-1/2-Pakete konnte weiterhin **kein** Weiterverarbeitungscode
identifiziert werden, der auf den extrahierten Frame-Inhalt zugreift — die Funktion
extrahiert und kompaktiert den Puffer, gibt aber keinen Frame-Pointer an einen erkennbaren
Handler weiter; wahrscheinlich wird der Rückgabewert/Frame vom (nicht auffindbaren) Aufrufer
weiterverarbeitet. `BLE_Recv_Cmd_Dispatcher` (0x08007f58) bleibt von `UART_Packet_Receive_
Parse` und `Serial_Command_Dispatch` isoliert (keine Querverweise gefunden) — beide Pfade
teilen sich keinen gemeinsamen Code außer `Flash_Write_Protected` und `Comm_Status_Flags_
Reset`, was für **zwei parallele, unabhängige Protokollgenerationen** statt eines
UART→BLE-Bridge-Layers spricht: `UART_Packet_Receive_Parse` ist ein reiner CH395/SPI-
Netzwerkparser (siehe Korrektur zu Grobanalyse oben), während `Serial_Command_Dispatch`/
`BLE_Cmd_*` und `BLE_Recv_Cmd_Dispatcher` zwei getrennte BLE-nahe Kommandopfade ohne
erkennbare gegenseitige Aufrufbeziehung sind.

**Sicherheitsbewertung (Ergänzung):** Die bestehende Einschätzung "Reboot und Firmware-Flash
ausschließlich durch Magic-Byte + Checksumme geschützt" wird durch den Bounds-Check-Befund
verschärft: Es handelt sich nicht nur um fehlende Authentizität, sondern um eine fehlende
**Integritäts-/Bereichsprüfung der Zieladresse**, d.h. selbst ein an sich "erwartetes"
Kommando kann bereits durch einen einzelnen manipulierten Feldwert (Offset) Schaden
außerhalb des vorgesehenen OTA-Slots anrichten.

### 13.4 SOC-Ladebegrenzung (Punkt #7)

**Funktion:** `Battery_Charge_Power_Limiter` (0x08004490, 1 Caller)

**Korrektur zur Ausgangshypothese:** Im Code ist **kein SOC-Bezug (% Ladezustand)** nachweisbar.
Die Funktion kombiniert stattdessen (a) vier PV-Strang-Rohmesswerte aus der Struktur
`0x20014f40` (Offsets `0xC/0x12/0x18/0x1E`, Schwelle 101 zur Gültigkeitsprüfung) und (b) eine
aus der zentralen BMS-Struktur `0x20014f82` (Offset `0x00`=Pack-Spannung ×0.01,
Offset `0x24`=BMS-Ladestromlimit ×0.1) berechnete Hardware-Grenze `P = -(U×I)` mit fester
Untergrenze **-2500 W** (`Power_Limit_Clamp`, 0x08012f80). Nur bei negativem Eingabewert
(Laderichtung) und wenn mindestens ein PV-Strang-Wert ≥101 ist, wird die angeforderte
Ladeleistung auf `min(param, PV-Summe×0.1 + HW-Grenze)` gekappt; ein Modus-Flag
(`0x20014f82+0x17` Bit0) schaltet auf reine Hardware-Grenze um.

`Power_Limit_Clamp` ist ein generischer Baustein, der auch von `Grid_Export_Power_Limiter`
(0x0801ec38) und `Inverter_Power_Setpoint_Calc` (0x080061fc) genutzt wird — kein
Battery-Charge-spezifischer Code.

**Caller-Kette:** `Inverter_Power_Setpoint_Calc` → mehrere weitere Klemm-Stufen (PV-Ertrag,
Rückspeise-Sperre, feste Grenzen) → Gesamt-Sollwert wird via `Register_PackDescriptor(1,·,4,0)`
+ `Register_WriteValue` in das interne Register-System geschrieben (plausibel Modbus-lesbar
über `Modbus_StoreRegisterSlot`, konkrete Registeradresse nicht aufgelöst).

**HA-Relevanz:** Externe Fernsteuerungspfade (`Remote_Power_Command_Execute`, MQTT Passive
Mode) können eine Ziel-Ladeleistung vorgeben; `Battery_Charge_Power_Limiter` wirkt danach als
harte Sicherheitsbegrenzung — kein Bypass/Override im Code sichtbar. Für eine HA-Anzeige der
"aktuell zulässigen Ladeleistung" ist die BMS-Telemetriestruktur `0x20014f82` (bereits per
MQTT/BLE aufbereitet) die relevantere Quelle.

**Offene Fragen:** Exakte Feldbedeutung `0x20014f82+0x00/+0x24`; Bedeutung Flag-Bit0/Bit1 bei
`+0x17`; konkrete Modbus-Registeradresse des finalen Sollwerts; Vorzeichenkonvention
(negativ = Laden oder Entladen?) — ein bestehender Code-Kommentar an `Inverter_Power_Setpoint_Calc`
widerspricht der hier beobachteten Logik und ist vermutlich fehlerhaft.

**Empfehlung:** Punkt #7 in der Findings-Liste umbenennen zu "PV-Ertrags-/BMS-Stromlimit-
basierte Ladeleistungsbegrenzung" (kein SOC-Algorithmus).

### 13.5 CH395 Mutex-Blocking (Punkt #8)

**Funktionen:** `CH395_SPI_Cmd_WithData` (0x08002c38), `CH395_SPI_ReadByte` (0x08002e10),
`CH395_SPI_WriteCmd` (0x08002ea4), `CH395_Socket_SendData` (0x0802d12c), zusätzlich
`CH395_SPI_Send_Data` (0x08003644), `CH395_SPI_CmdWaitReady` (0x08002f38),
`CT_SyncTransfer` (0x0802d484), `Delay_Ms` (0x0803e304).

**Zentraler Fund:** Alle CH395-Treiberfunktionen sichern SPI-Zugriff über **eine einzige
globale FreeRTOS-Queue der Länge 1 (RAM `0x20000120`)** als Mutex-Ersatz — verifiziert über
identische Literal-Pool-Werte an den vier `DAT_*`-Referenzstellen. Es ist kein echter
`xSemaphoreCreateMutex` (keine Priority Inheritance), sondern `xQueueReceive`/`xQueueSend`
mit Timeout-Literal **5000** (≈5s bei 1kHz-Tick, Tick-Rate angenommen, nicht verifiziert).
Bei Timeout: stiller Fehlschlag (Rückgabe 0), kein Retry.

**Busy-Wait-Stellen:**

| Funktion | Timeout/Iterationen | Blockierend? |
|---|---|---|
| `CT_SyncTransfer` (pro SPI-Byte) | 2× 4096 Zählschleifen | echter Busy-Spin, kein Yield |
| `CH395_Socket_SendData`-Tail-Loop | 20000 abwärts, alle 500 ein Poll | reiner CPU-Spin |
| `CH395_SPI_CmdWaitReady` | bis 201× `Delay_Ms(5)` ≈ **~1,0s worst case**, **hält dabei den globalen Mutex** | kooperativ ggü. Scheduler, aber Mutex bleibt bis zu 1s belegt |

**Kaskaden-Risiko bestätigt:** `Modbus_Dispatcher` (0x0801e43c) ruft direkt
`CH395_SPI_WriteCmd`/`CH395_SPI_Send_Data`; `RS485_UART_Send` (0x080072a0, aus
`RS485_RTU_Frame_Dispatcher`, FC06/FC10-Handlern, `Protocol_AA_RS485Forward`) ruft direkt
`CH395_Socket_SendData` — synchron, ohne Queue-Entkopplung. Da alle CH395-Funktionen
denselben globalen Lock teilen, kann eine netzwerkseitige Operation (Chip-Init/Reset,
`CH395_UDP_ServerTask`, `HTTPS_POST_Request`), die den Lock bis zu ~1s hält (bei
`CH395_Reset_And_Reinit` durch zwei aufeinanderfolgende Init-Phasen ggf. deutlich mehr,
näherungsweise Richtung 5s-Timeout), einen gleichzeitigen Modbus-/RS485-Sendevorgang für
diese Dauer verzögern. Bei ≤1000ms-Timeout vieler Modbus-Master ist das plausibel ausreichend,
um als Master-seitiger Timeout wahrgenommen zu werden.

**Offene Fragen:** Tick-Rate nicht direkt verifiziert; Task-/Prioritätszuordnung von
`Modbus_Dispatcher` vs. `CH395_UDP_ServerTask` nicht ermittelbar (keine auflösbaren Caller,
vermutlich `xTaskCreate`-Tabelle); Aktivierungsstatus des RS485→Ethernet-Forwarding-Flags
in Standardkonfiguration ungeklärt.

### 13.6 I2C Bit-Bang + HW-I2C (Punkt #9)

**Funktionen:** `I2C_BitBang_Delay/WriteByte/Start/Stop/ReadBit/WriteBytes`,
`I2C_Init_Configure` (0x080028ec), `CAN_SendWorkModeFrame` (0x0802c5b0),
`CAN_SyncChangedRegisters` (0x0802c5d8, neu identifiziert).

**GPIO-Zuordnung (korrigiert):** Bit-Bang läuft über **GPIOC** (Basis `0x40011000`) —
**SCL=PC0, SDA=PC1** (BSRR/BRR/IDR-Zugriffe verifiziert). Die frühere Notiz "SDA=Pin2,
SCL=Pin1" bezog sich auf Bitmasken, nicht auf physische Pin-Nummern.

**Hardware-I2C-Peripherie — Fehlbenennung aufgedeckt:** `I2C_Init_Configure` ist **keine
I2C-Init, sondern eine bitgenaue Kopie von `CAN_Init()` aus der STM32-StdPeriph-Lib**
(CAN_MCR/CAN_MSR/CAN_BTR-Bitfelder exakt nachgewiesen). 0 Caller verifiziert — toter
StdPeriph-Restcode oder Hinweis auf eine zweite, ungenutzte CAN-Schnittstelle. Empfehlung:
Umbenennen zu `CAN_StdPeriph_Init_UNUSED`.

**I2C-Zielgerät (`CAN_SendWorkModeFrame`):** Sendet 2 Byte per Bit-Bang: Byte0=`0x48` (fix),
Byte1=`(WorkMode<<4|0x81)`. Zwei Aufrufer identifiziert, **beide aus dem Inverter-Subsystem**:
`Inverter_Sync_Init` (periodisch, 3000-Tick-Timer) und `Inverter_Apply_BatteryParams`.
`I2C_BitBang_WriteBytes` hat zusätzlich einen zweiten, bisher nicht dokumentierten Aufrufer:
`CAN_SyncChangedRegisters` (vergleicht 4 Byte-Register, sendet bei Abweichung 2-Byte-Frames) —
ebenfalls ausschließlich aus dem Inverter-Subsystem aufgerufen.

**Hypothese Zielgerät:** `0x48` als klassische 7-Bit-I2C-Adresse ist unüblich (kein bekannter
Standard-Chip). Zusammen mit dem Befund, dass ausnahmslos alle Aufrufer aus dem
Inverter-Sync-Subsystem stammen, ist die plausiblere Deutung ein **proprietäres
Punkt-zu-Punkt-Protokoll zu einem internen Co-Prozessor/MCU im Inverter-/Leistungsteil**
(Frame-/Kommando-IDs statt echter Multi-Slave-I2C-Adressierung) — nicht ein Standard-I2C-Chip
(Display/EEPROM/RTC). Bleibt Hypothese.

**Offene Fragen:** Ob eine vermeintliche 4-Byte-Adresstabelle bei `0x0805af35` real ist oder
ein Linker-/String-Deduplizierungs-Artefakt (überlappt verdächtig mit dem Debug-String
"udp=%d,..."); genaue WorkMode-Enum-Bedeutung; Grund für den toten CAN_Init-Restcode.

**Nachtrag (Vertiefung):**

7. **`0x0805af35` ist kein reales Array, sondern ein Debug-String-Overlap** — bestätigt.
Ghidras eigene Symbolvergabe an dieser Adresse lautet
`s_udp=%d,api=%d,net=%d,port=%d,inv_0805ac80+0x2b5`, d.h. die Adresse liegt exakt Byte-genau
(Offset `+0x2B5`) innerhalb des 848 Byte langen Debug-Format-Strings ab `0x0805ac80`
("cd=%d,tot_i=%d,...soh=%d"). Der Literal-Pool-Wert in `CAN_SyncChangedRegisters`
(`DAT_0802c628` = `0x0805AF35`) liest von dort 4 Bytes als "Byte1"-Sendewerte für die
I2C-Bit-Bang-Übertragung — das sind exakt die ASCII-Bytes `'u','d','p','='`
(0x75,0x64,0x70,0x3D) des Strings. Kein eigenständiges, bewusst designtes Datenarray, sondern
ein Compiler-/Linker-Platzierungsartefakt (wahrscheinlich fehlende/falsche
Speicherreservierung für ein ursprünglich vorgesehenes 4-Byte-Array im Quellcode, das der
Linker stattdessen mit vorhandenen .rodata-Bytes überlappen ließ).

8. **WorkMode-Adresse korrigiert:** Das eigentliche WorkMode-Byte liegt entgegen der
bisherigen Annahme in 13.2 nicht bei `0x20014cfc+0x68`, sondern bei **`0x20014cfc+0x74`**
(`0x20014d70`) — geschrieben von `Config_Write_WorkingMode`/`Config_Set_WorkMode_Validated`
(Wertebereich hart validiert: `< 8`, sonst verworfen), gelesen (ungeprüft) von
`CAN_SendWorkModeFrame` (`WorkMode<<4|0x81`). `0x20014cfc+0x68` wird dagegen von zahlreichen
anderen Funktionen inkl. `Config_Get_DeviceModelCode` genutzt — vermutlich das
Geräte-Modell-Byte, nicht WorkMode; die bisherige Zuordnung in 13.2 war ungenau. Einzelne
Enum-Werte 0–7 konnten inhaltlich nicht vollständig rekonstruiert werden; bekannt bleiben nur
die bereits dokumentierten Sonderfälle: WorkMode `10` = "Remote" (13.12, nur über RS485
erreichbar, umgeht die `<8`-Prüfung) sowie ein **separates** Sub-Flag bei `+0x69`
(`5` = "Force Charge", genutzt in `WorkMode_State_Machine`) — dieses `+0x69`-Feld ist **nicht**
identisch mit dem Haupt-WorkMode-Byte `+0x74` (mögliche Verwechslung in einer früheren
Code-Kommentierung).

9. **Toter CAN_Init-Restcode = `I2C_Init_Configure` selbst** (0x080028ec): 0 Caller
bestätigt, UND die Funktion liegt im Flash-Image direkt vor den echten, aktiv genutzten
CAN-Treiberfunktionen `CAN_ReadMailbox` (0x08002a20) und `CAN_SetupTxMailbox` (0x08002b10) —
passend zur These, dass hier ursprünglich eine zweite bxCAN-Peripherie-Instanz initialisiert
wurde, deren Init-Aufruf beim Umstieg auf die I2C-Bit-Bang-Lösung entfernt wurde, während der
kompilierte Funktionskörper (Objektfile-Linking ohne Function-Level Dead-Code-Elimination /
`--gc-sections`) unbenutzt im Image verblieb.

### 13.7 CAN Parallel-Inverter (Punkt #11)

**Funktionen:** `CAN_Parallel_Inverter_Sync` (0x0800557c), `CAN_Select_Master_Node`
(0x080056b4), `CAN_Detect_Mismatched_Nodes` (0x08004418), neu hinzugezogen:
`CAN_ParallelInverterDataParser` (0x0802e6e4).

**Korrektur zur Ausgangshypothese:** `CAN_Select_Master_Node` enthält **keinen SOC-Vergleich**.
Stattdessen wählt die Funktion den ersten "online" markierten Slot (Byte `+0x02≠0`) mit
plausiblen Statusbytes (Bereich 2–4) aus dem Node-Array `0x200152F0` (3×0x10 Byte). Die
drei Slots entsprechen laut `CAN_Update_Init`-Namenstabelle **mppt/bms/venus** — vermutlich
unterschiedliche Subsysteme für die CAN-basierte Firmware-Verteilung, nicht drei gleichrangige
Parallel-Wechselrichter.

Ein echter **Maximum-Vergleich** ("höchster Wert gewinnt") existiert tatsächlich, aber in
`CAN_Parallel_Inverter_Sync` (Fallback-Pfad bei mehrdeutiger Node-Lage), operierend auf einem
Byte+6-Feld einer separaten Tabelle (`0x20014e3c`) — ob dieses Feld SOC ist, konnte **nicht
verifiziert** werden (Spekulation).

**Versions-Kompatibilitätscheck** (`CAN_Detect_Mismatched_Nodes`): vergleicht eine
Referenz-ID aus dem BMS-Slot gegen eine Gerätetabelle (`0x20014fa8`); genau 1 Abweichung =
Normalfall, 0 oder >1 = Fehler-Flag gesetzt (Struktur `0x2000027a`). Kein Log-Eintrag,
steuert nur den Kontrollfluss von `CAN_Parallel_Inverter_Sync`.

**Datenquelle ungeprüft:** `CAN_ParallelInverterDataParser` (aufgerufen aus
`Protocol_AA_CommandDispatch`, dem 0xAA-Inter-Device-Protokoll) übernimmt Nutzdaten
**ungeprüft direkt aus CAN-Extended-ID-Frames** (Klasse `bits[23:20]==3`, Byte0=`0xce`) in
die Tabelle `0x20014e3c` — keine Sender-Authentisierung, kein CRC/Signatur-Check
(konsistent mit Finding #4).

**Caller-Kontext:** `CAN_Select_Master_Node` und `CAN_Parallel_Inverter_Sync` laufen beide
ausschließlich aus `CAN_Update_StateMachine`, also einmal pro Hauptschleifen-Tick
(Polling, nicht interrupt-getrieben).

**Sicherheitsbewertung:** Ein Angreifer mit CAN-Zugriff kann über geeignete Extended-IDs
beliebige Werte in `0x20014e3c` schreiben und damit sowohl den Fast-Path (rohe
Fremddaten-Übernahme) als auch den Maximum-Fallback gezielt beeinflussen — plausibel als
gezielte Manipulation der Update-Zielauswahl. Wer `0x200152F0` (Online-/Statusbytes je Slot)
beschreibt, konnte nicht lokalisiert werden (offen).

**Offene Fragen:** Schreiber von `0x200152F0`/`0x20014fa8`; Bedeutung Byte+6 in `0x20014e3c`;
Trigger von `*0x20000282=0` (Update-Start); ob "Parallelbetrieb mehrerer Venus-Einheiten"
oder "Multi-MCU-Update (MPPT/BMS)" die zutreffendere Interpretation ist — Namen
`CAN_Select_Master_Node`/`CAN_Parallel_Inverter_Sync` könnten irreführend sein
(Alternativvorschlag: `CAN_Select_Update_Target_Slot`).

### 13.8 Flash String-Obfuskation (Punkt #12)

**Funktion:** `Flash_Obfuscated_String_Decode` (0x080058cc)

**Ergebnis: Ausgangshypothese widerlegt.** Es gibt keinen Beleg für versteckte
Klartext-Strings (Credentials, URLs, Debug-Kommandos). Befunde:

- Der vermeintliche "obfuskierte Input" stammt aus `Flash_ReadWords` — einer generischen
  Hardware-Flash-Controller-Routine mit Busy-Wait-Polling, deren Rückgabewert `0x5a5a5a5a`
  ein **Erfolgs-Statuscode** ist, kein String-Byte/Terminator.
- Die vermeintliche Lookup-Tabelle (`0x0805D915`) enthält nur das monotone Muster
  `01 FF 01 FF …` über min. 256 Byte — für eine Zeichen-Substitutionstabelle untauglich.
- Von den 2 gefundenen Aufrufkontexten ist einer (`sscanf_Format_Parser`, 12 Aufrufstellen)
  der generische "get next char"-Callback der firmwareweiten `sscanf()`-Implementierung
  (keine individuellen String-Adressen pro Stelle); der andere
  (`Inverter_Register_Buffer_Init` → `MQTT_Client_Init`) befüllt einen 37-Byte
  **binären** Registerpuffer, kein Text.
- Aufrufkonvention (`r0`/`r1` erwartet vs. tatsächlich genutzte `r4/r5/r6/r8/r9/r10`) spricht
  dafür, dass die **Ghidra-Funktionsgrenze bei `0x080058cc` fehlerhaft gesetzt ist**
  (vermutlich zusammengelegter Code zweier unterschiedlicher Routinen).

**Kein Klartext-String konnte rekonstruiert werden** — bewusst keine Spekulation, da Modulus/
Tabelleninhalt nicht verifizierbar sind.

**Empfehlung:** Punkt #12 als "widerlegt/unklar — vermutlich Registerpuffer-Init, keine
String-Obfuskation" umkategorisieren, kein Sicherheitsrisiko.

**Offene Fragen:** Korrektur der Funktionsgrenze in Ghidra und Re-Analyse; tatsächliche
Bedeutung von `DAT_080010ec`/vermeintlichem sscanf-Callback; Rückverfolgung von `r9`/`r10`
würde Emulation erfordern.

**Nachtrag (Vertiefung):** Funktionsgrenze bestätigt fehlerhaft — per linearer Disassembly
(0x08005860–0x08005900, Ghidra-Skript) verifiziert. Die reale, zusammenhängende Funktion
beginnt bei **0x08005860** (`push {r3,r4,r5,r6,r7,r8,r9,r10,r11,lr}`) und endet bei
**0x080058d9** (122/0x7a Byte Gesamtgröße), einziger Caller `MQTT_Connect_And_Subscribe`
(0x080180de über `Inverter_Register_Buffer_Init`). Ghidras separater Funktionseintrag bei
`0x080058cc` (`Flash_Obfuscated_String_Decode`) liegt exakt auf der Instruktion `cmp r8,r9`
mitten in der Schleifenbedingung dieser Funktion — erreicht nur über einen `b`-Tail-Jump von
`0x080058a2` aus dem Funktionsanfang, niemals als gültiges eigenständiges Sprungziel. Die 12
`COMPUTED_CALL`-Xrefs von `sscanf_Format_Parser` sind damit als Ghidra-Fehlinterpretation
einzuordnen: ein indirekter Aufruf über die sscanf-Callback-Tabelle (Konvention `r0`/`r1`)
kann nicht sinnvoll auf eine Adresse zeigen, deren Code ausschließlich mit ererbtem
`r4/r5/r6/r8/r9/r10`-Kontext des Aufrufers arbeitet.

Reale Funktionslogik (bestätigt durch Disassembly): Parametervalidierung, `memset`+`memcpy`,
danach Schleife über `Flash_ReadWords()` (0x08000294 — Dekompilat verifiziert generische
Flash-Controller-Routine mit Busy-Poll auf Statusbit 0x80 über `DAT_080004ac[3]`; Rückgabe
`0x5a5a5a5a` ausschließlich als Erfolgs-Statuscode nach abgeschlossenem Wortlese-Loop). Bei
Erfolg wird `(gelesenes_wort mod 64)` als Index in eine per Literal-Pool-Pointer
`DAT_080058dc` (Speicherinhalt: `15 D9 05 08` = `0x0805D915`) referenzierte Tabelle
verwendet; das Ergebnisbyte wird in den Zielpuffer geschrieben. Speicherauszug der ersten 64
Byte ab `0x0805D915`: striktes Alternierungsmuster `FF 01 FF 01 …` — **nur 2 mögliche
Ausgabewerte** (paritätsabhängig 0x01/0xFF). Das ist strukturell unfähig, beliebige
Klartextzeichen zu erzeugen, und untermauert die bereits getroffene Einordnung als binäre
Registerpuffer-Initialisierung (Marker-/Flag-Bytes je Registerplatz für `MQTT_Client_Init`),
nicht als String-Dekodierung. Punkt #12 bleibt damit widerlegt — jetzt mit korrigierter
Funktionsgrenze und vollständig geklärter tatsächlicher Semantik.

### 13.9 Debug-Backdoor (Punkt #13)

**Funktion:** `Debug_Mode_Set` (0x08005fb8); `System_SetDebugMode`/`_Wrapper` (0x08050dd8)
sind **dieselbe Funktion** (Doppel-Eintrag im Tracking, sollte zusammengeführt werden).

**Mechanismus:** `0xC2` ist keine einfache Vergleichskonstante, sondern eine
**Register-Gruppen-ID** im internen CAN/RS485-Registerprotokoll
(`Register_PackDescriptor(0xC2,…)` → `Register_WriteValue` → FreeRTOS-Queue an ein
nachgelagertes Inverter/DSP-Subsystem, dieselbe Mechanik wie in Findings #4/#11). Gruppe
0xC2 wird ausschließlich hier erzeugt, kein Empfänger-Handler gefunden. Zusätzlich setzt die
Funktion bei Aktivierung ein lokales RAM-Flag `0x20000132 = 2`.

`0x08050dd8` ist ein CLI-artiger Wrapper (`printf("debug_mode=0/1")` + Aufruf von
`Debug_Mode_Set` mit Log-Level 4=DEBUG).

**Aktivierungskanal: statisch unerreichbar.** `Debug_Mode_Set` hat nur einen Caller
(`0x08050dd8`); für `0x08050dd8` selbst wurden **weder Code- noch Datenreferenzen noch
Funktionszeiger-Literale** gefunden (Cross-Reference- und Konstanten-Suche negativ). Der
Pfad ist im aktuellen Firmware-Image **toter Code** — vorbehaltlich einer nicht-typisierten
Sprungtabelle, die Ghidra nicht als Xref erkennen würde.

**Verwandtes, tatsächlich aktives Risiko:** Dasselbe RAM/EEPROM-Flag (`0x20000132`/EEPROM
`0x900`) lässt sich unabhängig von `Debug_Mode_Set` über **Modbus-Register 46000 (0xB3B0,
"OTA command") mit Magic-Value `0x5100`** setzen (`Write_Handler`, 0x08051f7a) — per TCP
oder RS485-RTU, **ohne Authentifizierung** (einzige Prüfung: Registernummer ≥40000). Das
aktiviert persistent (EEPROM-Backup) erweiterte Debug-Log-Ausgabe und überlebt einen Reboot.
Der von `Debug_Mode_Set` gesetzte Wert (`2`) aktiviert zusätzlich RS485-Passthrough-Forwarding
in `Protocol_AA_RS485Forward` (0x0802f0d0) bei eingehender Registergruppe 0xC3 — dieser Pfad
ist aber nur relevant, falls `Debug_Mode_Set` doch erreichbar wird.

**Sicherheitsbewertung:** Der ursprünglich als "Backdoor" eingestufte 0xC2/Debug_Mode_Set-Pfad
ist in FW 149.2 **inaktiv** und stellt aktuell kein Risiko dar. Das eigentlich ausnutzbare
Risiko liegt im ungesicherten Modbus-Schreibzugriff auf Register 46000, der dieselbe RAM-Zelle
missbraucht und mit dem OTA-Themenkomplex (Finding #14/#25) zusammenhängt.

**Offene Fragen:** Warum ist `0x08050dd8` unerreichbar (Rest eines entfernten CLI-Parsers)?
Consumer der Register-Gruppe-0xC2-Queue; Caller von `EEPROM_ClearSetting_0x900`
(0x0804d5b0, ebenfalls 0 Xrefs); Bedeutung weiterer Flag-Werte außer 1/2.

**Nachtrag (Vertiefung):**

*Warum `0x08050dd8` unerreichbar ist:* Die Strings `"debug_mode=1\r\n"`/`"debug_mode=0\r\n"`
sind ausschließlich von `0x08050dd8` selbst referenziert (kein externer Dispatcher). Im
Speicherbereich `0x080555a0`–`0x08055620` liegt zusätzlich ein zusammenhängender Block aus
Einstellungs-Namen mit chinesischsprachigen Beschreibungstexten — u.a. `"debug_mode"`
(0x080555ea, direkt gefolgt von `"开关逆变器调试功能"` = "Wechselrichter-Debug-Funktion
ein/aus") und `"venus_poweroff"` (0x08055611, gefolgt von einer Ruhemodus-Beschreibung).
**Beide Namens-Strings haben 0 Referenzen im gesamten Firmware-Image** (geprüft per
`find-cross-references`) — es handelt sich also nicht nur um einen einzelnen entfernten
Befehl, sondern um eine ganze verwaiste CLI-/Service-Menü-Parametertabelle (mehrere Settings
inkl. `debug_mode` und `venus_poweroff`), deren konsumierender Dispatcher komplett aus FW
149.2 herauskompiliert wurde; die Strings blieben nur als Bloat im `.rodata`-Bereich zurück.
Das stützt die These "Rest eines entfernten CLI-Parsers" und erweitert sie: nicht nur die
Funktion, auch die zugehörigen Nameneinträge sind verwaist.

*Consumer der Register-Gruppe-0xC2-Queue:* `Register_WriteValue` → `Modem_QueueSendMessage`
→ `xQueueSend(*(struct@0x200000e8 + 4), …)` — das Queue-Handle liegt in RAM `0x200000ec`
(Feld+4 einer größeren Kontrollstruktur, deren Feld+0 (`0x200000e8`) separat als CAN-RX-
Mailbox-Handle von `CAN_RxMailbox_Handler`/`CAN_RxQueue_DrainAndDispatch` genutzt wird — aktiv
und unabhängig vom 0xC2-Pfad). Als einziger plausibler Consumer für exakt dieses
Queue-Handle (`0x200000ec`) wurde `Modbus_SendResponse` (0x0802c060) identifiziert: es ruft
`Modbus_Response_Builder(*(0x200000e8+4), buf, 1000)` — eine Funktion, die direkt gegen
FreeRTOS-Queue-Interna arbeitet (`prvCopyDataFromQueue`, Nachrichtenzähler bei Struct-Offset
`+0x38`), de facto eine eigene `xQueueReceive`-Implementierung — und leitet bei Erfolg über
`CAN_SendMessage(buf)` weiter auf den CAN-Bus. **`Modbus_SendResponse` selbst hat jedoch 0
eingehende Referenzen** (`find-cross-references` beide Richtungen negativ; auch
Konstantensuche nach der Thumb-Adresse `0x0802c061` liefert keinen Treffer, keine erkennbare
Task-Erzeugungsstelle). Damit ist nicht nur der Producer (`Debug_Mode_Set` via `0x08050dd8`),
sondern auch der einzige im Image auffindbare Consumer-Pfad für Gruppe 0xC2 statisch
unerreichbar — die gesamte Kette Producer→Queue→Consumer ist in FW 149.2 inaktiv.

*Caller von `EEPROM_ClearSetting_0x900`:* Erneut gezielt geprüft — `find-cross-references`
(beide Richtungen, inkl. Daten-Referenzen) liefert weiterhin **0 Treffer**; zusätzlich
`find-constant-uses` für sowohl die reine Adresse `0x0804d5b0` als auch die Thumb-Bit-Variante
`0x0804d5b1` (mögliche Funktionszeiger-Tabelleneinträge) liefert ebenfalls **0 Treffer**.
Keine Funktionszeigertabelle, kein indirekter Aufruf gefunden. Die Funktion ist damit ein
drittes bestätigtes Beispiel toten Codes neben `0x08050dd8` und `Modbus_SendResponse` — passt
ins Gesamtbild eines teilweise deaktivierten/entfernten Debug-/Service-Subsystems in FW 149.2.

*Weitere Flag-Werte:* Vollständige Schreiber/Leser von RAM-Flag `0x20000132` ermittelt.
Schreiber: `Debug_Mode_Set` (0 beim Funktionseintritt / 2 bei Aktivierung), `EEPROM_
ClearSetting_0x900` (0), `Write_Handler`-0x5100-Pfad bei Reg. 46000 (schreibt **1**, zusammen
mit `EEPROM_Write(0x900,…)` — das ist der bereits dokumentierte persistente Aktivierungsweg).
Leser: `Protocol_AA_RS485Forward` (einzige Vergleichsstelle, prüft ausschließlich `== 2`),
`log_printf` (nur als Log-Ausgabeargument, kein Vergleich). Damit sind **0/1/2 die einzigen
tatsächlich erzeugten bzw. verglichenen Werte** — kein `switch`/keine weitere Vergleichskette
für dieses Flag gefunden. Zur Abgrenzung: Die im `Write_Handler`-Codekommentar dokumentierten
Werte `0x4d2`/`0x929`/`0xd80`/`0x11d7` für Register 46000 setzen ein **anderes** Flag
(`*DAT_08052000`, Werte 1–4, vermutlich OTA-/Reset-Modusauswahl) und sind nicht mit dem
0x20000132-Debug-Mode-Flag zu verwechseln. Nebenbefund: `CH395_Init_TCPServer_Socket`
referenziert dieselbe Basisadresse `0x20000132` nur zufällig als Basiszeiger einer
Socket-Deskriptor-Struktur (Offset `+0x40` ff., TCP-Port `0x1f9b`=8091) — Adress-Koinzidenz,
da das Debug-Mode-Flag am Anfang eines größeren globalen Kontrollblocks liegt, kein
inhaltlicher Zusammenhang.

### 13.10 OTA Flash Pipeline & Dispatcher (#14, #25, #43, #52, #93)

End-to-End-Kette: `App_MainLoopDispatcher` → `OTA_Update_Dispatcher` (0x080151c8, in Ghidra
noch `FUN_080151c8` — Umbenennung nachholen) → `OTA_Process_Pending_Updates` →
`ProcessFirmwareUpdateCommand` → `Flash_EraseRegion`/`Flash_WriteRegion` (interner STM32-Flash,
nur ein 40-Byte-**Slot-Deskriptor**, nicht das Firmware-Image selbst) bzw.
`OTA_Firmware_Download_Init` → `Flash_ReadWrite_Transaction` (externer QSPI-Flash). Finale
Prüfung in `OTA_FW_Verify_And_Apply`: CRC16 + Modellstring `"VNSD-0"` + `dev_mask`-Vergleich —
**an keiner der vier untersuchten Ebenen ein kryptographischer Signatur-Check.**

**#43 4-Slot-Layout bestätigt:** EMS=0x80000, MPPT=0x100000, BMS=0x180000, VNS=0x200000, je
512 KB, via `OTA_Flash_Prepare_ByTarget`.

**#52 llhttp:** Wird **nicht** für OTA-Downloads genutzt — `llhttp_execute` hat 0 Caller,
komplett tote Bibliothek. Der aktive HTTP-Client (`HTTPS_POST_Request`) dient ausschließlich
Cloud-Telemetrie-POSTs; ein vorbereiteter OTA-Zweig in dessen Response-Reader wird von keinem
Aufrufer aktiviert (`param_5=0`). Der tatsächliche Netzwerk-OTA-Trigger läuft stattdessen über
Quectel-AT-Befehl `AT+QWLANOTA` (s. §13.11).

**Sicherheit:** Wer BLE-Zugriff hat, kann über die BLE-OTA-Kette (§13.3) ein beliebiges Image
mit korrektem CRC16 + `"VNSD-0"` + `dev_mask` in einen der vier 512-KB-Slots schreiben — beide
Werte sind statisch/leicht berechenbar. Kein Signatur-Schutz auf keiner Ebene.

### 13.11 BLE OTA, WiFi-OTA & WiFi-Provisioning (#18, #41, #95)

**#18 WiFi-Provisioning:** Delimiter korrigiert: `<.,.>` (nicht `<,>`). SSID/PW werden über
`WiFi_Set_Credentials` → `Quectel_WiFi_SetAPConfig` (`AT+QSTAAPINFODEF`) angewendet und
zusätzlich **im Klartext** nach EEPROM 0x400/0x420 gespiegelt (I2C-Writer transformiert nichts).
Kein Auth-Gate auf BLE-Kommando 5.

**#41 BLE-OTA-Slotwahl:** Keine echte Slot-Arbitrierung — ein einzelnes globales
0x3C-Byte-Session-Struct, Zieladresse wird rein **client-seitig** über ein 1-Byte-Modellfeld
gewählt (EMS/MPPT/BMS/VNS), keine serverseitige Plausibilisierung. **Kein Rollback:** Jeder
128-Byte-Chunk wird unbedingt **vor** jeder Prüfung in den Flash geschrieben; bei fehlgeschlagener
CRC/Modell-Prüfung bleibt die möglicherweise korrupte Region einfach stehen, kein Backup/A-B.

**#95 ⚠️ kritischster Einzelfund dieser Gruppe:** `BLE_WiFi_OTA_WithURL` (0x0800b90c) nimmt eine
**beliebige, vom BLE-Client vorgegebene URL** entgegen und reicht sie 1:1 als
`AT+QWLANOTA=<url>[,<port>]` an das Quectel-Modem weiter — keine Whitelist, kein Protokollzwang,
einzige Prüfung ist eine Längenbegrenzung (≤255 Zeichen). Zusätzlich existiert ein
cloud-unabhängiger fester Modus (`AT+QWLANOTA=http://192.168.137.1/FC41D_OTA.rbl`, klassische
Hotspot-Gateway-IP). Der eigentliche Download/Flash-Vorgang läuft komplett im Quectel-Modul,
die Control-MCU hat keinerlei Sicht auf den Inhalt. Nach jedem Trigger folgt unbedingt ein
`System_Reboot()` — DoS-Nebenwirkung selbst bei wirkungslosem Angriff.

### 13.12 RS485 Register-Map & Remote Power Control (#15, #28, #46)

Alle `Inverter_Set_*`/`Inverter_RS485_Cmd_*`-Funktionen laufen über
`Register_PackDescriptor→Register_WriteValue→Queue` und senden **synchron und sofort**, unabhängig
vom "24-Dirty-Bit"-System. Das Dirty-Bit-Array (`Timeslot_Bitmap_SetClear`) wird nur innerhalb
seiner eigenen Setter-Funktion gelesen — **kein RS485-Versand hängt tatsächlich daran**;
Ausgangsthese zum Dirty-Bit-Sendemechanismus damit widerlegt.

**Kein Auth-Mechanismus** in `Write_Handler` (Modbus TCP wie RS485-RTU) — einzige Schranke ist
der Adressbereich `≥40000`. Das "Register-40000-Unlock" (0x55AA) gated On/Off, Power-Setpoint
und WorkMode **nicht** — diese laufen unabhängig davon. Reg 45012
(`Inverter_Power_Setpoint_Apply`) umgeht zudem die Safety-Clamps, die der reguläre Pfad
(`Inverter_Power_Setpoint_Calc`) anwendet.

**#28 Remote Power Control:** `Remote_Power_Command_Execute` (Mode 0=Zero/1=Discharge/2=Charge/
3=SOC-Schwelle) feuert nur bei WorkMode==10 ("Remote"). Dieser Modus ist über die regulären
Modbus-WorkMode-Register **nicht erreichbar** (dort hart auf <6/<8 begrenzt) — er wird primär über
**MQTT/Cloud-JSON** (`work_mode`-Feld **ohne Wertebereichsprüfung**) oder BLE gesetzt. Schutz
hängt vollständig vom TLS/Broker-Vertrauensmodell ab, nicht von In-Firmware-Autorisierung.

**#46 WorkMode-Modus 1** ("CH395Reset" laut altem Namen) ist **kein Hardware-Reset** — nur ein
Connection-Flag-Reset + `TimePlan_Evaluate_Setpoint`-Trigger (Namenskorrektur).

### 13.13 TLV Parser & 0xAA Inter-Device-Protokoll (#16, #42)

**#16 Namenskorrektur:** `TLV_Record_Parse` ist in Wahrheit ein **DNS-Resource-Record-Parser**
(RFC 1035, bereits am 2026-07-09 zu `DNS_ResourceRecord_Parse` umbenannt); `TLV_Record_Skip`
sollte konsequent zu `DNS_ResourceRecord_Skip` werden. Kein Bezug zu OTA-Metadata. Bug gefunden:
RR-Typen SOA/HINFO/MX/TXT überspringen RDATA nicht — Desync-Risiko bei Mehrfach-Answer-Records
(DNS-Antworten sind spoofbar, da UDP/Port 53 ohne DNSSEC).

**#42 0xAA-Protokoll:** Transport ist **CAN** (Extended-ID, Magic in ID-Bits[15:8]=0xAA), nicht
RS485. Die 17-Entry-Handler-Tabelle liegt zur Laufzeit in RAM (`0x2000018c`) — **kein
Initialisierungscode gefunden**, Inhalt bleibt unbekannt (offene Frage). Wichtiger Namensfund:
Die 6 "bekannten Handler" (`Protocol_AA_SetChannelData` etc.) hängen **nicht** am 0xAA-Gate,
sondern an einem separaten `Telemetry_Register_Dispatcher` (CAN-ID-Klasse 4, 11 Register,
komplett unauthentifiziert). Gefährlichste Funktion: `Protocol_AA_RS485Forward` (Reg 0xC3)
bridged ungeprüfte 8-Byte-CAN-Payload direkt auf den RS485-Bus **oder** einen TCP/UDP-Socket —
klassische Trust-Boundary-Verletzung zwischen CAN- und RS485/Netzwerk-Domäne.

**Nachtrag (Vertiefung):** Der einzige Zugriff auf die Tabelle im gesamten Image ist
`Protocol_AA_CommandDispatch` (0x0802efac) selbst — sie liest über den Flash-Konstantenpointer
`DAT_0802f00c` (Wert `0x2000018c`) 17 Einträge à 8 Byte (2-Byte-ID + 4-Byte-Funktionszeiger,
+2 Pad) und ruft bei ID-Treffer den Handler auf. Drei unabhängige Suchverfahren fanden **keine**
weitere Referenz auf diesen Wert: `find-cross-references` auf `0x2000018c` (0 Treffer),
Volltextsuche über alle Dekompilate nach `2000018c` (0 Treffer) und `find-constant-uses` nach
dem Immediate `0x2000018c` (0 Treffer, durchsucht auch alle Instruktions-Immediates jenseits
symbolisch aufgelöster Pointer). Die RAM-Adresse liegt zudem außerhalb des einzigen von Ghidra
gemappten Speicherblocks (`ram`, `0x08000000`–`0x0805dfff`, nur Flash) — ein direktes `get-data`
auf `0x2000018c` ist daher nicht möglich, und die Hypothese "vorbelegter .data-Init-Wert" lässt
sich mangels erreichbarem Flash-Quell-Offset (kein generischer Datensegment-Kopierloop im
statisch analysierten Code gefunden) nicht verifizieren. Fazit: Die Tabelle wird entweder von
Code außerhalb des untersuchten App-Images beschrieben (z.B. Bootloader oder anderer
Firmware-Teil), oder die Initialisierung erfolgt über einen Mechanismus, der keinen der drei
Suchansätze triggert (z.B. rein register-relative Adressierung ohne Literal-Pool-Konstante). Der
Tabelleninhalt bleibt damit **statisch nicht bestimmbar** — bestätigt den bisherigen Befund,
schließt aber jetzt Initialisierung durch bekannten App-Code mit hoher Konfidenz aus.

### 13.14 Config/EEPROM Layout & Factory Reset (#17, #20)

Drei Factory-Reset-Modi (1=voll inkl. Cloud-Zertifikate, 2=Config-Reset, 3=nur Cert-Wipe),
erreichbar über **vier** Kanäle ohne zusätzliche Auth: Modbus TCP, RS485-RTU, MQTT-JSON-RPC
(Methode 0x11) und BLE (Cmd 6) — **kein physischer Taster-Pfad im App-Image nachweisbar**.
Modus 1 löscht EEPROM-Validity, Statistik, **und Cloud-TLS-Zertifikate** (CA/User-Cert/Key via
`Quectel_SSL_Certificate_Manage`, s. §13.16).

Wichtiger Namensfund: 6 Funktionen (`Config_Read_U8/U16/U32/String/Block`) heißen "Read", rufen
aber tatsächlich `EEPROM_Write` auf — Fehlbenennung, sollten zu `Config_Set_*` werden.
EEPROM-Zugriffsschicht (`EEPROM_Write`/`EEPROM_Read`) hat **kein CRC, kein Wear-Leveling** —
nur Change-Detection zur Zyklenreduktion.

### 13.15 BMS-Zelldaten über BLE + intern (#19, #89)

`BLE_Build_BMS_Data_Response` (Cmd 0x14, kein Auth-Gate) und `BMS_CellVoltage_MinMax_Finder`
(#89, in Ghidra weiterhin `FUN_08013060` — Umbenennung nicht durchgeführt) lesen dieselbe
Quelle (`0x20014f82`/`0x20014fa8`). Bestätigt: **6 Kanäle × 16 Zellen** (plausibel 6
Packs/Module à 16S). Über BLE ohne Autorisierung abrufbar: Packspannung/-strom/-temperatur/SOC,
Lade-/Entladelimits, Fehlerflags (teilweise) und 16 Einzelzellspannungen von Pack 0 — Privacy-
relevant (Rückschlüsse auf Zellalterung). Keine Balancing-Logik im Control-FW gefunden, nur
Reporting.

**Nachtrag (Vertiefung):** Vier gezielte Nachfragen zur Struct-Feldbedeutung geklärt bzw. als
unauflösbar bestätigt:

1. **Feld `0x20014f82+0x00`:** **Pack-/Systemspannung, Einheit 10 mV (unsigned short)** —
   belegt durch den (unverdrahteten, aber layout-identischen) Debug-Printer
   `CAN_Battery_Telemetry_Debug_Print` (`0x080358ec`), dessen erste Ausgabe exakt dieses Feld
   mit dem Format-String `"pgn_1801_info.bat_volt(10mv)=%d"` beschriftet (verifiziert über
   `find-cross-references` auf `0x080358f0`→`DAT_20014f82`, unmittelbar gefolgt vom String-Zugriff
   auf `0x080359d0`). Konsistent mit `Power_Limit_Clamp` (`0x08012f80`), das `*DAT_08012fe0`
   (=`0x20014f82`) mit `0.01` skaliert (10-mV-Rohwert → Volt) und mit dem Feld bei `+0x12`
   (`chrg_curr`, 100-mA-Einheit, gleiche Debug-String-Tabelle) zu einer Leistungs-Clamp-Grenze
   multipliziert — d. h. dieses Feld ist die zentrale Spannungsgröße, die in praktisch der
   gesamten Lade-/Entlade-Regelkette (`Power_Limit_Clamp`, `WorkMode_State_Machine`,
   `Grid_Power_Dynamic_Adjust`, `Inverter_Power_Setpoint_Calc`, `Inverter_Apply_BatteryParams`)
   referenziert wird. Feld `0x20014f82+0x24` (`0x20014fa6`) dagegen hat **keinen einzigen
   statischen Reader/Writer** (leeres `find-cross-references`-Ergebnis) — es liegt in einer
   2-Byte-Lücke zwischen dem letzten breit genutzten Feld `+0x22`/`+0x23` (referenziert u. a. von
   `MQTT_Telemetry_Struct_Builder`, `Cloud_Report_URL_Builder`, `BLE_RuntimeInfo_Builder`,
   `BLE_Recv_Cmd_Dispatcher`) und dem Beginn der 6-Kanal-Zellstruktur bei `0x20014fa8`.
   Wahrscheinlichste Erklärung: Padding/Reserve-Byte, alternativ ein nur dynamisch (nicht
   konstant-propagierbar) adressiertes Feld — bleibt offen.

2. **Flag-Bit0/Bit1:** Das getestete Byte sitzt bei `0x20014f82+0x16` (`0x20014f98`) und trägt
   laut derselben Debug-String-Tabelle den Namen **`chrg_flag`** (`"pgn_1803_info_chrg_flag=%d"`,
   ein Byte weiter folgt ein separates `force_chrg`-Flag bei `+0x17`). `WorkMode_State_Machine`
   (`0x0802c784`) testet beide Bits, um die normale SOC-Hysterese für Ladestart/-stopp
   (Start < 51 %, Stopp > 50 %, s. bestehende Doku) zu überbrücken:
   `bVar6 < 0x33 || (chrg_flag>>1 & 1)` (Bit1 gesetzt ⇒ Ladestart wird auch oberhalb 51 % SOC
   erzwungen) UND `0x32 < bVar6 || (chrg_flag & 1)` (Bit0 gesetzt ⇒ Lademodus bleibt auch
   unterhalb 50 % SOC aktiv). Das Feld wird zusätzlich von `Battery_Forced_Charge_Check`
   (`0x08005344`) gelesen, was die Interpretation als BMS-seitiges "Zwangslade"-Anforderungsflag
   stützt. Ein Schreiber wurde nicht lokalisiert (plausibel: CAN-RX-Empfangspfad vom BMS,
   analog zu Punkt 3).

3. **Schreiber von `0x200152F0` und `0x20014fa8`:** Trotz erschöpfender Suche (alle bekannten
   Flash-Literal-Pool-Einträge, die auf diese RAM-Adressen zeigen, per
   `find-cross-references`/`find-constant-uses` durchsucht) wurden **ausschließlich Leser**
   gefunden — kein Schreiber im Firmware-Image lokalisierbar; die "offene Frage" aus §13.1 wird
   damit als **tatsächlich unauflösbar** bestätigt (keine bloße Suchlücke). Bestätigt außerdem:
   **zwei unterschiedliche Speicherbereiche**, kein Adress-Alias. `0x200152F0` ist das
   3×0x10-Byte-Node-Array (Leser: `CAN_Select_Master_Node` `0x080056b4`, `CAN_Update_Init`
   `0x08027224`) für den Firmware-Update-Peer-Status je Subsystem-Slot (mppt/bms/venus, s.
   §13.1). `0x20014fa8` ist die separate 6-Kanal-BMS-Zellstruktur (6×0x60 Byte; Leser:
   `BMS_CellVoltage_MinMax_Finder`/`FUN_08013060`, `BLE_Build_BMS_Data_Response`,
   `CAN_Detect_Mismatched_Nodes` `0x08004418`, das Kanal-Mismatch über Feld `+0x1e` je Kanal
   erkennt). Beide folgen direkt aufeinander im RAM (Node-Array endet bei `0x20015320`, dort
   beginnt laut `CAN_Update_Init` die Update-Zustandsstruktur) bzw. direkt an die
   Pack-Summenstruktur `0x20014f82` an (`0x20014fa8` = `0x20014f82+0x26`) — beides spricht für
   denselben CAN-RX-Empfangspfad als wahrscheinlichsten (aber nicht verifizierten) Schreiber,
   vermutlich über einen PGN-Dispatcher-Mechanismus, der von Ghidras statischer
   Konstantenpropagierung nicht erfasst wird (ähnlich dem indirekten `Register_PackDescriptor`-
   Muster aus §13.18).

4. **Byte+6 in `0x20014e3c`:** Struct ist ein Array von 8-Byte-Einträgen (Basis `0x20014e3c`,
   indiziert `uVar3*8`, Anzahl in `0x2000027a+2`), verarbeitet in `CAN_Parallel_Inverter_Sync`
   (`0x0800557c`). Byte+6 je Eintrag ist ein **Prioritäts-/Rangwert für die "Maximum-Fallback"-
   Masterwahl** zwischen parallelen Venus-Einheiten: Wert `0` markiert einen Eintrag als "noch
   keine Daten" und bricht die Wahl ab (`if (*(entry+6) == 0) { reset; return; }`); andernfalls
   gewinnt der Eintrag mit dem höchsten Byte+6-Wert über alle Einträge (Vergleichs-/Max-Tracking
   in `0x2000027a+3`, Gewinner-Index in `0x2000027a+4`). Das bestätigt direkt den in §13.1
   beschriebenen "Maximum-Fallback"-Mechanismus (Modus-Byte `0x20015320+0x12 == 3`, während
   Modus `2` den direkten "Fast-Path" auf den ersten Eintrag nimmt) und damit auch die dortige
   Sicherheitsbewertung: Ein Angreifer mit CAN-Zugriff kann über gefälschte Extended-ID-Frames
   beliebige Byte+6-Werte einspielen und so gezielt bestimmen, welcher (simulierte) Node die
   Master-Rolle gewinnt.

**Weiterhin offen:** exakte Feldbedeutung von `0x20014f82+0x24` (vermutlich Padding); Schreiber
von `0x200152F0`/`0x20014fa8` (CAN-RX-Pfad plausibel, aber nicht verifiziert); Schreiber des
`chrg_flag`/`force_chrg`-Bytes bei `+0x16`/`+0x17`.

### 13.16 Quectel/Cellular Subsystem (#21, #22, #49)

**#21** `Quectel_SSL_Certificate_Manage` verwaltet 3 benannte Slots ("CA"/"User Cert"/"User Key")
für mTLS — im laufenden Firmware-Image aber **nur der Delete-Zweig erreichbar** (aus
Factory-Reset/BLE-Reset); Upload/Query/List haben 0 Caller. Tatsächliches Zertifikatsmaterial
liegt nicht im Control-FW-Image (s. auch §13.27 Private-Key-Befund).

**#22** `Quectel_URC_JsonFrameParser`: sauberer 511-Byte-Überlaufschutz, keine Endlosschleife.
Aber ein Resync-Wartemuster (`"id=%s&latest=true"`) sieht wie ein Format-String-Artefakt aus,
der in echten Modem-Antworten wörtlich kaum auftreten dürfte — **Verdacht auf einen
Parser-Hänger nach dem ersten Frame** (nicht laufzeitverifiziert, offene Frage).

**#49** `Modem_ParseThreePhaseActivePower` liest denselben Puffer wie #22 (JSON-Pipeline
UART→Brace-Assembler→Key/Value-Extraktion), keine Signatur-/Plausibilitätsprüfung der Werte.
Ob diese ungefiltert in `CT_PowerSetpoint_Compute` (§13.21) einfließen, konnte nicht
lückenlos verifiziert werden (Queue-Consumer nicht lokalisiert).

**Nachtrag (Vertiefung):**

**Zu #22 (Parser-Hänger):** Verdacht **bestätigt** — Bug gefunden. Volle Dekompilation von
`Quectel_URC_JsonFrameParser` (0x08010eb0) zeigt einen Byte-für-Byte-State-Machine-Parser mit
zwei Modi über das Flag `*DAT_08010ff4`: Modus 0 = normales JSON-Frame-Sammeln (bis `}\r\n` bei
Klammertiefe 0 erkannt wird → Flag wird auf 1 gesetzt); Modus 1 = "Resync-Wait", der eingehende
Bytes gegen ein 16-Byte-Referenzmuster (`DAT_08010ff8` → `0x0805c65e`) vergleicht. Dieses Muster
ist keine eigenständige Konstante, sondern ein Teilstring (Offset 74–89) der HTTP-URL
`"http://%s.hamedata.com/external-services/api/v1/devices/backup-configs?devid=%s&latest=true"`,
konkret die 16 Zeichen `"id=%s&latest=tru"` — inklusive des literalen `%s`-Platzhalters, der in
echten Modem-URCs praktisch nie als Byte-Sequenz auftritt. Bei Byte-Mismatch wird zwar der
Sammelpuffer geleert (`memset` + Längenzähler auf 0), **aber `*DAT_08010ff4` wird nicht
zurückgesetzt** — nur der einzige Erfolgspfad (16/16 Byte Treffer, Zeilen 53–57 der Dekompilation)
setzt Modus zurück auf 0. Da dieses Muster im normalen Modem-Datenverkehr faktisch nie exakt
auftritt, bleibt der Parser nach dem ersten erfolgreich geparsten JSON-Frame dauerhaft im
Resync-Wait-Zustand hängen und verwirft ab dann jedes weitere Zeichen, ohne je wieder ein
JSON-Frame zu erkennen — ein reproduzierbarer Parser-Hang/DoS nach Frame 1 (laufzeitverifiziert
nur durch Codepfad-Analyse, nicht durch Hardware-Test).

**Zu #49 (Queue-Consumer):** Lokalisiert. `Modem_ParseThreePhaseActivePower` schreibt selbst in
keine Queue — es füllt direkt eine Stack-Struktur (4×4 Byte: Total-/PhaseA-/PhaseB-/
PhaseC-Wirkleistung) im Aufrufer `Modem_Response_Dispatch` (0x08026b40). Dieser sendet die
Struktur bei Erfolg per `xQueueSend(*DAT_08026bf0, &local_30, 0, 2)` in eine Queue (Handle
in RAM `0x200000f8`). Konsument: `CT_GridPower_Controller` (0x0802baa4) liest exakt dieselbe
Queue — `Modbus_Response_Builder(*DAT_0802bc64, &local_38, 0x1e)`, wobei `DAT_0802bc64` ebenfalls
`0x200000f8` referenziert. `Modbus_Response_Builder` ist trotz des Namens die tatsächliche
FreeRTOS-`xQueueReceive`-Implementierung (Fehlerstrings referenzieren `.../SDK/FreeRTOS/src/
queue.c`, nutzt `vTaskEnterCritical` — weiterer Namensfehler analog zur bekannten
Batch-Naming-Problematik). Die empfangenen Werte werden in `DAT_0802bc6c[0..3]` übernommen, davon
fließt ein Wert (abzüglich eines festen Offsets `*(short*)(DAT_0802bc70+0x83)`) über
`Power_Direction_Change_Check`/`Power_Delta_Detect` direkt in `CT_PowerSetpoint_Compute(local_10,
local_14)` (Zeile 72) ein. **Bestätigt:** Die modem-geparsten Leistungswerte erreichen
ungefiltert (keine Range-/Plausibilitätsprüfung, nur Richtungswechsel-/Delta-Gating)
`CT_PowerSetpoint_Compute` — die offene Frage aus #49 ist damit geklärt.

### 13.17 MQTT Protokoll (#23, #24, #79)

**#23** MQTT v3.1 ("MQIsdp") bestätigt fest verdrahtet, v3.1.1-Zweig ist im Standardfall toter
Code. Credentials im CONNECT-Paket unverschlüsselt (Schutz nur durch TLS). **Bestätigt
kritisch, s. Nachtrag am Ende dieses Abschnitts:** Der Codepfad in `MQTT_Session_Init`, der
`mbedTLS_SSL_Connection_Init` überspringt, ist real und über eine unauthentifizierte BLE-
Provisionierung erreichbar — er aktiviert einen vollständig TLS-freien "Custom-Broker"-Modus,
Credentials und Nutzdaten gehen dabei im Klartext raus.

**#24 Passive Mode:** Cloud-Fernsteuerung (`work_mode=3`), Leistung ±2500 (Einheit
unbestätigt) per JSON-RPC `"Passive"`, **keine Nachrichtenauthentifizierung über TLS hinaus**.
Countdown-Watchdog erzwingt bei Timeout Leistung=0 (Failsafe), verlässt den Passive-Modus aber
nicht automatisch.

**#79** `MQTT_Config_ParseScheduleEntries` ist kein eigenständiger Zeitplan-Mechanismus, sondern
ein zweiter (Text-`key=value`-statt-JSON) Schreibweg in dieselbe 10-Slot-Tabelle
(`0x20014cfe`), die vermutlich auch `TimePlan_Evaluate_Setpoint` (§13.22) liest — Verhältnis
zwischen Cloud-Schedule, lokalem RAM-Array und RS485-Register-Zeitplan (`Inverter_Set_Schedule_Reg`)
nicht abschließend geklärt (evtl. drei parallele Zeitplan-Speicher).

**Nachtrag (Vertiefung, sicherheitskritisch geprüft):** `MQTT_Session_Init` (0x080187fc,
einziger Aufrufer: `CH395_MQTT_Init_And_CertSetup` @0x08024e32, `MQTT_Session_Init(7)`) enthält
zwei Vorkommen derselben Bedingung — identisch an 0x08018840-0x08018852 (Ziel-Host-Auswahl) und
0x080188a8-0x080188ba (TLS-Init-Skip):

```
if ((*(char *)(cfg + 0xe4) == 1) && (strlen(cfg + 1) > 5)) {
    // Zeile 22f: nutzt cfg+0x22 (Server-String) statt Default-Host als CH395-Zielhost
} ...
if ((*(char *)(cfg + 0xe4) != 1) || (strlen(cfg + 1) < 6)) {
    mbedTLS_SSL_Connection_Init();   // Zeile 37f, 0x080188bc -> 0x08018364
}
// -> bei Flag==1 && strlen(Xid)>5 wird mbedTLS_SSL_Connection_Init KOMPLETT übersprungen
```

`cfg` ist ein global gemeinsam genutzter Konfigurationsblock (0xe5 Byte, per
`Flash_Read_Protected(cfg, ..., 0xe5)` aus Flash/EEPROM geladen), dessen Layout über
Log-Format-Strings (`0x08059994`, `0x08059b1c`, `0x08059b7c`) und die BLE-Schreibroutine
verifiziert wurde:

| Offset | Feld | Größe |
|---|---|---|
| 0x00 | ID/Typ-Byte | 1 |
| 0x01 | **Xid** (Geräte-/Topic-Identität, s. `MQTT_Topic_Builder`) | 0x21 |
| 0x22 | **Server/Url** (Custom-Broker-Hostname, wird bei aktivem Flag als CH395-Zielhost genutzt) | 0x40 |
| 0x62 | Port | 2 |
| 0x64 | User (MQTT-Username) | 0x40 |
| 0xa4 | Pwd (MQTT-Passwort) | 0x40 |
| 0xe4 | **Flag** ("Custom-Broker gültig/aktiv") | 1 |

**Schreiber des Flags (`find-cross-references`, 22 Treffer gesamt, davon 8 WRITE):**
- `MQTT_Config_VID_Init` (0x0801f394, 0x0801f3c6) — wird als **allererster Schritt** von
  `MQTT_Session_Init` unconditional aufgerufen (Zeile 21) und **derived** das Flag bei jedem
  Session-Aufbau neu: lädt bei Bedarf den Config-Block per `Flash_Read_Protected` aus Flash nach
  und setzt `cfg[0xe4] = 1`, sobald `strlen(cfg+1)` (Xid) > 5 ist — unabhängig davon, welchen
  Rohwert ein vorheriger Schreiber gesetzt hatte.
- `BLE_Recv_Cmd_Dispatcher`, Kommando **0x50, Subcode 0x0C** ("Write xid info", 0x080097e2ff.):
  parst den kompletten Rohpayload aus dem BLE-Paket per `BLE_WiFiConfig_Parse` im Format
  `<Feld,Feld,...>` direkt in `cfg` (inkl. Xid, Server, Port, User, Pwd, Flag), schreibt
  anschließend via `Flash_Write_Protected(cfg, ..., 0xe6)` **persistent in den Flash** und ruft
  danach implizit (über den nächsten `MQTT_Session_Init`) den TLS-Skip-Pfad hervor, sobald Xid
  ≥6 Zeichen lang ist. Laut Kommentarkopf des Dispatchers ("0x50-0x51: VID/XID provisioning")
  ist dies ein **regulärer, dokumentierter Provisionierungsbefehl ohne Zusatz-Authentifizierung**
  (kein Magic-Byte-Schutz wie bei Kommando 0x0C "Develop Mode", kein Passwort) — jeder Client,
  der eine BLE-Verbindung zum Gerät aufbauen kann, kann Server/User/Pwd/Xid beliebig setzen.
- `BLE_MQTT_Command_Execute` (0x080253ae, Fall `param_1==3`, „Xid err"-Pfad): setzt das Flag
  ebenfalls direkt auf 1, wenn die bereits gespeicherte Xid ≥6 Zeichen hat — aufgerufen aus
  `BLE_Pending_Commands_Process`, also ebenfalls über den BLE-Kommandokanal erreichbar.
- Weitere Schreiber (`MQTT_Session_BLE_Notify`, `CH395_MQTT_Init_And_CertSetup`,
  `MQTT_Connect_And_Subscribe`) setzen/lesen das Flag im normalen Session-Lifecycle, sind aber
  keine unabhängigen externen Trigger.

**Bewertung — Pfad ist real erreichbar, kein Debug-Dead-Code:** Der TLS-Skip ist kein
unbenutztes Leftover, sondern die Kehrseite eines **echten Produkt-Features** ("eigener/
selbstgehosteter MQTT-Broker" via Xid+Server+Port+User+Pwd, provisionierbar per App/BLE-Befehl
0x50/0x0C). Genau in dem Moment, in dem dieses Feature aktiv genutzt wird (Flag==1 durch gültige
Xid), verzichtet die Firmware **vollständig** auf `mbedTLS_SSL_Connection_Init` — es wird kein
TLS-Kontext aufgebaut, `MQTT_Connect_And_Subscribe` läuft direkt über den rohen CH395-TCP-Socket.
Damit gehen MQTT-CONNECT-Credentials (User/Pwd) und der komplette Pub/Sub-Traffic zum
Custom-Broker im Klartext raus — ohne Warnhinweis im Code. Da Server/User/Pwd über denselben
ungeschützten BLE-Befehl frei überschreibbar sind, kann zusätzlich jeder BLE-Client in Reichweite
das Gerät auf einen beliebigen Broker umleiten (Bestätigung/Verschärfung von #45/#54 zu
ungeschützten BLE-Schreibpfaden, §13.23). **Sicherheitsbewertung aktualisiert:** vormals "dringende
offene Frage" → jetzt **bestätigtes, real erreichbares Risiko** (kein reines Debug-Flag).

### 13.18 CRC16-Implementierungen & Register-System (#26, #50)

Alle drei CRC16-Varianten sind **byte-identisch** (Poly 0xA001, reflektiert) — Redundanz ist
rein API-bedingt (Pointer- vs. Wert-Init), kein funktionaler Unterschied. `CRC16_Modbus_Incremental`
hat **0 Caller** (toter Code). Trotz des Namens läuft **keine** der drei über den
Modbus-RTU/TCP-Dispatcher — Nutzung ausschließlich in OTA/Config-Persistenz; Modbus selbst nutzt
eine andere, separate CRC16-Routine (`CRC16_Calculate`, Dual-Lookup-Tabelle).

`Register_PackDescriptor` (8/4/4/5-Bit category/subindex/field/flags) ist als bidirektionaler
Adress-Layer verifiziert: TX über `Register_WriteValue`→Queue (Consumer nicht lokalisiert,
vermutlich CAN-TX-Task), RX über `CAN_FrameDispatcher`→`Modbus_ResponseDispatch`, das exakt
dasselbe Bitschema aus CAN-Antwortframes entpackt und in Modbus-lesbare Slot-Tabellen ablegt —
verbindet damit intern CAN-Kommunikation mit extern lesbaren Modbus-Registern. 5 Bit (19:16) im
Deskriptor werden von keinem bekannten Decoder ausgewertet (offen).

**Nachtrag (Vertiefung):** Consumer der `Register_WriteValue`-Queue lokalisiert.
`Register_WriteValue` (`0x08026598`) ruft `Modem_QueueSendMessage` (`0x08027394`) auf, das per
`xQueueSend` in ein Queue-Handle schreibt, das aus einer gemeinsamen RAM-Struktur bei `0x200000e8`
gelesen wird (Feld `+4` = `0x200000ec`; der Zeigerwert `0x200000e8` liegt als Flash-Literal
mehrfach dupliziert vor: `0x080273b0`, `0x0801d028`, `0x0802c08c`). Dieselbe Queue wird zusätzlich
von `WiFi_HardwareResetSequence` (`0x0801cf1c`, Case 0) befüllt — es ist also keine exklusive
Register-Queue, sondern eine geteilte Ausgabe-Queue. Konsument (Reader) ist `Modbus_SendResponse`
(`0x0802c060`, **0 Aufrufer und keine Datenreferenz** — analog zu `App_MainLoopDispatcher` in
§13.24 vermutlich per `xTaskCreate`-Funktionszeiger registriert, also die gesuchte CAN-TX-Task):
sie ruft mit 1000 Ticks Timeout aus der Queue ab und sendet bei Erfolg über `CAN_SendMessage` +
`vTaskDelay(1)`. **Namenskorrektur nötig:** Die dabei intern aufgerufene Funktion
`Modbus_Response_Builder` (`0x080541f8`) ist trotz ihres Namens **kein Modbus-spezifischer Code**,
sondern die generische FreeRTOS-Queue-Implementierung (`xQueueReceive`/`xQueueGenericReceive` —
verifiziert über eingebettete Fehlerstrings `.../SDK/FreeRTOS/src/queue.c` sowie interne
Funktionsnamen `prvCopyDataFromQueue`/`prvUnlockQueue`); sie wird von 9 unterschiedlichen Callern
für unterschiedliche Queues genutzt (u. a. `CAN_RxQueue_DrainAndDispatch`,
`Quectel_SendCmd_WaitResponse`, `Write_Handler`, `RS485_RTU_Frame_Dispatcher`) und sollte
umbenannt werden (z. B. `FreeRTOS_xQueueReceive`), um Fehlinterpretationen zu vermeiden — Fall
für den Dubletten-Check nach Batch-Naming.

### 13.19 Cloud Report Pipeline & Connection Watchdog (#27, #34)

**Korrektur:** Die 8 (+1) `Cloud_Report_Fill*`-Funktionen sind **keine periodische
Cloud-Telemetrie**, sondern befüllen die Antwort eines **unverschlüsselten lokalen
JSON-RPC-über-UDP-Query/Response-Mechanismus** (`MQTT_JSON_RPC_Dispatcher`, ereignisgesteuert bei
eingehendem UDP-Paket, kein Timer). Header (34 Byte, nicht "0x22B") = Echo der JSON-RPC-Request-ID.
Getrennt von der bereits dokumentierten AES-128-ECB-Cloud-Telemetrie-Pipeline
(`AES_Crypto_Stack_Analyse.md`) — keine Überschneidung, RPC-Antworten sind reines Klartext-JSON.
Offengelegte Daten ohne erkennbare Authentifizierung: Seriennummer, MAC, 4 IP-Adressen,
Zeitzone, Echtzeit-Batterie-/PV-/Netzdaten — starkes Geräte-/Standort-Fingerprint für jeden
Client im selben Netzsegment.

`Cloud_EdgeDetectAndWatchdog`: 12000-Tick-Watchdog (~2 Min) ohne Backoff/Obergrenze, löst bei
Verbindungsproblem `Cloud_Response_Action` aus (State-Flags zurücksetzen + Leistungssollwert
per Failsafe auf 0) — kein harter CH395-Chip-Reset.

### 13.20 Debug/Logging-Infrastruktur & cJSON-Namensfehler (#29, #35, #87)

**#29 Korrektur:** Die dokumentierten Adressen waren falsch zugeordnet. Tatsächlich existieren
**13 dedizierte Debug-Print-Funktionen** (Batterie, MPPT, Inverter, CAN-PGN inkl.
Lock-/Factory-Test-Flag, SSL-Zertifikatsinfo, Event-/Error-Log-Dump, WiFi, Modbus-Adresse), **alle
mit 0 Callern** — kompilierter, aber unverdrahteter Diagnose-Code, kein aktives
Information-Disclosure-Risiko in FW 149.2.

**#87 widerlegt:** `Task_AppendStatusToJSON` sammelt reale FreeRTOS-Stack-Watermarks, landet
aber nachweislich **nicht** in Cloud-Reports — nur in einer lokalen `printf`-Debug-Ausgabe, die
selbst unerreichbar ist (ihr einziger Aufrufer-Block ist referenzlos).

**#35 bestätigt erledigt:** cJSON-Namenskorrektur (`cJSON_InitHooks` vs. `cJSON_NewObject`)
bereits in Ghidra korrekt gesetzt, keine Handlungsnotwendigkeit mehr.

### 13.21 Relay Staged Timing & CT Power Control Loop (#30, #32)

**#30** GPIO Bit15 = **PE15** (GPIOE, STM32F1-Standardregister BSRR/BRR/ODR verifiziert),
direkte Contactor-Ansteuerung. 3-Stufen-Sequenz (310/610/1010 Ticks) entspricht klassischer
Precharge→Hauptrelais-zu→Bestätigungs-/Debounce-Sequenz; Schließen ist an ein externes
Bereitschafts-Flag gebunden (kein reines Zeit-Only-Schließen). Auffällig: Stufe 3 nutzt ein
**XOR-Toggle** statt Set/Clear auf dem ODR-Register — bei Zustands-Desync (z. B. Reset
mittendrin) potenziell abweichender physischer Pinzustand vom angenommenen Softwarezustand.

**#32** Regelkette bestätigt: CT-Messung → WorkMode/Remote-Verarbeitung →
`Voltage_Stability_Check` (Debounce gegen Netzschwankungen) → `Power_Direction_Change_Check` →
`Power_Delta_Detect` → `CT_PowerSetpoint_Compute` (P-Regler mit konfigurierbarem 30–100%-Gain,
4-fach-Clamp, Dead-Band **exakt 11 W bzw. 15 W** je nach Kanal-/Modusselektor bestätigt). Bei
Netzproblemen fährt der Regler defensiv auf 0 W.

### 13.22 Event-Log-System & Zeitplan-Engine (#31, #37, #91, #92)

**#31 Korrektur:** Dedup-Fenster ist **31 Minuten**, nicht 31 Sekunden (Rechnung im Code nutzt
Stunden×60+Minuten-Differenz). Beide Logs (DisplayError 14B/EEPROM 0x1100, SystemEvent
9B/EEPROM 0x2000, je 20 Slots) sind aus Sicht des Control-FW **write-only** — keine
Auslese-Funktion in dieser Firmware gefunden (vermutlich Debug-Backdoor oder andere MCU).

**#37** 10-Slot-Zeitplan (`TimePlan_Evaluate_Setpoint`) bestätigt: Wochentag-Bitmask + gepackte
HH:MM-Start/End-Zeit + Power-Setpoint (Sonderwert -1 = Standby/Grid-Follow). Priorität = Slot-
Index (niedrigster Index gewinnt, keine explizite Prioritätslogik). Trigger alle 300 Ticks oder
bei Flag. Schreiber des RAM-Arrays (`0x20014cfe`) nicht lokalisiert — Verhältnis zu
`MQTT_Config_ParseScheduleEntries` (§13.17) offen.

**#91/#92** `RTC_TimeToFiveMinSlot`: `(Stunde*60+Minute)/5`. RTC wird über **drei** Kanäle
gestellt: HTTP (mit `DateTime_Validate`), MQTT (**ohne erkennbare Validierung** — auffälligster
Einzelbefund), BLE. Zeitplan-Engine läuft unabhängig von Cloud-Erreichbarkeit mit der zuletzt
gesetzten/ggf. driftenden RTC-Zeit weiter, kein "Zeit ungültig"-Sperrzustand.

**Nachtrag (Vertiefung):** Zeitplan-Speicher-Verhältnis (§13.17 #79) geklärt — es sind **keine
drei unabhängigen Speicher**, sondern zwei funktional getrennte Systeme. Da `0x20014cfe` selbst
nie als statische Adresse referenziert wird (nur über pro-Funktion duplizierte Flash-Literale mit
demselben Wert erreichbar), wurden die Schreiber über die Literal-Werte statt direkter
Cross-Referenz auf die Adresse verifiziert:

1) Das lokale 10-Slot-RAM-Array `0x20014cfe` ist ein **einziger geteilter Speicher** mit
   mindestens vier Schreibern:
   - `MQTT_Config_ParseScheduleEntries` (`0x08049674`, §13.17 #79): parst Text-`key=value` in
     einen Staging-Puffer (`0x20019091`) und kopiert per `memcpy` (Aufruf bei `0x08049806`) alle
     100 Byte nach `0x20014cfe`.
   - `MQTT_JSON_RPC_Dispatcher` (`0x0801a5a4`, "Manual"-Zweig, ca. Zeilen 383–396): schreibt
     direkt slotweise in dieselbe Tabelle (Basiswert `0x20014cfe`, als 4-Byte-Literal bei
     `0x0801b344` per Rohspeicher-Lesung verifiziert — von Ghidras Auto-Analyse dort fälschlich
     als 1-Byte-Skalar typisiert).
   - `Write_Handler` (`0x08050f20`, Register-Bereich `0xa85c`–`0xa85e`, von Modbus-TCP **und**
     RS485-RTU FC06/FC10 gemeinsam genutzt): schreibt direkt in dieselbe Tabelle (Basisliteral bei
     `0x08051bc4` = `0x20014cfe`).
   - `BLE_Recv_Cmd_Dispatcher` (`0x08007f58`): schreibt in dieselbe Tabelle über ein Basisliteral
     `0x20014cfc` (= Tabelle − 2 Byte, vermutlich 2-Byte-Header/Count vor dem 10-Slot-Array).

   Gelesen wird die Tabelle von `TimePlan_Evaluate_Setpoint` (`0x0802d018`, Basisliteral
   `0x0802d0e4` = `0x20014cfe`, damit #37 bestätigt) sowie von `BLE_Build_Settings_Response`
   (`0x0800ae5c`, Basisliteral `0x0800af0c` = `0x20014cfe`) zur Rückmeldung des aktuellen
   Zeitplans an die App.

2) `Inverter_Set_Schedule_Reg` (`0x08005d74`) wird von `Write_Handler` aus einem **anderen**
   Register-Bereich (`0x30`–`0x3e`, nicht `0xa85c`+) aufgerufen und ist tatsächlich ein
   **eigenständiger, unabhängiger dritter Pfad**: Er schreibt **nicht** in `0x20014cfe`, sondern
   persistiert in EEPROM (Offset `0x36bf + n*8`) und leitet den Wert per
   `Register_PackDescriptor`+`Register_WriteValue` an dieselbe CAN-TX-Queue weiter, die in
   §13.18 (Nachtrag) beschrieben ist — ein Spiegel-/Sync-Schreibvorgang zu externen
   (inverterseitigen) Registern, unabhängig von der lokalen RAM-Zeitplan-Engine.

   Ergebnis: **zwei** funktional getrennte Zeitplan-Mechanismen — ein geteiltes lokales
   RAM-Array mit vier Schreibern/zwei Lesern (MQTT-Text, MQTT-JSON-RPC, Modbus/RS485-Register,
   BLE), plus ein unabhängiger CAN-Register-Spiegelpfad zum Inverter — nicht drei parallele
   Speicher wie in §13.17 #79 vermutet.

### 13.23 Netzwerk-Transport-Dispatch & CH395-Server/Reset (#33, #36, #45, #54, #74, #81)

**#33** Transport 1 (bisher "unbekannt") identifiziert: natives Quectel-Modem-MQTT via
`AT+QMTPUB` (Modem-interner Stack, parallel zum geräteeigenen Software-MQTT/TLS in Transport 3).

**#36** `CH395_Reset_And_Reinit` über BLE (Cmd 0x0C, Case 6, nur durch öffentlichen 3-Byte-Magic-
Präfix "geschützt") hat **kein Rate-Limiting** — plausibler DoS-Vektor gegen die gesamte
Netzwerk-Konnektivität (Ethernet + davon abhängige Modbus/TCP/Broadcast-Dienste).

**#45/#54 bestätigt kritisch:** Port 8090 (UDP-Broadcast, `255.255.255.255`) ist praktisch ein
**Cloud-Kommando-Interface ohne Cloud** — jedes Gerät im LAN kann per Broadcast denselben vollen
`MQTT_JSON_RPC_Dispatcher`-Methodensatz auslösen (WiFi-Config, Setpoints, Factory-Reset), einzige
"Prüfung" ist ein IP≠0-Check. Port 8091 (TCP) läuft über echten `CH395_TCPListen`, Laufzeit-Handler
nicht lokalisiert.

**#74** Widerspruch zur bisherigen Doku: Modbus-Port 502 nutzt denselben Mode=2/`TCPListen`-Pfad
wie der TCP-Server (Port 8091) — spricht für **TCP statt UDP**, Confidence auf "medium"
abgesenkt, Datenblatt-Abgleich als TODO. Überraschender Fund: Die RS485-Modbus-Register-Map wird
beim CH395-Reset **über denselben CH395-SPI-Bus** initialisiert (`RS485_Modbus_MapRead/WriteRegister`),
ohne eigenen Mutex — nur sicher, weil der einzige Aufrufer den globalen CH395-Lock bereits hält.

**#81** `CH395_SPI_SendCmd`, 26 Aufrufer: 24 klassische CH395-Treiberfunktionen + die beiden
RS485-Modbus-Register-Map-Funktionen aus #74.

**Gesamtbild:** Lokale Netzwerk-Angriffsfläche erheblich größer als "ein Modbus-Port" — Port
8090 allein reicht für vollständige Fernkonfiguration ohne Cloud und ohne Auth.

**Nachtrag (Vertiefung):** Beide offenen Punkte aus #45/#54/#74 geklärt.

*Port-8091-Laufzeit-Handler gefunden:* `Network_ReceiveAndDispatchData` (`0x0804d4e8`, 0 auffindbare
Aufrufer — vermutlich eigener FreeRTOS-Task). Wartet per `xQueueReceive` auf ein Queue-Signal,
liest dann explizit über Socket-Deskriptor **1** (`CH395_GetRecvLen()`/`CH395_ReadRecvBuf(1,...)`
— exakt der Deskriptor, den `CH395_Init_TCPServer_Socket` für Port 8091 vergibt) bis zu 256 Byte
und reicht jedes Byte einzeln an `BLE_GATT_DispatchCommandByte` weiter — **denselben
Byte-State-Machine-Handler wie der BLE-GATT-Kommandokanal**. Port 8091 ist damit funktional ein
TCP-Tunnel in den BLE-GATT-Kommandodispatcher, ohne im Code erkennbare zusätzliche
Authentifizierung. Zum Vergleich: der separate `Modbus_Dispatcher` (`0x0801e43c`) bedient
sauber getrennt Socket-Deskriptor **0** (`CH395_GetRecvLen(0)`/`CH395_ReadRecvBuf(0,...)`) —
beide Handler laufen unabhängig über denselben CH395-TCP-Treiber.

*Modbus-Port-502-Transport bestätigt (TCP, Confidence jetzt hoch):* `CH395_Init_Modbus_TCP_Socket`
(`0x08048754`, einziger Aufrufer `CH395_Reset_And_Reinit`) setzt Quell- **und** Zielport auf
`0x1f6` = **502 (dez.)**, Modus-Byte = **2**, Socket-Deskriptor **0**. `CH395_Init_TCPServer_Socket`
(`0x08032c0c`) setzt analog Port `0x1f9b` = **8091 (dez.)**, ebenfalls Modus 2, Socket-Deskriptor
1. In `CH395_Socket_Open_ByDescriptor` mündet der Modus-2-Zweig in beiden Fällen direkt in einen
Aufruf von `CH395_TCPListen()` — einer Operation, die im CH395-Treiber nur für TCP-Sockets
existiert (kein UDP-Äquivalent). Damit ist Modbus-Port-502 **mit hoher Konfidenz als TCP**
bestätigt (nicht UDP); der in #74 offene Datenblatt-Abgleich ist durch diesen Code-Beleg ersetzt.

### 13.24 Shutdown/Watchdog/MainLoop/FreeRTOS-Kern (#38, #40, #47, #55, #80, #82, #83, #86, #94)

**Adresskonflikt #86/#94 aufgelöst:** `0x08053ba4` ist `FreeRTOS_StartScheduler` (Standard-
Portable-Layer), **nicht** der SysTick-Handler. Der reale SysTick-ISR ist eine andere,
bisher nicht dokumentierte Funktion (`Periodic_Tick_Handler`, `0x0802d9ca`), die zusätzlich zum
FreeRTOS-Tick auch einen app-eigenen Energiezähler inkrementiert — #94 im Tracking-Dokument auf
diese Adresse korrigieren.

**#55** `App_MainLoopDispatcher` (0 auffindbare Aufrufer — vermutlich `xTaskCreate`-Tabelle):
tatsächliche Reihenfolge ist **Shutdown → OTA-Update-Dispatcher → CAN-Update → Periodic-Tasks →
Cloud-Watchdog** (OTA-Schritt fehlte in der ursprünglichen Kurzbeschreibung).

**#47 Korrektur:** `Comm_Watchdog_CheckTimeout` löst **keinen** Reboot/Shutdown aus — nur
`OTA_Set_SlotStatus(..., failed)` + internen Retry-Zähler-Reset. Ist ein OTA-Download-
spezifischer Timeout, kein allgemeiner Systemwächter.

**#40 Korrektur:** `Shutdown_Sequence_Handler` suspendiert keine 7 Tasks, sondern stoppt 7
Software-**Timer**. Es gibt **vier** verschiedene, sich teils überlappende Timer-Stop-Stellen
(`Shutdown_Sequence_Handler`, `OTA_PrepareShutdown`, `System_StopAllTimers` für BLE-Reboot,
weitere) — funktional redundant, aber nicht fehlerhaft, da am Ende immer ein NVIC-System-Reset
steht.

**#38 Idle-Watchdog:** Reboot nach 3600 Ticks ohne PV-Ertrag UND ohne Lade-/Entlade-Aktivität —
kann durch **legitimen nächtlichen Standby ausgelöst werden** (kein reiner Hänger-Detektor).
Praktisch relevantester Befund: Gerät könnte nachts wiederkehrend neu starten.

### 13.25 Heap/Memory-Allokator (#48, #76, #77)

**Korrektur:** Es sind **zwei unabhängige Heaps**, keine Variante desselben Systems — Heap A
(`malloc`, 1.276 B Pool, nur für `calloc`/`realloc`) und Heap B (FreeRTOS-Standard-`heap_4`,
71.680 B bestätigt, für praktisch alles inkl. des kompletten TLS/X.509/RSA/ECC-Stacks über
`mbedTLS_Calloc`). OOM-Verhalten sauber (NULL-Return, von Callern geprüft).

**#77 Heap Canaries bestätigt fehlend:** Weder `heap_Free_Coalesce` noch `Heap_InsertFreeBlock`
prüfen Magic-Bytes/Guard-Werte vor dem Verketten — jeder Header-Wert wird ungeprüft vertraut.
`pvPortFree` hat nur eine Double-Free-Plausibilitätsprüfung (kein unabhängiger Canary), bei
Verletzung nur ein Log, kein Halt. Zusatzfund: `calloc`/`Heap_Calloc` multiplizieren
Größenparameter ohne Overflow-Check (CWE-190). Netzwerkgesteuerte Allokationsgrößen laufen über
den mbedTLS/TLS-Zertifikatspfad (5 identifizierte Funktionen) — reale Ausnutzbarkeit hängt von
einem noch nicht nachgewiesenen Overflow-Bug in einem Parser ab (kein direkt ausnutzbarer Fund,
strukturelles Risiko).

### 13.26 Custom-Crypto & mbedTLS-Kernprimitive (#51, #53, #58–62, #66, #67, #75)

Alle geprüften Constant-Time-Eigenschaften (#58 MemCompare, #59 RSA-PKCS1v15-Unpad/Bleichenbacher-
Schutz, #62 GCM-Zeroize-vor-Return, #67/#75 MPI-Vergleiche) **bestätigt korrekt**, keine
Abweichung von der mbedTLS-2.28-Referenz. #60: nur SECP256R1 aktiviert (Build-Entscheidung,
keine Schwäche an sich). #61 `mbedTLS_ECP_Check_PubPriv`: 0 Caller, toter Code. #66 bereits in
Batch 18 korrigiert, kein offener Punkt mehr.

**#53 Korrektur:** `GCM_Setup_Hash_Subkey`/`GCM_GHASH_Multiply` sind **keine** unabhängige
AES-GCM-Implementierung, sondern interne mbedTLS-`gcm.c`-Helfer (`gcm_gen_table`/`gcm_mult`) ohne
`mbedTLS_`-Präfix — die vermutete BLE-Nutzung ist durch den Call-Graph nicht belegt.

**#51** Software-AES bestätigt (S-Box/T-Table-Generierung, keine STM32-CRYP-Zugriffe) —
Performance-Nachteil, aber auf Cortex-M ohne D-Cache praktisch kein Cache-Timing-Risiko
(Einschätzung).

### 13.27 mbedTLS PKI/Zertifikate inkl. Private-Key-Frage (#63, #64, #65, #71, #72, #78, #85)

**🔑 Private-Key-Befund — Nachtrag 2026-07-10, ERFOLGREICH EXTRAHIERT:** Die vorherige Einschätzung
(Key läge in einem externen, memory-gemappten QSPI-Bereich und sei nicht statisch extrahierbar) ist
überholt. Ein roher Byte-Scan des Flash-Images (statt Decompiler-Pointer-Verfolgung) fand einen
ROT-obfuskierten AES-128-Schlüsselkandidaten statisch im Flash. Damit wurden AWS-IoT-Root-CA,
Device-Zertifikat und **Private Key** erfolgreich aus dem Flash-Dump extrahiert und kryptografisch
verifiziert (`openssl rsa -check` bestanden, Modulus-Abgleich mit Device-Zertifikat exakt
identisch). Der Private Key liegt also sehr wohl **statisch im Flash-Image** (verschlüsselt per
AES-128, nicht in einem externen QSPI-Bereich) — die "unbewiesene Hypothese" ist damit
widerlegt/geklärt. Verwendungszweck weiterhin bestätigt: mTLS-Client-Authentifizierung für die
MQTT-Verbindung (faktisch AWS IoT Core), `VERIFY_REQUIRED` gesetzt.

> **Sicherheitsrelevanter Befund — bewusst nicht öffentlich dokumentiert.** Der Schlüssel, die
> vollständige Extraktions-Methodik und die extrahierten Credentials selbst sind **nicht Teil dieses
> öffentlichen Repos**. Es handelt sich um ein produktlinienübergreifend geteiltes, hartcodiertes
> AWS-IoT-Client-Zertifikat samt Private Key — bereits vertraulich per Responsible Disclosure an den
> Hersteller gemeldet, Details werden bis zur Behebung zurückgehalten. Interne, nicht-öffentliche
> Dokumentation dazu liegt lokal im `security/`-Ordner (nicht Teil dieses Repos).

**#63** Encrypted-PEM-Support bestätigt fehlend. **#65** nur RSA/ECKEY/ECKEY_DH. **#71** RSA-
PKCS1v15-Verify: **0 Caller, kompletter Dead Code** — stützt die bereits bekannte
Signatur-lose OTA (§13.10/§13.11). **#72** Sign-with-Blinding + Verify-after-Sign bestätigt
(Fault-Attack-Schutz korrekt). **#78** Max. 2048-bit RSA bestätigt (harte Ablehnung größerer
Keys). **#85/#90** sind **dieselbe Funktion** (Adress-Duplikat im Tracking-Dokument, Ghidra-Name
weiterhin `FUN_080528c8` trotz dokumentierter Umbenennung) — vollständige X.509-Pipeline
bestätigt aktiv im TLS-Handshake genutzt.

### 13.28 mbedTLS TLS/SSL-Handshake & Config (#68, #69, #70, #73, #84)

**#68** AEAD-only bestätigt — kein CBC-Codepfad vorhanden, folglich keine Padding-Oracle-Fläche.
**#69** TLS 1.2 hart erzwungen (min=max=Version 3.3) bestätigt. **#73** 16-State-Handshake
entspricht 1:1 Standard-mbedTLS-Client, keine übersprungene Zertifikatsprüfung; Namensfehler
gefunden: `mbedTLS_SSL_Parse_ServerKex` (0x0804f284) ist tatsächlich die
ClientHello-**Schreib**funktion. **#84** HMAC-SHA256-PRF bestätigt, kein MD5/SHA1-Fallback.

**#70 ⚠️ bestätigt kritisch:** `mbedTLS_SSL_Conf_CA_Chain` wird mit **festverdrahtetem Literal
`NULL`** als CRL-Parameter aufgerufen — einziger Aufrufer im gesamten Programm, kein
OCSP-Ersatz. Zertifikatswiderruf wird strukturell nie geprüft. In Kombination mit sonst starker
TLS-Konfiguration (1.2-only, AEAD-only, Client-mTLS, Hostname-Check) bleibt die fehlende
Widerrufsprüfung der einzige belastbare Schwachpunkt — relevant, sobald ein Server-Zertifikat
je rotiert/widerrufen werden muss.

### 13.29 MPPT/GPIO-Datenstrukturen (#57, #88)

**#57** Vollständiges MPPT-Struct-Layout bei RAM `0x20014F40` (56 Byte) aus Debug-Format-Strings
rekonstruiert: Mppt_State/Error/Temp/Warning, PV1–4 je V(0.1V)/I(0.1A)/P(0.1W), Tages-/Monats-/
Jahreskapazität (10 Wh), Batterie-/Grund-/PE-Spannung — HA-tauglich dokumentiert. Schreiber der
Struktur nicht abschließend lokalisiert; wahrscheinlichster Kandidat ein UART-AT-Kommando-Pfad
zur MPPT-Sub-MCU (nicht CAN, wie ursprünglich vermutet).

**#88** Namen `GPIO_Pin_Clear`/`GPIO_Pin_Set` in Ghidra **nicht angewendet** (weiterhin
`Generic_StructField_Set_0x14`/`FUN_08012d90`) — Inhalt (STM32F1 BSRR/BRR) bestätigt. Größte
Nutzergruppe (~25 Aufrufer): CH395-SPI-Chip-Select. Weitere Kategorien: I2C-Bit-Bang SDA/SCL,
Hauptrelais GPIOE15, BLE/WiFi-Modul-Reset, I2C-Bus-Recovery — inkl. eines direkten GPIO-Zugriffs
über Modbus-Register 45023–45029 (Diagnose-/Factory-Test-Schnittstelle laut Write_Handler-
Kommentar).

**Nachtrag (Vertiefung):** Schreiber der MPPT-Struktur (`0x20014F40`) lokalisiert — Pfad ist
**CAN**, nicht UART-AT wie zuletzt vermutet (ursprüngliche CAN-Hypothese damit wieder bestätigt).
Kette: `CAN_RxQueue_DrainAndDispatch` (`0x080292d4`, vermutlich eigener FreeRTOS-Task) liest
CAN-Frames aus der Empfangs-Queue → `CAN_FrameDispatcher` (`0x0802e698`) verzweigt anhand von
Bitfeldern der CAN-ID u. a. nach `Telemetry_Register_Dispatcher` (Klasse 4),
`Modbus_ResponseDispatch` (Klasse 2) und `Protocol_AA_CommandDispatch` (0xAA-Protokoll, §13.13).
Für Klasse 2 verzweigt `Modbus_ResponseDispatch` (`0x0802ea54`) anhand eines im CAN-Statuswort
eingebetteten Kommando-Bytes weiter; bei Wert 3 ruft sie `Modbus_StoreRegisterSlot` (`0x0802e94c`)
auf, die einen 3-Bit-Slot-Index (Wertebereich 1–7) aus dem Statuswort extrahiert und damit einen
8-Byte-Slot ab Basis `0x20014F40` (per `get-data` verifiziert) beschreibt — **7 Slots × 8 Byte =
exakt die 56 Byte Strukturgröße aus #57**, was das Layout zusätzlich bestätigt. Bemerkung: Die
Funktionsnamen `Modbus_ResponseDispatch`/`Modbus_StoreRegisterSlot` sind vermutlich ein
Namensartefakt aus einem früheren Batch — der reale Code verarbeitet CAN-Payloads, kein
Modbus-PDU-Format (Kandidat für Korrektur in Function_Tracking.md, s. auch §13.18 zum
verwandten `Register_PackDescriptor`-Bitschema). Kein UART-Empfangspfad mit Schreibzugriff auf
`0x20014F40` gefunden — die AT-Kommando-Hypothese gilt damit als widerlegt.

### 13.30 Re-Audit Modbus/RS485 + Inverter/Register/Energie-Cluster (2026-07-14)

**Kontext:** Gezielter Re-Audit der beiden für die HA-Integration wichtigsten Themencluster in
`Control_FW_Function_Tracking_new.md` (Modbus/RS485: 33 Funktionen, Inverter/Register/Energie:
89 Funktionen) gegen frische Ghidra-Dekompilierung (inkl. Caller/Callee-Kontext), analog zum
Batch-18-Re-Audit des mbedTLS-Clusters. Insgesamt 85 Funktionen geprüft (33/33 Modbus + 52/89
Inverter/Register, priorisiert nach fehlender Beschreibung, medium/low Confidence und zentralen
Dispatchern). Fehlerquote deutlich niedriger als im mbedTLS-Cluster (Batch 18: 62 Fehlbenennungen):
Modbus-Cluster 2 von 33 fragwürdige Namen (94% korrekt), Inverter/Register-Cluster 1 von 52
fragwürdiger Name (98% korrekt). Alle Detail-Ergebnisse (Umbenennungsvorschläge, ergänzte
Beschreibungen) direkt in den jeweiligen Tabellenzeilen von `Control_FW_Function_Tracking_new.md`
gepflegt (Quelle-Spalte "Doku (Re-Audit 2026-07-14)").

**Bestätigung einer bestehenden Beobachtung:** Der in §13.29 als Namensartefakt vermutete Befund
zu `Modbus_ResponseDispatch`/`Modbus_StoreRegisterSlot` (CAN-Payload statt Modbus-PDU) wurde beim
Re-Audit unabhängig reproduziert und um weitere Funktionen derselben Familie ergänzt:
`Modbus_StoreWithHandshake` (0xCB), `Modbus_StoreDualSlot` (0xCE), `Modbus_StoreValue16` (0xFE),
`Modbus_StorePairSlot` (0xFF) hängen alle am selben `Modbus_ResponseDispatch`-Einstiegspunkt, der
ausschließlich von `CAN_FrameDispatcher` (Klasse 2, CAN-ID-Muster
`(id&0xffff)>>0xc==0 && (id&0xffffff)>>0x14==2`) erreicht wird — kein Aufruf aus dem RS485- oder
TCP-Modbus-Pfad. Diese fünf Funktionen bilden damit ein eigenständiges **"CAN-getunneltes
Pseudo-Modbus-Protokoll"** für Parallelbetrieb/Multi-Pack-Kommunikation, das mit dem eigentlichen
RS485/TCP-Modbus-Server (Abschnitt 2 oben) nichts zu tun hat außer der (mutmaßlich historisch
bedingten) Namensgebung.

**Neuer Fund — `Modbus_SendResponse` (`0x0802c060`) sendet über CAN, nicht über USART:** Die
Dekompilierung zeigt einen Aufrufpfad über `CAN_SendMessage`/`CAN_SetupTxMailbox`, keinen
USART-Zugriff. Aktuell 0 Caller in Ghidra auffindbar (evtl. Function-Pointer-Ziel oder toter Code).
Passt thematisch zur obigen CAN-Pseudo-Modbus-Familie — möglicherweise die Response-Gegenstück-
Funktion dazu, aber nicht abschließend an einen Caller gebunden.

**Neuer Fund — `Modbus_Response_Builder` (`0x080541f8`) ist keine Modbus-Funktion:** Dekompilierung
zeigt eine generische, blockierende FreeRTOS-Queue-Receive-Implementierung (Timeout via
`vTaskPlaceOnEventList`/`xTaskCheckForTimeOut`, funktional analog `xQueueReceive`), die branchenweit
genutzt wird: `RS485_RTU_Frame_Dispatcher` (UART-Byte-Empfang), `CAN_RxQueue_DrainAndDispatch`,
`Quectel_SendCmd_WaitResponse` (Modem-AT-Kommandos), `Write_Handler`, `CT_GridPower_Controller`,
`Network_ReceiveAndDispatchData`, `WorkMode_Modbus_ResponseCache_Refresh`. Baut an keiner Stelle
einen Modbus-Frame. Name ist eine Fehlinterpretation aus einem früheren Batch — Umbenennung
vorgeschlagen (z. B. `Queue_Receive_WithTimeout`), aber noch nicht angewendet (s. Konvention:
Umbenennungen zentral gegen Dubletten prüfen).

**Gemeinsame BatteryParams-Struct (SRAM `0x20014F82`):** Zahlreiche Funktionen im
Inverter/Register-Cluster (`Power_Limit_Clamp`, `Inverter_Power_Setpoint_ScaleFactor_Calc`,
`Inverter_PowerSetpoint_DeadbandClamp`, `WorkMode_State_Machine`, `Telemetry_Timestamp_Get`,
`Grid_Power_Dynamic_Adjust`, sowie Cloud-/BLE-/MQTT-Builder) greifen laut
`find-cross-references` (38 Referenzstellen) alle auf denselben globalen Struct-Basiszeiger
`0x20014F82` zu. Die zahlreichen `DAT_*`-Literal-Pool-Adressen im Code (`DAT_08012fe0`,
`DAT_0801304c`, `DAT_08013df4`, `DAT_0802f2ec` u. a.) sind sämtlich Zeiger auf dieselbe Struktur.
Lohnendes Ziel für eine künftige Struct-Retype-Aktion in Ghidra (Feldoffsets u. a. bei `0x0`,
`+0xC`, `+0x12`, `+0x18`, `+0x1E`, `+0x24`, `+0x28`, `+0xF` bereits aus mehreren Funktionen
rekonstruierbar).

**Namensverdacht — `Telemetry_Timestamp_Get` (`0x0802f2b4`) — gelöst, s. §13.46:** Kein RTC-/Zeit-Zugriff im
Code. Liest aus der o. g. BatteryParams-Struct ein Disable-Flag (Offset `+0xF`) und einen skalierten
Wert (Offset `+2`, geteilt durch 10) und liefert einen Statuscode 0–3 zurück (0 = disabled). Wird u. a.
in `Cloud_Report_FillPowerFlow` direkt neben einem SOC-Byte abgelegt — spricht für einen
Lade-/Kapazitätsklassen-Code statt eines Zeitstempels. **Update 2026-07-15:** umbenannt zu
`BatteryParams_PowerFlowState_Get` (Confidence `medium`, exakte physikalische Einheit von Offset+2 nicht
abschließend bewiesen — Details s. §13.46).

**Bestätigung TCP/RS485-Symmetrie:** Der bereits in Abschnitt 2.1 dokumentierte 1:1-Spiegel
zwischen TCP- und RS485-Pfad wurde beim Re-Audit bestätigt; einzige funktionale Divergenz ist das
Broadcast-Verhalten (RS485-Broadcast an Adresse 0x00 sendet bewusst keine Antwort, TCP kennt kein
Broadcast-Konzept und antwortet immer) — bereits korrekt in Abschnitt 2.1 dokumentiert.

Übrige 82 geprüfte Funktionen beider Cluster (inkl. aller zentralen Dispatcher wie
`Register_WriteValue`, `Register_PackDescriptor`, `CT_GridPower_Controller`,
`WorkMode_ChangeHandler`, `RS485_Modbus_RegisterMap_Init`) wurden verifiziert und sind korrekt
benannt und beschrieben — keine weiteren Korrekturen nötig.

### 13.31 Re-Audit CAN / BLE / Config-EEPROM / OTA-Flash (2026-07-14)

Vier Themencluster der Control-FW-Tracking-Tabelle, die seit der unkontrollierten Erstvergabe
(Batch 1-17) nie einzeln gegen frische Dekompilierung geprüft worden waren, wurden per
Sub-Audit (4 parallele Agenten, 133 von 194 Funktionen geprüft) re-verifiziert. Details/Tabellen
siehe `Control_FW_Function_Tracking_new.md`, Abschnitte "CAN-Bus", "BLE / GATT",
"Config / EEPROM", "OTA / Flash". Wichtigste inhaltliche Funde:

**CAN-Bus — CAN1-Peripherie bestätigt, aber zwei Funktionen fehlklassifiziert:**
- CAN1-Basisadresse `0x40006400` (STM32 CAN1) in `CAN_SetupTxMailbox` verifiziert; TX-Mailbox-Register
  (TIxR/TDTxR/TDLxR/TDHxR bei Offset `0x180 + Mailbox*0x10`) bestätigen echte HW-CAN-Nutzung.
- `CAN_FrameDispatcher` unterscheidet Frames per `(id>>0xc)&0xffff`/`(id>>0x14)&0xffffff`: Wert `4` →
  `Telemetry_Register_Dispatcher`, Wert `2` → `Modbus_ResponseDispatch`, sonst →
  `Protocol_AA_CommandDispatch` — bisher nicht dokumentiertes CAN-Frame-ID-Bitfeld-Schema.
- Modbus-Antworten können über CAN übertragen werden (`Modbus_SendResponse` → `CAN_SendMessage`),
  nicht nur über RS485/TCP.
- `CAN_SendWorkModeFrame` (`0x0802c5b0`) und `CAN_SyncChangedRegisters` (`0x0802c5d8`) sind trotz
  Namens **keine CAN-Funktionen**: Sie rufen ausschließlich `I2C_BitBang_WriteBytes` auf feste
  I2C-Slave-Adresse `0x48` auf (klassisches I2C-Bitbang-Protokoll: Start/WriteByte/ReadBit-ACK/Stop).
  Zeigt, dass die Inverter-Board-Kopplung teilweise über I2C läuft, getrennt vom eigentlichen
  CAN-Bus für Parallelbetrieb/BMS-Updates. Umbenennungsvorschlag (noch nicht angewendet, s.
  Tracking-Tabelle): `I2C_SendWorkModeFrame` / `I2C_SyncChangedRegisters`.

**BLE — Cmd-0x50/0x51-Substruktur präzisiert, GATT-Characteristic-Handle gefunden, großer
Fehlklassifizierungs-Fund:**
- Echte GATT-Notify-Characteristic-Handle `0xFF02` bestätigt (`AT+QBLEGATTSNTFY=ff02,<len>` in
  `BLE_GATT_Notify_Send`).
- Cmd 0x50/0x51 Sub-Selector `0x0A` = VID-Provisioning (String, Flash `0x22`B), Sub-Selector `0x0C`
  = XID-Provisioning (Struktur Typ/2×31-63B-Strings/Port/2 weitere Strings, `0xE6`B gesamt, Flash-Adresse
  `DAT_0800999c`). Semantik der einzelnen Config-Felder (Host/Topic-Präfix o. ä.) bleibt
  **unklar/braucht weitere Prüfung**.
- **Wichtigster Fund:** Die 18 Funktionen im Adressbereich `0x0804bd58`–`0x0804cc40` (bisher alle mit
  `BLE_`/`BLE_GATT_`-Präfix benannt) sind laut Aufrufkette **keine BLE-Funktionalität**, sondern eine
  generische, transport-unabhängige CLI-/AT-Kommando-Engine: 5 parallele Sessions, 16-Byte-
  Kommandotabellen-Einträge (Sichtbarkeits-Flag, Typ-Code, Match-Maske, Wert-/Handler-Pointer),
  `$name`-Variablensubstitution, 5-Eintrag-History-Ringpuffer, Tab-Completion. Initialisiert über
  `CLI_InitSession`, aufgerufen aus `CH395_Recv_Buffer_Setup` (CH395 = externer Ethernet/SPI-Chip);
  Eingabe-Dispatcher wird ausschließlich aus `Network_ReceiveAndDispatchData` (CH395/Modbus-TCP)
  aufgerufen — kein BLE-Codepfad. Passt zu Cmd 0x28 "Local API enable + port (Modbus TCP)". Alle
  bereits vorhandenen Nachbarfunktionen sind schon korrekt als `CLI_*`/`ATCmd_*`/`Util_*` benannt,
  die `BLE_GATT_*`-Präfixe sind damit auch stilistisch inkonsistent. Umbenennungsvorschläge (18
  Funktionen, `CLI_*`-Präfix) liegen vor, s. Tracking-Tabelle — **Rückfrage an den Nutzer nötig**, ob
  dieser Block als eigener Cluster "CLI/AT-Command-Engine" geführt werden soll (Querschnittsthema,
  vgl. Doku-Struktur-Konvention).

**Config/EEPROM — konsolidierte EEPROM-Adress-Map (aus Kommentaren + Cross-Reference-Analyse):**

```
0x160        DateTime (8B) — Produktionsdatum/Reboot-State
0x201        Discharge-Cutoff-SOC (1B, Komplement)
0x202/0x204  je U16-Wert, max 2500 (0x9c4)
0x300        EPS (Kommentar)
0x301        work_mode (Kommentar) — Widerspruch zu 0x374, s. u.
0x302        time_slots (100B = 10×10B)
0x366        auto_mode (Kommentar)
0x367        1-Byte Flag/Enum (<2)
0x369        1-Byte Wert (0-4)
0x36b        1-Byte Wert (schwellenwertvalidiert)
0x36d/0x36e  0xAA-Magic + 2B Wert (Validity-Pattern)
0x370        Capacity-Factor Byte (30-100%)
0x371/0x372  api_enable / api_port (Kommentar)
0x374        WorkingMode (0-7)
0x375        Bool-Flag (Feature unklar)
0x376        String (13B)
0x383        Signed-16-Bit Power-Offset/Kalibrierung
0x388        String (13B, max. 12 Zeichen+NUL)
0x441        server_type (0-4)
0x484/0x488/0x492  power_stats (je 4B)
0x500        Runtime-Counter-Block (52B)
0x900/0x901  Modbus-Adresse + 0xAA-Validity
0x2000+n*9   Event-Log-Einträge (9B/Eintrag)
0x3500       meter_ip (16B)
0x36b7/0x36b9/0x36bb  je 2B SSL-Zertifikat-Prüfwerte (CH395_MQTT_Init_And_CertSetup)
0x36bd       1-Byte Flag (BLE "sdv_en")
0x4000       User-Data-Block (36B) — interner Kommentar nennt ihn "net_cfg" (Widerspruch zum
             bisherigen Namen "User-Datenblock", s. u.)
```

Offene Widersprüche (nicht aufgelöst, brauchen weitere Prüfung): (1) EEPROM `0x301` wird intern als
"work_mode" kommentiert, während `Config_Write_WorkingMode` nachweislich nach `0x374` schreibt —
unklar ob zwei getrennte Felder oder veralteter Kommentar. (2) `Config_Save_UserDataBlock`
(EEPROM `0x4000`) — interner Kommentar nennt den Bereich "net_cfg" statt "User-Daten"; Aufrufer
(`Config_SaveWithCRC`, `OTA_InitSlotConfig`) passen eher zu Netzwerk-/OTA-Konfiguration.

Zusätzlicher struktureller Fund: Die generische Helferfamilie `Config_Read_U8/U16/U32/String/Block`
ist zu >80 % falsch benannt — 5 von 6 Funktionen rufen tatsächlich nur `EEPROM_Write` auf (kein
einziger `EEPROM_Read`-Aufruf), sind also Schreib- statt Lesefunktionen. Vermutlich Ergebnis eines
einzelnen fehlerhaften Batch-Namensvergabe-Laufs, der "Read/Write" pauschal statt nach tatsächlichem
Zugriffstyp vergeben hat. Umbenennungsvorschläge s. Tracking-Tabelle.

**OTA/Flash — zwei getrennte Flash-Subsysteme, QSPI-Kommando-Set, Speicherlayout bestätigt:**
- Internes MCU-Flash (STM32-Flash-Controller: `Flash_ErasePage`/`Flash_ProgramWord`/`Flash_Lock`/
  `Flash_Unlock`/`Flash_WaitReady`) vs. externes QSPI-NOR-Flash (memory-mapped Basis `0x70000000`,
  Offset-Umrechnung `addr - 0x70000000` in mehreren Funktionen bestätigt).
- QSPI-Kommando-Set verifiziert: `0x06` Write Enable, `0x20` Sector Erase (4KB), `0x32` Quad Page
  Program (256B-Pages), `0x6B` Quad Output Fast Read, `0xFF` Dummy/Release-Byte nach
  Read/CRC/Checksum-Operationen. Statusregister-Offset `+0x28` (Bit0 BUSY, Bit1/Bit3 Transfer-Flags),
  Datenregister-Offset `+0x60`.
- Flash-Speicherlayout pro Zielsystem bestätigt: EMS `0x80000`, MPPT `0x100000`, BMS `0x180000`,
  VNS `0x200000`, je 512KB Abstand; Download-Staging-Größe konstant `0x7D000` (500 000 Byte).
- **CRC-Algorithmus-Korrektur:** `OTA_CRC_Verify`/`QSPI_Flash_CalculateCRC` nutzen entgegen bisheriger
  Doku **CRC-16 (Modbus)**, nicht CRC-32 (`CRC16_Calculate`, Init `0xFFFF`, Vergleich `& 0xffff`).
- OTA-Ablauf bestätigt: `OTA_Update_Dispatcher` → `OTA_Process_Pending_Updates` →
  `OTA_Slot_Config_Validate` → `OTA_Slot_Config_Summary_Build` → `OTA_Firmware_Download_Init` →
  `OTA_PrepareShutdown` → `OTA_Download_Retry_Handler` (max. 2 Retries/Slot, 4 Slots). Chunks landen
  über `OTA_WriteDataToRingBuffer` in 5-Slot-Ringpuffer (`0x800`B/Slot), `OTA_Flash_Page_Writer`
  schreibt 2KB-weise nach Flash, danach nur Verify+Statuscode (`OTA_FW_Verify_And_Apply` schreibt
  entgegen seinem Namen selbst nichts — Umbenennungsvorschlag `OTA_FW_Verify_SetStatus`, s.
  Tracking-Tabelle).
- `0x080273dc` (bisher `SPI_Flash_ResetGPIO`) greift nachweislich nur auf `RCC_AHBPeriphResetCmd`
  zu, keinen einzigen GPIO-Registerzugriff — Umbenennungsvorschlag `QSPI_Controller_Reset`.
- `0x0802b8cc` (bisher `Flash_ReadWrite_Transaction`) führt ausschließlich `SPI_Flash_SectorErase`-
  Aufrufe aus (kein Read/Write) — Umbenennungsvorschlag `Flash_EraseAddressRange`.

**Gesamtergebnis Re-Audit:** 133 von 194 Funktionen (69 %) der vier Cluster geprüft. Davon ca. 88 %
korrekt, ca. 12 % mit Namens- oder Beschreibungsfehlern (Details/Umbenennungsvorschläge in
`Control_FW_Function_Tracking_new.md`, keine Ghidra-Umbenennung ohne zentralen Dubletten-Check
durchgeführt).

### 13.32 Re-Audit MQTT-Cluster (2026-07-14)

Der MQTT-Cluster (`## MQTT — Client/Protokoll/Payload`, 101 Funktionen) war seit der Erstvergabe
nie einzeln gegen frische Dekompilierung geprüft worden (Ausnahme: die Dublettenauflösung
`MQTT_Decode_RemainingLength` vs. `..._ViaCallback` aus Batch 19). 65 der 101 Funktionen wurden
geprüft (Ziel 55-65 laut Auftrag erreicht): alle mit unvollständiger Beschreibung/fehlendem
Confidence-Wert (15), sämtliche zentralen Dispatcher/Handler entlang der Connect-/Subscribe-/
Publish-/Receive-Pfade (25 — u.a. `MQTT_Session_Init`, `MQTT_Connect_And_Subscribe`,
`MQTT_Connect`, `MQTT_Subscribe_Impl`, `MQTT_Process_IncomingPacket`,
`MQTT_Dispatch_PublishCallback`, `MQTT_ReceivePacket`, `MQTT_Transport_ReceiveAll`,
`MQTT_Client_SendAndReceive`, alle Serialize/Deserialize/Encode/Decode-Helfer, `MQTT_TopicFilter_Match`,
`MQTT_KeepAlive_SendPing`, `MQTT_Next_PacketId`), plus eine repräsentative Stichprobe der
JSON-RPC-Response-Builder, Publish_*-Varianten und Config-Parser (25).

**Ergebnis: 63 von 65 Funktionen (97 %) korrekt benannt und beschrieben** — der MQTT-Kern
(Connect/Subscribe/Publish/Receive/Encode/Decode, das komplette JSON-RPC-Dispatcher-Ökosystem samt
`MQTT_Build*Response`-Familie) ist sauber und deckungsgleich mit dem tatsächlichen Code. Zwei
Fehlbenennungen gefunden (Fehlerquote 3 %, deutlich niedriger als in den zuvor auditierten
Clustern — CAN/BLE/Config/OTA lagen bei ~12 %, mbedTLS-Cluster hatte in Batch 18 62 Korrekturen
bei ca. 260 Funktionen, also ~24 %):

- **`MQTT_Subscribe_Handler` (`0x080109d8`) hat nichts mit MQTT-Subscribe zu tun.** Der Code
  iteriert über 10 Schedule-Slots (Stride 10B, Power-Feld bei Offset+2 als int16) und klemmt Werte
  >800 auf 800, danach `Config_Notify_Change(slot)` je geänderten Slot. Aufrufer sind
  `MQTT_JSON_RPC_Dispatcher` (direkt nach `EEPROM_Write(0x90,...)`) und `BLE_Recv_Cmd_Dispatcher` —
  in beiden Fällen als Config-Postprocessing-Schritt nach dem Schreiben von Zeitplan-/Setpoint-Daten,
  kein SUBSCRIBE-Paket, kein Topic-Bezug. Vermutlich beim Erstbenennen fälschlich aus dem
  MQTT-Aufrufkontext abgeleitet statt aus dem tatsächlichen Funktionskörper.
- **`MQTT_Topic_Build` (`0x0802fa18`) baut keinen Topic-String.** Die Funktion nimmt einen Index
  (1-4) und gibt eine von mehreren Flash/RAM-Adressen zurück (`0x310000`-Literal oder eine von drei
  `DAT_`-Zeigern); alle vier Aufrufer (`OTA_ValidateUrlSlots`, `BLE_Recv_Cmd_Dispatcher`,
  `Quectel_AT_Response_Parser`, `MQTT_JSON_RPC_Dispatcher`) übergeben das Rückgabe-Ergebnis direkt an
  `Flash_EraseAddressRange(..., 0xfb)` bzw. `0x04` — Größenordnung 0xfb (251 Byte) passt zu einem
  URL-/Config-Slot, nicht zu einem MQTT-Topic-Buffer. Eher ein generischer Slot-Adress-Selektor
  (mutmaßlich für OTA-/Server-URL-Konfigurationsslots) als ein Topic-Builder.

Beide Funde sind reine Namens-/Klassifizierungsfehler ohne Sicherheitsrelevanz; Umbenennungsvorschläge
liegen vor (s. Tracking-Tabelle, Spalte "Namens-Verdacht"), wurden aber wie bei allen bisherigen
Re-Audits **nicht in Ghidra angewendet**, bis der zentrale Dubletten-Check erfolgt ist.

**Neue inhaltliche Erkenntnisse (Topic-/Payload-Struktur):**
- `MQTT_Topic_Builder` (`0x080058e0`, zu unterscheiden vom o.g. `MQTT_Topic_Build`) baut vier
  Topic-Strings über `Cloud_Telemetry_JSON_Builder`: `marstek/{xid}/server/{sn}/ctrl` und
  `marstek/{xid}/device/{sn}/ctrl` (nur falls Custom-Xid ≥6 Zeichen aktiv ist, s. §13.17) sowie
  immer `marstek_energy/{sn}/device/{sn}/ctrl` und `marstek_energy/{sn}/App/{sn}/ctrl` — d. h. es
  existieren **zwei parallele Topic-Namespaces** (`marstek/...` für den optionalen Custom-Broker via
  Xid, `marstek_energy/...` als Standard-Cloud-Topic), beide mit demselben `.../ctrl`-Suffix-Schema.
- Alle `MQTT_Publish_Telemetry`/`MQTT_Send_Data_Buffer`/`MQTT_Publish_AI_Data`/etc.-Funktionen senden
  über dasselbe Muster: entweder direkt per `Quectel_Modem_DataSend` (Transport-Modus 1, TCP-Socket)
  oder als AT-Kommando `AT+QMTPUB=0,0,0,0,"marstek_energy/{xid}/device/{sn}/ctrl",{len},{payload}`
  (Quectel-Modem-AT-Schnittstelle) — die Firmware unterstützt also zwei redundante Transportwege zum
  selben Cloud-Endpunkt, gesteuert über einen einzigen Mode-Parameter je Publish-Aufruf.
- Response-Payload-Feldnamen bestätigt (aus `MQTT_Build*Response`-Familie, cJSON-Objektnamen direkt
  aus dem Code gelesen): `Bat_data`, `Ble_data`, `Device_data`, `Em_data`, `Es_mode_data`, `Es_data`,
  `Marstek_data`, `Pv_data`, `Wifi_data`, `Err_data` (Error-Envelope), `Result_data` (Set-Result) —
  ergänzt bestehende Tabelle in §9 (MQTT-Feldnamen → Register-Mapping) um den generischen
  JSON-RPC-Envelope-Mechanismus (`MQTT_JSON_CreateResponseEnvelope` → Root+ID+Result-Array,
  `MQTT_JSON_AddTypedValue` unterstützt nur Typ 8=Int und Typ 0x10=String).

### 13.33 Re-Audit Config/EEPROM + OTA/Flash — Fortsetzung/Vertiefung (2026-07-14)

Fortsetzung von §13.31 (dort waren 133/194 Funktionen der vier Cluster CAN/BLE/Config-EEPROM/
OTA-Flash geprüft). Dieser Durchgang hat gezielt die zuvor noch offenen Funktionen der beiden
Cluster **Config/EEPROM** und **OTA/Flash/SPI-Flash/QSPI** nachgeprüft, mit Fokus auf (a) alle
Funktionen ohne Beschreibung und (b) alle verbleibenden `Read`/`Get`-benannten Funktionen (wegen
des in §13.31 gefundenen Fehlermusters, dass mehrere `Config_Read_*` in Wahrheit Schreibfunktionen
waren).

**Config/EEPROM:** 22 zusätzliche Funktionen geprüft (13 ohne Beschreibung, 5 `Get`/`Read`-benannte,
4 aus der `Config_Param5x`-Familie), macht zusammen mit den 8 aus §13.31 **30 von 57 Funktionen
(53 %)** geprüft. Alle 22 neu geprüften Funktionen bestätigten Name und (soweit vorhanden)
Beschreibung — **keine weiteren Read/Write-Verwechslungen gefunden**. Insbesondere die restlichen
`Config_Get_Capacity_Factor`, `Config_Get_WorkMode`, `Config_Get_DeviceModelCode`,
`Config_Read_String_0x388`, `Config_Read_ProductionDate` lesen nachweislich nur (über `EEPROM_Read`
bzw. direkten Struct-Zugriff) — das in §13.31 gefundene Fehlermuster war offenbar auf die dort
bereits identifizierten `Config_Read_U8/U16/U32/String/Block`-Funktionen beschränkt und zieht sich
nicht durch den ganzen Cluster. Die beiden Kernprimitiven `EEPROM_Read`/`EEPROM_Write` (Mutex-/
Queue-geschützter I2C-Zugriff, zuvor ohne Beschreibung) sowie `EEPROM_Mutex_Wait` und
`EEPROM_Config_Factory_Write` wurden dokumentiert.

**OTA/Flash/SPI-Flash/QSPI:** 21 zusätzliche Funktionen geprüft (13 ohne Beschreibung, 8 bisher nur
per Namens-Match ohne Dekompilierungs-Review markiert), macht zusammen mit den 6 aus §13.31
**27 von 61 Funktionen (44 %)** geprüft. Auch hier **keine Namens-/Beschreibungsfehler gefunden** —
das komplette QSPI-Low-Level-Set (`QSPI_ReadDataRegister`/`QSPI_WriteDataRegister`/
`QSPI_TransferWords`/`QSPI_SendAndReceive`/`QSPI_SendCommandIrqSafe`/`QSPI_ConfigureMode`/
`QSPI_ApplyRegisterConfig`) sowie die SPI-Flash-GPIO-/Clock-Konfiguration
(`SPI_Flash_PeripheralEnable`/`QSPI_Controller_Reset`/`SPI_Flash_ConfigGPIO`/
`SPI_Flash_ClockGateControl`/`SPI_Flash_WriteEnableCheck`) und die Kommando-Funktionen
(`SPI_Flash_SectorErase`, `SPI_Flash_QuadPageProgram`, `QSPI_Flash_QuadRead`,
`QSPI_Flash_PollStatusReady`, `Flash_SelfTest`) sind alle namensgerecht implementiert.
`OTA_FW_Verify_SetStatus` (zuvor ohne Beschreibung) bestätigt exakt die bereits in §13.31
dokumentierte Verify-Logik (CRC-16 + dev_mask + Modellstring, Statuscodes 0x401-0x403).
`SPI_Flash_MutexTransaction` und `Flash_EraseAddressRange` (letztere war in §13.31 bereits inhaltlich
korrigiert, jetzt vollständig mit Aufruferliste dokumentiert) wurden ebenfalls nachgezogen.

**Fehlerquote dieser Fortsetzung: 0 von 43 geprüften Funktionen (0 %)** — deutlich niedriger als die
~12 % aus §13.31 (Erstdurchgang). Interpretation: Die Fehlklassifizierungen aus §13.31 konzentrierten
sich auf spezifische, bereits identifizierte Funktionsfamilien (`Config_Read_*`-Helfer,
`SPI_Flash_ResetGPIO`, `Flash_ReadWrite_Transaction`, `OTA_FW_Verify_And_Apply`); die übrigen, in
diesem Durchgang geprüften Funktionen (primär Low-Level-Hardware-Primitiven ohne komplexe
Namenssemantik) waren bereits korrekt benannt.

**Restbestand:** Config/EEPROM 27 von 57 Funktionen weiterhin ungeprüft (primär die
`Config_Write_*`/`Config_Set_*`/`Config_Apply_*`-Familie mit Namen, die schreibende Semantik klar
ausdrücken — geringes Fehlerrisiko basierend auf dem gefundenen Muster). OTA/Flash 34 von 61
Funktionen weiterhin ungeprüft (primär High-Level-OTA-Orchestrierung: `OTA_Update_Dispatcher`,
`OTA_Process_Pending_Updates`, `OTA_Slot_Config_Summary_Build`, `OTA_Firmware_Download_Init`,
`OTA_InitSlotConfig`, `OTA_Download_Retry_Handler`, `OTA_Flash_Prepare_ByTarget`,
`OTA_Flash_Page_Writer`, interne MCU-Flash-Funktionen `Flash_ReadWords`/`Flash_ReadWithECC`/
`Flash_ErasePage`/`Flash_Lock`/`Flash_Unlock`/`Flash_ProgramWord`/`Flash_WaitReady`/
`Flash_EraseRegion`/`Flash_WriteRegion` sowie diverse Batch-20-Funktionen). **Beide Cluster sind
damit noch nicht zu 100 % re-auditiert** — Fortsetzung in einer weiteren Session empfohlen, falls
vollständige Abdeckung gewünscht ist.

### 13.34 Re-Audit cJSON-Vendor-Lib + Quectel-Modem/WiFi/AT-Cluster (2026-07-14)

Erster individueller Re-Audit der beiden Cluster `cJSON — Vendor-Lib` (30 Funktionen) und
`Quectel-Modem / WiFi / AT-Commands` (65 Funktionen), zuvor nie einzeln geprüft. Durchgeführt über
4 parallele Teil-Audits (alle 30 cJSON-Funktionen; 42 Nicht-Batch-20 Quectel-Funktionen in zwei
Hälften; Stichprobe von 8 der 23 Batch-20-Quectel-Funktionen), jeweils per
`get-decompilation(includeCallers, includeCallees)`.

**cJSON-Cluster (30/30 geprüft, 0 Namensfehler mit Handlungsbedarf, 11 Beschreibungen korrigiert):**
Die Firmware nutzt eine **modifizierte cJSON-Variante**: `cJSON_New_Item(type, name)` nimmt den
Namen bereits bei der Knoten-Allokation auf, wodurch `Create*`-Funktionen systematisch mehr
Parameter haben als die echte Dave-Gamble-cJSON-API (z. B. `cJSON_CreateBool`/`_CreateString` mit
Name+Value statt nur Value; `cJSON_CreateDouble` mit 3 statt 1 Parameter). Das ist konsistentes,
firmwarespezifisches Design und keine Fehlbenennung. Einzige echte Namens-Auffälligkeit:
`cJSON_AddItemToObject` (`0x0802a290`) nimmt nur 2 Parameter (Name, Item) und erzeugt **immer einen
neuen** benannten Wrapper-Knoten statt ein bestehendes Objekt zu mutieren — entspricht nicht der
3-Parameter-Semantik der echten API `cJSON_AddItemToObject(object, string, item)`; die eigentliche
Verkettung ins Elternobjekt passiert extern über `cJSON_AddItemToArray` bei allen 11 Aufrufern.
Vorschlag (nicht angewendet): `cJSON_CreateNamedItem`. `cJSON_NewObject` (`0x0802a32c`) entspricht
exakt `cJSON_CreateObject(void)` — Umbenennung optional, kein Fehler. `cJSON_GetValue`/
`cJSON_FindChildByName` sind keine Dubletten, sondern unterschiedliche interne Helfer (Value-Pointer-
Accessor vs. Name-Suche). Auffällig: `0x08013e04 JSON_ExtractFieldValue` gehört inhaltlich **nicht**
zur cJSON-Lib (kein rekursiver Parser, nur strstr/strncpy-Scanner für ein HTTP-JSON-API-Feld
`device_id`), bleibt aber aus Konsistenzgründen im Cluster (bereits korrekt benannt, keine
Verschiebung nötig).

**Quectel-Cluster (50/65 geprüft = 77 %, davon alle 42 Nicht-Batch-20 + Stichprobe 8/23 Batch-20;
7 Namensfehler, 15 Beschreibungskorrekturen):**

1. `0x08022b4c Quectel_AT_Response_Parser` — parst tatsächlich **MQTT-OTA-Metadaten** (id/type/
   size/crc/url je Device-Slot) und schreibt sie per Flash_Write/Erase in den Flash, kein generisches
   AT-Reply-Parsing. Vorschlag: `Quectel_MQTT_OTA_Info_Parser`.
2. `0x0804d018–0x0804d1d4` (5 Funktionen: `ATCmd_OutputLineTruncated`, `ATCmd_PrintCommandInfo`,
   `ATCmd_PrintPrompt`, `ATCmd_PrintReturnValue`, `ATCmd_WriteString`) — **gehören nicht zum
   Quectel-Modem**, sondern sind Output-Primitiven der generischen CLI/AT-Command-Engine
   (`0x0804bd58`–`0x0804cc40`), die im vorherigen Re-Audit vom 2026-07-14 bereits von `BLE_GATT_*`
   auf `CLI_*` korrigiert wurde (s. §13.31/Batch-19-Historie). Alle 5 Funktionen werden ausschließlich
   von dort aus aufgerufen (`CLI_PrintCommandEntry`, `CLI_HelpOrInfoDispatch`, `CLI_InsertChar`/
   `CLI_TabComplete`/`CLI_ConfirmAndExecute`, `CLI_ExecuteCommand`, 13× diverse `CLI_*`). Der
   Namensteil "ATCmd" suggeriert fälschlich Quectel-AT-Modem-Bezug. Vorschlag: `CLI_*`-Präquel
   (`CLI_OutputLineTruncated`, `CLI_PrintCommandInfo`, `CLI_PrintPrompt`, `CLI_PrintReturnValue`,
   `CLI_WriteString`). Damit wächst der bereits vermerkte "offene Punkt für den Nutzer" (eigener
   CLI/AT-Command-Engine-Cluster?) um einen weiteren Adressbereich außerhalb des ursprünglich
   gefundenen 18-Funktionen-Blocks.
3. `0x08011008 Quectel_TCP_SendData` — Format-String-Branch enthält sowohl reine TCP-Form
   (`"AT+QISEND=%d,%d"`) als auch UDP-Zieladress-Form (`"AT+QISEND=%d,%d,\"%s\",\"%s\",%d"`), Caller
   ist der protokoll-neutrale `Network_TransportDispatch` — kein TCP-Spezialfall. Vorschlag:
   `Quectel_QISEND_SendData_TCP_UDP`.
4. `0x0801285c Quectel_SignalQuality_PeriodicCheck_Save` (aus Batch 20!) — **kein Modem-/AT-/
   UART-Bezug**, operiert stattdessen auf Inverter-/PV-String-Telemetrie-Structs (`0x20014f40`/
   `0x20014e90`), Aufrufer-Umfeld ist rein energie-/wechselrichterbezogen
   (`Grid_Export_Limit_Periodic_StateMachine`, `Battery_Forced_Charge_Check`, `Inverter_Sync_Init`).
   Vermutlich Fehlklassifikation *innerhalb* Batch 20 (Funktion landete im falschen Cluster/mit
   falschem Namensmuster). Vorschlag: `Inverter_PVString_ChannelValue_PeriodicCheck_Save`. Dies ist
   der erste bestätigte Fehler in der Batch-20-Stichprobe dieses Clusters (1 von 8 = 12,5 %) — die
   bisherige Annahme "Batch 20 zuverlässiger" gilt also nicht ausnahmslos.

Weitere Erkenntnisse ohne Umbenennungsbedarf: Mehrere als "TCP_"-benannte Hilfsfunktionen
(`Quectel_TCP_ConnectionState_Query`, `Quectel_TCP_SendAndVerify`) werden nachweislich auch von
`Quectel_UDP_CommStateMachine`/`Quectel_UDP_OpenSocket` genutzt, da Quectel AT+QISTATE/AT+QISEND
connectID-basiert und protokollunabhängig sind (Beschreibungen ergänzt, Namen belassen). Die
vermutete Verwechslungsgefahr zwischen 5 AT-Send-Varianten (`Quectel_SendCmd_WaitResponse`,
`Quectel_AT_SendAndVerify`, `Quectel_AT_SendAndPollResponse`, `Quectel_AT_SendRaw_WithMutex`,
`Quectel_TCP_SendAndVerify`) bestätigte sich **nicht** — es sind tatsächlich 5 unterschiedliche
Implementierungen (Byte-Assembler+Timer / Notify+strstr / Tick-Polling / Raw ohne Verify / eigener
Buffer). Die 5 GPIO-Reset-Funktionen (`WiFi_Module_RestartStateMachine`,
`WiFi_HardwareResetSequence`, `WiFi_ModuleResetDispatcher`, `WiFi_ResetWithRecoveryWait`,
`WiFi_PowerCycleSequence`) sind ebenfalls sauber gegeneinander abgegrenzt, keine Verwechslung.

**Fehlerquoten:** cJSON 0/30 echte Namensfehler (0 %, 1 optionale Alternative); Quectel 7/50 Namensfehler
(14 %, davon 5 aus einem einzigen fehlklassifizierten Adressblock). Alle Umbenennungsvorschläge sind
**nicht** in Ghidra angewendet — zentrale Dublettenprüfung steht noch aus (offener Punkt).

### 13.35 Re-Audit Abschluss BLE/GATT + Inverter/Register/Energie-Cluster (2026-07-14)

Abschluss-Re-Audit der beiden zuvor teilweise geprüften Cluster `BLE / GATT` (50 Funktionen) und
`Inverter / Register / Energie-Logik` (89 Funktionen). Geprüft wurden alle verbleibenden, noch nicht
mit "Re-Audit 2026-07-14" markierten Zeilen (28 im BLE-Cluster ohne die bereits vorher nach `CLI_*`
umbenannten Funktionen, 64 im Inverter-Cluster) über 5 parallele Teil-Audits, jeweils per
`get-decompilation(includeCallers, includeCallees)`. Damit sind **beide Cluster jetzt vollständig
(100 %) re-auditiert**: BLE/GATT 34/34 relevante Zeilen (50 minus 16 bereits als `CLI_*` korrigierte
Funktionen), Inverter/Register/Energie-Logik 89/89.

**BLE/GATT-Cluster (28/28 geprüft, 1 Namensfehler, 1 Struktur-Anomalie, 6 Beschreibungskorrekturen/-ergänzungen):**

1. `0x0800a740 BLE_CRC_Calculate` — berechnet tatsächlich nur eine **XOR-Prüfsumme** (`uVar2 ^=
   *(byte*)(param_1+i)` in Schleife), kein echter CRC mit Polynom/Tabelle. Vorschlag (nicht
   angewendet): `BLE_XOR_Checksum_Calculate`.
2. `0x08008000 BLE_Command_Handler` — **Struktur-Anomalie, kein Namensfehler — gelöst, s. §13.46**: Der
   Code-Body war inhaltlich identisch mit einem Case-Block aus `BLE_Recv_Cmd_Dispatcher` (0x08007f58,
   direkt davor liegend) und enthielt nicht auflösbare `in_stack_...`-Parameter im Decompilat —
   typisches Symptom einer fälschlich gesetzten Ghidra-Funktionsgrenze mitten in einer
   Switch-Anweisung. **Update 2026-07-15:** Root-Cause bestätigt (vollständig überlappende
   Geisterdefinition innerhalb von `BLE_Recv_Cmd_Dispatcher`, alle Referenzen `PARAM`-Typ statt
   `CALL`/`JUMP`), Funktionsdefinition per `FunctionManager.removeFunction()` entfernt, Doku-Zeile
   entfernt, Cluster-Header BLE/GATT (36→35) korrigiert. Details s. §13.46.
3. `0x08007f58 BLE_Recv_Cmd_Dispatcher`, `0x0800a764 BLE_Send_Response`, `0x08026bfc
   BLE_XidServerConfig_Parse` — hatten keine Beschreibung, jetzt anhand des Codes nachgetragen
   (Dispatcher: Frame-Validierung + Switch auf >50 Cmd-Handler; Send_Response: zentrale
   Antwort-Frame-Konstruktion, >80 Aufrufer; XidServerConfig_Parse: 6-Felder-Parser für
   VID/XID-Provisioning aus BLE-Cmd 0x0C).
4. `0x0800b430 BLE_Build_BMS_Data_Response` — wird entgegen der bisherigen Beschreibung **nicht nur
   für BLE** verwendet, sondern der aufbereitete Puffer wird auch von `MQTT_Publish_BMS_Full_Data`
   für den MQTT-Kanal weiterverwendet.
5. `0x08010718 BLE_Pending_Commands_Process` — funktional wie dokumentiert (WiFi-Setup/OTA/
   Socket-Ctrl-Dispatch), hat aber laut `find-cross-references` **0 Aufrufer im aktuellen
   Codepfad** (evtl. nur über nicht aufgelösten Funktionszeiger erreichbar) — als Hinweis ergänzt.

**Inverter/Register/Energie-Cluster (64/64 geprüft, 4 Namensfehler/-verdachte, 8
Beschreibungskorrekturen/-ergänzungen, 1 Faktenkorrektur):**

1. `0x08005860 Inverter_Register_Buffer_Init` — **klarer Fehlgriff**: einziger Aufrufer ist
   `MQTT_Connect_And_Subscribe`, kein RS485/Inverter-Bezug im Code. Die Funktion macht
   memset+memcpy und ruft `Flash_Obfuscated_String_Decode()` auf — decodiert einen obfuskierten
   Flash-String (vermutlich ein MQTT/TLS-Credential) in einen Puffer für den MQTT-Client-Aufbau.
   Potenziell relevant für das laufende TLS/AWS-IoT-Credential-Projekt (s. Memory-Eintrag
   "Control FW TLS-Zertifikat-Extraktion"). Vorschlag: `MQTT_Credential_Buffer_Decode` (Name
   vorläufig, exakte Semantik des dekodierten Strings noch zu klären).
2. `0x08005adc Inverter_Sync_Init` — wird entgegen dem Namen bei **jedem** Durchlauf aus
   `MainLoop_Periodic_Tasks` aufgerufen, nicht nur einmalig; "Init" trifft nur den Erstlauf-Zweig
   (MarkAll bei leerem Flag), danach laufend Timeslot_ApplyConfigOnSync + Inverter_Apply_BatteryParams
   + 3000-Tick-WorkMode-Frame + I2C-Sync. Vorschlag: `Inverter_Sync_Periodic` o. ä.
3. `0x08005d00 Timeslot_Bitmap_Set_Slot2` und `0x08005dd4 Timeslot_Bitmap_SetClear` — beide tragen
   einen irreführenden "Timeslot"-Namen, obwohl sie als generisches Register-Dirty-Bitfeld für
   diverse Inverter-Register dienen (WorkMode, ChgVolt, DischgVolt, PowerSetpoint, GridPower,
   BatteryParams) und **keiner** ihrer insgesamt 9 Aufrufer einen Zeitplan-/Uhrzeit-Bezug hat.
   Vorschläge: `Inverter_RegDirty_Mark_BatteryParams` bzw. `Inverter_RegDirty_Bitmap_SetClear`.
   Betrifft indirekt auch die Namensfamilie `Inverter_BatteryParams_Timeslot2_SetClear`
   (0x08006530, ruft `Timeslot_Bitmap_SetClear` auf) — dort ist "Timeslot2" im Kontext von
   Batterie-Parametern ebenfalls fachlich ungenau, aber ohne eigenen Rename-Vorschlag geprüft.
4. `0x08032348 Register_PackDescriptor` — Faktenkorrektur: tatsächlich **36 Aufrufer** (nicht 35 wie
   in der bisherigen Beschreibung), verifiziert per vollständiger Caller-Liste.
5. Mehrere kleinere Beschreibungspräzisierungen: `Inverter_RegDirty_MarkAll`/`_Mark_ChgVolt`/
   `_Mark_DischgVolt` setzen oder löschen abhängig vom Parameter (nicht nur "setzen");
   `Inverter_Power_Value_Scale` wendet zusätzlich `Inverter_PowerSetpoint_DeadbandClamp` an (fehlte
   in der Beschreibung); `Inverter_Apply_BatteryParams` ruft am Ende zusätzlich
   `Grid_Power_Dynamic_Adjust` auf und enthält ein Init-Gate + Timeslot2-Bitmap-Logik (fehlte in der
   Beschreibung); `0x0801e290 WorkMode_Flag_Reset_And_TriggerSetpointEval` hatte eine **sachlich
   falsche** Beschreibung ("Connection-Flag löschen, Disconnect triggern") — tatsächlich wird bei
   gesetztem Broadcast-Flag oder abgelaufenem 300ms-Timer `TimePlan_Evaluate_Setpoint()`
   (Sollwert-Neuberechnung) angestoßen, kein Connection-/Disconnect-Bezug im Code.
6. Drei Debug-Print-Funktionen (`Battery_Config_Debug_Print`, `MPPT_Debug_Print`,
   `Inverter_PowerSetpoint_Apply_Wrapper`) haben **0 Aufrufer/Referenzen** im gesamten Binary —
   als Hinweis ergänzt, keine Fehlbenennung (passt zum bereits bekannten Muster toter
   Debug-/Wrapper-Funktionen).

**Fehlerquoten:** BLE/GATT 1/28 klarer Namensfehler (3,6 %) + 1 Struktur-Anomalie ohne
Umbenennungsempfehlung; Inverter/Register/Energie 4/64 Namensfehler/-verdachte (6,3 %, davon 1
klarer Fehlgriff und 3 irreführende "Timeslot"-Namen in derselben Funktionsfamilie). Alle
Umbenennungsvorschläge sind **nicht** in Ghidra angewendet — zentrale Dublettenprüfung steht noch
aus (offener Punkt, konsistent mit §13.34).

### 13.36 Re-Audit Hardware/HAL-Cluster (GPIO/ADC/SPI/I2C/USART/RCC/RTC, 81 Funktionen, 2026-07-14)

Erster individueller Re-Audit des Clusters „Hardware / HAL" (81 Funktionen, zuvor nie einzeln
geprüft). Durchgeführt über 4 parallele Teil-Audits (RCC/SysTick/NVIC/FPU 21, GPIO/ADC/SPI 17,
I2C-Bitbang/EEPROM_I2C 21, RTC/UART/USART 20) plus 3 selbst durchgeführte Referenz-Verifikationen
(RCC_APB2PeriphClockCmd, SPI_DeInit, USART_Init) — **alle 81 Funktionen zu 100 % geprüft**, jeweils
per `get-decompilation(includeCallers, includeCallees)` plus `get-data` zur Auflösung referenzierter
`DAT_`-Peripherie-Basisadressen.

**Verifizierte STM32F1-Peripherie-Basisadress-Map** (durch direkte Ghidra-Analyse bestätigt, Werte
aus realen `DAT_`-Konstanten im Programm ausgelesen — nicht nur aus Referenzliteratur übernommen):

| Peripherie | Basisadresse | Bus | Beleg-Funktion |
|---|---|---|---|
| RCC | 0x40021000 | — | RCC_APB2PeriphClockCmd (`DAT_08028014`) |
| FLASH-Interface | 0x40022000 | — | ehem. RCC_EnablePeripheralClock (`DAT_080077f0`) |
| AFIO | 0x40010000 | APB2 | ehem. STM32_RCC_Clock_Config (`DAT_08012c4c`) |
| SPI1 | 0x40013000 | APB2 | SPI_DeInit (`DAT_0802b9dc`) |
| SPI2 | 0x40003800 | APB1 | SPI_DeInit (`DAT_0802b9e0`), ADC_Peripheral_Init (`DAT_0801796c`) |
| SPI3 | 0x40003C00 | APB1 | SPI_DeInit (`DAT_0802b9e4`) |
| USART1 | 0x40013800 | APB2 | USART_Init (`DAT_0802dfb4`) |
| I2C1 | 0x40005400 | APB1 | EEPROM_I2C_* -Cluster (14 Funktionen) |
| GPIOB | 0x40010C00 | APB2 | SPI_Timer_Peripheral_Init/EEPROM_I2C_GPIO_ClockPulseRecovery |
| GPIOC | 0x40011000 | APB2 | I2C_BitBang_*-Cluster (5 Funktionen) |
| GPIOD | 0x40011400 | APB2 | GPIOD_Pin9_Write |
| GPIOE | 0x40011800 | APB2 | SPI_Timer_GPIO_ChipSelect_Init, Peripheral_SetBit15 |

**13 Namensfehler mit Codebeleg gefunden** (Vorschläge, **nicht** in Ghidra angewendet — Nutzer-
entscheidung ausstehend):

| Adresse | Alter Name | Neuer Name (Vorschlag) | Begründung (Kurzfassung) |
|---|---|---|---|
| 0x080077e4 | RCC_EnablePeripheralClock | Flash_SR_ClearFlags | Basisadresse 0x40022000 = FLASH-Interface (nicht RCC 0x40021000), Offset+0xC=FLASH_SR; einzige Aufrufer Flash_ErasePage/Flash_ProgramWord |
| 0x08012a04 | STM32_RCC_Clock_Config | AFIO_PinRemapConfig | Basisadresse 0x40010000 = AFIO (nicht RCC); Register-Offsets passen zu MAPR/MAPR2, nicht zu Clock-Config |
| 0x08028044 | RCC_SetClockBypass | RCC_LSICmd | Bit-Band-Alias-Rückrechnung → RCC_CSR (0x40021024) Bit0 = LSION, nicht HSEBYP/LSEBYP |
| 0x08028050 | RCC_SetClockOutputFlag | RCC_RTCCLKCmd | Bit-Band-Alias-Rückrechnung → RCC_BDCR (0x40021020) Bit15 = RTCEN, nicht MCO/Clock-Output |
| 0x08001fb6 | GPIO_PulsePin | RCC_BackupDomainReset_Pulse | Ruft nur GPIO_WritePinValue(1)/(0) auf, Ziel ist RCC_BDCR.BDRST (s. u.), kein GPIO |
| 0x08028038 | GPIO_WritePinValue | RCC_BDCR_BDRST_Write | Bit-Band-Alias 0x42420440 → 0x40021020 (RCC_BDCR) Bit16 = BDRST, kein GPIO-Register beteiligt (Rückrechnung verifiziert) |
| 0x080178bc | ADC_Peripheral_Init | SPI2_Peripheral_Init | Basisadresse 0x40003800 = SPI2 (nicht ADC1=0x40012400); RCC_APB1(0x4000=SPI2EN)/APB2(GPIOB) passen zu SPI2 |
| 0x0802b6d4 | ADC_SetControlBit0x40 | SPI_Cmd | Setzt/löscht SPI_CR1 Bit6 (SPE) — Standard-SPL SPI_Cmd() |
| 0x0802ba04 | ADC_ApplyChannelConfig | SPI_Init | Schreibt SPI_CR1 + löscht I2SCFGR.I2SMOD — Standard-SPL SPI_Init() |
| 0x0802ba40 | ADC_SetScanMode | SPI_SSOutputCmd | Setzt/löscht SPI_CR2 Bit2 (SSOE) — Standard-SPL SPI_SSOutputCmd() |
| 0x08017ed4 | SPI_Timer_Peripheral_Init | EEPROM_I2C_Peripheral_Init | Basisadresse 0x40005400 = I2C1 (nicht SPI/Timer); GPIOB8/9 AF-OD (I2C1-Remap SCL/SDA); Callees ausschließlich EEPROM_I2C_* |
| 0x08028628 | RTC_GetTime | RTC_GetDate | Liest RTC_DR (0x40002804, Offset+0x04), dekodiert Jahr/Monat/Tag/Wochentag; Caller-Semantik in RTC_GetDateTime bestätigt Tausch |
| 0x08028674 | RTC_GetDate | RTC_GetTime | Liest RTC_TR (0x40002800, Offset+0x00), dekodiert Stunde/Minute/Sekunde |
| 0x08028750 | RTC_SetTime | RTC_SetDate | Schreibziel = WPR−0x20 = RTC_DR; Parameter-Mapping Jahr/Monat/Tag/Wochentag |
| 0x08028404 | RTC_SetDate | RTC_SetTime | Schreibziel = WPR−0x8 = RTC_TR; Parameter-Mapping Stunde/Minute/Sekunde/PM |
| 0x0800468c | UART_Packet_Receive_Parse | CH395_Packet_Receive_Parse | Kein UART-Bezug; ruft ausschließlich CH395_ReadRecvBuf/CH395_GetRecvLen/CH395_SPI_WriteCmd auf (CH395-SPI-Ethernet-Controller) |

Zusätzlich 2 Konsistenz-Hinweise ohne harten Fehler (nicht in obige Tabelle gezählt):
`RCC_PeriphBitControl` (0x08028018, tatsächlich RCC_APB2RSTR — funktional korrekt, aber
inkonsistent zum Namensschema der Schwesterfunktionen RCC_APB1/APB2PeriphResetCmd) und
`Peripheral_SetBit15` (0x08032324, bestätigt GPIOE Pin15 — Name nicht falsch, aber ungenauer als
das Schwesterpaar GPIOD_Pin9_Write nahelegt).

**I2C↔CAN-Verwechslungsverdacht NICHT bestätigt:** Der in der Aufgabenstellung befürchtete Fall
(I2C-Bitbang-Funktionen fälschlich als CAN_* benannt, wie es in einer früheren Session bei anderen
Funktionen vorkam) wurde für den kompletten I2C-Bitbang-/EEPROM_I2C-Cluster (21 Funktionen)
**widerlegt** — alle Basisadressen (I2C1=0x40005400 für 13 EEPROM_I2C-Funktionen, GPIOC=0x40011000
für die 6 I2C_BitBang-Kernfunktionen, GPIOB=0x40010C00 für die Bus-Recovery) stimmen exakt mit den
Namen überein. Einziger Fund: die Tracking-Doku nannte für `I2C_BitBang_WriteBytes` (0x0802fdb8)
einen veralteten Aufrufer „CAN_SendWorkModeFrame" — im aktuellen Ghidra-Stand heißt diese Funktion
bereits `I2C_SendWorkModeFrame` (0x0802c5b0, ruft ihrerseits `Inverter_Sync_Init`/
`Inverter_Apply_BatteryParams` auf) — reiner Doku-Sync-Fehler, kein Ghidra-Fix nötig, in der
Tracking-Tabelle korrigiert.

**Offener Punkt — dritte UART-Instanz mit untypischer Adresse:** `USART_Init` (0x0802df0c) prüft
`param_1` gegen drei Basisadress-Konstanten: `DAT_0802dfb4=0x40013800` (USART1, Standard-STM32F103,
APB2/PCLK2), sowie `DAT_0802dfb8=0x40015000` und `DAT_0802dfbc=0x40015400` — **beide entsprechen
nicht** den STM32F103-Standardadressen für USART2 (0x40004400) oder USART3 (0x40004800). Die Logik
behandelt alle drei Adressen gleich (PCLK2 statt PCLK1 für die Baudratenberechnung), was auf zwei
weitere APB2-getaktete UART-Instanzen bei ansonsten sonst höheren Adressen hindeutet — passt nicht
zum reinen STM32F103-Standardlayout und deutet auf ein pin-/registerkompatibles Derivat (z. B.
GD32F103- oder AT32F403-Familie mit erweitertem USART-Angebot) oder ein anderes SoC-Package hin.
Nicht abschließend geklärt; betrifft nur die interne Verzweigungslogik von USART_Init, nicht dessen
Namen (Funktion selbst bleibt korrekt benannt, da sie generisch für beliebige USART-Instanzen gilt).

**7 Beschreibungskorrekturen direkt in Control_FW_Function_Tracking_new.md angewendet** (Name
unverändert): GPIO_ConfigPinAsInput, RCC_AHBPeriphResetCmd, RCC_APB1PeriphResetCmd,
RCC_PeriphBitControl, RCC_GetFlagStatus (jeweils fehlende Beschreibung ergänzt), GPIOD_Pin9_Write
(falsche Beschreibung "MPU/Flash Region Protection" ersetzt — Name war korrekt, nur die Beschreibung
falsch) und I2C_BitBang_WriteBytes (veralteter CAN-Aufrufer-Hinweis korrigiert).

**Fehlerquote:** 13/81 klare Namensfehler (16,0 %) + 2 Konsistenz-Hinweise ohne Umbenennungsbedarf.
Damit liegt dieser Cluster über der bisherigen Projekt-Fehlerquote (Ø ca. 6–14 % in den anderen
2026-07-14 re-auditierten Clustern), was den in der Aufgabenstellung vermuteten Schwerpunkt
"Peripherie-Basisadress-Verwechslung" für HAL-nahe Funktionen bestätigt — allerdings primär als
RCC↔FLASH/AFIO- und ADC↔SPI-Verwechslung, nicht wie befürchtet als I2C↔CAN-Verwechslung. Alle
Umbenennungsvorschläge sind **nicht** in Ghidra angewendet — zentrale Dublettenprüfung und
Nutzerentscheidung stehen noch aus (offener Punkt, konsistent mit §13.34/§13.35).

### 13.37 Re-Audit Abschluss Config/EEPROM + OTA/Flash-Cluster (2026-07-14)

Fortsetzung/Abschluss der in §13.33 begonnenen Re-Audit-Kampagne: die verbliebenen 27 von 57
Funktionen im Cluster „Config / EEPROM" sowie 34 von 61 Funktionen im Cluster „OTA / Flash /
SPI-Flash / QSPI" wurden jetzt ebenfalls einzeln per `get-decompilation(includeCallers,
includeCallees)` geprüft. **Beide Cluster stehen damit zu 100 % auf „Re-Audit 2026-07-14"**
(57/57 bzw. 61/61).

**1 Namensfehler mit Codebeleg gefunden** (Vorschlag, **nicht** in Ghidra angewendet):

| Adresse | Alter Name | Neuer Name (Vorschlag) | Begründung |
|---|---|---|---|
| `0x08006f98` | EEPROM_Clear_RebootState | EEPROM_Save_RebootTimestamp (oder EEPROM_Write_RebootDateTime) | Die Funktion initialisiert einen lokalen 8-Byte-Puffer zwar mit 0, überschreibt ihn aber sofort mit `RTC_GetDateTime(&local_10)` und schreibt anschließend diesen (nicht-genullten) Puffer per `EEPROM_Write(0x160, &local_10, 8)`. Es wird also das aktuelle RTC-Datum/-Uhrzeit vor dem Reboot persistiert, nichts wird gelöscht. Einziger Aufrufer `System_Reboot` (direkt vor der eigentlichen Reboot-Auslösung, nach `Config_Save_RuntimeCounters`). Bemerkenswert: `Config_Read_ProductionDate` (0x08006b62) liest denselben EEPROM-Offset 0x160 als 8B-DateTime — das Feld ist also ursprünglich das Produktionsdatum, wird aber vor jedem Reboot mit dem aktuellen Zeitstempel überschrieben (vermutlich als "letzter sauberer Reboot"-Marker missbraucht). Sollte dies stimmen, wäre auch `Config_Read_ProductionDate` ggf. eher `Config_Read_LastRebootOrProductionDate` — hier aber kein Rename-Vorschlag, da ohne weitere Codebelege (z. B. Schreibpfad für das initiale Produktionsdatum ab Werk) nicht sicher unterscheidbar. |

**1 Beschreibungskorrektur** (stale Cross-Reference, Name unverändert): `OTA_Flash_Page_Writer`
(0x0802fdec) referenzierte in der Doku-Beschreibung eine Funktion „OTA_FW_Verify_And_Apply", die im
aktuellen Ghidra-Stand nicht (mehr) existiert — der tatsächliche Callee bei vollständigem
Page-Transfer ist `OTA_FW_Verify_SetStatus` (0x08004efc, bereits in §13.33 re-auditiert). Korrigiert.

**Weitere 33 Beschreibungen ergänzt/präzisiert** (Aufrufer-Kontext, exakte Register-/EEPROM-Offsets,
Byte-Größen aus Hex-Literalen aufgelöst) ohne inhaltlichen Fehlerbefund — Namen jeweils bestätigt,
u. a. für die komplette QSPI-Low-Level-Kette (`QSPI_Flash_IsBusy`, `QSPI_TransferReady_Poll`,
`QSPI_WriteComplete_Check`, `OTA_QSPI_ReadRegion_CalcCRC`, `SPI_Flash_DataChecksum_Calc`), den
internen Flash-Treiber (`Flash_ReadWords`, `Flash_ReadWithECC`, `Flash_ErasePage`,
`Flash_GetStatusFromFlags`, `Flash_Lock`/`Flash_Unlock`, `Flash_ProgramWord`, `Flash_WaitReady`,
`Flash_EraseRegion`, `Flash_WriteRegion`) sowie den OTA-Ablauf-Dispatcher
(`OTA_Update_Dispatcher` → `OTA_Process_Pending_Updates`, `OTA_Slot_Config_Validate`,
`OTA_Slot_Config_Summary_Build`, `OTA_Firmware_Download_Init`, `OTA_PrepareShutdown`,
`OTA_Download_Retry_Handler`, `OTA_StopAllTimers`, `OTA_InitSlotConfig`, `OTA_Flash_Prepare_ByTarget`,
`OTA_Set_SlotStatus`, `OTA_FlashPageWrite_Counter_Increment`) sowie den restlichen Config-Cluster
(diverse `Config_Write_*`/`Config_Set_*`/`Config_Apply_*`-Wrapper und -Terminalfunktionen — bei allen
`Set_`/`Apply_`-benannten Funktionen wurde gezielt auf die in der Aufgabenstellung befürchtete
Get_/Set_-Verwechslung geprüft; **keine einzige gefunden**, alle schreiben tatsächlich).

**Fehlerquote dieser Teilrunde:** 1/61 klarer Namensfehler (1,6 %) + 1 Beschreibungs-Stale-Reference.
Deutlich unter der Fehlerquote des Hardware/HAL-Clusters (§13.36, 16,0 %) und im unteren Bereich der
bisherigen Cluster — plausibel, da Config/EEPROM und OTA/Flash bereits in der ersten Teilrunde
(§13.33) die auffälligsten `Config_Read_*`-eigentlich-Write-Fälle abgefangen hatten und die
verbliebenen Funktionen überwiegend einfache, gut lesbare Wrapper/Register-Writer sind.

**Beide Cluster damit vollständig (100 %) re-auditiert: Config/EEPROM 57/57, OTA/Flash 61/61.**

### 13.38 Re-Audit CH395-Cluster (Ethernet-Controller, 54/54 Funktionen, 2026-07-14)

Vollständige Einzelprüfung aller 54 Funktionen des Clusters „CH395 — Ethernet-Controller" per
`get-decompilation(includeCallers, includeCallees)` — bislang war dieser Cluster nur vom
Dubletten-Fix in Batch 19 (`CH395_Socket_SendData` vs. `_ViaSocketPtr`) berührt worden, nie einzeln
gegen frische Dekompilierung geprüft. Cluster steht jetzt zu **100 % auf „Re-Audit 2026-07-14"**
(54/54).

**Ergebnis: 0 Namensfehler.** Alle 54 Funktionen sind korrekt als `CH395_*` klassifiziert — die
befürchtete Fehlklassifizierung (z. B. reine Socket-Buffer-Verwaltung ohne HW-Zugriff fälschlich als
CH395 benannt, oder umgekehrt echte SPI-Zugriffe generisch benannt) wurde **nicht** gefunden. Die
komplette SPI-Low-Level-Kette (`CH395_SPI_Cmd_WithData`, `_SPI_ReadByte`, `_SPI_WriteCmd`,
`_SPI_CmdWaitReady`, `_SPI_Send_Data`) greift durchgängig über `SPI_BeginCommand`/`SPI_WriteByte`/
`SPI_ReadByte` (generische SPI-HAL-Funktionen, nicht Teil dieses Clusters) auf den Chip zu, mit
CH395-Kommando-Opcodes als erstem Byte (0x2C Version, 0x3C RecvBuf, 0x3B RecvLen, 0x30 SocketStatus,
0x35/0x37/0x38/0x36 Open/Connect/Disconnect/Listen, 0x39 SendData, 0x58/0x56/0x57/0x59/0x31-34
Set-Register) — alle Opcode-Werte in der Doku-Beschreibung stimmen mit dem Code überein. Die
höheren Orchestrierungs-Ebenen (`CH395_Socket_Open_ByDescriptor`, `CH395_Reset_And_Reinit`,
`CH395_MQTT_Init_And_CertSetup`, `CH395_UDP_ServerTask`/`_DataHandler`) rufen konsistent auf die
SPI-Kette bzw. aufeinander durch, keine Fehlzuordnung zu anderen Peripherien (I2C/CAN/UART)
gefunden — anders als beim CAN-Cluster (§13.31, dort 2 I2C-Bitbang-Funktionen fälschlich als CAN
benannt) trat dieses Muster hier nicht auf.

**4 Beschreibungskorrekturen/-ergänzungen** (Namen jeweils unverändert/bestätigt):

- `0x08003644` `CH395_SPI_Send_Data` — hatte keine Beschreibung; ergänzt: CMD 0x39, Kern-Sendefunktion
  mit Socket-Busy-Poll (max. 10×3ms) und Mutex, Byte-für-Byte-Versand über `SPI_WriteByte`. Zentrale
  Funktion, die von praktisch allen anderen CH395-Sendepfaden aufgerufen wird (9 Aufrufer: DNS-Query,
  Modbus-TCP-Handler FC03/06/10, `CH395_ConfigAndSendSocket`, `CH395_SPI_SendData_Verified`,
  `CH395_Socket_SendSafe`, `CH395_Socket_SendData_ViaSocketPtr`).
- `0x08024d80` `CH395_MQTT_Init_And_CertSetup` — hatte keine Beschreibung; ergänzt anhand vorhandenem
  Ghidra-Kommentar (bereits im Dekompilat vorhanden, vermutlich aus früherer Session): orchestriert
  TLS-Zertifikat-Entschlüsselung (`TLS_Cert_Decrypt_All`), MQTT-Session-Init, CRC16 der Zertifikate
  nach EEPROM 0x36B7-0x36BB. 686 Byte groß, 0 Aufrufer im aktuellen Stand gefunden (vermutlich aus
  Main-Loop/State-Machine per Funktionszeiger aufgerufen, nicht direkt referenziert).
- `0x080329b2` `CH395_Socket_SendData_ViaSocketPtr` — hatte keine Beschreibung (Batch-19-Dublette);
  ergänzt: dünner Wrapper, dereferenziert Socket-Pointer (Byte 0 = Socket-Index) und ruft direkt
  `CH395_SPI_Send_Data` auf. 0 Aufrufer im aktuellen Stand.
- `0x080195a4` `CH395_Recv_Buffer_Setup` — Beschreibung war **fachlich falsch** und wurde korrigiert:
  Doku behauptete „DMA Receive Buffer (512B) initialisieren", tatsächlich greift die Funktion an
  keiner Stelle auf SPI/CH395-Hardware zu und es gibt keine DMA-Nutzung. Sie setzt ein Feld im
  CH395-Socket-Deskriptor und ruft dann `CLI_InitSession(buf, size, 0x200)` auf — das ist derselbe
  `CLI_InitSession`, der bereits in §13.31 als Init-Funktion der (dort neu erkannten) generischen
  CLI/AT-Command-Engine identifiziert wurde (18 Funktionen im Bereich `0x0804bd58`-`0x0804cc40`,
  ursprünglich fälschlich als `BLE_*` benannt). Die 512 (0x200) ist also keine DMA-Puffergröße,
  sondern die Session-Puffergröße, die intern in 5 Slices unterteilt wird; Session-Lookup erfolgt per
  Versionsstring „VNSD_0_v1492". Zusätzlicher Fund: **die Funktion hat 0 Aufrufer/Kreuzreferenzen**
  (`find-cross-references` liefert 0 `to`-Referenzen) — vermutlich toter Code oder nur über einen von
  Ghidra nicht aufgelösten Funktionszeiger erreichbar. Name `CH395_Recv_Buffer_Setup` bleibt
  bestehen (kein Rename-Vorschlag), da die Funktion konzeptionell weiterhin zum CH395-Empfangspfad
  gehört (Aufruf-Kontext laut §13.31 aus dem CH395/Modbus-TCP-Empfangspfad), auch wenn sie selbst
  keine SPI-Operation ausführt — reine Beschreibungskorrektur.

**Keine Umbenennungsvorschläge aus diesem Cluster.** Einziger offener Punkt bleibt die in §13.31
bereits gestellte Rückfrage an den Nutzer zur CLI/AT-Command-Engine (mit der `CH395_Recv_Buffer_Setup`
über `CLI_InitSession` verknüpft ist).

**Fehlerquote:** 0/54 Namensfehler (0 %) — mit Abstand die niedrigste Fehlerquote aller bisher
re-auditierten Cluster (vgl. Hardware/HAL 16,0 % in §13.36, Config/EEPROM+OTA 1,6 % in §13.37).
Plausibel: der Cluster wurde ursprünglich sehr systematisch nach CH395-Kommando-Opcodes benannt
(direkter Bezug zum CH395-Datenblatt erkennbar), und die SPI-Low-Level-Funktionen sind strukturell
uniform (Mutex → SPI_BeginCommand → Opcode → optionale Parameter → Generic_StructField_Set_0x10 →
Mutex-Release), was Fehlbenennungen unwahrscheinlich macht.

---

### 13.39 Re-Audit FreeRTOS-Kernel-Cluster (Task/Queue/Timer/Heap, 85 Funktionen, 2026-07-15)

Geprüft wurden alle 44 Funktionen aus der Erstvergabe (Batches 1-17, nie einzeln dekompiliert)
plus eine Stichprobe von 11 der 41 Batch-20-Neuzugänge (2026-07-09) — insgesamt 55/85 (65 %) per
`get-decompilation(includeCallers, includeCallees)` einzeln geprüft.

**Kernbefund: 0 Namensfehler.** Der Cluster ist außergewöhnlich sauber benannt. Grund: FreeRTOS ist
eine bekannte Open-Source-RTOS-Bibliothek, und der Compiler hat in dieser Firmware (Debug-Build mit
`configASSERT`) die **originalen Sourcedatei-Pfade als String-Literale eingebettet**, z. B.
`____SDK_FreeRTOS_src_tasks_c`, `____SDK_FreeRTOS_src_queue_c`, `____SDK_FreeRTOS_src_timers_c`,
`____SDK_FreeRTOS_portable_RVDS_ARM_CM4F` (Assert-Fehlermeldungen `"Error: %s: %d"` mit Dateiname +
Zeilennummer aus dem `assert`-Makro). Diese Strings bestätigen direkt, dass Funktionen wie
`FreeRTOS_eTaskGetState`, `prvAddCurrentTaskToDelayedList`, `prvAddNewTaskToReadyList`,
`prvCheckForValidListAndQueue`, `prvCopyDataFromQueue`, `prvCopyDataToQueue`, `prvDeleteTCB`,
`prvGetDisinheritPriorityAfterTimeout`, `prvQueueSend_CopyAndNotify`, `prvResetNextTaskUnblockTime`,
`prvSwitchTimerLists`, `prvTaskIsTaskSuspended`, `prvUnlockQueue`, `vTaskEnterCritical`,
`vTaskExitCritical`, `vTaskDelay`, `xQueueSend`, `xQueueReceive`, `xTimerStop_Internal`,
`vTaskSwitchContext`, `vTaskPlaceOnEventListRestricted`, `FreeRTOS_xTaskIncrementTick`,
`FreeRTOS_xQueueGenericSend` und `FreeRTOS_xTimerCreateTimerTask` tatsächlich 1:1 den echten
FreeRTOS-internen Funktionsnamen aus `tasks.c`/`queue.c`/`timers.c`/`portable/RVDS/ARM_CM4F` bzw.
`portable/MemMang/heap_4.c` entsprechen — keine Vermutung, sondern verifizierte Fakten.

**Die einzige `medium`-Confidence-Funktion** (`FreeRTOS_Timer_InsertIntoActiveList`, 0x0804aae0,
bereits 2026-07-09 in Batch 18 korrigiert, s. Memory) wurde erneut geprüft: 0 Aufrufer bestätigt
(unverändert seit Batch-18-Korrektur), Logik entspricht exakt `prvInsertTimerInActiveList` aus
FreeRTOS `timers.c` (Vergleich `xNextExpireTime` gegen aktuellen Tick-Count inkl. Overflow-Fall,
Einfügen in Active- oder Overflow-Liste via `vListInsert`). Name und Beschreibung bleiben korrekt,
Konfidenz bleibt bei `medium` mangels Laufzeit-Beobachtung (0 Aufrufer im aktuellen Build — vermutlich
weil Auto-Reload-Timer diesen Pfad über `prvSwitchTimerLists` statt direkt erreichen).

**6 fehlende Beschreibungen ergänzt** (Namen unverändert, alle korrekt): `Task_Init_CreateAll`
(0x0801947c, erstellt 14 Tasks aus Tabelle + startet Scheduler), `prvQueueSend_CopyAndNotify`
(0x0804abdc), `FreeRTOS_vQueueAddToRegistry` (0x080504ac, Queue-Registry-Eintrag),
`vTaskDelay` (0x08050524, 90 Aufrufer FW-weit), `xQueueSend` (0x08053eb0, 77 Aufrufer),
`xQueueReceive` (0x08054370, 61 Aufrufer). Alle sechs sind zentrale, extrem breit verwendete
FreeRTOS-API-Funktionen — ihr Fehlen in der Doku war reine Dokumentationslücke, keine Fehlbenennung.

**Nebenbefund (kein Rename, nur Beobachtung):** Der Cluster enthält zwei strukturell fast identische
First-Fit-Allokatoren mit Block-Splitting: `pvPortMalloc`/`Heap_Init`/`Heap_InsertFreeBlock`
(FreeRTOS-eigener heap_4-Pool, 71.680 Byte, ausschließlich von FreeRTOS-Kernel-Funktionen genutzt)
und `Heap_AllocFromFreeList`/`Heap_Calloc` (separater Pool, Aufrufer sind `malloc`/`heap_Realloc` aus
der Utility/libc-Ecke, nicht Teil des FreeRTOS-Kernels). Beide Heaps koexistieren unabhängig
voneinander — plausible Ursache: newlib-`malloc`-Wrapper vs. FreeRTOS-`pvPortMalloc`, kein
Namensfehler, aber ein Hinweis, dass `Heap_AllocFromFreeList`/`Heap_Calloc` eigentlich besser in den
libc/Heap-Allocator-Cluster (§13.25, in Bearbeitung) gehören als in den FreeRTOS-Kernel-Cluster —
Umsortierung dem zuständigen Cluster-Owner überlassen, keine eigenmächtige Änderung vorgenommen.

**Fehlerquote dieser Teilrunde: 0/55 Namensfehler (0 %).** Mit Abstand die sauberste Teilrunde der
gesamten Re-Audit-Kampagne — konsistent mit der Erwartung, dass eine bekannte, gut dokumentierte
Open-Source-Bibliothek (FreeRTOS) beim Ersteinordnen deutlich weniger fehleranfällig ist als
firmware-eigene Business-Logik-Cluster.

### 13.40 Re-Audit CLI/Debug-Ausgabe/Logging + System/Reset/Shutdown/Watchdog (62 Funktionen, 2026-07-15)

Beide Cluster wurden vollständig geprüft (45 + 17 = 62/62, 100 %), jede Funktion einzeln per
`get-decompilation(includeCallers, includeCallees)`.

**Hauptbefund: systematische Cluster-Fehlklassifizierung, analog zum bekannten BLE/Quectel→CLI-Muster.**
28 der 45 Funktionen im Cluster „CLI / Debug-Ausgabe / Logging" (`0x0804bd80`–`0x0804d008`,
`CLI_DeleteCharForward` bis `CLI_PutChar`) haben mit Debug-Ausgabe/Logging **nichts zu tun** — es handelt
sich um den vollständigen Zeileneditor/Tokenizer/Command-Dispatcher der CLI-Engine: Cursor-Bewegung
(`CLI_CursorForward`, `CLI_CursorLeftRepeat`), Zeichen-Einfügen/-Löschen (`CLI_InsertChar`,
`CLI_DeleteChar`, `CLI_Backspace`), Tokenizer (`CLI_TokenizeLine`, `CLI_TokenizeInput`,
`CLI_StripQuotes`), Argument-Parser (`CLI_ParseNumber`, `CLI_ParseString`, `CLI_ParseEscapeChar`,
`CLI_ParseArgValue`, `CLI_DetectNumberFormat`), Tab-Complete (`CLI_TabComplete`,
`CLI_CommonPrefixLength`), Command-Ausführung (`CLI_ExecuteCommand`, `CLI_ProcessInputLine`,
`CLI_ConfirmAndExecute`), Ausgabe-Formatierung (`CLI_ListCommands`, `CLI_PrintCommandEntry`,
`CLI_ShowHelp`) sowie Low-Level I/O (`CLI_PutChar`). Direkter Call-Graph-Beleg für die Zugehörigkeit
zum bereits existierenden Cluster „CLI / AT-Command-Engine": `CLI_ProcessInputLine` ruft
`CLI_Entry_MatchAndInit` und `CLI_FindEntryByName` auf (beide dort), `CLI_HistoryNavigate` (dort) ruft
`CLI_ClearToEndOfLine` (hier) auf, `CLI_InitSession` (hier) ruft `CLI_Session_Register` (dort) auf,
`CLI_ExecuteCommand` (hier) ruft `CLI_InvokeCommandHandler` (dort) auf. Beide Gruppen bilden
zusammen exakt eine einzige zusammenhängende Untereinheit (Adressbereich `0x0804bd58`–`0x0804d7e4`,
lückenlos). Empfehlung: die 28 Funktionen bei zentraler Bereinigung in „CLI / AT-Command-Engine"
verschieben; die verbleibenden 17 Funktionen (`Debug_Mode_Set`, `EventLog_Record_*`, `debug_printf`,
`log_printf`/`log_SetLevel`/`log_SetEnabled`/`log_SetModeAndLevel`, `Debug_Print*`) sind tatsächlich
Debug/Logging und bleiben korrekt im Cluster. Alle 28 CLI-Funktionsnamen selbst sind aber korrekt und
entsprechen dem tatsächlichen Verhalten — reine Cluster-Zuordnungsfrage, keine Umbenennung nötig.
Nicht selbst verschoben (Anweisung: zentrale Prüfung vor Cluster-Umzug).

**Ein echter Namensfehler im System/Reset-Cluster:** `Reset_Command_Wrapper` (`0x08004838`) hat
keinerlei Bezug zu System-Reset. Die Funktion ist ein 1-Zeilen-Wrapper um `CH395_SPI_Cmd_WithData`
und wird ausschließlich von `CH395_Debug_PrintVersion` mit einem beliebigen SPI-Kommando-Byte
aufgerufen, um die CH395-Ethernet-Chip-Version per Debug-Ausgabe abzufragen — keine
Register-/Peripherie-Reset-Semantik, wie es der bisherige Name suggeriert. Vermutliche
Namensentstehung: `SPI_BeginCommand(6)` innerhalb der aufgerufenen `CH395_SPI_Cmd_WithData` könnte
mit einem CH395-Reset-Opcode verwechselt worden sein, ist aber ein fest codiertes generisches
Lese-Kommando, kein Reset. Rename- und Cluster-Verschiebungsvorschlag s. Abschlussantwort/Tabelle;
nicht selbst umbenannt.

**Kleinere Beschreibungskorrektur:** `MainLoop_Periodic_Tasks` (`0x0802d268`) hatte die
irreführende Angabe „(13 Aufrufer)" — tatsächlich hat die Funktion nur **1** Aufrufer
(`App_MainLoopDispatcher`) und ruft ihrerseits 13 Subsystem-Funktionen auf. Beschreibung auf
„(13 aufgerufene Subsysteme; 1 Aufrufer)" präzisiert.

**8 fehlende Beschreibungen ergänzt** (Namen unverändert, alle korrekt verifiziert): `debug_printf`,
`log_printf`, `Log_SetModeAndLevelCallback`, `Debug_PrintErrorAndEventLog`, `Debug_PrintWifiStatus`,
`Debug_PrintModbusAddress` (Cluster CLI/Debug), sowie `Factory_Reset` und `System_Reboot`
(letztere hatte bereits einen hilfreichen Ghidra-Funktionskommentar zum NVIC-AIRCR-Reset, der in
die Doku-Beschreibung übernommen wurde) im Cluster System/Reset.

**Fehlerquote dieser Teilrunde:** 1 echter Namensfehler unter 62 geprüften Funktionen (1,6 %) plus
1 struktureller Cluster-Fehlklassifizierungs-Befund, der 28 Funktionen betrifft (62 % des
CLI/Debug-Clusters, 45 % der Gesamtmenge dieser Runde) — die Namen selbst sind bei allen 28 korrekt,
nur die thematische Einsortierung nicht. Damit reiht sich der Befund konsistent in das bereits aus
BLE/Quectel→CLI-Ausgliederung bekannte Muster ein: die CLI-Engine wurde beim Ersteinordnen mehrfach
in falsche Nachbar-Cluster verteilt.

### 13.41 Re-Audit Abschluss MQTT-Cluster + Quectel-Modem/WiFi/AT-Cluster (2026-07-15)

Beide zuvor nur teilweise geprüften Cluster wurden auf 100 % gebracht: `## MQTT —
Client/Protokoll/Payload` (101/101, davor 14/101 mit "Re-Audit 2026-07-14" markiert) und
`## Quectel-Modem / WiFi / AT-Commands` (60/60, davor 14/60 markiert). Insgesamt **133 zuvor
ungeprüfte Zeilen** (87 MQTT + 46 Quectel) wurden per `get-decompilation(includeCallers,
includeCallees)` gegen Name/Beschreibung verifiziert — deutlich mehr als die ursprünglich geschätzten
36 (MQTT) bzw. 10-15 (Quectel) offenen Zeilen; die Schätzung basierte offenbar auf einer Verwechslung
zwischen "Beschreibung vorhanden" und "einzeln am Code re-verifiziert".

**Kernbefund: 0 Namensfehler in beiden Clustern.** Kein einziger Rename-Vorschlag aus 133 geprüften
Funktionen — beide Cluster waren bereits vor dieser Runde sauber benannt (MQTT-Protokoll-Engine und
Quectel-AT-Command-Schicht sind offenbar besonders sorgfältig in früheren Batches benannt worden).

**4 Beschreibungskorrekturen/-ergänzungen:**
- `MQTT_BuildPvDataResponse` (0x0801bf08): "4 Strings V/I/P/State" präzisiert zu "4 PV-Strings (PV1-4),
  je Power/Voltage/Current/State als int" — cJSON_CreateInt, keine Text-Strings.
- `MQTT_Clear_SubscriptionSlots` (0x0801d342): präzisiert — Code löscht bei Stride 8B nur das erste
  4B-Feld (Topic-Pointer) pro Slot, nicht den vollen 8B-Slot.
- `MQTT_Calc_Remaining_Length` (0x0801dac8): Beschreibung war sachlich falsch ("Remaining-Length für
  PUBLISH/PUBACK"). Tatsächlich einziger Aufrufer ist `MQTT_Serialize_Connect` — Funktion berechnet
  die Remaining-Length für das CONNECT-Paket (Protokollname/Version + Client-ID + optional
  Will-Topic/Message + Username/Password über `MQTT_String_ResolveLength`).
- `Quectel_MQTT_OTA_Info_Parser` (0x08022b4c): hatte GAR KEINE Beschreibung. Neu ergänzt: parst einen
  per MQTT empfangenen "key=value"-String (strtok) für bis zu 4 Device-OTA-Slots (mod/type/size/crc/
  url_len/url, URL bis 0xE6 Byte über mehrere Tokens zusammengesetzt) und schreibt nach vollständigem
  Parse-Durchlauf die OTA-Zieldaten je Slot per `Config_URLSlot_AddressSelect` +
  `Flash_EraseAddressRange` + `Flash_Write_Protected` in den Flash, mit Rücklese-Verifikation via
  `Flash_Read_Protected`. 0 Caller im Disassembly (vermutlich Callback aus MQTT-JSON-RPC-Dispatch).
  Name bleibt trotz Flash-Schreibanteils sachlich vertretbar (Parser als Kernfunktion des Ablaufs).

**Nebenbefunde ohne Doku-Änderung:**
- `MQTT_Topic_StringCompare`: ruft intern eine als `atoi` gelabelte Funktion mit 3 Parametern
  (ptr, ptr, len) auf — Ghidra-Thunk-Fehllabel, tatsächliches Verhalten entspricht memcmp
  (0 bei Gleichheit nach Längenvergleich). Bestehende Beschreibung "strlen+memcmp" war bereits korrekt.
- `MQTT_KeepAlive_SendPing` löst Disconnect nicht selbst aus, sondern setzt nur Fehlerstatus -1 bei
  unbeantwortetem Ping; der eigentliche Disconnect erfolgt im Aufrufer `MQTT_Process_IncomingPacket`.
- `Quectel_HTTP_GET_Request`/`Quectel_HTTP_ReadResponse`/`Quectel_HTTP_Config_SSLCtxId` rufen intern
  eine Funktion namens `HTTP_POST_Request` (0x0800bcc4) auf — generischer AT-Executor trotz
  POST-spezifischem Namen, für spätere HTTP-App-Layer-Re-Audit-Runde (Task #27) vermerkt.
- Mehrfach bestätigte Caller-Zahlen aus der bestehenden Doku (exakt nachgezählt, keine Abweichung):
  `MQTT_BuildErrorResponse` 42, `MQTT_RPC_BuildSetResult` 16, `MQTT_JSON_CreateResponseEnvelope`/
  `MQTT_JSON_SerializeAndSend` je 11, `MQTT_JSON_AddTypedValue` 10, `MQTT_ParseRpcParams` 9,
  `MQTT_Transport_ReceiveAll` 5, `MQTT_Encode_RemainingLength` 6, `MQTT_CalcPacketSize` 3.

**Fehlerquote dieser Teilrunde: 0/133 Namensfehler (0 %).** Beide Cluster sind damit vollständig
(101/101 MQTT, 60/60 Quectel) und Dubletten-frei geprüft — zentraler Dublettenscan über beide Cluster
nach Abschluss ergab 0 doppelte Funktionsnamen.

---

### 13.42 Re-Audit Utility/Byte-Helpers-Cluster + Sonstiges/Noch-nicht-kategorisiert (66 Funktionen, 2026-07-15)

Beide zuvor nie einzeln geprüften Cluster `## Utility / Byte-Helpers / Timer-Helpers` (43 Funktionen) und
`## Sonstiges / Noch nicht kategorisiert` (23 Funktionen) wurden vollständig per `get-decompilation`
(inkl. Caller/Callee) verifiziert — 66/66, aufgeteilt auf 3 parallele Teilprüfungen (22/22/22).

**Ergebnis: 2 echte Namensfehler, 25 Beschreibungskorrekturen/-ergänzungen (bereits angewendet), 23
Cluster-Umsortierungsvorschläge für den Sonstiges-Cluster.**

**Vorgeschlagene Umbenennungen (NICHT angewendet, zentrale Dublettenprüfung steht noch aus):**

| Adresse | Alter Name | Neuer Name | Begründung |
|---|---|---|---|
| `0x0800685a` | TLV_Record_Skip | DNS_QuestionRecord_Skip | Kein generisches TLV-Skip: ruft fest `DNS_Name_Decompress` auf und überspringt Name+TYPE+CLASS (+4 Byte), kein RDLENGTH/TTL wie bei DNS-Answer-Records. Einziger Aufrufer `DNS_ParseResponseHeader` (Question-Section-Loop) — Funktion ist DNS-spezifisch. |
| `0x0802dd5e` | DataStream_ReadNext | Timeout_RefreshAndGetTicksRemaining | Liest keine Stream-Bytes, sondern ruft (wie `Timeout_IsExpired`) `FreeRTOS_xTaskCheckForTimeOut` auf demselben Timeout-Struct-Typ auf und gibt die aktualisierte "Ticks-Remaining"-Zahl zurück. In `MQTT_ReceivePacket`/`MQTT_Transport_ReceiveAll` wird derselbe Timeout-Pointer abwechselnd mit `Timeout_IsExpired` UND dieser Funktion aufgerufen — Ergebnis dient als Timeout-Parameter für den Socket-Read-Callback, kein gelesenes Datenbyte. |

**Bug-Verdacht (dokumentiert, nicht behoben):** `Parse_TimeString_To_HourMinute` (0x0802dccc) kodiert laut
Disassembly NICHT `hour<<8|min` wie bisher dokumentiert, sondern `hour << (min+8)` (variable Schiebeweite
statt fixem Byte-Pack) — bei größeren Minutenwerten geht die Stunde durch Bitüberlauf/-verschiebung
potenziell verloren. Wirkt wie ein echter Firmware-Bug, kein reines Doku-Problem; Beschreibung entsprechend
korrigiert, keine Code-Änderung vorgenommen (Projekt-Konvention: keine spekulativen Fixes ohne weitere
Verifikation der Auswirkung).

**25 Beschreibungskorrekturen direkt in `Control_FW_Function_Tracking_new.md` angewendet** (Quelle-Spalte
auf "Re-Audit 2026-07-14" gesetzt), davon 14 im Utility-Cluster (u. a. `LZ77_Decompress` — dritter Modus
Zero-Run/RLE war nicht dokumentiert; `Periodic_RTC_Display_Format` — Beschreibung sprach irreführend von
"Sensor-Daten" statt RTC-Datum; `Util_CalcHalfSizeCapped` — "max 48" suggerierte einen Ergebnis-Cap,
tatsächlich ist es eine Eingabegrenze mit Fallback 0; `RTOS_Delay_Ms` — "ISR vs. Task" war ungenau,
tatsächlich Scheduler-State-abhängig via `xTaskGetSchedulerState`) und 11 im Sonstiges-Cluster (wichtigster
Fund: `DateTime_Validate_NoNull` hatte eine Beschreibung, die das GENAUE GEGENTEIL des Codes behauptete —
"mit Null-Pointer-Check" statt korrekt "ohne").

**Cluster-Umsortierungsvorschläge für „Sonstiges" (23/23 Funktionen ließen sich einem bestehenden Thema
zuordnen — der Cluster ist nach dieser Prüfung inhaltlich vollständig auflösbar, nicht umgesetzt, nur
Vorschlag):**

| Adresse | Name | Vorgeschlagener Cluster |
|---|---|---|
| `0x08000268` | Get_ActiveIRQn | Hardware/HAL (Cortex-M-Systemregister, einziger Aufrufer FreeRTOS-Portschicht) |
| `0x08001814` | ProcessFirmwareUpdateCommand | OTA/Flash |
| `0x08003dd0` | CRC16_Calculate | CRC16/Checksum-System |
| `0x08004844` | Serial_Packet_Validate | BLE (einziger Aufrufer verteilt nur BLE_Cmd_*) |
| `0x08004888` | Device_Network_Info_Init | Netzwerk/DNS |
| `0x080049ec` | Voltage_Stability_Check | Relay/CT-Power-Control |
| `0x08004b24` | Status_Bitfield_Update | Config/EEPROM |
| `0x08004c7c` | DateTime_Validate | Hardware/HAL (RTC) |
| `0x08005230` | DateTime_Validate_NoNull | Hardware/HAL (RTC) / Config/EEPROM |
| `0x080054e0` | Retry_Until_Success_Or_Limit | OTA/Flash (QSPI-Polling) |
| `0x08005500` | Standby_Wakeup_Debounce | Relay/CT-Power-Control |
| `0x080068ac` | Stats_Clear_Counters | Config/EEPROM |
| `0x080071c4` | Display_Cycle_DataSources | Event-Log/Zeitplan-Engine |
| `0x08012d8c` | Generic_StructField_Set_0x14 | Utility/Byte-Helpers (17 Aufrufer über völlig verschiedene Subsysteme) |
| `0x08012d90` | Generic_StructField_Set_0x10 | Utility/Byte-Helpers (44 Aufrufer, gleiches Muster) |
| `0x0801d084` | Relay_StagedTimingControl | Relay/CT-Power-Control |
| `0x08025eac` | Event_Params_Pack | MQTT |
| `0x08025eb2` | Serial_Command_Dispatch | BLE |
| `0x08026344` | DeviceInfo_BuildStatusString | Netzwerk/HTTP-App-Layer/Cloud-Reporting |
| `0x0802d00c` | Unused_FuncCall_Wrapper | Debug/Logging |
| `0x0802d018` | TimePlan_Evaluate_Setpoint | Event-Log/Zeitplan-Engine |
| `0x0804fe20` | Read_Serializer | Modbus/RS485 |
| `0x08050f20` | Write_Handler | Modbus/RS485 |

**Fehlerquote dieser Teilrunde: 2/66 Namensfehler (≈3 %), 25/66 Zeilen mit Beschreibungsbedarf (≈38 %,
davon 5 mit sachlich irreführendem/falschem statt nur fehlendem Inhalt).** Kein doppelter Funktionsname
unter den 66 geprüften Adressen festgestellt.

---

### 13.43 Re-Audit Netzwerk/DNS/Sockets + HTTP/HTTPS-App-Layer + Cloud-Reporting (70 Funktionen, 2026-07-15)

Alle 70 Funktionen der drei thematisch verwandten Cluster `Netzwerk / DNS / Sockets (allgemein)` (29),
`HTTP/HTTPS — App-Layer` (18) und `Cloud-Reporting` (23) wurden einzeln per `get-decompilation`
(inkl. Caller/Callee) geprüft. Fokus lag laut Auftrag auf Transport-Layer-Verwechslungen
(TCP/UDP/DNS), analog zum bekannten Quectel-Fehlermuster aus früheren Runden.

**Kernbefund: generischer sprintf-Wrapper als "Cloud_Telemetry_JSON_Builder" fehletikettiert.**
Die Funktion `Cloud_Telemetry_JSON_Builder` (`0x080303bc`) ist ein reiner sprintf/vsprintf-Wrapper
(ruft intern nur `printf_Format_Engine` + `sprintf_Output_Char` auf, ohne jeden Cloud- oder
JSON-Bezug). Sie hat **39 Aufrufer quer durch praktisch jeden Cluster der Firmware**: BLE-GATT-Namen
(`BLE_Set_Device_Name`), MQTT-Topic-Aufbau (`MQTT_Topic_Builder`), Quectel-AT-Kommandos
(`Quectel_HTTP_GET_Request`, `Quectel_MQTT_Subscribe`, `Quectel_WiFi_SetSTAInfo_NoSave`,
`Quectel_SSL_Certificate_Manage`, u.v.a.), cJSON-Serialisierung (`cJSON_PrintNumber`,
`cJSON_PrintStringPtr`), DNS/Broadcast-Strings (`Network_BroadcastAddr_ComputeAndLog`), TCP-Close
(`TCP_Socket_Close`, `Cloud_Close_TCP_Connection`) sowie tatsächliche Cloud-Reporting-Stellen. Der
Name suggeriert eine auf Cloud-Telemetrie-JSON spezialisierte Funktion, tatsächlich ist es die
zentrale generische String-Formatierungsprimitive der gesamten Firmware — vergleichbar mit der
bereits bekannten `snprintf` (`0x08030388`), nur ohne Längenbegrenzung. Umbenennungsvorschlag:
`sprintf` (passt zur bestehenden Namenskonvention neben `snprintf`).

**Folgebefund: BLE-GATT-Notify-Hexencoder-Kette fälschlich unter "Cloud_" einsortiert.** Die Kette
`Cloud_Format_And_Send_Byte` (`0x08004808`) → `Cloud_Format_And_Send_Buffer` (`0x0800b7dc`) →
`Cloud_Transmit_Byte_Blocking` (`0x0802fa58`) hat **ausschließlich** `BLE_GATT_Notify_WithData` und
`BLE_GATT_Notify_Send` als (indirekte) Aufrufer. Die Funktionen kodieren ein Byte als 2
ASCII-Hex-Zeichen (via o. g. sprintf-Wrapper) und senden diese blockierend per UART
(`USART_SendData` + Status-Poll) — reine BLE-GATT-Notify-Payload-Übertragung zum Quectel-Modul,
kein Bezug zu Cloud-Reporting. Vermutlich historisch falsch einsortiert, weil der generische
Formatierungs-Helfer fälschlich als "Cloud"-Funktion galt und die Namensgebung diesen Fehler
weitervererbt hat.

**Folgebefund (bereits von paralleler Session in 13.41 vorab notiert, hier vertieft):
`HTTP_POST_Request` ist ein generischer Quectel-AT-Executor, nicht POST-spezifisch.**
`HTTP_POST_Request` (`0x0800bcc4`) sendet ein beliebiges AT-Kommando (param_1) per UART, wartet auf
Notify (max. 400 Ticks) + Delay, und prüft die Antwort auf 1–2 Teilstrings. Sie wird aufgerufen von
`Quectel_HTTP_GET_Request` (HTTP**GET**!), `Quectel_HTTP_ReadResponse` (AT+QHTTPREAD),
`Quectel_HTTP_Config_SSLCtxId` (AT+QHTTPCFG, SSL-Konfiguration) UND von den eigentlichen
POST-Reporting-Stellen (`HTTP_Cloud_Reporting_Dispatcher`, `Cloud_Reporting_setVenusDReporting`).
Der Name "POST_Request" trifft also nur einen Teil der tatsächlichen Verwendung. Davon klar zu
unterscheiden ist `HTTPS_POST_Request` (`0x08014dc0`) — ein komplett separater, korrekt benannter
Pfad, der über CH395-Ethernet (nicht Quectel-AT) tatsächlich einen TCP-Socket öffnet, einen
HTTP-Request-Buffer baut und sendet; keine Verwechslung der beiden Funktionen untereinander
festgestellt.

**Alle übrigen 66 Funktionen** (Netzwerk/DNS-Cluster komplett: `Network_ProtocolDispatcher`,
`DNS_ResourceRecord_Parse`, `DNS_Name_Decompress`, `DNS_Query_Build`/`_Send`,
`DNS_ParseResponseHeader`, `TCP_Socket_Close`, `Network_TransportDispatch`,
`Protocol_AA_*`-Familie, u.a.; HTTP/HTTPS-Cluster: alle Parser/Builder für P1-Meter, EcoTracker,
StormOne-Meter, Economy/TOU, llhttp-Response-Parse; Cloud-Reporting: alle `Cloud_Report_Fill*`,
`Cloud_Config_Apply`, `Cloud_Response_Action`, `Cloud_EdgeDetectAndWatchdog`,
`Cloud_HTTP_Response_Parser`, `Cloud_Report_URL_Builder`) wurden verhaltensgleich zu Name/Beschreibung
befunden — keine Transport-Layer-Verwechslungen (TCP/UDP/DNS) wie im Quectel-Cluster gefunden. Eine
kleinere thematische (nicht Namens-)Anmerkung: `Protocol_AA_CommandDispatch` und die
`Protocol_AA_Set*`/`Protocol_AA_EnqueueCommand`/`Protocol_AA_RS485Forward`-Familie werden
ausschließlich aus dem CAN-Bus-Cluster (`CAN_FrameDispatcher`) heraus aufgerufen und gehören
inhaltlich eher zu CAN-Bus/Parallelbetrieb als zu Netzwerk/Sockets — die Funktionsnamen selbst sind
aber korrekt, nur die Cluster-Zuordnung in der Doku-Struktur ist historisch gewachsen.

**8 fehlende Beschreibungen ergänzt** (Namen dabei unverändert gelassen, nur Beschreibungsspalte):
`HTTP_Cloud_Reporting_Dispatcher`, `HTTP_Economy_TOU_Parser`, `HTTPS_POST_Request`,
`HTTP_Response_Parse` (HTTP/HTTPS-Cluster); `Network_HeartbeatHandler`,
`Network_ReceiveAndDispatchData` (Netzwerk-Cluster); `Cloud_Report_URL_Builder`,
`Cloud_Reporting_setVenusDReporting`, `Cloud_HTTP_Response_Parser`, `Cloud_Config_Apply`,
`Cloud_Response_Action` (Cloud-Reporting-Cluster). Bei `HTTP_POST_Request`, `Cloud_Format_And_Send_Byte`
und `Cloud_Format_And_Send_Buffer` wurde die Beschreibung ebenfalls ergänzt, jedoch mit
Namens-Verdacht-Vermerk (s. o.), da hier Name und Verhalten auseinanderlaufen.

**Umbenennungsvorschläge (Anwendung nach zentraler Dublettenprüfung, nicht selbst durchgeführt):**

| Adresse | Alter Name | Neuer Namensvorschlag | Begründung |
|---|---|---|---|
| `0x080303bc` | Cloud_Telemetry_JSON_Builder | `sprintf` | Reiner sprintf/vsprintf-Wrapper (printf_Format_Engine + sprintf_Output_Char), 39 Aufrufer quer durch alle Cluster, kein Cloud-/JSON-Bezug; Name passt zur bestehenden `snprintf`-Konvention |
| `0x08004808` | Cloud_Format_And_Send_Byte | `BLE_GATT_HexByte_Send` (o.ä.) | Formatiert Byte als 2 Hex-ASCII-Zeichen, sendet via UART; einziger Aufrufer-Pfad ist BLE-GATT-Notify, kein Cloud-Bezug |
| `0x0800b7dc` | Cloud_Format_And_Send_Buffer | `BLE_GATT_HexBuffer_Send` (o.ä.) | Schleife über obige Funktion, ausschließlich aus BLE_GATT_Notify_WithData/Send genutzt |
| `0x0802fa58` | Cloud_Transmit_Byte_Blocking | `UART_TransmitByte_Blocking` (o.ä.) | Generischer blockierender USART-Byte-Versand ohne jeden Cloud-Bezug; einziger Aufrufer ist obige BLE-Hexencoder-Kette |
| `0x0800bcc4` | HTTP_POST_Request | `Quectel_HTTP_AT_SendAndVerify` (o.ä.) | Generischer Quectel-AT-Executor (Kommando senden + Notify/Delay + Substring-Check), wird für GET/READ/SSL-Config UND POST gleichermaßen verwendet — "POST" trifft nur einen Teil der Aufrufer |

**Fehlerquote dieser Runde:** 5 Namens-Verdachtsfälle unter 70 geprüften Funktionen (7,1 %), davon
1 Fall mit besonders großer Tragweite (39 Aufrufer quer durchs gesamte Firmware-Image). Zusätzlich
1 rein struktureller Cluster-Zuordnungs-Hinweis (Protocol_AA-Familie, Namen korrekt) ohne
Umbenennungsbedarf. Keine TCP/UDP/DNS-Transport-Verwechslungen im engeren Sinn gefunden — das aus
dem Quectel-Cluster bekannte Muster wiederholt sich hier nicht 1:1, stattdessen dominieren
generische Helper-Funktionen, die nach ihrem (nicht repräsentativen) Erstverwendungszweck benannt
wurden.

---

### 13.44 Re-Audit libc/Standardbibliothek + Fixed-Point-Math (fp64)/dtoa + Heap-Allocator (78 Funktionen, 2026-07-15)

Alle 78 Funktionen der drei thematisch verwandten Cluster `libc / Standardbibliothek / Speicher-Utilities`
(45), `Fixed-Point-Math (fp64) / dtoa / Float-Formatting` (28) und `Heap-Allocator (intern)` (5) wurden
einzeln per `get-decompilation` (inkl. Caller/Callee) geprüft und für libc-Funktionen gegen die bekannte
Standard-C-API-Signatur, für fp64/dtoa gegen den erwarteten IEEE-754-Ablauf verglichen.

**Kernbefund 1: Zwei vertauschte libc-Namen im "atoi"-Cluster.**
- `0x080009c0` heißt `atoi`, implementiert aber einen reinen 3-Parameter-Byte-Vergleich
  (`for (i=0;i<n && s1[i]==s2[i] && s1[i]!=0; i++)`), ohne jede Zahl-Konvertierung — das ist `strncmp`,
  nicht `atoi`. Aufrufer wie `CLI_FindEntryByName`, `MQTT_Topic_StringCompare`, `cJSON_Parse_Value`
  nutzen es exakt als Gleichheitsprüfung (`if (iVar2 == 0)`), passend zu strncmp.
- `0x08000cc6` heißt `atoi_u16`, implementiert aber exakt Standard-`atoi`-Verhalten: ruft
  `strtol(s,NULL,10)` auf und stellt anschließend errno wieder her — keinerlei 16-Bit-Spezifik. 73
  Aufrufer (u. a. `HTTP_ParseContentLengthHeader`, `Meter_ExtractValue_ByKey`, `AT_Response_Parser`)
  nutzen es generisch für beliebige Int-Konvertierung.
- Die beiden Fehlbenennungen sind vermutlich historisch miteinander verknüpft (ein früherer Batch hat
  vermutlich versucht, "atoi" zu vergeben und dabei auf die falsche Funktion gezielt bzw. die echte
  atoi-Funktion vorsorglich umbenannt, um den Namenskonflikt zu vermeiden).

**Kernbefund 2: `strncat` ist tatsächlich `strchr`.**
`0x08000956` heißt `strncat`, hat aber nur 2 Parameter `(ptr, char)` statt der für strncat nötigen
`(dest, src, n)`. Der Code sucht linear nach dem übergebenen Einzelzeichen im String und gibt bei
Fund einen Pointer darauf zurück, sonst NULL — exakt `strchr(s, c)`. Alle 11 Aufrufer (`DNS_Query_Build`,
`HTTP_URL_ExtractPath`, `MQTT_Config_ExtractStringValue`, `MQTT_JSON_Payload_EnsureBracePrefix` u. a.)
übergeben Ein-Byte-Trennzeichen wie `.`, `/`, `;`, `{` — passend zu strchr, nicht zu strncat.

**Kernbefund 3 (größte Tragweite): `dtoa_Float_To_String` ist tatsächlich `pow()`, keine Float→String-
Konvertierung.** Die 2900 Byte große Funktion `0x080305b8` wurde bislang als "dtoa" (double-to-ASCII)
eingeordnet, implementiert aber x^y für zwei fp64-Operanden: Sonderfälle für 0^y/x^0/x^1/x^-1, Sqrt-
Kurzschluss (y=0,5, ruft `fp64_sqrt_WithExceptionCheck`), Quadrier-Kurzschluss (y=2, ruft
`dtoa_Square_Constant_A/B`), Overflow-Pfad (`fp_Set_Exception(2)` + `dtoa_Generate_Infinity`), und für
den allgemeinen Fall eine klassische Bereichsreduktion mit Tabellen-Lookup + Horner-Polynom-Auswertung
(`fp64_Polynomial_Eval`) — der Standard-Aufbau einer Software-`pow(x,y) = exp(y·log(x))`-Implementierung.
Der **einzige Aufrufer** ist `cJSON_Parse_Number` (JSON-Zahlen-Parser), der die Funktion als
`pow(10, exponent)` aufruft, um die Mantisse beim Parsen von Exponentialschreibweise ("1.5e10") zu
skalieren — nicht um einen Double in einen String zu konvertieren. Damit sind auch die drei
Hilfsfunktionen `dtoa_Generate_Infinity`, `dtoa_Square_Constant_A` und `dtoa_Square_Constant_B`
fehlklassifiziert: Sie gehören zum Overflow-Pfad von `pow()`, nicht zu einer dtoa-Routine. Die
tatsächliche "double → Dezimalstring"-Funktionalität der Firmware liegt weiterhin bei
`printf_Float_To_Digits` (unverändert, Name korrekt) — eine separate, bereits korrekt benannte
Funktion. Der Cluster-Titel "Fixed-Point-Math (fp64) / dtoa / Float-Formatting" ist also insofern
irreführend, als es in diesem Cluster **keine echte dtoa-Implementierung** gibt — nur eine fälschlich
so benannte pow()-Funktion.

**Randnotiz (kein Namensfehler, aber Dekompilierungs-Einschränkung):** `fp64_div` (`0x08000fc0`) und
`fp64_cmp_ge` (`0x08000ff0`) zeigen in Ghidra identischen, nur 9-zeiligen Dekompilat-Code trotz
unterschiedlicher Adressen und laut Aufruf-Kontext unterschiedlicher Aufgaben (Caller übergeben je 4
Parameter, während Ghidra nur 2 erkennt) — vermutlich ARM-Assembly mit bedingter Ausführung (IT-Block)
oder VFP-Koprozessor-Instruktionen, die die einfache Dekompilierung nicht auflöst. Die Namen sind laut
Aufrufkontext (Divisions- bzw. Vergleichs-Operationen an den erwarteten Stellen in `fp64_floor`,
`printf_Float_To_Digits`, `cJSON_Parse_Number`) weiterhin plausibel, wurden aber nur mit "medium"-
Konfidenz belassen; eine vollständige manuelle Disassembly-Prüfung wäre nötig, um die Signaturlücke zu
schließen — außerhalb des Umfangs dieser Runde.

**24 fehlende Beschreibungen ergänzt** (Namen dabei unverändert gelassen, nur Beschreibungsspalte):
`memcpy`, `memset`, `strstr`, `strncpy`, `strlen`, `strcmp`, `memcmp`, `strtok`, `sscanf_Format_Parser`,
`printf`, `snprintf`, `putchar`, `printf_Format_Engine` (libc-Cluster); `fp64_add`, `fp64_sub`,
`fp64_neg`, `fp64_mul`, `int_to_fp64`, `uint_to_fp64`, `fp64_to_int`, `fp64_to_uint`, `fp64_div`,
`fp64_cmp_ge`, `fp64_abs_cmp`, `fp64_normalize`, `fp64_sqrt_WithExceptionCheck` (fp64-Cluster). Bei
`atoi`, `strncat`, `atoi_u16`, `dtoa_Float_To_String`, `dtoa_Generate_Infinity`,
`dtoa_Square_Constant_A/B` wurde die Beschreibungsspalte mit "Name falsch" bzw. Verweis auf den
Umbenennungsvorschlag ergänzt statt einer regulären Beschreibung.

**Umbenennungsvorschläge (Anwendung nach zentraler Dublettenprüfung, nicht selbst durchgeführt):**

| Adresse | Alter Name | Neuer Namensvorschlag | Begründung |
|---|---|---|---|
| `0x080009c0` | atoi | `strncmp` | 3 Parameter (s1,s2,n), reiner Byte-Vergleich bis Mismatch/Nullterminator, keine Zahl-Konvertierung — entspricht strncmp |
| `0x08000cc6` | atoi_u16 | `atoi` | Ruft strtol(s,NULL,10) auf, stellt errno wieder her — exaktes Standard-atoi-Verhalten. Nur möglich, sobald 0x080009c0 umbenannt ist (Namenskollision) |
| `0x08000956` | strncat | `strchr` | 2 Parameter (ptr,char) statt (dest,src,n); sucht Einzelzeichen im String, gibt Pointer oder NULL zurück — entspricht strchr(s,c) |
| `0x080305b8` | dtoa_Float_To_String | `fp64_pow` | Implementiert x^y (Sonderfälle 0^y/x^0/x^-1, sqrt via y=0,5, Quadrieren via y=2, Bereichsreduktion+Polynom für Allgemeinfall) — Standard-C pow(), keine Float→String-Konvertierung. Einziger Aufrufer cJSON_Parse_Number nutzt es als pow(10,exponent) |
| `0x08031350` | dtoa_Generate_Infinity | `fp64_pow_OverflowInfinity` (o. ä.) | Overflow-Rückgabepfad von pow() (0x080305b8), nach fp_Set_Exception(2) aufgerufen — abhängig von obigem Rename |
| `0x080313b8` | dtoa_Square_Constant_A | `fp64_pow_OverflowConst_A` (o. ä.) | Quadriert Overflow-Konstante zur Erzeugung eines korrekt geflaggten +Inf im pow()-Overflow-Pfad — abhängig von obigem Rename |
| `0x080313d8` | dtoa_Square_Constant_B | `fp64_pow_OverflowConst_B` (o. ä.) | Wie 0x080313b8, zweite Variante — abhängig von obigem Rename |

**Fehlerquote dieser Runde:** 7 Namensfehler unter 78 geprüften Funktionen (9,0 %) — davon 3 direkte
API-Verwechslungen mit hoher Aufrufer-Reichweite (atoi↔strncmp, strncat→strchr, insgesamt 90+ Aufrufer
betroffen) und 4 zusammenhängende Fehlklassifikationen im vermeintlichen "dtoa"-Bereich, die sich als
Teile einer `pow()`-Implementierung herausstellten. Cluster `Heap-Allocator (intern)` (5/5) fehlerfrei.
Von den 28 fp64-Funktionen waren 21 bereits korrekt benannt und dokumentiert, 3 (Generate_Infinity,
Square_Constant_A/B) thematisch fehlklassifiziert (Name beschreibt die Mechanik korrekt, aber falscher
Funktionsbereich/Cluster), 1 (Float_To_String) komplett falsch klassifiziert. Von den 45 libc-Funktionen
waren 42 korrekt, 3 fehlerhaft (atoi, atoi_u16, strncat).

### 13.45 Re-Audit llhttp-Cluster (HTTP-Parser, Vendor-Lib, 96 Funktionen, 2026-07-15)

Alle 96 Funktionen des Clusters `llhttp — HTTP-Parser (Vendor-Lib)` wurden erstmals einzeln per
`get-decompilation` (inkl. Caller/Callee) geprüft — zuvor war in diesem Cluster nur ein Dubletten-Fix
(8 Bit-Test-Helfer in Batch 19) erfolgt, nie eine inhaltliche Einzelprüfung. Geprüft wurden alle 51
Funktionen ohne Beschreibung (Konfidenz "-"), alle 7 Funktionen mit "medium"-Konfidenz, sowie eine
großzügige Stichprobe zentraler Dispatcher/Parser-Callbacks aus dem bereits dokumentierten
"high"-Bestand — insgesamt **75 von 96 Funktionen** individuell verifiziert.

**Kernbefund: Cluster ist zu ~100 % korrekt benannt — kein einziger Fehlbenennungsfall gefunden.**
Das unterscheidet diesen Cluster deutlich von den bisherigen Re-Audit-Runden (7–63 Fehler pro Cluster
in Abschnitten 13.30–13.44). Grund: Die Namen der internen Helfer (`llhttp__internal__c_or_flags*`,
`c_test_flags*`, `c_store_*`, `c_update_*`) sind **keine Ghidra-Rekonstruktionen**, sondern entsprechen
exakt dem Namensschema, das der echte llhttp-Codegenerator (nodejs/llhttp) für seine C-Ausgabe verwendet
— vermutlich wurden sie aus Debug-Strings/Symbolresten im Binary übernommen. Dadurch war die
Ausgangsbenennung dieses Clusters von vornherein sehr zuverlässig.

**Bit-für-Bit-Verifikation der Flags-Helfer:** Alle `OrFlags_*`/`c_or_flags*`-Funktionen (0x08036a26–
0x08036be8) wurden gegen ihre tatsächlichen Bitmasken auf dem Flags-Wort @Offset 0x32 (bzw. lenient-flags
@0x2e) geprüft — jede setzt exakt das durch den Namen implizierte Bit (F_CHUNKED=0x01,
F_CONNECTION_KEEP_ALIVE=0x02, F_CONNECTION_CLOSE=0x04, F_CONNECTION_UPGRADE=0x08, F_UPGRADE=0x10,
F_CONTENT_LENGTH=0x20, F_SKIPBODY=0x40, F_TRAILING=0x80, F_TRANSFER_ENCODING=0x200). Ebenso wurden alle
`c_test_flags*`/`c_test_lenient_flags*`-Bit-Test-Helfer gegen ihre Masken/Shifts verifiziert — die in
Batch 19 vergebenen `_Off32`/`_Off2e`-Suffixe sind korrekt den beiden Struct-Feldern zugeordnet.

**Kleiner Sonderfall (kein Rename, nur Dokumentationshinweis):** `llhttp__internal__c_or_flags_4`
(`0x08036be8`) folgt zwar der Namensfamilie "c_or_flags", führt aber tatsächlich eine direkte
Byte-Zuweisung (`*(byte*)(param_1+0x30) = 1`) statt einer Bit-OR-Operation aus. Funktional äquivalent
(das Feld @0x30 hält offenbar nur dieses eine Flag), aber technisch keine echte OR-Operation — in der
Beschreibungsspalte vermerkt, kein Rename-Vorschlag, da der Name weiterhin sinnvoll und konsistent mit
der generierten llhttp-Familie ist.

**Zentrale Dispatcher bestätigt:** `llhttp_Parser_Execute` (0x08036bf4) ist mit 22.470 Bytes die riesige
generierte State-Machine (entspricht `llhttp__internal__run` im echten llhttp) und dispatcht über alle
oben genannten Helfer sowie sämtliche Settings-Callbacks. `llhttp_Parse_Wrapper` (0x0803d538) ist der
äußere Wrapper (entspricht `llhttp__internal_execute`): cached den Fehlerstatus @0xc, ruft
Parser_Execute auf und verwaltet Pause/Reexec über einen im Parser-Struct gespeicherten
State-Handler-Funktionszeiger @0x08. `llhttp_execute`, `llhttp_init`, `llhttp_settings_init`,
`llhttp_set_error_reason` (9 Aufrufer, alle verifiziert), `llhttp_ShouldKeepAlive`,
`llhttp_message_needs_eof` und `llhttp_errno_name` (440B Switch/Jumptable) wurden je gegen ihre
Dekompilierung geprüft und entsprechen exakt ihrer Beschreibung.

**Ghidra-Instabilität während der Prüfung:** 6 Funktionen (`c_load_upgrade`, `c_test_lenient_flags`,
`c_test_flags_4`, `ClearHeaderState`, `GetHeaderState`, `MatchSequence`) lieferten bei
Volldekompilierung wiederholt Timeouts (vermutlich Serverlast durch parallel laufende Re-Audit-Sessions
anderer Cluster, s. Memory-Eintrag zu paralleler Kampagne) — für diese wurden Signatur, Größe und
Caller-Kontext erfolgreich abgerufen und gegen das Muster der jeweils benachbarten (voll verifizierten)
Schwesterfunktionen abgeglichen; Konfidenz dafür auf "medium" mit Vermerk "Teilverifikation" gesetzt statt
"high", da der eigentliche Funktionskörper nicht eingesehen werden konnte.

**51 fehlende Beschreibungen ergänzt** (Namen durchweg bestätigt, keine Änderung nötig): alle
`Load*`/`MulAdd*`/`OrFlags_*`/`c_or_flags*`/`c_store_*`/`c_test_flags*`/`c_test_lenient_flags*`/
`c_update_*`/`Set*`/`Clear*`-Helfer im Adressbereich 0x0803686e–0x08036bdc, sowie `Parser_Execute` und
`Parse_Wrapper`. Zusätzlich wurden 24 bereits dokumentierte Zeilen (Quelle vorher "Doku"/"Batch 20") nach
individueller Re-Verifikation auf Quelle "Re-Audit 2026-07-14" aktualisiert, davon 5 medium→high
hochgestuft (`OnChunkComplete`, `OnChunkHeader`, `OnHeaderFieldComplete`, `OnReset`, `ParserInternalInit`
— alle exakt wie zuvor in Batch 18 dokumentiert bestätigt).

**Fehlerquote dieser Runde:** 0 Namensfehler unter 75 individuell geprüften Funktionen (0 %) — der bislang
sauberste Cluster der gesamten Re-Audit-Kampagne. Keine Umbenennungsvorschläge. Verbleibende 21 nicht
individuell geprüfte Funktionen sind ausschließlich bereits "high"-dokumentierte Span/Lifecycle-Callbacks
mit identischem, mehrfach verifiziertem Muster (Settings-Pointer-Null-Check + bedingter Call) und gelten
als hinreichend abgesichert.

### 13.46 Deep-Dive: 0x0802f2b4 (BatteryParams-Struct) & 0x08008000 (Ghidra-Funktionsgrenzen-Artefakt) (2026-07-15)

Zwei vom Nutzer gezielt benannte Verdachtsfälle wurden abgeschlossen geprüft.

**1) `0x0802f2b4`, vormals `Telemetry_Timestamp_Get`.** Der Name war nachweislich falsch — die
Dekompilierung enthält keinerlei RTC-/Zeit-Zugriff:

```c
undefined4 Telemetry_Timestamp_Get(void)
{
  undefined4 uVar1 = 0;
  if (*(char *)(DAT_0802f2ec + 0xf) != '\x01') {           // Offset+0xF: Disable-Flag
    if ((int)*(short *)(DAT_0802f2ec + 2) / 10 < 1) {       // Offset+2: signed short, /10
      uVar1 = (*(short *)(DAT_0802f2ec + 2) / 10 < 0) ? 3 : 1;
    } else {
      uVar1 = 2;
    }
  }
  return uVar1;
}
```

`DAT_0802f2ec` ist die literal-pool-Kopie der BatteryParams-Struct-Basis `0x20014F82` (dieselbe Basis,
die u. a. von `Power_Limit_Clamp`, `Inverter_Power_Setpoint_Calc`, `Inverter_Power_Setpoint_ScaleFactor_Calc`
und `Inverter_Apply_BatteryParams` referenziert wird, s. Offset-Tabelle unten). Die Funktion liefert einen
4-Zustands-Code: `0` = disabled (Flag @+0xF == 1), `1` = Wert nahe Null (`0 <= wert/10 < 1`), `2` = positiv
(`wert/10 >= 1`), `3` = negativ (`wert/10 < 0`).

Alle drei Aufrufer betten das Ergebnis als einzelnes Status-Byte in größere Telemetrie-/Report-Structs ein:

- `MQTT_Telemetry_Struct_Builder` (0x080124a4): Ergebnis nach `puVar1[1]` bzw. `DAT_0801274c[2]`.
- `Cloud_Report_FillPowerFlow` (0x0801c748): Ergebnis nach `param_1+0x23`, direkt neben einem
  Skalierungs-/Prozent-Byte (`param_1+0x22`, aus einer `fp64_mul`-Berechnung) und vor mehreren
  Differenz-/Summen-Feldern aus vier Prozentwerten (Offsets 0xC/0x12/0x18/0x1E derselben Struct-Familie,
  geclampt auf 0 bei Werten ≥101 — klassisches SOC-/Prozent-Validierungsmuster). Der Funktionsname
  "FillPowerFlow" und die Nachbarfelder stützen eine Lade-/Entlade-/Leistungsfluss-Semantik.
- `BLE_RuntimeInfo_Builder` (0x0800af78): Ergebnis nach `DAT_0800b388+4`, ein Byte in einer generischen
  Laufzeit-Info-Struct.

**Bewertung:** Der Beweis, dass die Funktion **keinen Zeitstempel** liest, ist vollständig erbracht
(kein RTC-Zugriff, kein Tick-Counter, keine Zeit-Bibliotheksfunktion im Aufrufpfad). Die genaue physikalische
Bedeutung von Offset+2 (vermutlich eine Netto-Leistungs- oder Stromgröße in 0.1-Einheiten, deren Vorzeichen
Lade-/Entladerichtung anzeigt) ließ sich mangels eines gefundenen **Schreibzugriffs** auf exakt Offset+2
nicht letztgültig beweisen — `Inverter_Apply_BatteryParams` (der wahrscheinlichste Setter für die Struct)
schreibt nachweislich *nicht* auf Offset+2, sondern liest nur andere Offsets (0x8/0xE/0x14/0x1A auf einer
zweiten Struct-Instanz) für Dirty-Flag-Zwecke — der tatsächliche Writer von Offset+2 wurde nicht lokalisiert.
Der neue Name beschreibt daher konservativ **was die Funktion tut** (Statuscode aus BatteryParams-Feld
ableiten), nicht eine unbewiesene physikalische Einheit. Umbenannt zu **`BatteryParams_PowerFlowState_Get`**,
Konfidenz `medium` (Verhalten 100 % bewiesen, exakte physikalische Bedeutung von Offset+2 nicht). Ghidra-Rename
und Plate-Comment mit vollständiger Begründung angewendet.

**2) `0x08008000`, vormals `BLE_Command_Handler` — bestätigtes Ghidra-Funktionsgrenzen-Artefakt.**
Root-Cause-Analyse bestätigte den Verdacht: die Funktion war eine vollständig überlappende Geisterdefinition
innerhalb des echten Funktionskörpers von `BLE_Recv_Cmd_Dispatcher` (`0x08007f58`–`0x0800a26f`, 6732 Byte).
Die bogus-Funktion beanspruchte `0x08008000`–`0x0800a277` (liegt komplett innerhalb plus 8 Byte über das reale
Ende hinaus). Belege: (a) erste Instruktion `lsls r5,r3,#0xb` ist kein gültiger Funktions-Prolog; (b) der
Dekompilat-Körper enthielt ein `pop {pc}` bei `0x08007f76` — eine Adresse *unterhalb* des behaupteten
Entry-Points, was für eine echte Funktion unmöglich ist; (c) alle 5 eingehenden "Referenzen" waren
`PARAM`-Typ (Daten-Konstanten-Treffer), keine echten `CALL`/`JUMP`-Referenzen. Die Funktionsdefinition wurde
per `FunctionManager.removeFunction()` entfernt, ein Plate-Comment mit der Begründung an `0x08008000`
hinterlegt, `BLE_Recv_Cmd_Dispatcher` nach der Bereinigung als unverändert (weiterhin 6732 Byte, korrekt
begrenzt) verifiziert. Die entsprechende Zeile wurde aus `Control_FW_Function_Tracking_new.md` entfernt,
Cluster-Header „BLE / GATT" von (36) auf (35) korrigiert. Live-Funktionszahl im Programm: 1623 → 1622.

---

## Anhang A: Scan-Kontext (Gerätezustand beim Scan)

```
Datum:          Mai 2026
Gerät:          Marstek Venus D (VNSD-0)
Batterie-Packs: 2
SOC Pack1:      10.9% (raw 109, Scale 0.1)
SOC Pack2:      12.0% (raw 120, Scale 0.1)
Spannung Pack1: 50.12V
Spannung Pack2: 51.25V
AC-Netz:        239.8V / 49.9Hz
AC-Strom:       −4.98A (Einspeisung)
PV:             NICHT angeschlossen (MPPT = Leerlauf ~9.9V)
Modus:          Anti-Einspeisung (work_mode=1)
RS485:          Steuerung AKTIV (42000=0x55AA)
Backup/UPS:     Aktiv (41200=1)
```

## Anhang B: Werkzeuge & Abhängigkeiten

```bash
# Python-Abhängigkeiten
pip3 install pymodbus pandas

# Ghidra (macOS)
brew install ghidra
brew install --cask temurin@21  # Java 21

# Ghidra-Skripte: Jython 2.7 (eingebaut, kein Extra-Install)
# Wichtig: # -*- coding: utf-8 -*- in Zeile 1, keine Umlaute!
```

---

*Erstellt: Mai 2026, aktualisiert Juli 2026 | Firmware: VNSD-0 v149.2 | Gerät: Marstek Venus D*  
*Analyse-Tool: Ghidra + PyGhidra + ReVa-MCP + pymodbus + marstek-fw-checker*  
*v1: Firmware 149.2 analysiert, rein Venus-D-fokussiert, OTA-Status aktualisiert*

---

## Anhang C: Erweiterte Ghidra-Analyse (Ergänzung)

### C.1 Neugefundene SRAM-Variablen

Aus `FUN_08004bd8` (Max-Leistungs-Initialisierung):

| SRAM-Adresse | Variable | Bedeutung |
|---|---|---|
| `0x20000136` | `DAT_20000136` | Hardware-Version (version_num) |
| `0x2000012f` | `DAT_2000012f` | Max Ladeleistung (dynamisch, versionsabhängig) |
| `0x2000012d` | `DAT_2000012d` | Max Entladeleistung |
| `0x20000260` | `DAT_20000260` | Aktueller Leistungs-Setpoint (EMS) |
| `0x2000026f` | `DAT_2000026f` | RS485-Tabellen-Index |
| `0x20000270` | `DAT_20000270` | Modbus-Slave-ID (low byte) |
| `0x20000271` | `DAT_20000271` | Modbus-Slave-ID (high byte) |
| `0x200002b2` | `DAT_200002b2` | Timer/Hysterese-Counter |
| `0x20000269` | `DAT_20000269` | EMS-Steuerungs-State |

Hardware-Version → Max-Leistung Mapping:
```
version_num = 0  →  max_power = 2500 W  (Standard Venus D)
version_num = 1  →  max_power =  800 W  (kleinere Variante)
version_num = 2  →  max_power =  600 W  (kleinste Variante)
```

### C.2 Zweite Descriptor-Tabelle entdeckt

In `FUN_08004b20` wurde ein identisches Zugriffsmuster auf eine zweite Tabelle gefunden:

```c
// Haupt-Tabelle (TCP Modbus):
(&DAT_20000354)[uVar4 * 6]          // base: 0x20000354, 246 Einträge

// Zweite Tabelle (RS485/EMS):
*(ushort *)(DAT_2000026f * 6 + 0x600172b8)  // base: 0x600172b8, ~96 Einträge
```

| Eigenschaft | TCP-Tabelle | RS485-Tabelle |
|---|---|---|
| Basis | `0x20000354` (SRAM) | `0x600172b8` (Ext-RAM / CH395Q) |
| Einträge | 246 (0xF6) | ~96 (0x5F+1) |
| Stride | 12 Bytes | 12 Bytes (identisch) |
| Zweck | Modbus TCP Read-Register | RS485/EMS interne Register |

### C.3 Abschließende Analyse-Ergebnisse

**Vollständig dekompilierte Funktionen (149.2-Äquivalente):**

| Funktion (149.2) | Rolle | Status |
|---|---|---|
| `FUN_0801e43c` | Modbus_Dispatcher | ✅ Vollständig |
| `FUN_0801eaa4` | FC03_ReadHandler | ✅ Vollständig |
| `FUN_0804fe20` | Read_Serializer | ✅ Vollständig |
| `FUN_08050f20` | Write_Handler | ✅ Vollständig |

**Descriptor-Init: Conclusio**

Die Init-Funktion für die Descriptor-Tabelle (`0x20000354`) ist durch statische Analyse
nicht auffindbar — die Registernummern werden zur Laufzeit **berechnet** (nicht als Array
oder Immediates gespeichert). Vier unabhängige Prüfungen belegen dies (s. Abschnitt 0.3).

Lösungswege:
1. **Batch-Scan** (empfohlen): `scan_modbus_batch.py` → 0-65535 in ~52 Min
2. **JTAG/SWD**: 2952 Bytes ab `0x20000354` bei laufendem Gerät lesen
3. **Unicorn-Emulation**: Binary emulieren bis SRAM initialisiert ist

---

## Anhang D: Vollständiger Scan — 413 Register (Mai 2026)

### D.1 Scan-Ergebnis Übersicht

```
Scan-Datum:        Mai 2026
Methode:           Raw TCP Socket, Batch=32, direkte Adressierung (PDU-Addr = Register-Nr)
Scanner:           scan_modbus_batch.py v7
Dauer:             2:30h (Batch=32, Fallback Einzel-Reads, Skip leere Blöcke)
Gefunden:          413 Register (vorher: 130)
Adressraum:        0 – 65535 (vollständig gescannt ✅)

ABGESCHLOSSEN:
  Register 0–29999:     LEER — keine einzige Antwort
  Register 30000–39999: 89 Read-Register bestätigt
  Register 40000–49999: 41 Write-Register bestätigt
  Register 50000–65535: LEER — keine einzige Antwort
```

> **Bedeutung:** Der Modbus-Adressraum ist damit vollständig kartiert.
> Es gibt keine weiteren unbekannten Bereiche. Alle 413 gefundenen Register
> befinden sich ausschließlich zwischen 30000 und 49999.

### D.2 Neuentdeckte Register-Cluster

| Cluster | Register | Inhalt |
|---|---|---|
| **NEU** | 30000–30010 | Neue Leistungs-/Status-Register |
| Bekannt | 30020–30040 | MPPT / PV |
| **NEU** | 30100–30110 | Pack 1 BMS (erweitert) |
| **NEU** | 30200–30214 | Firmware-Versionen (erweitert) |
| **NEU** | 30400–30403 | IP-Adressen (Gerät + Gateway) |
| Bekannt | 31000–31009 | Gerätename |
| Bekannt | 33000–33011 | Energie-Zähler |
| **NEU** | 34000–34033 | Pack 1 (detailliert, inkl. Einzel-Temps) |
| **NEU** | 34100–34133 | Pack 2 (detailliert) |
| **NEU** | 34200–34233 | Pack 3 Slot (leer = nicht verbaut) |
| **NEU** | 34300–34333 | Pack 4 Slot (leer) |
| **NEU** | 34400–34433 | Pack 5 Slot (leer) |
| **NEU** | 34500–34533 | Pack 6 Slot (leer) |
| **NEU** | 34600–34633 | Pack 7 Slot (leer) |
| **NEU** | 35000–35012 | Temperaturen (erweitert) |
| **NEU** | 35110–35112 | Leistungs-Limits (neu) |
| Bekannt | 36000–36103 | Alarm / Fehler |
| **NEU** | 37000–37024 | Kombinierte Netz+Sensor-Werte |

### D.3 Neudekodierte Register (vollständige Liste)

#### Neue Register 30000–30010

| Register | Rohwert | Interpretiert | Status |
|---|---|---|---|
| 30000 | 509 | ? (evtl. grid_power oder combined_pv_power) | Unbekannt |
| 30001 | −10 | battery_power = −10 W (Entladung) | Bekannt |
| 30002 | 179 | ? | Unbekannt |
| 30003 | 181 | ? | Unbekannt |
| 30004 | 2410 | 241.0 V (evtl. ac_voltage 2. Messung) | Plausibel |
| 30005 | 2 | backup_voltage (Backup-Ausgangsspannung, Scale 0.1V) — s. Vermutungen_Register_Analyse.md, Sicherheit: Hoch | Bestimmt |
| 30006 | 0 | ac_power = 0 W | Bekannt |
| 30007 | 0 | backup_power (Backup-Ausgangsleistung, W) — s. Vermutungen_Register_Analyse.md, Sicherheit: Hoch | Bestimmt |
| 30010 | 0 | ? | Unbekannt |
| 30028 | 513 | 0x0201 = ? (selber Wert wie 37022) | Unbekannt |
| 30029 | 65535 | battery_power_factor (Leistungsindex, nicht linear, int16) — s. Vermutungen_Register_Analyse.md, Sicherheit: Mittel | Bestimmt |
| 30036 | 219 | hardware_version (konstant 219 über alle Scans/2+h Langzeit, keine Sensorgröße) — s. Vermutungen_Register_Analyse.md, Sicherheit: Mittel | Bestimmt |

#### Neue Netzwerk-Register (30400–30403)

```
30400–30401:  device_ip   = 192.168.x.x  (eigene IP des Geräts)
30402–30403:  gateway_ip  = 192.168.x.1
```

Kodierung: jedes Register = 2 Bytes der IPv4-Adresse (Big-Endian)
```python
ip_hi = raw_uint16 >> 8    # erstes Oktett
ip_lo = raw_uint16 & 0xFF  # zweites Oktett
```

#### Erweiterte Pack-1-Register (34000–34017)

| Register | Rohwert | Interpretiert |
|---|---|---|
| 34000 | 5114 | pack1_voltage = 51.14 V |
| 34001 | 0 | pack1_current = 0.0 A |
| 34002 | 146 | **pack1_soc = 14.6 %** (Scale 0.1!) |
| 34003 | 19 | pack1_cycle_count = 19 |
| 34004 | 3 | packX_charge_status (0=idle, 3=aktiv laden/entladen) — s. Vermutungen_Register_Analyse.md, Sicherheit: Hoch |
| 34005 | 3199 | pack1_max_cell_voltage = 3.199 V |
| 34006 | 3195 | pack1_min_cell_voltage = 3.195 V |
| 34010 | 116 | **pack1_bms_version = 116** (nicht Temperatur — raw 116 = BMS-Version wie Reg 30204!) |
| 34011 | 261 | **pack1_temp_max = 26.1 °C** |
| 34012 | 198 | pack1_temp_? = 19.8 °C (NEU) |
| 34013 | 193 | **pack1_temp_min = 19.3 °C** (NEU) |
| 34014 | 194 | pack1_temp_? = 19.4 °C (NEU) |
| 34015 | 192 | pack1_temp_? = 19.2 °C (NEU) |
| 34016 | 191 | pack1_temp_? = 19.1 °C (NEU) |

#### Batterie-Pack-Slots (Firmware unterstützt 7 Packs!)

> **Hinweis:** Dieser Scan stammt von Mai 2026 mit 2 Packs. Das Gerät hat inzwischen
> **6 Batterie-Packs** — der 149.2-Live-Scan wird die Tabelle aktualisieren.

| Pack | Basis-Register | Spannung | SOC | Zyklen | Status |
|---|---|---|---|---|---|
| Pack 1 | 34000 | 51.14 V | 14.6 % | 19 | ✅ Verbaut |
| Pack 2 | 34100 | 50.24 V | 10.9 % | 17 | ✅ Verbaut |
| Pack 3 | 34200 | — | — | — | ✅ Verbaut (seit Erweiterung) |
| Pack 4 | 34300 | — | — | — | ✅ Verbaut (seit Erweiterung) |
| Pack 5 | 34400 | — | — | — | ✅ Verbaut (seit Erweiterung) |
| Pack 6 | 34500 | — | — | — | ✅ Verbaut (seit Erweiterung) |
| Pack 7 | 34600 | — | — | — | ❌ Leer |

#### Register 37000–37024 (neu, kombinierte System-Werte)

| Register | Rohwert | Interpretiert |
|---|---|---|
| 37000 | 1 | system_status = 1 |
| 37004 | 0 | grid_power_setpoint = 0 W (Soll-/Regelwert, ≈30006, reagiert ~1 Scan-Zyklus schneller — s. Vermutungen_Register_Analyse.md) |
| 37005 | 14 | ? (1.4) |
| 37006 | 192 | ? (19.2 °C oder 192 W?) |
| 37007 | 3198 | **max_cell_v_all_packs = 3.198 V** |
| 37008 | 3195 | **min_cell_v_all_packs = 3.195 V** |
| 37012 | 116 | **bms_version = 116** (nicht Temperatur — selber Wert wie 30204 und 34010/34110) |
| 37016 | 2416 | ac_voltage = 241.6 V |
| 37022 | 513 | 0x0201 = ? (Protokoll-Version 2.01?) |

#### Register 35110–35112 (neu)

| Register | Rohwert | Wahrscheinliche Bedeutung |
|---|---|---|
| 35110 | 576 | max_charge_power_current = 576 W? |
| 35111 | 500 | rated_charge_power = 500 W? |
| 35112 | 500 | rated_discharge_power = 500 W? |

### D.4 Geräte-Zustand zum Scan-Zeitpunkt

```
Pack 1:  51.14 V,  SOC 14.6%,  19 Zyklen,  BMS-Version 116  (Reg 34010 — NICHT Temperatur!)
Pack 2:  50.24 V,  SOC 10.9%,  17 Zyklen,  BMS-Version 116  (Reg 34110 — NICHT Temperatur!)
Netz:    241.6 V,  Strom 0 A (kein Import/Export)
Modus:   Anti-Einspeisung (work_mode=1)
RS485:   Steuerung aktiv (0x55AA)
Backup:  Aktiv (=1)
Alarm:   0 (kein Alarm)
Fehler:  0x0963 (fault_bits, nicht 0!)
```

> **⚠️ Korrektur:** Reg 34010 (Pack 1) und 34110 (Pack 2) enthalten **BMS-Firmware-Version 116**,
> identisch mit Reg 30204. Der Rohwert 116 wurde fälschlicherweise als 11.6 °C (Scale 0.1)
> interpretiert — ein zur Jahreszeit plausibel erscheinender Wert.
> Tatsächliche Pack-Temperaturen sind in Reg 34011–34016 (Pack 1) bzw. 34111 (Pack 2) zu finden.

### D.5 Technische Erkenntnisse

**Adressierung:** Marstek verwendet **direkte Adressierung** — PDU-Adresse = User-Register-Nummer (kein Offset, kein -1). Beweis: TCPRouter.c vergleicht die rohe PDU-Adresse direkt mit `descriptor.base_addr` ohne jede Korrektur. pymodbus: `read_holding_registers(30000)` → liest Register 30000.

**Maximale Batch-Größe:** 32 Register pro FC03-Request.
Bei Batch > 32 gibt das Gerät keine Antwort (Timeout, kein Exception-Code).

**Lücken im Register-Map:** Viele Adressen sind nicht belegt.
Ein Batch-Request über eine Lücke → Exception Code 2.
Lösung: Fallback auf Einzel-Reads bei Exception.

**Pack-Erweiterbarkeit:** Die Firmware unterstützt bis zu 7 Batterie-Packs
(Register-Blöcke 34000, 34100, 34200, ..., 34600).
Die BMS-Firmware erlaubt intern bis zu **9 Packs** (`param_1 < 10` im CAN-Sender),
Marstek limitiert offiziell auf 6. Register für Pack 7 (34600) existieren als Platzhalter.
Nicht verbundene Packs antworten mit 0 für alle Register.

**Fault-Bits 0x0963:** Aus der BMS-FW-Analyse (v117.7) sind die Protect-Bitmasks
vollständig dekodiert. Protect1 hat 12 Bits (Cell OVP/UVP, Overcurrent L2,
Temperatur-Schutz, Hardware-SCP), Protect2 hat 5 Bits (NTC-Fehler, Comm-Error,
Error-Lock). Vollständige Bit-Definitionen: siehe `BMS_FW_Analyse_v117.7.md`, Sektion 5.2/5.3.

---

*Erstellt: Mai 2026 | Firmware: VNSD-0 v149.2 / Micro v116 / BMS v117.7 | Gerät: Marstek Venus D*  
*Analyse-Tool: Ghidra + ReVa MCP + Python 3 + pymodbus*  
*v1: Modbus-Handler, Descriptor-Tabelle, Cloud-API*  
*v2: Telemetrie-Brücke (48-Byte-Block, 20 Felder, SRAM 0x20014E90)*  
*v3: System-Architektur, DC-Bus-Topologie, PV-Verhalten, Pack-Rotation, Cross-FW-Referenzen*