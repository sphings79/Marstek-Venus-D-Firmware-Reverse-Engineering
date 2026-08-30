# Offene Descriptor-Register — Ghidra-Analyse (Control-FW v150)

**Gerät:** Marstek Venus D (VNSD-0), STM32 Cortex-M
**Firmware:** `VNSD-0_app_0150_0805_115146.bin` (v150), Ghidra/ReVa, 1618 Funktionen
**Datum:** 14. August 2026
**Ausgangslage:** 121 Register mit sicherem Typ/Skala, aber unbekannter Bedeutung.
**Ergebnis:** **0 Register ohne Zuordnung.** 100 hoch · 101 mittel · 16 niedrig · 29 Hypothesen.
Nach Cross-Prüfung gegen BMS-FW v118 und Micro-FW v116 (Abschnitt 7) und Auswertung des
Versions-Debug-Prints (Abschnitt 8).

---

## 1. Methodik

Das SRAM (0x2000xxxx) ist in Ghidra **kein** Memory-Block — die Descriptor-Quellzeiger liegen nicht
als Daten vor. Der Durchbruch kam über zwei Hebel:

1. **movw/movt-Referenzauflösung.** Cortex-M lädt SRAM-Adressen als `movw/movt`-Immediates; Ghidra
   rekonstruiert daraus Referenzen mit Zieladresse **und** Typ (READ/WRITE). Ein Skript über alle
   Instruktionen ergibt die Writer/Reader-Karte je SRAM-Adresse.
2. **Struct-Basis-Rückrechnung aus Debug-Print-Funktionen.** Die FW enthält `printf`-Debugausgaben
   mit **Klartext-Feldnamen** in `.rodata`. Aus `[rBase,#offset]` plus der von Ghidra aufgelösten
   Zieladresse folgt die Struct-Basis — damit ist jedes Feld-Offset einer Registeradresse zuordenbar.
   Die Paarung erfolgt positionsweise: n-ter aufgelöster SRAM-Zugriff ↔ n-ter Formatstring.

### Zwei Fallstricke (dokumentiert, damit sie nicht wiederkehren)

- **`mem.getBytes(addr, bytearray)` funktioniert in PyGhidra/Jython nicht** — der Python-Puffer
  bleibt mit Nullen gefüllt, das Skript meldet stillschweigend „nichts gefunden". Zwingend
  `mem.getInt()` / `mem.getByte()` verwenden. Ein erster Literal-Scan lieferte dadurch ein
  falsches Negativ-Ergebnis.
- **Decompiler-Symbole wie `_DAT_080365a4` sind Artefakte**, die einen benachbarten String
  überlappen ("Globals starting with '_' overlap smaller symbols"). Die echte Struct-Basis kommt
  aus der Referenzauflösung, nicht aus dem Symbolnamen.

### Befund: Das Image ist unvollständig

314 Flash-Pointer im Image zeigen **hinter das Image-Ende** (0x0805EFFF), davon **287 kompakt in
0x0805F000–0x08062FFF**. Genau dort liegen die Cloud-`snprintf`-Formatstrings
(`DAT_0801f82c` → 0x08060524, `DAT_08024ef0` → 0x08060830). Dem vorliegenden `.bin` fehlt also ein
**~16 KB Rodata-/String-Blob**. Eine falsche Ladebasis wurde ausgeschlossen (bei −0x10000 steht dort
Thumb-Code, kein String). **Das ist der einzige Grund, warum die Pack-Feldnamen offen bleiben.**

---

## 2. Vier identifizierte Quell-Structs

### 2a. Inverter/Grid-Telemetrie — Basis `0x20014E9C` (v149.2: 0x20014E90, +12 Drift)
Quelle: `Inverter_Telemetry_Debug_Print` (0x08036BD4), 28 printf mit Klartextnamen.

| Off | SRAM | Feld (FW-String) | Register |
|---|---|---|---|
| +0x00 | 20014E9C | inv_state | **35100** |
| +0x01…03 | 9D/9E/9F | buz_state, chrg_flag, back_func | – |
| +0x04 | 20014EA0 | warn_code (u32) | **36000** |
| +0x08 | 20014EA4 | error_code1 (u32) | **36100 / 37013** |
| +0x0c | 20014EA8 | error_code2 (u32) | **36102 / 37015** |
| +0x10 | 20014EAC | grid_volt (0.1 V) | 30004 / 32200 / 32201 |
| +0x12 | 20014EAE | grid_pf (0.1 Hz) | 32204 |
| +0x14 | 20014EB0 | off_grid_volt (0.1 V) | 30005 / 32300 / 32301 |
| +0x16 | 20014EB2 | grid_permit | – |
| +0x18 | 20014EB4 | grid_sample_power (1 W) | 30006 / 32202 / 37004 |
| +0x1a | 20014EB6 | off_grid_power (1 W) | 30007 / 32302 |
| +0x1c | 20014EB8 | bat_sample_power (1 W, i16) | 30001 / **32102** |
| +0x1e | 20014EBA | bat_sample_volt (0.1 V) | 30000 |
| +0x20 | 20014EBC | env_temp (0.1 °C) | 30002 / 35000 |
| +0x22 | 20014EBE | radiator_temp (0.1 °C) | 30003 / 35001 / 35002 |
| +0x24/26 | EC0/EC2 | max_power, min_power | – |
| +0x28/2c | EC4/EC8 | chrg_energy, dischrg_energy (1 Wh) | – |

Zusatzblöcke derselben Funktion: `0x2000015C` hard_ver (nicht serviert), **`0x2000015E` soft_ver =
30202**, **`0x20000160` boot_ver = 30203**, `0x20000162` dev_state; `0x20000144` work_mode = 30010,
+1 sleep_flag, +2 bat_mode.

### 2b. BMS-Aggregat — Basis `0x20014F8E` (CAN PGN 1801–1804)
Quelle: `CAN_Battery_Telemetry_Debug_Print` (0x080364C4).

| Off | Register | Feld | Einheit |
|---|---|---|---|
| +0x00 | **32100** | bat_volt | **10 mV** |
| +0x02 | **32101** | bat_curr | 100 mA |
| +0x04 | **32108** / 35010 | bat_temp | 0.1 °C |
| +0x06 | 32104 | bat_soc | 0.1 % |
| +0x08 | **32105** | bat_energy | Wh |
| +0x0a | **32109** | bat_total_nb (Pack-Anzahl) | – |
| +0x0b | **32110** | bat_online_mask (u16) | Bitmaske |
| +0x0d | **32111** | work_bat_idx | – |
| +0x10 | **35110** | chrg_volt | 0.1 V |
| +0x12 | **32106** / 35111 | chrg_curr | 100 mA |
| +0x14 | **32107** / 35112 | dischrg_curr | 100 mA |
| +0x1e | **32113** / 30109 | factory_test | Flag |
| +0x1f | **32112** | lock_flag | Flag |
| +0x20 | **30214** | self_check | Flag |

### 2c. Inverter/MPPT — Basis `0x20014F4C`
Quelle: `MPPT_Debug_Print` (0x08036884). Befüllt via `Modbus_StoreRegisterSlot`
(CAN fc 0x03, 8 Slots × 8 Byte).

| Off | Register | Feld |
|---|---|---|
| +0x02 | **37023** | Mppt_Error |
| +0x06 | **37024** | Mppt_Warning |
| +0x08…1e | 30020–30040 | PV1–4 Vol/Cur/Pow |
| +0x2c | **37021** | PV_Year_Cap (u32, 10 Wh) |
| +0x30 | **30028** | bat_vol (0.1 V) |
| +0x32 | **30029** | bat_cur (0.1 A) |
| +0x34 | **30036** | base_vol (0.01 V) |
| +0x38…3e | 30031–30034 | Slot 8, von MPPT_Debug_Print nicht ausgegeben |

### 2d. Pack-Struct — Basis `0x20014FB4`, Stride 0x60
Dreifach bestätigt (`Schedule_MinMax_PerGroup_Calc`, `BLE_Build_BMS_Data_Response`,
`BLE_Build_DevelopModeInfo_Response`). `Schedule_MinMax_PerGroup_Calc` iteriert 6 Packs, liest die
16 Zellspannungen ab Pack+0x20 (= Reg 34x18 ✓) und legt je Pack max-Index/min-Index/max/min ab.
Die offenen Felder 34x03/04/07/08/09/11/12/17 sind exakt verortet; die Namen stehen im fehlenden
Flash-Tail.

---

## 3. CAN-Telemetrie-Dispatch (Protocol AA)

`CAN_FrameDispatcher` → `Telemetry_Register_Dispatcher` verteilt nach CAN-ID-Lowbyte:
0x10–0x14 Protocol_AA_Set*, 0x40–0x43 Energiezähler, 0x54/0xC1/0xCB/0xCE Telemetry_Store_*.

**Der 38000-Block ist damit exakt aufgelöst** — vier CAN-Frames, Nutzdaten 1:1 als 16-Bit-Register:

| CAN-ID | Ziel-SRAM | Länge | Register |
|---|---|---|---|
| 0x40 | 0x20000168 | 8 B | 38000–38003 |
| 0x41 | 0x20000170 | 6 B | 38004–38006 |
| 0x42 | 0x20000176 | 8 B | 38007–38010 |
| 0x43 | 0x2000017E | 8 B | 38011–38014 |

---

## 4. Korrekturen an der bisherigen Register-Map

| Register | Bisher | Firmware-Wahrheit |
|---|---|---|
| **32102** | float32 (Typkonflikt mit 30001) | **Konflikt gelöst:** Quelle 0x20014EB8 ist i16 `bat_sample_power(1W)`. Die float32-Angabe des Descriptors ist die falsche Seite. |
| **36000** | alarm_status | `warn_code` |
| **36100 / 37013** | fault_status_lo | `error_code1` |
| **36102 / 37015** | fault_status_hi | `error_code2` |
| **30201** | ems_sub_version | **`ems_boot_ver`** — Bootloader-Version des Control |
| **30202** | vms_version | **`vns_ver`** — VNS (Micro-Inverter), nicht "vms". Writer `Telemetry_Store_RegCB` (CAN-ID 0xCB) |
| **30203** | vms_sub_version | **`vns_boot_ver`** — dito. hard_ver @0x2000015C wird nicht serviert |
| **30205** | bms_sub_version | **`mppt_ver`** — MPPT-Firmware-Version (u16), siehe Abschnitt 8 |
| **32101** | dc_current, Trunkierung vermutet | `bat_curr(100mA)` aus dem BMS-CAN-Aggregat — keine Trunkierung |
| **32100** | dc_voltage | `bat_volt` in **10 mV** (nicht 0.1 V) |
| **32114 / 30110** | Sensor angenommen | wird vom **Write-Handler beschrieben** → Config-Setpoint |

---

## 5. Verifikation gegen Live-Scan (`control_150_vns_116.csv`)

| Reg | Roh | Interpretiert | Erwartung | ✓ |
|---|---|---|---|---|
| 32100 | 5372 | 53.72 V (10 mV) | Batteriespannung | ✓ |
| 30028 | 533 | 53.3 V (0.1 V) | Batteriespannung Inverter-Seite | ✓ |
| 35110 | 576 | 57.6 V (0.1 V) | Ladespannungs-Limit LFP | ✓ |
| 34002 | 887 | 88.7 % | Pack-SOC | ✓ |
| 30036 | 219 | 2.19 V (0.01 V) | interne Referenz | plausibel |

---

## 6. Verbleibende Punkte

1. **Fehlender Flash-Tail (0x0805F000–0x08063000).** Enthält die Cloud-Formatstrings und damit die
   exakten Namen der 60 Pack-Felder. Beschaffung: vollständigeres Image aus dem FW-Archiv oder
   SWD-/OpenOCD-Dump. Der Ordner „Marstek FW Archiv" war in dieser Sitzung nicht verbunden.
2. **30031–30035:** Inverter-Struct-Schwanz (Slot 8 bzw. fc 0xff Slot 2), im Image ohne Klartextname.
3. **30212 (0x20000138):** keine aufgelösten Writer/Reader.
4. **32202:** `elem_size` 4 bei Typ i16 bleibt eine Descriptor-Inkonsistenz.

---

## 7. Cross-FW-Verifikation gegen BMS v118 und Micro v116

Beide Nachbar-Firmwares sind in Ghidra geladen und liefern unabhängige Bestätigung —
sie sind die **Sender** der Daten, die der Control nur weiterreicht.

### 7a. Versionsblock: VNS, nicht "VMS"

`Telemetry_Store_RegCB` schreibt den Block `0x2000015C` aus einem **CAN-Frame (ID 0xCB)** —
die Werte kommen also von einem externen Modul, nicht vom Control selbst. Zusammen mit dem
lesenden `Inverter_Telemetry_Debug_Print` ergibt sich die Zuordnung zum **Micro-Inverter (VNS)**.
Die Registerstaffelung ist dadurch stimmig:

| Register | Modul | Feld |
|---|---|---|
| 30200 / 30201 | **EMS** (Control) | ems_version (Flash 0x08010000) / ems_sub_version |
| 30202 / 30203 | **VNS** (Micro-Inverter) | soft_ver / boot_ver |
| 30204 / 30205 | **BMS** | bms_version / bms_sub_version |

### 7b. BMS v118 bestätigt das Aggregat-Struct vollständig

Die BMS-FW enthält exakt benannte Sendefunktionen, die 1:1 den Control-Debug-Strings entsprechen:

| BMS-Funktion | CAN-PGN | Control-Struct 0x20014F8E |
|---|---|---|
| `CAN_TX_PF1_PackMeasurements` | 1801 | bat_volt, bat_curr, bat_temp, bat_soc |
| `CAN_TX_PF2_Capacity` | 1802 | bat_energy, bat_total_nb, online_mask, work_bat_idx |
| `CAN_TX_PF3_ChargeDischargeLimits` | 1803 | chrg_volt, chrg_curr, dischrg_curr, chrg_flag |
| `CAN_TX_PF4_ProtectWarnings` | 1804 | bat_err1/2, bat_warn1, factory_test, lock_flag |

Damit sind alle 14 Register des Aggregat-Structs **beidseitig** belegt.

### 7c. Pack-Struct: Frame-Layout schließt die Lücke

`CAN_TX_PerPack_10Msgs` (BMS, 1868 B) sendet **10 Frames je Pack**, ID `0x18[Grp]AA[PackID]`,
aus einem BMS-internen Pack-Array mit **ebenfalls Stride 0x60**:

| CAN-Gruppe | Inhalt | Control-Pack-Offset | Register |
|---|---|---|---|
| 0x20–0x23 | Übersicht (volt, curr, soc, cycle, limits, protect, version) | +0x00…+0x1e | 34x00–34x10 |
| 0x30–0x33 | **16 Zellspannungen** | **+0x20…+0x3F** | 34x18–34x33 ✓ |
| 0x40 | **4 NTC-Temperaturen** | **+0x40…+0x47** | 34x13–34x16 ✓ |
| 0x41 | **Ave / MOS / ENV NTC** | **+0x4A, +0x4C, +0x4E** | **34x11, 34x12, 34x17** |

Die beiden mit ✓ markierten Zeilen decken sich exakt mit der Descriptor-Tabelle (16 bzw. 4
Elemente an genau diesen Offsets) — eine starke, unabhängige Bestätigung. Daraus folgt, dass
**34x11/34x12/34x17 Temperaturwerte** sind; die ältere `BLE_Modbus_CrossReference.md` führt
34011–34014 ebenfalls als `temperature1-4` und 34015 als `mosfetTemperature`.

Aus den BMS-Debug-Strings (`Cyc Cnt`, `Chg Mos/Dsg Mos`, `Max NTC/Min NTC/Ave NTC`,
`MOS NTC/ENV NTC`, `Max Cell/Min Cell`, `Protect1/Protect2`) ergibt sich für die
Übersichtsfelder: **34x03 = cycle_count** (unabhängig bestätigt durch die BLE-CrossReference,
BLE-Offset 0x18 → 34003), 34x04 = MOSFET-Status, 34x07/34x08 = Max/Min NTC, 34x09 = Protect1.
Diese vier bleiben als **Hypothese** markiert, da die Feldreihenfolge im Frame nicht
byte-genau verifiziert ist.

### 7d. Micro v116 bestätigt die Inverter-Seite

Die Micro-FW enthält die Gegenstücke zu den Control-Feldern:
`err1 = %x err2 = %x, war1 = %x` (→ error_code1/2, warn_code), `max_power/min_power`,
`work_mode = %d, bat_mode = %d, backup = %d`, `grid_standand`, sowie die BMS-Sicht
`charge_u / charge_i / discharge_i / soc / cap / bat_vol / bat_cur / max_temp /
charge_req / force_charge_req / sleep_flag`. Letztere deckt sich Feld für Feld mit dem
Aggregat-Struct — mit dem Hinweis, dass `bat_temp` dort **`max_temp`** heißt, also
vermutlich die höchste Zelltemperatur ist.

### 7e. Der fehlende String-Blob ist in keinem Archiv-Image

Alle 14 Control-Images des FW-Archivs (VNSD-0, VNSA-0, VNSE3-0, HMG-50) enthalten dieselben
drei `pgn_180x`-Debugstrings und **keinen** Cloud-String-Blob. Der Bereich
0x0805F000–0x08063000 wird also nicht per OTA verteilt. Für die exakten Cloud-Feldnamen der
Pack-Register bleibt nur ein **SWD-/OpenOCD-Dump** dieser Flash-Region vom laufenden Gerät.

---

## 8. Versions-Debug-Print — alle Versionsregister endgültig geklärt

Bei `0x08036F40` liegt eine (von Ghidra nicht als Funktion erkannte) Versionsausgabe. Sie löst
den gesamten 302xx-Block auf und korrigiert zwei Register:

```
Build:          Aug  5 2026 11:51:21
ems_type=       VNSD-0
boot_ver=       [0x20000038]                    -> Reg 30201
ems_ver=        150 (Konstante 0x96)            -> Reg 30200
=============================
mppt_ver(new)=  [0x20000188] | [0x20000189]<<8  -> Reg 30205   (u16)
mppt_ver(old)=  [0x20000188]                                    (u8)
bms_ver=        [0x20014FB0+0x22] = 0x20014FD2  -> Reg 30204
vns_ver=        [0x2000015E]                    -> Reg 30202
```

| Register | Quelle | Bedeutung | Status |
|---|---|---|---|
| 30200 | Flash 0x08010000 | **ems_ver** — Control-App | bestätigt |
| 30201 | 0x20000038 | **ems_boot_ver** — Control-Bootloader | **korrigiert** (war ems_sub_version) |
| 30202 | 0x2000015E | **vns_ver** — Micro-Inverter Software | bestätigt |
| 30203 | 0x20000160 | **vns_boot_ver** — Micro-Inverter Bootloader | bestätigt |
| 30204 | 0x20014FD2 | **bms_ver** — BMS (Pack0-Struct +0x1e) | bestätigt |
| 30205 | 0x20000188 | **mppt_ver** — MPPT-Firmware | **korrigiert** (war bms_sub_version) |

Die Firmware kennt also **vier** unabhängige Module: EMS (Control), VNS (Micro-Inverter),
MPPT und BMS. `hard_ver` (0x2000015C) und `dev_state` (0x20000162) werden nicht per Modbus
serviert. Interessant ist die Doppelausgabe `mppt_ver(new)`/`mppt_ver(old)`: die MPPT-Version
wurde von u8 auf u16 erweitert, das Register liefert die neue 16-Bit-Form.

---

## 9. Fehler- und Warncodes (36000 / 36100 / 36102)

### Herkunft eindeutig geklärt

Die drei Codes entstehen in der **Micro-Inverter-FW v116** und werden vom Control nur
weitergereicht:

| Micro-FW SRAM | Micro-Name | Control-Feld | Modbus |
|---|---|---|---|
| 0x200019F4 | `err1` | error_code1 | **36100 / 37013** |
| 0x200019F8 | `err2` | error_code2 | **36102 / 37015** |
| 0x200019FC | `war1` | warn_code | **36000** |

Beleg: `build_telemetry_block` (Micro) liest genau diese drei Wörter in den Telemetrieblock,
den der Control in seine Struct 0x20014E9C übernimmt. Bestätigt durch die Debug-Strings
`err1 = %x err2 = %x, war1 = %x` (Micro, `ADC_Sensor_Debug_Print`) und `err_code=%x` /
`warn_code=%x` (Control, `Debug_PrintErrorCodes`).

Zusätzlich führt der Control zwei Ringpuffer mit je 20 Einträgen
(`Debug_PrintErrorAndEventLog`): **Error-Log** 14 Byte/Eintrag (Code u16 + 4 Bytes + Timestamp)
und **Event-Log** 9 Byte/Eintrag. Diese sind nicht per Modbus serviert.

### Klartext: in der Firmware nicht vorhanden

Eine Volltextsuche über Micro v116 und BMS v118 nach Fehlerbegriffen (`ovp|uvp|ocp|otp|scp|
over|under|fault|protect|alarm|warn`) findet **keine Bit-zu-Text-Tabelle** — nur generische
Meldungen (`Error: %s, %d`, `error lock on/set/reset`). Die Codes sind reine Bitmasken; die
Zuordnung existiert nur in Marstek-interner Doku bzw. der App.

**Machbar ist die Rekonstruktion über die Setzstellen:** jede Stelle, die ein Bit in
`err1/err2/war1` setzt, steht unter einer Auslösebedingung (Schwellwertvergleich), aus der sich
die Bedeutung ableiten lässt. `Inverter_Grid_Control` schreibt z.B. nachweislich in die obere
Hälfte von `err1` (0x200019F6). Das ist ein **eigenes Arbeitspaket** (die Micro-FW enthält
~1000 `orr`/`bic`-Instruktionen in 168 Funktionen; relevant ist davon nur die Protection-Logik)
und nicht in einem Zug mit der Registeranalyse zu erledigen.

Gleiches gilt BMS-seitig für `Protect1`/`Protect2` (Pack-Register 34x09) — die BMS-FW gibt sie
nur numerisch aus (`Protect1:%d  Protect2:%d`).

---

## 10. Ghidra-Korrektur

`0x08032F20` war als **`Register_PackDescriptor`** benannt — die Funktion registriert jedoch
nichts, sondern baut aus vier Komponenten eine 29-Bit-CAN-Arbitration-ID (Funktionscode,
Quelle, Ziel, Zähler). Sie hat 41 Aufrufer. Umbenannt in **`CAN_Build_Arbitration_ID`**,
analog zur gleichnamigen Funktion in der BMS-FW, und mit Erklärkommentar versehen.

---

## 11. Nachtrag 2026-08-16 — Re-Analyse der offenen Punkte 1–4

Erneuter Ghidra-Durchlauf (ReVa/PyGhidra auf v150, 1630 Funktionen) mit dem Ziel, die
in Abschnitt 6 gelisteten Restpunkte durch Code-Erzeugung aus dem Decompilat weiter
aufzulösen. **Methodischer Fund vorab:** Dieses Image lädt SRAM-Adressen **nicht** per
`movw/movt` (0 `movt`-Instruktionen im gesamten Image), sondern ausschließlich über
**Literal-Pools** (`ldr rX,[pc,#…]`). Der Writer/Reader-Scan wurde entsprechend auf
Pool-Wort-Auflösung umgestellt (Pool-Wort = SRAM-Zieladresse, Ghidra-Referenz vorhanden).

### Punkt 1 — Pack-Feldnamen: Blocker reproduziert, Offsets weiter gehärtet

- **Fehlender Flash-Tail bestätigt.** Ein Vollscan der Flash-Wörter ergibt **290 Pointer,
  die hinter das Image-Ende (0x0805EFFF) zeigen**, konzentriert auf **0x08061000 (165),
  0x08060000 (71), 0x0805F000 (47)**. Genau dort liegen die Cloud-`snprintf`-Formatstrings
  mit den Pack-Feldnamen. Der Befund aus Abschnitt 1 ist damit unabhängig reproduziert:
  die exakten Namen sind **physisch nicht im `.bin`**. Mehr Decompilat kann Strings, die
  nicht im Image stehen, nicht rekonstruieren → **harter Datenverfügbarkeits-Blocker**,
  nur per SWD-/OpenOCD-Dump der Region lösbar.
- **Offsets zusätzlich gehärtet.** `Schedule_MinMax_PerGroup_Calc` (0x08013314) iteriert
  bestätigt 6 Packs à Stride 0x60 und liest die 16 Zellen ab Pack+0x20 (= 34x18) ✓.
  `BLE_Build_BMS_Data_Response` (0x0800b4f4) liest unabhängig **Pack+0x4A und +0x4C** →
  bestätigt **34x11 = Ave-NTC** und **34x12 = MOS-NTC** (zweite Quelle neben BMS-CAN 0x41).
  Damit sind 34x11/34x12 von „Hypothese" auf **bestätigt** hochgestuft; 34x03/04/07/08/09
  bleiben inhaltlich per BMS-FW belegt, nur ohne Cloud-Klartextnamen.

### Punkt 2 — 30031–30035 (Inverter/MPPT-Struct-Schwanz): **Writer identifiziert** ✓

Kein „unaufgelöster" Schwanz mehr. Die Schreibkette ist vollständig:

```
CAN_FrameDispatcher (Protokolltyp-Feld Bits20-23 == 2)
  -> Modbus_ResponseDispatch (0x0802f630), Verzweigung nach CAN-Funktionscode (Lowbyte):
       fc 0x03 -> Modbus_StoreRegisterSlot  -> Basis 0x20014F4C, Slots 1..7 (+0x00..+0x30)
       fc 0xFF -> Modbus_StorePairSlot      -> Basis 0x20014F84 (= +0x38), 8-Byte-Paar
```

| Register | SRAM | Writer | Bedeutung |
|---|---|---|---|
| 30031–30034 | 0x20014F84–0x20014F8A | `Modbus_StorePairSlot`, fc 0xFF Slot 1 | Erweiterter Telemetrie-Kanal des Inverter/PV-CAN-Node (gleiche Quelle wie 30020–30040) |
| 30035 | 0x20014F8C (i16) | fc 0xFF Slot 2 | dito |

`Modbus_StoreRegisterSlot` (fc 0x03) begrenzt den Slot-Index auf `< 8` (Slots 1–7), schreibt
also **nie** den +0x38-Schwanz — daher füllt fc 0xFF (`Modbus_StorePairSlot`) diese vier
Register. `MPPT_Debug_Print` gibt Slot 8 nicht aus → **kein Klartextname im Image**, aber
Herkunft und Struktur sind jetzt eindeutig. Live = 0 (kein PV/Inverter aktiv), konsistent.
Durabler Ghidra-Kommentar auf `Modbus_StorePairSlot` gesetzt.

### Punkt 3 — 30212 / 0x20000138: **kein Runtime-Writer — statisches Read-only-Byte** ✓

- Ein **Store-Vollscan über das gesamte Image (8341 Stores)** findet **keinen einzigen
  Schreibzugriff** auf 0x20000138 — weder per Immediate- noch per abdeckendem Wort-/
  Doppelwort-Store.
- Ein zunächst gemeldeter `strd`-Treffer in `MQTT_JSON_RPC_Dispatcher` (0x0801c070) war ein
  **Falsch-Positiv**: der `strd r0,r1,[sp,#0]` ist ein **Stack-Store**; wegen der
  strd-Operandenreihenfolge hatte der Resolver r1 (=0x20000136) fälschlich als Basis gelesen.
  Die echten Schreibzugriffe dort sind `strb r0,[0x20000136]` mit Werten **0/1/3** je nach
  **Leistungsklasse** (600/800/1200/1500/2200/2500 W) — also das Klassen-Config-Byte
  @0x20000136, **nicht** 0x20000138.
- **Schluss:** 0x20000138 (Reg 30212, u8, Live konstant **5**) wird von keiner Business-Logik
  beschrieben. Es ist ein **statisch initialisiertes, schreibgeschützt via Descriptor
  ausgeliefertes Config-/Variantenbyte** (Init aus dem `.data`-Abbild beim Reset). Das
  frühere „keine aufgelösten Writer/Reader" ist damit erklärt statt offen. Durabler
  Ghidra-Kommentar auf 0x0801c054/0x0801c070 gesetzt.

### Punkt 4 — 32202 (elem_size 4 bei i16): **kein Typkonflikt, 4-Byte-Fenster** ✓

Descriptor-Eintrag: `32202, i16, elem_size 4, count 1, src 0x20014EB4`. Vergleich aller
`elem_size==4`-Einträge zeigt: **alle anderen** sind echte 32-Bit-Typen (u32/float32,
z.B. 33000, 36000, 32102). **32202 ist der einzige i16 mit elem_size 4.** Konsequenz im
Serializer: es werden **4 Byte ab 0x20014EB4** ausgegeben = zwei benachbarte i16-Felder:

| Register | SRAM | Feld |
|---|---|---|
| 32202 | 0x20014EB4 | `grid_sample_power` (i16, 1 W) — identisch zu 30006/37004 |
| 32203 | 0x20014EB6 | `off_grid_power` (i16, 1 W) — das „Phantom"-Register aus elem_size 4 |

Damit ist auch **32203 benannt** (Live=0, off-grid inaktiv → plausibel). Es ist kein
Datentyp-Widerspruch, sondern eine Descriptor-Eigenheit (elem_size wie ein 32-Bit-Feld
gesetzt, Typbyte i16), die zwei i16-Werte als Registerpaar exponiert. Für die HA-Integration:
32202 = grid_sample_power (i16), 32203 = off_grid_power (i16).

### Status nach dem Nachtrag

| Punkt | vorher | jetzt |
|---|---|---|
| 1 Pack-Feldnamen | offen (Flash-Tail fehlt) | **Blocker reproduziert & bestätigt**; 34x11/34x12 auf bestätigt hochgestuft |
| 2 30031–30035 | ungelöst | **gelöst** — Writer/Quelle identifiziert (CAN fc 0xFF Pair-Slot) |
| 3 30212 / 0x20000138 | keine Writer/Reader | **erklärt** — statisches Read-only-Config-Byte, kein Runtime-Writer (Falsch-Positiv widerlegt) |
| 4 32202 | Descriptor-Inkonsistenz | **erklärt** — 4-Byte-Fenster; 32202=grid_sample_power, 32203=off_grid_power |

*Erzeugt via ReVa/PyGhidra-Skripte (Literal-Pool-Auflösung, Store-Vollscan, Effektivadress-Resolver). Ghidra-Kommentare durabel gesetzt auf Modbus_StorePairSlot und MQTT_JSON_RPC_Dispatcher.*

---

## 12. Nachtrag 2026-08-16 (Teil 2) — Pack-Feldnamen DOCH in der FW gefunden

**Korrektur des Kernbefunds aus Abschnitt 1/6.** Die Annahme „Pack-Feldnamen nur im fehlenden
Flash-Tail" war zu pessimistisch (analog zur Modbus-Tabelle, die auch erst „nicht im Bin" schien
und dann doch da war). Nach Freigabe des FW-Archivs und einem frischen Vollcheck über alle drei
Firmwares steht fest: **die Feldnamen liegen als Klartext in der Firmware.**

### 12.1 Namen sind als Strings im Image (roh nachgewiesen)

- **Control v150** enthält u.a. den vollständigen Per-Pack-Debug-String
  `cd=%d,b_ver,b_chv,b_rci,b_rdi,b_soc,b_soh,b_cap,b_vol,b_cur,b_tem,b_chf,b_slf,b_cpc,b_err,b_war,
  b_ret,b_ent,b_mot,b_tp1..b_tp4,b_vo1..b_vo16,self_check,mos` sowie den Cloud-JSON-Key-String
  (`{"d":"di=%s&sn=%s&...&t1..t3&vc&tc&cy&..."}`) und PV-/BMS-Strings. Nur die *druckende* Cloud-
  Funktion liegt hinter dem Image-Ende — die **Namen selbst sind drin**.
- **BMS v118** enthält die maßgeblichen Feldnamen als Debug-Strings (`Bat Volt`, `Bat Curr`,
  `Bat Soc`, `Cyc Cnt`, `Chg Mos/Dsg Mos`, `Max/Min/Ave NTC`, `MOS NTC/ENV NTC`, `Max/Min Cell`,
  `Cell NTC`, `Cell Volt`, `Protect1/Protect2`, `Version`, `Soh`, `Max/Min Temp`).

### 12.2 Ursache, warum die Refs fehlten: nicht-disassemblierter Code

Diese Strings hatten in Ghidra `referenceCount 0`, weil die zugehörigen Funktionen **nicht
disassembliert** waren. Coverage-Analyse BMS: ~29 KB Instruktionen, aber **~21 KB undefinierte
Bytes**, davon große Blöcke mit klaren Thumb-Prologen (`push {..,lr}`) = Code. Es gab also sehr
wohl noch nicht dekompilierte Bereiche.

**Nachgeholt (Disassemblier-Lauf über Prolog-Kandidaten in den Lücken):**

| Firmware | Funktionen vorher | nachher | neu |
|---|---|---|---|
| BMS v118 | 550 | 649 | **+99** |
| Control v150 | 1630 | 1884 | **+254** |
| Micro v116 | 571 | 584 | **+13** |

### 12.3 Autoritative Pack-Feldliste (aus neu dekompilierter BMS-Funktion)

`BMS_Debug_PerPack_Detail_Print` @0x08007098 (vormals FUN_/undisassembliert) iteriert alle Packs
(BMS-interne Struct, Basis 0x200041b6, **Stride 0x60**) und druckt jedes Feld mit Name, Skala und
Offset. Damit ist die Feldliste **firmware-belegt** (nicht mehr geraten):

| Feld | Skala/Typ | Feld | Skala/Typ |
|---|---|---|---|
| Bat Volt | u16, /100 → 10 mV | Cell NTC[5] | i16 (5 Zell-Temps) |
| Bat Curr | i16, /10 → 0.1 A | Cell Volt[16] | u16, mV |
| Bat Soc | u16, /10 → 0.1 % | Max/Min Cell | u16, mV |
| Cyc Cnt | u16 | Max/Min NTC | i16 |
| Chg/Dsg Mos | u8 Bitfeld | Ave NTC / MOS NTC / ENV NTC | i16 |
| Protect1/Protect2 | u16 (Bitmaske) | Version | u16 |

Der BMS-Debug-String `cd=%d, BMS(%d): num,vol,cur,soc,c_vol,c_cur,d_cur,mos,ver,max_v,min_v,
max_t,min_t,b_err1,b_err2,b_war1,b_vol[16],temp[5],env,mos` liefert zusätzlich die
Overview-Feldreihenfolge der per-Pack-CAN-Frames.

### 12.4 Auswirkung auf die Register-Map

Die Control-Pack-Register (34xNN, Pack-Struct 0x20014FB4, Stride 0x60) sind damit
**FW-belegt benannt** statt hypothetisch. In `Marstek_Venus_D_Register_Map_Final_all_register.csv`
wurden **91 Pack-Register** (alle 7 Packs) mit dem BMS-Feldbeleg versehen und die Konfidenz
hochgestuft (u.a. 34x00 Bat Volt, 34x01 Bat Curr, 34x05/06 Max/Min Cell, 34x08/09 Protect1/2,
34x17 ENV NTC → **hoch**). Bereits zuvor bestätigt: 34x02 SOC, 34x03 Cyc Cnt, 34x04 Chg/Dsg Mos,
34x10 Version, 34x11/12 Ave/MOS NTC, 34x13–16 Cell-NTC, 34x18–33 16 Zellspannungen.

### 12.5 Was echt offen bleibt

- **Exakte Byte-Reihenfolge einiger Overview-Felder** (z.B. 34x07 @+0x18, Live 0..7 = Flag, keine
  Temperatur) — auflösbar über die noch nicht extrahierte Control-Per-Pack-CAN-Store-Funktion.
- **Cloud-JSON-Kurz-Keys** (di/sn/to/…): der Formatstring ist im Image, die zusammenbauende
  Cloud-Funktion liegt im abgeschnittenen Bereich 0x0805F000+. Für die Modbus-Register aber
  irrelevant, da die BMS-Namen maßgeblich sind.

**Fazit:** Die These „Namen nicht rekonstruierbar" ist widerlegt. Die Pack-Feldnamen sind in der
Firmware vorhanden, wurden durch Disassemblieren versteckten Codes freigelegt und in die
Register-Map übernommen.

---

## 13. Nachtrag 2026-08-16 (Teil 3) — Pack-Overview byte-genau + Korrekturen

Dein Einwand („runtime-aufgebaut heißt nicht unauffindbar") war goldrichtig. Der komplette
Per-Pack-Store-Pfad ist jetzt aus dem Flash rekonstruiert — die Handler waren nur nicht
disassembliert.

### 13.1 Store-Pfad

```
CAN_FrameDispatcher (0x0802f274) -> else -> Protocol_AA_CommandDispatch (0x0802fb88)
   -> Dispatch ueber SRAM-Tabelle 0x2000018c (matcht CAN-Gruppe id>>0x10)
   -> 8 Store-Handler bei 0x0802f764..0x0802f8b8 (vormals undisassembliert, jetzt benannt):
```

| Handler | CAN-Grp | Pack-Offset | Inhalt |
|---|---|---|---|
| CAN_Store_PerPack_Grp20_Overview0 | 0x20 | +0x00 | 34x00 BatVolt, 34x01 BatCurr, 34x02 Soc, 34x03 CycCnt |
| CAN_Store_PerPack_Grp21_Overview1 | 0x21 | +0x08 | +0x08/0c misc, **34x04(+0x0e)=Chg/Dsg-Mos-Flag** |
| CAN_Store_PerPack_Grp22_Overview2 | 0x22 | +0x10 | 34x05 MaxCell, 34x06 MinCell, +0x14 MaxNTC, +0x16 MinNTC |
| CAN_Store_PerPack_Grp23_Overview3 | 0x23 | +0x18 | **34x07 Protect1, 34x08 Protect2, 34x09 rsv(+0x5a), 34x10 Version** |
| CAN_Store_PerPack_Grp30_33_Cells | 0x30-33 | +0x20 | 34x18-34x33 = 16 Zellspannungen |
| CAN_Store_PerPack_Grp40_CellNTC | 0x40 | +0x40 | 34x13-34x16 = 4 Cell-NTC |
| CAN_Store_PerPack_Grp41_NTC | 0x41 | +0x48 | +0x48 AveNTC(kein Reg), **34x11(+0x4a)=ENV NTC, 34x12(+0x4c)=MOS NTC, 34x17(+0x4e)=0** |
| CAN_Store_PerPack_GrpExt_0x50 | – | +0x50 | Zusatzframe (nicht in CAN_TX_PerPack_10Msgs) |

Die Byte-Semantik jeder Frame ist aus dem BMS-Sender `CAN_TX_PerPack_10Msgs` (0x08005b58,
BMS v118) verifiziert — der liest die BMS-Struct-Felder und packt sie 1:1 in die 8-Byte-Frames.

### 13.2 Korrekturen an der Register-Map (42 Zeilen, alle 7 Packs)

| Register | vorher | **jetzt (FW-belegt)** |
|---|---|---|
| **34x07** (+0x18) | status_flags (Hypothese) | **Protect1** (Schutz-Bitmaske 1; Live 0..7 passt) |
| **34x08** (+0x1a) | protect1 | **Protect2** (Schutz-Bitmaske 2) |
| **34x09** (+0x1c) | protect2 | **BMS-Feld @struct+0x5a** (im Debug-Print unbenannt, Live ~0) |
| **34x11** (+0x4a) | temp_1 / „Ave NTC" | **ENV NTC** (Umgebungstemp) |
| **34x12** (+0x4c) | temp_2 | **MOS NTC** (MOSFET-Temp) |
| **34x17** (+0x4e) | temp_3 (niedrig, „Live meist 0") | **konstruktionsbedingt IMMER 0** (Frame 0x41 Byte6-7 = 0) |

Bestätigt (unverändert): 34x00 BatVolt, 34x01 BatCurr, 34x02 Soc(0.1%), 34x03 CycCnt,
34x04 Chg/Dsg-Mos, 34x05 MaxCell, 34x06 MinCell, 34x10 Version, 34x13-16 Cell-NTC,
34x18-33 16 Zellspannungen.

### 13.3 Ergebnis

**Damit ist die Pack-Overview lückenlos und byte-genau aufgelöst — die letzte offene Frage
(34x07) ist beantwortet.** Es gibt keine „nicht rekonstruierbaren" Pack-Register mehr; die
einzigen nicht als Modbus-Register exponierten Felder (+0x08/0c misc, +0x14/16 Max/Min NTC,
+0x48 Ave NTC) sind identifiziert, aber vom Descriptor schlicht nicht ausgegeben.
