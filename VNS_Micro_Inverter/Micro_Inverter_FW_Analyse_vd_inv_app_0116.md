# Marstek Venus D — Micro/Inverter Co-Prozessor Firmware Analyse
## `vd_inv_app_0116_0702_ota_163439.bin`

**Firmware:** v116 (OTA `firmwareType: micro`)  
**Analysedatum:** 04.07.2026 (Ersterfassung), **10.07.2026** (Korrektur-Session, Tranche 2 + Tranche 3a/3b/3c + Tranche 4a/4b/4c + Tranche 5a/5b/5c)  
**Methode:** Statische Analyse (Ghidra + ReVa MCP)  
**Status:** CAN-Protokoll, SRAM-Map, Debug-Shell, RS485 Modbus Register-Map, Fehlercodes, Netzstandards, EEPROM-Map dekodiert.
**Funktions-Benennung:** 392/445 Funktionen in Ghidra tatsächlich benannt (88,1%), Stand 10.07.2026 nach Abschluss Tranche 5a+5b+5c (unabhängig verifiziert per `get-function-count filterDefaultNames=true/false` + vollständigem Dubletten-Scan über alle 392 Namen, 0 Kollisionen). 53 Funktionen sind noch `FUN_*` — davon 5 bestätigte Ghidra-Interworking-Veneers/Sprungtrampoline (10 Byte, keine echten eigenständigen Funktionen, s. 13.18/13.21), eine unreferenzierte "Dead-Code"-Funktionsfamilie um 0x08002824/0x08004528 (0 Caller, Instance-Adressen außerhalb der offiziellen STM32F3-Peripheriekarte), ein HRTIM-Cluster bei 0x080090f8 (ebenfalls 0 Caller) und ein GPIO/UART/ADC-Bitfeld-Restcluster (0x08009a40–0x08009a92, Compiler-Identical-Code-Folding über Peripherie-Domänen hinweg), der Rest sind reine 2-16-Byte-Stubs/Padding ohne rekonstruierbare Semantik. Diese verbliebenen 53 gelten als statisch ausgereizt — weitere Tranchen würden voraussichtlich keine zusätzlichen Treffer mehr liefern.

> ⚠️ **Wichtiger Hinweis (10.07.2026):** Die in einer früheren Version dieser Doku behauptete Quote
> "398/445 (89%)" aus der "Massenanalyse vom 07.07.2026 via 5 parallele Ghidra-Agenten" war **falsch**
> bzw. wurde **nie in Ghidra eingecheckt**. Beim Öffnen des Projekts am 10.07.2026 waren in Ghidra nur
> **21 Funktionen** tatsächlich benannt (Rest weiterhin `FUN_0800xxxx`). Die Namen in Abschnitt 13 unten
> stammten aus einer Analyse, die nie persistiert wurde. In dieser Session wurden **106 der in Abschnitt 13
> gelisteten Namen einzeln per Dekompilierung verifiziert und in Ghidra umbenannt** (siehe Hinweis-Box in
> Abschnitt 13). Ein Teil der ursprünglich dokumentierten Namen erwies sich dabei als **falsch** (Adress-Drift,
> vermutlich aus der nie verifizierten 07.07-Analyse) und wurde bewusst **nicht** übernommen bzw. korrigiert —
> siehe Abschnitt 13.9 "Korrektur-Session 10.07.2026".

---

## 1. Binary-Fingerprint

Live aus Ghidra verifiziert (Stand 2026-07-15). Ein Vergleich mit den anderen fünf analysierten
Firmware-Images (Control 149.2/147, VNS 115, BMS 118/117.7) steht in der Projekt-`README.md`.

| Eigenschaft | Wert |
|---|---|
| Datei | `vd_inv_app_0116_0702_ota_163439.bin` |
| Version | 116 (aktuell) |
| Größe | 115.712 B (0x1C400, 113 KB) |
| Architektur | ARM Cortex-M4F, Thumb-2, Little-Endian |
| Flash-Bereich | `0x08000000–0x0801C3FF` |
| Initial SP | `0x20009A70` (~40 KB SRAM) |
| Reset Handler | `0x080042AD` |
| Funktionen | 392 / 445 benannt (88,1 %) |
| Strings | 251 |
| Compiler | RVDS/Keil ARM |
| RTOS | FreeRTOS (`heap_4`, `ARM_CM4F`-Port, FPU aktiv) |
| Crypto | — (keine mbedTLS) |
| WiFi/TCP | — (nicht vorhanden) |
| Kommunikation | CAN + RS485 |

**Wesentliche Unterschiede zur Control-FW:**
- Kein WiFi-Stack, kein TCP/IP, kein Modbus TCP — die Micro-MCU kommuniziert ausschließlich über CAN-Bus und RS485/UART
- Kein mbedTLS — keine Verschlüsselung, keine Cloud-Anbindung
- Deutlich kleiner (~30% der Control-FW)
- Verwendet RVDS/Keil Compiler statt GCC
- Enthält eigenen Bootloader-Thunk-Bereich (`0x10000xxx`)

---

## 2. Speicher-Layout

```
Flash (0x08000000 – 0x0801C3FF):
  0x08000000 – 0x080001FF   IVT (Interrupt-Vektortabelle)
  0x08000200 – 0x080009FF   Thunks zu Bootloader (0x10000xxx)
  0x08000A00 – 0x0800B3FF   Peripherie-Treiber (CAN, UART, ADC, GPIO, Flash, PWM)
  0x0800B400 – 0x0800B5FF   FreeRTOS Task-Erstellung
  0x0800B600 – 0x0800C8FF   Firmware-Update (UART Ymodem + CAN)
  0x0800C900 – 0x0800D7FF   Debug/Diagnose-Ausgabe (Sensor-Dump)
  0x0800D800 – 0x0800DFFF   Utility-Funktionen
  0x0800E000 – 0x0800E9FF   Hex-Konvertierung, FreeRTOS Assert-Handler
  0x0800EA00 – 0x0800EDFF   Initialisierung, CAN-Filter-Setup
  0x0800EE00 – 0x08014FFF   Wechselrichter-Regelung (FP-intensiv)
  0x08015000 – 0x0801C3FF   FreeRTOS Kernel + Task-Schleifencode

SRAM-Regionen (identifiziert):
  0x20000000 – 0x200003FF   Task-Handles, Konfiguration, Kalibrierdaten
  0x20000400 – 0x200004FF   Betriebsparameter, Flags, Modi
  0x20000D00 – 0x20000EFF   ADC-Messwerte (Roh + kalibriert)
  0x20001400 – 0x200019FF   Debug-Counter, Fehlerlog, Energiezähler
  0x20003400 – 0x200038FF   FW-Update-Puffer, CAN-Empfangspuffer
  0x20003900 – 0x200039FF   BMS-Daten (via CAN empfangen)
  0x20003D00 – 0x20003EFF   Betriebsmodi, Konfiguration
```

---

## 3. FreeRTOS Task-Architektur

`FUN_0800b420` = Task-Creator (noch nicht in Ghidra umbenannt, außerhalb Tranche-2c-Bereich), `0x08013998` = `xTaskCreate` (in Ghidra benannt)

| Task | Priorität | Stack | Entry-Point | Funktion |
|---|---|---|---|---|
| `vtask_led` | 16 (höchste) | 512 B | `0x080163E8` | LED-Statusanzeige |
| `vtask_time` | 15 | 1 KB | `0x080164C8` | Zeitgeber/RTC |
| `vtask_modbus` | 14 | 512 B | `0x08016424` | RS485-Modbus-Kommunikation |
| `vtask_shell` | 9 | 2 KB | `0x0801643C` | Debug-CLI (UART) |
| `vtask_prt` | 8 | 1 KB | `0x08016430` | Debug-Ausgabe |
| `vtask_can_receive` | 7 | 1 KB | `0x080163E0` | CAN-Empfang |
| `vtask_can` | 6 | 1 KB | `0x080163D0` | CAN-Senden |
| `IDLE` | 0 | 512 B | `0x08012FD0` | FreeRTOS Idle |

**Anmerkung:** Die Task-Entry-Points ab `0x08016xxx` liegen in einem zusammenhängenden FP-Codeblock für die Wechselrichter-Regelung. Ghidra hat Schwierigkeiten mit der Funktionsgrenzen-Erkennung dort, da die Regelschleifen stark ineinandergreifen.

---

## 4. Kommunikationsarchitektur

### 4.1 CAN-Bus (Hauptkommunikation)

CAN-Peripherie: `0x40006400` (CAN1, STM32F3-Layout — bxCAN, gleiche Basisadresse wie bei F4)

**CAN-Init/HAL-Layer (Tranche 3a, 10.07.2026 identifiziert):** `CAN1_Init` (`0x08001ea0`) baut das
CAN-Handle auf (Instance=`0x40006400`, Timing-Parameter) und ruft `HAL_CAN_Init` (`0x08004fe0`,
klassische bxCAN-Init-Zustandsmaschine: INRQ setzen → auf INAK warten (Timeout via `HAL_GetTick`) →
MCR/BTR/Mode konfigurieren → `CAN_InitMailboxes` → State=READY). Laufzeit-Funktionen:
`HAL_CAN_AddTxMessage` (`0x08004c5c`, wählt freie TX-Mailbox über TSR-Code-Feld, ruft `CAN_CopyTxFrame`),
`HAL_CAN_ConfigFilter` (`0x08004caa`, gemeinsame Filterbank-Schreibfunktion, aufgerufen aus
`CAN_SetFilter_ExtID`/`CAN_SetFilter_StdID`), `HAL_CAN_GetRxMessage` (`0x08004d70`, dekodiert
FIFO0/FIFO1-Mailbox: IDE/RTR/ID/DLC/Timestamp/FilterMatchIndex + Datenkopie), `HAL_CAN_IRQHandler`
(`0x08004e76`, zentrale ISR — dispatcht TME/FMP0/FMP1/FF/FOV/EWG/EPV/BOF/LEC/ERR anhand SR&IER-Masken
an die jeweiligen Sub-Handler, ruft am Ende den Error-Callback bei gesetztem Fehlercode).

**Ergänzung Tranche 4b (10.07.2026):** `HAL_CAN_DeInit` (`0x08004d3e`, wird als allererster Schritt in
`CAN1_Init` aufgerufen, setzt State/ErrorCode auf `0`/RESET zurück, ruft `CAN_ExitInitMode_WaitAck` +
einen No-Op-Msp-DeInit-Stub) und `HAL_CAN_ActivateNotification` (`0x08004b7c`, State-Guard
`READY|LISTENING` identisch zur echten HAL-Funktion, aktiviert IER-Bits mit Spurious-IRQ-Vermeidung;
Aufrufer: `CAN1_Init` [TX-Mailbox-Empty] und `HAL_CAN_RxFifo0MsgPendingCallback` [Re-Arm nach
Nachrichtenverarbeitung]) vervollständigen den CAN-HAL-Layer weiter.

**CAN-Filter (konfiguriert in `CAN_Filter_Setup`, `0x0800eb88`):**

| Filter | ID | Maske | Matches | Protokoll |
|---|---|---|---|---|
| 1 | `0x4000` | `0xFF00` | `0x40xx` | EMS→Inverter Befehle |
| 2 | `0x4100` | `0xFF00` | `0x41xx` | Inverter→EMS Antworten |
| 3 | `0x1801AA01` | `0x1FF0FFFF` | `0x180xAA01` | BMS CAN-Protokoll |

**Ergänzung Tranche 4a (10.07.2026):** `HAL_CAN_RxFifo0MsgPendingCallback` (`0x08005248`) dispatcht
zusätzlich nach `FilterMatchIndex==4` an `BMS_FW_Update_CAN_Handler` (`0x08001868`) — ein
PF-Byte-basierter Handler analog zu `BMS_CAN_Parser`, der Init/Verify-Zustände (Werte `2`/`4`) nach
SRAM `0x200038cb`–`0x200038d0` schreibt und damit vermutlich den in Abschnitt 9 dokumentierten
"BMS-Update über CAN"-Pfad (CMD `0xCE`) bedient. Die genaue ID/Masken-Konfiguration dieses 4. Filters
wurde nicht separat aus `CAN_Filter_Setup` extrahiert (offen für eine künftige Tranche).

### 4.2 BMS CAN-Protokoll (Extended Frame, 29-bit)

Parser: `FUN_080018e8` — PF-Byte (Bits 16–19 der CAN-ID) bestimmt den Nachrichtentyp.

| CAN-ID | PF | Byte 0–1 | Byte 2–3 | Byte 4–5 | Byte 6–7 |
|---|---|---|---|---|---|
| `0x1801AA01` | 1 | bat_vol (u16) | bat_cur (i16) | max_temp (i16) | soc (u16) |
| `0x1802AA01` | 2 | cap (u16) | ? | ? | ? |
| `0x1803AA01` | 3 | charge_u (u16) | charge_i (u16) | discharge_i (u16) | ? |
| `0x1804AA01` | 4 | err (u32) | warn (u32) — **s. Anmerkung unten** |

**SRAM-Mapping der BMS-Daten:**

| SRAM-Adresse | Variable | Typ | Inhalt |
|---|---|---|---|
| `0x2000397B` | bat_vol | uint16 | BMS Batteriespannung |
| `0x2000397D` | bat_cur | int16 | BMS Batteriestrom |
| `0x2000397F` | max_temp | int16 | BMS Max-Temperatur |
| `0x20003981` | soc | uint16 | State of Charge |
| `0x20003983` | cap | uint16 | Kapazität |
| `0x2000398A` | sleep_flag | byte | BMS Sleep-Anforderung |
| `0x2000398B` | charge_u | uint16 | Ladespannungs-Sollwert |
| `0x2000398D` | charge_i | uint16 | Ladestrom-Limit |
| `0x2000398F` | discharge_i | uint16 | Entladestrom-Limit |
| `0x20003991` | charge_req | byte | Ladeanforderung (Flag) |
| `0x20003992` | force_charge_req | byte | Zwangsladung (Flag) |
| `0x20003993` | err | uint32 | BMS Fehlerbitmask |
| `0x20003997` | warn | uint32 | BMS Warnbitmask |

> **Klarstellung (2026-07-10, per Ghidra beidseitig verifiziert, kein Widerspruch zu `BMS_FW_Analyse_v117.7.md`):**
> `BMS_CAN_Parser` (`0x080018e8`) übernimmt für PF=4 wirklich nur zwei rohe 32-Bit-Werte
> (`_bms_error_bitmask = *param_2; _bms_warn_bitmask = param_2[1];`), ohne sie weiter zu zerlegen.
> Auf Sender-Seite (`CAN_TX_PF4_ProtectWarnings`, BMS-FW `0x080055d4`) sind diese 8 Bytes aber
> strukturiert: Byte 0–1 = `protect1` (u16), Byte 2–3 = `protect2` (u16), Byte 4–5 = reserviert (immer 0),
> Byte 6 = `warn_byte`, Byte 7 = `status_flag`. Die hier als „err" gelesenen 4 Bytes sind also
> `protect1 | (protect2 << 16)`, und „warn" ist `(status_flag << 24) | (warn_byte << 16)` (untere 16 Bit
> immer 0). Beide Beschreibungen sind korrekt — die Micro-FW liest die Felder aktuell nur als
> unzerlegte 32-Bit-Rohwerte, während die BMS-FW-Seite (Sender) die feingranulare Bedeutung zeigt.
> Für die tatsächliche Bit-Bedeutung von protect1/protect2 siehe `BMS_FW_Analyse_v117.7.md` §5.2/5.3.

### 4.3 EMS↔Inverter internes CAN-Protokoll (Standard Frame, 11-bit)

Dispatcher: `FUN_08001940` (1.168 Bytes, 269 Zeilen — größte Funktion)

CAN-ID-Format: `0x40xx` (EMS→INV) / `0x41xx` (INV→EMS), wobei `xx` = Command-ID

#### Befehle EMS → Inverter:

| CMD | Hex | Beschreibung | Daten |
|---|---|---|---|
| Set Power | 0x01 | Leistungssollwert setzen | int→float Wandlung |
| Enable/Disable | 0x02 | Wechselrichter ein/aus | 0=aus, 1=ein |
| Max Discharge Power | 0x03 | Max. Entladeleistung | Limit (capped 2500W) |
| Max Charge Power | 0x04 | Max. Ladeleistung | Limit (capped 2500W) |
| Unknown Flag | 0x05 | Internes Flag setzen | DAT_2000043c=1 |
| Sleep Mode | 0x06 | Schlafmodus | DAT_200004a4=1 |
| Address Assign | 0x07 | CAN-Adresse zuweisen | Adresse+1 |
| Config Block | 0x16 | Konfigurationsdaten | 8 Bytes → 0x20003EA7 |
| Factory Test Enter | 0x50 | Werkstestmodus | 0=exit, 1=enter |
| FW Update Trigger | 0x51 | Firmware-Update starten | — |
| FW Update Phase | 0x52 | Update-Phase setzen | 1/2/3 → Step 2/3/4 |
| FW Update Complete | 0x53 | Update abschließen | Step=5 |
| FW Update Finalize | 0x55 | Update finalisieren | Step=6 |
| Set Power (Factory) | 0x56 | Leistung im Werksmodus | Power-Wert |
| Backup Mode | 0x57 | Notstrom ein/aus | 1=ein, 0=aus |
| Set Power (Battery) | 0x58 | Leistung im Bat-Modus | Power-Wert |
| Start FW Update | 0x60 | FW-Update initiieren | Update-Typ |
| FW Update Sequence | 0xC1 | Update-Sequenz starten | Step=1 |
| Debug Mode | 0xC2 | Debug ein/aus | 1→Level 2, else→1 |
| CAN Queue Data | 0xC3 | Daten an CAN weiterleiten | bis 8 Bytes |
| Flash Program | 0xCE | Flash-Programmierung | Typ 0=Init, 1=Data, 2=Verify |

#### Antworten Inverter → EMS:

| CMD | Hex | Beschreibung | Daten |
|---|---|---|---|
| Data Block | 0x10 | 48 Bytes Betriebsdaten | ab 0x200038E8 |
| Status | 0x11 | 8 Bytes Statusinfo | ab 0x20000440 |
| Version Info | 0x12 | FW-Versionsdaten | 6 Bytes |
| Calibration | 0x13 | Kalibrierdaten | 4 Bytes |
| Flash ID | 0x54 | Flash-Chip-Identifikation | — |
| Version/Flash | 0xCB | Erweiterte Version/Flash-Info | 8 Bytes |

**Wichtige Erkenntnisse:**
- **Max-Power-Cap 2500W** (0x9C4) — bestätigt Venus-D-Hardware
- `DAT_20003E04` = work_mode: `0x00`=Normal, `0x01`=Test, `0x04`=Update, `0x0C`=Factory
- `DAT_2000043E` = Firmware-Update-Step-Counter (1–7)
- `DAT_200004AD` = max_discharge_power, `DAT_200004AB` = max_charge_power (beide ≤2500)

---

## 5. ADC-Sensor-Map (Inverter-Messwerte)

Aus Debug-Funktion `FUN_0800cc40` extrahiert.

### 5.1 Roh-ADC-Werte (int16, SRAM `0x20000E44`–`0x20000E62`)

| SRAM | Variable | Typ | Beschreibung |
|---|---|---|---|
| `0x20000E44` | grid_vol | int16 | Netzspannung (Roh-ADC) |
| `0x20000E46` | offgrid_vol | int16 | Notstrom-Spannung (Roh) |
| `0x20000E48` | out_vol | int16 | Ausgangsspannung (Roh) |
| `0x20000E4A` | grid_vref1 | int16 | Netz-Referenz 1 |
| `0x20000E4C` | grid_vref3 | int16 | Netz-Referenz 3 |
| `0x20000E4E` | grid_vref4 | int16 | Netz-Referenz 4 |
| `0x20000E50` | grid_cur | int16 | Netzstrom (Roh-ADC) |
| `0x20000E52` | offgrid_cur | int16 | Notstrom-Strom (Roh) |
| `0x20000E54` | highv_vol | int16 | DC-Bus-Spannung (Roh) |
| `0x20000E56` | bat_cur | int16 | Batteriestrom (Roh) |
| `0x20000E58` | bat_cur_df | int16 | Batteriestrom diff (Roh) |
| `0x20000E5A` | bat_vol | int16 | Batteriespannung (Roh) |
| `0x20000E5C` | vac_offset | int16 | AC-Spannungs-Offset |
| `0x20000E5E` | iac_offset | int16 | AC-Strom-Offset |
| `0x20000E60` | ntc_rad1 | int16 | NTC Radiator 1 (Roh) |
| `0x20000E62` | ntc_rad2 | int16 | NTC Radiator 2 (Roh) |

### 5.2 Kalibrierte Float-Werte (SRAM `0x20000DE0`–`0x20000E34`)

| SRAM | Variable | Typ | Beschreibung |
|---|---|---|---|
| `0x20000DE0` | grid_vol | float | Netzspannung (V, kalibriert) |
| `0x20000DE4` | grid_cur | float | Netzstrom (A, kalibriert) |
| `0x20000DEC` | highv_vol | float | DC-Bus-Spannung (V) |
| `0x20000DF0` | out_vol | float | Ausgangsspannung (V) |
| `0x20000DF4` | bat_vol | float | Batteriespannung (V) |
| `0x20000DF8` | bat_cur | float | Batteriestrom (A) |
| `0x20000DFC` | bat_cur_df | float | Batteriestrom diff (A) |
| `0x20000E04` | offgrid_cur | float | Notstrom-Strom (A) |
| `0x20000E08` | offgrid_vol | float | Notstrom-Spannung (V) |
| `0x20000E0C` | highv_notch_vol | float | DC-Bus Notch-gefiltert (V) |
| `0x20000E10` | bat_vol_avg | float | Batteriespannung Mittelwert |
| `0x20000E14` | bat_cur_avg | float | Batteriestrom Mittelwert |
| `0x20000E20` | vac_offset | float | AC-Spannungs-Offset (kal.) |
| `0x20000E24` | iac_offset | float | AC-Strom-Offset (kal.) |
| `0x20000E2C` | ntc_temp | float | Temperatur allgemein (°C) |
| `0x20000E30` | ntc_inv | float | Inverter-Temperatur (°C) |
| `0x20000E34` | ntc_mppt | float | MPPT-Temperatur (°C) |

### 5.3 Weitere Kalibrier-/Statuswerte

| SRAM | Variable | Beschreibung |
|---|---|---|
| `0x20000338` | g_offset_vol | Globaler Spannungs-Offset (float) |
| `0x20000344` | real_offset_vol | Realer Spannungs-Offset (float) |
| `0x200002A4` | inverter_run_state | Inverter-Zustandsmaschine |
| `0x200002A5` | llc_run_state | LLC-Wandler-Zustand |
| `0x200002A8` | ctl_state | Control-Hauptzustand |
| `0x200004A6` | bat_mode | Batteriemodus |
| `0x200004AF` | grid_standand | Netzstandard-Code |
| `0x2000030C` | max_power | Max. Leistung (float) |
| `0x20000310` | min_power | Min. Leistung (float) |
| `0x200019F4` | err1 | Fehlerregister 1 (hex) |
| `0x200019F8` | err2 | Fehlerregister 2 (hex) |
| `0x200019FC` | war1 | Warnregister (hex) |

---

## 6. Hardware-IO-Map (GPIO)

Aus Debug-Strings in den IO-Show/Test-Funktionen extrahiert:

| GPIO-Bezeichner | Funktion | Beschreibung |
|---|---|---|
| `LED0` | Status-LED | Betriebs-/Fehler-LED |
| `IO_RELAY_GRID` | Netzrelais | Grid-Kontakt (Netzverbindung) |
| `IO_RELAY_OFFGRID` | Notstrom-Relais | Off-Grid-Kontakt (UPS) |
| `IO_FAULT_RESET` | Fehler-Reset | Hardware-Fault-Reset-Pin |
| `IO_AUX_GRID` | Hilfs-Netz | Auxiliary Grid-Kontakt |
| `IO_AUX_BAT` | Hilfs-Batterie | Auxiliary Batterie-Kontakt |
| `IO_FAULT_HARDWARE` | HW-Fehler | Hardware-Fault-Eingang |
| `IO_FAULT_HARDWARE_IGRID_1` | Netzstrom-Fehler 1 | Überstromschutz Netz Ch1 |
| `IO_FAULT_HARDWARE_IGRID_2` | Netzstrom-Fehler 2 | Überstromschutz Netz Ch2 |
| `IO_FAULT_HARDWARE_VBUS` | DC-Bus-Fehler | Überspannungsschutz DC-Bus |
| `IO_FAULT_HARDWARE_IBAT_1` | Batteriestrom-Fehler 1 | Überstromschutz Batterie Ch1 |
| `IO_FAULT_HARDWARE_IBAT_2` | Batteriestrom-Fehler 2 | Überstromschutz Batterie Ch2 |

---

## 7. Debug-Shell (UART-CLI)

Die Firmware enthält eine vollständige Debug-Shell über UART (`vtask_shell`, 2 KB Stack).
Shell-Bibliothek: letter-shell-Variante mit Kommando-/Variablen-/User-Registrierung.
Shell-Kontext-Struct in SRAM bei `0x20001410`, Eingabepuffer bei `0x2000147C` (512 Bytes).

### 7.1 Authentifizierung & Passwort

#### Auth-Mechanismus (Assembly-verifiziert)

Login-Handler: `FUN_08010208` (90 Bytes). User-Suche: `FUN_08010194` (16-Byte-Einträge,
strcmp über `FUN_08000388`). Passwort-Prüfung in `FUN_0800f7a0`.

Die Authentifizierung erfolgt in drei Stufen — die **ersten beiden gewähren Zugang ohne Passwort**:

```
FUN_08010208 — Login-Entscheidung (Assembly 0x08010210–0x0801022A):

  0x08010210: LDR r0, [r5, #0x8]      ; r0 = Passwort-Pointer aus User-Entry+8
  0x08010212: CMP r0, #0               ; NULL-Check
  0x08010214: BEQ 0x08010256           ; → NULL = KEIN PASSWORT → Zugang gewährt
  0x08010216: BL  FUN_0800037a         ; r0 = strlen(passwort)
  0x0801021A: CBZ r0, 0x08010256       ; → strlen==0 = LEERES PASSWORT → Zugang gewährt
  0x0801021C: LDRH r0, [r4, #0x36]    ; Argument-Count prüfen
  0x08010222: LDR r1, [r4, #0x18]     ; r1 = User-Eingabe-Buffer
  0x08010224: LDR r0, [r5, #0x8]      ; r0 = Passwort erneut laden
  0x08010226: BL  FUN_08000388         ; strcmp(passwort, eingabe)
  0x0801022A: CBZ r0, 0x08010256       ; → Match = Zugang gewährt
              ; sonst: "password error", Zugang verweigert
```

Bestätigte Hilfsfunktionen:
- `FUN_0800037a` = `strlen` (14 Bytes, do-while-Schleife bis `\0`)
- `FUN_08000388` = `strcmp` (Rückgabe 0 bei Match)
- `FUN_080106d0` = `shell_print` (String-Ausgabe über UART)

#### User-Eintrag

Die Shell-Kommandotabelle liegt im Flash bei `0x0801892C` bis `0x08018C7C`
(53 Einträge × 16 Bytes = 0x350 Bytes, Literal-Pool bei `0x0800FE38/FE3C`).

> **Hinweis:** Die Tabelle wird vom RVDS/Keil-Compiler im Code/Daten-Interleave-Format
> erzeugt. Die 16-Byte-Einträge sind zwischen ARM-Instruktionen eingebettet, was
> statisches Parsen der Struct-Felder erschwert. Die Entry-Suche (`FUN_08010194`)
> iteriert mit `entry_addr = base + index * 0x10` und prüft `*(byte)(entry+1) & 0xF`
> als Type-Feld (Type 8 = USER).

String-Daten im Shell-Datenbereich (`0x08013F70`–`0x080148FF`):

```
0x0801447C: 55 73 65 72 00          "User\0"
0x08014481: 00                      "\0"          ← leeres Passwort-Feld
0x08014482: 64 65 66 61 75 6C 74 20 75 73 65 72 00  "default user\0"
```

#### Passwort-Bewertung

| Indiz | Bewertung |
|---|---|
| String-Daten zeigen `User\0\0default user` | Leeres Passwort zwischen Name und Beschreibung |
| Auth-Code hat explizite NULL/Empty-Pfade | Beide gewähren sofortigen Zugang |
| User-Description ist `"default user"` | Standard-User ohne individuelle Konfiguration |
| Kein Passwort-Hash oder -String im Binary | Keine Kandidaten bei Brute-Force-Suche gefunden |
| Shell ist Debug-/Entwickler-Tool | Typischerweise kein Passwort in Produktions-FW |

**Ergebnis: Das Passwort ist mit hoher Wahrscheinlichkeit leer (Empty String).**

#### Praktische Anleitung für UART-Zugang

```
1. UART-Pins am Board identifizieren (TX, RX, GND der Micro-MCU)
2. USB-UART-Adapter anschließen (3.3V Pegel!)
3. Terminal öffnen: 115200 Baud, 8N1 (Standard für STM32)
4. Enter drücken
5. Wenn "Please input password:" erscheint → Enter (leeres Passwort)
6. Shell-Prompt sollte erscheinen (vermutlich "User>")
7. "help" eingeben für Befehlsliste
8. "version" für SOFT_VERSION und BOOT_VERSION
```

> **Fallback:** Falls leeres Passwort nicht funktioniert, könnte das Passwort zur Laufzeit
> über CAN vom EMS-Controller gesetzt werden. In dem Fall wäre CAN-Sniffing des
> Config-Blocks (CMD `0x16`, 8 Bytes → SRAM `0x20003EA7`) der nächste Ansatzpunkt.

### 7.2 Shell-Befehle (vollständig, 33 Kommandos)

Aus String-Analyse und chinesischen Beschreibungen extrahiert:

| Befehl | Chinesische Beschreibung | Funktion |
|---|---|---|
| `version` | 版本信息 | SOFT_VERSION, BOOT_VERSION, Hardware-Rev |
| `log_data` | 打印数据 | Sensor-Daten loggen |
| `log_list` | 打印日志 | Log-Einträge auflisten |
| `log_err` | 打印错误日志 | Fehlerlog anzeigen |
| `log_clear` | 打印错误日志 | Log löschen |
| `log_open` | 开启日志自动打印 | Automatisches Log-Drucken aktivieren |
| `prt` | 持续打印 功能码[重复次数][打印间隔] | Dauer-Druck: Funktionscode, Wiederholungen, Intervall |
| `help_prt` | 持续打印项信息 | Print-Optionen anzeigen |
| `rtos_status` | RTOS状态 | FreeRTOS Task-Statistiken |
| `io_show` | IO状态 | GPIO-Pin-Status anzeigen |
| `io_set` | IO状态设置 | GPIO-Pin manuell setzen |
| `fan_set` | 设置风扇占空比 0 - 400 | Lüfter-PWM Duty 0–400 |
| `set_power` | 进入标准模式后输入功率 | Leistung setzen (nach Moduswechsel) |
| `show_power` | 展示powercfg功能 | set_power/max_power/low_power anzeigen |
| `power_cfg` | 设定模式 设定值(…浮点数) 设定值2 | Leistungskonfiguration (Float-Werte) |
| `pf_power` | 设定无功功率(…小于总功率) | Blindleistung setzen (< Gesamtleistung) |
| `pf_set` | 设定pf值(范围 -1, 1) | Power Factor setzen (-1 bis 1) |
| `pf` | 设定pf值(范围 -1, 1) | Power Factor (Alias) |
| `bat_mode` | 设置为电池模式 | Batteriemodus aktivieren |
| `backup_mode` | 设置为备份模式 | Notstrom/Backup-Modus |
| `par_mode` | 设置为备份模式 | Parallelmodus |
| `set_mode` | 0零馈电 1手动 2交易 3调试 15双向电压源 | Betriebsmodus wählen (siehe unten) |
| `sr_set` / `set_sr` | 设定同步整流(1开启 0关闭) | Synchron-Gleichrichtung ein/aus |
| `dac_high` | 设置PFC上限电流 | PFC Oberstrom-Limit via DAC |
| `dac_low` | 设置PFC下限电流 | PFC Unterstrom-Limit via DAC |
| `alarm` | 蜂鸣器噪声 | Buzzer-Steuerung |
| `qpr` | 修改电流环qpr参数 kp kr | PR-Regler Parameter ändern |
| `pi` | 修改电流环pi参数 | PI-Strom-Regler Parameter |
| `vol_pi` | 修改电压环pi参数 | PI-Spannungs-Regler Parameter |
| `show_pi` | 查看pi参数 | PI-Reglerparameter anzeigen |
| `update` | — | Selbst-Update via UART (Ymodem) |
| `update_bms` / `update_bms2` | — | BMS-Update via CAN / RS485 |
| `reset` | — | System-Reset |
| `reset_memory` | 1:清空所有数据 其他:清空累计以外 | 1=Alles löschen, sonst=ohne Zähler |
| `old_ate` | 设定老化模式 | ATE Factory-Burn-in-Modus |
| `clear` | clear console | Terminal löschen |
| `help` | show command info | Hilfe anzeigen |

### 7.3 set_mode Betriebsmodi

Aus chinesischer Beschreibung im Shell-Datenbereich:

| Wert | Chinesisch | Beschreibung |
|---|---|---|
| 0 | 零馈电 | Zero Feed-in (keine Netzeinspeisung) |
| 1 | 手动模式 | Manueller Modus |
| 2 | 交易模式 | Trading-Modus (zeitgesteuert) |
| 3 | 调试模式 | Debug-/Testmodus |
| 15 | 双向电压源模式 | Bidirektionaler Spannungsquellen-Modus |

### 7.4 Version-Strings

```
SOFT_VERSION:%d    — Firmware-Version (Wert: 116)
BOOT_VERSION:%d    — Bootloader-Version
hardware %d ,set_ver: %d — Hardware-Revision + Set-Version
```

### 7.5 Shell-Architektur (Internes)

| Komponente | Adresse/Wert | Beschreibung |
|---|---|---|
| Shell-Kontext | SRAM `0x20001410` | Haupt-Struct der Shell-Instanz |
| Eingabepuffer | SRAM `0x2000147C` | 512 Bytes Kommandozeilen-Buffer |
| Kommandotabelle | Flash `0x0801892C` | 53 Einträge × 16 Bytes |
| Tabellen-Ende | Flash `0x08018C7C` | Literal-Pool bei `0x0800FE38/FE3C` |
| Init-Funktion | `FUN_0800fdc0` | Shell-Kontext initialisieren |
| User-Suche | `FUN_08010194` | 16-Byte-Entry-Iterator mit strcmp |
| Name-Extraktor | `FUN_0800fb10` | Entry-Name aus Offset+4 lesen |
| Login-Handler | `FUN_08010208` | Passwort-Prüfung (3 Pfade) |
| Passwort-Check (2) | `FUN_0800f7a0` | Nachträgliche Auth bei laufender Shell |
| Kommando-Dispatcher | `FUN_08010102` | Type-basierter Dispatch (0=Func, 8=User) |
| Print-Funktion | `FUN_080106d0` | UART-String-Ausgabe |

---

## 8. Wechselrichter-Regelung

### Zustandsmaschine:

```
ctl_state (0x200002A8) — Hauptsteuerung
    ↳ llc_run_state (0x200002A5) — LLC-Wandler (DC-DC)
    ↳ inverter_run_state (0x200002A4) — H-Brücke (DC-AC)
```

### Regelungsbausteine:
- **PID-Regler** mit `kp`, `ki` (Leistungs- und Stromregelung)
- **PR-Regler** (Proportional-Resonant) mit `kp`, `kr` (Netzstrom-Regelung)
- **RMS-Berechnung** via FP-Summierung (`g_irms_struct`)
- **Nulldurchgangserkennung** (`zcd` = Zero Crossing Detector)
- **Notch-Filter** für DC-Bus (`highv_notch_vol`)
- **Synchron-Gleichrichtung** (`sr_duty`)

### Betriebsmodi (`work_mode` @ `DAT_20003E04`):

| Wert | Modus | Beschreibung |
|---|---|---|
| 0x00 | Normal | Normalbetrieb |
| 0x01 | Test | Werkstestmodus |
| 0x04 | Update | Firmware-Update aktiv |
| 0x0C | Factory | Fabrikmodus (12) |

---

## 9. Firmware-Update-Mechanismus

Die Micro-MCU unterstützt drei Update-Pfade:

| Pfad | Interface | Beschreibung |
|---|---|---|
| Selbst-Update | UART (Ymodem) | Eigene FW über serielle Konsole |
| BMS über CAN | CAN-Bus | BMS-FW an BMS-MCU weiterleiten |
| BMS über RS485 | RS485/UART | BMS-FW über RS485 flashen |

**Update-Sequenz über CAN (vom EMS-Controller gesteuert):**
1. `0xC1` → Step 1 (Initialisierung)
2. `0x60` → Update-Typ setzen, work_mode=0x04
3. `0x51` → Update triggern
4. `0x52(1)` → Step 2, `0x52(2)` → Step 3, `0x52(3)` → Step 4
5. `0x53` → Step 5 (Verifikation)
6. `0x55` → Step 6 (Finalisierung)
7. `0xCE` → Flash-Daten schreiben (Typ 0=Init, 1=Data, 2=Verify)

---

## 10. Bootloader-Thunks

Die Firmware enthält Thunks zu externen Funktionen im Bereich `0x10000xxx`:

| Thunk-Adresse | Ziel | Vermutete Funktion |
|---|---|---|
| `0x08000960` | `0x10000B58` | Power-Regler-Funktion (3 Aufrufe) |
| `0x08000974` | `0x100009E8` | Inverter Stop/Start (2 Aufrufe) |
| `0x0800097E` | `0x10000160` | Float-Verarbeitung (3 Aufrufe) |
| `0x08000988` | `0x100069E4` | Enable/Disable-Funktion (2 Aufrufe) |
| `0x080009BA` | `0x10006874` | Einmalige Init-Funktion |
| `0x08000A1E` | `0x10000124` | Einmalige Init-Funktion |

Diese Funktionen liegen im System-Memory oder Bootloader-Bereich und werden beim Start in den SRAM gemapped.

**Ergänzung Tranche 4a (10.07.2026):** Zusätzlich zu den obigen von Ghidra als `thunk_EXT_FUN_*`
erkannten echten Thunk-Funktionen gibt es mindestens einen **inline computed jump** in den
Bootloader-Bereich: `UART_TxEvent_ADC1_BootloaderThunk` (`0x08003af0`, Aufrufer `UART_IRQHandler`)
springt bedingt (nur wenn die geprüfte Handle-Instance `0x50000000`/ADC1 entspricht) direkt zu
`0x10001428` (`LAB_10001428`) — kein eigenständiger Thunk-Funktionskörper, sondern ein
Computed-Jump innerhalb einer größeren Funktion. Ziel-Adresse `0x10001428` liegt im selben
Bootloader-/System-Memory-Bereich wie die Tabelle oben, wurde aber bisher nicht separat gelistet.

---

## 11. Telemetrie-Block & Status-Block (CAN → Modbus-Brücke)

> Die EMS-Control-MCU liest periodisch zwei Datenblöcke via CAN vom Inverter ab
> und exponiert die Werte als Modbus-Register. Diese Analyse dekodiert beide Blöcke
> vollständig aus der Builder-Funktion `build_telemetry_block` (`FUN_08001560`, 688 Bytes).

### 11.1 Telemetrie-Block (CAN CMD `0x10` — 48 Bytes)

SRAM-Ziel: `0x200038E8`–`0x20003917`. Gesendet via `FUN_08001f34(addr, 0x10, 0x200038E8, 0x30)`.

| Offset | Bytes | Source SRAM | Variable | Scale | Typ | Beschreibung |
|--------|-------|-------------|----------|-------|------|-------------|
| 0x00 | 1 | `0x2000046D` | ctl_status | 1 | byte | Inverter-Betriebsstatus (0–6) |
| 0x01 | 1 | — | (reserved) | — | byte | Immer 0 |
| 0x02 | 1 | `0x200002B3` | grid_connected | 1 | byte | Netzverbindungs-Flag |
| 0x03 | 1 | `0x20003E03` | backup_mode | 1 | byte | Notstrom-Modus-Flag |
| 0x04 | 4 | `0x200019FC` | war1 | 1 | u32 | Warnbitmask |
| 0x08 | 4 | `0x200019F4` | err1 | 1 | u32 | Fehlerregister 1 |
| 0x0C | 4 | `0x200019F8` | err2 | 1 | u32 | Fehlerregister 2 |
| 0x10 | 2 | `0x200018E4` | grid_voltage_rms | ×10 | u16 | 电网电压有效值 — Netz-Spannung RMS (V×10) |
| 0x12 | 2 | `0x200002F0` | (unbekannt) | ×10 | u16 | Float×10 — vermutl. Netzfrequenz oder Strom |
| 0x14 | 2 | `0x200018BC` | offgrid_voltage_rms | ×10 | u16 | 离网电压有效值 — Offgrid-Spannung RMS (V×10) |
| 0x16 | 2 | `0x200002AB` | (unbekannt) | 1 | u16 | Byte→u16, vermutl. Regelparameter |
| 0x18 | 2 | `0x200018F0` | actual_power | 1 | i16 | 实际功率 — Ist-Leistung (W) |
| 0x1A | 2 | `0x200018C8` | output_power | 1 | i16 | 发出功率 — Abgegebene Leistung (W) |
| 0x1C | 2 | `0x20000E00` | power_3 | 1 | i16 | Leistungsmessung 3 (W) |
| 0x1E | 2 | `0x20000E10` | bat_vol_avg | ×10 | u16 | Batteriespannung Mittelwert (V×10) |
| 0x20 | 2 | `0x20000E30` | ntc_inv | ×10 | i16 | Inverter-Temperatur (°C×10) |
| 0x22 | 2 | `0x20000E34` | ntc_mppt | ×10 | i16 | MPPT-Temperatur (°C×10) |
| 0x24 | 2 | `0x2000030C` | max_power | 1 | u16 | Max. Leistung (W, float→int) |
| 0x26 | 2 | `0x20000310` | min_power | 1 | u16 | Min. Leistung (W, float→int) |
| 0x28 | 4 | `0x20003E83` | daily_charge_energy | 1 | u32 | 日充电 — Tägliche Ladeenergie (Wh) |
| 0x2C | 4 | `0x20003E87` | daily_discharge_energy | 1 | u32 | 日放电 — Tägliche Entladeenergie (Wh) |

**Hinweise:**
- `ctl_status` Werte (aus `FUN_0800d834`): 0=Idle, 1=Starting?, 2=Running?, 3=Fault?, 4=Stopping?, 6=Standby?
- Float→u16 Konvertierung mit ×10 via `VectorFloatToUnsigned(value * 10.0, 3)` — Clamp auf 3 Dezimalstellen
- Energiezähler-Limits konfiguriert via CAN CMD `0x16` Config-Block (SRAM `0x20003EA7`/`0x20003EAB`)
- Offsets 0x12 und 0x16 sind noch nicht eindeutig identifiziert — Kandidaten: Netzfrequenz, Grid-Strom-RMS

### 11.2 Status-Block (CAN CMD `0x11` — 8 Bytes)

SRAM-Ziel: `0x20000440`–`0x20000447`. Ebenfalls in `build_telemetry_block` befüllt (Zeile 41–45).

| Offset | Bytes | Source SRAM | Variable | Typ | Beschreibung |
|--------|-------|-------------|----------|------|-------------|
| 0x00 | 1 | `0x20003E04` | work_mode | byte | Arbeitsmodus (0=Normal, 1=Test, 4=Update, 0xC=Factory) |
| 0x01 | 1 | `0x200004A4` | sleep_mode | byte | Schlafmodus-Flag |
| 0x02 | 1 | `0x200004A6` | bat_mode | byte | Batteriemodus |
| 0x03 | 1 | — | (padding) | byte | — |
| 0x04 | 2 | `0x200004AB` | max_charge_power | u16 | Max. Ladeleistung (W, ≤2500) |
| 0x06 | 2 | `0x200004AD` | max_discharge_power | u16 | Max. Entladeleistung (W, ≤2500) |

### 11.3 Vollständige RMS-SRAM-Region (`0x200018B4`–`0x200018F0`)

Aus chinesischen Debug-Format-Strings extrahiert:

| SRAM | Variable | Chinesisch | Beschreibung |
|---|---|---|---|
| `0x200018B4` | grid_current_rms | 并网电流有效值 | Grid-Strom RMS (A) |
| `0x200018B8` | offgrid_current_rms | 离网电流有效值 | Offgrid-Strom RMS (A) |
| `0x200018BC` | offgrid_voltage_rms | 离网电压有效值 | Offgrid-Spannung RMS (V) |
| `0x200018C0` | output_voltage_rms | 输出电压有效值 | Ausgangsspannung RMS (V) |
| `0x200018C4` | (output_power?) | — | Leistungs-Variable (im 4er-Block) |
| `0x200018C8` | output_power | 发出功率 | Abgegebene Leistung (W) |
| `0x200018E4` | grid_voltage_rms | 电网电压有效值 | Netzspannung RMS (V) |
| `0x200018F0` | actual_power | 实际功率 | Aktuelle/Istleistung (W) |

### 11.4 Vermutete Zuordnung Telemetrie → Modbus-Register

| Telemetrie-Offset | Micro-Variable | Vermutetes Modbus-Register | Control-FW Beschreibung |
|---|---|---|---|
| 0x10 (grid_voltage_rms ×10) | `0x200018E4` | **32200** | ac_voltage |
| 0x14 (offgrid_voltage_rms ×10) | `0x200018BC` | **32300** | ac_offgrid_voltage |
| 0x18 (actual_power) | `0x200018F0` | 32100 oder 32102? | inverter_power |
| 0x1A (output_power) | `0x200018C8` | 32100? | ac_output_power |
| 0x1E (bat_vol_avg ×10) | `0x20000E10` | 34003? | battery_voltage |
| 0x20 (ntc_inv ×10) | `0x20000E30` | 35000–35002 | temperature |
| 0x22 (ntc_mppt ×10) | `0x20000E34` | 35003–35005 | temperature |
| 0x28 (daily_charge Wh) | `0x20003E83` | 33000? | daily_charge_energy |
| 0x2C (daily_discharge Wh) | `0x20003E87` | 33004? | daily_discharge_energy |

> **Nächster Schritt:** Die Control-FW v149.2 CAN-Empfangsfunktion analysieren, um die
> exakte Zuordnung Telemetrie-Offset → Modbus-Register-Nummer zu bestätigen.
> Alternativ: CAN-Bus-Sniffer während Modbus-Lesezugriff auf bekannte Register.

---

## 12. Lade-/Entlade-Steuerung & Pack-Rotation

> **Neu.** Analyse von `FUN_0800d834` (942 Bytes, 170 Zeilen) — die Hauptfunktion für
> Lade-/Entlade-Entscheidungen und die Rotations-Taktung.

### 12.1 Inverter-Status (`DAT_2000046D`)

Die Funktion setzt den Inverter-Status basierend auf Sensordaten:

| Wert | Bedingung | Bedeutung |
|------|-----------|-----------|
| 0 | `DAT_200004A4 == 1` (Sleep-Modus) | **Standby/Sleep** |
| 1 | Kein Backup, kein Parallel, ctl_state normal | **Normal-Betrieb** |
| 2 | Temperatur `_DAT_20000E1C < -10` | **Untertemperatur-Schutz** |
| 3 | Temperatur `_DAT_20000E1C >= 11` | **Übertemperatur-Schutz** |
| 4 | Backup/Parallel aktiv, ctl_state nahe 0xD4 | **Backup-Modus aktiv** |
| 6 | GPIO `0x48000C00` Bits 15+3 gesetzt | **Hardware-Fehler** |

### 12.2 Betriebsmodus-abhängige Steuerung

Die Logik hängt von `DAT_20003E04` (work_mode) ab:

| Mode | Wert | Lade-/Entlade-Logik |
|------|------|---------------------|
| 0 | Zero Feed-in | Nicht in dieser Funktion (vermutlich in Control-FW) |
| 1 | Manuell | Nicht in dieser Funktion |
| 2 | Trading | `return` — keine lokale Steuerung |
| **3** | **Debug/Auto** | **SOC-basierte Rotation mit 600s-Timer** (s. 12.3) |
| **4** | **Kalibrierung** | **Voll-Lade/Entlade-Zyklus** (s. 12.4) |

### 12.3 SOC-basierte Rotation (Mode 3 = Debug/Auto)

**Zustandsmaschine `DAT_2000046E`:**

| Wert | Richtung | Power-Wert (IEEE 754) | Beschreibung |
|------|----------|----------------------|-------------|
| 0 | Idle | `0x00000000` = 0W | Warten auf nächste Entscheidung |
| 1 | **Entladen** | `0x451C4000` = **+2500W** | Batterie entladen |
| 2 | **Laden** | `0xC51C4000` = **-2500W** | Batterie laden |

**Timer-Konfiguration:**

| Timer-SRAM | Timeout | Sekunden | Funktion |
|---|---|---|---|
| `0x20000470` | `0xE10` = 3600 | **60 Minuten** | Haupt-Zyklus-Timer (Neuentscheidung) |
| `0x20000472` | 600 | **10 Minuten** | Entlade-Sub-Timer |
| `0x20000474` | 600 | **10 Minuten** | Lade-Sub-Timer |

**Entscheidungslogik:**

```
Alle 3600s (1 Stunde):
  ├── SOC < 50.1% (501) → State = 2 (Laden bei -2500W)
  └── SOC ≥ 50.1%       → State = 1 (Entladen bei +2500W)

Während Laden (State 2):
  ├── Alle 600s (10 Min): CAN-Update an BMS senden
  └── SOC ≥ 99.9% (999): → State = 0 (Stop, Voll)

Während Entladen (State 1):
  ├── Alle 600s (10 Min): CAN-Update an BMS senden
  └── SOC < 15.0% (150): → State = 0 (Stop, Leer)
```

**CAN-Update-Nachricht** (via `FUN_0800ab88`):
```c
FUN_0800ab88(2, inverter_temp, soc, max_bms_temp);
```
Sendet: CMD=2, Inverter-Temperatur, aktueller SOC, max BMS-Temperatur.

> **Die Nutzerbeobachtung bestätigt:** Der **600-Sekunden-Timer (10 Minuten)** entspricht
> genau dem "gefühlten" Rotationsintervall aus der App-Beobachtung!

### 12.4 Kalibrierungs-Zyklus (Mode 4 = Self-Test)

7-Stufen Charge/Discharge-Zyklus für Werks-/Kapazitätstests:

```
State 0: Init
  → max_discharge = 2500W (0x9C4)
  → Testzeit: 9000s (2.5h), oder 14400s (4h) wenn cap > 3000

State 1: Vollladen → −2500W
  → Bis SOC = 100% ODER Timeout

State 2: Pause → 0W
  → 59s Mindestpause, bis Temp < 45°C oder max 1800s

State 3: Vollentladen → +2500W
  → Bis SOC < 30% ODER Timeout
  → Entlade-Energie messen (daily_discharge)

State 4: Pause → 0W
  → 59s Mindestpause, bis Temp < 50°C oder max 1800s

State 5: Teilladen → −2500W
  → Bis SOC > 47.9% (0x1DF)
  → Lade-Energie messen
  → Ergebnisse in Flash schreiben (Addr 0x950, 0x952)
  → Kalibrierungsdaten: DAT_20000497 = 1
  → max_discharge auf 800W reduzieren

State 6: Stop → 0W
```

**Flash-Kalibrierungsadressen:**

| Flash-Addr | Inhalt | Beschreibung |
|---|---|---|
| `0x0950` | discharge_energy_cal | Gemessene Entlade-Energie (Wh) |
| `0x0952` | charge_energy_cal | Gemessene Lade-Energie (Wh) |
| `0x0090` | cal_flag | Kalibrierung abgeschlossen (1) |

### 12.5 Bootloader-Funktionen (Thunks identifiziert)

| Thunk | Ziel | Funktion | Parameter |
|---|---|---|---|
| `thunk_EXT_FUN_10000160` | `0x10000160` | **set_inverter_power(float)** | Leistung in Watt (±2500W) |
| `thunk_EXT_FUN_10000B58` | `0x10000B58` | **disable_inverter(0,0)** | Inverter abschalten |

> `0x10000160` ist die wichtigste Bootloader-Funktion: sie setzt die Inverter-Leistung.
> Positive Werte = Entladen, negative = Laden. Maximal ±2500W (Venus D Hardware-Limit).

### 12.6 Architektur-Erkenntnis: Pack-Rotation

Die Analyse zeigt, dass die **Micro-MCU die Lade-/Entladerichtung steuert**, aber die
**Pack-Selektion anders funktioniert als ursprünglich angenommen:**

```
Mode 0/1/2 (Normal/Manuell/Trading):
  → Control-MCU gibt Leistungs-Sollwert vor (via CAN CMD 0x01)
  → Micro-MCU steuert Inverter
  → ALLE Packs hängen parallel am DC-Bus
  → BMS-Master verteilt über MOSFET-Steuerung (CAN CMD 6/3)
  → Rotation wird durch BMS-Master oder Control-MCU getriggert

Mode 3 (Debug/Auto):
  → Micro-MCU steuert autonom: ±2500W, 10-Min-Intervalle
  → SOC-basierte Richtungsentscheidung alle 60 Min
  → Pack-Rotation via BMS CAN CMD 6/3 (Adress-basiert)

Mode 4 (Kalibrierung):
  → Autonomer 7-Stufen-Zyklus, keine Pack-Rotation
```

> **Offene Frage:** Die Pack-Rotation im Normalmodus (0/1/2) ist vermutlich in der
> **Control-FW** implementiert, die Pack-spezifische Befehle über RS485 an die Micro-MCU
> sendet, welche sie als CAN CMD 6/3 an die BMS-Packs weiterleitet.

### 12.7 DC-Bus-Architektur & PV-Verhalten

> **Aus der FW-Architektur abgeleitete Erklärung** für beobachtetes PV-Drosselungsverhalten
> und den regelmäßigen Lade-/Entlade-Zyklus.

#### Physischer Signalpfad (ein Inverter, ein DC-Bus)

```
PV-Panels (Dach)
   ↓ DC
MPPT-Regler (ntc_mppt, DAT_20000E34)
   ↓ DC
┌──────────────────────────────────────────────────┐
│             DC-Bus (~400V)                       │
│          highv_vol (DAT_20000DEC)                │
│          highv_notch_vol (DAT_20000E0C)          │
│                                                  │
│   ← LLC-Wandler (DC-DC) →        H-Brücke (DC-AC) →
│   llc_run_state                   inverter_run_state
│   bat_vol, bat_cur                grid_vol, grid_cur
└──────────┬───────────────────────────┬───────────┘
           ↓                           ↓
     Batterie-Packs              AC-Grid (Hausnetz)
     (parallel am Bus)           grid_volt, offgrid_volt
```

**Kritische Einschränkung:** Es gibt nur EINEN `set_inverter_power(float)` Aufruf
(`thunk_EXT_FUN_10000160`). Der Inverter kann nicht gleichzeitig laden UND ins Grid
einspeisen. Der Leistungswert steuert die NETTO-Richtung:

| Power-Wert | Energiefluss | PV-Verhalten |
|---|---|---|
| **< 0** (negativ) | PV/Grid → Batterie (Laden) | MPPT liefert max. den Ladebedarf, Rest wird gedrosselt |
| **= 0** | Inverter aus | MPPT läuft auf Leerlaufspannung, kein Grid-Export |
| **> 0** (positiv) | Batterie → Grid (Entladen) | PV + Batterie → Grid (BEIDES gleichzeitig!) |

#### Beobachtetes Verhalten: PV-Drosselung bei fast vollem Akku

**Phase 1 — Akku lädt, PV wird progressiv gedrosselt:**
```
BMS: SOC steigt → Strom-Limit-Matrix (Flash 0x0801B884) reduziert max_charge_current
     Temperatur × SOC → erlaubter Ladestrom fällt von z.B. 50A auf 5A
     charge_current_limit über CAN PF=3 → Micro-MCU
     
Micro: set_inverter_power = -(BMS charge_limit × bat_voltage)
       Inverter nimmt nur noch wenig Leistung vom DC-Bus
       
MPPT: DC-Bus-Spannung steigt → MPPT regelt Arbeitspunkt herunter
      → PV-Panels liefern weniger als möglich
      → Überschuss geht NICHT ins Grid (kein separater Pfad)
```

**Phase 2 — Akku bei 100%, kurze Idle-Phase:**
```
BMS: show_soc ≥ 999 (99.9%) + full_flag → SOC gecapped auf 1000
Micro: Lade-Richtung stoppt → set_inverter_power(0)
       Inverter komplett aus, PV wird voll gedrosselt
```

**Phase 3 — Entladen beginnt, PV fließt wieder:**
```
Timer 0x20000470 abgelaufen (3600s/60min) ODER Control-MCU CMD
SOC ≥ 50.1% → state = 1 (Entladen)
set_inverter_power(+2500W)

LLC-Wandler zieht Energie AUS Batterie → DC-Bus
MPPT schiebt PV-Energie auf gleichen DC-Bus
H-Brücke exportiert SUMME (PV + Batterie) ins Grid
→ PV-Leistung fließt wieder komplett ins Hausnetz!
```

**Phase 4 — SOC fällt, Zyklus wiederholt sich:**
```
SOC fällt durch Entladen
Wenn SOC < Schwelle → zurück zu Phase 1 (Laden)
→ Regelmäßiger Lade-/Entlade-Zyklus beobachtbar
```

#### Warum Marstek das nicht anders löst

Der Venus D ist ein **Batterie-Inverter mit integriertem MPPT**, kein echter Hybrid-Wechselrichter.
Echte Hybrid-WR (Fronius, SMA) haben **separate Leistungspfade** mit unabhängigen Reglern:
- Pfad 1: PV → Grid (immer aktiv, unabhängig vom Akku)
- Pfad 2: PV → Batterie (zusätzlich, wenn Überschuss)
- Pfad 3: Batterie → Grid (bei Bedarf)

Der Venus D hat nur **einen bidirektionalen Pfad** (LLC ↔ DC-Bus ↔ H-Brücke).
Die Zustandsmaschine (`ctl_state` → `llc_run_state` + `inverter_run_state`) erlaubt
zwar zwei separate Zustandsmaschinen, aber der Leistungs-Sollwert (`set_inverter_power`)
ist ein einziger Float — die FW kann nicht "lade mit 500W UND speise 1000W PV ein".

---

## 13. Vollständige Funktionsliste (363 benannt / 445 total, Stand 10.07.2026 nach Tranche 3c — s. 13.13/13.15 für die aktuellsten Zahlen, Tabellen 13.1–13.4 unten sind älterer Stand)

> **Historie:** Die Notiz "07.07.2026 — Massenanalyse via 5 parallele Ghidra-Agenten, 398/445 benannt"
> aus einer früheren Version dieser Doku war **irreführend** — diese Umbenennungen wurden nie in Ghidra
> gespeichert (Ghidra-Ist-Zustand beim Session-Start am 10.07.2026: nur 21 Funktionen benannt). Die
> Tabellen unten (13.1–13.4) enthalten daher überwiegend **Namensvorschläge aus jener nicht persistierten
> Analyse**, nicht den tatsächlichen Ghidra-Zustand.
>
> **Session 10.07.2026:** 106 dieser vorgeschlagenen Namen wurden per Dekompilierung einzeln verifiziert
> (nicht blind übernommen) und in Ghidra umbenannt — siehe **Abschnitt 13.9** für die vollständige Liste,
> Konfidenz-Einschätzung und die dabei gefundenen Korrekturen/Ablehnungen. Zusätzlich wurde die Dublette
> `CAN_Filter_Setup` behoben: Der 10-Byte-Thunk auf `0x080150f2` (fälschlich ebenfalls `CAN_Filter_Setup`
> genannt) wurde zu `thunk_CAN_Filter_Setup` umbenannt; die echte 260-Byte-Funktion bleibt auf `0x0800eb88`.
>
> Die Tabellen 13.1–13.4 sind **nicht mehr tagesaktuell verifiziert für alle Zeilen** — nur die in 13.9
> gelisteten Adressen sind für den Ghidra-Ist-Zustand am 10.07.2026 bestätigt. Für alle anderen Zeilen gilt:
> Name ist ein **unverifizierter Vorschlag**, in Ghidra weiterhin `FUN_<adresse>`, bis in einer Folge-Session
> verifiziert.

### 13.1 C-Runtime & Startup (0x08000200–0x080009FF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800020c` | ~~`NVIC_SystemReset`~~ ❌ | 40B | **Widerlegt 10.07.2026** — Dekompilat zeigt Privileg-Eskalation+SVC(0), kein AIRCR-Write. Bleibt `FUN_0800020c`, s. 13.9 |
| `0x08000234` | `FPU_Enable` | 14B | FPU aktivieren via CPACR |
| `0x080002a4` | `get_current_irq_number` | 6B | Aktuelle ISR-Nummer aus IPSR |
| `0x080002d0` | `__aeabi_uldivmod` | 98B | 64-bit unsigned Division |
| `0x08000332` | `memcpy` | 36B | Speicherkopie (word-aligned) |
| `0x08000356` | `__aeabi_memset` | 14B | ARM EABI memset (dst, n, val) |
| `0x08000364` | `memclr` | 4B | Speicher nullen (22 Aufrufe) |
| `0x08000368` | `memset` | 18B | Standard memset |
| `0x0800037a` | `strlen` | 14B | Stringlänge |
| `0x08000388` | `strcmp` | 28B | Stringvergleich |
| `0x080003a4` | `strcpy` | 18B | Stringkopie |
| `0x080003b6` | `strncmp` | 30B | Stringvergleich mit Limit |
| `0x080003d4` | `__aeabi_ui2d` | 38B | uint → double Konvertierung |
| `0x0800042c` | `__aeabi_uidiv` | 44B | 32-bit unsigned Division |
| `0x08000458` | `__aeabi_llsl` | 30B | 64-bit Links-Shift |
| `0x08000476` | `__aeabi_llsr` | 32B | 64-bit Rechts-Shift |
| `0x08000496` | `__aeabi_dadd` | 322B | Double Addition |
| `0x080005e4` | `__aeabi_dmul` | 228B | Double Multiplikation |
| `0x080006c8` | `__aeabi_ddiv` | 252B | Double Division |
| `0x080007a6` | `__aeabi_d2lz` | 48B | Double → int64 |
| `0x080007d8` | `__aeabi_d2iz` | 48B | Double → int32 |
| `0x0800082c` | `__aeabi_lasr` | 36B | 64-bit arithm. Rechts-Shift |
| `0x0800086e` | `__aeabi_dnorm` | 156B | Double Normalisierung/Rundung |

### 13.2 Peripherie-Treiber — GPIO, UART, CAN, DMA (0x08000A00–0x080042FF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08000a28` | `UART_IRQHandler` | 126B | UART Interrupt-Handler |
| `0x08000aa6` | `UART_ErrorHandler` | 14B | UART Fehler-Handler |
| `0x08000ac0` | `UART_DMA_Handler` | 10B | UART DMA-Transfer-Complete |
| `0x08000acc` | `UART_WaitReady` | 128B | UART Ready warten mit Timeout |
| `0x08000b50` | ~~`CAN_WaitReady`~~ ❌ | 134B | **Widerlegt 10.07.2026** — Aufrufer-Kontext ist UART/DMA, kein CAN. Bleibt `FUN_08000b50`, s. 13.9 |
| `0x08000bdc` | `GPIO_ConfigPin` | 32B | GPIO-Pin konfigurieren (Normal Speed) |
| `0x08000bfc` | `GPIO_ConfigPin_HighSpeed` | 32B | GPIO-Pin konfigurieren (High Speed) |
| `0x08000c20` | `Peripheral_GPIO_Init` | 658B | Alle GPIO-Ports initialisieren (A-E) |
| `0x08000ef0` | `ADC_ConvertRawValues` | 172B | ADC-Rohwerte → kalibrierte Floats |
| `0x08000fb4` | `CAN_Peripheral_Init` | 394B | CAN1/2/3 Peripherie initialisieren |
| `0x08001158` | `ADC_ProcessSamples` | 360B | ADC DMA-Puffer verarbeiten |
| `0x080012e0` | `Grid_Protection_SetLimits` | 406B | Netz-Schutzgrenzen pro Land setzen |
| `0x0800150a` | ~~`NVIC_SetPriority`~~ ❌ | 40B | **Widerlegt 10.07.2026** — passt nicht zu NVIC_IPR-Zugriff. Bleibt `FUN_0800150a`, s. 13.9 |
| `0x08001532` | ~~`NVIC_EnableIRQ`~~ ❌ | 40B | **Widerlegt 10.07.2026** — echtes NVIC_EnableIRQ liegt auf `0x0800675c` (s. 13.3/13.9). Bleibt `FUN_08001532` |
| `0x08001868` | `CAN_RX_ParseBMSCommand` | 60B | BMS CAN-Befehle parsen |
| `0x08001e3c` | `CAN_TX_ReadQueue` | 90B | CAN TX-Queue lesen und senden |
| `0x08001ea0` | `UART_Init` | 92B | UART2 initialisieren |
| `0x08001f04` | `CAN_RX_DispatchTask` | 36B | CAN RX FreeRTOS-Task |
| `0x08001f34` | `CAN_TX_SendMessage` | 232B | Daten in 8-Byte CAN-Frames segmentieren |
| `0x08002024` | `CAN_TX_SendCommand` | 14B | CAN-Kommando ohne Daten senden |
| `0x08002034` | `CAN_TX_SendFrame` | 54B | Einzelnen CAN-Frame senden |
| `0x08002070` | `CAN_TX_ProcessQueue` | 54B | CAN TX-Ringpuffer verarbeiten |
| `0x080020b0` | `CAN_BuildArbID` | 30B | CAN Arbitration-ID bauen |
| `0x080020d0` | `CAN_SetFilter_ExtID` | 50B | CAN Extended-ID Filter |
| `0x08002108` | `CAN_SetFilter_StdID` | 48B | CAN Standard-ID Filter |
| `0x0800213c` | `OTA_FW_Update_StateMachine` | 386B | OTA Update-Zustandsmaschine |
| `0x08002614` | `Serial_ValidatePacket` | 92B | Serielles Paket validieren (XOR-CRC) |
| `0x0800273e` | `memcpy_reverse` | 36B | Big→Little-Endian Kopie |
| `0x0800277c` | `DMA_CalcBaseAndOffset` | 54B | DMA Stream-Basisregister berechnen |
| `0x080027e0` | `DMA_SetConfig` | 66B | DMA Stream konfigurieren |
| `0x08002824` | `TIM6_PWM_Init` | 96B | TIM6 PWM initialisieren |
| `0x0800288c` | `TIM7_PWM_Init` | 74B | TIM7 PWM initialisieren |
| `0x080028e0` | `TIM8_PWM_Init` | 92B | TIM8 PWM initialisieren |
| `0x0800299c` | `Inverter_SetMode` | 86B | Inverter-Betriebsmodus setzen |
| `0x080029fc` | `EEPROM_ClearStats` | 70B | EEPROM-Statistiken löschen |
| `0x08002a3c` | `delay_ms` | 40B | Millisekunden-Verzögerung (6 Aufrufe) |
| `0x08002a68` | `EEPROM_LoadConfig` | 614B | Konfiguration aus I2C-EEPROM laden |
| `0x08002ce8` | `EEPROM_WriteRegister` | 144B | EEPROM-Register schreiben (I2C Mutex) |
| `0x08002d84` | `EEPROM_ReadRegister` | 120B | EEPROM-Register lesen |
| `0x08002e14` | `EEPROM_SaveTimestamp` | 44B | Timestamp in EEPROM sichern |
| `0x08002e40` | `EEPROM_WriteVerify` | 300B | EEPROM schreiben+verifizieren (8 Aufrufe) |
| `0x08002f78` | `EEPROM_WriteVerify_NoMutex` | 216B | EEPROM schreiben (Boot-Zeit) |
| `0x08003078` | `Error_Handler` | 10B | Fataler Fehler → Endlosschleife (7 Aufrufe) |
| `0x08003090` | `CAN_InitMailboxes` | 100B | CAN Mailbox-Pointer initialisieren |
| `0x08003104` | `CAN_CopyTxFrame` | 112B | TX-Header+Daten in CAN-Mailbox |
| `0x08003178` | `FLASH_FlushCaches` | 84B | Flash I/D-Cache flushen |
| `0x080031d4` | `FLASH_MassErase` | 54B | Flash Mass-Erase |
| `0x08003210` | `FLASH_SectorErase` | 72B | Flash Sektor-Erase |
| `0x0800325c` | `FLASH_ProgramDoubleWord` | 22B | Flash 8-Byte schreiben |
| `0x08003278` | `FLASH_Program256Bit` | 38B | Flash 32-Byte Block schreiben |
| `0x080032a4` | `FLASH_WaitForOperation` | 98B | Flash BSY-Flag warten |
| `0x08003310` | `FLASH_EraseSectors` | 96B | Flash Sektoren-Range löschen |
| `0x08003378` | `FLASH_WriteData` | 108B | Datenpuffer nach Flash schreiben |
| `0x080033f0` | `Get_GridFrequency` | 62B | AC-Netzfrequenz berechnen |
| `0x0800343c` | `checksum_add` | 28B | Additive Prüfsumme |
| `0x08003458` | `checksum_xor` | 30B | XOR-Prüfsumme |
| `0x080035d4` | `UART_SetBaudRate` | 148B | UART Baudrate setzen |
| `0x08003670` | `HAL_GPIO_Init_Extended` | 1094B | Vollständige GPIO-Init (Mode/AF/Speed/Pull/EXTI) |
| `0x08003af0` | `UART_RX_Callback` | 24B | UART1 RX-Callback |
| `0x08003b04` | `HAL_UART_Init` | 546B | UART-Peripherie komplett initialisieren |
| `0x08003d54` | `UART_MspInit` | 634B | UART MSP Init (Clocks, GPIO, DMA) |
| `0x08003ff8` | `UART_StartReceive_DMA` | 264B | UART DMA-Empfang starten |
| `0x08004128` | `HAL_TIM_Base_Init_Full` | 604B | Timer-Basis komplett initialisieren |

### 13.3 Erweiterte Peripherie — TIM, SPI, HRTIM, I2C (0x08004300–0x080097FF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x080043a8` | `TIM_PWM_Channel_Config` | 148B | TIM PWM-Kanal konfigurieren |
| `0x08004528` | `TIM_PWM_Start` | 458B | TIM PWM-Ausgang starten (3 Aufrufe) |
| `0x080046fc` | `TIM_CC_Enable` | 42B | TIM Capture/Compare aktivieren |
| `0x08004728` | `TIM_IC_Start_DMA` | 130B | TIM Input-Capture via DMA |
| `0x080047bc` | `TIM_DMA_DelayPulse` | 50B | TIM DMA Delay-Pulse Callback |
| `0x080047ee` | `TIM_CCx_ChannelCmd` | 110B | TIM CC-Kanal ein/aus |
| `0x0800485c` | `TIM_OC_ConfigChannel` | 104B | TIM Output-Compare Kanal-Konfig |
| `0x080048c4` | `TIM_IC_ConfigChannel` | 118B | TIM Input-Capture Kanal-Konfig |
| `0x0800493a` | `TIM_SlaveMode_Config` | 204B | TIM Slave-Mode konfigurieren |
| `0x08004a08` | `TIM_MasterMode_Config` | 180B | TIM Master-Mode konfigurieren |
| `0x08004ac8` | `TIM_DMA_Config` | 144B | TIM DMA Burst-Transfer |
| `0x08004b58` | `TIM_Generate_Event` | 32B | TIM Software-Event generieren |
| `0x08004b7c` | `TIM_Base_Start_IT` | 224B | TIM mit Interrupt starten |
| `0x08004c5c` | `TIM_Encoder_Config` | 78B | TIM Encoder-Modus konfigurieren |
| `0x08004caa` | `TIM_ClockSource_Config` | 94B | TIM Taktquelle setzen |
| `0x08004d08` | `TIM_SetPrescaler_Event` | 54B | TIM Prescaler + Update-Event |
| `0x08004d70` | `SPI_Init` | 254B | SPI-Peripherie initialisieren |
| `0x08004e76` | `SPI_TransmitReceive_IT` | 360B | SPI Interrupt-basierter TX/RX |
| `0x08004fe0` | `SPI_IRQHandler` | 466B | SPI Interrupt-Handler (TX/RX/Error) |
| `0x080051c0` | `DMA_Init` | 124B | DMA Stream initialisieren |
| `0x08005248` | `DMA_Start_IT` | 112B | DMA mit Interrupt starten |
| `0x080052c6` | `DMA_DeInit` | 44B | DMA Stream deinitialisieren |
| `0x080052f2` | `DMA_IRQHandler` | 132B | DMA Interrupt-Handler (TC/HT/TE) |
| `0x08005384` | `ADC_Init` | 238B | ADC-Peripherie initialisieren |
| `0x0800547c` | `ADC_ConfigChannel` | 22B | ADC Kanal-Sequenz konfigurieren |
| `0x08005498` | `ADC_Start_DMA` | 120B | ADC DMA-Konvertierung starten |
| `0x08005518` | `ADC_Calibrate` | 28B | ADC Kalibrierung ausführen |
| `0x080055c4` | `HAL_RCC_ClockConfig` | 400B | RCC Takt-Konfiguration (9 Aufrufe!) |
| `0x08005774` | `HAL_RCC_GetPCLK1Freq` | 14B | PCLK1 Frequenz lesen |
| `0x08005782` | `HAL_RCC_GetPCLK2Freq` | 16B | PCLK2 Frequenz lesen |
| `0x08005792` | `HAL_RCC_GetHCLKFreq` | 12B | HCLK Frequenz lesen |
| `0x080057a0` | `HAL_RCC_GetSysClockFreq` | 8B | System-Takt lesen |
| `0x080057ac` | `HAL_GetTick` | 6B | Tick-Counter lesen (26 Aufrufe!) |
| `0x08005c10` | `I2C_Init` | 174B | I2C-Peripherie initialisieren |
| `0x08005cc8` | `I2C_DisableOwnAddress` | 30B | I2C Eigene Adresse deaktivieren |
| `0x08005cf0` | `I2C_Master_Transmit` | 176B | I2C Master-TX mit Timeout |
| `0x08005db0` | `I2C_Master_Receive` | 64B | I2C Master-RX |
| `0x08005df0` | `I2C_Mem_Read` | 56B | I2C Register lesen (Mem-Adresse) |
| `0x0800617c` | `I2C_RequestMemoryWrite` | 90B | I2C Memory-Write Request aufbauen |
| `0x080061d6` | `I2C_RequestMemoryRead` | 86B | I2C Memory-Read Request aufbauen |
| `0x0800622c` | `I2C_WaitOnMasterFlag` | 186B | I2C Master-Flag warten mit Fehlerbehandlung |
| `0x080062ec` | `I2C_MasterTransmit_ISR` | 324B | I2C Master-TX Interrupt-Schleife (4 Aufrufe) |
| `0x08006438` | `I2C_MasterReceive_ISR` | 324B | I2C Master-RX Interrupt-Schleife (4 Aufrufe) |
| `0x08006584` | `I2C_Slave_AddrCallback` | 164B | I2C Slave-Adress-Callback |
| `0x080066d8` | `IWDG_Init` | 68B | Watchdog initialisieren |
| `0x0800675c` | `NVIC_EnableIRQ` ✅ (**korrigiert** 10.07.2026, war `IWDG_SetPrescaler`) | 26B | NVIC->ISER-Bitband Interrupt aktivieren |
| `0x08006778` | `IWDG_WaitForReady` | 60B | Watchdog bereit warten |
| `0x08006800` | `DAC_Init` | 190B | DAC-Peripherie initialisieren |
| `0x080068dc` | `DAC_SetChannel` | 776B | DAC Kanal konfigurieren (4 Aufrufe) |
| `0x08006bec` | `DAC_DMA_Config` | 432B | DAC DMA-Transfer konfigurieren |
| `0x08006dc0` | `HAL_RCC_GetSysClockFreq` ✅ (**korrigiert** 10.07.2026, war `DAC_SetValue`) | 106B | Systemtakt aus RCC_CFGR-SWS-Bits ermitteln (16/8 MHz) |
| `0x08006e34` | `HRTIM_Init` | 1090B | High-Resolution Timer initialisieren |
| `0x080072d0` | `HRTIM_StartPWM` | 80B | HRTIM PWM starten |
| `0x08007324` | `HRTIM_CounterStart_IT` | 142B | HRTIM Counter mit Interrupt starten |
| `0x080073b8` | `HRTIM_OutputConfig` | 74B | HRTIM Ausgang konfigurieren |
| `0x0800740c` | `HRTIM_SetCompare` | 52B | HRTIM Compare-Wert setzen |
| `0x08007464` | `HRTIM_SetDeadTime` | 40B | HRTIM Totzeit konfigurieren |
| `0x08007498` | `HRTIM_TimerInit` | 188B | HRTIM Timer-Unit initialisieren |
| `0x08007574` | `HRTIM_WaveformInit` | 136B | HRTIM Wellenform-Init |
| `0x08007606` | `HRTIM_OutputStart` | 78B | HRTIM Ausgangs-Pins aktivieren |
| `0x08007654` | `HRTIM_OutputStop` | 50B | HRTIM Ausgangs-Pins deaktivieren |
| `0x08007724` | `HRTIM_SoftwareUpdate` | 68B | HRTIM Software-Trigger |
| `0x08007774` | `HRTIM_BurstModeConfig` | 192B | HRTIM Burst-Mode konfigurieren |
| `0x08007834` | `HRTIM_EventConfig` | 78B | HRTIM Event-Eingang konfigurieren |
| `0x08007884` | `HRTIM_FaultConfig` | 50B | HRTIM Fault-Eingang |
| `0x080078c0` | `HRTIM_ADCTriggerConfig` | 358B | HRTIM ADC-Trigger konfigurieren |
| `0x08007a48` | `HRTIM_MspInit` | 518B | HRTIM MSP Init (GPIO, DMA, NVIC) |
| `0x08007c4c` | `HRTIM_TimerBaseConfig` | 110B | HRTIM Timer-Basis konfigurieren |
| `0x08007cbc` | `HRTIM_CaptureConfig` | 50B | HRTIM Capture-Unit |
| `0x08007cfc` | `HRTIM_CompareConfig` | 78B | HRTIM Compare-Unit |
| `0x08007d4c` | `HRTIM_WaveformTimerConfig` | 324B | HRTIM Wellenform-Timer |
| `0x08007eb8` | `HRTIM_OutputSetConfig` | 310B | HRTIM Output Set/Reset Source |
| `0x08007fee` | `HRTIM_EventFilterConfig` | 78B | HRTIM Event-Filter |
| `0x0800803c` | `HRTIM_DeadTimeConfig` | 172B | HRTIM Totzeit komplett |
| `0x08008100` | `TIM_PWM_Start_NoIT` | 258B | TIM PWM ohne Interrupt |
| `0x080082e4` | `TIM_PeriodElapsedCallback` | 24B | TIM6 Update-Callback |
| `0x080082f8` | `TIM_ReadCapturedValue` | 44B | TIM CCR-Register lesen |
| `0x08008330` | `UART_AbortReceive` | 188B | UART Empfang abbrechen |
| `0x080083f8` | `UART_IRQHandler_Full` | 776B | UART IRQ-Handler (IDLE/RX/TX/Error) |
| `0x080086e4` | `HAL_UART_Receive_IT` | 366B | UART Interrupt-Empfang starten |
| `0x0800873c` | `SPI_DMA_TransferComplete` | 282B | SPI DMA-Completion Callback |
| `0x08008834` | `HAL_UART_Transmit_DMA` | 152B | UART DMA-Senden starten |
| `0x080088dc` | `HRTIM_UpdatePWMDuty` | 338B | HRTIM PWM-Duty aktualisieren |
| `0x08008d4c` | `HRTIM_TimerBaseConfig_Ext` | 38B | HRTIM Timer Prescaler/Periode |
| `0x08008d72` | `HRTIM_TimerConfig_Ext` | 148B | HRTIM Timer-Control |
| `0x08008e06` | `HRTIM_OutputConfig_Ext` | 222B | HRTIM Output Polarität/Quellen |
| `0x08008ee4` | `HRTIM_CaptureUnitConfig` | 56B | HRTIM Capture-Unit |
| `0x08008f1c` | `HRTIM_CompareUnitConfig` | 30B | HRTIM Compare-Unit Prescaler |
| `0x08008f3c` | `HRTIM_TimerWaveformConfig` | 432B | HRTIM Wellenform (Deadtime/Burst/DLL) |
| `0x080090f8` | `HRTIM_EventConfig_Full` | 80B | HRTIM Event-Filter/Blanking |
| `0x08009694` | `UART_EndTransfer` | 34B | UART nach Fehler zurücksetzen |
| `0x080096b8` | `UART_WaitOnFlagUntilTimeout` | 268B | UART Flag warten + Fehlerprüfung |
| `0x080097c8` | `I2C_TransferConfig` | 44B | I2C CR2 konfigurieren |
| `0x080097f8` | `I2C_WaitOnFlagUntilTimeout` | 86B | I2C Flag warten |

### 13.4 Applikationslogik — Modbus, Ymodem, Debug-Log (0x08009800–0x0800CFFF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x08009850` | `UART_Transmit_Wait` | 162B | UART TX warten mit Timeout |
| `0x080098f8` | `UART_Receive_Wait` | 76B | UART RX warten mit Timeout |
| `0x08009944` | `UART_Transmit_Wait_Alt` | 80B | UART TX Alternative (∞ Timeout) |
| `0x08009994` | `I2C1_Init` ✅ (**korrigiert** 10.07.2026, war `USART2_Init`) | 76B | I2C1-Handle initialisieren (Base 0x40005400), von EEPROM-Funktionen genutzt |
| `0x080099ec` | `uint_to_decimal_string` | 66B | uint32 → ASCII Dezimalstring |
| `0x08009a34` | `IWDG_Reload` | 18B | Watchdog füttern (0xAAAA) |
| `0x08009a4c` | ~~`DMA_Get_TCIF`~~ ❌ | 8B | **Widerlegt** — nie in Ghidra angewendet. Bleibt `FUN_08009a4c`, s. 13.21: `(*(uint*)(p1+8)&0xf)>>3`, Aufrufer `HAL_GPIO_Init_Extended` UND `HAL_ADC_Init` — domänenübergreifend, keine DMA-Register |
| `0x08009a54` | ~~`DMA_Get_Error_Flag`~~ ❌ | 8B | **Widerlegt** — dito. Bleibt `FUN_08009a54`, s. 13.21: `*(uint*)(p1+8)&1`, Aufrufer `UART_WaitReady`/`ADC_ConversionStop_WaitReady`/`HAL_GPIO_Init_Extended`/`HAL_ADC_Init` — domänenübergreifend |
| `0x08009a5c` | ~~`DMA_Get_HTIF`~~ ❌ | 8B | **Widerlegt** — dito. Bleibt `FUN_08009a5c`, s. 13.21: `(*(uint*)(p1+8)&7)>>2`, Aufrufer `HAL_GPIO_Init_Extended`/`HAL_ADC_Init`/`HAL_ADC_Start_DMA` — domänenübergreifend |
| `0x08009b48` | `debug_log_dequeue` | 42B | Debug-Ringpuffer: nächsten Eintrag holen |
| `0x08009ba0` | `debug_log_format_entry` | 1712B | Debug-Log formatieren (~60 Event-Typen, größte Funktion!) |
| `0x0800ab88` | `debug_log_enqueue` | 70B | Event in Debug-Ringpuffer einfügen |
| `0x0800abda` | `CRC16_Modbus` | 50B | CRC-16/Modbus (Poly 0xA001) |
| `0x0800ac0c` | `Modbus_Process_Request` | 260B | Modbus-Dispatcher: FC03/FC06/FC10 |
| `0x0800ad14` | `Modbus_UART_Start_Receive` | 26B | USART1 DMA-Empfang für Modbus |
| `0x0800ad40` | `NTC_ADC_To_Temperature_1` | 128B | NTC-Lookup Tabelle 1 (Binärsuche) |
| `0x0800adcc` | `NTC_ADC_To_Temperature_2` | 128B | NTC-Lookup Tabelle 2 |
| `0x0800ae58` | `CAN_Send_Packet` | 172B | CAN-Paket bauen + via USART2 senden |
| `0x0800af54` | `I2C_Get_Clock_Freq` | 66B | I2C Taktfrequenz aus PLL berechnen |
| `0x0800afa4` | `BCD_To_Decimal` | 18B | BCD → Dezimal Konvertierung |
| `0x0800afb6` | `I2C_Wait_SB_Flag` | 72B | I2C Start-Bit warten (1s Timeout) |
| `0x0800affe` | `I2C_Wait_ADDR_Flag` | 80B | I2C ADDR-Flag warten |
| `0x0800b050` | `Ymodem_Receive_Packet` | 186B | Ymodem Paket empfangen (SOH/STX/EOT/CAN) |
| `0x0800b120` | `Modbus_Read_Holding_Registers` | 222B | Modbus FC03: Holding-Register lesen |
| `0x0800b208` | `Modbus_Write_Single_Register` ✅ (**korrigiert** 10.07.2026, war `Modbus_Read_Input_Registers`) | 90B | Modbus FC06: einzelnes Register schreiben |
| `0x0800b26c` | `Modbus_Broadcast_Write_Single_Register` ✅ (**korrigiert** 10.07.2026, war `Modbus_Broadcast_Read_Input_Regs`) | 44B | Modbus Broadcast FC06: einzelnes Register schreiben |
| `0x0800b29c` | `Modbus_Write_Multiple_Registers` | 206B | Modbus FC10: Multiple Register schreiben |
| `0x0800b374` | `Modbus_Broadcast_Write_Multi_Regs` | 134B | Modbus Broadcast Write Multiple |
| `0x0800b400` | `RTC_Read_Time` | 90B | RTC Zeit via I2C lesen (BCD) |
| `0x0800b540` | `Ymodem_Send_Byte` | 10B | Ymodem Byte senden (UART5) |
| `0x0800b80c` | `Ymodem_Parse_File_Header` | 200B | Ymodem Datei-Header parsen |
| `0x0800b8d4` | `SysTick_Handler_App` | 64B | App-SysTick: ms/sec Counter |
| `0x0800b958` | `TIM_Base_Init` | 176B | TIM Basis-Register konfigurieren |
| `0x0800ba2c` | `TIM_Set_DMA_Bit` | 26B | TIM DIER Bit setzen/löschen |
| `0x0800ba60` | `TIM_OC1_Config` | 148B | TIM Output Compare Kanal 1 |
| `0x0800bb10` | `TIM_OC2_Config` | 136B | TIM Output Compare Kanal 2 |
| `0x0800bbb4` | `TIM_OC3_Config` | 134B | TIM Output Compare Kanal 3 |
| `0x0800bc58` | `TIM_OC4_Config` | 136B | TIM Output Compare Kanal 4 |
| `0x0800bcfc` | `TIM_IC1_Config` | 92B | TIM Input Capture Kanal 1 |
| `0x0800bd74` | `TIM_IC2_Config` | 94B | TIM Input Capture Kanal 2 |
| `0x0800bdf0` | `TIM_ETR_Config` | 100B | TIM External Trigger |
| `0x0800bf10` | `USART3_PWM_Init` | 96B | USART3 auf TIM3 PWM |
| `0x0800bf7c` | `USART3_Deinit` | 168B | USART3 Timer deinitialisieren |
| `0x0800bf94` | `TIM1_PWM_Init` | 80B | TIM1 PWM: Periode 400, Duty 200 |
| `0x0800c008` | `TIM8_PWM_Init_Encoder` | 102B | TIM8 Encoder-Modus |
| `0x0800c078` | `TIM1_Set_Duty` | 26B | TIM1 PWM Duty setzen (0-400) |
| `0x0800c098` | `TIM5_Init` | 152B | TIM5 initialisieren (Periode 999) |
| `0x0800c0d8` | `Timer_Elapsed_Ms` | 34B | Soft-Timer: ms abgelaufen? |
| `0x0800c100` | `Timer_Elapsed_Sec` | 34B | Soft-Timer: Sekunde abgelaufen? |
| `0x0800c128` | `SPI_DMA_Complete_IRQ` | 80B | SPI DMA-Completion IRQ |
| `0x0800c178` | `SPI_DMA_Start_Receive` | 40B | SPI DMA-Empfang starten |
| `0x0800c1e4` | `SPI_DMA_RX_Disable` | 78B | SPI DMA RX deaktivieren |
| `0x0800c25c` | `SPI_DMA_TX_Disable` | 46B | SPI DMA TX deaktivieren |
| `0x0800c28a` | `SPI_DMA_RX_IRQ_Handler` | 160B | SPI DMA RX Interrupt |
| `0x0800c32c` | `SPI_DMA_TX_IRQ_Handler` | 362B | SPI DMA TX Interrupt |
| `0x0800c7f8` | `CAN_Wait_Response` | 98B | CAN Antwort warten (3s Timeout) |
| `0x0800c94c` | `CAN_Start_FW_Update` | 28B | FW-Update-Modus aktivieren |
| `0x0800ca3c` | `Operating_Hours_Update` | 204B | Betriebsstunden + Fehlerzähler |
| `0x0800cb10` | `UART5_Send_Byte` | 52B | UART5 Byte senden (Polled) |
| `0x0800cb50` | `USART1_DMA_Send` | 42B | USART1 DMA-TX starten |
| `0x0800cb80` | `USART2_Poll_Send` | 40B | USART2 Byte-für-Byte senden |
| `0x0800cbac` | `UART5_Poll_Send` | 40B | UART5 Byte-für-Byte senden |
| `0x0800cbd8` | `Shell_Task_Init` | 18B | Shell-Prompt setzen + init |

### 13.5 Printf, Utility, OTA (0x0800D000–0x0800EDFF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800dc40` | `ota_firmware_download` | 434B | OTA FW-Download: Chunks empfangen, Flash schreiben |
| `0x0800de28` | `debug_sprintf_wrapper` | 34B | sprintf Wrapper |
| `0x0800de72` | `NVIC_SetPriority_Alt` | 32B | NVIC Priorität (0xE000E400) |
| `0x0800de94` | `assert_failed_halt` | 26B | Assert/Fault → DSB + Endlosschleife |
| `0x0800deec` | `printf_float_format` | 334B | Float→String Formatierung für printf |
| `0x0800e050` | `printf_core` | 1696B | Printf Format-Engine (%d/%x/%s/%f) |
| `0x0800e72c` | `printf_pad_trailing` | 36B | Trailing-Space Padding |
| `0x0800e750` | `printf_pad_leading` | 46B | Leading-Space/Zero Padding |
| `0x0800e77e` | `sprintf_putchar` | 10B | Callback: Char in Puffer schreiben |
| `0x0800e788` | `flash_write_config_block` | 44B | 16-Byte Config nach Flash 0x08040000 |
| `0x0800e7f0` | `buzzer_stop` | 14B | Buzzer-Zähler löschen |
| `0x0800e7f8` | `buzzer_tick` | 66B | Periodischer Buzzer-Toggle |
| `0x0800e84c` | `buzzer_beep_short` | 8B | Kurzer Buzzer-Ton (10 Ticks) |
| `0x0800e858` | `can_tx_enqueue` | 42B | CAN TX in Ringpuffer einfügen |
| `0x0800e8a8` | `eTaskGetState` | 120B | FreeRTOS Task-Status abfragen |
| `0x0800ed4c` | `prvAddCurrentTaskToDelayedList` | 138B | Task in Delayed-Liste verschieben |
| `0x0800ede0` | `prvAddNewTaskToReadyList` | 158B | Neuen TCB in Ready-Liste einfügen |

### 13.6 FreeRTOS Kernel (0x0800EE00–0x08013FFF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800ee8c` | `prvDeleteTCBCleanup` | 52B | Task-Deletion Cleanup (Idle Task) |
| `0x0800eec8` | `prvCopyDataFromQueue` | 40B | Queue-Item lesen |
| `0x0800eef0` | `prvCopyDataToQueue` | 110B | Queue-Item einfügen (back/front/overwrite) |
| `0x0800ef5e` | `prvDeleteTCB` | 20B | Task-Speicher + TCB freigeben |
| `0x0800ef72` | `prvGetDisinheritedPriority` | 20B | Original-Priorität für Mutex |
| `0x0800ef88` | `prvHeapInit` | 62B | heap_4 Free-List initialisieren |
| `0x0800eff8` | `prvInitialiseMutex` | 24B | Mutex-Queue-Felder initialisieren |
| `0x0800f010` | `prvInitialiseNewQueue` | 38B | Queue-Control-Block initialisieren |
| `0x0800f038` | `prvInitialiseNewTask` | 160B | TCB initialisieren (Stack, Name, Prio) |
| `0x0800f104` | `prvInitialiseTaskLists` | 74B | Scheduler-Listen (32 Ready + Delayed) |
| `0x0800f15c` | `prvInsertBlockIntoFreeList` | 78B | heap_4 Free-List Insert (Coalescing) |
| `0x0800f1b0` | `prvIsQueueEmpty` | 26B | Queue leer? |
| `0x0800f1ca` | `prvIsQueueFull` | 30B | Queue voll? |
| `0x0800f1e8` | `prvListTasksWithinSingleList` | 92B | Tasks einer Liste enumerieren |
| `0x0800f244` | `prvNotifyQueueSetMembers` | 126B | Queue-Set benachrichtigen |
| `0x0800f2f0` | `prvResetNextTaskUnblockTime` | 28B | Nächste Unblock-Zeit zurücksetzen |
| `0x0800f310` | `prvTaskCheckFreeStackSpace` | 20B | Stack-Watermark (0xA5) zählen |
| `0x0800f390` | `prvUnlockQueue` | 124B | Deferred Queue-Lock verarbeiten |
| `0x0800f430` | `pvPortMalloc` | 196B | heap_4 First-Fit Allokator |
| `0x0800f538` | `prvGetMutexHolder` | 20B | Mutex-Holder TCB |
| `0x0800f550` | `pxPortInitialiseStack` | 30B | Task Exception-Stack Frame |
| `0x08011b24` | `uxListRemove` | 38B | FreeRTOS: Item aus Liste entfernen |
| `0x08011b4c` | `uxTaskGetNumberOfTasks` | 6B | Aktuelle Task-Anzahl |
| `0x08011b58` | `uxTaskGetSystemState` | 158B | Alle Task-Status-Infos |
| `0x08011c04` | `vListInitialise` | 22B | Liste initialisieren |
| `0x08011c1a` | `vListInitialiseItem` | 6B | List-Item initialisieren |
| `0x08011c20` | `vListInsert` | 48B | Sortiertes Einfügen in Liste |
| `0x08011c50` | `vListInsertEnd` | 24B | Am Index einfügen |
| `0x08011c68` | `vPortEnterCritical` | 50B | BASEPRI → 0x90, Nesting++ (13 Aufrufe) |
| `0x08011ce8` | `vPortExitCritical` | 38B | Nesting--, BASEPRI löschen (13 Aufrufe) |
| `0x08011d58` | `vPortFree` | 98B | heap_4 Speicher freigeben |
| `0x08011e00` | `vPortSetupTimerInterrupt` | 32B | SysTick konfigurieren |
| `0x08011e24` | `vPortValidateInterruptPriority` | 70B | ISR-Priorität validieren |
| `0x08011eb8` | `vTaskDelay` | 66B | Task N Ticks verzögern |
| `0x08011f30` | `vTaskGetTaskInfo` | 112B | Task-Status-Struct füllen |
| `0x08011fa4` | `vTaskSetTimeOutState` | 12B | Timeout-State erfassen |
| `0x08012060` | `vTaskMissedYield` | 8B | xYieldPending = 1 |
| `0x0801206c` | `vTaskPlaceOnEventList` | 46B | Task auf Event-Warteliste |
| `0x080120cc` | `prvTaskPriorityDisinheritAfterTimeout` | 186B | Mutex-Timeout Prio-Restore |
| `0x0801224c` | `vTaskSuspend` | 176B | Task suspendieren |
| `0x08012338` | `vTaskEnterCritical` | 10B | uxCriticalNesting++ (8 Aufrufe) |
| `0x08012348` | `vTaskSwitchContext` | 84B | Höchste Ready-Prio via CLZ finden |
| `0x08013078` | `xPortStartScheduler` | 228B | FreeRTOS Scheduler starten (FPU Config) |
| `0x080131b4` | `xPortSysTickHandler` | 38B | SysTick ISR: Tick++, PendSV |
| `0x080131e0` | `xSemaphoreCreateMutex` | 24B | Mutex-Semaphore erstellen |
| `0x080131f8` | `xQueueCreateMutex` | 78B | Mutex-Queue allozieren + init |
| `0x08013274` | `xQueueGenericReset` | 174B | Queue zurücksetzen |
| `0x08013354` | `xQueueGenericSend` | 372B | Queue-Item senden (blockierend) |
| `0x080134f8` | `xQueueGenericSendFromISR` | 224B | Queue-Item aus ISR senden |
| `0x08013604` | `xQueueGenericReceive` | 296B | Queue-Item empfangen (blockierend) |
| `0x0801375c` | `xQueueSemaphoreTake` | 340B | Semaphore nehmen (Timeout) |
| `0x080138e0` | `xTaskCheckForTimeOut` | 134B | Timeout abgelaufen? |
| `0x08013a00` | `xTaskGetSchedulerState` | 24B | Scheduler-Status (0/1/2) |
| `0x08013a1c` | `xTaskIncrementTick` | 292B | Tick++, Delayed→Ready verschieben |
| `0x08013b74` | `prvTaskPriorityDisinherit` | 166B | Mutex-Release Prio-Restore |
| `0x08013c50` | `prvTaskPriorityInherit` | 172B | Mutex-Take Prio-Inherit |
| `0x08013d04` | `xTaskRemoveFromEventList` | 206B | Event→Ready verschieben (7 Aufrufe) |
| `0x08013e0c` | `xTaskResumeAll` | 280B | Scheduler fortsetzen (8 Aufrufe) |

### 13.7 Letter-Shell Bibliothek (0x0800F500–0x080110FF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0800f5c0` | `shell_register_instance` | 26B | Shell-Instanz registrieren |
| `0x0800f628` | `shell_check_permission` | 48B | Benutzerrechte für Kommando prüfen |
| `0x0800f658` | `shell_print_logo` | 24B | Shell-Banner ausgeben |
| `0x0800f674` | `shell_clear_input_line` | 42B | Terminal-Eingabezeile löschen |
| `0x0800f6a6` | `shell_delete_char` | 214B | Zeichen löschen (vorwärts/rückwärts) |
| `0x0800f788` | `shell_password_input` | 22B | Passwort-Eingabe + Callback |
| `0x0800f7a0` | `shell_password_verify` | 162B | Nachträgliche Passwort-Prüfung |
| `0x0800f814` | `shell_detect_number_base` | 78B | Zahlenbasis erkennen (dec/bin/oct/hex/float) |
| `0x0800f862` | `shell_parse_escape_char` | 60B | C-Escape-Sequenzen parsen (\n, \r, \t) |
| `0x0800f89e` | `shell_parse_number` | 194B | Numerischen String parsen (int/float) |
| `0x0800f960` | `shell_parse_argument` | 94B | Einzelnes Argument parsen |
| `0x0800f99c` | `shell_parse_string` | 70B | String mit Quotes parsen |
| `0x0800fa04` | `shell_invoke_command` | 204B | Kommando mit 0-7 Argumenten dispatchen |
| `0x0800fad8` | `shell_hex_char_to_val` | 44B | Hex-ASCII → numerisch |
| `0x0800fb04` | `shell_entry_get_desc` | 10B | Entry-Beschreibung (Offset+0xC) |
| `0x0800fb10` | `shell_entry_get_name` | 60B | Entry-Name (Offset+4) |
| `0x0800fb50` | `shell_get_active_instance` | 36B | Erste aktive Shell-Instanz |
| `0x0800fb78` | `shell_get_variable_value` | 56B | Variable lesen (Ptr/Val/Getter) |
| `0x0800fc90` | `shell_cmd_help` | 40B | `help` Kommando-Handler |
| `0x0800fcb8` | `shell_history_navigate` | 154B | Kommando-History navigieren (↑/↓) |
| `0x0800fd52` | `shell_history_push` | 108B | Kommando in History-Ring (5 Einträge) |
| `0x0800fdc0` | `shell_init` | 118B | Shell-Kontext initialisieren |
| `0x0800ff10` | `shell_backspace_display` | 26B | Backspace-Anzeige |
| `0x0800ff30` | `shell_list_commands` | 70B | Alle erlaubten Kommandos auflisten |
| `0x0800ff7c` | `shell_print_command_entry` | 154B | Kommando-Eintrag formatiert ausgeben |
| `0x08010034` | `shell_parse_args` | 118B | Eingabe in max. 8 Tokens zerlegen |
| `0x080100aa` | `shell_strip_quotes` | 66B | Anführungszeichen entfernen |
| `0x08010102` | `shell_command_dispatch` | 146B | Type-basierter Kommando-Dispatch |
| `0x08010194` | `shell_user_search` | 116B | User-Entry suchen (16-Byte Iterator) |
| `0x08010208` | `shell_login_handler` | 90B | Login-Handler (3 Passwort-Pfade) |
| `0x08010268` | `shell_print_variable` | 154B | Variable anzeigen (Dec+Hex) |
| `0x08010324` | `shell_common_prefix_len` | 36B | Common-Prefix für Tab-Completion |
| `0x08010348` | `shell_strcpy` | 24B | Byte-für-Byte String-Kopie |
| `0x08010360` | `shell_tab_complete` | 314B | Tab-Completion (Single/Multi/Double-Tab) |
| `0x080104a4` | `shell_int_to_dec` | 82B | Int → Dezimalstring |
| `0x080104f6` | `shell_int_to_hex` | 42B | Int → Hexstring |
| `0x08010526` | `shell_write_char` | 12B | Einzelnes Zeichen via Callback |
| `0x08010534` | `shell_write_string` | 76B | String ausgeben (max 150, "..." Abschnitt) |
| `0x08010584` | `shell_show_command_help` | 88B | Detaillierte Hilfe für Kommando |
| `0x080105e4` | `shell_print_prompt` | 78B | "user:path$ " Prompt ausgeben |
| `0x08010648` | `shell_print_return_value` | 98B | "Return: <dec>, 0x<hex>" ausgeben |
| `0x080106d0` | `shell_print` | 40B | UART String-Ausgabe (13 Aufrufe) |

### 13.8 Modbus-Register & Inverter-Regelung (0x08011100–0x08015FFF)

| Adresse | Name | Größe | Beschreibung |
|---|---|---|---|
| `0x0801178c` | `SPI_DMA_Init` | 150B | SPI mit DMA initialisieren |
| `0x0801182c` | `watchdog_feed_and_decrement` | 4B | Watchdog füttern + Safety-Counter |
| `0x08011830` | `decrement_safety_counter` | 24B | DAT_2000046c Counter dekrementieren |
| `0x08011854` | `TIM3_PWM_Init` | 128B | TIM3 PWM initialisieren (Periode 8499) |
| `0x080118e8` | `modbus_read_register_block` | 526B | Register-Block lesen mit Float→Int Skalierung |
| `0x080124e8` | `modbus_register_handler` | 2842B | **Massiver Modbus Register R/W Handler** (größte Funktion!) |
| `0x080150d4` | ~~`CAN_TxMailbox_SetDLC`~~ ❌ | 10B | **Widerlegt** — nie in Ghidra angewendet (Stale-Doku aus 07.07). Bleibt `FUN_080150d4`, s. 13.18/13.21: realer MOVW/MOVT/BX-Interworking-Veneer, springt in `UART_WaitOnFlagUntilTimeout`-Tail |
| `0x080150e8` | ~~`CAN_RxFilter_Config`~~ ❌ | 10B | **Widerlegt** — dito. Bleibt `FUN_080150e8`, s. 13.18/13.21: Veneer, springt in `UART_WaitOnFlagUntilTimeout`-Tail |
| `0x080150fc` | ~~`float_to_fixed_point`~~ ❌ | 10B | **Widerlegt** — dito. Bleibt `FUN_080150fc`, s. 13.18/13.21: Veneer, springt in `RCC_OscConfig`-Tail, Aufrufer `Inverter_Grid_Control` (8×) |
| `0x080151c4` | ~~`CAN_frame_pack`~~ ❌ | 10B | **Widerlegt** — dito. Bleibt `FUN_080151c4`, s. 13.18/13.21: Veneer, springt in `RCC_OscConfig`-Tail |
| `0x08015450` | `inverter_grid_control` | 836B | Netzanschluss-Steuerung (BMS-Fehler, Schutz) |
| `0x08015818` | `atan_normalized` | 140B | Polynomiale atan(x)/π Näherung |
| `0x0801590a` | `biquad_filter_design` | 94B | Biquad IIR-Filterkoeffizienten berechnen |
| `0x0801598c` | `PI_controller_step` | 116B | PI-Regler: P + I mit Clamping |
| `0x08015a00` | `PI_controller_reset` | 34B | PI-Regler Zustand zurücksetzen |
| `0x08015b0c` | `compute_reactive_power_ref` | 164B | Blindleistungs-Referenz aus PF berechnen |
| `0x0801b2fc` | `notch_filter_design` | 126B | 2. Ordnung Notch-Filter (Ts=35.7µs) |
| `0x0801ba34` | `grid_freq_filter_update` | 72B | Biquad+Notch Koeffizienten für Netzfrequenz |

### 13.9 Korrektur-Session 10.07.2026 — tatsächlich in Ghidra verifiziert & umbenannt

> Ausgangslage: Ghidra-Ist-Zustand vor dieser Session = **21 benannte Funktionen** (445 total,
> `filterDefaultNames=true` lieferte 21). Alle anderen Namen in 13.1–13.8 waren nur Doku-Vorschläge
> aus der nie eingecheckten 07.07.-Analyse. In dieser Session wurden **106 Funktionen einzeln per
> Dekompilierung verifiziert** (Signatur, Aufrufer-Kontext, Register-/Adress-Konstanten geprüft) und
> per Ghidra-Skript (`setName`, `SourceType.USER_DEFINED`) umbenannt. Neuer Ghidra-Ist-Zustand:
> **127 benannte Funktionen** (21 + 106), 0 Namenskollisionen. 318 Funktionen sind weiterhin `FUN_*`.

**Dubletten-Fix:** `CAN_Filter_Setup` lag doppelt vor — echte Funktion `0x0800eb88` (260B, CAN-Filter
konfigurieren, 9 Callees) und ein 10-Byte-Thunk auf `0x080150f2` (48 Aufrufer, Sprung zu `0x0800eb88`
via `resolve-thunk` bestätigt). Der Thunk wurde zu `thunk_CAN_Filter_Setup` umbenannt.

**106 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch (Register-Konstanten / Algorithmus eindeutig erkennbar):*
`0x08000332 memcpy`, `0x08000356 __aeabi_memset`, `0x08000364 memclr`, `0x08000368 memset`,
`0x0800037a strlen`, `0x08000388 strcmp`, `0x080003a4 strcpy`, `0x080003d4 __aeabi_ui2d`,
`0x0800042c __aeabi_uidiv`, `0x08000458 __aeabi_llsl`, `0x08000476 __aeabi_llsr`,
`0x080002d0 __aeabi_uldivmod`, `0x08000496 __aeabi_dadd`, `0x080005e4 __aeabi_dmul`,
`0x080006c8 __aeabi_ddiv`, `0x080007a6 __aeabi_d2lz`, `0x0800082c __aeabi_lasr`,
`0x0800086e __aeabi_dnorm`, `0x08000234 FPU_Enable` (CPACR |= 0xF00000),
`0x0800abda CRC16_Modbus` (Poly 0xA001, exakt), `0x08009a34 IWDG_Reload` (`*reg=0xAAAA`),
`0x0800325c FLASH_ProgramDoubleWord`, `0x080031d4 FLASH_MassErase`, `0x08003210 FLASH_SectorErase`,
`0x08003178 FLASH_FlushCaches` (FLASH_ACR 0x40022000), `0x080032a4 FLASH_WaitForOperation`,
`0x080057ac HAL_GetTick`, `0x0800675c NVIC_EnableIRQ` (NVIC->ISER-Bitband, **korrigiert**, s.u.),
`0x08006dc0 HAL_RCC_GetSysClockFreq` (RCC_CFGR SWS-Bits, **korrigiert**, s.u.),
`0x08006800 DAC_Init` (DAC_BASE 0x40007000), `0x0800afa4 BCD_To_Decimal`,
`0x080099ec uint_to_decimal_string`, `0x08000ef0 ADC_ConvertRawValues` (Skalierung 0.21606445,
Ziel = SRAM-Adressen aus Tabelle 5.2), `0x08001158 ADC_ProcessSamples` (Ziel = Tabelle 5.1),
`0x080012e0 Grid_Protection_SetLimits` (grid_standard-abhängige Float-Konstanten),
`0x08002ce8 EEPROM_WriteRegister` / `0x08002d84 EEPROM_ReadRegister` (I2C-Adr. 0xA0/0xA2),
`0x08002a68 EEPROM_LoadConfig`, `0x080020d0 CAN_SetFilter_ExtID` / `0x08002108 CAN_SetFilter_StdID`
(direkt aus `CAN_Filter_Setup` mit Werten `0x4000/0xFF00` etc. — deckt sich exakt mit Tabelle 4.1),
`0x08001f34 CAN_TX_SendMessage` (Segmentierung `param_4>>3`, 8-Byte-Frames),
`0x0800ac0c Modbus_Process_Request` (CRC16_Modbus-Aufruf bestätigt),
`0x0800b120 Modbus_Read_Holding_Registers` (FC03-Zweig in Modbus_Process_Request),
`0x0800b29c Modbus_Write_Multiple_Registers` / `0x0800b374 …Broadcast_Write_Multi_Regs` (FC16-Zweig),
`0x0800ca3c Operating_Hours_Update` (Stundenzähler, Ziel-SRAM = daily_charge/discharge_energy aus 11.1),
`0x0800ab88 debug_log_enqueue` / `0x08009b48 debug_log_dequeue` (Ringpuffer 0x20001A2C,
Gegenstück bestätigt, `debug_log_enqueue` zusätzlich aus `Mode3_RoundRobin_Timer` gemäß Abschnitt 12.3
verifiziert), `0x0800b8d4 SysTick_Handler_App` (inkrementiert denselben Tick wie `Timer_Elapsed_Ms`),
`0x0800c0d8 Timer_Elapsed_Ms` / `0x0800c100 Timer_Elapsed_Sec`, `0x08003670 HAL_GPIO_Init_Extended`
(gemeinsame Zielfunktion von `GPIO_ConfigPin`/`_HighSpeed`), `0x08000bdc GPIO_ConfigPin` /
`0x08000bfc GPIO_ConfigPin_HighSpeed`, `0x08000c20 Peripheral_GPIO_Init`.

*Mittel (Kontext/Aufrufer stimmig, Details nicht 100% verifiziert):*
`0x080002a4 get_current_irq_number`, `0x080003b6 strncmp`, `0x0800273e memcpy_reverse`,
`0x08002a3c delay_ms`, `0x08003078 Error_Handler`, `0x0800343c checksum_add`, `0x08003458 checksum_xor`,
`0x08000a28 UART_IRQHandler`, `0x08000aa6 UART_ErrorHandler`, `0x08000ac0 UART_DMA_Handler`,
`0x08000acc UART_WaitReady`, `0x08002024 CAN_TX_SendCommand`, `0x080020b0 CAN_BuildArbID`,
`0x08001e3c CAN_TX_ReadQueue`, `0x08001f04 CAN_RX_DispatchTask`, `0x08002034 CAN_TX_SendFrame`,
`0x08002070 CAN_TX_ProcessQueue`, `0x08003090 CAN_InitMailboxes`, `0x08003104 CAN_CopyTxFrame`,
`0x08003278 FLASH_Program256Bit`, `0x08003310 FLASH_EraseSectors`, `0x08003378 FLASH_WriteData`,
`0x080033f0 Get_GridFrequency`, `0x0800213c OTA_FW_Update_StateMachine`, `0x08002614 Serial_ValidatePacket`,
`0x0800277c DMA_CalcBaseAndOffset`, `0x080027e0 DMA_SetConfig`, `0x0800299c Inverter_SetMode`,
`0x080029fc EEPROM_ClearStats`, `0x08002e14 EEPROM_SaveTimestamp`, `0x08002e40 EEPROM_WriteVerify`,
`0x08002f78 EEPROM_WriteVerify_NoMutex`, `0x0800ad40 NTC_ADC_To_Temperature_1` /
`0x0800adcc NTC_ADC_To_Temperature_2` (Aufrufer = `ADC_ProcessSamples`), `0x0800ae58 CAN_Send_Packet`,
`0x0800b400 RTC_Read_Time` (BCD_To_Decimal-Aufrufe bestätigt), `0x0800b540 Ymodem_Send_Byte`,
`0x0800c94c CAN_Start_FW_Update`, `0x0800af54 I2C_Get_Clock_Freq`, `0x0800afb6 I2C_Wait_SB_Flag`,
`0x0800affe I2C_Wait_ADDR_Flag`, `0x0800b050 Ymodem_Receive_Packet`, `0x0800b80c Ymodem_Parse_File_Header`,
`0x08009850 UART_Transmit_Wait`, `0x080098f8 UART_Receive_Wait`, `0x08009944 UART_Transmit_Wait_Alt`,
`0x0800ad14 Modbus_UART_Start_Receive`, `0x0800cb10 UART5_Send_Byte`.

**Korrekturen gegenüber dem alten Doku-Vorschlag (Name war falsch, nach Verifikation neu vergeben):**

| Adresse | Alter Doku-Name (falsch) | Neuer Name (verifiziert) | Begründung |
|---|---|---|---|
| `0x0800675c` | `IWDG_SetPrescaler` | `NVIC_EnableIRQ` | Schreibt `NVIC->ISER[n/32] = 1<<(n%32)` — klassisches NVIC-Bitband-Enable-Pattern, kein IWDG-Register |
| `0x08006dc0` | `DAC_SetValue` | `HAL_RCC_GetSysClockFreq` | Liest `RCC_CFGR`-SWS-Bits (`0x40021008`), gibt 16 MHz/8 MHz zurück — klassische Clock-Source-Erkennung, kein DAC-Zugriff |
| `0x08009994` | `USART2_Init` | `I2C1_Init` | Schreibt `0x40005400` (= I2C1-Base auf STM32F4, nicht USART2 = `0x40004400`); Handle wird direkt von den bestätigten EEPROM-I2C-Funktionen verwendet |
| `0x0800b208` | `Modbus_Read_Input_Registers` | `Modbus_Write_Single_Register` | Schreibt einen Wert (`FUN_080124e8(addr, value, 1, …)`), liest nichts — FC06 ist Modbus "Write Single Register", nicht "Read" |
| `0x0800b26c` | `Modbus_Broadcast_Read_Input_Regs` | `Modbus_Broadcast_Write_Single_Register` | Broadcast-Variante derselben Write-Funktion |

**Abgelehnt (Doku-Name klar widerlegt, absichtlich NICHT umbenannt — bleibt `FUN_<adresse>`):**

| Adresse | Doku-Name (verworfen) | Grund |
|---|---|---|
| `0x0800020c` | `NVIC_SystemReset` | Dekompilat zeigt Privilegien-Eskalation + SVC(0) + FPU-Enable-Pattern (CMSIS-RTOS-Kernel-Start-artig), keine SCB->AIRCR-Schreiboperation |
| `0x080007d8` | `__aeabi_d2iz` | Nur 9 Zeilen, reine Vorzeichen-Negation — zu simpel für vollständige Double→Int-Konvertierung |
| `0x08000b50` | `CAN_WaitReady` | Aufrufer ist `FUN_08003ff8` (UART/DMA-Kontext), keine CAN-Bezüge im Code |
| `0x0800150a` | `NVIC_SetPriority` | Ruft `FUN_080055c4` mit magischer Konstante `0x110000` — Struktur passt nicht zu direktem NVIC_IPR-Register-Zugriff |
| `0x08001532` | `NVIC_EnableIRQ` | Gleiches Muster wie `0x0800150a`; echtes `NVIC_EnableIRQ` wurde stattdessen bei `0x0800675c` gefunden |
| `0x08000fb4` | `CAN_Peripheral_Init` | Schreibt `0x50000000` (USB-OTG-FS-Base auf STM32F4) in Zielstruktur — kein CAN-Bezug |
| `0x08001ea0` | `UART_Init` | Schreibt `0x40006400` (= CAN1-Base) in `DAT_20001270` — genau das Handle, das `CAN_SetFilter_ExtID/StdID` benutzen. Ist vermutlich der echte CAN-Init, nicht UART |
| `0x08001868` | `CAN_RX_ParseBMSCommand` | Aufrufer-Kontext (`FUN_08005248`, dort als "DMA_Start_IT" dokumentiert) passt nicht zu BMS/CAN |
| `0x08002824` | `TIM6_PWM_Init` | Schreibt `0x50000800` — nicht TIM6-Base (`0x40001000`) |
| `0x080035d4` | `UART_SetBaudRate` | Wird mehrfach mit identischer Konstante `0x7f` auf verschiedene Zeiger aufgerufen — passt nicht zu "eine Baudrate setzen"; hängt an der fraglichen `0x08000fb4`-Kette |
| `0x08003af0`, `0x08003b04`, `0x08003d54`, `0x08003ff8`, `0x08004128` | `UART_RX_Callback`, `HAL_UART_Init`, `UART_MspInit`, `UART_StartReceive_DMA`, `HAL_TIM_Base_Init_Full` | Gesamter Cluster hängt an `0x08000fb4`; mehrere Funktionen referenzieren `0x50000000`/`0x50000100`/`0x50000300` (USB-OTG-FS-Adressraum) — vermutlich ungenutzter USB-Treibercode, nicht UART |
| `0x08005384` | `ADC_Init` | Aufrufer ist bestätigtes `FLASH_EraseSectors` (`0x08003310`) — kein ADC-Bezug |
| `0x08005774`, `0x08005782`, `0x08005792`, `0x080057a0` | `HAL_RCC_GetPCLK1Freq`, `…PCLK2Freq`, `…GetHCLKFreq`, `…GetSysClockFreq` | Dekompilate sind generische Bitfeld-Setter/-Tester ohne Frequenzberechnung; die echte Systemtakt-Funktion wurde bei `0x08006dc0` gefunden |
| `0x08005c10` | `I2C_Init` | Generische Struct-Init, keine I2C-spezifischen Register erkennbar |
| `0x080066d8` | `IWDG_WaitForReady` | Aufrufer sind HRTIM-/DAC-Funktionen, kein IWDG-Bezug |
| `0x08009a4c`, `0x08009a54`, `0x08009a5c` | `DMA_Get_TCIF`, `…Error_Flag`, `…HTIF` | Aufrufer ist bestätigtes `HAL_GPIO_Init_Extended` — Bitfelder passen zu GPIO-MODER-Extraktion, nicht DMA-Flags |

**Offen für Folge-Session (Stand vor Tranche 2c):** 318 Funktionen waren weiterhin `FUN_0800xxxx`/`FUN_0801xxxx` (445 − 127).
Besonders der Adressbereich ca. `0x08004caa`–`0x08009800` (TIM/HRTIM/RCC/ADC/I2C in 13.3) zeigt
systematischen Adress-Drift zwischen Doku-Vorschlag und Ghidra-Realität und sollte komplett neu
verifiziert statt aus der alten Tabelle übernommen werden.

### 13.10 Tranche 2c (10.07.2026) — Adressbereich 0x08010034–0x0801ba34

> Bearbeiteter Bereich: oberer FW-Bereich (Letter-Shell-Bibliothek, FreeRTOS-Kernel/Tasks-Umfeld,
> CAN-Filter-Umfeld, Modbus-Register-Handler, Wechselrichter-Regelung/DSP-Block). Methodik wie in
> 13.9: jede Funktion einzeln per `get-decompilation` (inkl. Caller-Kontext) dekompiliert und
> verifiziert, nicht blind aus Abschnitt 13.7/13.8 übernommen. Ghidra-Ist-Zustand vor Tranche 2c:
> 127 benannte Funktionen. Nach Tranche 2c: **193 benannte Funktionen** (127 + 66), 0 Namenskollisionen
> (per Skript-Dubletten-Check gegen alle 193 Namen bestätigt).
>
> **Besonders wertvolle Verifikationsquelle in diesem Bereich:** Der FreeRTOS-Kernel-Code enthält an
> vielen Stellen eingebettete Debug-Strings mit Original-Quelldateipfaden, z. B.
> `"..\\..\\SDK\\FreeRTOS\\portable\\RVDS\\ARM_CM4F\\port.c"`, `"..\\..\\SDK\\FreeRTOS\\tasks.c"`,
> `"..\\..\\SDK\\FreeRTOS\\queue.c"`, `"..\\..\\SDK\\FreeRTOS\\portable\\MemMang\\heap_4.c"`
> (jeweils mit Zeilennummer als zweitem `debug_printf`-Argument). Diese Strings erlauben eine
> Verifikation der FreeRTOS-Kernel-Funktionen nahezu auf Ground-Truth-Niveau (Datei+Zeile stimmen mit
> der bekannten FreeRTOS-Quellstruktur überein) — deutlich zuverlässiger als reine Registerkonstanten-
> Heuristik. Alle als "hoch" eingestuften FreeRTOS-Namen unten sind über diesen Mechanismus bestätigt.

**66 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Letter-Shell-Bibliothek (0x08010034–0x080106d0, hoch — Parameter-/Aufrufer-Struktur exakt zur
Shell-Kontext-Struct aus Abschnitt 7 passend, `shell_login_handler` zusätzlich durch die bereits in
7.1 dokumentierte Assembly-Verifikation bestätigt):*
`0x08010034 shell_parse_args`, `0x080100aa shell_strip_quotes`, `0x08010102 shell_command_dispatch`,
`0x08010194 shell_user_search`, `0x08010208 shell_login_handler`, `0x08010268 shell_print_variable`,
`0x08010324 shell_common_prefix_len`, `0x08010348 shell_strcpy`, `0x08010360 shell_tab_complete`,
`0x080104a4 shell_int_to_dec`, `0x080104f6 shell_int_to_hex`, `0x08010526 shell_write_char`,
`0x08010534 shell_write_string`, `0x08010584 shell_show_command_help`, `0x080105e4 shell_print_prompt`,
`0x08010648 shell_print_return_value`, `0x080106d0 shell_print`.

*FreeRTOS-Kernel (hoch — Quelldatei+Zeile aus eingebetteten Debug-Strings bestätigt, siehe oben;
Ausnahmen ohne String-Beleg aber mit eindeutigem Strukturmuster ebenfalls hoch):*
`0x08011b24 uxListRemove`, `0x08011b4c uxTaskGetNumberOfTasks`, `0x08011b58 uxTaskGetSystemState`,
`0x08011c04 vListInitialise`, `0x08011c1a vListInitialiseItem`, `0x08011c20 vListInsert`,
`0x08011c50 vListInsertEnd`, `0x08011c68 vPortEnterCritical` (port.c:0x1b9),
`0x08011ce8 vPortExitCritical` (port.c:0x1c0), `0x08011d58 vPortFree` (heap_4.c:0x12f/0x130),
`0x08011e00 vPortSetupTimerInterrupt`, `0x08011e24 vPortValidateInterruptPriority` (port.c:0x34d/0x35d),
`0x08011eb8 vTaskDelay` (tasks.c:0x51c), `0x08011f30 vTaskGetTaskInfo`, `0x08011fa4 vTaskSetTimeOutState`,
`0x08012060 vTaskMissedYield`, `0x0801206c vTaskPlaceOnEventList` (tasks.c:0xc0e),
`0x080120cc prvTaskPriorityDisinheritAfterTimeout` (tasks.c:0x1098/0x10b3),
`0x0801224c vTaskSuspend`, `0x08012338 vTaskEnterCritical`,
`0x08012348 vTaskSwitchContext` (LZCOUNT auf Ready-List-Bitmap, tasks.c:0xbf6),
`0x08013078 xPortStartScheduler` (port.c:0x146/0x147/0x160), `0x080131b4 xPortSysTickHandler`,
`0x080131e0 xSemaphoreCreateMutex`, `0x080131f8 xQueueCreateMutex` (queue.c:0x1e4),
`0x08013274 xQueueGenericReset` (queue.c:0x12e), `0x08013354 xQueueGenericSend`,
`0x080134f8 xQueueGenericSendFromISR` (queue.c:0x420–0x422), `0x08013604 xQueueGenericReceive` (queue.c:0x56b),
`0x0801375c xQueueSemaphoreTake` (queue.c:0x5fd), `0x080138e0 xTaskCheckForTimeOut` (tasks.c:0xcef/0xcf0),
`0x08013a00 xTaskGetSchedulerState`, `0x08013a1c xTaskIncrementTick` (tasks.c:0xab7),
`0x08013b74 prvTaskPriorityDisinherit` (tasks.c:0x1048/0x1049), `0x08013c50 prvTaskPriorityInherit`,
`0x08013d04 xTaskRemoveFromEventList` (tasks.c:0xc74), `0x08013e0c xTaskResumeAll` (tasks.c:0x885).

*Modbus / Safety (hoch — Aufrufer sind bereits verifizierte Modbus-Funktionen bzw. Struktur exakt
zur ModbusRegDescriptor-Struct aus Abschnitt 16.2 passend):*
`0x080118e8 modbus_read_register_block` (Descriptor-Struct + Skalierungs-Switch 1/2/3/4 exakt wie
16.2), `0x080124e8 modbus_register_handler` (Aufrufer = alle 5 bereits verifizierten Modbus-FC03/06/16-
Funktionen; siehe Abschnitt 16 — dieselbe Funktion, jetzt zusätzlich in Ghidra selbst umbenannt),
`0x08011830 decrement_safety_counter` (dekrementiert `DAT_2000046c`, Aufrufer `Mode3_RoundRobin_Timer`).

*Safety (mittel):* `0x0801182c watchdog_feed_and_decrement` (4-Byte-Stub direkt vor
`decrement_safety_counter`, fällt in dieselbe Funktion durch; ruft eine noch unbenannte Funktion
außerhalb dieses Bereichs auf, daher Watchdog-Bezug plausibel aber nicht 100% verifiziert).

*Wechselrichter-Regelung / DSP (hoch — Algorithmus/Konstanten eindeutig):*
`0x08015450 Inverter_Grid_Control` (836B, BMS-Fehlerbitmaske + Netzverbindungs-Logik + mehrere
`thunk_CAN_Filter_Setup`-Aufrufe mit Status-Codes — Größe exakt wie alter Doku-Vorschlag),
`0x08015818 atan_normalized` (Polynom-Näherung, Koeffiziententabelle bei externem Flash `0x10006b00`,
Division durch π am Ende), `0x0801590a biquad_filter_design` (klassische Biquad-Koeffizientenberechnung
aus Grenzfrequenz+Q, 5 Koeffizienten b0/b1/b2/a1/a2-Muster),
`0x0801598c PI_controller_step` (P+I mit Clamping zwischen Max/Min-Feldern der Regler-Struct),
`0x08015a00 PI_controller_reset` (nullt alle Zustandsfelder der PI-Struct),
`0x08015b0c compute_reactive_power_ref` (sqrt(1/pf²−1)-Berechnung, klassische PF→Q-Umrechnung),
`0x0801b2fc notch_filter_design` (2. Ordnung, Ts=3.5714285e-05s=35,7µs — exakt wie alter
Doku-Vorschlag), `0x0801ba34 grid_freq_filter_update` (ruft `biquad_filter_design` +
`notch_filter_design` mit Netzfrequenz-Parameter auf).

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, nicht umbenannt):**

| Adresse | Grund |
|---|---|
| `0x0801178c` | Kombiniertes DAC/HRTIM-Init (ruft `DAC_Init`, 2× `FUN_08006e34`, `FUN_08006bec` — alle Callees liegen außerhalb dieses Bereichs und sind noch nicht durch Tranche 2a/2b verifiziert; Doku-Vorschlag "SPI_DMA_Init" wird vom Dekompilat klar widerlegt — keine SPI-Basisadresse im Code), Zweck bleibt unklar |
| `0x08011854` | HRTIM-Capture-Setup mit GPIO/EXTI-Konfiguration und `NVIC_EnableIRQ(0x1e)` — Doku-Vorschlag "TIM3_PWM_Init" widerlegt (keine TIM3-Basisadresse `0x40000400` im Code, stattdessen HRTIM-Callees); mögliche Zero-Crossing-Detection, aber nicht sicher genug für Umbenennung |
| `0x08011b10` | Trivialer 2-Instruktionen-Stub (`_DAT_20000458 = _DAT_20000024`), kein erkennbarer semantischer Name ableitbar |
| `0x080150d4`, `0x080150e8`, `0x080150fc`, `0x080151c4` | Je 10 Byte, Dekompilat verwendet `unaff_r4`/`unaff_r5`/`unaff_r6`-Register (Ghidra-Artefakt für Codefragmente ohne sauberen Funktionseintritt) — vermutlich fälschlich als eigene Funktionen erkannte Sprungziele innerhalb des interleaved Shell-Kommandotabellen-Bereichs (vgl. Hinweis in Abschnitt 7.1 zum RVDS/Keil Code/Daten-Interleave). Alte Doku-Vorschläge (`CAN_TxMailbox_SetDLC` etc.) sind nicht verifizierbar und wurden bewusst nicht übernommen |

**Bereits vor Tranche 2c benannt (unverändert, nur zur Vollständigkeit im Bereich erwähnt):**
`0x080150f2 thunk_CAN_Filter_Setup`, `0x08013998 xTaskCreate`, `0x080163d0 vtask_can`,
`0x08016424 vtask_modbus`.

### 13.11 Tranche 2b (10.07.2026) — Adressbereich 0x0800803c–0x0800ffff

> Bearbeiteter Bereich: mittlerer FW-Bereich (HRTIM/TIM/SPI/I2C-Peripherietreiber-Ausläufer,
> UART-DMA/IRQ-Handler, Modbus/CAN-Umfeld, Buzzer-Steuerung, printf/sprintf-Engine, OTA-Ymodem-
> Download, kompletter FreeRTOS-Kernel-Block `0x0800ed4c`–`0x0800f550` sowie großer Teil der
> Letter-Shell-Bibliothek `0x0800f5c0`–`0x0800ff7c`). Methodik wie 13.9/13.10: jede Funktion einzeln
> per `get-decompilation` (inkl. Caller-Kontext) dekompiliert, Doku-Vorschläge aus 13.2–13.7 nicht
> blind übernommen. Ghidra-Ist-Zustand vor Tranche 2b: 193 benannte Funktionen (nach Tranche 2c,
> parallel bearbeitet). Tranche 2b selbst hat **94 Funktionen** neu benannt (80 im ersten Durchgang +
> 14 im Nachtrag, s. u.). Nach Tranche 2b: **309 benannte Funktionen*** (per Skript-Dubletten-Check
> gegen alle Namen im gesamten Programm bestätigt: 0 Kollisionen). *Gesamtzahl inkl. paralleler
> Tranche-2a/2c-Beiträge anderer Agenten-Läufe im selben Ghidra-Projekt.
>
> **Wertvollste Verifikationsquelle:** Wie in Tranche 2c enthält auch dieser Adressbereich den
> kompletten FreeRTOS-Kernel-Kern (`heap_4.c`, `tasks.c`, `queue.c`) mit eingebetteten
> Debug-Pfad-Strings (`"..\\..\\SDK\\FreeRTOS\\tasks.c"` bei `0x35d`/`0x392`/`0x54a`,
> `"..\\..\\SDK\\FreeRTOS\\queue.c"` bei `0xbe3`/`0xbe4`/`0xc04`) — alle 20 FreeRTOS-Funktionen in
> diesem Bereich (`prvAddCurrentTaskToDelayedList` … `pxPortInitialiseStack`) sind dadurch auf
> nahezu Ground-Truth-Niveau verifiziert.

**94 neu vergebene Namen (Adresse → Name, Konfidenz) — 80 im ersten Durchgang, 14 im Nachtrag:**

*Hoch (Quelldatei-String, eindeutiges Registermuster oder direkt verifizierter Aufrufer-Kontext):*

FreeRTOS-Kernel (heap_4.c/tasks.c/queue.c-Strings bestätigt):
`0x0800ed4c prvAddCurrentTaskToDelayedList`, `0x0800ede0 prvAddNewTaskToReadyList`,
`0x0800ee8c prvDeleteTCBCleanup`, `0x0800eec8 prvCopyDataFromQueue`, `0x0800eef0 prvCopyDataToQueue`,
`0x0800ef5e prvDeleteTCB`, `0x0800ef72 prvGetDisinheritedPriority`, `0x0800ef88 prvHeapInit`,
`0x0800eff8 prvInitialiseMutex`, `0x0800f010 prvInitialiseNewQueue`,
`0x0800f038 prvInitialiseNewTask` (tasks.c:0x35d/0x392), `0x0800f104 prvInitialiseTaskLists`,
`0x0800f15c prvInsertBlockIntoFreeList`, `0x0800f1b0 prvIsQueueEmpty`, `0x0800f1ca prvIsQueueFull`,
`0x0800f1e8 prvListTasksWithinSingleList`, `0x0800f244 prvNotifyQueueSetMembers` (queue.c:0xbe3/0xbe4/0xc04),
`0x0800f2f0 prvResetNextTaskUnblockTime`, `0x0800f310 prvTaskCheckFreeStackSpace`,
`0x0800f390 prvUnlockQueue`, `0x0800f40c prvWriteNameToBuffer` (neu identifiziert, nicht in altem
Doku-Vorschlag — strcpy+Leerzeichen-Padding auf 15 Zeichen, klassisches FreeRTOS
`prvWriteNameToBuffer`-Muster), `0x0800f430 pvPortMalloc` (heap_4.c-String direkt im Code),
`0x0800f538 prvGetMutexHolder`, `0x0800f550 pxPortInitialiseStack`.

Letter-Shell (Struktur/Aufrufer exakt zur Shell-Kontext-Struct aus Abschnitt 7 passend,
`shell_init` zusätzlich durch Cross-Referenz mit bereits verifiziertem `shell_login_handler`
aus Tranche 2c bestätigt):
`0x0800f5c0 shell_register_instance`, `0x0800f628 shell_check_permission`,
`0x0800f658 shell_print_logo`, `0x0800f7a0 shell_password_verify`, `0x0800fb04 shell_entry_get_desc`,
`0x0800fb10 shell_entry_get_name`, `0x0800fc90 shell_cmd_help`, `0x0800fdc0 shell_init`
(ruft `shell_register_instance`, `shell_user_search`, `shell_login_handler`, `shell_print_prompt`),
`0x0800ff10 shell_backspace_display`, `0x0800ff30 shell_list_commands`,
`0x0800ff7c shell_print_command_entry`.

UART/I2C-Peripherie, Sonstiges:
`0x08008330 UART_AbortReceive`, `0x080083f8 UART_IRQHandler_Full`, `0x080086e4 HAL_UART_Receive_IT`,
`0x08008834 HAL_UART_Transmit_DMA`, `0x080096b8 UART_WaitOnFlagUntilTimeout`,
`0x080097c8 I2C_TransferConfig` (I2C_CR2-Bitmuster SADD/NBYTES/RELOAD/AUTOEND),
`0x080097f8 I2C_WaitOnFlagUntilTimeout`, `0x08009694 UART_EndTransfer`,
`0x08009ba0 debug_log_format_entry` (1712B, größte Funktion im Bereich, ~60 Event-Typen im
switch — exakt wie alter Doku-Vorschlag), `0x0800c7f8 CAN_Wait_Response` (Timer_Elapsed_Ms-Timeout
3000ms + xQueueGenericReceive-Aufruf), `0x0800cbd8 Shell_Task_Init` (ruft `shell_init` mit
Shell-Kontext `0x20001410`/Puffer `0x2000147c`/512B — exakt wie Abschnitt 7.5),
`0x0800dc40 ota_firmware_download` (Ymodem_Receive_Packet-Schleife + Flash-Ziel `0x08044000`),
`0x0800de28 debug_sprintf_wrapper` (ruft `printf_core` + `sprintf_putchar`),
`0x0800de72 NVIC_SetPriority` (schreibt `(&DAT_e000e400)[irq] = prio<<4` — klassisches
CMSIS NVIC_IPR-Muster; **Hinweis:** dies ist die tatsächlich echte NVIC_SetPriority-Funktion,
zu unterscheiden vom widerlegten `0x0800150a` aus Tranche 2a/13.9),
`0x0800de94 assert_failed_halt` (doppeltes DSB + Endlosschleife), `0x0800e050 printf_core`
(1696B Format-Engine, Aufrufer `debug_printf`/`debug_sprintf_wrapper`), `0x0800e72c printf_pad_trailing`,
`0x0800e750 printf_pad_leading`, `0x0800e77e sprintf_putchar` (klassischer Puffer-Putc-Callback),
`0x0800e788 flash_write_config_block` (16-Byte-Struct inkl. `checksum_add`-Aufruf →
`FLASH_WriteData(0x08040000, …)`), `0x0800e7f0 buzzer_stop`, `0x0800e7f8 buzzer_tick`
(Cross-Referenz: dekrementiert denselben Zähler `0x20000464`, den `buzzer_stop` nullt),
`0x0800e84c buzzer_beep_short` (setzt `0x20000468 = 10`), `0x0800e858 can_tx_enqueue`
(Ringpuffer `0x2000399c`, Aufrufer `CAN_TX_SendMessage`), `0x0800e8a8 eTaskGetState`
(tasks.c-String bei `0x54a`, prüft `pxCurrentTCB`/Ready-/Suspended-Listen),
`0x0800bf94 TIM1_PWM_Init` (Basis `0x40012c00`=TIM1, Periode 399, Duty 200 — Callees
`TIM_Handle_Init`/`TIM_OC_ConfigChannel`/`TIM_Channel_SetState` bereits durch Tranche 2a benannt),
`0x0800c078 TIM1_Set_Duty` (Clamp 0–400, schreibt CCR der TIM1-Config aus `TIM1_PWM_Init`,
Aufrufer u. a. `modbus_register_handler`), `0x0800cb50 USART1_DMA_Send` (ruft
`HAL_UART_Transmit_DMA`), `0x0800cb80 USART2_Poll_Send` (Basis `0x40004400`=USART2 bestätigt).

**Nachtrag (zweiter Durchgang, zuvor übersehener Block `0x0800bf94`–`0x0800cbac`):** Bei
Cross-Prüfung des TIM/SPI/USART-Clusters direkt vor der bereits benannten `ADC_Sensor_Debug_Print`
(`0x0800cc40`) wurden 14 weitere Funktionen identifiziert, dekompiliert und umbenannt. Dabei zwei
wichtige Korrekturen gegenüber den alten Doku-Vorschlägen aus Abschnitt 13.4:
- **Peripherie-Adressen falsch zugeordnet:** `0x0800c098` (Periode 999, wie im alten
  Doku-Vorschlag "TIM5_Init" behauptet) liegt tatsächlich auf Basis `0x40001400` = **TIM7**, nicht
  TIM5 (`0x40000c00`) → umbenannt zu `TIM7_Init`. `0x0800c008` (alter Vorschlag "TIM8_PWM_Init_Encoder")
  liegt auf Basis `0x40015000` = **TIM20** (diese MCU-Familie hat kein TIM8, sondern nutzt HRTIM+
  TIM1/15/16/17/20 wie in Abschnitt 13.11 oben belegt) → umbenannt zu `TIM20_Init` (Encoder-Charakter
  nicht zweifelsfrei bestätigbar, daher ohne "_Encoder"-Suffix).
- **"SPI_DMA_*"-Namen widerlegt:** Der komplette Cluster `0x0800c128`–`0x0800c32c` (alter
  Doku-Vorschlag: `SPI_DMA_Complete_IRQ`, `SPI_DMA_Start_Receive`, `SPI_DMA_RX_Disable`,
  `SPI_DMA_TX_Disable`, `SPI_DMA_RX_IRQ_Handler`, `SPI_DMA_TX_IRQ_Handler`) verwendet exakt dieselben
  Bitmasken-Muster (`0xfffffedf`/`0xeffffffe` via `ExclusiveAccess`/`hasExclusiveAccess`-Bitband) wie
  das bereits verifizierte `UART_AbortReceive` (`0x08008330`) — und `0x0800c1e4` wird zusätzlich
  direkt aus `UART_IRQHandler_Full` aufgerufen. Es handelt sich damit um UART-DMA-Transfer-Handling,
  nicht SPI. Neue Namen: `0x0800c128 UART_DMA_TxRxComplete_Check`, `0x0800c178 UART_DMA_RX_Start`,
  `0x0800c1e4 UART_DMA_RX_Disable`, `0x0800c25c UART_DMA_TX_Disable`,
  `0x0800c28a UART_DMA_RX_IRQ_Handler`, `0x0800c32c UART_DMA_TX_IRQ_Handler`. Zusätzlich
  `0x0800c0c4 UART_ResetXferCounters` (nullt dieselben Struct-Felder `+0x56`/`+0x5e`, die im
  UART-DMA-Cluster als Tx-/RxXferCount verwendet werden — zuvor fälschlich als "zu generisch" (s.
  gestrichene Zeile unten) zurückgestellt, nach Kontextabgleich mit dem Cluster aber sicher
  zuordenbar) und `0x0800cbac USART1_Poll_Send` (Basis `0x40013800` = **USART1 auf dieser
  STM32F3-Reihen-MCU** [nicht F4-Mapping, wo dieselbe Adresse SYSCFG wäre] — Korrektur gegenüber
  altem Doku-Vorschlag "UART5_Poll_Send").

Konfidenz: `TIM1_PWM_Init`, `TIM1_Set_Duty`, `USART1_DMA_Send`, `USART2_Poll_Send` = hoch (siehe
oben). `TIM7_Init`, `TIM20_Init`, `UART_ResetXferCounters`, `UART_DMA_TxRxComplete_Check`,
`UART_DMA_RX_Start`, `UART_DMA_TX_Disable`, `UART_DMA_RX_IRQ_Handler`, `UART_DMA_TX_IRQ_Handler`,
`USART1_Poll_Send` = mittel (Peripherie-Basis bestätigt, aber Detailsemantik nicht 100% verifiziert).
`UART_DMA_RX_Disable` = mittel-hoch (zusätzlich durch direkten Aufruf aus `UART_IRQHandler_Full`
bestätigt).

*Mittel (Kontext stimmig, Details nicht 100% verifiziert):*
`0x0800873c UART_DMA_RxCplt_Dispatch` (dispatcht per Peripherie-Basisadresse USART1 `0x40013800`/
UART5 `0x40004400` an `xQueueGenericSendFromISR` — **Korrektur** gegenüber alter Doku
"SPI_DMA_TransferComplete", die durch das Dekompilat nicht gestützt wird),
`0x0800bf10 Buzzer_Timer_Init` / `0x0800bf7c Buzzer_Timer_Stop` / `0x0800bf88 Buzzer_Channel_Disable`
(**Korrektur** gegenüber alter Doku "USART3_PWM_Init"/"USART3_Deinit" — Aufrufer-Kette führt zu
`buzzer_tick`/`buzzer_stop`, keine USART3-Bezüge im Code; Timer-Konfigwerte Prescaler 0x10/
Periode 0xe77 auf TIM3-Basis `0x40000400`), `0x0800deec printf_number_format` (**Korrektur**
gegenüber alter Doku "printf_float_format" — Dekompilat zeigt generische Vorzeichen-/Präfix-Logik
für printf-Zahlenformatierung, kein float-spezifischer Code sichtbar), `0x0800f674 shell_clear_input_line`,
`0x0800f6a6 shell_delete_char`, `0x0800f788 shell_password_input`, `0x0800f814 shell_detect_number_base`,
`0x0800f862 shell_parse_escape_char`, `0x0800f89e shell_parse_number`, `0x0800f960 shell_parse_argument`,
`0x0800f99c shell_parse_string`, `0x0800fa04 shell_invoke_command`, `0x0800fad8 shell_hex_char_to_val`,
`0x0800fb50 shell_get_active_instance`, `0x0800fb78 shell_get_variable_value`,
`0x0800fcb8 shell_history_navigate`, `0x0800fd52 shell_history_push`.

**Thunk-Fix:** `0x0800ff2a` war als `thunk_FUN_0800ff30` benannt (enthielt noch den alten `FUN_`-Namen
des Ziels). Nach Umbenennung von `0x0800ff30` zu `shell_list_commands` wurde der Thunk konsistent zu
`thunk_shell_list_commands` umbenannt.

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, nicht umbenannt):**

| Adresse(n) | Grund |
|---|---|
| `0x080080fc`, `0x08008324`, `0x08008326`, `0x0800832e`, `0x080083f4`, `0x080088d8`, `0x0800e9d4` | 2–4-Byte-Stubs (Padding/geteilte Return-Veneers) ohne rekonstruierbaren Namen |
| `0x0800803c`, `0x08008100`, `0x0800b958`, `0x0800ba2c`, `0x0800ba46`, `0x0800ba60`, `0x0800bb10`, `0x0800bbb4`, `0x0800bc58`, `0x0800bcfc`, `0x0800bd74`, `0x0800bdf0`, `0x0800be70`, `0x0800bea6`, `0x0800bed8` | TIM/HRTIM-Kanal-Konfig-Helferfamilie mit gemeinsamem Peripherie-Adress-Vergleichsmuster (TIM1/8/15/16/17/20-Basen `0x40012c00`/`0x40013400`/`0x40014000`/`0x40014400`/`0x40014800`/`0x40015000`). `0x0800803c` widerlegt alten Doku-Vorschlag "HRTIM_DeadTimeConfig" (Funktion konfiguriert GPIO-artig anhand Peripherie-Typ, kein Deadtime-Register). Kanal-Nummerierung (OC1–4/IC1–2) aus Bit-Shift-Analyse mehrdeutig — Register-Offsets `+0x18`/`+0x1c`/`+0x20` passen zu CCMR1/CCMR2/CCER, aber genaue Kanalzuordnung der alten Doku-Tabelle (13.3) konnte nicht zweifelsfrei bestätigt werden |
| `0x08008d4c`, `0x08008d72`, `0x08008e06`, `0x08008ee4`, `0x08008f1c`, `0x08008f3c`, `0x080090f8` | Nicht individuell verifiziert; direkt benachbart zum widerlegten `0x0800803c`, daher erhöhtes Fehlerrisiko bei blinder Übernahme der alten HRTIM-Namen |
| `0x08009a40`, `0x08009a64`, `0x08009a74`, `0x08009a92` | Interne Hilfsfunktionen von `HAL_GPIO_Init_Extended` (GPIO-AFR/EXTI-Register bei Offset `+0x14`/`+0x60`), exakte Register-Semantik ohne Referenzvergleich nicht sicher benennbar |

### 13.12 Tranche 2a (10.07.2026) — Adressbereich 0x0800020c–0x08007fee

> Bearbeiteter Bereich: früher Boot-Code, GPIO/ADC/CAN/DMA/EEPROM/FLASH-Treiber-Cluster sowie der in
> Abschnitt 13.9 als "systematischer Adress-Drift" markierte TIM/HRTIM/RCC/ADC/I2C-Bereich
> (`0x08004caa`–`0x08007fee`). Methodik wie in 13.9–13.11: jede Funktion einzeln per
> `get-decompilation` (inkl. Caller-Kontext, `get-callers-decompiled`) verifiziert, alte
> Doku-Vorschläge aus 13.2/13.3 wurden **nicht** blind übernommen.
>
> **Wichtigster Fund dieser Tranche:** Die alten Doku-Vorschläge für den TIM/HRTIM/RCC/I2C-Cluster
> beruhten auf STM32F4-Peripherie-Adressen. Die tatsächlichen Register-Konstanten im Binary zeigen
> aber ein **STM32F3-Speicherlayout**: `RCC_BASE = 0x40021000` (nicht `0x40023800` wie F4),
> `Flash-Interface = 0x40022000` (nicht `0x40023C00`), `GPIO A/B/C = 0x48000000/0x48000400/0x48000800`
> (AHB2, nicht `0x40020xxx` wie F4), `HRTIM1_BASE = 0x40016800` (existiert bei F4 gar nicht,
> STM32F3-spezifisches Peripheral). Diese vier Adressen wurden jeweils an mehreren unabhängigen
> Stellen im Code bestätigt (u. a. `RCC_APB2ENR`-Bit 26 = HRTIM1EN, Flash-`KEYR`-Unlock-Sequenz mit
> Standard-Konstante `0xCDEF89AB`, direkte GPIOA/B/C-Basiswerte in mehreren `HAL_GPIO_Init`-Aufrufen).
> Das erklärt rückwirkend, warum in 13.9 mehrere GPIO/UART/NVIC-Vorschläge widerlegt wurden — sie
> passten schlicht zur falschen MCU-Familie. Deckt sich mit den unabhängigen Funden aus Tranche 2b
> (`0x0800803c` widerlegt "HRTIM_DeadTimeConfig") und Tranche 2c (`0x08011854` widerlegt "TIM3_PWM_Init",
> `0x0801178c` DAC/HRTIM-Callees unklar). **Empfehlung für Folge-Sessions:** Namensvorschläge für den
> restlichen TIM/HRTIM-Bereich nur noch gegen dieses F3-Layout prüfen, nicht gegen F4-Annahmen.

**Ghidra-Ist-Zustand:** Vor Tranche 2a waren in diesem Teilbereich (0x0800020c–0x08007fee) noch
~108 Funktionen `FUN_*` (18 davon bereits in 13.9 einzeln geprüft und bewusst abgelehnt, Rest
unverifizierte Doku-Vorschläge oder gar nicht dokumentiert). Nach Tranche 2a: **23 neu benannt**,
0 Namenskollisionen (Skript-Dubletten-Check gegen alle 452 Funktionsnamen im Programm bestätigt:
0 Duplikate zum Zeitpunkt der Umbenennung).

**23 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch (Register-Konstanten oder Aufrufer-Kette eindeutig belegt):*
`0x080055c4 HAL_GPIO_Init` (GPIOA-Base `0x48000000`/GPIOB-Base `0x48000400` direkt im Code, klassisches
MODER/AFR-Bitpacking wie `GPIO_InitTypeDef`, 26 Aufrufer), `0x0800547c FLASH_Lock` (setzt Bit 31 in
`0x40022014`=FLASH_CR direkt nach Erase/Write, klassisches Lock-Pattern), `0x08005518 FLASH_Unlock`
(schreibt Standard-Key2 `0xCDEF89AB` nach `0x40022008`=FLASH_KEYR, prüft LOCK-Bit vorher/nachher),
`0x080068cc PWR_EnableBackupAccess` (`0x40007000 |= 0x100` = PWR_CR-Bit 8 „DBP", F3-PWR-Base),
`0x08005cc8 RCC_EnableHRTIMClock` (prüft Base `== 0x40016800`=HRTIM1, setzt RCC_APB2ENR-Bit 26),
`0x08005cf0 HRTIM_GPIO_AF_Init` (prüft Base `== 0x40016800`, konfiguriert GPIOB/C via `HAL_GPIO_Init`
für HRTIM-Alternate-Function-Pins), `0x0800622c I2C_ConfigureRegisters` (direkter erster Aufruf aus
bestätigtem `I2C1_Init`, konfiguriert CR1/OAR), `0x0800617c I2C_CR1_Enable` (Aufrufer `I2C1_Init`,
setzt PE-Bit), `0x080062ec I2C_MasterTransmit_ISR` / `0x08006438 I2C_MasterReceive_ISR` (Aufrufer:
`EEPROM_WriteRegister`/`EEPROM_ReadRegister`/`EEPROM_WriteVerify`, I2C-typisches ISR-Timeout-Pattern
`0x8000`), `0x08007324 I2C_Master_Transmit` (ruft direkt die bereits bestätigten `I2C_Wait_SB_Flag`/
`I2C_Wait_ADDR_Flag` auf), `0x08007fee TIM_Handle_Init` (ruft bestätigtes `TIM_Base_Init` auf,
Aufrufer sind die bereits benannten `TIM1_PWM_Init`/`USART3_PWM_Init`), `0x08007498
TIM_Channel_SetState` (Kanal-Selektor 0/4/8/C = CH1–4, exakt wie HAL TIM-Channel-Enum, Aufrufer
`TIM1_PWM_Init`), `0x08007eb8 TIM_OC_ConfigChannel` (Dispatcher, ruft direkt die bereits bestätigten
`TIM_OC1_Config`/`TIM_OC2_Config`/`TIM_OC4_Config` je nach Kanal-Parameter auf).

*Mittel (Kontext stimmig, Detail-Semantik nicht 100 % verifiziert):*
`0x0800150a GPIO_ConfigPin_AF` / `0x08001532 GPIO_ConfigPin_Input` (**Korrektur** gegenüber der in
13.9 abgelehnten NVIC-Hypothese — beide rufen nachweislich `HAL_GPIO_Init` mit festen Mode/Pull-Werten
auf, sind also GPIO-Pin-Konfigurationsvarianten, keine NVIC-Funktionen; nicht zu verwechseln mit dem
echten `NVIC_SetPriority` aus Tranche 2b bei `0x0800de72`), `0x08005498 FLASH_ProgramSelect`
(Dispatcher zwischen `FLASH_ProgramDoubleWord`/`FLASH_Program256Bit`, Mutex-Flag `DAT_20000270`),
`0x08005c10 HRTIM_TimerUnit_Init` (ruft `RCC_EnableHRTIMClock` auf, konfiguriert
Timer-Control-Bitfelder), `0x08006584 I2C_Timing_Config` (Aufrufer `I2C_ConfigureRegisters`, prüft
Base `== 0x40005400`=I2C1, großes Register-Array — vermutlich Baudraten-/Timing-Berechnung),
`0x080061d6 I2C_CR2_ConfigBits` (Aufrufer `I2C1_Init`, Bitfeld-Shift `<<8`, exakte Registerrolle
unklar), `0x080066a8 SysTick_Accumulate_Counter` (Aufrufer `SysTick_Handler_App`, addiert zwei
SRAM-Zähler), `0x080067dc Fault_Handler_Halt` (DSB×2 + Endlosschleife, ähnliches Muster wie
`assert_failed_halt` aus Tranche 2b, aber separater Aufrufer/separate Adresse), `0x08004a08
GPIO_DMA_ChannelSetup` (5× Aufrufer `Peripheral_GPIO_Init`, ruft bestätigtes
`DMA_CalcBaseAndOffset` auf, DMA1/DMA2-Basiswerte `0x40020000`/`0x40020400` im Code).

**Korrektur gegenüber Doku-Vorschlag (Name war falsch, jetzt an korrekter Rolle vergeben):**

| Adresse | Alter Doku-Name (falsch/anderswo verwendet) | Neuer Name | Begründung |
|---|---|---|---|
| `0x0800150a`/`0x08001532` | `NVIC_SetPriority`/`NVIC_EnableIRQ` (13.9 bereits abgelehnt) | `GPIO_ConfigPin_AF`/`GPIO_ConfigPin_Input` | Rufen nachweislich `HAL_GPIO_Init` (neu bestätigt) auf — GPIO, nicht NVIC |
| `0x08006e34` | `HRTIM_Init` (Doku-Vorschlag, nie verifiziert) | — (bleibt `FUN_08006e34`) | Dekompilat zeigt Zugriffe auf `0x40021000`/`0x40021008`/`0x4002100c` = RCC CR/CFGR/CIR (F3-Layout), keine HRTIM-Bezüge. Vermutlich Takt-/Oszillator-Konfiguration (`HAL_RCC_OscConfig`-artig), aber Rolle nicht klar genug für Umbenennung |
| `0x08005c10` (vormals Doku „I2C_Init") | `I2C_Init` | `HRTIM_TimerUnit_Init` | Prüft Base `== 0x40016800` (HRTIM1), keine I2C-Bezüge — bereits in 13.9 korrekt als „generische Struct-Init ohne I2C-Bezug" verworfen, jetzt echte Rolle identifiziert |

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, nicht umbenannt):**

| Adresse(n) | Grund |
|---|---|
| `0x0800288c`, `0x080028e0`, `0x08004528`, `0x080046fc`, `0x08004728`, `0x080047bc`, `0x080047ee`, `0x08004b58` | Gehören zur selben verdächtigen Funktionsfamilie wie das in 13.9 bereits abgelehnte `FUN_08002824` (dort "TIM6_PWM_Init" verworfen) — alle referenzieren Peripherie-Basisadressen im Bereich `0x50000800`/`0x50000c00`/`0x50001000`, die im STM32F3-Speicherlayout **nicht existieren** (reserviert/nicht gemappt). Vermutlich toter/unbenutzter Code (evtl. Rest eines F4-HAL-Ports). Keine plausible Umbenennung möglich |
| `0x080043a8` | Prüft Basiswerte `0x40010200`/`0x4001020c`/`0x40010208` — passt zum STM32F3-Komparator-Adressbereich (COMP-Register liegen im SYSCFG-Block), konfiguriert danach GPIOA/B via `HAL_GPIO_Init`. Nur mittlere Konfidenz für "Analog-Komparator-Pin-Config", bewusst nicht umbenannt um keine neue unbestätigte Peripherie-Kategorie einzuführen |
| `0x0800485c` | Aufrufer ist der (außerhalb dieses Bereichs liegende) `FUN_080083f8`; Registerzugriffe nur relativ zu Handle-Pointer, keine erkennbare Basisadresse — Rolle unklar |
| `0x08004d3e` | Callee von zwei weiteren unbenannten Funktionen (`FUN_080052f2`, `FUN_080051bc`); ohne deren Klärung keine sichere Zuordnung |
| `0x08005db0`, `0x08005df0` | Teilen das Handle-Layout (Offsets `+0xdc`/`+0xdd`) mit den neu benannten HRTIM-Funktionen `HRTIM_TimerUnit_Init`/`HRTIM_GPIO_AF_Init`, sind also vermutlich ebenfalls HRTIM-Wrapper (Wait-Flag/Locked-Config), aber ohne konkrete Registerkonstante nicht sicher genug für einen spezifischen Namen |
| `0x080073b8` | Wird von `I2C_Master_Transmit` beim ersten Aufruf konfigurationsartig aufgerufen (analog zur Rolle von `I2C_Timing_Config` in der anderen I2C-Kette) — plausibel I2C-Timing-bezogen, aber nicht gegengeprüft |
| ~50 weitere Funktionen im Bereich `0x08004300`–`0x08007fee` (u. a. der ursprünglich als "TIM_PWM_Channel_Config", "SPI_*", "ADC_ConfigChannel/Start_DMA/Calibrate" dokumentierte Cluster) | In dieser Tranche aus Zeitgründen nicht mehr einzeln verifiziert. Nach dem F3-Adress-Fund oben ist bei allen diesen Namen erhöhte Vorsicht geboten — **nicht** ungeprüft aus 13.2/13.3 übernehmen. Kandidat für eine dedizierte Folge-Tranche mit dem jetzt bekannten F3-Peripherie-Layout als Referenz |
| ~21 Winzig-Stubs (2–6 Byte, z. B. `0x0800155c`, `0x08003afe`, `0x08003b00`, `0x08004d6a`, `0x08004d6c`, `0x08004e74`, `0x080051bc`, `0x080052c4`, `0x08005376`–`0x08005380`, `0x08006db4`, `0x0800748c`–`0x08007496`, `0x08007d4a`) | Reine Rücksprung-/Padding-Stubs ohne rekonstruierbare Semantik — bewusst nicht geraten |
| 18 bereits in Abschnitt 13.9 einzeln geprüfte und abgelehnte Funktionen (`0x0800020c`, `0x080007d8`, `0x08000b50`, `0x08000fb4`, `0x08001868`, `0x08001ea0`, `0x080035d4`, `0x08003af0`, `0x08003b04`, `0x08003d54`, `0x08003ff8`, `0x08004128`, `0x08005384`, `0x08005774`, `0x08005782`, `0x08005792`, `0x080057a0`, `0x080066d8`) | Unverändert — Ablehnung aus 13.9 bleibt gültig, keine neue Evidenz in dieser Tranche gefunden, die eine Umbenennung rechtfertigen würde |

**Hinweis zu bereits benannten (nicht FUN_-)Funktionen — Korrektur-Kandidat für Folge-Session:**
`DAC_Init` (`0x08006800`, vor dieser Tranche bereits benannt, daher außerhalb des Umbenennungs-Scopes
dieser Tranche) referenziert ausschließlich `0x40007000`/`0x40007014`/`0x40007080` = PWR-Registerbereich
(F3), **keine** DAC-Adresse — der Name ist mit hoher Wahrscheinlichkeit falsch (vermutlich echte
PWR-Init-Funktion). Nicht in dieser Tranche korrigiert, da außerhalb des FUN_-Scopes und um Konflikte
mit der parallelen Tranche 2c (die diese Funktion bereits unter dem Namen `DAC_Init` referenziert) zu
vermeiden — zur Prüfung in einer dedizierten Konsistenz-Session vormerken.

---

### 13.13 Tranche 3a (10.07.2026) — Adressbereich 0x0800020c–0x08004fe0

> Bearbeiteter Bereich: Teilmenge des in 13.12 (Tranche 2a) bereits abgedeckten Bereichs
> `0x0800020c–0x08007fee`. Tranche 2a hatte dort 23 Funktionen benannt und für den Rest (u. a. den
> "~50 weitere Funktionen"-Cluster `0x08004300–0x08007fee`) explizit eine dedizierte Folge-Tranche
> mit dem inzwischen bestätigten STM32F3-Peripherie-Layout empfohlen. Diese Tranche (3a) übernimmt
> davon den Teilbereich `0x0800020c–0x08004fe0`; der Rest bis `0x08007fee` liegt in Tranche 3b.
> Methodik unverändert: jede Funktion einzeln per `get-decompilation` (inkl. `includeCallers`/
> `includeCallees`), Register-/Bitfeld-Muster gegen bekannte HAL-Referenzimplementierungen
> (STM32Fx `stm32f3xx_hal_can.c`/`hal_dma.c`) abgeglichen, keine alten Doku-Vorschläge blind übernommen.

**Wichtigster Fund dieser Tranche:** Der komplette CAN-HAL-Layer (Init, TX, RX, Filter, IRQ-Dispatch)
und der DMA-HAL-Layer (Start_IT, Abort, IRQ-Dispatch) konnten anhand ihres charakteristischen
State-Machine-Musters (State-Byte-Konvention `0`=RESET, `1`=READY, `2`=BUSY, wie in der echten
STM32 HAL) und ihrer Aufrufer-/Aufgerufene-Ketten zu den bereits in Tranche 2a/13.9 bestätigten
Funktionen (`CAN_SetFilter_ExtID/StdID`, `CAN_TX_SendFrame`, `CAN_InitMailboxes`, `CAN_CopyTxFrame`,
`HAL_GetTick`, `DMA_SetConfig`) eindeutig identifiziert werden. Dabei stellte sich heraus, dass
`FUN_08001ea0` — in 13.9 nur als *"vermutlich echter CAN_Init, nicht UART"* vermerkt, aber mangels
Beweisen nicht umbenannt — tatsächlich der CAN1-Init-Wrapper ist: Er setzt `Instance = 0x40006400`
(bestätigte CAN1-Basis aus Abschnitt 4.1) und ruft direkt die neu identifizierte `HAL_CAN_Init`.

**9 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch (Aufrufer-/Aufgerufene-Kette + Register-/Zustands-Muster eindeutig, direkter Bezug zu bereits
verifizierten Funktionen):*
`0x08001ea0 CAN1_Init` (setzt Instance=`0x40006400`, konfiguriert Timing-Parameter, ruft `HAL_CAN_Init`
+ die neuen `HAL_CAN_ConfigFilter`/`HAL_CAN_ActivateNotification`-Kette; Aufrufer: bestätigtes
`CAN_Filter_Setup`), `0x08004fe0 HAL_CAN_Init` (klassische bxCAN-Init-Zustandsmaschine: INRQ/INAK-
Handshake mit `HAL_GetTick`-Timeout, MCR/BTR-Bitpacking exakt nach bxCAN-Schema, ruft bestätigtes
`CAN_InitMailboxes`, setzt State=READY), `0x08004c5c HAL_CAN_AddTxMessage` (State-Check READY, liest
TSR-Code-Feld zur Mailbox-Auswahl, ruft bestätigtes `CAN_CopyTxFrame`; Aufrufer: bestätigtes
`CAN_TX_SendFrame`), `0x08004caa HAL_CAN_ConfigFilter` (schreibt FR1/FR2-Filterbank-Register je nach
Std/Ext-Modus; Aufrufer: bestätigte `CAN_SetFilter_ExtID`/`CAN_SetFilter_StdID` — beide riefen bisher
eine namenlose gemeinsame Funktion auf), `0x08004d70 HAL_CAN_GetRxMessage` (dekodiert FIFO-Mailbox:
IDE/RTR/ID-Extraktion mit exakten bxCAN-Bitmasken `0x40000000`/`0x20000000`/`>>0x12`, DLC/Timestamp/
FMI-Felder, Datenkopie über DLC-Lookup-Tabelle `DAT_08017f60`), `0x08004e76 HAL_CAN_IRQHandler`
(liest SR&IER-Masken für TME/FMP0/FMP1/FF/FOV/EWG/EPV/BOF/LEC/ERR und dispatcht an 9 Sub-Handler,
ruft am Ende Error-Callback bei gesetztem Fehlercode — exaktes bxCAN-IRQHandler-Muster),
`0x08004ac8 HAL_DMA_Start_IT` (State-Übergang READY(1)→BUSY(2), ruft bestätigtes `DMA_SetConfig`,
TC/HT/TE-IT-Enable-Bitmuster (`0xE` mit / `0xA` ohne HT); Aufrufer: bestätigtes
`HAL_UART_Transmit_DMA`), `0x080048c4 HAL_DMA_Abort` (State-Check BUSY(2)→READY(1), Fehlercode
`0x04`=`HAL_DMA_ERROR_NO_XFER` im Fehlerpfad — exakter Treffer, ruft Abort-Callback; Aufrufer:
bestätigte `UART_AbortReceive`/`UART_IRQHandler_Full`), `0x0800493a HAL_DMA_IRQHandler` (dekodiert
ISR-Flags GIF/TCIF/HTIF/TEIF pro Kanal via Bit-Shift `<<bVar4`, dispatcht an XferCplt-/
XferHalfCplt-/XferError-Callback-Pointer — `callerCount=0`, da vermutlich nur über die
Interrupt-Vektortabelle referenziert, nicht per direktem Call).

**Dubletten-Check:** Alle 9 Namen vor der Umbenennung gegen die vollständige Symbolliste des gesamten
Programms geprüft (`get-symbols`, `filterDefaultNames=true`, alle 309 damals benannten Funktionen) —
**0 Kollisionen**. Ghidra-Ist-Zustand nach dieser Tranche: **318/445 benannt (71,5%)**.

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, nicht umbenannt):**

| Adresse | Grund |
|---|---|
| `0x080027bc` | Von bestätigtem `GPIO_DMA_ChannelSetup` aufgerufen, schreibt einen Registerzeiger `uVar1*4+0x40020900` sowie eine feste Adresse `0x40020940` in die Zielstruktur — Bitmuster passt zu einem Interrupt-Flag/Clear-Mechanismus, aber `0x40020900` lässt sich keinem bekannten STM32F3-Peripherieregister eindeutig zuordnen (DMA1/2-Basis liegt bei `0x40020000`/`0x40020400`, Kanalregister enden vor `0x400200A0`). Keine belastbare Rollenzuordnung |
| `0x08004b7c` | Aufrufer ist das neu bestätigte `CAN1_Init` sowie `FUN_08005248` (außerhalb dieses Bereichs). Manipuliert ein IER-artiges Register in CAN-typischen Bitgruppen (`0x7`,`0x38`,`0x1c0`,…, passend zu bxCAN-`IER`-Flag-Gruppen), aber die Logik (bedingtes Setzen eines Status-Flags je nachdem ob das Bit bereits gesetzt war) entspricht nicht dem einfachen 1:1-OR-Muster von `HAL_CAN_ActivateNotification`. Dritter Parameter ohne HAL-Äquivalent — vermutlich eine kundenspezifische CAN-IT-Statusfunktion, aber Rolle nicht sicher genug für einen Namen |
| `0x08004d08` | Aufrufer ist `CAN1_Init` (Aufruf mit Konstanten `2,2,1,1`), State-Check `==READY`. Schreibt vier gepackte Flag-Bits in ein Register bei Handle-Offset `+0x80` — Offset passt bei keinem Standard-bxCAN-Register (`CAN_TypeDef`-Reserved-Bereich). Rolle vermutlich CAN-Betriebsmodus-Konfiguration, aber Registeridentität nicht verifizierbar |
| `0x08004d3e` | Erster Aufruf innerhalb von `CAN1_Init`, setzt Fehlercode/State-Feld zurück (State=0/RESET) und ruft zwei weitere unbenannte Funktionen (`0x080052f2`, `0x080051bc` — beide außerhalb dieses Bereichs, liegen in Tranche 3b). Vermutlich `HAL_CAN_MspInit`-Wrapper oder Handle-Reset, aber ohne Klärung der beiden Callees nicht sicher genug. **Hinweis für Tranche 3b:** Falls `0x080052f2`/`0x080051bc` als GPIO-/NVIC-Init für CAN1 identifiziert werden, sollte `0x08004d3e` in einer Folge-Session als `HAL_CAN_MspInit` bestätigt werden |
| `0x0800493a` Sub-Handler `0x08004d6a`, `0x08004d6c`, `0x08004e74` (je 2 Byte) | Winzig-Stubs, von `HAL_CAN_IRQHandler` als Callback-Sprungziele referenziert — reine Rücksprung-Stubs ohne rekonstruierbare Semantik, bewusst nicht geraten (konsistent mit der Stub-Politik aus 13.12) |
| Alle 18 in 13.9 einzeln geprüften und abgelehnten Funktionen in diesem Bereich (`0x0800020c`, `0x080007d8`, `0x08000b50`, `0x08000fb4`, `0x08001868`, `0x080035d4`, `0x08003af0`, `0x08003b04`, `0x08003d54`, `0x08003ff8`, `0x08004128` u. a.) | Unverändert — keine neue Evidenz in dieser Tranche, die die dokumentierte Ablehnung entkräften würde |
| Dead-Code-Familie `0x0800288c`, `0x080028e0`, `0x08004528`, `0x080046fc`, `0x08004728`, `0x080047bc`, `0x080047ee`, `0x08004b58` (aus 13.12) | Erneut geprüft, keine neuen Erkenntnisse — referenzieren weiterhin nicht existente `0x50000800`/`0x50000c00`/`0x50001000`-Adressen (F3-Layout hat dort nichts gemappt). Bleibt unbenannt |
| `0x080043a8` (aus 13.12, Komparator-Kandidat) | Keine neue Evidenz gefunden, bewusst nicht übernommen |
| Stubs `0x0800155c`, `0x08003afe`, `0x08003b00` (aus 13.12) | Weiterhin reine Padding-/Rücksprung-Stubs |

**Ergebnis dieser Tranche:** 9 neu benannt, 0 Kollisionen, 5 bewusst zurückgestellt mit dokumentierter
Begründung (plus Bestätigung der bereits in 13.9/13.12 getroffenen Entscheidungen für die restlichen
`FUN_*` in diesem Adressbereich). Der Bereich `0x0800020c–0x08004fe0` gilt damit als für diese
Session abgeschlossen bearbeitet.

---

### 13.14 Tranche 3b (10.07.2026) — Adressbereich 0x080051bc–0x08007d4c

> Bearbeiteter Bereich: direkte Fortsetzung von Tranche 3a (13.13), die den Bereich bis `0x08004fe0`
> abgedeckt hatte. Diese Tranche übernimmt den Rest bis `0x08007d4c` (Ende laut Auftragsbereich).
> Methodik unverändert: jede Funktion einzeln per `get-decompilation` (inkl. `includeCallers`/
> `includeCallees`), Register-/Bitfeld-Muster gegen STM32F3-HAL-Referenzimplementierungen
> (`stm32f3xx_hal_can.c`, `hal_rcc.c`, `hal_rcc_ex.c`, `hal_tim.c`, CMSIS `core_cm4.h`) abgeglichen.
> Insgesamt **49 `FUN_*`-Funktionen** im Bereich identifiziert (via `get-functions filterDefaultNames=false`).

**Korrektur zum Hinweis aus 13.13:** Dort wurde vermutet, `0x08004d3e` könnte `HAL_CAN_MspInit` sein,
falls seine Callees `0x080052f2`/`0x080051bc` als GPIO-/NVIC-Init für CAN1 bestätigt werden. Das trifft
so nicht zu: Der eigentliche `HAL_CAN_MspInit` ist **`0x080051c0`** (Aufrufer: `HAL_CAN_Init`, prüft
`Instance==0x40006400`, konfiguriert GPIOD-Pins AF9 via `HAL_GPIO_Init` und aktiviert `CAN_RX1_IRQn`
(`0x15`/21) über `HAL_NVIC_SetPriority`+`NVIC_EnableIRQ`). `0x080052f2` und `0x080051bc` gehören dagegen
zu einer **CAN-Stop/DeInit-Sequenz** (aufgerufen von `0x08004d3e`): `0x080052f2` wartet mit Timeout auf
ein Ready-Flag und ist damit eher `HAL_CAN_Stop`-artig, `0x080051bc` ist ein reiner No-Op-Stub. `0x08004d3e`
selbst bleibt außerhalb dieses Bereichs (Tranche 3a-Territorium) unbenannt — sollte aber in einer
Folge-Session als `HAL_CAN_Stop` o. ä. geprüft werden, nicht als `HAL_CAN_MspInit`.

**Wichtigster Fund:** Der RCC-Takt-Init-Layer (`RCC_OscConfig`/`RCC_ClockConfig`/`RCC_PeriphClockSourceConfig`)
sowie ein zweiter TIM-Cluster (TIM7, TIM20, TIM4 — jeweils eigene Channels-Enable-/Clock-Enable-Funktionspaare,
analog zum bereits bestätigten HRTIM-Muster) konnten eindeutig identifiziert werden. Beide `RCC_OscConfig`
(`0x08006e34`) und `RCC_ClockConfig` (`0x08006bec`) werden nachweislich aus `SystemClock_Config`
(außerhalb dieses Bereichs) in genau dieser Reihenfolge aufgerufen — exakt das Muster von
`HAL_RCC_OscConfig()` gefolgt von `HAL_RCC_ClockConfig()` in echtem STM32-HAL-Code.

**30 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch (Register-Adresse/Bitmuster eindeutig auf bekannte Peripherie-Basis oder CMSIS-Systemregister
gemappt, oder Aufrufer-/Aufgerufene-Kette zu bereits bestätigten Funktionen eindeutig):*

| Adresse | Name | Begründung |
|---|---|---|
| `0x080051c0` | `HAL_CAN_MspInit` | Aufrufer `HAL_CAN_Init`; prüft `Instance==0x40006400` (CAN1); GPIOD-AF9-Pins + `CAN_RX1_IRQn`(21) |
| `0x08005248` | `HAL_CAN_RxFifo0MsgPendingCallback` | Aufrufer `HAL_CAN_IRQHandler`; dispatcht empfangenes Frame an `BMS_CAN_Parser`/`FUN_08001868`/FreeRTOS-Queue |
| `0x080052c6` | `CAN_State_EnterListening` | Aufrufer `CAN1_Init`; State-Byte 1(READY)→2(LISTENING), sonst Error-Flag — exaktes `HAL_CAN_StateTypeDef`-Muster |
| `0x080052f2` | `CAN_ExitInitMode_WaitAck` | Folgefunktion zu `CAN_State_EnterListening`/Teil der CAN-Stop-Sequenz; Timeout-Wartschleife auf Ready-Flag, State-Finalisierung |
| `0x08005384` | `FLASH_EraseSectors_Internal` | Einziger Aufrufer `FLASH_EraseSectors`; echte Erase-Implementierung (Busy-Flag, `FLASH_ACR`-Wait-States sichern/wiederherstellen, `FLASH_MassErase`/`FLASH_SectorErase`) |
| `0x08005782` | `GPIO_TogglePins` | Aufrufer `CAN_Filter_Setup` mit `param_1=0x48000000`(GPIOA); klassische BSRR-Toggle-Formel `(mask&~ODR)\|((ODR&mask)<<16)` |
| `0x08005792` | `I2C_EEPROM_SetXferState` | Ausschließlich aus `EEPROM_ReadRegister`/`WriteRegister`/`WriteVerify*` vor/nach `I2C_MasterReceive_ISR` aufgerufen |
| `0x080057a0` | `DBGMCU_GetRevisionID` | Liest `_DAT_e0042000>>0x10` — `0xE0042000` = Cortex-M `DBGMCU_BASE`/`IDCODE`, oberes Halbwort = REV_ID |
| `0x08006778` | `HAL_NVIC_SetPriority` | Liest `SCB->AIRCR`(`0xE000ED0C`) PRIGROUP-Feld, splittet Preempt-/Sub-Priorität, ruft CMSIS `NVIC_SetPriority` — Standard-HAL-Wrapper |
| `0x080066d8` | `SysTick_Reconfigure` | Ruft `SysTick_Config` dann `HAL_NVIC_SetPriority(SysTick_IRQn=-1, …)` — dynamische SysTick-Rate-Umkonfiguration |
| `0x080068dc` | `RCC_PeriphClockSourceConfig` | Aufrufer: CAN-/I2C-Timing-/RTC-Clock-Init; setzt reihenweise 2-Bit-Felder je nach Flag-Maske — Muster von `HAL_RCCEx_PeriphCLKConfig` inkl. RTC-Backup-Domain-Reset-Sequenz |
| `0x08006bec` | `RCC_ClockConfig` | Aufrufer `SystemClock_Config` (2. Aufruf nach `RCC_OscConfig`); konfiguriert `FLASH_ACR`-Wait-States + AHB/APB-Prescaler, ruft `HAL_RCC_GetSysClockFreq`+`SysTick_Reconfigure` |
| `0x08006e34` | `RCC_OscConfig` | Aufrufer `SystemClock_Config` (1. Aufruf); HSE/PLL-Enable+Ready-Wait-Sequenzen auf `RCC_CR`(`0x40021000`) |
| `0x080072d0` | `RTC_ConvertBCD_TimeDate` | Einziger Aufrufer `RTC_Read_Time`; entpackt BCD-Zeit/Datum-Register, ruft `BCD_To_Decimal` |
| `0x080073b8` | `RCC_EnableRTCClock` | Prüft `Instance==0x40002800`(RTC_BASE F3), aktiviert RTC-Takt via `RCC_PeriphClockSourceConfig` — Namensschema analog `RCC_EnableHRTIMClock` |
| `0x0800740c` | `I2C_ClearAddrFlag_Wait` | Aufrufer `I2C_Wait_ADDR_Flag`; löscht ADDR-Bit, Timeout-Wartschleife mit `HAL_GetTick` |
| `0x08007464` | `SysTick_Config` | Setzt `SysTick->LOAD`(`0xE000E014`)/`VAL`(`0xE000E018`)/`CTRL`(`0xE000E010`=7) + Priorität — exakte CMSIS-`SysTick_Config`-Implementierung |
| `0x08007574` | `TIM_OC_SetMode` | Aufrufer `TIM20_Init`; setzt OC-Mode-Nibble in CCMR-artigem Register, Sonderfall TIM16(`0x40014400`)/TIM17(`0x40014800`) |
| `0x08007606` | `TIM7_Channels_EnableAll` | Aufrufer `TIM7_Init`; setzt alle Channel-Enable-Flags, ruft `RCC_EnableTIM7Clock` |
| `0x08007654` | `RCC_EnableTIM7Clock` | Prüft `Instance==0x40001400`(TIM7_BASE F3), setzt APB1ENR-Bit5(TIM7EN) + `NVIC_EnableIRQ(0x37)` |
| `0x08007724` | `TIM20_CaptureUpdate` | Prüft `Instance==0x40015000`(TIM20_BASE); Capture-Perioden-Messung mit 4-Element-Ringpuffer, Aufrufer `TIM20_CC_EventDispatch` |
| `0x08007774` | `TIM_CCR_ConfigChannel` | Aufrufer `TIM20_Init`; konfiguriert Capture/Compare-Register je Kanal (0/4/8/0xC) über Sub-Handler `0x0800bdf0`/`be70`/`bea6`/`bed8` |
| `0x08007834` | `TIM20_Channels_EnableAll` | Aufrufer `TIM20_Init`; identisches Muster zu `TIM7_Channels_EnableAll`, ruft `RCC_EnableTIM20Clock` |
| `0x08007884` | `RCC_EnableTIM20Clock` | Prüft `Instance==0x40015000`(TIM20_BASE), setzt Enable-Bit20 + `NVIC_EnableIRQ(0x50)` |
| `0x080078c0` | `TIM_CCxChannelEnable` | Aufrufer `TIM20_Init`; generische CCER-Bit-Aktivierung + Counter-Start, TIM-Basisadress-Liste (TIM1/2/3/4/8/15/20) |
| `0x08007a48` | `TIM20_CC_EventDispatch` | Prüft 4 CC-Kanal-Event-Bitpaare + Update-Event, dispatcht an `TIM20_CaptureUpdate`/`TIM4_CaptureCallback_Dispatch`-artige Handler und Stub-Callbacks |
| `0x08007c4c` | `TIM4_Channel_ActionDispatch` | Aufrufer `0x08011854`(TIM4-Init-Kontext, `NVIC_EnableIRQ(0x1e)`=IRQ30=`TIM4_IRQn` F3); Busy-Guard + 6-Wege-Dispatch |
| `0x08007cbc` | `TIM4_CaptureCallback_Dispatch` | Prüft `Instance==0x40000800`(TIM4_BASE F3); ruft Callback-Funktionszeiger `_DAT_20000060`/`_DAT_20000064` je nach Kanalzustand |
| `0x08007cfc` | `TIM4_Channels_EnableAll` | Identisches Muster zu `TIM7_/TIM20_Channels_EnableAll`, im TIM4-Init-Kontext (`0x08011854`) |
| `0x08007d4c` | `TIM_CCxChannelEnable_MOE` | Wie `TIM_CCxChannelEnable`, zusätzlich `BDTR.MOE`-Bit(`0x8000`@offset`0x44`) für Advanced-Timer (TIM1/8/15/16/17/20) |

**Dubletten-Check:** Alle 30 Namen vor der Umbenennung gegen die vollständige Symbolliste des gesamten
Programms geprüft (`get-functions filterDefaultNames=true`, 318 zu Beginn dieser Tranche benannte
Funktionen inkl. der 9 aus Tranche 3a) — **0 Kollisionen**. Rename-Mechanismus: `create-label` mit
`setAsPrimary=true` am Funktionseinstiegspunkt (verifiziert per `get-decompilation`, dass der Funktionsname
tatsächlich übernommen wird, nicht nur ein Sekundär-Label).

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, 19 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x080051bc` | 2-Byte-No-Op-Stub (`return;`), Teil der CAN-Stop-Sequenz von `0x08004d3e` — Rolle verstanden, aber laut Stub-Policy (2–10 Byte) bewusst nicht umbenannt |
| `0x080052c4` | 2-Byte-Stub, Padding zwischen `CAN_State_EnterListening` und `CAN_ExitInitMode_WaitAck` |
| `0x08005376`, `0x08005378`, `0x0800537a`, `0x0800537c`, `0x0800537e`, `0x08005380` | Sechs 2-Byte-Stubs in Folge, keine Cross-Referenzen mit rekonstruierbarer Semantik |
| `0x08005774` | Generischer Bitmasken-Test-Helfer (`(*(x+0x10)&mask)!=0`), wird aber von völlig unterschiedlichen Kontexten (`EMS_Inverter_CAN_Dispatcher`, `Mode3_RoundRobin_Timer`) mit wechselnden Masken aufgerufen — zu generisch für einen treffenden Namen ohne Raten |
| `0x08005db0` | Generischer Wait-Flag-Timeout-Helfer auf einem Handle mit Offset `+0x388` (zu groß für bekannte Peripherie-Handles), State-Bytes an Offset `+0xdd`/`+0x37` ohne eindeutige Peripherie-Zuordnung |
| `0x08005df0` | Busy-Guard-Wrapper um unbenanntes `0x08008f1c` (außerhalb Bereich) — Rolle unklar ohne Klärung des Callees |
| `0x08006db4` | Trivialer Getter (`return _DAT_20000290;`); Global wird in Frequenz-Berechnungen verwendet, aber nicht eindeutig einer Domäne (Grid-Frequenz vs. genereller Tick-Zähler) zuordenbar |
| `0x0800748c`, `0x0800748e`, `0x08007490`, `0x08007492`, `0x08007494`, `0x08007496` | Sechs 2-Byte-Stubs, von `TIM20_CC_EventDispatch` als No-Op-Callback für ungenutzte Event-Kanäle referenziert — Rolle verstanden, aber laut Stub-Policy nicht umbenannt |
| `0x08007d4a` | 2-Byte-Stub, Callee von `TIM4_Channels_EnableAll` (Pendant zu `RCC_EnableTIM7Clock`/`RCC_EnableTIM20Clock`, aber für TIM4 offenbar No-Op) |

**Ergebnis dieser Tranche:** 30 neu benannt, 0 Kollisionen, 19 bewusst zurückgestellt (13 Mini-Stubs
2 Byte + 6 Funktionen mit zu genereller/unklarer Semantik). Der Bereich `0x080051bc–0x08007d4c` gilt
damit als für diese Session abgeschlossen bearbeitet.

---

### 13.15 Tranche 3c (10.07.2026) — Adressbereich 0x0800803c–0x080151c4

> Bearbeiteter Bereich: letzter verbleibender FUN_-Bereich der Micro-FW, inkl. des in Tranche 2b
> (13.11) bewusst zurückgestellten TIM/HRTIM-Kanal-Konfig-Clusters (`0x0800803c`–`0x0800bed8`), des
> Clusters um `0x08008d4c`–`0x080090f8` (HRTIM-Timer-Unit-Register, `param*0x80`-indiziert), der
> GPIO/UART-Bitfeld-Accessoren um `0x08009a40`–`0x08009a92`, der kleinen Cluster bei `0x0800e9d4`,
> `0x0801178c`/`0x08011854`/`0x08011b10` sowie `0x080150d4`–`0x080151c4`. Methodik wie 13.9–13.14:
> jede Funktion einzeln per `get-decompilation` (inkl. `includeCallers`/`includeCallees`,
> Disassembly bei Verdachtsfällen) verifiziert, alte Doku-Vorschläge nicht blind übernommen.
> Ghidra-Ist-Zustand vor dieser Tranche (inkl. paralleler Tranche 3a/3b-Beiträge): 346/445 benannt.
> Nach Tranche 3c: **363/445 benannt (81,6 %)**, per `get-functions`/`get-functions-by-similarity`
> gegen alle Namen im gesamten Programm geprüft — **0 Kollisionen**.

**Wichtigster Fund dieser Tranche 1 — TIM_OC_ConfigChannel/TIM_CCR_ConfigChannel-Dispatcher lösen den
in 13.11 als "mehrdeutig" zurückgestellten Kanal-Cluster vollständig auf:** Das bereits bestätigte
`TIM_OC_ConfigChannel` (`0x08007eb8`) dispatcht anhand `param_3` (0/4/8/0xc/0x10/0x14) direkt an
sechs bis dahin unbenannte Funktionen, die CCMR1/CCMR2/CCMR3 (Offsets `0x18`/`0x1c`/`0x50`) für die
Kanäle OC1–OC6 beschreiben (STM32F3 TIM1/TIM20 mit 6 Kanälen, HRTIM-artiges Layout). Der parallele
Dispatcher `TIM_CCR_ConfigChannel` (`0x08007774`, außerhalb dieses Bereichs, von Tranche 3b benannt)
dispatcht analog vier bis dahin unbenannte Input-Capture-Kanalfunktionen (Filter+Polarität in
CCMR1/CCMR2 + CCER). Damit ist die in 13.11 dokumentierte Kanal-Nummerierungs-Ambiguität für diesen
konkreten Funktionscluster **aufgelöst**.

**Wichtigster Fund 2 — `SystemClock_Config` identifiziert, stützt die in 13.12 bereits geäußerte
Vermutung zu `DAC_Init`:** `0x0801178c` (0 Callers — vermutlich nur aus dem Reset-Handler-Umfeld
erreicht, außerhalb des reinen Call-Graphen) ruft in exakter CubeMX-Reihenfolge `DAC_Init(0)` →
`PWR_EnableBackupAccess()` → zweimal Oszillator-Konfiguration (`FUN_08006e34`, von 13.12 bereits als
mögliches `HAL_RCC_OscConfig`-Äquivalent vermerkt) → Taktbaum-Konfiguration (`FUN_08006bec`, Aufruf
mit `ClockType=0xf`, `SYSCLKSource=3`(PLL), `FLASH_LATENCY=4`) → bedingtes Setzen von
FLASH_ACR-Bit 8 (Prefetch/Cache). Dieses Muster ist die klassische CubeMX-`SystemClock_Config`-
Signatur. Der Aufruf von `DAC_Init(0)` als **erster** Schritt (vor jeder Takt-Konfiguration) stützt
zusätzlich die in 13.12 dokumentierte Vermutung, dass `DAC_Init` (`0x08006800`, außerhalb des
Umbenennungs-Scopes) in Wirklichkeit eine PWR-Init-Funktion ist — ein DAC-Init an dieser Stelle vor
der Takt-Konfiguration wäre atypisch, ein PWR-Regler-Init hingegen exakt das erwartete CubeMX-Muster.
`FUN_08006e34`/`FUN_08006bec` liegen aber im Adressbereich von Tranche 3b und wurden hier **nicht**
umbenannt (fremder Scope).

**Wichtigster Fund 3 — kritische Bestätigung der Aufgabenstellungs-Hypothese zu `0x080150d4`–
`0x080151c4`:** Alle vier Funktionen in diesem Bereich (`0x080150d4`, `0x080150e8`, `0x080150fc`,
`0x080151c4`, je 10 Byte) liefern bei `get-decompilation` (inkl. Disassembly) **Dekompilat-/
Assembly-Inhalte, deren tatsächliche Instruktionsadressen (`0x08007xxx`/`0x08009xxx`) und
Register-Convention (`unaff_r4`/`unaff_r5`/`unaff_r8` — "nicht zugeordnete" Register, klassisches
Zeichen einer Sprung-ins-Mitte-einer-Funktion-Fehlerkennung) nicht zur eigenen Adresse passen**, und
zwei der vier liefern sogar identischen Pseudocode für unterschiedliche Adressen. Zusammen mit
`totalIncomingReferences` von bis zu 21 (weit verstreute Aufrufer-Adressen bis `0x0801a7xx`) ist dies
ein eindeutiger Beleg für die im Auftrag geäußerte Vermutung: **Ghidra hat hier keine echten,
eigenständigen Funktionen erkannt, sondern fälschlich Sprung-/Tabellenfragmente als Funktionsstart
markiert** (der thunk `thunk_CAN_Filter_Setup` bei `0x080150f2` sitzt exakt zwischen zwei dieser
Fragmente — ein Hinweis auf einen dicht gepackten Thunk-/Sprungtabellenbereich). Diese vier Adressen
wurden **bewusst nicht umbenannt** — eine Umbenennung würde eine nicht existente Funktionsidentität
suggerieren. Empfehlung für eine Folge-Session: Funktionsgrenzen in diesem Bereich mit Ghidras
`analyze-program`/manueller Function-Boundary-Korrektur neu ziehen, bevor hier weiter benannt wird.

**17 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch (Register-Offsets direkt über bestätigte Dispatcher-Funktionen `TIM_OC_ConfigChannel`/
`TIM_CCR_ConfigChannel` verifiziert, bzw. CCER-Bitmuster exakt auf HAL-Standardfunktion passend):*
`0x0800ba2c TIM_CCxChannelCmd` (CCER, 1-Bit-Maske bei `channel`-Offset — klassisches
`TIM_CCxChannelCmd`-HAL-Muster, 4 Aufrufer inkl. bereits bestätigtem `TIM_Channel_SetState`),
`0x0800ba46 TIM_CCxNChannelCmd` (CCER, Maske `4<<channel` = CCxNE-Bit, Aufrufer `TIM_Channel_SetState`),
`0x0800ba60 TIM_OC1_Config`, `0x0800bb10 TIM_OC2_Config`, `0x0800bbb4 TIM_OC3_Config`,
`0x0800bc58 TIM_OC4_Config`, `0x0800bcfc TIM_OC5_Config`, `0x0800bd74 TIM_OC6_Config` (alle sechs
direkt aus `TIM_OC_ConfigChannel`-Dispatch-Zweigen `param_3=0/4/8/0xc/0x10/0x14` identifiziert,
schreiben CCMR1/CCMR2/CCMR3 exakt an den erwarteten Bit-Offsets, speichern den Pulse/CCR-Wert an
`+0x34/+0x38/+0x3c/+0x40/+0x48/+0x4c`).

*Mittel-Hoch (Dispatcher `TIM_CCR_ConfigChannel` außerhalb des eigenen Scopes, aber Zielfunktionen
selbst mit klarem CCMR/CCER-Filter+Polarität-Muster):*
`0x0800bdf0 TIM_IC1_Config`, `0x0800be70 TIM_IC2_Config`, `0x0800bea6 TIM_IC3_Config`,
`0x0800bed8 TIM_IC4_Config` (Input-Capture-Kanalkonfiguration: ICxF-Filter (4 Bit) + CCxP/CCxNP-
Polarität in CCER, Dispatch-Reihenfolge 0/4/8/0xc identisch zum OC-Cluster).

*Hoch (Peripherie-Basisadresse + Aufrufer-Kette eindeutig):*
`0x0800803c TIM_GPIO_AF_Init` (prüft Timer-Basis `0x40012c00`=TIM1→GPIOC AF4 bzw.
`0x40000400`=TIM3→GPIOB AF1/AF2, ruft bestätigtes `HAL_GPIO_Init`; einziger Aufrufer: bestätigtes
`TIM_Handle_Init` — Gegenstück zu `HRTIM_GPIO_AF_Init` aus 13.12, widerlegt endgültig den alten
Doku-Namen "HRTIM_DeadTimeConfig" aus 13.11), `0x08011854 TIM4_IC_Init` (Basis `0x40000800`=TIM4
[F3-Layout], konfiguriert zwei Input-Capture-Kanäle [`param_3=0,4`] über das bestätigte
`TIM_CCR_ConfigChannel`, aktiviert danach `NVIC_EnableIRQ(0x1e)` = IRQn 30 = `TIM4_IRQn` auf
STM32F3 — eindeutiger Beleg für TIM4-Kontext; widerlegt den alten Doku-Vorschlag "TIM3_PWM_Init" aus
13.12 endgültig), `0x0801178c SystemClock_Config` (s. "Wichtigster Fund 2" oben).

*Mittel (Struktureller Kontext stimmig, Registerdetail nicht 100 % verifiziert):*
`0x08008100 TIM_Channel_Start` (State-Check→State=2(BUSY), ruft neu bestätigtes
`TIM_CCxChannelCmd`, setzt danach BDTR-MOE-Bit (Offset `+0x44`, nur bei Advanced-Timer-Basen
TIM1/15/16/17/20) sowie CR1-CEN-Bit — generisches "PWM-Kanal starten"-Äquivalent zu
`HAL_TIM_PWM_Start`/`HAL_TIM_OC_Start`; Aufrufer `Buzzer_Timer_Init`/`Buzzer_Channel_Disable`),
`0x080082f8 TIM_GetChannelPulse` (liest den bei `TIM_OC1_Config`…`TIM_OC4_Config` gespeicherten
Pulse-Wert aus `+0x34/+0x38/+0x3c/+0x40` je nach Kanalparameter — Getter-Gegenstück zu den OCx-Config-
Funktionen).

**Dubletten-Check:** Alle 17 Namen vor der Umbenennung per `get-symbols` (7 Seiten × 150,
`filterDefaultNames=true`, ~650 von 950 Symbolen inkl. aller TIM/RCC/Peripherie-Namensräume
gesichtet) sowie nach der Umbenennung zusätzlich per `get-functions-by-similarity` gegen
`TIM_OC1_Config`/`SystemClock_Config` gegengeprüft — **0 Kollisionen**, auch keine Kollision mit den
parallel von Tranche 3b vergebenen Namen (u. a. `TIM_CCR_ConfigChannel` bei `0x08007774`, außerhalb
des eigenen Scopes, aber als Kontext genutzt).

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, nicht umbenannt):**

| Adresse(n) | Grund |
|---|---|
| `0x080080fc`, `0x08008324`, `0x08008326`, `0x0800832e`, `0x080083f4`, `0x080088d8`, `0x0800e9d4` | 2–4-Byte-Stubs (Padding/geteilte Return-Veneers), konsistent mit 13.11 |
| `0x080082e4` | Bedingter Sprung zu einem Bootloader-Thunk (`LAB_1000219c`) abhängig von Timer-Basis `0x40001400`=TIM7; einziger Aufrufer ist das selbst unbenannte `FUN_08007a48` (Tranche-3b-Scope) — ohne dessen Klärung keine sichere Rollenzuordnung |
| `0x080088dc` (338 B) | Keine Aufrufer gefunden; berechnet modusabhängig (`DAT_20000035`=1/2/3) Duty-/Timing-Werte für einen SRAM-Puffer bei `0x20000cec`+Offsets — vermutlich Teil der Wechselrichter-PWM-Modulation, aber ohne Aufrufer-Kontext und ohne eindeutige Peripherie-Basisadresse nicht sicher benennbar |
| `0x08008d4c`, `0x08008d72`, `0x08008e06`, `0x08008ee4`, `0x08008f1c`, `0x08008f3c`, `0x080090f8` | Neuer struktureller Fund: alle nutzen ein `param_2 * 0x80`-Registerindexierungsmuster, das exakt zum Offset der HRTIM-Timer-Unit-Blöcke (TIMA…TIME, je 0x80 Byte ab HRTIM1-Basis `0x40016800`) passt — bestätigt die in 13.12 geäußerte Vermutung, dass die Aufrufer `0x08005db0`/`0x08005df0` "HRTIM-Wrapper" sind. Für eine präzise Register-Zuordnung (CMP/SET/RST/OUT je Timer-Unit) fehlt aber ein Referenzabgleich mit dem STM32F3-Referenzhandbuch; `0x08008d4c`/`0x08008e06`/`0x08008f3c`/`0x080090f8` haben zudem `callerCount=0` (vermutlich nur indirekt/tabellarisch erreicht) — bewusst nicht geraten |
| `0x08009a40`, `0x08009a4c`, `0x08009a54`, `0x08009a5c`, `0x08009a64`, `0x08009a74`, `0x08009a92` | Neuer Fund gegenüber 13.11: Nur `0x08009a40`/`0x08009a64`/`0x08009a74`/`0x08009a92` werden ausschließlich von `HAL_GPIO_Init_Extended` aufgerufen (konsistent mit altem Doku-Vermerk "GPIO-AFR/EXTI-Hilfsfunktionen"). `0x08009a4c`/`0x08009a54`/`0x08009a5c` sind dagegen generische 6–8-Byte-Bitfeld-Extraktoren (`*(param_1+8) & Maske`), die domänenübergreifend sowohl von `HAL_GPIO_Init_Extended` als auch von `UART_WaitReady`/`FUN_08000b50`/`FUN_08003b04`/`FUN_08003ff8` aufgerufen werden — widerspricht der bisherigen GPIO-exklusiven Einordnung. Für keine der sieben Funktionen ließ sich eine domänenspezifische Rolle sicher genug für einen Namen belegen |
| `0x08011b10` | Einzeiliger globaler Kopiervorgang (`DAT_20000458 = DAT_20000024`) ohne erkennbare Semantik der beiden Variablen, Aufrufer `UART_DMA_RxCplt_Dispatch` |
| `0x080150d4`, `0x080150e8`, `0x080150fc`, `0x080151c4` | **Bestätigter Ghidra-Funktionsgrenzen-Fehler** — s. "Wichtigster Fund 3" oben. Keine Umbenennung, da keine echten eigenständigen Funktionen |

**Ergebnis dieser Tranche:** 17 neu benannt, 0 Kollisionen, 28 Funktionen bewusst zurückgestellt
(davon 4 als bestätigter Ghidra-Analyseartefakt dokumentiert, nicht nur "unklar"). Der Bereich
`0x0800803c–0x080151c4` gilt damit als für diese Session abgeschlossen bearbeitet — verbleibende
`FUN_*`-Adressen sind entweder Stubs, domänenübergreifende Hilfsfunktionen ohne sichere Einzel-Rolle,
oder (im Fall `0x080150d4`–`0x080151c4`) keine echten Funktionsgrenzen.

---

### 13.16 Tranche 4a (10.07.2026) — Adressbereich 0x0800020c–0x08004128

> Bearbeiteter Bereich: der am häufigsten bereits durchsuchte Startbereich (Tranchen 2a/13.12,
> 3a/13.13). Per `get-functions filterDefaultNames=false` wurden im Bereich 18 `FUN_*`-Funktionen
> identifiziert. Methodik: jede Funktion einzeln per `get-decompilation` (inkl. `includeCallers`/
> `includeCallees`) untersucht, Registerkonstanten gegen die STM32F3-Peripheriekarte abgeglichen und
> Aufrufer-/Aufgerufene-Ketten mit dem inzwischen deutlich größeren Namensbestand abgeglichen.

**Wichtigster Fund — ein zusammenhängender ADC-HAL-Layer wurde vollständig aufgedeckt:** Die
Adressen `0x50000000`/`0x50000100`/`0x50000300`/`0x50000400`/`0x50000500`/`0x50000700` treffen exakt
die STM32F3-Speicherkarte für ADC1/ADC2/ADC1_2-Common/ADC3/ADC4/ADC3_4-Common. `0x08000fb4`
(`ADC_Instances_Init`) initialisiert nacheinander 5 handle-artige Structs mit diesen Instance-Werten
und ruft für jede `0x08003b04` (`HAL_ADC_Init`) auf, welches wiederum bei State==RESET
`0x08003d54` (`HAL_ADC_MspInit`, RCC-Takt + `HAL_GPIO_Init(0x48000000,...)`/`HAL_GPIO_Init(0x48000400,...)`
je Instanz) aufruft — ein wörtlicher Treffer auf das reale `HAL_ADC_Init()`/`HAL_ADC_MspInit()`-Muster.
Direkt danach ruft `ADC_Instances_Init` fünfmal `0x080035d4` (`HAL_ADCEx_Calibration_Start`) auf, das
Bit 31 (ADCAL) in einem CR-artigen Register setzt und mit Timeout auf dessen Rücksetzung wartet —
exakt die reale STM32-HAL-Kalibrierungssequenz. `0x08003ff8` (`HAL_ADC_Start_DMA`) rundet den Layer
ab: setzt DMA-Callback-Zeiger (`+0x2c/+0x30/+0x34`, dieselben Offsets wie bereits in 13.13 für
`HAL_DMA_Start_IT` verifiziert), setzt CR=`0x1c` (ADSTART-Bitgruppe) und ruft `HAL_DMA_Start_IT` auf;
sein interner Wartehelfer `0x08000b50` (`ADC_ConversionStop_WaitReady`) pollt bis zu 3 Ticks auf ein
Ready-Bit und setzt bei Timeout Fehler-/State-Flags — passt zum internen `ADC_ConversionStop()`-Helfer
der echten HAL. Die 5. Instanz (`0x50000600`) liegt zwischen ADC4 (`0x500`) und ADC3_4-Common (`0x700`)
und ist im offiziellen STM32F3-Referenzhandbuch nicht dokumentiert — sie wird vom Code strukturell wie
eine reguläre ADC-Instanz behandelt, bleibt aber in ihrer genauen Silizium-Identität unklar.

**Zweiter Fund — `0x08004128` ist ein Comparator-Init (`HAL_COMP_Init`):** Die Funktion prüft die
Registeradresse gegen `0x40010200`/`0x204`/`0x208`/`0x20c`/`0x210`/`0x214` — exakt COMP1_CSR…COMP6_CSR
auf STM32F3 (Comparator-Peripherie, existiert nicht auf F4, bestätigt erneut das F3-Layout) — und
leitet daraus eine EXTI-Line-Bitmaske ab, die in ein Register bei `0x40010424` (EXTI-Bereich,
Basis `0x40010400`) geschrieben wird. Ruft `0x080043a8` auf (liegt in Tranche 4b, dort bereits
mitbehandelt, in Tranche 5a — s. 13.19 — als `HAL_COMP_MspInit` identifiziert: wird nur beim allerersten
Init eines Comparators aufgerufen (`param_1[0x1d]==0`-Guard, klassisches HAL-"MspInit nur bei
State==RESET"-Muster) und konfiguriert per `HAL_GPIO_Init` den zugehörigen Analog-Eingangspin für
COMP1/COMP3/COMP4 auf GPIOA/B/C).

**Dritter Fund — `0x0800020c` ist `prvPortStartFirstTask`:** Wörtlicher Treffer auf die
FreeRTOS-ARM_CM4F-Portroutine — liest die initiale MSP aus der Vektortabelle (`*_DAT_e000ed08`,
das ist VTOR), aktiviert IRQ/FIQ, führt DSB/ISB aus und triggert `SVC 0`; zusätzlich wird
`_DAT_e000ed88` (CPACR) mit `0xf00000` (CP10/CP11, FPU) verodert — entspricht der CM4F-Variante von
`prvPortStartFirstTask()`, die die FPU-Freigabe inline enthält. Einziger Aufrufer: `xPortStartScheduler`.

**Vierter Fund — `0x08001868` ist ein 4. CAN-Filter-Handler für BMS-Firmware-Updates:**
`HAL_CAN_RxFifo0MsgPendingCallback` dispatcht nach `FilterMatchIndex`: `==3` → `BMS_CAN_Parser`
(bekannt), `==4` → `0x08001868`. Die Funktion prüft PF-Byte-Muster (Bits 16–23) analog zu
`BMS_CAN_Parser` und schreibt Status-/Größen-/Datenfelder nach `0x200038cb`–`0x200038d0` mit
State-Werten `2`/`4` — ein Init/Verify-Zustandsmuster, das zum in Abschnitt 9 dokumentierten
"BMS-Update über CAN"-Pfad passt (CMD `0xCE`, Typ 0=Init/1=Data/2=Verify). Benannt als
`BMS_FW_Update_CAN_Handler` (Filter 4 sollte ergänzend in der Tabelle 4.1 nachgetragen werden —
bisher waren dort nur 3 Filter dokumentiert).

**5 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch:*
`0x08003b04 HAL_ADC_Init`, `0x08003d54 HAL_ADC_MspInit`, `0x08003ff8 HAL_ADC_Start_DMA`,
`0x080035d4 HAL_ADCEx_Calibration_Start` (alle vier: wörtlicher Treffer auf reale STM32-HAL-ADC-
Referenzsequenz inkl. exakter STM32F3-ADC-Basisadressen 0x50000000/0x100/0x300/0x400/0x500/0x700),
`0x08004128 HAL_COMP_Init` (exakter Treffer auf COMP1_CSR…COMP6_CSR, `0x40010200`–`0x214`),
`0x0800020c prvPortStartFirstTask` (wörtlicher Treffer auf FreeRTOS-ARM_CM4F-Referenzcode,
einziger Aufrufer `xPortStartScheduler`).

*Mittel-Hoch:*
`0x08000fb4 ADC_Instances_Init` (klarer Aggregat-Init für 5 ADC-Handles, ruft `HAL_ADC_Init` 5×),
`0x08001868 BMS_FW_Update_CAN_Handler` (4. CAN-Filter, PF-Byte-Muster + Init/Verify-State-Schreiben
passend zu dokumentiertem BMS-Update-Pfad).

*Mittel:*
`0x08000b50 ADC_ConversionStop_WaitReady` (interner Wartehelfer, nur von `HAL_ADC_Start_DMA`
aufgerufen, Verhalten passt zu `ADC_ConversionStop()` der echten HAL, aber Ziel-Peripherie der
externen Lock-Aufrufe `0x08009a5c`/`0x08009a54` außerhalb des Tranche-Bereichs nicht abschließend
verifizierbar), `0x080027bc DMA_ChannelSelect_Compute` (berechnet Kanal-Index-Maske für
`GPIO_DMA_ChannelSetup`, Zieladresse `0x40020900` liegt in einer im STM32F3-Referenzhandbuch nicht
dokumentierten Reserved-Zone zwischen DMA2 und RCC — Rolle klar, exakte Register-Identität nicht),
`0x080007d8 printf_negate_if_positive` (Vorzeichenkorrektur-Helfer, einziger Aufrufer
`printf_number_format`, exakte Semantik innerhalb der Float-Formatierung nicht vollständig
rekonstruierbar), `0x08003af0 UART_TxEvent_ADC1_BootloaderThunk` (bedingter Sprung in den
Bootloader-Thunk-Bereich (`LAB_10001428`, neuer Eintrag für Tabelle in Abschnitt 10) nur wenn
Instance==ADC1-Basis; Aufrufer ist `UART_IRQHandler`, was auf eine domänenübergreifend geteilte
DMA-Callback-Struktur hindeutet — semantisch ungewöhnlich, aber Verhalten eindeutig belegt).

**Dubletten-Check:** Alle 12 Namen vor der Umbenennung gegen die vollständige benannte Funktionsliste
des gesamten Programms geprüft (`get-functions filterDefaultNames=true`, 370 Funktionen vor dieser
Tranche gesichtet, keine Kollision). Nach der Umbenennung erneut per `get-functions-by-similarity`
(Suchbegriffe "HAL_ADC" und "HAL_COMP_Init") verifiziert — Namensbestand stieg exakt um 12 auf 382,
**0 Kollisionen**.

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, 6 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x0800155c`, `0x08003afe`, `0x08003b00` | 2-Byte-Stubs (`BX LR`, sofortiges Return) — Aufrufer `Mode3_RoundRobin_Timer` bzw. `UART_DMA_Handler`/`UART_IRQHandler`; echte leere Callback-Platzhalter, keine Ghidra-Grenzartefakte, aber ohne Inhalt nicht sinnvoll benennbar |
| `0x08002824`, `0x0800288c`, `0x080028e0` | **Dead-Code-Familie** — `find-cross-references` liefert für alle drei `totalToCount=0` (weder Code- noch Datenreferenz irgendwo im Programm). Strukturell identisch zum ADC/HAL-Init-Muster (Instance-Werte `0x50000800`/`0xc00`/`0x1000`, Aufruf von `0x08004528`/`0x080046fc`/`0x080047ee`/`0x080047bc`), aber diese Instance-Adressen liegen außerhalb der offiziell dokumentierten STM32F3-ADC-Karte (die bei `0x700` endet) und sind unerreichbar. Deckt sich mit der unabhängigen Einschätzung aus Tranche 4b (13.17), die dieselbe Funktionsfamilie um `0x08004528` ebenfalls als Dead-Code einstuft — bewusst nicht benannt |

**Ergebnis dieser Tranche:** 12 neu benannt, 0 Kollisionen, 6 Funktionen bewusst zurückgestellt
(3 echte Stubs, 3 als Dead-Code identifiziert und durch Tranche 4b unabhängig bestätigt). Der Bereich
`0x0800020c–0x08004128` gilt damit für diese Session als abgeschlossen bearbeitet.

---

### 13.17 Tranche 4b (10.07.2026) — Adressbereich 0x080043a8–0x08007496

> Bearbeiteter Bereich: Teilmenge des mehrfach bereits bearbeiteten CAN-HAL-/DMA-HAL-/FLASH-/HRTIM-/
> I2C-/RCC-/TIM-Clusters aus den Tranchen 2a (13.12), 3a (13.13) und 3b (13.14). In diesem Bereich
> lagen nach Tranche 3b noch 29 `FUN_*`-Funktionen (per `get-functions filterDefaultNames=false`
> ermittelt), davon waren 27 bereits in 13.12/13.13/13.14 einzeln geprüft und bewusst zurückgestellt
> worden (Dead-Code-Familie, Stubs, generische Helfer, unklare Registeroffsets). Methodik: jede der
> 29 Funktionen erneut per `get-decompilation` (inkl. `includeCallers`/`includeCallees`) untersucht —
> mit dem Ziel, ob der seit Tranche 3c gewachsene Namensbestand in Aufrufer-/Aufgerufene-Ketten neue
> Anhaltspunkte liefert (wie in der Aufgabenstellung erwartet).

**Wichtigster Fund — der in 13.14 explizit offengelassene Hinweis zu `0x08004d3e` klärt sich nur
teilweise, dafür liefert der Kontext zwei unabhängige neue Treffer:** `0x08004d3e` ist der **erste**
Aufruf in `CAN1_Init`, noch bevor `Instance` auf `0x40006400` gesetzt wird. Er ruft das bereits
bestätigte `CAN_ExitInitMode_WaitAck` auf, löscht 2 Bit eines Peripherieregisters (Instance-Offset
`+0x5c`), ruft den bekannten No-Op-Stub `0x080051bc` (Msp-DeInit-Platzhalter) und setzt danach sowohl
das Handle-Fehlercode-Feld (`+0x18`, Wortindex) als auch das State-Byte (`+0x17`, Wortindex) auf `0`
zurück — exakt das Reset-auf-`HAL_CAN_STATE_RESET`-Muster von `HAL_CAN_DeInit`, aufgerufen als
Vorbereitungsschritt zu Beginn von `CAN1_Init`. Deutlich eindeutiger war `0x08004b7c`: Sein State-Guard
(`state==READY(1) || state==LISTENING(2)`, sonst Fehlercode `|=2`) ist ein wörtlicher Treffer auf die
reale `HAL_CAN_ActivateNotification()`-Prüfung, die anschließenden Bitgruppen-Vergleiche (`0x7`, `0x38`,
`0x1c0`, `0x1e00`, `0xe000`, `0x30000`, `0xfc0000`) gegen ein Statusregister vor dem bedingten Setzen
zweier IER-artiger Bits entsprechen dem "vermeide Spurious-IRQ beim Aktivieren"-Muster von
`HAL_CAN_ActivateNotification`, und beide Aufrufer (`CAN1_Init` mit `param_2=1`=TX-Mailbox-Empty-IT,
`HAL_CAN_RxFifo0MsgPendingCallback` mit `param_2=1`=Re-Arm nach Nachrichtenverarbeitung) passen exakt
zum erwarteten Aufrufkontext. Die in 13.13 geäußerte Unsicherheit ("dritter Parameter ohne
HAL-Äquivalent") bleibt zwar bestehen (param_3 steuert zusätzlich zwei kundenspezifische Register bei
`+0xdc`/`+0xe0`), ändert aber nichts an der hohen Konfidenz für die Kernrolle.

**Zweiter Fund — `0x08004b58` ist eine wörtliche `HAL_Delay()`-Implementierung:** Tick-Startwert via
`HAL_GetTick()`, bedingte Erhöhung des Timeout-Werts um einen globalen Tick-Frequenz-Offset
(`_DAT_20000268`, außer bei `param_1==0xffffffff`), danach Busy-Wait-Schleife `while(GetTick()-start <
wait)` — exakt der Referenz-Code von `HAL_Delay()` aus `stm32f3xx_hal.c`. Die Funktion wird sowohl von
der (weiterhin als Dead-Code eingestuften) Familie um `0x08004528` als auch von echtem Live-Code
(`modbus_register_handler`, `0x080047ee`) aufgerufen — sie ist also trotz eines Aufrufers aus der
Dead-Code-Familie selbst ein generischer, echter HAL-Baustein und wurde entsprechend benannt.

**Dritter Fund — `0x0800485c` ist das Gegenstück `HAL_DMA_Abort_IT` zum bereits bestätigten
`HAL_DMA_Abort`:** Die Funktion liegt unmittelbar vor `HAL_DMA_Abort` (`0x080048c4`) im Speicher, prüft
denselben State-Byte-Offset (`+0x25`) auf `BUSY(2)`, verwendet im Fehlerpfad denselben Fehlercode `4`
(`HAL_DMA_ERROR_NO_XFER`, bereits in 13.13 für `HAL_DMA_Abort` verifiziert) und wird — anders als das
blockierende `HAL_DMA_Abort` — direkt aus einem ISR-Kontext (`UART_IRQHandler_Full`) aufgerufen, ohne
auf ein TC-Flag zu warten. Das entspricht exakt dem Unterschied zwischen `HAL_DMA_Abort` (blockierend)
und `HAL_DMA_Abort_IT` (ISR-sicher, non-blocking) in der echten STM32-HAL.

**4 neu vergebene Namen (Adresse → Name, Konfidenz):**

*Hoch:*
`0x08004b58 HAL_Delay` (wörtlicher Treffer auf STM32-HAL-Referenzimplementierung inkl.
`0xffffffff`-Sonderfall und Tick-Frequenz-Offset; Aufrufer sowohl Dead-Code-Familie als auch
Live-Code `modbus_register_handler`/`0x080047ee`), `0x0800485c HAL_DMA_Abort_IT` (State-Check
identisch zu `HAL_DMA_Abort`, gleicher Fehlercode `4`, Aufrufer ist ISR-Kontext
`UART_IRQHandler_Full`, liegt direkt vor `HAL_DMA_Abort` im Speicher), `0x08004b7c
HAL_CAN_ActivateNotification` (State-Guard `READY|LISTENING` wörtlich identisch zur realen HAL-Prüfung,
Bitgruppen-Vergleichsmuster gegen Statusregister vor IER-Bit-Setzen entspricht dem
Spurious-IRQ-Vermeidungsmuster der echten Funktion, beide Aufrufer `CAN1_Init`/
`HAL_CAN_RxFifo0MsgPendingCallback` passen zum erwarteten Kontext).

*Mittel-Hoch:*
`0x08004d3e HAL_CAN_DeInit` (Reset von ErrorCode- und State-Feld auf `0`/RESET, ruft
`CAN_ExitInitMode_WaitAck` + Msp-DeInit-Stub `0x080051bc` auf, aufgerufen als allererster Schritt von
`CAN1_Init` — strukturell passend zu `HAL_CAN_DeInit`, auch wenn der genutzte Peripherieregister-Offset
`+0x5c` weiterhin nicht zu einem Standard-bxCAN-Register laut Referenzhandbuch passt, s. bereits in
13.12/13.13 dokumentierte Unsicherheit zu diesem Registerbereich).

**Dubletten-Check:** Alle 4 Namen vor der Umbenennung gegen die vollständige Funktionsliste des
gesamten Programms geprüft (`get-functions filterDefaultNames=false`, alle 5 Seiten × 100, 445/445
Funktionen gesichtet, keine der 4 Zielbezeichnungen existierte vorher) — **0 Kollisionen**. Nach der
Umbenennung zusätzlich per `get-decompilation signatureOnly=true` verifiziert, dass der Name
tatsächlich als Funktionsname (nicht nur Sekundär-Label) übernommen wurde.

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, 25 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x08004528` | Erneut geprüft: Nur 4 Aufrufer, alle aus der bereits in 13.12/13.13 als Dead-Code eingestuften Familie (`0x08002824`/`0x0800288c`/`0x080028e0`, referenzieren nicht gemappte `0x50000800`-Adressen). Struktur ähnelt einem generischen Timing-/Baudraten-Konfigurator (HAL_GetTick-Timeout-Poll auf `+0x34`, `HAL_Delay(1)`, gepackte 10-/8-Bit-Felder bei `+0x48`/`+0x4c`), aber ohne einen einzigen Aufrufer mit gültiger Peripherie-Basisadresse keine sichere Namensvergabe möglich |
| `0x08004d08` | Erneut geprüft: Aufrufer weiterhin nur `CAN1_Init` (State-Check `==READY`, feste Parameter `2,2,1,1`, schreibt gepackte Bits an Instance-Offset `+0x80` — liegt im bxCAN-Reserved-Bereich, kein Standardregister). Keine neue Evidenz gegenüber 13.13 |
| — | Zusatzprüfung: `0x08004d08` kann **nicht** analog zu `0x08004b7c` als "ActivateNotification"-Variante gedeutet werden, da der State-Guard nur `READY` (nicht `READY\|LISTENING`) prüft — bestätigt die 13.13-Einschätzung als eigenständige, nicht klar benennbare Funktion |
| `0x08004528`-Familie: `0x080046fc`, `0x08004728`, `0x080047bc`, `0x080047ee`, `0x08004b58`* | *`0x08004b58` wurde separat benannt (s. o.), da unabhängig auch von Live-Code aufgerufen. `0x080046fc`/`0x08004728` erneut geprüft: `0x08004728` referenziert weiterhin wörtlich `0x50000800`/`0x50000c00`/`0x50001000` (nicht gemappt im F3-Layout) — bestätigt Dead-Code-Einstufung unverändert. `0x080047bc`/`0x080047ee` nicht erneut einzeln dekompiliert, da Teil derselben bereits dreifach verifizierten Familie ohne neue Aufrufer |
| `0x08004d6a`, `0x08004d6c`, `0x08004e74` | 2-Byte-Stubs, Sub-Handler-Sprungziele von `HAL_CAN_IRQHandler` — unverändert |
| `0x080051bc`, `0x080052c4`, `0x08005376`, `0x08005378`, `0x0800537a`, `0x0800537c`, `0x0800537e`, `0x08005380` | 2-Byte-Stubs (Padding/No-Op), unverändert gegenüber 13.14. `0x080051bc` jetzt zusätzlich bestätigt als Msp-DeInit-Platzhalter innerhalb des neu benannten `HAL_CAN_DeInit` — bleibt aber laut Stub-Policy unbenannt |
| `0x08005774` | Erneut geprüft: Generischer 1-Zeiler-Bitmasken-Test (`(*(param_1+0x10) & mask) != 0`), weiterhin domänenübergreifend aus `EMS_Inverter_CAN_Dispatcher` (CMD `0x54`/`0xCB`) und `Mode3_RoundRobin_Timer` mit unterschiedlichen Masken (`2`, `8`, `0x8000`) aufgerufen — zu generisch für einen treffenden Namen |
| `0x08006db4` | Erneut geprüft: Trivialer Getter (`return _DAT_20000290;`), einziger Aufrufer jetzt eindeutig als `0x08004528` identifiziert (vorher nur vermutet) — aber da `0x08004528` selbst zur unklaren Dead-Code-Familie gehört, bleibt auch dieser Getter ohne sicher zuordenbare Domäne |
| `0x0800748c`, `0x0800748e`, `0x08007490`, `0x08007492`, `0x08007494`, `0x08007496` | 6× 2-Byte-Stubs, No-Op-Callbacks für ungenutzte `TIM20_CC_EventDispatch`-Kanäle — unverändert gegenüber 13.14 |

**Ergebnis dieser Tranche:** 4 neu benannt (davon 2 mit sehr hoher Konfidenz durch wörtlichen
Vergleich mit STM32-HAL-Referenzcode: `HAL_Delay`, `HAL_DMA_Abort_IT`), 0 Kollisionen, 25 Funktionen
bewusst zurückgestellt (14 Stubs, 6 Dead-Code-Familie, 2 generische Helfer ohne Domänenzuordnung,
2 CAN-Funktionen mit unklarem Registeroffset trotz plausibler struktureller Rolle). Der Bereich
`0x080043a8–0x08007496` gilt damit als für diese Session abgeschlossen bearbeitet.

---

### 13.18 Tranche 4c (10.07.2026) — Adressbereich 0x08007d4a–0x080151c4

> Bearbeiteter Bereich: letzter verbleibender Adressbereich der Micro-FW laut Auftrag, deckungsgleich
> mit dem Ende von Tranche 3b (13.14) + vollständig mit Tranche 3c (13.15). Per `get-functions
> filterDefaultNames=false` wurden **29 `FUN_*`-Funktionen** im Bereich identifiziert — alle 29 waren
> bereits in 13.14/13.15 einzeln geprüft und bewusst zurückgestellt worden. Methodik: jede der 29
> Funktionen erneut per `get-decompilation` (inkl. `includeCallers`/`includeDisassembly` bei den vier
> Verdachtsfällen, plus `read-memory` Rohbyte-Disassemblierung der vier "Artefakt"-Adressen von Hand)
> geprüft, mit dem Ziel neue Evidenz seit 13.15 zu finden.

**Wichtigster Fund 1 — die vier Adressen `0x080150d4/e8/fc/c4` sind KEINE leeren Ghidra-Artefakte,
sondern reale 10-Byte MOVW/MOVT/BX-Sprungveneers, deren *Ziel*-Code Ghidra fälschlich als eigenen
Funktionskörper anzeigt:** Per `read-memory` wurden die Rohbytes aller vier Adressen von Hand
disassembliert. `0x080150d4` z. B. besteht exakt aus `MOVW r12,#0x9793`, `MOVT r12,#0x0800`,
`BX r12` (10 Bytes, keine weiteren Instruktionen) — ein klassischer Langsprung-Trampolin, der nach
`0x08009793` springt (mitten in den bereits benannten `UART_WaitOnFlagUntilTimeout`,
`0x080096b8`–`0x080097c4`). Die von `get-decompilation` gezeigten "Funktionskörper" mit
`unaff_r4`/`unaff_r6`/`unaff_r9`/`unaff_r10` sind exakt der Pseudocode des Sprungziels, den Ghidras
Decompiler beim Verfolgen der `BX`-Instruktion inline anzeigt — die 4 Bewertung aus 13.15
("keine echten, eigenständigen Funktionen") bleibt in der **praktischen Konsequenz** richtig
(Umbenennung würde weiterhin eine falsche Funktionsidentität suggerieren, da der "Körper" gar nicht
zur Adresse gehört), war aber in der **Ursache** unpräzise: Es handelt sich nicht um fehlerkannte
Funktionsgrenzen ohne jeden Code, sondern um winzige, real kompilierte Interworking-Veneers
(vermutlich RVDS/Keil-Linker-Trampoline für Aufrufe außerhalb Sprungreichweite oder ARM/Thumb-Umschaltung),
die als eigenständige 3-Instruktionen-Funktionen behandelt werden sollten, deren jeweilige Rolle aber
nur über das sich ständig ändernde Sprungziel (nicht über eigenen Code) bestimmt wird. `0x080150fc`
wird nachweislich 8× aus dem bereits benannten `Inverter_Grid_Control` mit echten Parametern/
Rückgabewerten aufgerufen — ein weiterer Beleg, dass diese Adressen reale, im Kontrollfluss verankerte
Sprungziele sind, keine Daten. Eine sinnvolle Einzel-Benennung (z. B. nach der jeweiligen Sub-Rolle
innerhalb `UART_WaitOnFlagUntilTimeout`) würde jedoch eine vollständige Rekonstruktion der Aufrufer-
Bit-Konventionen erfordern (Register `unaff_r6`/`r9`/`r10` werden vom *Aufrufer* vorbelegt, nicht vom
Veneer selbst) — das übersteigt den Rahmen dieser Tranche. **Ergebnis unverändert: keine Umbenennung,
aber Neubewertung der Ursache dokumentiert.**

**Wichtigster Fund 2 — `EEPROM_SaveOperatingStats` (`0x0800e9d4`, 4 Bytes) lässt sich trotz Mini-Größe
eindeutig benennen:** Anders als die übrigen 2–10-Byte-Stubs in diesem Bereich besteht die Funktion
nicht aus `return;`, sondern aus einem einzigen sinnvollen Aufruf: `EEPROM_WriteVerify(0x500,
&DAT_20003e7f, 0x30)`. EEPROM-Adresse `0x500`/48 Bytes ist in Abschnitt 20.2 bereits als
"Betriebsstunden/Statistiken"-Block dokumentiert (dortige Zugriffs-Spalte nannte diesen Aufrufer bereits
namentlich als "Op_Hours"). Die drei Aufrufer (`build_telemetry_block`, `Mode3_RoundRobin_Timer`,
`Inverter_SetMode`) passen exakt zum Muster "Statistik-Block bei Telemetrie-Aufbau/Zyklus-Timer/
Moduswechsel persistieren". Dubletten-Check gegen `EEPROM_Save*`/gesamten Namensraum
(`get-functions-by-similarity`) — **0 Kollisionen**. Umbenennung durchgeführt und per
`get-decompilation signatureOnly=true` verifiziert.

**1 neu vergebener Name:**

| Adresse | Name | Konfidenz | Begründung |
|---|---|---|---|
| `0x0800e9d4` | `EEPROM_SaveOperatingStats` | Hoch | Einzeiliger Wrapper um `EEPROM_WriteVerify(0x500, &DAT_20003e7f, 0x30)`; EEPROM `0x500` bereits als Betriebsstunden-/Statistikblock dokumentiert (20.2); 3 plausible Aufrufer (Telemetrie-Aufbau, Zyklus-Timer, Moduswechsel) |

**Bewusst weiterhin offen (28 Funktionen, alle bereits in 13.14/13.15 geprüft, hier erneut bestätigt):**

| Adresse(n) | Grund |
|---|---|
| `0x08007d4a`, `0x080080fc`, `0x08008324`, `0x08008326`, `0x0800832e`, `0x080083f4`, `0x080088d8` | 2-Byte-No-Op-Stubs (`return;`), erneut per Disassembly/Decompilation bestätigt — reine Sprungziel-Platzhalter für ungenutzte `TIM20_CC_EventDispatch`/`UART_IRQHandler_Full`-Callback-Fälle |
| `0x080082e4` | Erneut geprüft: einziger Aufrufer `TIM20_CC_EventDispatch` ist inzwischen benannt (war in 13.15 noch `FUN_08007a48`), das ändert aber nichts an der Unsicherheit — die Funktion prüft `Instance==0x40001400`(TIM7) und springt bedingt zu einem Bootloader-Thunk (`LAB_1000219c`, neues Sprungziel, nicht in der Thunk-Tabelle aus Abschnitt 10). Ohne Kenntnis, welches der ca. 12 TIM20-Ereignisbits (UIF/COM/Break/Break2/Trigger) dies konkret ist, bleibt die Rolle zu unspezifisch für einen treffenden Namen |
| `0x080088dc` (338 B) | Erneut geprüft, weiterhin `callerCount=0` (auch per `find-cross-references` bestätigt: keine Referenzen). Modusabhängige (`DAT_20000035`) Duty-/Timing-Tabellenberechnung für SRAM-Puffer bei `0x20000a58`+Offsets `0x19c`/`0x1a4`/`0x1a8`/`0x1ac`/`0x21c`/`0x224`/`0x228`/`0x22c` — vermutlich PWM-DMA-Deskriptoren, aber ohne Aufrufer nicht sicher benennbar; evtl. nur indirekt über einen SRAM-Funktionszeiger erreicht |
| `0x08008d4c`, `0x08008d72`, `0x08008e06`, `0x08008ee4`, `0x08008f1c`, `0x08008f3c`, `0x080090f8` | Erneut geprüft: Cluster bestätigt als HRTIM-Timer-Unit-Registerkonfiguratoren (`param_2*0x80`-Indexierung, Offsets `0xb8`/`0xbc`/`0xc0`/`0xc4`/`0xc8`/`0xe4`/`0xec` relativ zur Timer-Unit-Basis). `0x08008e06` liefert jetzt einen klareren Dispatch-Baum (Bitmasken-Fälle `0x40/0x8/0x1/0x2/0x4/0x10/0x20/0x200/0x80/0x100/0x400/0x800` → 2 Zielregister), reicht aber ohne STM32F3-HRTIM-Referenzhandbuch nicht für eine registergenaue Namensvergabe (CMP/SET/RST/OUT-Zuordnung bleibt Vermutung) |
| `0x08009a40`, `0x08009a4c`, `0x08009a54`, `0x08009a5c`, `0x08009a64`, `0x08009a74`, `0x08009a92` | Erneut geprüft (`0x08009a40`: `return *(uint*)(p1+p2*4+0x60) & 0x7c000000;`, ausschließlich aus `HAL_GPIO_Init_Extended`) — bestätigt GPIO-Bezug für die 4 exklusiven Accessoren, aber die 3 domänenübergreifenden (`0x08009a4c`/`54`/`5c`) verhindern weiterhin eine saubere Cluster-Aufteilung ohne Raten |
| `0x08011b10` | Erneut geprüft: `_DAT_20000458 = _DAT_20000024;`, einziger Aufrufer `UART_DMA_RxCplt_Dispatch` im USART2-Zweig (`Instance==0x40004400`). Keine der beiden SRAM-Variablen ist an anderer Stelle in der Doku referenziert — Semantik bleibt unklar |
| `0x080150d4`, `0x080150e8`, `0x080150fc`, `0x080151c4` | **Reale MOVW/MOVT/BX-Interworking-Veneers** (nicht "keine Funktion", s. "Wichtigster Fund 1" oben) — Umbenennung weiterhin zurückgestellt, da die individuelle Rolle nur über das Sprungziel/die Aufrufer-Registerkonvention bestimmbar wäre, nicht über eigenen Code |

**Ergebnis dieser Tranche:** 1 neu benannt (`EEPROM_SaveOperatingStats`, hohe Konfidenz), 0 Kollisionen,
28 Funktionen bewusst zurückgestellt (7× 2-Byte-Stubs, 1× TIM7-Bootloader-Dispatch ohne Bit-Zuordnung,
1× PWM-Tabellenfunktion ohne Aufrufer, 7× HRTIM-Timer-Unit-Cluster ohne Referenzhandbuch-Abgleich,
7× GPIO/UART-Bitfeld-Cluster mit Domänen-Überschneidung, 1× Ein-Zeiler-Kopiervorgang ohne Semantik,
4× neu als reale Sprungveneers (nicht als Nicht-Funktionen) charakterisierte Trampolin-Adressen). Der
Bereich `0x08007d4a–0x080151c4` gilt damit als für diese Session abgeschlossen bearbeitet — alle 29
verbliebenen `FUN_*`-Adressen wurden mit frischer Evidenz erneut geprüft, ohne dass sich zusätzliche
sicher benennbare Fälle über `EEPROM_SaveOperatingStats` hinaus ergaben.

---

### 13.19 Tranche 5a (10.07.2026) — Adressbereich 0x0800155c–0x08005380

> Bearbeiteter Bereich: Teilbereich der fünften Tranche (parallele Agenten bearbeiten 5b
> `0x08005774–0x08008f3c` und 5c `0x080090f8–0x080151c4`). Per `get-functions filterDefaultNames=false`
> wurden in diesem Bereich **24 `FUN_*`-Funktionen** identifiziert. Alle 24 waren bereits in
> 13.12/13.13/13.16/13.17 einzeln geprüft und bewusst zurückgestellt worden (Dead-Code-Familie,
> Stubs, CAN-Reserved-Offset ohne Registeridentität). Methodik: jede Funktion erneut per
> `get-decompilation` (inkl. `includeCallers`/`includeCallees`) untersucht, dazu gezielt
> `find-cross-references` auf alle 7 Mitglieder der als "Dead-Code" eingestuften Funktionsfamilie
> (`0x08002824`, `0x0800288c`, `0x080028e0`, `0x08004528`, `0x080046fc`, `0x08004728`, `0x080047bc`,
> `0x080047ee`) angewendet, um die Einstufung aus dem Auftrag unabhängig gegenzuprüfen.

**Dead-Code-Familie erneut bestätigt (vollständige Re-Verifikation):** `find-cross-references` mit
`direction=to` liefert für `0x08002824`, `0x0800288c` und `0x080028e0` (die drei "Wurzelfunktionen"
der Familie) jeweils **`totalToCount=0`** — weder Code- noch Datenreferenz irgendwo im gesamten
Programm. Für die vier abhängigen Funktionen `0x08004528`, `0x080046fc`, `0x08004728`, `0x080047bc`
und `0x080047ee` wurden ausnahmslos **nur** Aufrufe aus genau diesen drei unerreichbaren
Wurzelfunktionen gefunden (z. B. `0x080047ee`: 3 Aufrufer, alle `0x08002824`/`0x0800288c`/`0x080028e0`).
Die gesamte Familie ist damit als in sich geschlossener, vom übrigen Programm vollständig
abgeschnittener Codepfad bestätigt — konsistent mit der Einstufung aus dem Auftrag und den Tranchen
13.12/13.13/13.17. Keine Umbenennung, keine weitere Tiefenprüfung nötig.

> **Korrektur-Hinweis zu 13.17:** Dort wurde für `HAL_Delay` einer der drei Aufrufer als
> "echter Live-Code (`modbus_register_handler`, `0x080047ee`)" beschrieben. Das ist eine
> Verwechslung: `0x080047ee` ist **nicht** `modbus_register_handler` (dieser liegt tatsächlich bei
> `0x080124e8`, 2842 Bytes, s. Abschnitt 16.1) — `0x080047ee` ist ein Mitglied der Dead-Code-Familie
> (s. o., ausschließlich von `0x08002824`/`0x0800288c`/`0x080028e0` aufgerufen). Die tatsächlichen
> `HAL_Delay`-Aufrufer sind laut `get-decompilation includeCallers=true`: `0x08004528` (2×,
> Dead-Code-Familie), `0x080047ee` (1×, Dead-Code-Familie) und `modbus_register_handler` (3×, echter
> Live-Code-Aufrufer). Die Kernaussage von 13.17 (`HAL_Delay` ist trotz Dead-Code-Aufrufern korrekt
> benannt, da auch von echtem Live-Code referenziert) bleibt richtig — nur die Adresszuordnung im
> Klammerzusatz war falsch.

**1 neu vergebener Name (Adresse → Name, Konfidenz):**

| Adresse | Name | Konfidenz | Begründung |
|---|---|---|---|
| `0x080043a8` | `HAL_COMP_MspInit` | Hoch | Einziger Aufrufer `HAL_COMP_Init`, aufgerufen exakt hinter dem klassischen HAL-"MspInit nur beim ersten Init"-Guard (`*(char*)(param_1+0x1d)==0`, danach `param_1[7]=0; param_1[8]=0;` — Reset der State-Felder). Konfiguriert per drei `HAL_GPIO_Init`-Aufrufen (GPIOA/B/C, `0x48000000`/`0x400`/`0x800`) den Analog-Eingangspin für COMP1 (`0x40010200`), COMP4 (`0x4001020c`) bzw. COMP3 (`0x40010208`) und setzt je ein "Pin-in-Use"-Bit in einem Register bei `0x4002104c`. Analog zum bereits etablierten Namensschema `HAL_ADC_MspInit`/`HAL_CAN_MspInit`. Dubletten-Check: `get-functions-by-similarity(searchString="HAL_COMP_MspInit")` über alle 382 zu Tranchenbeginn benannten Funktionen — 0 Kollisionen. Nach Umbenennung per `get-decompilation signatureOnly=true` verifiziert (Funktionsname korrekt übernommen, nicht nur Sekundär-Label). |

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, 23 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x0800155c`, `0x08003afe`, `0x08003b00` | 2-Byte-Stubs (`BX LR`), unverändert gegenüber 13.16 — echte leere Callback-Platzhalter, kein Ghidra-Grenzartefakt, aber ohne Inhalt nicht sinnvoll benennbar |
| `0x08002824`, `0x0800288c`, `0x080028e0`, `0x08004528`, `0x080046fc`, `0x08004728`, `0x080047bc`, `0x080047ee` | **Dead-Code-Familie**, in dieser Tranche vollständig re-verifiziert (s. o.) — `totalToCount=0` für alle drei Wurzelfunktionen, alle vier abhängigen Funktionen ausschließlich intern referenziert. Bestätigt unverändert |
| `0x08004d08` | Erneut geprüft: einziger Aufrufer weiterhin `CAN1_Init` (State-Check `==READY` an Offset `+0x17`, feste Parameter `2,2,1,1`, schreibt gepackte 4-Bit-Felder an Instance-Offset `+0x80`). `+0x80` liegt weiterhin im bxCAN-Reserved-Bereich laut Referenzhandbuch, keine neue Evidenz seit 13.13/13.17 gefunden, die eine Namensvergabe rechtfertigen würde |
| `0x08004d6a`, `0x08004d6c`, `0x08004e74` | 2-Byte-Stubs, Sub-Handler-Sprungziele von `HAL_CAN_IRQHandler` (erneut per Decompilation von `HAL_CAN_IRQHandler` bestätigt: dispatchen je nach ESR/IER-Bitgruppe (TME/FMP1/FF/BOF/EWG/EPV/LEC/ERR)). Die Dispatch-Stelle ist zwar jetzt eindeutig einer einzelnen Flag-Gruppe zuordenbar, der Stub-Körper selbst bleibt aber ein reines `return;` ohne eigene Semantik — konsistent mit der Stub-Politik bewusst nicht spekulativ nach IRQ-Flag benannt |
| `0x080051bc`, `0x080052c4`, `0x08005376`, `0x08005378`, `0x0800537a`, `0x0800537c`, `0x0800537e`, `0x08005380` | 2-Byte-Stubs (Padding/No-Op-Callbacks), unverändert gegenüber 13.14/13.17 |

**Ergebnis dieser Tranche:** 1 neu benannt (`HAL_COMP_MspInit`, hohe Konfidenz), 0 Kollisionen,
23 Funktionen bewusst zurückgestellt (14 echte 2-Byte-Stubs, 8 Dead-Code-Familie vollständig
re-verifiziert, 1 CAN-Funktion mit unverändert unklarem Registeroffset). Zusätzlich Korrektur eines
Adress-Verwechslungsfehlers aus 13.17 dokumentiert (`0x080047ee` ≠ `modbus_register_handler`). Der
Bereich `0x0800155c–0x08005380` gilt damit als für diese Session abgeschlossen bearbeitet — die
sinkende Erfolgsquote (12→9→30→17→5→4→1→1) bestätigt, dass sich der Namensbestand in diesem
Adressbereich seinem statischen Limit nähert.

---

### 13.20 Tranche 5b (10.07.2026) — Adressbereich 0x08005774–0x08008f3c

> Bearbeiteter Bereich: Teilbereich der fünften Tranche (parallele Agenten bearbeiten 5a
> `0x0800155c–0x08005380` und 5c `0x080090f8–0x080151c4`). Per `get-functions filterDefaultNames=false`
> wurden in diesem Bereich **25 `FUN_*`-Funktionen** identifiziert. Ein Großteil war bereits in
> 13.9/13.13/13.14/13.17/13.18 einzeln geprüft und bewusst zurückgestellt worden (generischer
> Bitmasken-Test, Dead-Code-Familie-Getter, 2-Byte-Stubs). Der Schwerpunkt dieser Tranche lag auf dem
> in 13.18 explizit als "ohne HRTIM-Referenzhandbuch nicht registergenau benennbar" eingestuften
> Timer-Unit-Cluster `0x08008d4c`–`0x080090f8` (Auftrags-Vorgabe) sowie zwei bislang nicht
> untersuchten Funktionen `0x08005db0`/`0x08005df0`, die im alten (Adress-Drift-behafteten) Doku-
> Vorschlag der Sektion 13.3 fälschlich als generische I2C-Funktionen vermutet wurden.

**Wichtigster Fund — HRTIM-Timer-Unit-Cluster per Referenzhandbuch-Offset-Abgleich vollständig
aufgelöst:** Der Cluster nutzt durchgängig `param_2*0x80`-Indexierung (Timer-Unit-Auswahl, 6 Einheiten
A–F) relativ zur HRTIM-Instanzbasis. Durch systematischen Abgleich der verwendeten Byte-Offsets gegen
das reale STM32F3/F334 `HRTIM_TypeDef`-Speicherlayout (Master-Block `0x00`–`0x28`: MCR/MPER/MREP;
Timer-Unit-Blöcke ab `0x80` im `0x80`-Raster mit TIMxCR/TIMxPER/TIMxREP/TIMxDTR/TIMxSETR1/RSTR1/
SETR2/RSTR2/TIMxFLTR/TIMxOUTR; Common-Block ab `0x380` mit BMCR bei `0x3a0`) ließen sich alle 6
Cluster-Funktionen konkreten Registergruppen zuordnen (s. Tabelle unten und Abschnitt 14.4). Besonders
eindeutig: `HRTIM_TimerUnit_OutputConfig` (`0x08008e06`) verzweigt nach einer Bitmaske, deren Werte
(`0x1,0x2,0x4,0x8,0x10,0x20,0x40,0x80,0x100,0x200,0x400,0x800`) exakt den realen HAL-Konstanten
`HRTIM_OUTPUT_TA1…TF2` entsprechen — Output1-Werte (ungerade Nibble-Position) gehen in SETx1R/RSTx1R,
Output2-Werte in SETx2R/RSTx2R, danach gemeinsames Update von TIMxOUTR. `HRTIM_TimerUnit_WaveformConfig`
(`0x08008f3c`, mit 432 Bytes größte Funktion des Clusters) setzt zusätzlich je Timer-Unit ein
BMCR-Bit exakt auf Position `1+param_2` — deckt sich bitgenau mit dem realen `BMCR.TxBM`-Feld
(Burst-Mode-Timer-Update-Enable). Details und vollständige Registertabelle s. Abschnitt 14.4.

**Zweiter Fund — `0x08005db0`/`0x08005df0` gehören ebenfalls zum HRTIM-Cluster, nicht zu I2C:** Der
alte, bereits mehrfach als unzuverlässig markierte Doku-Vorschlag (13.3) vermutete an dieser Adresse
`I2C_Mem_Read`. Tatsächlich liegt `0x08005df0` unmittelbar zwischen den bestätigten
`HRTIM_GPIO_AF_Init` (endet `0x08005da0`) und den echten I2C-Funktionen (beginnen `0x0800617c`), und
ruft direkt `HRTIM_TimerUnit_ChopperConfig` (`0x08008f1c`) auf — ein eindeutiger struktureller Beleg
für HRTIM-Zugehörigkeit. `0x08005db0` (direkt davor, gleiches Handle-Zugriffsmuster über
Instance-Offset `+0x388` = Common-Block `+0x08`) wurde entsprechend als Sibling-Funktion mitbenannt.
Beide Funktionen haben laut `find-cross-references` aktuell **keine** weiteren Aufrufer im Programm —
das deckt sich mit dem bereits für `HRTIM_TimerUnit_Init`/`HRTIM_GPIO_AF_Init` dokumentierten Befund
(ebenfalls `callerCount=0`), dass der gesamte HRTIM-Treiberblock nur indirekt (Funktionszeiger/
externer Bootloader-Code) oder gar nicht erreicht wird — Fehlen von Aufrufern wurde daher, wie bei den
bereits etablierten HRTIM-Namen, nicht als Ausschlusskriterium gewertet.

**8 neu vergebene Namen (Adresse → Name, Konfidenz):**

| Adresse | Name | Konfidenz | Kurzbegründung |
|---|---|---|---|
| `0x08008d4c` | `HRTIM_MasterTimer_BaseConfig` | Hoch | MCR-Prescaler-Bits + MPER(`+0x14`) + MREP(`+0x18`) — exakter Offset-Treffer auf `HRTIM_Master_TypeDef` |
| `0x08008d72` | `HRTIM_MasterTimer_WaveformConfig` | Hoch | MCR-Modus-/Sync-Bits + BMCR(`+0x3a0`) Burst-Enable |
| `0x08008e06` | `HRTIM_TimerUnit_OutputConfig` | Hoch | Bitmasken-Werte = reale `HRTIM_OUTPUT_Tx1/Tx2`-Konstanten, SETx1R/RSTx1R bzw. SETx2R/RSTx2R + TIMxOUTR |
| `0x08008ee4` | `HRTIM_TimerUnit_BaseConfig` | Hoch | TIMxCR-Prescaler-Bits + TIMxPER + TIMxREP, Pendant zu `HRTIM_MasterTimer_BaseConfig` |
| `0x08008f1c` | `HRTIM_TimerUnit_ChopperConfig` | Mittel | Bedingtes Schreiben auf Offset passend zu TIMxCHPR-Lage/Feldbreite, Registeridentität nicht 100% verifiziert |
| `0x08008f3c` | `HRTIM_TimerUnit_WaveformConfig` | Hoch | Kombiniert TIMxCR/TIMxFLTR/TIMxOUTR/BMCR.TxBM (Bitposition exakt `1+param_2`) |
| `0x08005db0` | `HRTIM_WaitOnFlagUntilTimeout` | Mittel | HAL-Wait-Timeout-Pattern auf Common-ISR-Lage (`+0x388`), Rückgabe `0`/`3` wie `HAL_StatusTypeDef` |
| `0x08005df0` | `HRTIM_TimerUnit_LockedUpdate` | Mittel | Software-Lock-Guard um Aufruf von `HRTIM_TimerUnit_ChopperConfig` |

**Dubletten-Check:** Vor der Umbenennung wurden alle 445 Funktionsnamen des Programms per
`get-functions filterDefaultNames=false` geladen und ein Python-Skript (`run-script`) hat jeden der 8
Zielnamen gegen diese vollständige Namensmenge geprüft — **0 Kollisionen**. Die Umbenennung erfolgte
in einer einzigen Ghidra-Transaktion (`setName`, `SourceType.USER_DEFINED`); alle 8 Rückmeldungen
bestätigen `alt → neu`.

**Bewusst zurückgestellt (bleiben `FUN_<adresse>`, 17 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x08005774` | Zum vierten Mal geprüft (13.9, 13.17, jetzt erneut): generischer Ein-Zeiler-Bitmasken-Test (`(*(p1+0x10)&p2)!=0`), weiterhin aus zwei fachfremden Kontexten (`EMS_Inverter_CAN_Dispatcher` CMD `0x54`/`0xCB`, `Mode3_RoundRobin_Timer`) mit unterschiedlichen Masken aufgerufen — keine neue Evidenz, zu generisch |
| `0x08006db4` | Erneut geprüft: Trivialer Getter (`return _DAT_20000290;`), einziger Aufrufer weiterhin die unerreichbare Dead-Code-Familie (`FUN_08004528`, s. 13.19-Re-Verifikation) — keine sicher zuordenbare Domäne |
| `0x0800748c`, `0x0800748e`, `0x08007490`, `0x08007492`, `0x08007494`, `0x08007496` | 6× 2-Byte-No-Op-Stubs, unveränderte Sprungziel-Platzhalter für ungenutzte `TIM20_CC_EventDispatch`-Kanäle |
| `0x08007d4a` | 2-Byte-Stub, unverändert |
| `0x080080fc` | 2-Byte-Stub, unverändert |
| `0x080082e4` | Einziger Aufrufer `TIM20_CC_EventDispatch`; prüft `Instance==0x40001400`(TIM7) und springt bedingt zu einem Bootloader-Thunk — ohne Kenntnis, welches TIM20-Ereignisbit dies konkret ist, weiterhin zu unspezifisch |
| `0x08008324`, `0x08008326`, `0x0800832e`, `0x080083f4` | 2-Byte-No-Op-Stubs, Sub-Handler-Sprungziele von `UART_IRQHandler_Full`, unverändert |
| `0x080088d8` | 2-Byte-Stub, unverändert |
| `0x080088dc` | Erneut geprüft, weiterhin `callerCount=0`/`totalToCount=0` (per `find-cross-references` bestätigt) — modusabhängige Duty-/Timing-Tabellenberechnung ohne erreichbaren Aufrufer, keine sichere Benennung möglich |

**Ergebnis dieser Tranche:** 8 neu benannt (6× Hoch, 2× Mittel — davon 6 den in 13.18 als Kernproblem
benannten HRTIM-Timer-Unit-Cluster vollständig auflösend), 0 Kollisionen, 17 Funktionen bewusst
zurückgestellt (14× echte 2-Byte-Stubs, 1× generischer Bitmasken-Test viermal erfolglos re-geprüft,
1× Dead-Code-Familie-Getter, 1× TIM7-Dispatch ohne Bit-Zuordnung, 1× Tabellenfunktion ohne Aufrufer).
Ghidra-Namensstand nach dieser Tranche: `get-function-count filterDefaultNames=true` = 392 von 445
(88,1%). Der Bereich `0x08005774–0x08008f3c` gilt damit als für diese Session abgeschlossen bearbeitet.

---

### 13.21 Tranche 5c (10.07.2026) — Adressbereich 0x080090f8–0x080151c4

> Bearbeiteter Bereich: letzter verbleibender Adressbereich laut Auftrag (parallel zu 5a
> `0x0800155c–0x08005380` und 5b `0x08005774–0x08008f3c`). Deckungsgleich mit dem Ende von 13.15/13.18.
> Per `get-functions filterDefaultNames=false` wurden **14 `FUN_*`-Funktionen** im Bereich identifiziert:
> `0x080090f8`, `0x08009a40`, `0x08009a4c`, `0x08009a54`, `0x08009a5c`, `0x08009a64`, `0x08009a74`,
> `0x08009a92`, `0x0800b958`, `0x08011b10`, `0x080150d4`, `0x080150e8`, `0x080150fc`, `0x080151c4`.
> Alle 14 waren bereits in 13.14/13.15/13.18 einzeln geprüft und zurückgestellt worden. Methodik: jede
> Funktion per `get-decompilation` (inkl. `includeCallers`) neu geprüft; für die 4 Veneer-Adressen
> zusätzlich Rohbyte-Disassembly per `read-memory` + manuelle Thumb-2-MOVW/MOVT-Dekodierung, um die
> exakten Sprungziele zu bestimmen (Weiterführung von 13.18, das die Ziele nur grob lokalisiert hatte).

**Wichtigster Fund 1 — Doku/Ghidra-Drift entdeckt und behoben: `TIM_Base_Init` (`0x0800b958`) war seit
13.4 dokumentiert, aber nie in Ghidra angewendet.** Die Funktion war in der Ersterfassung bereits
korrekt analysiert (Register-Whitelist exakt für TIM1/2/3/4/5/8/15/16/20-Instanzbasen `0x40012c00`/
`0x40000000`/`0x40000400`/`0x40000800`/`0x40000c00`/`0x40013400`/`0x40014000`/`0x40014400`/
`0x40014800`/`0x40015000`; schreibt CR1-Bits, ARR (`param_1[0xb]`), PSC (`param_1[10]`) sowie
bedingt RCR (`param_1[0xc]`) für die "advanced" Timer — klassisches `TIM_Base_InitTypeDef`-Pattern),
der `setName`-Aufruf wurde jedoch nie durchgeführt (Ghidra zeigte weiterhin `FUN_0800b958`, 4 Aufrufer
`TIM7_Channels_EnableAll`/`TIM_Handle_Init`/`TIM20_Channels_EnableAll`/`TIM4_Channels_EnableAll` —
alle Timer-Kanal-Aktivierungsfunktionen, die vor dem Freischalten zuerst die Basisregister
konfigurieren). Dubletten-Check: `TIM_Base_Init` kommt im gesamten Symbolraum nirgends vor (nur als
Freitext-Erwähnung in der Doku selbst). Umbenennung durchgeführt und per `get-decompilation
signatureOnly=true` verifiziert (`"functionName":"TIM_Base_Init"`).

**Wichtigster Fund 2 — zwei weitere stale Doku-Tabellen mit nie angewendeten Namen identifiziert und
korrigiert:** Analog zum bereits in 13.9 dokumentierten Muster ("398/445 behauptet, real 21") enthielten
Abschnitt 13.4 (`0x08009a4c`/`54`/`5c` als vermeintlich `DMA_Get_TCIF`/`DMA_Get_Error_Flag`/`DMA_Get_HTIF`)
und Abschnitt 13.8 (`0x080150d4`/`e8`/`fc`/`c4` als vermeintlich `CAN_TxMailbox_SetDLC`/
`CAN_RxFilter_Config`/`float_to_fixed_point`/`CAN_frame_pack`) Namen, die real **nie in Ghidra
gesetzt** wurden (alle 7 Adressen zeigten bei `get-functions filterDefaultNames=false` weiterhin
`FUN_*`). Beide Tabellen wurden mit ❌/Strikethrough korrigiert und verweisen auf diesen Abschnitt.
Die "DMA"-Hypothese für `0x08009a4c`/`54`/`5c` ist zudem inhaltlich widerlegt (s. Fund 3) — es sind
keine DMA-Register, sondern domänenübergreifende Bitfeld-Extraktoren.

**Wichtigster Fund 3 — GPIO/UART-Bitfeld-Cluster (`0x08009a40`–`0x08009a92`) erneut geprüft, ein
Cluster-Mitglied neu als UART-exklusiv (nicht GPIO) identifiziert:** Per `includeCallers=true` wurde
für jede der 7 Funktionen die vollständige Aufrufer-Liste erneut gezogen:

| Adresse | Body | Aufrufer | Domäne |
|---|---|---|---|
| `0x08009a40` | `*(uint*)(p1+p2*4+0x60) & 0x7c000000` | ausschließlich `HAL_GPIO_Init_Extended` (12×) | GPIO |
| `0x08009a4c` | `(*(uint*)(p1+8) & 0xf) >> 3` | `HAL_GPIO_Init_Extended` + `HAL_ADC_Init` | GPIO **und** ADC |
| `0x08009a54` | `*(uint*)(p1+8) & 1` | `UART_WaitReady`, `ADC_ConversionStop_WaitReady`, `HAL_GPIO_Init_Extended`, `HAL_ADC_Init` | UART **und** ADC **und** GPIO |
| `0x08009a5c` | `(*(uint*)(p1+8) & 7) >> 2` | `HAL_GPIO_Init_Extended`, `HAL_ADC_Init`, `HAL_ADC_Start_DMA` | GPIO **und** ADC |
| `0x08009a64` | `(p1[0xc] & 0xc00) != 0 ? 0 : 1` | **ausschließlich `UART_IRQHandler`** | UART (nicht GPIO!) |
| `0x08009a74` | schreibt `*(p1+0x14)` (3-Bit-Feld) | ausschließlich `HAL_GPIO_Init_Extended` (3×) | GPIO |
| `0x08009a92` | schreibt `*(p1+p2*4+0x60)` Bit 31 | ausschließlich `HAL_GPIO_Init_Extended` (4×) | GPIO |

`0x08009a64` war in 13.11/13.15/13.18 pauschal den "4 exklusiven GPIO-Accessoren" zugerechnet worden
(zusammen mit `0x08009a40`/`74`/`92`) — das ist **widerlegt**: sein einziger Aufrufer ist
`UART_IRQHandler`, nicht `HAL_GPIO_Init_Extended`. Die 3 domänenübergreifenden Funktionen
(`0x08009a4c`/`54`/`5c`) extrahieren jeweils ein festes Bit/Bitfeld aus Offset `+8` eines generischen
Parameters — identisches Bitmuster wird aber von UART-, ADC- und GPIO-Init-Code aus **unterschiedlichen**
Peripherie-Handles heraus abgefragt. Das ist typisch für RVDS/Keil-Identical-Code-Folding (der
Compiler/Linker dedupliziert bytegleiche kurze Funktionskörper über Modulgrenzen hinweg) — eine echte
GPIO- oder UART-spezifische Registersemantik lässt sich daraus nicht mehr rekonstruieren, ohne zu raten.
Alle 7 bleiben daher unbenannt; die Korrektur zu `0x08009a64` wurde in der Cluster-Tabelle in 13.4
nachgetragen (s. u.).

**Wichtigster Fund 4 — Rohbyte-Dekodierung bestätigt und präzisiert 13.18 für die 4 Veneer-Adressen,
`thunk_<Ziel>`-Benennung aber weiterhin nicht sinnvoll:** Manuelle Thumb-2-Dekodierung der MOVW/MOVT/BX-
Bytesequenzen (`read-memory`, 10 Bytes je Adresse) ergibt exakte Sprungziele:

| Veneer | MOVW/MOVT-Ziel | Liegt in Funktion | Aufrufer des Veneers |
|---|---|---|---|
| `0x080150d4` | `0x08009792` | `UART_WaitOnFlagUntilTimeout` (0x080096b8–0x080097c3) | `callerCount=0` (nur Datenreferenzen aus der Shell-Kommandotabelle `0x0801892c`ff., s. 7.1) |
| `0x080150e8` | `0x08009774` | `UART_WaitOnFlagUntilTimeout` | `callerCount=0` (dito, Datenreferenzen aus Shell-Tabelle) |
| `0x080150fc` | `0x0800707c` | `RCC_OscConfig` (0x08006e34–0x0800728b) | `Inverter_Grid_Control`, 8× (Leistungs-/Schutzschwellen-Vergleiche) |
| `0x080151c4` | `0x08007058` | `RCC_OscConfig` | `callerCount=0` (2 Datenreferenzen bei `0x0801a66c`/`0x0801a714`) |

Damit ist der in 13.18 vermutete "Interworking-Veneer"-Mechanismus konkret belegt — die Sprungziele
landen aber **mitten** in `UART_WaitOnFlagUntilTimeout` bzw. `RCC_OscConfig`, exakt in deren generischer
`HAL_GetTick`-Timeout-Warteschleife (`while(...) { if (5000 < HAL_GetTick()-t0) return 3; }` — der
Fehlercode `3` entspricht dem klassischen `HAL_TIMEOUT`). Diese Tail-Sequenz ist bytegleich in mehreren
sonst unabhängigen Funktionen enthalten und wurde vom RVDS/Keil-Linker offenbar cross-jump-optimiert
(mehrere Aufrufer springen in dieselbe physische Instruktionsfolge, die nur zufällig am Ende von
`RCC_OscConfig`/`UART_WaitOnFlagUntilTimeout` liegt). Der Aufrufer `Inverter_Grid_Control` (bei
`0x080150fc`) hat inhaltlich nichts mit Oszillator-Konfiguration zu tun — eine Benennung als
`thunk_RCC_OscConfig` oder `thunk_UART_WaitOnFlagUntilTimeout` (analog zu `thunk_CAN_Filter_Setup`)
würde daher fälschlich suggerieren, dass diese Veneers die semantische Funktion (Takt-Config bzw.
UART-Flag-Warten) aufrufen — tatsächlich nutzen sie nur eine zufällig dort kompilierte generische
Timeout-Warteschleife. Das unterscheidet sie fundamental von `thunk_CAN_Filter_Setup` (`0x080150f2`),
der sauber auf den **Funktionsanfang** von `CAN_Filter_Setup` (`0x0800eb88`) springt. **Ergebnis
unverändert gegenüber 13.18: keine Umbenennung**, jetzt aber mit exakten Sprungzieladressen belegt statt
nur grob lokalisiert.

**1 neu vergebener Name:**

| Adresse | Name | Konfidenz | Begründung |
|---|---|---|---|
| `0x0800b958` | `TIM_Base_Init` | Hoch | Seit Ersterfassung (13.4) korrekt analysiert, aber nie in Ghidra angewendet (Doku/Ghidra-Drift, s. Fund 1). Register-Whitelist exakt für die 9 STM32F3-TIM-Instanzbasen (TIM1/2/3/4/5/8/15/16/20); schreibt CR1/ARR/PSC/bedingt RCR — klassisches `TIM_Base_InitTypeDef`-Pattern. 4 Aufrufer sind alle bereits benannte `TIM*_Channels_EnableAll`/`TIM_Handle_Init`-Funktionen. 0 Kollisionen (`TIM_Base_Init` kam im Symbolraum nicht vor). Per `get-decompilation signatureOnly=true` verifiziert. |

**Bewusst weiterhin offen (13 Funktionen):**

| Adresse(n) | Grund |
|---|---|
| `0x080090f8` | Erneut geprüft inkl. `find-cross-references` (`totalToCount=0`, `totalFromCount=0` — vollständig unreferenziert). HRTIM-Timer-Unit-Registerschreiber (`param_2*0x80+0xec`-Indexierung, bedingter Zusatzblock bei `param_3[6]==1`), Teil des in 13.18 dokumentierten HRTIM-Clusters `0x08008d4c`–`0x080090f8`. Ohne Aufrufer und ohne STM32F3-HRTIM-Referenzhandbuch-Abgleich nicht sicher benennbar |
| `0x08009a40`, `0x08009a4c`, `0x08009a54`, `0x08009a5c`, `0x08009a64`, `0x08009a74`, `0x08009a92` | GPIO/UART/ADC-Bitfeld-Cluster, vollständige Aufrufer-Matrix neu erhoben (s. Fund 3). 4 Funktionen sind GPIO-exklusiv (`0x08009a40`/`74`/`92`) bzw. UART-exklusiv (`0x08009a64`, **neu korrigiert** — war fälschlich als GPIO eingestuft), 3 sind domänenübergreifend identisch (`0x08009a4c`/`54`/`5c`, vermutlich Compiler-Identical-Code-Folding). Register-Offset `+8`/`+0x14`/`+0x60` lässt sich ohne Herstellerhandbuch-Abgleich der zugrundeliegenden Custom-Struct (kein Standard-`GPIO_TypeDef`-Layout, da Offset `0x60` dort nicht existiert) nicht registergenau benennen |
| `0x08011b10` | Erneut geprüft: `_DAT_20000458 = _DAT_20000024;`, einziger Aufrufer weiterhin `UART_DMA_RxCplt_Dispatch` (USART2-Zweig). Keine neue Evidenz seit 13.15/13.18 — beide SRAM-Variablen bleiben ohne dokumentierte Semantik |
| `0x080150d4`, `0x080150e8`, `0x080150fc`, `0x080151c4` | **Bestätigte Interworking-Veneers mit jetzt exakt bekannten Sprungzielen** (s. Fund 4) — Umbenennung als `thunk_<Ziel>` bewusst unterlassen, da die Sprungziele in generischem, cross-jump-optimiertem Timeout-Code unrelated Funktionen landen und ein solcher Name die tatsächliche Semantik aktiv fehlleiten würde (anders als bei `thunk_CAN_Filter_Setup`, das sauber auf einen Funktionsanfang zeigt) |

**Ergebnis dieser Tranche:** 1 neu benannt (`TIM_Base_Init`, hohe Konfidenz — Doku/Ghidra-Drift behoben),
0 Kollisionen, 13 Funktionen bewusst zurückgestellt (1 unreferenzierter HRTIM-Registerschreiber, 7
GPIO/UART/ADC-Bitfeld-Cluster mit neu präzisierter Aufrufer-Matrix, 1 Ein-Zeiler-Kopiervorgang ohne
Semantik, 4 Interworking-Veneers mit jetzt exakt dekodierten, aber irreführenden Sprungzielen). Zusätzlich
2 stale Doku-Tabellen (13.4, 13.8) mit nie in Ghidra angewendeten Namen identifiziert und korrigiert.
Der Bereich `0x080090f8–0x080151c4` gilt damit als für diese Session abgeschlossen bearbeitet.

---

## 14. Neue Erkenntnisse aus Massenanalyse

### 14.1 Modbus RS485 Slave (vollständig dekodiert)

Die Micro-MCU betreibt einen **eigenen Modbus-Slave** über USART1/USART2 (unabhängig vom TCP-Modbus der Control-MCU):
- `Modbus_Process_Request` (0x0800ac0c) — Dispatcher für FC03/FC06/FC10
- `CRC16_Modbus` (0x0800abda) — Standard CRC-16/Modbus (Poly 0xA001, Init 0xFFFF)
- `modbus_register_handler` (0x080124e8, **2842 Bytes!**) — Massiver Register-Handler
- `modbus_read_register_block` (0x080118e8) — Float→Int Skalierung für Register-Lesung

### 14.2 Debug-Log-System (Ringpuffer)

200-Slot Ringpuffer bei SRAM `0x20001A2C` mit ~60 Event-Typen:
- `debug_log_enqueue` → Timestamped Event einfügen
- `debug_log_dequeue` → Nächsten Eintrag holen
- `debug_log_format_entry` (1712 Bytes) — Riesiger Switch für alle Event-Typen

### 14.3 EEPROM-Konfiguration (I2C)

I2C-EEPROM (Adressen 0xA0/0xA2) für persistente Konfiguration:
- `EEPROM_LoadConfig` (614B) — Alle Einstellungen beim Boot laden
- `EEPROM_WriteVerify` (300B, **8 Aufrufe**) — Schreiben mit Byte-Verifikation
- `EEPROM_SaveTimestamp` — Tick-Counter in Register 0x80 sichern
- `EEPROM_SaveOperatingStats` (`0x0800e9d4`, 4B, Tranche 4c) — Wrapper `EEPROM_WriteVerify(0x500, &DAT_20003e7f, 0x30)`,
  sichert den 48-Byte Betriebsstunden-/Statistikblock (EEPROM `0x500`, s. 20.2); Aufrufer: `build_telemetry_block`,
  `Mode3_RoundRobin_Timer`, `Inverter_SetMode`

### 14.4 HRTIM (High-Resolution Timer)

Umfangreiche HRTIM-Nutzung für die PWM-Steuerung der H-Brücke und des LLC-Wandlers — 20+ Funktionen für HRTIM-Konfiguration (Deadtime, Burst-Mode, ADC-Trigger, Waveform). Dies bestätigt, dass die Inverter-Regelung direkt auf dieser MCU läuft.

**Ergänzung Tranche 5b (10.07.2026) — Timer-Unit-Cluster `0x08008d4c`–`0x08008f3c` registergenau aufgelöst:**
Durch Abgleich der `param_2*0x80`-Indexierung und der Byte-Offsets gegen das reale
`HRTIM_Timerx_TypeDef`/`HRTIM_Master_TypeDef`/`HRTIM_Common_TypeDef`-Speicherlayout (STM32F3/F334
Referenzhandbuch RM0364) konnte der zuvor als "ohne Referenzhandbuch nicht registergenau benennbar"
eingestufte Cluster (s. 13.18) aufgelöst werden:

| Adresse | Name | Register-Zuordnung | Konfidenz |
|---|---|---|---|
| `0x08008d4c` | `HRTIM_MasterTimer_BaseConfig` | schreibt MCR (Prescaler-Bits, Offset `+0x00`) + MPER (`+0x14`) + MREP (`+0x18`) — kein `param_2`, also Master-Timer (kein Timer-Unit-Index) | Hoch |
| `0x08008d72` | `HRTIM_MasterTimer_WaveformConfig` | schreibt MCR (Modus-/Sync-Bits) + BMCR (`+0x3a0` = Common-Block-Basis `0x380`+`0x20`, Burst-Mode-Enable) | Hoch |
| `0x08008e06` | `HRTIM_TimerUnit_OutputConfig` | wählt je nach Output-Bitmaske (`0x1,0x4,0x10,...`=Output1 → SETx1R/RSTx1R `+0x3c/+0x40`; `0x2,0x8,0x20,...`=Output2 → SETx2R/RSTx2R `+0x44/+0x48`, jeweils rel. zur Timer-Unit-Basis) und aktualisiert TIMxOUTR (`+0x64`) — Bitmasken-Werte entsprechen exakt den realen `HRTIM_OUTPUT_Tx1/Tx2`-Konstanten (`0x1…0x800`) | Hoch |
| `0x08008ee4` | `HRTIM_TimerUnit_BaseConfig` | schreibt TIMxCR (Prescaler-Bits) + TIMxPER (`+0x14` rel.) + TIMxREP (`+0x18` rel.) je Timer-Unit (`param_2`-indexiert, `0x80`-Stride) — Pendant zu `HRTIM_MasterTimer_BaseConfig` | Hoch |
| `0x08008f1c` | `HRTIM_TimerUnit_ChopperConfig` | bedingtes Schreiben (nur wenn Ready-Bit gesetzt) auf Offset `+0x6c` rel. zur Timer-Unit-Basis (Bits 6–15) — Lage/Feldbreite passt zu TIMxCHPR (Chopper-Register), Registeridentität nicht 100% referenzhandbuch-verifiziert | Mittel |
| `0x08008f3c` | `HRTIM_TimerUnit_WaveformConfig` | größte Funktion (432B) des Clusters: kombiniert TIMxCR-Modusbits, TIMxFLTR (`+0x68` rel.), TIMxOUTR (`+0x64` rel.), ein Chopper-artiges Feld (`+0x54` rel.) und BMCR-Burst-Enable-Bit (`1<<(1+param_2)`, exakt passend zu `BMCR.TxBM`) — Pendant zu `HRTIM_MasterTimer_WaveformConfig` | Hoch |

Zusätzlich zwei direkt benachbarte, mit dem Cluster über Aufrufe verknüpfte Hilfsfunktionen:

| Adresse | Name | Beschreibung | Konfidenz |
|---|---|---|---|
| `0x08005db0` | `HRTIM_WaitOnFlagUntilTimeout` | Klassisches HAL-Wait-Pattern (`HAL_GetTick`-Timeout-Poll auf ein Bit bei Instance-Offset `+0x388` = Common-Block `0x380`+`0x08`/ISR-Lage; Rückgabe `0`=OK/`3`=TIMEOUT wie `HAL_StatusTypeDef`), strukturell direkt neben den bestätigten HRTIM-Init-Funktionen (`HRTIM_TimerUnit_Init`/`HRTIM_GPIO_AF_Init`) platziert | Mittel |
| `0x08005df0` | `HRTIM_TimerUnit_LockedUpdate` | Software-Lock-Guard (State-Byte-Muster `0/1/2`, analog HAL `Lock`/`State`-Feld) um einen einzelnen Aufruf von `HRTIM_TimerUnit_ChopperConfig` — einziger Aufrufer/Aufgerufener-Beleg für die Cluster-Zugehörigkeit dieser beiden Funktionen | Mittel |

Damit ist der in 13.18 als unklar eingestufte HRTIM-Cluster vollständig benannt (8 von 8 dort offenen Funktionen).

### 14.5 DSP-Funktionen (Regelungstechnik)

- `PI_controller_step` / `PI_controller_reset` — PI-Regler mit Anti-Windup
- `biquad_filter_design` / `notch_filter_design` — IIR-Filter für Netzfrequenz
- `atan_normalized` — Polynomiale atan(x)/π Näherung (Phasenberechnung)
- `compute_reactive_power_ref` — Blindleistungsberechnung aus Power Factor

### 14.6 RTC & Watchdog

- `RTC_Read_Time` — Echtzeituhr via I2C mit BCD-Konvertierung
- `IWDG_Reload` — Independent Watchdog (Schlüssel 0xAAAA)
- `Operating_Hours_Update` — Betriebsstundenzähler (3600s Intervall)

---

## 16. RS485 Modbus Register-Map (`modbus_register_handler`)

### 16.1 Architektur

Die Micro-MCU bedient RS485-Modbus-Anfragen über **zwei getrennte Pfade**:

| Registerbereich | Handler | Beschreibung |
|---|---|---|
| **< 40000** (0x0000–0x9C3F) | `modbus_read_register_block` + Descriptor-Tabelle | Telemetrie (Read-Only) |
| **≥ 40000** (0x9C40+) | `modbus_register_handler` (2842 Bytes) | Steuerung (R/W) |

**Funktionssignatur:**
```c
int modbus_register_handler(void *pRegMap, void *pRequest, int isWrite, int writeValue)
// pRegMap   = Ausgabepuffer für Read-Antwort
// pRequest  = Modbus Register-Adresse (16-bit, direkt als Integer)
// isWrite   = 0: Read (FC03), 1: Write (FC06/FC10)
// writeValue = Zu schreibender Wert (nur bei isWrite=1)
// Return: 0=OK, 1=Read-Only/Modus-Fehler, 2=Unbekanntes Register, 3=Ungültiger Wert
```

**Unterstützte Modbus Function Codes:**
- FC03 (Read Holding Registers): Beide Pfade
- FC06 (Write Single Register): Nur `modbus_register_handler`
- FC10 (Write Multiple Registers): Nur `modbus_register_handler`

### 16.2 Telemetrie-Descriptor-Tabelle (Register < 40000)

Die Telemetrie-Register werden über eine **runtime-aufgebaute Descriptor-Tabelle** bei SRAM `0x200004C0` bedient. Bis zu **70 Einträge** (Loop-Limit `0x46`), je **12 Bytes**:

```c
struct ModbusRegDescriptor {    // 12 Bytes, bei SRAM 0x200004C0 + n*12
    uint16_t base_address;      // +0: Basis-Registeradresse
    uint16_t _pad;              // +2: (Padding)
    uint32_t data_ptr;          // +4: Pointer auf SRAM-Datenarray
    uint8_t  data_type;         // +8: Datentyp (siehe unten)
    uint8_t  elem_size_flags;   // +9: Low-Nibble = Element-Größe (Bytes), High = Flags
    uint8_t  scale_factor;      // +10: Skalierung
    uint8_t  element_count;     // +11: Anzahl Elemente
};
```

**Datentypen** (Byte +8):

| Wert | Typ | Beschreibung |
|---|---|---|
| 0x01 | u8 | Unsigned Byte |
| 0x02 | u16 | Unsigned 16-bit |
| 0x04 | u32 | Unsigned 32-bit |
| 0x11 | i8 | Signed Byte |
| 0x12 | i16 | Signed 16-bit |
| 0x14 | i32 | Signed 32-bit |
| 0x24 | float | 32-bit Float (→ Int-Konvertierung via `VectorFloatToUnsigned`) |
| 0x31 | ASCII | Byte mit Uppercase-Shift (> 0x60 → -0x20) |

**Skalierung** (Byte +10):

| Wert | Operation | Beispiel |
|---|---|---|
| 0 | Keine | — |
| 1 | ×10 | 23.5 → 235 |
| 2 | ×100 | 2.35 → 235 |
| 3 | ÷10 | 235 → 23 |
| 4 | ÷100 | 235 → 2 |
| 5 | Negation | 100 → -100 |

> **Hinweis:** Die Descriptor-Tabelle wird von Code im **externen Flash (0x10000000+)** aufgebaut, der nicht im analysierten Binary enthalten ist. Die konkreten Telemetrie-Register-Adressen sind daher aus dieser Analyse nicht extrahierbar.
> 
> **KORREKTUR 2026-08-16:** Zu absolut. Das **Eintragsformat** ist vollständig aus `modbus_read_register_block` (@0x080118e8) rekonstruiert: 12 Byte je Eintrag — Reg@+0, Quellzeiger(SRAM)@+4, Typ@+8, elem_size@+9, Scale-Code@+0xa, count@+0xb (Scale 0x01=×10 … 0x04=×0.01), max 70 Einträge. Der *Builder* liegt bestätigt im separaten 0x10000000-Bereich (nicht im .bin; FileBytes=Mapped). Die Register-**Inhalte** sind aber — wie beim Control — per Live-Scan + Debug-Print-Feldnamen rekonstruierbar. Siehe `Methodik_und_Meta/Doku_Audit_Offene_Punkte_2026-08-16.md`.

### 16.3 Steuerregister (≥ 40000) — Vollständige Map

Alle Register aus `modbus_register_handler` (0x080124E8), dekodiert aus 788 Zeilen Decompilation.

#### 16.3.1 System-Steuerung (40000–41200)

| Register | Hex | R/W | Beschreibung | Gültige Werte | SRAM | EEPROM |
|---|---|---|---|---|---|---|
| 40000 | 0x9C40 | **W** | FW-Update / Selbsttest | `0x55AA` = FW-Update (work_mode→4), `0x55A1`–`0x55A6` = Selbsttest Slot 1–6 | `inv_work_mode` | — |
| 41000 | 0xA028 | R/W | Reset-Enable-Flag | W: `0x55AA` = Flag setzen; R: Flag-Wert | `DAT_200004B8` | — |
| 41001 | 0xA029 | R/W | Statistiken löschen | W: `0x55AA` = EEPROM_ClearStats(3) + Flag | `DAT_200004B8` | clears |
| 41010 | 0xA032 | R/W | Kalibrierungsstatus | R: Kalibrierflag; W: `800` = Limit 800W + Kalibrierung, `2500` = zurücksetzen | `DAT_20000497` | 0x90 |
| 41100 | 0xA08C | R/W | Konfig-Byte | Wert 0–255, gespeichert in EEPROM | `DAT_200004A5` | 0x101 |
| 41200 | 0xA0F0 | R/W | Backup-Modus | R: invertiert (0 = aktiv); W: `0` = Backup an, `1` = Backup aus | `backup_mode_flag` | — |

#### 16.3.2 Work-Mode & Basis-Config (42000–42011)

| Register | Hex | R/W | Beschreibung | Gültige Werte | SRAM | EEPROM |
|---|---|---|---|---|---|---|
| 42000 | 0xA410 | R/W | Work-Mode Persist | `0x55AA` = ACK, **`0x55BB`** = Speichern in EEPROM | `inv_work_mode` | 0x301 |
| 42010 | 0xA41A | R/W | State-Variable | 0–2 gültig | `DAT_200004B9` | — |
| 42011 | 0xA41B | R/W | Modbus Slave-Adresse | 11–100 (0x0B–0x64) | `DAT_200004BA` | — |

> **Wichtig:** Register 42000 mit Wert `0x55BB` ist der bekannte **RS485-Unlock** — identisch mit dem Control-FW Verhalten (dort Reg 42000 = 0x55AA für Write-Freischaltung).

#### 16.3.3 Schedule / Timer-Slots (43100–43124)

**5 Slots × 5 Register** für zeitgesteuerte Lade-/Entladeplanung. SRAM-Basis: `0x20003E05` (Slot-Stride: 10 Bytes).

| Offset | Register (Slot n) | R/W | Beschreibung | SRAM-Offset | Werte |
|---|---|---|---|---|---|
| +0 | 43100 + n×5 | R/W | End-Zeit | slot×10 + 0x20003E0B | HH:MM als `(hour<<8)\|min` |
| +1 | 43101 + n×5 | R/W | Start-Zeit | slot×10 + 0x20003E09 | HH:MM als `(hour<<8)\|min` |
| +2 | 43102 + n×5 | R/W | Ladeleistung | slot×10 + 0x20003E07 | i16, ±2500 (W) |
| +3 | 43103 + n×5 | R/W | Enable | slot×10 + 0x20003E06 | 0/1 |
| +4 | 43104 + n×5 | R/W | Modus | slot×10 + 0x20003E05 | Betriebsmodus |

**Slot-Adressen:**

| Slot | Register | SRAM-Basis |
|---|---|---|
| 0 | 43100–43104 | 0x20003E05 |
| 1 | 43105–43109 | 0x20003E0F |
| 2 | 43110–43114 | 0x20003E19 |
| 3 | 43115–43119 | 0x20003E23 |
| 4 | 43120–43124 | 0x20003E2D |

#### 16.3.4 Globale Leistungslimits (43133–43134)

| Register | R/W | Beschreibung | Wertebereich | SRAM | EEPROM |
|---|---|---|---|---|---|
| 43133 | R/W | Max. Ladeleistung (global) | 0–2500 W | `DAT_200004A0` | 0x800 |
| 43134 | R/W | Max. Entladeleistung (global) | 0–2500 W | `DAT_200004A2` | 0x802 |

#### 16.3.5 Netz-/Leistungs-Konfiguration (44000–44003)

| Register | R/W | Beschreibung | Wertebereich | Skalierung | SRAM | EEPROM |
|---|---|---|---|---|---|---|
| 44000 | R/W | Netzspannungs-Schwelle | 800–1000 (→ 80.0–100.0V) | ÷10 gespeichert, ×10 gelesen | `DAT_200004A9` | 0x201 |
| 44001 | R/W | Netzfrequenz-Schwelle | 120–300 (→ 12.0–30.0) | ÷10 gespeichert, ×10 gelesen | `DAT_200004AA` | 0x201 |
| 44002 | R/W | Max. Ladeleistung (Kanal) | 0–2500 W (bei Kalibrierung: max 800) | direkt | `DAT_200004AB` | 0x202 |
| 44003 | R/W | Max. Entladeleistung (Kanal) | 0–2500 W (bei Kalibrierung: max 800) | direkt | `DAT_200004AD` | 0x204 |

#### 16.3.6 Netzstandard (44100)

| Register | R/W | Beschreibung | Gültige Werte |
|---|---|---|---|
| 44100 | **W** | Grid-Standard setzen | 0–4 (ruft `Grid_Protection_SetLimits()` auf) |

Vermutete Zuordnung: 0=Deaktiviert, 1=VDE-AR-N 4105, 2=EN 50549, 3=CEI 0-21, 4=AS/NZS 4777

#### 16.3.7 Factory-Mode & Test (45000–45019)

| Register | R/W | Beschreibung | Gültige Werte |
|---|---|---|---|
| 45000 | **W** | Factory-Mode Steuerung | `0x55EE` = Factory-Modus aktivieren, `0x55FF` = Normal-Modus, `0x55DD` = Einstellungen speichern |
| 45010–45018 | **W** | Schedule-Config-Block | Schreibt zu SRAM `0x20003DE8 + (reg-45010)×2` |
| 45019 | **W** | Schedule-Config Speichern | Trigger: speichert 45010-Block nach EEPROM |

#### 16.3.8 Hardware-Test (45200–45300)

| Register | R/W | Beschreibung | Werte |
|---|---|---|---|
| 45200 | **W** | Buzzer-Test | Beliebiger Wert → `buzzer_beep_short()` |
| 45300 | **W** | TIM1-PWM-Test | `0` = aus (Duty 0), `1` = 50% Duty (TIM1 CCR1, ~13 kHz) |

> **Hinweis zu 45300:** TIM1 (0x40012C00) erzeugt ~13 kHz PWM (Prescaler 16, ARR 399). Nur im Factory/Idle-Modus nutzbar. Beim Venus D (passiv gekühlt) **kein Lüfter** — vermutlich Hilfsspannungs-PWM, Gate-Driver-Versorgung, oder ungenutzter Pin für andere Modellvarianten.

#### 16.3.9 Factory Inverter-Steuerung (45400–45402)

Nur im **Factory-Modus** (nach Reg 45000 = 0x55EE) nutzbar:

| Register | R/W | Beschreibung | Werte |
|---|---|---|---|
| 45400 | **W** | LLC-Start (Factory) | `0` = Stop, `1` = Start Modus 1 |
| 45401 | **W** | Inverter-Start (Factory) | `0` = Stop, `1` = Start Modus 2 |
| 45402 | **W** | Off-Grid-Start (Factory) | `0` = Stop, `1` = Start Modus 6 |

#### 16.3.10 Inverter-Betriebssteuerung (45500–45502)

Verhalten **unterscheidet sich** zwischen Normal- und Factory-Modus:

| Register | R/W | Normal-Modus | Factory-Modus |
|---|---|---|---|
| 45500 | **W** | `0` = Stop, `1` = +2000W Einspeisen | `0` = Stop, `1` = Restart Modus 3 |
| 45501 | **W** | `0` = Backup aus + Stop, `1` = Backup an | `0` = Stop, `1` = Restart Modus 4 |
| 45502 | **W** | `0` = Stop, `1` = -2500W (Laden) | `0` = Stop, `1` = Restart Modus 5 |

**Internes Verhalten bei Normal-Modus:**
- Reg 45500 Wert 1: `set_inverter_power(+2000.0f)` → Einspeisen 2kW
- Reg 45502 Wert 1: `set_inverter_power(-2500.0f)` → Laden 2.5kW

#### 16.3.11 Leistungssollwerte (45600–45601)

| Register | R/W | Beschreibung | Werte |
|---|---|---|---|
| 45600 | **W** | Ladeleistung setzen | `writeValue` → `set_inverter_power(-float(value))` (negativ = Laden) |
| 45601 | **W** | Entladeleistung setzen | `writeValue` → `set_inverter_power(+float(value))` (positiv = Einspeisen) |

> Nur im **Normal-Modus** wirksam. Im Factory-Modus werden diese Register ignoriert.

#### 16.3.12 Kalibrierungs-Readback (45603–45604)

| Register | R/W | Beschreibung | EEPROM | Format |
|---|---|---|---|---|
| 45603 | **R** | Kalibrierung Entlade-Energie | 0x950 | BCD (Wh) |
| 45604 | **R** | Kalibrierung Lade-Energie | 0x952 | BCD (Wh) |

#### 16.3.13 Spezialkommandos (46000)

| Register | R/W | Beschreibung | Werte |
|---|---|---|---|
| 46000 | **W** | System-Steuerung | `0x5100` = DAT_20000499=1 (EEPROM 0x900 Persist), `0x04D2` (1234) = Reboot (Inverter aus + Reset-Flags), `0x0929` (2345) = Reboot + DAT_200040C0=2 |

### 16.4 EEPROM-Adressen (Zusammenfassung)

Aus `modbus_register_handler` extrahierte EEPROM-Schreibzugriffe:

| EEPROM-Adresse | Modbus-Register | Beschreibung |
|---|---|---|
| 0x090 | 41010 | Kalibrierungsstatus |
| 0x101 | 41100 | Konfig-Byte |
| 0x201 | 44000–44001 | Netzspannung/-frequenz Schwellen |
| 0x202 | 44002 | Max. Ladeleistung (Kanal) |
| 0x204 | 44003 | Max. Entladeleistung (Kanal) |
| 0x301 | 42000 | Work-Mode (persistiert bei 0x55BB) |
| 0x800 | 43133 | Max. Ladeleistung (global) |
| 0x802 | 43134 | Max. Entladeleistung (global) |
| 0x900 | 46000 | Spezialkommando-Flag |
| 0x950 | 45603 | Kalibrierung Entlade-Energie (R/O) |
| 0x952 | 45604 | Kalibrierung Lade-Energie (R/O) |

### 16.5 Callees von `modbus_register_handler`

| Funktion | Aufrufe | Rolle |
|---|---|---|
| `memcpy_reverse` | 16× | Big-Endian ↔ Little-Endian Konvertierung für Modbus-Wire-Format |
| `thunk_EXT_FUN_100009e8` | 18× | Externe Funktion (Flash 0x10000000+), vermutlich Konfig-Update |
| `EEPROM_WriteVerify` | 14× | Persistente Speicherung mit Verifikation |
| `thunk_EXT_FUN_10000160` (`set_inverter_power`) | 8× | Leistungssollwert an Inverter-Regelung übergeben |
| `thunk_EXT_FUN_10000B58` (`disable_inverter`) | 5× | Wechselrichter abschalten |
| `Grid_Protection_SetLimits` | 1× | Netzschutz-Parameter nach Standard setzen |
| `EEPROM_ClearStats` | 1× | Statistiken löschen |

---

## 17. Fehlercode-Bitmasks (err1 / err2 / war1)

### 17.1 SRAM-Layout

| Variable | SRAM-Adresse | Telemetrie-Offset | Beschreibung |
|---|---|---|---|
| `err1` | `0x200019F4` | +0x08 | Error Code 1 (uint32) |
| `err2` | `0x200019F8` | +0x0C | Error Code 2 (uint32) |
| `war1` | `0x200019FC` | +0x04 | Warning Code 1 (uint32) |

Telemetrie-Block bei `0x200038E8`, gesendet via CAN CMD 0x10.

### 17.2 Bestätigte Bits (aus M4-Firmware)

Nur 4 Bits werden direkt im analysierten Binary gesetzt. Die restlichen Bits werden von der **M0-Firmware** (externer Flash 0x10000000+) über `thunk_EXT_FUN_10006874()` verwaltet.

| Feld | Bit | Hex-Maske | Event | Beschreibung (CN) | Bedeutung |
|---|---|---|---|---|---|
| err1 | 20 | 0x00100000 | 0x33 | CAN通信异常 | CAN-Kommunikationsfehler |
| err1 | 21 | 0x00200000 | 0x3B | 电池上传故障 | BMS meldet Fehler |
| err2 | 7 | 0x00000080 | 0x13 | 电池放电保护 | Batterie-Entladestrom-Schutz |
| err2 | 11 | 0x00000800 | 0x35 | 开关机异常 | Ein-/Ausschalt-Anomalie |

### 17.3 Debug-Log Event-Codes (M4 → M0 Dispatch)

Die folgenden Fehlerbedingungen werden via `debug_log_enqueue` protokolliert und an die M0-FW via `thunk_EXT_FUN_10006874()` weitergeleitet. Die genaue Bit-Zuordnung liegt in der M0-Firmware.

| Event | Chinesisch | Bedeutung |
|---|---|---|
| 0x2A | 电网捕获频率异常 | Netzfrequenz-Erfassungsfehler |
| 0x2B | SPLL频率异常 | Software-PLL Frequenzfehler |
| 0x2C | 电网VRMS异常 | Netz-VRMS abnormal |
| 0x2D | 电网MAX电压异常 | Netz-Maximalspannung Fehler |
| 0x2E | 电压波形异常 | Spannungs-Wellenform Fehler |
| 0x2F | 电池电压异常 | Batteriespannung abnormal |
| 0x30 | 软件锁相环重启 | Software-PLL Neustart |
| 0x31 | 过温异常 | Übertemperatur |
| 0x32 | 电池异常 | Batteriefehler (allgemein) |
| 0x34 | 高压母线电压波动 | HV-Bus Spannungsschwankung |
| 0x36 | 输出电流保护 | Ausgangsstrom-Schutz |
| 0x37 | 高压母线电压波动 | HV-Bus Spannungsschwankung (2) |
| 0x3C | 电池电压异常 | Batteriespannung → Netztrennung |
| 0x3D | 并网电流异常 | Netz-Einspeisestrom Fehler |
| 0x3E | 电网检测异常 | Netzerkennung abnormal / SOC |
| 0x3F | 过流异常 | Überstrom |
| 0x40 | 过压异常 | Überspannung |
| 0x41 | 漏电异常 | Fehlerstrom (Leakage) |
| 0x42 | 电流偏置 | Strom-Offset-Fehler |

> **Hinweis:** Die vollständige Bit→Event-Zuordnung für err1/err2/war1 erfordert Analyse der M0-Firmware (0x10000000+), die nicht im analysierten Binary enthalten ist.

---

## 18. Netzstandard-Codes (`grid_standand`, Register 44100)

### 18.1 Code-Zuordnung

Aus `Grid_Protection_SetLimits` (0x080012E0). Gespeichert in EEPROM 0x206, SRAM `DAT_200004AF`.

| Code | Netzstandard | Anti-Islanding | Besonderheit |
|---|---|---|---|
| **0** | **VDE-AR-N 4105** (Deutschland) | 2 s | Default, dynamische Frequenzschwellen |
| **1** | VDE-AR-N 4105 (Alias) | 2 s | Identisch mit Code 0 |
| **2** | **EN 50549 / CEI 0-21** (EU/Italien) | 60 s | Feste 50Hz-Schwellen |
| **3** | **AS/NZS 4777.2** (Australien/NZ) | 300 s (5 min) | Strenge UV-Schwelle 69V |
| **4** | VDE-AR-N 4105 (Alias) | 2 s | Identisch mit Code 0 |

### 18.2 Schutzparameter im Vergleich

| Parameter | Code 0/1/4 (DE) | Code 2 (EU/IT) | Code 3 (AU/NZ) |
|---|---|---|---|
| **Überspannung Stufe 1** | 265.0 V / 55 s | 253.0 V / 55 s | 255.3 V / 60 s |
| **Überspannung Stufe 2** | 287.5 V / 1 ms | 287.5 V / 1 ms | 264.5 V / 100 ms |
| **Unterspannung Stufe 1** | 103.0 V / 55 s | 103.0 V / 25 s | 69.0 V / 800 ms |
| **Unterspannung Stufe 2** | — / 1 ms | — / 250 ms | — / 100 ms |
| **Überfrequenz 1** | nom + 1.8 Hz | 51.5 Hz | 51.5 Hz |
| **Unterfrequenz 1** | nom − 2.6 Hz | 47.5 Hz | 47.5 Hz |
| **Überfrequenz 2** | nom + 0.8 Hz | 50.5 Hz | 50.5 Hz |
| **Unterfrequenz 2** | nom − 2.4 Hz | 47.55 Hz | 47.55 Hz |
| **Reconnect-Zeit** | 1.000 ms | 1.000 ms | — |
| **Anti-Islanding** | 2.000 ms | 60.000 ms | 300.000 ms |
| **Ramp Rate** | 0.5 | 0.5 | — |

> **Alle Codes sind 230V/50Hz-basiert** — es gibt kein 120/240V 60Hz Profil (USA/UL 1741) in dieser Firmware. Codes 1 und 4 fallen in denselben else-Branch wie Code 0 und sind funktional identisch (reserviert für zukünftige Standards oder regionale Varianten).

---

## 19. Pack-Scheduling (Control-FW Analyse)

### 19.1 Control-FW Status

Die Control-FW (`VNSD-0_app_1492_0702_142136.bin`, 385 KB, 1615 Funktionen) ist in Ghidra geladen und wurde analysiert.

### 19.2 Ergebnis: Keine Pack-Rotation in Control-FW

Die Control-FW enthält **keine Pack-Auswahl-Logik** (welcher physische Akku aktiv ist). Sie verwaltet ausschließlich **zeitbasierte Lade-/Entladeplanung**:

**Zeitslot-Struct** (10 Bytes × bis zu 10 Slots, EEPROM 0x302):

| Offset | Feld | Typ | Beschreibung |
|---|---|---|---|
| +0x00 | `week_set` | u8 | Wochentag-Bitmask (0x00–0x7F, Mo–So) |
| +0x01 | `enable` | u8 | 0/1 |
| +0x02 | `power` | i16 | Ladeleistung (W), negativ = Laden |
| +0x04 | `start_time` | 2×u8 | Stunde, Minute |
| +0x06 | `end_time` | 2×u8 | Stunde, Minute |
| +0x08 | — | 2 | Padding |

**Work-Modes** (EEPROM 0x301):

| Wert | Modus | Beschreibung |
|---|---|---|
| 0 | Self-Use | Eigenverbrauch-Optimierung |
| 1 | Manual/Zeitplan | Zeitslot-gesteuert |
| 5 | Economy/Force Charge | Zwangsladen (SOC 50–51% Hysterese) |

**Modbus-Register (Control-FW TCP):**
- 41500–41515: Zeiteinstellungen (u16 Array)
- 41600–41631: Leistungseinstellungen (u16 Array)
- 43100–43129: Slot-Structs direkt (6 Slots × 5 Register)

**Cloud-TOU-Scheduling:**
- `HTTP_Economy_TOU_Parser` (0x080149F8) lädt Tarif-Zeitpläne von `https://{env}.hamedata.com/external-services/api/v1/schedulings/policies`
- Bis zu 96 Perioden pro Tag (6-Byte Struct: Preis, Sekundärwert, Typ, Flag)

> **Fazit:** Die Pack-Rotation (welcher physische Akku-Slot aktiv ist) wird auf der **Micro-MCU** gesteuert — die 6 Slots × 10 Bytes bei SRAM `0x20003E05` sind ein Micro-MCU Konzept. Die Control-FW kennt nur Zeitpläne und Leistungs-Sollwerte.

---

## 20. EEPROM Register-Map (Vollständig)

### 20.1 Übersicht

Aus `EEPROM_LoadConfig` + allen `EEPROM_WriteVerify`-Aufrufen extrahiert. I2C-EEPROM (Geräteadressen 0xA0/0xA2).

Adresse 0x000 enthält ein **Config-Versions-Flag**: `0x03` = gültige Konfiguration, `0x02` = nur Statistiken, alles andere → Werkseinstellungen.

### 20.2 Vollständige Adresstabelle

| EEPROM | Größe | SRAM-Variable | Beschreibung | Zugriff |
|---|---|---|---|---|
| `0x000` | 1 | Stack | **Config-Version** (0x03=gültig, 0x02=partiell) | LoadConfig (R/W), Inverter_SetMode (W) |
| `0x001` | 47 | `0x20003DD4` | **Haupt-Konfigblock** (Netzparameter, Timer, Scheduling) | LoadConfig (R/W) |
| `0x021` | 20 | `0x20003DE8` | **Schedule-Tabelle** (10×2-Byte TOU-Einträge, Teil von 0x001) | modbus_register_handler (W) |
| `0x080` | 1 | Stack/Tick | **Heartbeat-Timestamp** (HAL_GetTick LSB) | EEPROM_SaveTimestamp (W) |
| `0x090` | 1 | `DAT_20000497` | **Kalibrierungsstatus** (0=normal/2500W, 1=kalibriert/800W) | LoadConfig (R), modbus_handler (W) |
| `0x100` | 5 | `DAT_200004A4` | **Config-Block 1** (EMS-Präsenz + Sub-Felder) | LoadConfig (R/W), CAN_Filter_Setup (W) |
| `0x101` | 1 | `DAT_200004A5` | **Konfig-Byte** (Sub-Feld) | modbus_handler (W) |
| `0x102` | 1 | `DAT_200004A6` | **Backup-Enable-Flag** (Sub-Feld) | modbus_handler (W) |
| `0x150` | 1 | `DAT_20000496` | **CAN-Retry-Zähler** (dekrementiert bei Reconnect, Reset bei 0xFF) | LoadConfig (R), CAN_Filter_Setup (W) |
| `0x200` | 7 | `DAT_200004A9` | **Netz-Konfig-Block** (Spannung/Frequenz + Sub-Felder) | LoadConfig (R/W) |
| `0x201` | 1 | `DAT_200004A9` | **Netzstandard / Spannungsschwelle** (×10 skaliert) | modbus_handler (W) |
| `0x202` | 2 | `DAT_200004AB` | **Max. Ladeleistung** (W) | modbus_handler (W), CAN_Dispatcher (W) |
| `0x204` | 2 | `DAT_200004AD` | **Max. Entladeleistung** (W) | modbus_handler (W), CAN_Dispatcher (W) |
| `0x206` | 1 | `DAT_200004AF` | **Grid-Standard** (0–4, → Grid_Protection_SetLimits) | modbus_handler (W) |
| `0x300` | 124 | `backup_mode_flag` | **Work-Mode-Block** (Backup, Modus, Scheduling, Timer) | LoadConfig (R/W), modbus_handler (W) |
| `0x301` | 1 | `inv_work_mode` | **Inverter Work-Mode** (Sub-Feld) | modbus_handler (W) |
| `0x500` | 48 | `DAT_20003E7F` | **Betriebsstunden / Statistiken** (Laufzeit, Energiezähler) | LoadConfig (R/W), ClearStats (W), `EEPROM_SaveOperatingStats` (W, Tranche 4c) |
| `0x800` | 4 (R) / 2 (W) | `DAT_200004A0` | **Globale Max. Ladeleistung** | LoadConfig (R/W), modbus_handler (W) |
| `0x802` | 2 | `DAT_200004A2` | **Globale Max. Entladeleistung** | modbus_handler (W) |
| `0x900` | 2 (R) / 1 (W) | `DAT_20000499` | **Spezialkommando-Flag** (1=ausgelöst) | LoadConfig (R/W), modbus_handler (W) |
| `0x901` | 1 | Stack | **Kommando-Acknowledge** (Boot: →0x00, Telemetrie: →0x01) | LoadConfig (W), build_telemetry (W) |
| `0x950` | 2 | `DAT_2000049C` | **Kalibrierung Entlade-Energie** (Wh) | LoadConfig (R), modbus_handler (R) |
| `0x952` | 2 | `DAT_2000049E` | **Kalibrierung Lade-Energie** (Wh) | LoadConfig (R), modbus_handler (R) |

### 20.3 Speicher-Regionen

| Region | Bereich | Größe | Inhalt |
|---|---|---|---|
| Config-Version | `0x000` | 1 B | Boot-Validierungsflag |
| Haupt-Config | `0x001–0x02F` | 47 B | Netzparameter, Scheduling (enthält 0x021 Sub-Block) |
| Heartbeat | `0x080` | 1 B | Tick-Timestamp |
| Kalibrierung | `0x090` | 1 B | Normal vs. kalibriertes Leistungslimit |
| Config Block 1 | `0x100–0x104` | 5 B | EMS-Präsenz, Konfig-Byte, Backup-Enable |
| CAN-Zähler | `0x150` | 1 B | Reconnect-Retry-Zähler |
| Netz-Config | `0x200–0x206` | 7 B | Spannungs-/Frequenzschwellen, Leistungslimits, Grid-Standard |
| Work-Mode | `0x300–0x37B` | 124 B | Backup-Flag, Work-Mode, Scheduling-Timer |
| Statistiken | `0x500–0x52F` | 48 B | Betriebsstunden, Energiezähler |
| Leistungslimits | `0x800–0x803` | 4 B | Max. Lade- + Entladeleistung (global) |
| Spezialkommando | `0x900–0x901` | 2 B | Kommando-Flag + Acknowledge |
| Kalibrier-Energie | `0x950–0x953` | 4 B | Entlade- + Ladeenergie (Wh) |

> **22 diskrete Zugriffsadressen** über den Bereich 0x000–0x953. Der Großteil des Zwischenraums (0x030–0x07F, 0x105–0x14F, 0x207–0x2FF, 0x37C–0x4FF, 0x530–0x7FF, 0x804–0x8FF, 0x902–0x94F) ist ungenutzt.

---

## 15. Offene Fragen

| # | Thema | Nächster Schritt |
|---|---|---|
| ~~1~~ | ~~Telemetrie Offset 0x12~~ | ✅ = **grid_pf (0.1Hz, Netzfrequenz)** — aus Control-FW verifiziert |
| ~~2~~ | ~~Telemetrie Offset 0x16~~ | ✅ = **grid_permit (Netzberechtigung)** — aus Control-FW verifiziert |
| ~~3~~ | ~~Telemetrie → Modbus-Mapping~~ | ✅ Control-FW `FUN_08035ffc` + SRAM `0x20014E90` vollständig dekodiert |
| ~~4~~ | ~~Unbekannte Funktionen~~ | ✅ **392/445 Funktionen benannt (88,1%)**, endgültig abgeschlossen 2026-07-14 (korrigiert; die hier ursprünglich genannten 398/445 aus der 07.07.-Massenanalyse waren nie eingecheckt, s. Abschnitt 14) — restliche 53 statisch ausgereizt, s. Memory `project-micro-inverter-fw-naming-status` |
| ~~5~~ | ~~Fehlercode-Bitmasks~~ | ✅ **4 Bits in M4-FW bestätigt**, 19 Event-Codes dokumentiert — Abschnitt 17. Vollständige Bit-Map erfordert M0-FW |
| ~~6~~ | ~~grid_standand Werte~~ | ✅ **3 Standards dekodiert** (VDE 4105, EN 50549/CEI 0-21, AS/NZS 4777) — Abschnitt 18 |
| 7 | **UART-Shell testen** | Leeres Passwort verifizieren (115200 8N1). **Update 2026-07-15:** Versions-Diff gegen VNS 115 zeigt, dass die komplette Shell (`shell_*`, Login/Passwort, >30 Kommandos, Task `vtask_shell`) erst ab VNS 116 existiert — in 115 komplett fehlend. Ein Testgerät mit älterer FW hätte also gar keine Shell zum Testen. S. Abschnitt 21. |
| ~~8~~ | ~~Pack-Rotation Normal-Modus~~ | ✅ Control-FW hat nur Zeitslot-Scheduling, **keine Pack-Auswahl** — Pack-Rotation ist Micro-MCU Konzept (Abschnitt 19) |
| ~~9~~ | ~~Modbus RS485 Register-Map~~ | ✅ **43 Register dekodiert** — Abschnitt 16 (System-Steuerung, Schedule, Factory, Leistungssollwerte, Kalibrierung) |
| ~~10~~ | ~~EEPROM Register-Map~~ | ✅ **22 Adressen, 0x000–0x953** — Abschnitt 20 |

---

## 21. Versions-Diff: VNS 115 → VNS 116 (2026-07-15)

Ghidra Version-Tracking-Diff zwischen `Micro_VNS_115` (190 Funktionen, davon nur 13 benannt — nie
eigenständig analysiert) und `Micro_VNS_116` = dieser Doku-Stand (452 Funktionen, 392 benannt).
Alle verfügbaren Korrelatoren angewendet (Symbol-Name, Exact Bytes/Instructions/Mnemonics, Duplicate
Instructions, Function/Data-Reference, Combined-Reference) — Ergebnis stabil über alle Runden:

| | Anzahl |
|---|---|
| Matched (identisch) | 65 |
| Matched (verändert, nur neue Callees, 0 Byte-Änderung am Funktionskörper selbst) | 65 |
| Nur in 115 (kein Gegenstück in 116 gefunden) | 53 |
| **Nur in 116 (neu gegenüber 115)** | **315** |

Die 315 "neuen" Funktionen sind durch alle Korrelatoren gegangen (auch Call-Graph-basiert) ohne
jede Korrelation zu 115 zu finden — das ist ein starkes Signal für **echten Funktionszuwachs**, nicht
nur Compiler-/Optimierungs-Rauschen. Bestätigt durch String-Diff: **41 komplett neue String-Literale**
in 116 (u. a. BMS-Update-Meldungen, Shell-Kommandonamen), nur 15 "entfernte" Strings — und die sind
größtenteils wortgleiche Format-Strings, die nur um ein führendes Leerzeichen ergänzt wurden (keine
echte Funktionsentfernung).

**Wichtigster Befund: VNS 115 ist ein deutlich abgespecktes Frühstadium der Firmware**, nicht nur ein
Punktrelease. Ganze Subsysteme fehlen komplett und wurden erst bis 116 aufgebaut:

- **BMS-Firmware-Update über CAN/RS485 (komplett neu):** `BMS_FW_Update_CAN_Handler`, `CAN_Start_FW_Update`,
  `OTA_FW_Update_StateMachine`, Ymodem-Empfang (`Ymodem_Receive_Packet`, `Ymodem_Parse_File_Header`,
  `Ymodem_Send_Byte`), Flash-Schreibpfad (`FLASH_EraseSectors`, `FLASH_WriteData`, `FLASH_WaitForOperation`).
  Neue Strings bestätigen exakt den in Abschnitt 9 beschriebenen Mechanismus: "Start to upgrade BMS with CAN",
  "Start to upgrade BMS with 485", "BMS upgrade successful/failed, system will reboot!". **Der komplette in
  Abschnitt 9 dokumentierte Firmware-Update-Mechanismus existiert also erst ab 116** — 115 kann die BMS
  offenbar noch nicht selbst flashen.
- **Modbus-RTU-Interface (komplett neu):** `CRC16_Modbus`, `Modbus_Process_Request`,
  `Modbus_Read_Holding_Registers`, `Modbus_Write_Single_Register`, `Modbus_Write_Multiple_Registers`
  (+ Broadcast-Varianten), `modbus_register_handler`, eigener Task `vtask_modbus`. Die in Abschnitt 16
  dokumentierte 43-Register-Map ist damit ebenfalls erst ab 116 ansprechbar.
- **Passwortgeschützte Shell/CLI (komplett neu):** kompletter `shell_*`-Namensraum (Login, Passwort-Prüfung,
  History, Tab-Complete, Parser, >30 Kommandos als Strings: `update`, `update_bms`, `reset_memory`,
  `bat_mode`, `set_power`, `io_show`/`io_set`, `dac_high`/`dac_low`, `rtos_status`, `version`, u. v. m.),
  eigener Task `vtask_shell`. Direkt relevant für offene Frage #7 oben.
- **CAN-Ökosystem stark ausgebaut:** `BMS_CAN_Parser`, `EMS_Inverter_CAN_Dispatcher`, komplette
  TX-Queue/Dispatch-Kette (`CAN_TX_ReadQueue/SendMessage/SendCommand/SendFrame/ProcessQueue`,
  `CAN_BuildArbID`), `CAN_RX_DispatchTask`, `CAN_Filter_Setup`, eigene Tasks `vtask_can`/`vtask_can_receive`
  sowie der komplette `HAL_CAN_*`-Treiber (Init/DeInit/AddTxMessage/GetRxMessage/IRQHandler/RxFifoCallback).
- **Hardware-Treiber-Ausbau:** HRTIM (Master- + Timer-Unit Base/Waveform/Output/Chopper-Config, für die
  PWM-Erzeugung der Wechselrichter-Brücke), volle TIM1/4/7/20-Konfiguration (OC1–6, IC1–4), DMA-Layer,
  erweiterter ADC (Kalibrierung, DMA-Start, `ADC_ProcessSamples`), I2C-Master-Layer, `DAC_Init`,
  Buzzer-Steuerung, EEPROM-Subsystem (Load/Write/Read/SaveTimestamp/ClearStats/SaveOperatingStats), IWDG
  (Watchdog), 2-Kanal-NTC-Temperaturkonvertierung.
- **Regelungs-/Steuerlogik erweitert:** `Inverter_SetMode`, `Inverter_Grid_Control`,
  `Grid_Protection_SetLimits`, `build_telemetry_block`, `Mode3_RoundRobin_Timer`.

**Cross-Check mit der Naming-Kampagne:** Ein Großteil der 315 neuen Funktionen ist bereits benannt (die
oben genannten); die weiterhin unbenannten `FUN_*`-Adressen darunter decken sich mit den seit 2026-07-10
als "statisch ausgereizt" eingestuften 53 Restfunktionen (Dead-Code-Familie, HRTIM-Feinheiten ohne
Referenzhandbuch, Interworking-Veneers, Padding) — konsistent, kein neuer Handlungsbedarf.

**Nachträglich vollständig analysiert (2026-07-15, auf Nutzerwunsch, für Dokumentationszwecke):** Alle 53
nur-in-115-Funktionen wurden einzeln per `get-decompilation`/`find-cross-references` geprüft (2 parallele
Subagenten, je eine Hälfte). Ergebnis:

| Kategorie | Anzahl | Beschreibung |
|---|---|---|
| Thunk/Veneer | 13 | reine Sprung-Trampoline, darunter 4× `thunk_EXT_FUN_*` |
| Genuine Funktion, sinnvoller Zweck erkennbar | ~30 | siehe Namensvorschläge unten |
| Ghidra-Artefakt (überlappendes Sprungziel-Fragment einer Nachbarfunktion) | ~8 | keine eigenständige Funktion |
| Trivialer Stub | 2 | 2-Byte-Endlosschleife (Halt-Trap) bzw. toter 2-Byte-Thunk |

**Bestätigtes Muster — CCM-SRAM-Trampoline:** Die 4 `thunk_EXT_FUN_*` (0x08000964, 0x08000982, 0x080009aa,
0x080009be) springen alle nach `0x1000xxxx` — außerhalb des geladenen Flash-Images, ins STM32F3-CCM-SRAM.
Exakt das gleiche Muster wie die bereits aus der Control-FW und aus VNS 116 selbst bekannten
RAM-residenten Flash-Self-Programming-Routinen (dürfen nicht aus der gerade zu löschenden Flash-Bank
laufen). Haupt-Caller ist `FUN_0800d83c` (Fehlercode-Ableitung/Regelschritt) — passt inhaltlich zu
OTA/Flash-Kontext.

**Wichtigster Einzelfund: ein komplett verwaister „Legacy"-Regel-Subsystem-Block.** Fünf zusammenhängende
Funktionen — `FUN_08017000` (302 B), `FUN_08017800` (2480 B, größte Funktion im gesamten 53er-Set),
`0x0801aec0`, `0x0801b000`, `0x0801b030` — bilden zusammen eine vollständige alte Batterie-Lade-Strom-Limit-
Regelschleife (Temperatur-/Spannungskurven, Alarmflags, State-Init). Diese Gruppe hat **0 Aufrufer im
gesamten 115-Image**, auch nicht über Funktionszeiger/Konstanten (`find-constant-uses` geprüft) — sie war
also bereits **innerhalb von 115 selbst toter Code**, nicht erst beim Übergang zu 116 entfernt. In 116
existiert dafür kein Gegenstück mehr — konsistent mit einer bereits vor 115 begonnenen, aber nie
abgeschlossenen Ablösung dieser Regellogik durch die in Abschnitt 8 dokumentierte aktuelle
Wechselrichter-Regelung. Bemerkenswert: die von diesem Cluster mitgenutzte Hilfsfunktion `0x0800eb8c`
(Sleep-Watchdog/CAN-Filter-Reinit) ist selbst NICHT tot — sie wird zusätzlich von aktivem Code außerhalb
der 53er-Liste aufgerufen (0x08018558, 0x0801873a) und geteilt genutzt.

**Zweiter Fund: doppelte Debug-Dump-Infrastruktur.** `0x0800cc56` und `0x0800d14c` sind zwei fast
identische Diagnose-Dump-Routinen (ctl_state/llc_run_state/inverter_run_state, Grid-/Batteriewerte), beide
nur über tote/isolierte Thunks erreichbar — vermutlich ein Vorläufer der in 116 aktiven, produktiven
Debug-Ausgabe.

**Vollständige Namensvorschläge (nicht in Ghidra angewendet, da 115 kein aktiv gepflegtes Projekt ist):**

| Adresse | Vorschlag | Kategorie |
|---|---|---|
| 0x08000368 | `Mem_Fill_Bytes` | genuine |
| 0x08002a04 | `ParamBlock_Mode_Reset` | genuine |
| 0x08002e0c | `Apply_ParamBlock_Cmd0x500` | genuine |
| 0x080032ac | `Flash_CR_WaitBusy_And_Lock` | genuine |
| 0x0800555e | `EXTI_Fault_LogAndDisableIRQ` | genuine |
| 0x0800675c | `NVIC_EnableIRQ` | genuine (CMSIS-Standard) |
| 0x08006778 | `NVIC_SetPriority` | genuine (CMSIS-Standard) |
| 0x080068dc | `Peripheral_Clock_Enable_WaitReady` | genuine |
| 0x0800699c | `Timer_ChannelConfig_ApplyFromStruct` (unsicher) | genuine |
| 0x08007084 | `HRTIM_Channel_Enable_Callback` | genuine, per Funktionszeigertabelle erreicht |
| 0x080096b8 | `UART_ErrorFlag_WaitAndRecover` | genuine |
| 0x08009774 | `UART_ErrorFlag_Variant_A` | genuine, per Vtable erreicht |
| 0x08009792 | `UART_ErrorFlag_Variant_B` | genuine, per Vtable erreicht |
| 0x0800bf8c | `Channel_State_Transition_1to2_Apply` | genuine |
| 0x0800cc56 | `Debug_PrintSystemStatus_Dump` | genuine, isoliert/tot |
| 0x0800d000 | `Spinlock_AcquireExclusive_SetBusyFlag` | genuine, isoliert/tot |
| 0x0800d14c | `Debug_PrintSystemStatus_Dump_Variant` | genuine, isoliert/tot |
| 0x0800d83c | `InverterControl_FaultCode_And_ChargeGate_Update` | genuine, isoliert/tot |
| 0x0800df00 | `Printf_DoubleToDecimalDigits` | genuine |
| 0x0800e084 | `Printf_FormatString_Core` | genuine |
| 0x0800eb00 | `Fault_UpdateIndicatorAndTimingState` | genuine, nur via Legacy-Cluster |
| 0x0800eb8c | `PowerMode_SleepWatchdog_And_CanFilterReinit` | genuine, **aktiv genutzt** (nicht Teil des toten Clusters) |
| 0x0800f8d8 | `CLI_ParseFloatLiteral` | genuine, isoliert/tot |
| 0x0800f944 | `Fraction_ScaleAndSign_Normalize` (unsicher) | genuine, isoliert/tot |
| 0x0800fff6 | `Output_SendCRLF_ViaStreamHandle` | genuine, isoliert/tot |
| 0x08017000 | `Legacy_ChargeVoltageFault_StateMachine` | genuine, **toter Legacy-Cluster** |
| 0x08017800 | `Legacy_BatteryChargeCurve_ControlLoop` | genuine, **toter Legacy-Cluster** |
| 0x0801aec0 | `AlarmFlags_EvaluateAndClear` | genuine, **toter Legacy-Cluster** |
| 0x0801b000 | `Legacy_ThresholdCheck_TriggerFault8` | genuine, **toter Legacy-Cluster** |
| 0x0801b030 | `Legacy_ChargeController_State_Init` | genuine, **toter Legacy-Cluster** |

**Ghidra-Artefakte (überlappende Fragmente, keine eigenständigen Funktionen — analog zum bereits aus der
Control-FW bekannten `0x08008000`-Muster):** `0x080041f4`/`0x0800424c`/`0x080042b0`/`0x080042ca` (vier
Fragmente EINER größeren, selbst unreferenzierten EXTI-Init-Routine — STM32F3-Layout bestätigt über
IMR2/EMR2/RTSR2/FTSR2), `0x0800676c` (Duplikat-Tail von `NVIC_EnableIRQ`), `0x08006980` (Duplikat-Anfang
von `0x0800699c`), `0x0800708c` (Duplikat-Körper von `HRTIM_Channel_Enable_Callback`), `0x0800ebdc`
(Duplikat-Tail von `PowerMode_SleepWatchdog_And_CanFilterReinit`), `0x0801af00` (ausgelagerter gemeinsamer
Tail-Block von `AlarmFlags_EvaluateAndClear`, nur per bedingtem Sprung erreicht, nie per Call).

**Fazit:** Von den 53 nur-in-115-Funktionen sind die meisten entweder (a) bereits in 115 selbst totes/
verwaistes Legacy-Regelcode (der komplette Batterie-Lade-Kurven-Cluster), (b) Ghidra-Doppel-Artefakte ohne
eigene Existenz, oder (c) Low-Level-Hilfsroutinen (NVIC/EXTI/Debug-Print/UART-Fehlerbehandlung), die in 116
vermutlich einfach umstrukturiert/ersetzt wurden (die entsprechenden Themenbereiche existieren in 116
weiterhin, nur mit anderen, in Abschnitt 21 oben bereits erfassten Funktionen). Es gibt **keinen Hinweis
auf tatsächlich verlorene Funktionalität** zwischen 115 und 116 — im Gegenteil, 116 ist in jeder Hinsicht
ein Ausbau.

---

*Erstellt via Ghidra + ReVa MCP — Statische Analyse ohne Live-Gerät*
