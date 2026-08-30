# Command-Register-Block 45000–46000 (Control FW v150)

> **Firmware:** `VNSD-0_app_0150_0805_115146.bin` (v150) · ARM Cortex-M, FreeRTOS
> **Quelle:** Statische Analyse `Write_Handler` (`FUN_08051d14`, 0x08051d14) in Ghidra
> **Stand:** 2026-08-14
> **Adressierung:** direkt (PDU = Register-Nummer, kein Offset) · Write via **FC06/FC10**

---

## 1. Was dieser Block ist

Die Register **45000–46000** sind **kein** normaler Steuer-Registersatz wie
42010 (`force_mode`) oder 43000 (`work_mode`), sondern ein **Service-/Engineering-
Kommando-Interface**. Fast jedes Kommando übersetzt einen Modbus-Write in eine
**interne CAN-Bus-Nachricht an den Wechselrichter-MCU** — gebaut über
`CAN_Build_Arbitration_ID(funccode, …)` + `Register_WriteValue()`. Einige wenige
Kommandos schalten stattdessen **lokale Hardware** (GPIO-Pins, Relais, CH395-
Netzwerkchip, BLE) oder lösen **OTA/EEPROM** aus.

Eigenschaften des Blocks:

- **Write-only** (Lesen → Modbus-Exception `2`), außer den drei Read-Registern
  45603/45604/45605.
- Ungültige Werte → Exception `3`.
- Viele Funktionen **überschneiden sich** mit den offiziellen Steuerregistern
  (42010/42020/43000) — nur auf niedrigerer, direkterer Ebene.
- **Mehrere sind gefährlich** (OTA, Relais, GPIO, SMR-ADC) und ohne
  Hardware-Verständnis nicht zu benutzen.

### CAN-Funktionscodes (beobachtet)

| CAN-Func | Bedeutung | genutzt von |
|---|---|---|
| 0x01 | Inverter On/Off | 45021, (45020, 45000) |
| 0x06 | Flag-Register 0x06 | 45002 |
| 0x50 | Feature-Enable | 45000 |
| 0x52 | WorkMode (1 Byte) | 45004 |
| 0x55 | Config-Param 55 | 45007 |
| 0x56 | Leistungs-**Sollwert** (u32) | 45008 |
| 0x57 | Flag 0x57 (Ein/Aus) | 45009 |
| 0x58 | Leistungs-**Limit** (u32) | 45010 |
| 0xC1 | Zähler-Reset | 45001 |
| 0xFB | Reg 0xFB | 45022 |
| 0xFE | Reg 0xFE | 45023 |

---

## 2. ⚠️ Adress-Drift 149.2 → v150

Die frühere `Write_Handler_Register_Map.csv` wurde aus **FW 149.2** abgeleitet.
Die dort genannten `FUN_`-Ziel­adressen (z. B. `FUN_08005f94`, `FUN_08005ccc`,
`FUN_08002e10`) sind in v150 **verschoben** und zeigen dort auf andere Funktionen.
Der `Write_Handler` selbst hat sich geändert (Ghidra-Similarity 149.2→150 = 0.629).

**Register-Nummern und Grundbedeutung bleiben gültig** — die konkreten Funktions-
namen/Adressen unten stammen aus v150. Die CSV wurde entsprechend korrigiert.

Zusätzlich: Der **Kommentar-Header im Binär-`Write_Handler`** benennt die Read-
Register falsch (nennt „45539–45541" und „45597/0xB28D"). Der tatsächliche Code
adressiert **45603/45604 (0xB223/0xB224)** und **45605 (0xB225)** — passend zur
Register-Map-CSV, nicht zum Kommentar.

---

## 3. Kommando-Tabelle (v150-verifiziert)

| Reg | Name | Werte | Wirkung | Backend |
|---|---|---|---|---|
| 45000 | cmd_system_control | `0x55EE` / `0x55BB` (sonst Err 3) | `Config_Feature_Enable(0)` bzw. `(1)` + Inverter On/Off 0x01; Statusbyte=2 | CAN 0x50 |
| 45001 | cmd_reset_init | beliebig | `Config_Counters_Reset()` + `Config_Write_ResetFlag()` | CAN 0xC1 |
| 45002 | cmd_function_1 | beliebig | `Inverter_Set_Flag_Reg_0x06(1)` | CAN 0x06 |
| 45003 | cmd_function_2 | beliebig | `Config_Param51_Reset()` | CAN |
| 45004 | **cmd_mode_select** | `1`/`2`/`3` | `Config_WorkMode_Set(1/2/3)` — Wert 1:1 als Modus | CAN 0x52 (1 B) |
| 45005 | cmd_function_3 | beliebig | `Config_Param53_Activate()` | CAN |
| 45006 | cmd_function_4 | beliebig | `Config_PostWriteCommit()` | CAN |
| 45007 | cmd_function_5 | beliebig | `Config_Param55_Set(1)` | CAN 0x55 |
| 45008 | **cmd_set_power_a** | 1–2500 W; >32767 = neg. (Wert−65535); 0/2501–32767 ignoriert | `Config_PowerSetpoint_Write()` — **Sollwert** ±2500 W | CAN 0x56 (u32) |
| 45009 | cmd_enable_disable_a | `0`/`1` | `Inverter_Set_Flag_Reg_0x57(0/1)` | CAN 0x57 |
| 45010 | **cmd_set_power_b** | wie 45008 | `Inverter_Set_PowerLimit_Reg_0x58()` — **Limit** ±2500 W | CAN 0x58 (u32) |
| 45011 | **cmd_mode_select_ext** | 1–9 (>9 Err 3) | `WorkMode_Register_Write()` mit Remap **1→1, 2→2, 3→4, 4→0, 5→5, 6–9→0** | 8-B Reg-Write |
| 45012 | cmd_set_power_default | 1–29999 W; sonst → **2000 W** | `Inverter_Power_Setpoint_Apply()` → über **I2C** (nicht CAN!) | I2C-Sync |
| 45020 | cmd_smr_relay_adc | 1–3999 (sonst keine Aktion) | On/Off 0x01, 3 ms Delay, 2 ADC-Werte skaliert, `Inverter_RS485_Command_Send(1,1,wert,…)` | RS485 + ADC |
| 45021 | cmd_smr_enable | `0`/`1` | `Inverter_Set_OnOff_Reg_0x01(1)` bzw. `(1,0)` | CAN 0x01 |
| 45022 | cmd_function_6 | beliebig | `Inverter_Set_Reg_0xFB(1)` | CAN 0xFB |
| 45023 | cmd_gpio_debug_1 | beliebig | `Inverter_Set_Reg_0xFE(1)` | CAN 0xFE |
| 45024 | cmd_gpio_debug_2 | beliebig | `Inverter_RS485_Cmd_Reset(1)` | RS485 |
| 45025 | cmd_gpio_pin_0x400 | `1`=setzen / `0`=löschen | GPIO-Bit **0x400** via Struct-Feld | lokale HW |
| 45026 | cmd_gpio_pin_0x8000 | `1`/`0` (**invertiert!**) | GPIO-Bit **0x8000**, Logik gegenüber 45025 vertauscht | lokale HW |
| 45027 | cmd_wifi_reset | beliebig | `Register_ClearOnWrite(1)` (CH395/Netzwerk reset) | lokale HW |
| 45028 | cmd_relay_contactor | beliebig | `Config_Apply_SingleReg(2)` | Relais |
| 45029 | cmd_debug_flag | `1`/`0` | Setzt/löscht SRAM-Flag `*(DAT_08052ddc+0x21)` | lokal |
| 45030 | cmd_ble_enable | `1`=ein / `0`=aus | `Config_Apply_SingleReg(0xB)` bzw. `(0xC)` | BLE |
| 45031 | cmd_smr_relay_retry | nur `1` | SMR-Status `==0xAA` prüfen; `Config_Apply_SingleReg(4)` wenn ok, sonst `(0xA0)` + bis 50× 100 ms poll; Err 3 bei Timeout | Relais + Retry |
| 45603 | adc_version_bcd_ch1 | **read-only** | Queues leeren, `Inverter_Clear_Reg_0x13()`, 200 ms warten, **BCD**-Version Kanal 1 (`DAT_08052de8`) | Queue/ADC |
| 45604 | adc_version_bcd_ch2 | **read-only** | wie 45603, Kanal 2 (`DAT_08052dec`) | Queue/ADC |
| 45605 | status_query | **read-only** | `CH395_SPI_ReadByte()` — Statusbyte vom **CH395-Netzwerkchip** über SPI | SPI |
| 46000 | **ota_command** | `0x5100`=EEPROM-Flag (Addr 0x900); `0x4D2`(1234)=Mode 1; `0x929`(2345)=Mode 4; `0xD80`(3456)=Mode 3; `0x11D7`(4567)=Mode 2 | OTA-Mode-Flag `DAT_08052df4` bzw. EEPROM-Flag `DAT_08052df0` | OTA/EEPROM |

> Register **45013–45019** sind reserviert und geben Exception `2` (illegal data address) zurück.

---

## 4. Die drei „Set-Power"-Varianten

Optisch identisch (alle 1–2500 W, signed), aber **drei verschiedene Backends**:

| Reg | Funktion | Pfad | Semantik |
|---|---|---|---|
| 45008 | `Config_PowerSetpoint_Write` | CAN-Func **0x56** | Leistungs-**Sollwert** an Inverter |
| 45010 | `Inverter_Set_PowerLimit_Reg_0x58` | CAN-Func **0x58** | Leistungs-**Limit** |
| 45012 | `Inverter_Power_Setpoint_Apply` | **I2C**-Registersync | separater I2C-Pfad, Default-Fallback 2000 W |

Das erklärt die scheinbare Redundanz: Sollwert vs. Limit vs. I2C-gekoppelter Pfad.

---

## 5. Modus-Auswahl: 45004 vs. 45011

- **45004** (`cmd_mode_select`): sendet Wert 1/2/3 direkt per CAN-0x52. Nur 1–3 gültig.
- **45011** (`cmd_mode_select_ext`): akzeptiert 1–9, **mappt aber um** und schreibt
  einen 8-Byte-WorkMode-Record. Das interne Modus-Codeset ist **nicht** deckungs-
  gleich mit der Eingabe:

  | Eingabe | 1 | 2 | 3 | 4 | 5 | 6–9 | >9 |
  |---|---|---|---|---|---|---|---|
  | intern | 1 | 2 | **4** | **0** | 5 | 0 | Error 3 |

---

## 6. Gefahren-Hinweis

Diese Register sind Werks-/Debug-Funktionen ohne Missbrauchsschutz:

- **46000 (OTA)** — kann Update-Prozess auslösen.
- **45028 / 45031 (Relais/Contactor)** — schaltet Leistungs-Hardware.
- **45020 (SMR-Relay + ADC)** — Relay-Schaltung + Messung.
- **45023–45027 (GPIO / WiFi-Reset)** — direkter Pin-/Modul-Eingriff.

Auf produktiven Geräten nur die klar verstandenen Register (Mode/Power/BLE/Version)
verwenden — deren Funktion ist ohnehin weitgehend über die offiziellen Register
42010/42020/43000 abgedeckt.

---

## 7. Referenzen

- `Write_Handler` @ `0x08051d14` (v150) — Dispatch für gesamten 40000–47400-Bereich
- Dispatch-Selektor 45000-Block: `iVar11 = param_2 − 45000` (switch), 45000 selbst über `uVar8 == 0x76a`
- `Modbus_RS485_TCP/Scan_Logs/Write_Handler_Register_Map.csv` — vollständige Write-Register-Map (v150-korrigiert)
- `Control_FW/Control_FW_Analyse_app_0150_0805_115146.md` — v150-Gesamtanalyse
