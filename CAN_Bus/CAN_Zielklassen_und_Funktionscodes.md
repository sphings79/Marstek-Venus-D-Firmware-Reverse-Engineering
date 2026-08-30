# Interner CAN-Bus: Zielklassen und Funktionscodes

**Stand 2026-08-22.** Statische Analyse von drei Images:
`VNSD-0_app_0150_0805_115146.bin` (Control v150),
`Micro_VNS_116_vd_inv_app_0116_0702_ota_163439.bin` (Wechselrichter v116),
`BMS_118_20260119100535e43806957.bin` (BMS v118).

Dieses Dokument beschreibt den **internen** CAN-Bus zwischen den MCUs. Nicht zu
verwechseln mit dem externen Modbus (TCP/RS485) oder den internen RS485/UART-
Strecken — siehe die Begriffswarnung in der Projekt-README.

---

## 1. Aufbau der Arbitration-ID

Alle Sendestellen im Control laufen über `CAN_Build_Arbitration_ID`
(`0x08032F20`):

```c
return (param_4 & 0xfff0ffff) + 0x10000 & 0xe00f0000 | param_1 & 0xff |
       (param_2 & 0xf) << 8 | (param_3 & 0xf) << 0xc | (param_4 & 0x1f) << 0x18;
```

| Bits | Feld | Bedeutung |
|---|---|---|
| 0–7 | `param_1` | **Funktionscode** |
| 8–11 | `param_2` | Quelle / Knotenindex |
| 12–15 | `param_3` | **Zielklasse** |
| 16–19 | abgeleitet aus `param_4` | Sequenz (`+0x10000`, maskiert mit `0xe00f0000`) |
| 24–28 | `param_4 & 0x1f` | Zähler / Flags |

Auch bei `param_4 = 0` bleibt Bit 16 gesetzt: `(0 + 0x10000) & 0xe00f0000 =
0x10000`. Jede so gebaute ID ist damit **> 11 Bit**, also ein Extended Frame.

Beispiel `Inverter_Set_Schedule_Reg` mit `(0x30+idx, 1, 4, 0)`:

```
ID = 0x10000 | (4 << 12) | (1 << 8) | (0x30+idx) = 0x00014130 + idx
```

Der Empfänger bestätigt das Layout unabhängig: Der BMS-Dispatcher prüft
`(ushort)id >> 0xc == 3` (Zielklasse) und `(id & 0xfff) >> 8` (Knotenindex).

---

## 2. Zielklassen

46 Aufrufer von `CAN_Build_Arbitration_ID` im Control v150:

| Zielklasse | Knoten | Sendestellen | Beleg |
|---|---|---|---|
| **4** | Wechselrichter (Micro/VNS) | 34 | `EMS_Inverter_CAN_Dispatcher` behandelt genau diese Codegruppe |
| **3** | BMS | 5 | `CAN_RX_Command_Dispatcher` verlangt Zielfeld `== 3` |
| **2** | RS485-Pfad zum Wechselrichter | 13 | ausschließlich `Inverter_RS485_*`-Funktionen |
| **1** | Control selbst | 1 | nur `Debug_Mode_Set(0xC2, 0, 1)` |

`Debug_Mode_Set` sendet `0xC2` an alle vier Klassen (1, 2, 3, 4) — ein
Broadcast-Muster, das die Klassenzuordnung zusätzlich stützt.

---

## 3. Funktionscodes je Zielklasse

### Ziel 4 — Wechselrichter

Gesendet vom Control:

| Code | Sendestelle |
|---|---|
| `0x01` | `Inverter_Power_Setpoint_Calc` |
| `0x02` | `Config_Mode_Apply` |
| `0x03` | `Inverter_Write_Reg_0x03_U32Value` |
| `0x04` | `Inverter_Write_Reg_0x04_U32Value` |
| `0x05` | `Inverter_Set_Flag_Reg_0x05` |
| `0x06` | `Inverter_Set_Flag_Reg_0x06` |
| `0x07` | `Inverter_Write_Reg_0x07_Value` |
| `0x08` | `Inverter_Set_BLEMode_Reg_0x08` |
| `0x0A` | `Config_Param0A_Relay` |
| `0x10` | `FUN_080289DA` |
| `0x11` | `FUN_080289B8` |
| `0x12` | `Inverter_Clear_Reg_0x12` |
| `0x13` | `Inverter_Clear_Reg_0x13` |
| `0x14` | `FUN_08029964` |
| `0x16` | `FUN_0802D208` |
| `0x17` | `FUN_0802D27C` |
| `0x30`–`0x3E` | `Inverter_Set_Schedule_Reg` (Registerblock 46500–46544) |
| `0x40`–`0x43` | `FUN_0802D2F4` |
| `0x50` | `Config_Feature_Enable` |
| `0x51` | `Config_Param51_Reset` |
| `0x52` | `Config_WorkMode_Set` |
| `0x53` | `Config_Param53_Activate` |
| `0x54` | `Config_PostWriteCommit` |
| `0x55` | `Config_Param55_Set` |
| `0x56` | `Config_PowerSetpoint_Write` |
| `0x57` | `Inverter_Set_Flag_Reg_0x57` |
| `0x58` | `Inverter_Set_PowerLimit_Reg_0x58` |
| `0x60` | `Inverter_Set_WorkMode_Reg_0x60` |
| `0xC1` | `Config_Counters_Reset` |
| `0xC2` | `Debug_Mode_Set` |
| `0xCB` | `FUN_08029940` |

Behandelt vom Wechselrichter (`EMS_Inverter_CAN_Dispatcher`, `0x08001940`,
27 Codes):

```
0x01 0x02 0x03 0x04 0x05 0x06 0x07
0x10 0x11 0x12 0x13 0x16
0x50 0x51 0x52 0x53 0x54 0x55 0x56 0x57 0x58 0x60
0xC1 0xC2 0xC3 0xCB 0xCE
```

Der Dispatcher liest den Code als `param_1 & 0xff` — dieselbe Bitposition, die
der Builder füllt. Es gibt **keinen Default-Zweig**: ein unbekannter Code fällt
ohne Reaktion, ohne Fehler und ohne ACK hinten heraus.

### Ziel 3 — BMS

Gesendet vom Control: `0x0A` (`Register_ClearOnWrite`), `0xC1`
(`Config_Counters_Reset`), `0xC2` (`Debug_Mode_Set`), `0xC4`
(`Config_Write_Category0xC4`), `0xCF` (`FUN_0800653C`).

Behandelt vom BMS (`CAN_RX_Command_Dispatcher`, `0x0800C928`, 8 Codes):

```
0x01 0x02 0x03 0x04 0x05 0x0A 0xC4 0xCE
```

Reihenfolge der Prüfungen im BMS — das Zielfeld zuerst:

```c
if ((ushort)local_10 >> 0xc == 3) {              // 1. Zielklasse muss 3 sein
    bVar1 = (byte)local_10;                      // 2. erst dann Funktionscode
    if (((local_10 & 0xfff) >> 8 == *DAT_0800CA74) ||   // 3. eigener Knotenindex
        ((local_10 & 0xfff) >> 8 == 0xf) ||             //    oder Broadcast 0xF
        ((local_10 & 0xfff) >> 8 == 0)) { ... }         //    oder 0
```

Eine Nachricht mit falscher Zielklasse wird verworfen, **bevor** der
Funktionscode überhaupt gelesen wird.

### Zweiter BMS-Empfangspfad — festes ID-Schema

`CAN_RX_Handler` (`0x08005A40`) benutzt ein anderes, hart kodiertes Schema und
vergleicht vollständige IDs statt Felder:

| ID | Wirkung |
|---|---|
| `0x100101AA` | `CAN_CMD_01_Handler` |
| `0x100201AA` | `CAN_CMD_02_Handler` |
| `0x100301AA` | Balancing-Register (`KA495XX_Write_Balancing_Register`) |
| `0x100401AA` | `CAN_CMD_04_Handler` |
| `0x180102AA` | Referenz-ID, Offsets `+0x100/+0x200/+0x300/+0x400/+0xFD00` |

Das niedrige Halbwort ist fest (`0x01AA` / `0x02AA`), die Kommandonummer sitzt
in Bits 16–19. Dieses Schema ist **nicht** das des Control-Builders und gehört
zur Kommunikation zwischen den Batteriepacks. Beide Pfade hängen an
`APP_CAN_RX_Task_Process`.

---

## 4. Abdeckungslücken

Der Abgleich Sender ↔ Empfänger deckt sich **nicht** vollständig.

### Gesendet, aber vom Empfänger nicht behandelt

| Ziel | Codes | Bemerkung |
|---|---|---|
| 4 | `0x08`, `0x0A`, `0x14`, `0x17` | Einzelbefehle ohne Zweig im Micro v116 |
| 4 | `0x30`–`0x3E` | Schedule-Block, Quelle: Modbus-Register 46500–46544 |
| 4 | `0x40`–`0x43` | `FUN_0802D2F4`. Der Control hat Empfangspuffer dafür, sie blieben leer (siehe unten) |
| 3 | `0xC1`, `0xC2`, `0xCF` | BMS-Dispatcher kennt `0xCE`, aber nicht `0xCF` |

**23 der an Ziel 4 gesendeten Codes haben in v116 keinen Empfänger.** Das ist
kein Randfall, sondern ein durchgehendes Muster.

### Behandelt, aber vom Control nie gesendet

| Ziel | Codes | Wahrscheinliche Erklärung |
|---|---|---|
| 4 | `0xC3`, `0xCE` | `0xCE` wird von `Register_WriteCategory0xCE` mit variabler Zielklasse gesendet |
| 3 | `0x01`–`0x05`, `0xCE` | Pack-zu-Pack-Verkehr: Absender ist das Master-Pack, nicht der Control |

### Gegenrichtung: `0x40`–`0x43` kommen beim Control an

Der Control ist für diese Codes auch **Empfänger**. `CAN_FrameDispatcher` →
`Telemetry_Register_Dispatcher` (`0x0802FD9C`) liest den Code als `id & 0xff`
und reicht ihn an `Telemetry_Store_EnergyCounters` (`0x0802FD38`) weiter:

```c
if      (param_1 == '@') { /* 0x40 -> 8 Byte nach 0x20000168 */ }
else if (param_1 == 'A') { /* 0x41 -> 6 Byte nach 0x20000170 */ }
else if (param_1 == 'B') { /* 0x42 -> 8 Byte nach 0x20000176 */ }
else if (param_1 == 'C') { /* 0x43 -> 8 Byte nach 0x2000017E */ }
```

Diese Puffer sind über die Modbus-Register `38000`–`38014` lesbar, und ein
Cross-Reference-Lauf bestätigt: `Telemetry_Store_EnergyCounters` ist der
**einzige** Schreiber. Damit lässt sich am Registerwert direkt ablesen, ob ein
Frame angekommen ist.

**Kein Frame wurde je beobachtet.** Der gesamte Block `38000`–`38014` stand in
allen Messungen über elf Logs auf null.

Ein früher notierter Ausreißer — `38003` zeigte dreimal den Wert `118` — hat
sich als **Scanner-Artefakt** erwiesen, nicht als Telemetrie:

| Log | `37012` (`bms_version`) | `38003` |
|---|---|---|
| `entladen_lang` | 118 in 65/66, **0 in genau einem Batch** | 0 in 65/66, **118 in genau demselben Batch** |
| `entladen_dc` | 118 in 3/4, 0 in einem | 0 in 3/4, 118 in demselben |
| `discharge`-Watch | 118 in 7/8, 0 in einem | 0 in 7/8, 118 in demselben |

Die 118 ist die BMS-Version aus Register `37012`. Ursache:
`scan_continuous.py` und `scan_known_registers.py` setzen zwar eine
Modbus-Transaction-ID, **prüfen sie beim Empfang aber nicht**. Eine verspätete
Antwort auf Anfrage N wird dadurch als Antwort auf Anfrage N+1 gelesen. Nur das
neuere `scan_registers.py` validiert die TID (`expect_tid`).

Für die Sendeseite heißt das: Es gibt **keinen Beleg**, dass irgendjemand
Frames `0x40`–`0x43` erzeugt. Der Control hat Empfangspuffer dafür, sie sind
aber leer geblieben. Damit bleibt die Codegruppe auf beiden Seiten
unbestätigt — der Micro v116 sendet sie nicht und behandelt sie nicht.

### Wie das zu lesen ist

Eine Lücke bedeutet **nicht** automatisch „tote Funktion". Möglich sind:

- Der Empfänger ist eine andere Firmware-Version oder Hardware-Variante. Die
  Codes existieren im Control, weil dieselbe Codebasis Venus A, D und E v3
  bedient.
- Der Absender ist ein anderer Knoten als der Control (belegt für die
  BMS-Seite).
- Die Funktion ist im Control angelegt, im Zielgerät aber nicht implementiert.

Belegt ist nur: **In dieser konkreten Firmware-Paarung (Control v150 ↔
Micro v116 ↔ BMS v118) gibt es für diese Codes keinen Empfänger.**

---

## 5. Praktische Folge für die Home-Assistant-Integration

Modbus-Register `46500`–`46544` schreiben über `Inverter_Set_Schedule_Reg` in
diesen Bus. Ein Schreibvorgang kostet einen EEPROM-Zyklus und erzeugt eine
CAN-Nachricht, die nachweislich niemand auswertet. **Nicht in die Integration
aufnehmen.** Details in
`../Modbus_RS485_TCP/Write_Register_46500_Block_v150.md`.

---

## 6. Methodik

- 46 Aufrufer von `CAN_Build_Arbitration_ID` per Decompiler-Scan über das
  Control-Image, Argumente je Aufrufstelle extrahiert.
- Funktionscodes der Empfänger durch vollständiges Auslesen der
  Vergleichszweige (`uVar14 ==`, `case`, `bVar1 ==`), nicht durch Stichproben.
- Gegenprobe im BMS: Scan über alle 649 Funktionen nach einem Vergleich gegen
  `0x30`–`0x3E`. Fünf Treffer, alle unbeteiligt (I²C-EEPROM, printf-
  Ziffernparser, EEPROM-Logslots, CLI-Escape, SoC-Kalibrierung).
- Feste IDs im BMS aus dem Literal-Pool aufgelöst, nicht geschätzt.

### Offen

- Zielklasse 2 (RS485-Pfad) ist nicht gegen einen Empfänger geprüft.
- Zweck von `0x40`–`0x43` (`FUN_0802D2F4`) unbekannt.
- Bits 16–19 und 24–28 der ID (Sequenz/Zähler) sind nicht funktional
  nachvollzogen.
