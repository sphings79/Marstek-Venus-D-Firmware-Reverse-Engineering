# Register 46500–46544: 15 Strukturen à 8 Byte, EEPROM-persistent, CAN-weitergereicht

**Datum:** 22. August 2026
**Firmware:** Control v150, `Write_Handler` @ `0x08051D14`
**Status:** Mechanik vollständig dekodiert, Feldbedeutung offen

---

## 1. Adressierung

```c
if (0xb5a3 < reg && reg < 0xb5d1) {          // 46500 .. 46544
    idx   = (reg - 0xb5a4) / 3;              // 0..14  -> 15 Strukturen
    field = (reg - 0xb5a4) % 3;              // 0..2
```

Basis der Struktur: SRAM **`0x20014ED4`**, 8 Byte je Eintrag.

| `field` | Register (Beispiel Eintrag 0) | Zugriff |
|---|---|---|
| 0 | 46500 | `u16` bei `+0` |
| 1 | 46501 | obere 16 Bit des `u32` bei `+4` |
| 2 | 46502 | untere 16 Bit desselben `u32` |

Es gibt einen **Lesepfad** (`param_3 == 0`) — am Gerät bestätigt: 46500–46512
antworten, alle mit 0, weil ungenutzt.

## 2. Was ein Schreibvorgang auslöst

```c
EEPROM_Write(idx * 8 + 0x3700, base + idx * 8, 8);
Inverter_Set_Schedule_Reg(idx + 0x30, u16@+0, u32@+4);
```

Zwei Nebenwirkungen bei **jedem** Schreibvorgang:

1. **EEPROM** ab Adresse `0x3700 + idx*8`, 8 Byte. **Kein Change-Guard** — anders als
   bei 44002/44003 landet auch ein unveränderter Wert im nichtflüchtigen Speicher.
   Nicht zyklisch beschreiben.
2. **CAN an den Wechselrichter**, Registerindex `0x30 + idx` (gültig `0x30`–`0x3E`,
   also genau 15). Payload 8 Byte: `u16` in Byte 0–1, Byte 2–3 null, `u32` in Byte 4–7.
   Aufbau in `Inverter_Set_Schedule_Reg` @ `0x08005CE0` über
   `CAN_Build_Arbitration_ID(reg, 1, 4, 0)` und `Register_WriteValue(id, buf, 8)`.

## 3. Der Wechselrichter kennt diese Nachrichten nicht

**Aufgeschlüsselt 2026-08-22.** Die CAN-ID entsteht in `CAN_Build_Arbitration_ID`
(`0x08032F20`):

```
Bits 0–7    Funktionscode      hier 0x30 + idx
Bits 8–11   Quelle             hier 1
Bits 12–15  Ziel               hier 4
Bits 24–28  Zähler/Flags       hier 0
```

Der Empfänger in der Micro-/VNS-Firmware v116 ist
`EMS_Inverter_CAN_Dispatcher` (`0x08001940`). Er dekodiert den Funktionscode als
`param_1 & 0xff` — dieselbe Stelle, die der Builder füllt — und verzweigt auf:

| Codes | Bedeutung |
|---|---|
| `0x01`–`0x07` | SetPower, Enable/Disable, Max-Entlade-/Ladeleistung (Deckel 2500 W), Sleep |
| `0x10`–`0x13` | Telemetrieblock (48 B), weitere Abfragen |
| `0x16` | zwei u32 in den Inverter-Struct |
| `0x50`–`0x58` | Werkstest, FW-Update, Backup-Modus |
| `0x60`, `0xC1`–`0xC3`, `0xCB`, `0xCE` | Debug und Sonstiges |

**`0x30`–`0x3E` fehlt vollständig.** Die Werte landen im Zweig `uVar14 < 0x52`,
treffen dort keine der Unterbedingungen und werden ohne Reaktion verworfen.

Ein Schreibvorgang auf 46500–46544 verbraucht also einen EEPROM-Zyklus und erzeugt
eine CAN-Nachricht, die **niemand auswertet** — jedenfalls nicht der Wechselrichter
in v116. Denkbar bleibt ein anderer Busteilnehmer (das Ziel-Feld steht auf 4) oder
eine Funktion, die in dieser Firmware-Paarung nicht fertig implementiert ist.

## 3b. Auch das BMS ist nicht der Adressat

**Geprüft 2026-08-22 gegen `BMS_118_20260119100535e43806957.bin`.**

Die konkrete CAN-ID der Schedule-Nachricht ist berechenbar. Mit
`param_4 = 0` liefert der Builder `(0 + 0x10000) & 0xe00f0000 = 0x10000`, dazu
`Ziel 4 << 12`, `Quelle 1 << 8` und der Funktionscode:

```
ID = 0x00014130 + idx        (idx = 0..14)   → Extended Frame
```

Der BMS-Empfänger `CAN_RX_Command_Dispatcher` (`0x0800C928`) prüft als **erstes**
das Zielfeld:

```c
if ((ushort)local_10 >> 0xc == 3) {      // Bits 12-15 muessen 3 sein
    bVar1 = (byte)local_10;              // erst dann der Funktionscode
```

Unsere Nachrichten tragen dort eine **4**. Sie werden verworfen, bevor der
Funktionscode überhaupt gelesen wird. Und selbst wenn sie durchkämen: das BMS
kennt nur `0x01`–`0x05`, `0x0A`, `0xC4`, `0xCE`. Der zweite Empfangspfad
`CAN_RX_Handler` (`0x08005A40`) vergleicht feste Voll-IDs (`0x180102AA`,
`0x100401AA` und Ableitungen) — keine davon liegt in unserem Bereich. Ein Scan
über alle 649 BMS-Funktionen nach einem Vergleich gegen `0x30`–`0x3E` liefert
fünf Treffer, allesamt unbeteiligt (I²C-EEPROM, printf-Ziffernparser,
EEPROM-Logslots, CLI-Escape, SoC-Kalibrierung).

### Zielklassen

46 Aufrufer von `CAN_Build_Arbitration_ID` im Control ergeben: Ziel 4 =
Wechselrichter (34 Sendestellen), Ziel 3 = BMS (5), Ziel 2 = RS485-Pfad (13),
Ziel 1 = Control selbst (1). Unsere Schedule-Nachricht geht an Ziel 4 — der
Adressat ist also **richtig gewählt**, der Wechselrichter *ist* der passende
Empfänger für Schedule-Daten. Er versteht diese Befehle in v116 nur nicht.

Vollständige Tabelle aller Sendestellen, Empfänger-Codelisten und
Abdeckungslücken: `../CAN_Bus/CAN_Zielklassen_und_Funktionscodes.md`.

**Wichtige Einordnung:** `0x30`–`0x3E` ist *nicht* die einzige Lücke. An Ziel 4
sendet der Control insgesamt **23 Codes, für die es im Micro v116 keinen
Empfänger gibt** — zusätzlich `0x08`, `0x0A`, `0x14`, `0x17` und `0x40`–`0x43`.
Der Schedule-Block ist damit kein Einzelfall, sondern Teil eines Musters:
Die Control-Firmware bedient Venus A, D und E v3 aus einer Codebasis und
enthält Befehle, die diese konkrete Wechselrichter-Firmware nicht kennt.

Das schwächt die Aussage nicht ab — für den Schreibzugriff auf 46500–46544
bleibt es dabei, dass in dieser Firmware-Paarung niemand die Nachricht
auswertet. Es heißt nur: Ein fehlender Empfänger belegt nicht, dass die
Funktion generell tot ist. Eine andere Firmware-Version oder Hardware-Variante
könnte sie kennen.

## 4. Warum die Bedeutung dennoch offen bleibt

Ein Cross-Reference-Lauf auf `0x20014ED4` liefert **null** Treffer: Der Control liest
den Block nirgends aus, wertet ihn nicht aus und trifft keine Entscheidung damit. Er
ist reiner Durchreicher — Modbus hinein, EEPROM und CAN hinaus.

Die Semantik liegt also in der **Micro-/VNS-Firmware**, bei deren Registern
`0x30`–`0x3E`. Erste Suche dort blieb ergebnislos: `modbus_register_handler`
(`0x080124E8`) behandelt einen eigenen Zeitplan mit **10-Byte**-Einträgen und
HH/MM-Validierung (`< 0x18` Stunden, `< 0x3c` Minuten) — das ist eine andere
Tabelle als unsere 8-Byte-Struktur. Der CAN-Empfangspfad wurde noch nicht
aufgeschlüsselt.

Der von Ghidra vergebene Name `Inverter_Set_Schedule_Reg` ist eine **Vermutung**
und sollte nicht als Beleg für „Zeitplan" gelten.

## 5. Abgrenzung

Nicht verwechseln mit:

- **43100–43129** — die sechs Zeitplan-Slots, die die Integration abbildet
  (10-Byte-Struct: enable/start/end/power).
- **`0x20014D02`** — 10 Einträge à 10 Byte, Leistung bei `+2`. Das ist der Block, den
  `Config_ScheduleEntries_ClampPower800W` bei der 800-W-Leistungsklasse klemmt.
- **41500–41631** — Roh-Arrays für Zeit und Leistung, ebenfalls SRAM.

## 6. Empfehlung

**Nicht in die Integration aufnehmen.** Ein Schreibvorgang verbraucht einen
EEPROM-Zyklus und erzeugt eine CAN-Nachricht, für die es in v116 keinen Empfänger
gibt. Lesen ist unbedenklich — solange alle 15 Einträge null sind, gibt es dort aber
nichts zu sehen.

Nächster sinnvoller Schritt wäre die BMS-Firmware: das Ziel-Feld der CAN-ID steht
auf 4, und ob dieser Knoten die Codes `0x30`–`0x3E` kennt, ist ungeprüft.
