# Pack-1-BMS-Fehler: Backup-Steckdose lässt sich nicht einschalten

**Datum:** 21. August 2026
**Anlass:** Der Venus D verweigert das Einschalten der Backup-/Notstrom-Steckdose. Ein
Versions-Scan zeigte gleichzeitig einen BMS-Versions-Mismatch zwischen Pack 1 und den
übrigen Packs.
**Eingang:** Drei Live-Scans über Modbus-TCP (Proxy `192.168.1.50:1502` → Gerät
`192.168.1.100:502`), Endstand `Scan_Logs/pack1_bms_fault_2026-08-21.csv`
(540 von 582 Registern, 12:07:16–12:08:48).
**Ergebnis:** Pack 1 ist ein **neu verbautes Pack im Auslieferungszustand** — Release-FW
117, null Zyklen, ~50 % Lager-SOC. Die übrigen Packs laufen auf 118. Aus diesem
Versionsversatz meldet Pack 1 einen **Kommunikationsfehler**, das Gerät sperrt daraufhin
den Offgrid-Zweig. Die Hardware ist einwandfrei.

---

## 1. Der Befund in einer Zeile

`error_code1 = 0x00200000` → **Bit 21 = BMS-Fehler**. Es ist der einzige gesetzte
Fehler im ganzen Gerät.

| Register | Wert | Bedeutung |
|---|---|---|
| `36100` / `37013` | `0x0020` | error_code1 High-Word → **Bit 21 gesetzt** |
| `36101` / `37014` | `0x0000` | Low-Word — Bit 7 (Backup-/Offgrid-Störung) **nicht** gesetzt |
| `36102` / `36103` | `0x0000` | error_code2 sauber |
| `36000` / `36001` | `0x0000` | warn_code sauber |
| `37023` / `37024` | `0x0000` | MPPT-Fehler/-Warnung sauber |
| `41200` | `0` | `backup_ups_enable` — Backup deaktiviert |
| `30005` / `30007` | `5` / `0` | Offgrid 0,5 V / 0 W — Dose stromlos |

Wortreihenfolge nach `Fehlercodes_Micro_FW_Analyse.md` §9.1:
`error_code1 = (36100 << 16) | 36101`. `0x0020` im High-Word = Bit 16+5 = **Bit 21**.

**Bit 20 (CAN-Kommunikationsfehler) ist nicht gesetzt** — die CAN-Strecke
Wechselrichter ↔ BMS steht. Der Fehler ist BMS-intern.

---

## 2. Pack-Vergleich (Scan 12:07:16, Rohwerte)

| Offset | Feld | **Pack 1** | Pack 2 | Pack 3 | Pack 4 | Pack 5 | Pack 6 | Pack 7 |
|---|---|---|---|---|---|---|---|---|
| +00 | `bat_volt` | **5259** | 5329 | 5335 | 5281 | 5339 | 5338 | 0 |
| +01 | `bat_curr` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| +02 | `soc` | **479** | 705 | 799 | 696 | 698 | 697 | 0 |
| +03 | `cycle_count` | **0** | 13 | 19 | 19 | 62 | 56 | 0 |
| +04 | `mos_status` | **3** | 0 | 0 | 0 | 0 | 0 | 0 |
| +05 | `max_cell_voltage` | **3289** | 3332 | 3336 | 3302 | 3339 | 3338 | 0 |
| +06 | `min_cell_voltage` | **3286** | 3330 | 3334 | 3300 | 3336 | 3336 | 0 |
| +07 | `protect1` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| +08 | `protect2` | **16384** | 0 | 0 | 0 | 0 | 0 | 0 |
| +09 | `bms_reserved_5a` | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| +10 | `bms_version` | **117** | 118 | 118 | 118 | 118 | 118 | 0 |
| +11 | `temp_1` | 300 | 294 | 299 | 305 | 302 | 289 | 0 |
| +12 | `temp_2` | 232 | 238 | 238 | 244 | 236 | 227 | 0 |
| +13…+16 | `ntc_block` | 202–211 | 235–237 | 231–233 | 231–236 | 223–226 | 220–222 | 0 |

Pack 7 durchgängig 0 — es sind sechs Packs verbaut, das ist der Normalzustand.

Register-Basis: `34x00`–`34x16`, Namen nach
`Marstek_Venus_D_Register_Map_Final_all_register.csv` (Stand der Korrektur 2026-08-16,
Frame 0x23: Byte0-1 = Protect1, Byte2-3 = Protect2, Byte4-5 = Struct-Feld @+0x5a).

---

## 3. Pack 1 ist hardwareseitig gesund

| Pack | Zellen | min–max | Spreizung |
|---|---|---|---|
| **1** | 16 | 3286–3289 mV | **3 mV** |
| 2 | 16 | 3330–3332 mV | 2 mV |
| 3 | 16 | 3334–3336 mV | 2 mV |
| 4 | 16 | 3300–3302 mV | 2 mV |
| 5 | 16 | 3336–3339 mV | 3 mV |
| 6 | 16 | 3336–3338 mV | 2 mV |

Alle 16 Zellen von Pack 1 antworten, die Balance ist mit 3 mV so gut wie bei den
gesunden Packs, die Temperaturen (30,0 °C / 23,2 °C, NTC 20,2–21,1 °C) sind
unauffällig. **Das BMS kommuniziert** — der Fehler ist kein Kommunikationsabriss,
sondern eine gemeldete Störung.

---

## 4. Was mit Pack 1 los ist

**Pack 1 ist neu verbaut und im Auslieferungszustand.** Drei Werte, die einzeln nach
Störung aussehen, sind zusammen genau das erwartete Bild eines fabrikfrischen Packs:

| Wert | Beobachtung | Erklärung |
|---|---|---|
| `cycle_count = 0` | 13–62 bei den anderen Packs | **Nie zyklisiert** — das Pack ist neu |
| `soc = 479` (47,9 %) | 69,6–79,9 % bei den anderen | **Lager-SOC ab Werk** (~50 %, üblicher Lagerladezustand für Lithium) |
| `bms_version = 117` | 118 bei den anderen | **Werksseitige Release-Firmware**, noch nicht auf 118 gehoben |

Die niedrigere Packspannung (52,59 V gegen 53,29–53,39 V) und die niedrigeren
Zellspannungen (3286–3289 mV gegen 3300–3339 mV) sind schlicht die Folge des geringeren
Ladezustands, keine eigenständige Auffälligkeit.

Der einzige echte Fehler ist **`protect2 = 0x4000`** = Bit 14 = **Kommunikationsfehler**
(`BMS_FW_Analyse_v117.7.md` §5.3, Setzbedingung `DAT_20002901 ≠ 0`) — ausgelöst durch den
**Versionsversatz 117 gegen 118** im Pack-Verbund.

### 4.1 Das Versionsschema

Ergänzung zur bisherigen Doku, die 116 / 1177 / 118 nur als Beobachtungswerte führte:

| Rohwert | Version | Typ |
|---|---|---|
| `116` | v116 | Release |
| `117` | v117 | **Release** — Auslieferungsstand neuer Packs |
| `118` | v118 | Release |
| `1177` | v117.7 | **Beta** |

> **Regel:** Ganzzahlige Werte sind **Release**-Versionen und werden direkt gespeichert.
> Versionen mit Nachkommastelle (`.x`) sind **Beta**-Stände und werden als Version × 10
> abgelegt (`1177` = v117.7).

Dasselbe Muster gilt für `ems_version` (`1492` = v149.2 Beta, `150` = v150 Release).

### 4.2 Warum das den Backup-Betrieb blockiert

- **Versionsversatz im Verbund:** Pack 1 spricht das Protokoll der FW 117, die übrigen
  fünf das der 118. Das Aggregat-BMS quittiert das mit dem Kommunikationsfehler-Bit und
  gibt den Verbund nicht frei.
- **SOC-Versatz:** Pack 1 liegt mit 52,59 V rund **0,7–0,8 V unter** den übrigen Packs.
  Direktes Parallelschalten triebe einen erheblichen Ausgleichsstrom — eine Sperre ist
  hier sachlich richtig, unabhängig vom Versionsproblem.
- **`mos_status` invertiert:** Pack 1 = 3 (Lade- und Entlade-MOSFET geschlossen),
  Packs 2–6 = 0 (beide offen).
- **`bat_curr = 0` bei allen Packs** — es fließt nirgends Strom, es gibt keinen
  freigegebenen Entladepfad.

`error_code1` Bit 7 (Backup-/Offgrid-Störung) ist folgerichtig **nicht** gesetzt: Der
Offgrid-Zweig läuft nicht in eine Überlast, er startet gar nicht erst.

---

## 5. Zwei Korrekturen an der bestehenden Doku

### 5.1 err1 Bit 21 ist erstmals live beobachtet

`VNS_Micro_Inverter/Fehlercodes_Micro_FW_Analyse.md` §9.3 hält fest:

> „**err1 Bit 21 (BMS-Fehler)** wurde nie beobachtet: bei Batterietrennung reißt zuerst
> der CAN ab (Bit 20), ein inhaltlicher BMS-Fehler lag in keinem Test vor."

Genau dieser Fall liegt jetzt vor — **Bit 21 gesetzt, Bit 20 frei**. Die statisch
abgeleitete Bedeutung ist damit live bestätigt.

### 5.2 Ein BMS-Fehler ist doch lokalisierbar

Dieselbe Datei hält in §9.5 fest, `bat_err1`/`bat_err2`/`bat_warn1` hätten keinen
Descriptor-Eintrag, weshalb ein BMS-Fehler über Modbus „**ausschließlich als Sammelbit
err1 Bit 21** sichtbar — ohne jede Detailinformation" sei.

Das gilt für die **Aggregat**-Fehlerwörter, nicht für das Gesamtbild: über die
**Per-Pack-Register `34x08` (`protect2`)** lässt sich der Fehler eindeutig einem
einzelnen Pack zuordnen und über die dokumentierte Protect2-Bitmaske benennen. Die Lücke
im Modbus-Interface ist damit kleiner als angenommen.

---

## 6. Methodische Nebenbefunde

- **Bereichs-Scans über undokumentierte Register legen den Modbus-Server lahm.** Ein
  Scan mit `--regs 36000-36103` (101 der 126 Register nicht in der Map) führte um 11:53
  zum Verbindungsabbruch; der Proxy meldete danach `ConnectionRefused` auf
  `192.168.1.100:502`. Konsequenz: **immer `--tiers ok,verm,unb` statt roher
  Bereichsangaben** — damit werden ausschließlich kartierte Register gelesen und die
  Lücken nie angefasst.
- **42 Register ohne Antwort sind kein Fehler.** Es sind ausschließlich Write-Only-Register
  (kompletter `45000`er Command-Block, `41000`, `41100`, `45603`, `45604`, `46000`,
  `46500`–`46503`). Sie haben FC06/FC10-Write-Handler, aber keinen Lesepfad.
- **Die Register-Map wurde am 21.08. vereinheitlicht.** `Final_claude_generated.csv`
  (440 Register, veraltete Pack-Zuordnung bei `34x07`–`34x09`) wurde entfernt; kanonisch
  ist jetzt `Final_all_register.csv` (582 Register). Die drei Scan-Skripte verstehen
  beide Spalten-Schemata, siehe `Methodik_und_Meta/Analyse_Skripte.md`.

---

## 7. Offene Punkte

| # | Punkt |
|---|---|
| 1 | Pack 1 von der Werks-FW 117 auf 118 heben — BMS-OTA anstoßen. Über Modbus ist nichts zu erzwingen: `41200` hebt die Sperre nicht auf (sie sitzt im BMS), die Versions-Register sind Read-Only-Spiegel. |
| 2 | Nach dem Update prüfen, ob `34008` auf 0 zurückgeht und `36100` mit ihm. |
| 3 | Offen, ob der Kommunikationsfehler allein am Versionsversatz hängt oder zusätzlich am SOC-Versatz. Wird sich zeigen, sobald Pack 1 auf 118 steht: verschwindet das Bit trotz weiterhin niedrigem SOC, war es rein die Version. |
| 4 | `mos_status`-Inversion (Pack 1 = 3, Rest = 0) im Normalbetrieb gegenprüfen — unklar, ob 0 bei den anderen Packs der Ruhezustand ist oder eine aktive Isolierung. |
| 5 | Protect1 Bits 12–15 und Protect2 Bits 0–8, 10, 13 sind weiterhin nicht dekodiert. |
| 6 | Das Versionsschema aus §4.1 in die Register-Map-Notizen zu `30204` / `34x10` / `ems_version` übernehmen. |
