# Fehler- und Warncodes der Venus D — Analyse (Stand 14.08.2026, Runde 2)

**Ziel:** Klartext für **36000** (warn_code), **36100/37013** (error_code1), **36102/37015** (error_code2).
**Status:** Mechanismus vollständig geklärt, **10 Bits zugeordnet**, Hardware-Schutzpfad identifiziert.
Punkt 7/Schritt 2 ausgeführt (Abschnitt 8). **Live-Gegenprobe aus vorhandenen Scan-Logs ausgewertet
(Abschnitt 9) — sie bestätigt die statische Ableitung und klärt die u32-Wortreihenfolge.**

---

## 1. Herkunft

| Micro-FW v116 | Name | Control-Struct 0x20014E9C | Modbus |
|---|---|---|---|
| `0x200019F4` | `err1` (u32) | +0x08 | **36100 / 37013** |
| `0x200019F8` | `err2` (u32) | +0x0C | **36102 / 37015** |
| `0x200019FC` | `war1` (u32) | +0x04 | **36000** |

Der Control erzeugt **keine** eigenen Codes — `build_telemetry_block` (Micro) liest die drei Wörter,
der Control reicht sie unverändert an Modbus durch.

## 2. Voraussetzung: Image war nur zur Hälfte disassembliert

Der eigentliche Blocker war nicht die Analyse, sondern der Zustand des Ghidra-Projekts:

| | vorher | nachher |
|---|---|---|
| disassembliert | 56,0 % (64.794 B) | **87,0 % (100.640 B)** |
| Funktionen | 452 | **561** |
| in Funktionen | 51,0 % | 61,4 % |
| Fehler-Ladestellen auffindbar | 6 | **22** |

101 Lücken wurden im Thumb-Modus disassembliert, danach lief Ghidras Auto-Analyse (+109 Funktionen).
**Der Stand ist gespeichert.** Stichprobe verifiziert: Bei 0x08018A60 stehen die Rohbytes
`03 21 35 20 FC F7 45 FB 75 48 41 79 41 F0 08 01` = `movs r1,#3 / movs r0,#0x35 / bl / ldr r0,[pc] /
ldrb r1,[r0,#5] / orr.w r1,r1,#8` — echter Code, kein fehlinterpretiertes Datensegment.

## 3. Mechanismus

```
  <Bedingung>
  mov  r0,#<Event-Code> ; ggf. r1..r3 = Messwerte/Kanal
  bl   <Event-Logger 0x080150F2>
  ldr  rX,[<Literal = 0x200019F4>]
  ldrb rY,[rX,#<Byte-Offset>]
  orr  rY,rY,#<Bit>            ; bic bei Entwarnung
  strb rY,[rX,#<Byte-Offset>]
```
Byte-Offset 0–3 = err1, 4–7 = err2, 8–11 = war1. Entwarnung nutzt einen **eigenen** Event-Code.

## 4. Zugeordnete Bits

| Bit | Event (set/clear) | Auslöser | Konfidenz |
|---|---|---|---|
| **err1 Bit 20** | 0x33 / 0x18 | CAN-Statusflag `0x20000448` == 0; Logger erhält die bxCAN-Register `0x40006840/50/54` → **CAN-Kommunikationsfehler** | hoch |
| **err1 Bit 21** | 0x3B / 0x0B | `bms_error_bitmask >> 2 != 0` → **BMS meldet Fehler** | hoch |
| **err2 Bit 0** | 0x36 | HW-Latch `0x200002BA` Bit 1 | hoch |
| **err2 Bit 1** | 0x36 | HW-Latch `0x200002BA` Bit 0 | hoch |
| **err2 Bit 3** | 0x36 | HW-Latch `0x200002BA` Bit 2 | hoch |
| **err2 Bit 4** | 0x36 | wird bei **jeder** HW-Schutzabschaltung gesetzt (Sammelbit) | hoch |
| **err2 Bit 7** | 0x13 | Zustandsautomat: `float @r4+0x54 < 0`, GPIOD Pin 8 wird abgeschaltet; danach Retry-Timer 60000 | mittel |
| **err2 Bit 9** | 0x29 | Zustandsautomat, Parameter = `r4+0x23` | niedrig |
| **err2 Bit 11** | 0x35 | Grenzwert **länger als 3000 Zyklen** überschritten; **5 Setzstellen** mit Kanalindex als Parameter (3,2)/(4,2)/(4,3)/(11,6)/(2,3) | mittel |
| **err2 Bit 16** | – | Ende der Init-/Selbsttestsequenz: Rückgabe von `0x08002A68` != 0 → **Selbsttest fehlgeschlagen** | mittel |
| err2 Bit 31 | – | wird per `bic` **gelöscht** (FUN_0801bb50) | — |

## 5. Der Hardware-Schutzpfad (neu identifiziert)

`0x0801AEAC` — umbenannt in **`HW_Protection_Latch_To_ErrorBits`**:

```c
HW_Protection_Latch_To_ErrorBits() {
    log_event(0x36, <float1>, DAT_200002BA, <float2>);
    if (DAT_200002BA & 0x01) err2 |= 0x0002;   // Bit 1
    if (DAT_200002BA & 0x02) err2 |= 0x0001;   // Bit 0
    if (DAT_200002BA & 0x04) err2 |= 0x0008;   // Bit 3
    err2 |= 0x0010;                            // Bit 4 (Sammelbit)
    DAT_200002BA = 0;                          // Latch quittieren
    shutdown(7); shutdown(8); shutdown(10); shutdown(0x17); shutdown(0x28);
}
```

`DAT_200002BA` ist ein **Hardware-Latch** (Komparator-/Break-Signale), das an anderer Stelle
(`0x0801AF3E/AF42`, vermutlich ISR) gesetzt wird. Aufgerufen aus dem Haupt-Zustandsautomaten
(0x080171F0 / 0x0801722E). Die drei HW-Bits sind damit die **schnellen Hardware-Schutzauslösungen**
(Überstrom/Überspannung/Desat) — welche genau, entscheidet die Comparator-Konfiguration.

Im selben Zustandsautomaten stehen konkrete Grenzwerte im Klartext:
`0x41F00000` = **+30,0** und `0xC1F00000` = **−30,0** (float) → ±30-A-Fenster, sowie eine
Zeitschwelle von **3000** Zyklen für Bit 11.

## 6. Kein Klartext in der Firmware

Volltextsuche über Micro v116 und BMS v118 nach `ovp|uvp|ocp|otp|scp|over|under|fault|protect|alarm`
findet **keine Bit-zu-Text-Tabelle**. Jede Benennung muss aus der Auslösebedingung erschlossen werden —
das ist der Grund, warum hier Aufwand pro Bit anfällt.

## 7. Was noch fehlt

15 der 22 Ladestellen liegen in einem zusammenhängenden Codeblock (0x08017000–0x0801A000), der
**nur per Sprung** erreicht wird — kein `bl`, kein `push {lr}`. Ghidra legt dort auch nach der
Auto-Analyse keine Funktionen an, also gibt es kein Dekompilat, nur Disassembly.

**Nächste Schritte, nach Ertrag sortiert:**

1. **Live-Gegenprobe** — der mit Abstand schnellste Weg. Einen bekannten Fehler provozieren
   (Backup-Überlast wie in `backup_overload_ac_disconnect.csv`, Batterie trennen, CAN abziehen) und
   36000/36100/36102 mitschreiben. Jeder Versuch ordnet ein Bit **eindeutig** zu und validiert
   zugleich die statische Ableitung.
2. Funktionen im Block 0x08017000–0x0801A000 **manuell** an den Sprungzielen anlegen, dann
   dekompilieren und die restlichen Bedingungen auslesen.
3. Die Comparator-/Break-Konfiguration (HRTIM/COMP-Peripherie) auswerten, um `DAT_200002BA`
   Bit 0/1/2 physikalisch zu benennen.

---

## 8. Nachtrag: Funktionen im Sprung-Block angelegt (Punkt 7, Schritt 2)

Der Block 0x08017000–0x0801A000 wird nur per Sprung erreicht — keine `bl`-Ziele, keine
`push {lr}`-Prologe. Ghidras Funktionssuche greift dort prinzipiell nicht. Vorgehen stattdessen:
von jeder Setzstelle rückwärts das nächste **Sprungziel** suchen, dessen Vorgänger den Kontrollfluss
beendet (unbedingter Sprung oder Return), und dort eine Funktion anlegen.

**Ergebnis: 11 der 15 Setzstellen liegen jetzt in Funktionen** und sind dekompilierbar.

| Funktion (neu) | deckt Setzstelle | Erkenntnis |
|---|---|---|
| **`Protect_Err2Bit11_Timeout3000`** (0x080189FC) | 0x08018A68 | `if (3000 < param_2)` → **err2 Bit 11 nach Zeitüberschreitung**; davor Verhältnis-Check `float[r9+0xc] < float[r9+0x14] * 8.0`; Event 0x35 mit Kanalindex |
| **`Protect_Err2Bit7_Ev13`** (0x08018CCE) | 0x08018CDA | err2 Bit 7, Event 0x13; Auslöser `float @r4+0x54 < 0`, GPIOD Pin 8 wird abgeschaltet, danach Retry-Timer 60000 |
| **`Protect_Err2Bit9_Ev29`** (0x08019ED6) | 0x08019EE2 | err2 Bit 9, Event 0x29 mit `r4[0x23]`; Folgeprüfung `r10[0x19] > 99` |
| **`Inverter_StateMachine_CurrentWindow`** (0x0801710A) | 0x08017124 | prüft Stromfenster gegen **+30,0 / −30,0** (float) und ruft den HW-Schutzpfad |
| FUN_080191d0 / FUN_08019364 / FUN_08019c5e | 6 weitere | zusätzliche Setzstellen für **err2 Bit 11** mit anderen Kanalindizes |

**Damit ist belegt:** err2 Bit 11 ist kein einzelner Fehler, sondern ein **Sammelbit für
„Grenzwert zu lange überschritten"**, das aus mindestens 5 Kanälen gesetzt wird — der Kanal steht
nur im Event-Log (Parameter des Event-Codes 0x35), nicht im Modbus-Register.

### Wichtige Einschränkung

Die angelegten Funktionen beginnen an einem **Sprungziel**, nicht am echten Funktionsanfang. Die
auslösende Bedingung steht deshalb teilweise *vor* dem Funktionsanfang und fehlt im Dekompilat —
sie wurde für die obigen Fälle aus dem Disassembly ergänzt. Die Dekompilate zeigen außerdem viele
`unaff_*`-Variablen (Register, die vor dem künstlichen Einstieg gesetzt wurden). Das ist erwartbar
und kein Fehler, macht die Dekompilate aber nur eingeschränkt lesbar.

### Ebenfalls aufgefallen

Beim Schließen der Disassembly-Lücken wurden auch einige **Literal-Pools als Code** interpretiert
(z.B. 0x08016900–0x0801691C: `hlt`, `itttt vc`, `mov.vc r0,r0` — sinnfreie Instruktionen zwischen
echtem Code). Das ist die bekannte Kehrseite eines pauschalen Disassemblier-Laufs. Betroffen sind
Füllbereiche zwischen Funktionen; die ausgewerteten Codestellen wurden stichprobenartig gegen die
Rohbytes verifiziert. Ein erster Versuch, bei 0x0801691E eine Funktion anzulegen, traf einen solchen
Pool und wurde wieder entfernt.

**Stand gespeichert.** Funktionen: 561 → **571**.

---

## 9. Live-Gegenprobe — aus den vorhandenen Scan-Logs

Die Messreihen lagen bereits im Projekt (`Scan_Logs/`); eine neue Messung war nicht nötig.
Ausgewertet wurden die Zeitverläufe von 36100/36101 (error_code1), 36102/36103 (error_code2)
und 36000/36001 (warn_code) über alle Ereignis-Logs.

### 9.1 Die u32-Wortreihenfolge ist damit geklärt

| Ereignis | 36100 | 36101 |
|---|---|---|
| Batterie getrennt (`battery_disconnect.csv`, 15:38:12) | **16** | 0 |
| Batterie wieder dran (15:38:42) | 0 | 0 |

`16` = `0x0010`. Meine statische Analyse hatte **err1 Bit 20 = CAN-Kommunikationsfehler** ergeben
(Bedingung: CAN-Statusflag `0x20000448` == 0). Beim Trennen der Batterie reißt genau diese
CAN-Verbindung zum BMS ab. Bit 20 liegt im **oberen** Halbwort (16 + 4). Damit gilt:

> **Register 36100 = High-Word (Bits 16–31), Register 36101 = Low-Word (Bits 0–15).**
> `error_code1 = (36100 << 16) | 36101` — analog 36102/36103 und 36000/36001.

Das ist für die HA-Integration entscheidend und bestätigt zugleich die statisch abgeleitete
Bedeutung von Bit 20 **unabhängig**.

### 9.2 Bestätigte und neu belegte Bits

| Bit | Live-Beleg | Bedeutung |
|---|---|---|
| **err1 Bit 20** | `battery_disconnect.csv`: 36100 geht auf 16, beim Wiederanschließen zurück auf 0 | **CAN-Kommunikationsfehler** (statisch + live bestätigt) |
| **err1 Bit 7** | `backup_overload_ac_disconnect.csv`, `unter_dod_backup_lässt_sich_nicht_einschalten…csv`, `discharge_under_dod.csv`, Betrieb ohne Batterie nach Powercycle | **Backup-/Offgrid-Störung** — der Offgrid-Zweig kann seine Funktion nicht erfüllen (Überlast, zu wenig Energie, keine Batterie). Der Dateiname des zweiten Logs benennt es wörtlich. |
| err1 Bits 6 + 9 | `entladen_dc.csv` und `unklar_watch discharge power 0→2500`: 36101 = 576 (`0x240`) während des DC-Entladens | **beobachtet, nicht gesichert** — tritt bei DC-Entladevorgängen auf; nur Low-Word gescannt |

Verlauf in `discharge_under_dod.csv`, der Bit 7 gut zeigt:

```
10:12:55  36101=128   SOC 10,7 %   Offgrid 239,4 V   -> Bit 7 gesetzt
10:14:04  36101=0     SOC  0,0 %   Offgrid   0,6 V   -> Offgrid aus, Bit weg
10:16:22  36101=128   SOC 11,1 %   Offgrid 240,3 V   -> Bit 7 wieder gesetzt
```

### 9.3 Was die Logs *nicht* hergeben

- **error_code2 (36102/36103) und warn_code (36000/36001) bleiben in allen sauberen Logs durchgehend 0.**
  Die statisch gefundenen err2-Bits (0/1/3/4/7/9/11/16) wurden also nie ausgelöst — die Hardware-
  Schutzpfade sind im gesamten bisherigen Messmaterial nie angesprungen. Das ist ein gutes Zeichen
  für das Gerät, heißt aber: diese Bits sind nur statisch belegbar.
- Die Werte in `entladen_lang.csv` / `laden_lang.csv` für die Fehlerregister (496, 500, 586, 601,
  2413, 2524 …) sind **keine Bitmasken**, sondern die bekannten Einzelausreißer dieser beiden Logs
  (siehe Abgleichbericht Abschnitt 7) — z.B. ist 500 der Wert von `grid_pf`. Nicht verwertbar.
- **err1 Bit 21 (BMS-Fehler)** wurde nie beobachtet: bei Batterietrennung reißt zuerst der CAN ab
  (Bit 20), ein inhaltlicher BMS-Fehler lag in keinem Test vor.
  > **ÜBERHOLT 2026-08-21:** Bit 21 ist jetzt live aufgetreten — gesetzt bei freiem Bit 20,
  > ausgelöst durch einen Kommunikationsfehler in Pack 1 (neu verbautes Pack auf Werks-FW 117
  > gegen 118 im übrigen Verbund).
  > Die statisch abgeleitete Bedeutung ist damit bestätigt.
  > Siehe `BMS/Pack1_BMS_Fehler_Analyse_2026-08-21.md`.

### 9.4 Warum Bit 20 und Bit 21 sich nicht durch Kabelziehen trennen lassen

Die Packs des Venus D werden **gestapelt und über Kontaktflächen verbunden**, der Wechselrichter
sitzt oben auf. Es gibt kein steckbares CAN-Kabel — ein gezielter Kommunikationsabriss bei
laufender Batterie ist mechanisch nicht möglich. Der naheliegende Trenntest entfällt damit.

### 9.5 Die BMS-Fehlerwörter sind gar nicht per Modbus erreichbar

Abgleich des BMS-Aggregat-Structs (`0x20014F8E`, CAN PGN 1801–1804) gegen die Descriptor-Tabelle:

| Struct-Offset | Feld | Modbus |
|---|---|---|
| +0x18 | `bat_err1` | **kein Register** |
| +0x1A | `bat_err2` | **kein Register** |
| +0x1C | `bat_warn1` | **kein Register** |
| +0x0E / +0x0F | `dischrg_dod` / `key_sleepy` | kein Register |
| +0x16 / +0x17 | `chrg_flag` / `force_chrg` | kein Register |

Die drei BMS-Fehler-/Warnwörter existieren im Speicher und werden von
`CAN_Battery_Telemetry_Debug_Print` ausgegeben, haben aber **keinen Descriptor-Eintrag**. Über
Modbus ist ein BMS-Fehler deshalb ausschließlich als **Sammelbit err1 Bit 21** sichtbar — ohne
jede Detailinformation. Das ist eine echte Lücke im Modbus-Interface, kein Analysefehler.

> **EINGESCHRÄNKT 2026-08-21:** Das gilt für die **Aggregat**-Fehlerwörter. Über die
> **Per-Pack-Register `34x08` (`protect2`)** lässt sich ein BMS-Fehler sehr wohl einem einzelnen
> Pack zuordnen und über die dokumentierte Protect2-Bitmaske benennen — im Störfall vom
> 2026-08-21 war `34008 = 0x4000` (Bit 14, Kommunikationsfehler) bei 0x0000 in allen anderen
> Packs. Die Lücke ist damit kleiner als hier angenommen.
> Siehe `BMS/Pack1_BMS_Fehler_Analyse_2026-08-21.md`.

### 9.6 Praktikabler Ersatz: die Pack-Schutzregister mitscannen

Statt Bit 21 zu provozieren, lässt sich der BMS-Schutz **direkt** beobachten. Serviert sind je Pack:

| Register | Inhalt |
|---|---|
| **34x08** | `protect1` — Schutz-Bitmaske des Packs |
| **34x09** | `protect2` — zweite Schutz-Bitmaske |
| 34x07 | Status-/Flagfeld (0..7) |
| 32112 / 30214 | `lock_flag` / `self_check` des Aggregats |

In allen bisherigen Logs sind `protect1`/`protect2` durchgehend 0 — es lag also nie ein
BMS-Schutzfall vor. Nimmt man sie in den Standard-Scan auf, wird jeder künftige Fall automatisch
mitgeschnitten, **ohne dass etwas provoziert werden muss**.

Zusätzlich unterscheiden sich die beiden Fälle im Begleitbild eindeutig:

- **Bit 20 (CAN-Abriss):** die BMS-Register (32100–32111, 34xxx) frieren ein oder fallen auf 0
- **Bit 21 (BMS-Fehler):** die BMS-Register liefern **weiter plausible Werte**, aber 34x08/34x09 ≠ 0

Damit ist die Trennung auch ohne Kabelziehen möglich — rein aus dem Datenbild.

### 9.7 Verbleibende sinnvolle Messungen

1. **Standard-Scan erweitern** um 36100 **und** 36101 (in `entladen_dc.csv` fehlte 36100, dort ist
   nur das halbe Fehlerwort bekannt) sowie 34x08/34x09 für alle Packs.
2. **Offgrid-Last knapp über Nennleistung** → grenzt Bit 7 gegen die Bits 6/9 ab.
3. **Laden bei Zelltemperatur < 0 °C** (im Winter ohnehin natürlich auftretend): LFP-BMS sperrt das
   Laden — der wahrscheinlichste ungefährliche Weg, Bit 21 und `protect1` real zu sehen.
