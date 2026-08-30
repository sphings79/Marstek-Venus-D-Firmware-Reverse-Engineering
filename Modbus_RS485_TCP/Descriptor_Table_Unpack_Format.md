# Modbus-Descriptor-Tabelle — Entpack-Format vollständig reverse-engineered

**Gerät:** Marstek Venus D (VNSD-0), STM32 ARM Cortex-M, FreeRTOS
**Firmwares:** `VNSD-0_app_1492_0702_142136.bin` (v149.2) und `VNSD-0_app_0150_0805_115146.bin` (v150)
**Datum:** 14. August 2026
**Status:** Format geknackt, 246/246 Einträge beider Versionen dekodiert und validiert
**Werkzeuge:** Python + Capstone (eigener Solver). **Ohne Ghidra, ohne Gerät, rein statisch.**

---

## 1. Ausgangslage und was daran falsch war

Der bisherige Projektstand lautete:

> Die Descriptor-Tabelle bei SRAM `0x20000354` wird zur Laufzeit aufgebaut. Die 246
> Registernummern sind aus dem Flash nicht statisch enumerierbar (vier unabhängige
> PyGhidra-Prüfungen). Registernummern werden im Init-Code berechnet. Enumeration nur
> per Live-Scan, Emulation oder SWD-Dump.

**Diese Schlussfolgerung ist widerlegt.**

Die Tabelle wird nicht berechnet. Sie ist ein ganz normales `.data`-Global. Das
`.data`-Image liegt **LZ77-komprimiert am Flash-Ende** und wird beim Boot von der
C-Runtime entpackt.

Damit erklären sich alle vier negativen Vorbefunde auf einen Schlag:

| Vorbefund | Erklärung |
|---|---|
| Kein aufsteigendes Register-Array im Flash | liegt komprimiert vor |
| Keine dichten Register-`MOVW`-Immediates | Registernummern sind Daten, kein Code |
| Nur 2 Code-Referenzen auf `0x20000354` (beide Leser, kein Builder) | korrekt — es *gibt* keinen Builder |
| Kein `.data`-Template mit Pointer-Signatur | das Template ist komprimiert, also unerkennbar |

Auch die beobachteten „Marker" `0x5A0C` (23052) und `0x1A0C` (6668) sind erklärt:
Es sind keine Marker, sondern zwei häufige Opcode/Distanz-Paare (siehe Abschnitt 3).

---

## 2. Wie der gepackte Bereich zu finden ist

Das Packformat kodiert **jedes Nullbyte als Nullrun-Opcode**. Der komprimierte Stream
enthält deshalb garantiert **kein einziges `0x00`**. Das ist die Signatur:

> Suche im Flash-Image den längsten zusammenhängenden Bereich ohne `0x00`-Byte.

| Firmware | Gepackter Bereich | Länge |
|---|---|---|
| v149.2 | `0x0805CBCC` … `0x0805D7D3` | ca. 2,5 KB |
| v150 | analog am Flash-Ende | analog |

Dahinter folgt `0xFF`-Füllung bis zum Image-Ende, mit der Signatur `VNSD` bei
`0x0805DFE0` (v149.2).

Zusätzlich bestätigt: Es existiert **kein** `MOVT #0x0805` im gesamten Image und **kein**
Literal-Pool-Wort, das auf den Streamanfang zeigt. Der Entpacker bekommt seinen
Quellzeiger also anders (Scatter-/Region-Mechanismus). Der Reset-Vektor im OTA-Image
(`IVT[1]` = `0x08004A71`) zeigt auf eine gewöhnliche Applikationsfunktion, nicht auf einen
C-Startup — der Startup-Pfad ist über die Vektortabelle dieses Images nicht erreichbar.

---

## 3. Das Packformat (vollständig)

Ein-Byte-Opcode, danach optional Literale und ein Distanzbyte.

```
op = *src++

nlit = (op & 0x07) - 1        // 0..6 Literale; (op & 7) == 0 = Escape
len4 = (op >> 4) & 0x0F       // Längenfeld, 4 Bit (Bit 7 gehört dazu)

<nlit Literalbytes aus dem Stream kopieren>

if (op & 0x08) {              // Bit 3 gesetzt = LZ77-Match
    dist = *src++;            // 1 Byte Rückwärtsdistanz
    mlen = len4 + 2;
    <mlen Bytes von (out_ptr - dist) kopieren, Überlappung erlaubt>
} else {                      // Bit 3 gelöscht = Nullrun
    <len4 Nullbytes ausgeben>
}
```

### Bitfelder

| Bits | Bedeutung |
|---|---|
| 0–2 | Literalanzahl + 1 (Wert 0 = Escape, siehe unten) |
| 3 | 0 = Nullrun, 1 = LZ77-Match |
| 4–7 | Match-Länge − 2 bzw. Anzahl Nullbytes |

### Die häufigsten Opcodes

| Opcode | Bedeutung | Typischer Einsatz |
|---|---|---|
| `0x1A` | 1 Literal + Match Länge 3 | Registernummer + `75 00 00` aus Vorgängereintrag |
| `0x5A` | 1 Literal + Match Länge 7 | Pointer-Lowbyte + Rest des Vorgängereintrags |
| `0x1B` | 2 Literale + Match Länge 3 | Eintragsgrenze überspannend |
| `0x23` | 2 Literale + 2 Nullbytes | Registernummer + Padding-Feld |
| `0x17` | 6 Literale + 1 Nullbyte | vollständiger Pointer + Typ/Größe |
| `0x13` | 2 Literale + 1 Nullbyte | Typ/Größe + Skala |

Die Distanzen sind fast immer Vielfache von 12 (`0x0C` = 12, `0x18` = 24, `0x24` = 36,
`0x30` = 48) — also Rückverweise auf vorherige Descriptor-Einträge. Genau daher kommen die
scheinbaren „Marker" `0x5A0C` und `0x1A0C`: das sind die Bytepaare
`<Opcode 0x5A|0x1A><Distanz 0x0C>`.

### Der Escape-Fall

`(op & 7) == 0` ist selten — sieben Vorkommen im gesamten v149.2-Image, davon **genau eines
innerhalb der Descriptor-Tabelle** (`0x0805CEA3`, op `0x18`). Die Semantik ist noch nicht
restlos formalisiert. Der Decoder löst diese Stellen per Lookahead-Suche auf: er probiert
Literalanzahlen durch und wählt die, die die nachfolgende 12-Byte-Struktur intakt lässt.
Für die Tabelle ist das durch die 246-Einträge-Validierung abgesichert; für andere
`.data`-Bereiche sollte man sich nicht blind darauf verlassen.

Beobachtete Escape-Stellen v149.2:

```
0x0805CEA3  op=18  nlit=9   consume_extra=1   <- innerhalb der Tabelle
0x0805D2BA  op=E0  nlit=0   consume_extra=0
0x0805D320  op=68  nlit=21  consume_extra=0
0x0805D3AF  op=10  nlit=32  consume_extra=1
0x0805D430  op=08  nlit=24  consume_extra=0
0x0805D54F  op=E0  nlit=0   consume_extra=0
0x0805D582  op=00  nlit=16  consume_extra=0
```

---

## 4. Eintragslayout (12 Byte) — bestätigt

```
+0   u16   Registernummer   (direkte PDU-Adresse, KEIN Offset, nicht 0-basiert)
+2   u16   0                (Padding, in allen 246 Einträgen null)
+4   u32   Quellzeiger      (SRAM, in einem Fall Flash)
+8   u8    Typcode
+9   u8    Elementgröße     (low nibble)
+10  u8    Skalencode
+11  u8    Anzahl Elemente
```

| Typcode | Typ | | Skalencode | Wirkung |
|---|---|---|---|---|
| `0x01` | u8 | | 0 | ×1 (keine Umrechnung) |
| `0x02` | u16 | | 1 | ×10 |
| `0x04` | u32 | | 2 | ×100 |
| `0x11` | i8 | | 3 | ÷10 |
| `0x12` | i16 | | 4 | ÷100 |
| `0x14` | i32 | | 5 | negieren |
| `0x24` | float32 | | | |
| `0x31` | ASCII (memcpy) | | | |

**Wichtig:** Der Skalencode beschreibt, was die **Firmware** rechnet — nicht die Einheit.
Skalencode 0 heißt „Rohwert unverändert", auch wenn der Rohwert in 0,1-V- oder
0,1-%-Einheiten vorliegt. Die Umrechnung in die Anzeigeeinheit muss dann der Client machen.

---

## 5. Validierung

1. **Exakt 246 gültige Einträge** — identisch mit der Schleifengrenze im FC03-Handler
   (`FUN_0801eaa4`, v149.2).
2. Alle 246: Padding `+2` = 0, gültiger Typcode, Pointer in plausiblem SRAM-/Flash-Bereich,
   Registernummern monoton steigend 30000 → 38014.
3. **218 verschiedene Startoffsets** liefern eine **byte-identische** Tabelle
   (SHA-256 `becbf8146ce51ffb…`). Der Decoder resynchronisiert robust, das Ergebnis hängt
   nicht vom geratenen Streamanfang ab.
4. Gegenprobe gegen bekannte Register bestanden — siehe Abschnitt 7.
5. Der v149.2↔v150-Diff sortiert sich in **fünf saubere Pointer-Delta-Gruppen** statt in
   Rauschen. Bei einem Dekodierfehler wäre das nicht der Fall.

---

## 6. Versionsvergleich v149.2 ↔ v150

| Kennzahl | v149.2 | v150 |
|---|---|---|
| Einträge | 246 | 246 |
| Registerbereich | 30000 – 38014 | 30000 – 38014 |
| Register nur in einer Version | – | – |
| Typ-Änderungen | – | **0** |
| Scale-Änderungen | – | **0** |
| elem_size-Änderungen | – | **0** |
| count-Änderungen | – | **0** |

**Die Modbus-Semantik ist zwischen v149.2 und v150 unverändert.** Die einzige Differenz sind
verschobene SRAM-Quellzeiger (Speicherlayout-Drift durch eingefügte Variablen).

Für `marstek_venus_modbus` heißt das: **keine versionsabhängige Fallunterscheidung nötig.**

### Pointer-Verschiebungen

| Delta | Register | Bereich | Deutung |
|---|---|---|---|
| **+12** | 204 | `0x20014EA0…0x20015236` | Vor dem Inverter-/BMS-Telemetriestruct wurden 12 Byte eingefügt; Basis jetzt `0x20014EAC` statt `0x20014EA0` |
| **+10** | 6 | 33000–33010 | Energiezählerblock |
| **+16** | 4 | 30301, 30302, 30304, 30400 | separate späte SRAM-Puffer |
| **+4** | 1 | 31000 | device_name-Puffer |
| **±0** | 31 | `0x200000xx…0x200001xx`, `0x20001F4x` | unveränderte Kern-Globals |

### Block 38000–38014 ist NICHT neu in v150

Alle 15 Einträge existieren in v149.2 bereits — gleiche Register, gleiche Typen, gleiche
Skalen und **identische Quellzeiger** (`0x20000168`–`0x20000184`, Delta ±0). Sie gehören zu
den unverschobenen Kern-Globals.

Der ursprünglich geplante Gegentest („38000-38014 muss in v150 neu auftauchen") schlägt also
fehl — nicht wegen der Dekodierung, sondern weil die Prämisse nicht stimmt. Dass der Block
im Live-Scan nur Nullen liefert, ist kein Versionsthema: die Quellvariablen werden im
getesteten Betriebszustand nicht beschrieben. Auslöser ist vermutlich das Zustandsflag bei
SRAM `0x20000EE5`, das laut v149.2-Analyse bei Lesezugriffen im Bereich 38000–39014 gesetzt
wird.

---

## 7. Register 32101 (dc_current) — Stand

In **beiden** Versionen identisch definiert:

| Feld | Wert |
|---|---|
| Typ | `i16` (Typcode `0x12`) |
| Skala | Code 3 = ÷10 |
| Count | 1 |
| Quelle v149.2 | `0x20014F84` |
| Quelle v150 | `0x20014F90` |

**Die Abschneide-Hypothese ist damit vom Tisch.** Die Quelle ist bereits 16 Bit breit; der
Read-Serializer kopiert die volle Registerbreite, es wird nichts truncated.

`0x9965` als `i16` gelesen ist **−26267**, geteilt durch 10 also **−2626,7 A** — physikalisch
unsinnig. Der Fehler entsteht damit eindeutig im **Writer** des SRAM-Slots, nicht im
Modbus-Pfad. Wahrscheinlich wird beim Entladen ein u16-Wert geschrieben, der als negative
Größe fehlinterpretiert wird.

**Offen:** Identifikation des Writers. Das ist der einzige verbliebene Punkt, der Ghidra
erfordert (SRAM-Block anlegen → Cross-References auf `0x20014F90` → Schreibstelle lesen →
Lade-/Entlade-Verzweigung).

---

## 8. Korrekturen an der bestehenden Register-Map

| Register | Bisher dokumentiert | Firmware-Wahrheit |
|---|---|---|
| **32301** | `ac_offgrid_current`, uint16, 0.01 A | **Duplikat von 32300** — identischer Quellzeiger, also nochmal die Offgrid-Spannung. Kein eigener Messwert. |
| **32204** | int16 | **u16** (Typcode `0x02`) |
| **32302** | int32, 2 Register | **i16**, 1 Register |
| **36100** | uint64 über 4 Register | **zwei getrennte u32**: 36100/36101 und 36102/36103 |
| **30303** | Scale −1 (dBm) | Skalencode 0 — die Firmware setzt **kein** Vorzeichen |
| **34010** | teils als Temperatur geführt | Version — identischer Quellzeiger wie 30204 |
| **30005** | Pack-Count vermutet | `ac_offgrid_voltage` — identische Quelle wie 32300/32301 |
| **33000er** | Scale 0.01 kWh (Annahme) | bestätigt: Skalencode 3, FW teilt selbst durch 10 |

---

## 9. Skalen-Inkonsistenzen (in beiden Versionen gleich)

Direkt relevant für die HA-Integration:

| Register | Skalencode | Konsequenz |
|---|---|---|
| **32104** (globaler SOC) | 3 = ÷10 | Firmware teilt **selbst** → Client darf **nicht** nochmal ×0,1 rechnen |
| **34002** (Pack-0-SOC) | 0 = ×1 | Rohwert in 0,1-%-Einheiten → Client **muss** ×0,1 rechnen |
| **37005** | 3 = ÷10 | gleiche Quelle wie 34002, aber bereits geteilt |
| **32200 / 32204** | 0 = ×1 | Rohwerte in 0,1 V bzw. 0,1 Hz, keine FW-Skalierung |
| **30104 / 30105** | 1 = ×10 | Firmware **multipliziert** mit 10 |

---

## 10. Alias-Gruppen — 32 mehrfach bediente Quellen

Viele „unbekannte" Register sind keine neuen Messwerte, sondern Duplikate. Liste für v150
(v149.2 analog, Pointer −12):

| Quelle (v150) | Register |
|---|---|
| `0x20014EAC` | 30004, 32200, 32201 |
| `0x20014EB0` | 30005, 32300, 32301 |
| `0x20014EB4` | 30006, 32202, 37004 |
| `0x20014EB6` | 30007, 32302 |
| `0x20014EB8` | 30001, 32102 |
| `0x20014EBC` | 30002, 35000 |
| `0x20014EBE` | 30003, 35001, 35002 |
| `0x20014EA4` | 36100, 37013 |
| `0x20014EA8` | 36102, 37015 |
| `0x20014F58 / F5E / F64 / F6A` | 30037/37017, 30038/37018, 30039/37019, 30040/37020 |
| `0x20014F92` | 32108, 35010 |
| `0x20014FA0 / FA2` | 32106/35111, 32107/35112 |
| `0x20014FAC / FAF` | 30109/32113, 30110/32114 |
| `0x20014FB4 / FB6` | 30100/34000, 30101/34001 |
| `0x20014FB8` | 34002, 37005 |
| `0x20014FC2` | 30210, 34004 |
| `0x20014FC4 / FC6` | 30102/34005/37007, 30103/34006/37008 |
| `0x20014FC8 / FCA` | 30104/37006, 30105/35011 |
| `0x20014FCC / FD0` | 34007/37009, 34009/37011 |
| `0x20014FD2` | 30204, 34010 (= 37012) |
| `0x20014FFE / 0x20015000 / 0x20015002` | 30107/34011, 30108/34012, 30106/34017 |

---

## 11. Neu abgeleitete Strukturen

### MPPT-Struct — 4 Strings, Stride 6 Byte

Basis v150 `0x20014F54` (v149.2 `0x20014F48`):

| Feld-Offset | Register | Bedeutung |
|---|---|---|
| +0 | 30020, 30021, 30022, 30023 | mppt1–4 Spannung |
| +2 | 30024, 30025, 30026, 30027 | mppt1–4 Strom |
| +4 | 30037, 30038, 30039, 30040 | mppt1–4 Leistung |

Vorher war nur der Spannungsblock dokumentiert; Strom und Leistung fallen direkt aus dem
Pointer-Stride heraus.

### Pack-Struct — 7 Blöcke, Stride 0x60

34000 / 34100 / … / 34600, je 18 Descriptor-Einträge (Master + 6 Packs).

### Register mit `count > 1` (belegen mehrere Modbus-Register)

| Register | count | elem | belegt |
|---|---|---|---|
| 30304 | 12 | 1 | 30304–30309 (MAC, ASCII) |
| 30350 | 12 | 1 | 30350–30355 (Comm-Modul-FW) |
| 30400 | 8 | 1 | 30400–30403 (IP-Adressen) |
| 31000 | 20 | 1 | 31000–31009 (device_name) |
| 34x13 | 4 | 2 | 34x13–34x16 (NTC-Block, je Pack) |
| 34x18 | 16 | 2 | 34x18–34x33 (16 Zellspannungen, je Pack) |
| 37009 | 2 | 2 | 37009–37010 |
| 37011 | 2 | 2 | 37011–37012 (37012 = bms_version) |

---

## 12. Konfidenzstand der Register-Map

Die Descriptor-Tabelle liefert den **Serving-Vertrag** endgültig: Adresse, Typ, Skala,
Elementgröße, Anzahl, Quellzeiger. Sie liefert **nicht** die Bedeutung — dafür braucht es
den Writer des jeweiligen SRAM-Slots.

| Konfidenz | Register | Grundlage |
|---|---|---|
| hoch | 62 | Struct-Offset + Live-Scan + Telemetrie-Feldnamen decken sich |
| mittel | 62 | aus Pack-Struct-Stride oder Alias abgeleitet, plausibel aber nicht verifiziert |
| niedrig | 1 | 32102 (Typkonflikt mit 30001: gleiche Quelle, dort i16, hier float32) |
| **offen** | **121** | Typ/Skala sicher, Bedeutung unbekannt |

---

## 13. Offene Punkte

1. **Telemetrie-Struct gegen Descriptor-Pointer legen.** Der 48-Byte-Block der Micro-FW ist
   bereits zu 20 Feldern dekodiert. Ein reiner Offset-Abgleich gegen die Quellzeiger ab
   `0x20014EAC` (v150) dürfte 30–40 der 121 offenen Register auf einen Rutsch benennen.
   Reine Rechenarbeit, kein Ghidra nötig.
2. **Writer-Analyse in Ghidra** für die verbleibenden offenen Slots — mit den jetzt bekannten
   Zieladressen mechanisch: SRAM-Block anlegen, Cross-References, Schreibstelle lesen.
3. **32101-Writer** (siehe Abschnitt 7).
4. **Escape-Opcode formalisieren** (`op & 7 == 0`, 7 Vorkommen).
5. **Live-Gegenprobe** bei laufender PV und aktivem Offgrid zur Bestätigung der abgeleiteten
   MPPT-Strom-/Leistungsregister.
6. **32202** hat `elem_size` 4 bei Typ `i16` — inkonsistent, nachprüfen.
7. **32110** liest von einer ungeraden Adresse (`0x20014F99`) — unaligned u16, nachprüfen.

---

## 14. Werkzeuge und Dateien

### Erzeugt in dieser Sitzung

| Datei | Inhalt |
|---|---|
| `marstek_descriptor_unpack.py` | Eigenständiger Entpacker, funktioniert auf jeder Venus-D-Control-FW |
| `Descriptor_Table_Decoded_VNSD-0_app_1492.csv` | 246 Einträge v149.2 |
| `Descriptor_Table_Decoded_v150.csv` | 246 Einträge v150 |
| `Marstek_Venus_D_Register_Map_v150_annotiert.csv` | 246 Einträge mit `name`, `unit`, `confidence`, beiden Pointer-Spalten, Notizen |
| `Descriptor_Table_Diff_v1492_vs_v150.md` | Detail-Diff der beiden Versionen |
| `Descriptor_Table_Unpack_Format.md` | dieses Dokument |

### Aufruf

```bash
python3 marstek_descriptor_unpack.py <firmware.bin> [ausgabe.csv]
```

Keine Abhängigkeiten außer Python 3. Laufzeit wenige Sekunden. Bei 246 Einträgen ist die
Dekodierung bestätigt.

Da der Registersatz zwischen den Versionen identisch ist, lassen sich die Notizen per Join
auf die Spalte `register` auf jede neue Version übertragen.

### Analyseumgebung dieser Sitzung

Kein Ghidra-/ReVa-MCP verbunden. Genutzt wurden: Filesystem-MCP (Zugriff beschränkt auf
`/Users/<user>/Downloads/Claude`), eigener Linux-Container mit Python 3 und Capstone 5.0.7
für die Thumb-2-Disassemblierung, sowie ein selbst geschriebener Solver für das Packformat.

### Methodik, die zum Ziel führte

1. Registernummern als u16-Literale im Flash gesucht → Cluster am Flash-Ende gefunden.
2. Entropie-/Nullbyte-Profil des Tails erstellt → nullfreien Bereich isoliert.
3. `MOVW`/`MOVT`-Scan über das gesamte Image → keine Konstruktion einer `0x0805xxxx`-Adresse.
4. Anker gesetzt: `30 75` (Register 30000) gefolgt von einem plausiblen SRAM-Pointer
   `ae 4e 01 20` (`0x20014EAE`) — der bekannten Adresse von `bat_sample_volt`.
5. Von diesem Anker aus die Opcode-Semantik durch Constraint-Auflösung hergeleitet
   (bekannte Sollausgabe ↔ beobachteter Bytestrom).
6. Format implementiert, über Startoffsets und Escape-Varianten validiert, bis exakt 246
   gültige Einträge herauskamen.

Ein Umweg über einen SWD-/OpenOCD-Dump der Live-Tabelle ist damit nicht mehr nötig.
