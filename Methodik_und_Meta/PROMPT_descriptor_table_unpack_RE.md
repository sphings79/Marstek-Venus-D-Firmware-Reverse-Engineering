# Aufgabe: Entpack-Format der Modbus-Descriptor-Tabelle vollständig reverse-engineeren

Du arbeitest am Projekt **Marstek Venus D FW Debug**. Ghidra ist über den **ReVa-MCP**
verbunden (Setup s. Projekt-Memory `reference_ghidra-mcp-setup.md`: ReVa-Extension in
pyghidra auf `127.0.0.1:8080/mcp/message`). Lies zu Beginn die Projekt-Memory-Dateien
`reference_modbus-register-serving.md`, `project_modbus-scan-fixes-2026-08-14.md` und
`project_control-fw-150-analysis.md` — dort steht der Kontext.

## Ziel

Die Firmware bedient Modbus-FC03-Reads über eine **Descriptor-Tabelle im SRAM** (Register →
Typ/Skala/Quellzeiger). Diese Tabelle wird beim Boot aus einer **kodierten/gepackten
Init-Struktur im Flash** aufgebaut. Entschlüssle dieses Entpack-Format vollständig und
extrahiere daraus die **exakte Zuordnung für alle Register**:

`Register-Nr → Typ → Skala → SRAM-Quellzeiger → Count`

Damit lässt sich für jedes noch unklare Register (v. a. **32101 dc_current beim Entladen**)
eindeutig sagen, wie sein Wert entsteht.

## Bekannter Stand (nicht neu herausfinden — verifizieren)

**Programm in Ghidra:** `/VNSD-0_app_0150_0805_115146.bin` (Control FW v150, ARM Cortex-M,
1618 Funktionen, Flash-Basis 0x08000000). SRAM 0x20000000 ist NICHT im statischen Image →
die Live-Tabelle kann man statisch nicht lesen, nur die Flash-Quelle.

**Serving-Pfad (bereits analysiert, Plate-Kommentare gesetzt):**
- `FC03_Read_Handler` @ `0x0801f06c` (TCP) und `RS485_FC03_ReadWrite_Handler` @ `0x0802a990`
  (RS485) → Descriptor-Lookup → `Read_Serializer` @ `0x08050c14`.
- Descriptor-Basis: Literal-Pool `0x0801f1f8` = **`0x20000354`** (zweiter Leser-Pool
  `0x0802aae8`). Tabelle = **246 Einträge à 12 Byte** (0x20000354 … 0x20000EDC).
- **Eintrags-Layout (12 B), abgeleitet aus Read_Serializer:**
  - `+0`  u16  Register-Nummer (Basis der Gruppe)
  - `+2`  u16  (unklar / evtl. reserviert)
  - `+4`  u32  **Quellzeiger** (SRAM-Adresse der Rohdaten)
  - `+8`  u8   **Typ-Code**
  - `+9`  u8   low-nibble (&0xf) = Elementgröße in Byte
  - `+10` u8   **Skala-Code**
  - `+11` u8   Count (Anzahl Elemente)
- **Typ-Codes:** 01=u8, 02=u16, 04=u32, 11=i8, 12=i16, 14=i32, 24=float(IEEE754),
  31=ASCII(memcpy).
- **Skala (int):** 0=×1, 1=×10, 2=×100, 3=÷10, 4=÷100, 5=negate.
  **Skala (float):** 0=×1, 1=×10, 2=×100, 3=×0.1, 4=×0.01 (Konstanten @0x0805009C/A0/A4).
- Read_Serializer kopiert nur die **Registerbreite** (meist 2 Byte) → breite/float-Quellen
  werden auf 16 Bit abgeschnitten (erklärt u. a. den 32101-Entladewert 0x9965).

**Flash-Quelle der Tabelle:** Nur die 2 o. g. Leser referenzieren `0x20000354` als Literal —
KEIN Builder lädt die Basis direkt. Die Tabelle ist also entweder ein `.data`-Global (vom
C-Startup aus einer Flash-LMA kopiert) oder wird von einer Routine (De-/Entpacker) gefüllt.
Die Register-Nummern stehen NICHT als flache Liste im Flash. Beim Scan nach den 16-Bit-Basen
tauchen sie in einer **gepackten Struktur am Flash-Ende (~`0x0805dcb0`)** auf: dort liegen
`30000` @0x0805dcb8, `31000` und `32100` @0x0805de4e, umgeben von wiederkehrenden 16-Bit-
Mustern **`0x5A0C` (23052)** und **`0x1A0C` (6668)** — sehr wahrscheinlich Token/Marker eines
RLE- oder Token-Formats. `32200`/`34000` fehlen dort als Literal → Gruppen werden vermutlich
aus Basis + Offset expandiert.

## Vorgehen (Vorschlag)

1. **Startup/Init finden:** Reset-Vektor (aus der Vektortabelle @0x08000004) → Reset_Handler.
   C-Runtime-`.data`-Kopierschleife (`__etext`/`_sdata`/`_edata`-Muster) suchen. Falls die
   Tabelle im `.data`-Bereich liegt: LMA der VMA `0x20000354` berechnen und die 2952 Byte
   **direkt als 12-Byte-Einträge parsen** (dann ist nichts komprimiert).
2. **Falls gepackt:** Den Entpacker/Decompressor identifizieren (die 0x5A0C/0x1A0C-Marker
   verfolgen; prüfen ob es eine bekannte GCC-/Keil-Dekompression oder ein Custom-Format ist)
   und das Format vollständig dekodieren. Alternativ die **Runtime-Builder-Funktion** finden,
   die in den Bereich 0x20000354… schreibt (Basis evtl. als `0x20000000 + 0x354` aus zwei
   Immediates oder über einen globalen Zeiger).
3. **Tabelle rekonstruieren:** Alle 246 Einträge dekodieren → Register-Nr, Typ, Skala,
   Quellzeiger, Count.
4. **Gegenprüfen** (Pflicht) gegen bekannte Register — die Dekodierung ist nur korrekt, wenn
   diese passen:
   - `32200` ac_voltage → u16, ÷10 (×0.1 V) ; `32204` ac_frequency → i16 ÷10
   - `30006` ac_power ; `30001` battery_power (i16/i32, ×1 W)
   - `32105` bat_total_energy (×0.001 kWh) ; `34002` SoC ÷10
   - `30350-30355` ASCII (Typ 0x31) ; `31000` device_name ASCII
   - Kalibrierwerte s. Projekt-Memory `project_discharge-calibration-2026-08-14.md`.
   - **Neu in v150:** Der Registerblock `38000-38014` existierte in der Vor-Update-Firmware
     (vor v150/VMS116) NICHT. Er MUSS also in der v150-Descriptor-Tabelle neu hinzugekommen
     sein → idealer Gegentest: nach dem Dekodieren müssen 38000-38014 als eigene Einträge
     auftauchen (Typ/Quelle zeigt, was sie sind — bisher unbekannt, im Scan alle 0).
5. **32101 auflösen:** Eintrag von 32101 (Typ/Skala/Quellzeiger) extrahieren, dann den
   **Writer** des Quell-SRAM-Slots finden und die Lade-/Entlade-Verzweigung zeigen — damit ist
   endgültig geklärt, warum Laden saubere Ampere und Entladen 0x9965 liefert.

## PyGhidra-Fallstricke (wichtig)

- `run-script` läuft in **CPython (PyGhidra), NICHT Jython** → `import jarray` schlägt fehl.
  Für Java-Byte-Arrays `jpype`/`from java.lang import …` nutzen ODER — am robustesten —
  Speicher mit `mem.getByte/getShort/getInt` in Schleifen lesen. **Achtung:**
  `mem.getBytes(addr, python_bytearray)` füllt das bytearray NICHT zuverlässig (in dieser
  Umgebung lieferte es Nullen) — nicht darauf verlassen, stattdessen wortweise lesen oder
  `mem.findBytes` mit echtem Java-`byte[]`.
- Änderungen (Rename/Kommentare) in `currentProgram.startTransaction(...)`/`endTransaction(...)`
  klammern. Analyse ansonsten read-only.

## Deliverables

1. **Dekodierte Tabelle** als CSV im Projekt:
   `Modbus_RS485_TCP/Descriptor_Table_Decoded.csv` (Spalten: register, type, scale, elem_size,
   count, source_ptr, notes) — alle 246 Einträge.
2. **Register-Map aktualisieren** (`Modbus_RS485_TCP/Marstek_Venus_D_Register_Map_Final_all_register.csv`):
   Type/Scale/Confidence für die Register präzisieren, die durch die Tabelle nun eindeutig sind
   (v. a. die bisher „Verm/Unb"-Register). Bestehendes Format/Spalten beibehalten.
3. **32101 endgültig klären** (Typ + Quelle + Writer + Lade/Entlade-Branch), Ergebnis in die
   Map-Notiz und in `reference_modbus-register-serving.md` schreiben.
4. **Ghidra-Kommentare** am Entpacker/Builder + relevanten Struct-Zugriffen setzen.
5. **Doku:** `Modbus_RS485_TCP/Marstek_Modbus_TCP_Verbindungsreferenz.md` um das Entpack-Format
   ergänzen. **Projekt-Memory** aktualisieren.
6. **Dateien auf die Platte committen** (device_commit_files) und dem Nutzer die Ergebnisse
   zusammenfassen — insbesondere die neu eindeutig gewordenen Register.

## Falls statisch nicht auflösbar

Wenn das Entpack-Format nach ernsthaftem Versuch nicht knackbar ist: das ehrlich sagen,
dokumentieren wie weit du gekommen bist, und als Alternative die **Live-SRAM-Tabelle
(0x20000354) per Debugger/SWD (OpenOCD) vom laufenden Gerät auslesen** vorschlagen (246×12 B
dumpen und mit obigem Layout parsen) — das umgeht die Dekompression komplett.
