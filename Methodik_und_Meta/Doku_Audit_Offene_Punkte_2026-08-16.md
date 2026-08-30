# Doku-Audit: „Blockierte" Aussagen & offene Punkte

**Datum:** 16. August 2026
**Anlass:** Systematische Prüfung der gesamten Projekt-Doku (37 MD-Dateien) auf Aussagen der
Form „nicht im Code / nicht im Bin / nicht möglich / zur Laufzeit generiert / nur per SWD-Dump".
**Leitthese (bestätigt):** Solche Aussagen waren mehrfach zu pessimistisch. Was im Gerät läuft,
liegt fast immer irgendwo im Flash — man muss nur gründlich genug (und im richtigen Image) suchen.

**Track Record dieser Session:**
- „Pack-Feldnamen nur im fehlenden Flash-Tail / nur per SWD" → **widerlegt**: Namen liegen im
  Control- UND BMS-Image; Debug-Funktion `BMS_Debug_PerPack_Detail_Print` nach Disassemblieren
  freigelegt. (Descriptor_Offene_Register §12)
- „0xAA-Handler-Tabelle 0x2000018c nur per Live-RAM-Dump klärbar" → **funktional widerlegt**:
  alle 8 Per-Pack-Store-Handler gefunden + benannt, Register byte-genau gemappt. (§13)

---

## Kategorien

- ✅ **REFUTED** — in dieser Session bereits gelöst; Quelldoku ist veraltet und sollte korrigiert werden.
- 🔍 **RE-INVESTIGATE** — Aussage vermutlich zu pessimistisch; mit den neuen Techniken (Disassemblier-
  Läufe versteckter Funktionen, findBytes, Cross-FW-Abgleich) angreifbar.
- ⛔ **DATA-LIMIT** — Bytes physisch in KEINEM verfügbaren Image (echter Verfügbarkeits-Blocker);
  aber pro Fall neu zu prüfen, ob die Info nicht anderswo (Nachbar-FW, Live-Output) steht.

---

## Befunde (Datei : Zeile)

### ✅ REFUTED — Quelldoku veraltet, Korrektur nötig

| Fundstelle | Aussage | Realität (2026-08-16) |
|---|---|---|
| `Control_FW_Analyse_app_1492…md:1806` | „0xAA-Kommandotabelle (RAM 0x2000018c) … keine Schreib-Xref … nur per Live-RAM-Dump oder CAN-Sniffing" | 8 Handler @0x0802f764.. gefunden+benannt; Gruppen→Offsets→Register vollständig gemappt (BMS-CAN-TX-verifiziert). Nur die rohe Slot-Reihenfolge im RAM bleibt kosmetisch offen. |
| `…1492…md:2503 / 2520 / 2526` | „17-Entry-Handler-Tabelle … statisch nicht bestimmbar" | dito — funktional bestimmt. |
| `Descriptor_Offene_Register…md:167/241/246/305/344-350/376` (Abschn. 1,6,7e,9) | „Pack-Feldnamen im fehlenden Flash-Tail, nur per SWD-Dump" | **widerlegt** — s. §12/§13 derselben Datei. Alte Abschnitte brauchen Korrektur-Hinweis. |
| `…1492…md:4360` | „Registernummern zur Laufzeit berechnet, nicht als Array auffindbar" | Descriptor-Unpack-Format wurde rekonstruiert (`Descriptor_Table_Unpack_Format.md:412`: „SWD-Dump nicht mehr nötig"). |

### 🔍 RE-INVESTIGATE — lohnt einen gründlichen Angriff

| Fundstelle | Aussage | Angriffsplan |
|---|---|---|
| `Micro_Inverter_FW…md:2684` | „Descriptor-Tabelle wird von Code im externen Flash (0x10000000+) aufgebaut … nicht extrahierbar" | Prüfen ob Builder-Code doch im analysierten Binary liegt; QSPI-Mapping/Init suchen; ggf. Nachbar-Micro-FW (VNSA/VNSE3) vergleichen. Disassemblier-Lauf über undefinierte Bereiche (analog BMS). |
| `Micro_Inverter_FW…md:2646` | „runtime-aufgebaute Descriptor-Tabelle 0x200004C0" | Wie beim Control: den Aufbau-/Store-Code per Prolog-Scan freilegen. |
| `…1492…md:1980 / 2061 / 2066 / 2154` | „callerCount 0 / vermutlich zur Laufzeit registrierter Funktionszeiger / nicht auffindbarer Aufrufer" | Genau das Muster der Per-Pack-Handler. Undefinierte Code-Regionen disassemblieren, dann Xref-Neuprüfung; Callback-Registrierung suchen. |
| `Shell.md:354` | „4-Byte-Befehlsmuster in Flash-Sektor 7 (0x08060EF8), nicht im Binary" | 0x08060EF8 liegt hinter dem OTA-Image-Ende — aber die Match-Werte werden evtl. im nutzenden Code (Vergleiche) materialisiert; find-constants im Dispatcher prüfen. |
| `…1492…md:2294` | „Kein Klartext-String konnte rekonstruiert werden" (Krypto/Modulus) | Kontext prüfen; falls RSA/Schlüssel: ggf. aus Zertifikaten/Nachbar-FW ableitbar (vgl. TLS-Key-Erfolg). |

### ⛔ DATA-LIMIT — echter Verfügbarkeits-Blocker (pro Fall verifiziert)

| Fundstelle | Aussage | Status |
|---|---|---|
| `Descriptor_Offene_Register…md` (Cloud-Formatstrings 0x0805F000–0x08063000) | ~290 Pointer zeigen hinter das Image-Ende | Bytes in KEINEM der 14 Archiv-Images. ABER: Pack-Feldnamen & Cloud-JSON-Keys sind DOCH in-image (§12) — nur die druckende Cloud-Funktion fehlt. Für die Register irrelevant. |
| `Descriptor_Table_Unpack_Format.md:15-18`, `Reverse_Engineering_Methodik.md:137-139`, `Control_FW_Analyse_app_0150…md:180/368` | Descriptor-Tabelle 0x20000354 „zur Laufzeit aufgebaut" | Registernummern per Live-Scan enumerierbar; Unpack-Format aber rekonstruiert. Kein Blocker mehr für die Bedeutung, nur für die reine Nummern-Enumeration ohne Gerät. |
| `BMS_FW_Analyse_v117.7.md:328` | Werte-Auslesen nur per SWD/Debug-Shell | Betrifft Live-Werte, nicht Struktur. |

### ℹ️ KEINE Blocker (Falsch-Positive des Scans)

- `BLE_Command_Map_v150.md:91` (Meter-IP auto-discovered) — Feature-Beschreibung, kein RE-Blocker.
- `BMS_FW_Analyse_v118.md:167` („in 117.7 nicht vorhanden") — Versions-Diff-Aussage, korrekt.
- `Micro…md:41` (WiFi nicht vorhanden), `Fehlercodes_Micro…md:213` (Trenntest mechanisch) — sachlich.
- `Control…1492…md:1071/1276/1526/1527` — Register im Scan nicht vorhanden = HW-abhängig (MPPT/DCDC nicht verbaut), kein Code-Blocker.

---

## Empfohlene Reihenfolge für den nächsten Durchgang

1. **Micro-Descriptor 0x200004C0 / „externes Flash"** — größter offener „nicht extrahierbar"-Claim;
   mit dem BMS-Disassemblier-Rezept angehen.
2. **„callerCount 0 / runtime-Funktionszeiger" im Control** — systematisch alle undefinierten
   Code-Regionen disassemblieren (wie in §12 begonnen: Control 1630→1884), dann Xref-Neubewertung.
3. **Shell.md Command-Matcher (Sektor 7)** — Match-Werte aus dem nutzenden Vergleichs-Code ziehen.
4. **Quelldoku-Korrekturen** für die ✅-REFUTED-Einträge (Verweise auf §12/§13 bzw. neue Befunde).

*Erstellt nach Volltext-Grep über 37 MD-Dateien + gezielter Ghidra-Verifikation. Die ✅-Einträge
sind belegt; die 🔍-Einträge sind noch nicht abschließend geprüft, aber nach bisheriger Erfahrung
mit hoher Wahrscheinlichkeit lösbar.*

---

## Systematischer Durchgang 2026-08-16 — Ergebnis & vereinheitlichende Erkenntnis

Alle 🔍-Punkte per Ghidra gründlich geprüft (inkl. zusätzlicher Disassemblier-Läufe). Ergebnis:

### Was IM Code liegt und rekonstruiert wurde (These bestätigt)
- **Alle funktionalen Handler/Tasks/Funktionen** sind im Image und analysierbar — bewiesen an den
  8 Per-Pack-CAN-Store-Handlern (byte-genaues Register-Mapping) und den Debug-Print-Funktionen.
- **Micro-Descriptor-Format 0x200004C0**: vollständig aus `modbus_read_register_block` dekodiert
  (12-Byte-Eintrag: Reg@+0, Quellzeiger@+4, Typ@+8, elem_size@+9, Scale@+0xa, count@+0xb;
  Scale-Codes 0x01=×10 … 0x04=×0.01). Contents per Live-Scan + Debug-Prints rekonstruierbar (wie Control).

### Der EINE gemeinsame, verifizierte Blocker
Mehrere „wer registriert/ruft X"-Fragen (0xAA-Tabellen-Registrar, `Serial_Command_Dispatch`,
`UART_Packet_Receive_Parse`, `Modbus_Dispatcher`/`CH395_UDP_ServerTask`-Taskerzeugung) enden alle
gleich: **die Adressen dieser Funktionen kommen als 32-Bit-Wert NIRGENDWO im verfügbaren Flash vor**
(exhaustiv per findBytes für even+thumb geprüft; Methode verifiziert — 0x20014FB4 liefert 22 Treffer,
0x2000018c genau 1). Da das Image auch kein `movt` nutzt und `adr` die verstreuten Ziele nicht
erreichen kann, liegt die **Registrierungs-/Verdrahtungs-Schicht nachweislich in dem Flash-Bereich,
der in KEINEM OTA-Image enthalten ist**:
- **Control:** Tail ab `0x0805F000` (Sektor 7, u.a. auch Shell-Command-Match-Tabelle 0x08060EF8).
- **Micro:** separater Bereich `0x10000000+` (~128 KB, Builder der Descriptor-Tabelle; FileBytes=Mapped, kein Anhang).

**Konsequenz:** Das ist ein **echter, verifizierter Datenverfügbarkeits-Blocker** — kein
Gründlichkeitsproblem. Die *Bedeutung* aller Register ist trotzdem geklärt (über Handler + Debug-Prints
+ Live-Scan); nur die *Verdrahtung* (welcher Slot ruft welchen Handler, welcher Task startet wo)
braucht die fehlenden Sektoren. **Einzige echte Lösung: Voll-Chip-Dump via SWD/JTAG** des laufenden
Geräts (bzw. das externe 0x10000000-Image des Micro).

### Nicht-Blocker (aufgelöst/umkategorisiert)
- „Punkt #12 / kein Klartext-String" (Control 2294): bereits als **binärer Registerpuffer-Init**
  (`Inverter_Register_Buffer_Init`) erkannt, keine String-Obfuskation → kein Blocker.

### Fazit
Deine Devise stimmt für **alles Funktionale**: es steht im Code, man muss nur (oft in
nicht-disassembliertem Code) gründlich suchen. Der verbleibende Rest ist kein „nicht gefunden",
sondern „physisch nicht im verteilten Image" — und ist jetzt exakt lokalisiert und begründet.
