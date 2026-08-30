# Marstek Venus D — Analyse-Skripte (Übersicht)

**Projekt:** Marstek Venus D (`VNSD-0`) Reverse Engineering
**Bezug:** Ausgelagert aus [Control_FW_Analyse_app_1492_0702_142136.md](Control_FW_Analyse_app_1492_0702_142136.md) (ehemals Abschnitt 12)

**Stand 2026-07-14:** Diese Übersicht wurde gegen den tatsächlichen Ordnerinhalt geprüft und
korrigiert (Cross-Check vom 2026-07-10 hatte angemerkt, dass mehrere referenzierte Skripte nicht
mehr existieren). Abschnitte 1 und 5 listen die **tatsächlich vorhandenen** Skripte; Abschnitte
2–4 dokumentieren frühere Einmal-Werkzeuge, die inzwischen aus dem Projektordner entfernt wurden
(Ergebnisse bleiben in den jeweiligen Analyse-Dokumenten erhalten).

---

## 1. Modbus-TCP Scan-Skripte (vorhanden im Projektordner)

| Skript | Beschreibung | Verwendung |
|---|---|---|
| `scan_registers.py` | Flexibler Register-Scanner (Raw-Socket, kein pymodbus) — einzelne/Bereichs-Register, Watch-Modus, `--unknown-only`-Filter | `python3 scan_registers.py --host IP --regs 30000-30040,32200,34000-34033` |
| `scan_known_registers.py` | Gezielter Scan **nur** der in der Register-Map (CSV) bereits bekannten Register — ~30 statt ~440 Batches, ca. 30× schneller als Vollscan | `python3 scan_known_registers.py --host IP --out scan.csv` |
| `scan_continuous.py` | Dauerscan bekannter Register in festem Intervall, CSV mit einer neuen Spalte pro Durchlauf (Ctrl+C speichert & beendet) | `python3 scan_continuous.py --host IP --interval 10 --out monitor.csv` |
| `scan_powercycle.py` | Event-Scanner für Zustandswechsel (Power-Cycle, Batterie-DC-Trennung, Offgrid/Notstrom, Force-Mode-Wechsel) — fokussiert auf unbekannte/bisher-immer-0-Register | `python3 scan_powercycle.py --host IP --interval 2 --out event_scan.csv` |

**Hinweis zu Batch-Performance** (galt für den ursprünglichen Vollscan-Ansatz):

| Methode | Requests für 65535 Reg | Zeit (100ms/Req) |
|---|---|---|
| Einzel | 65.535 | ~109 Stunden |
| Batch (32/Req, wie aktuelle Skripte) | ~2.048 | **deutlich schneller, s. `scan_known_registers.py` für gezielten Scan** |

*Korrektur ggü. früherer Version dieser Datei:* Die früher hier gelisteten `scan_modbus.py` /
`scan_modbus_batch.py` (125 Register/Request) existieren nicht mehr im Projektordner — die o. g.
vier Skripte sind die aktuell genutzten Nachfolger. **Bekannter offener Punkt (nicht Teil dieses
Bereinigungslaufs):** `Marstek_Modbus_TCP_Verbindungsreferenz.md` referenziert in Abschnitt 7/8
ebenfalls noch `scan_modbus_batch.py` und `test_batch_limit.py` — beide ebenfalls nicht mehr
vorhanden. Das müsste in einem separaten Durchgang an jener Datei korrigiert werden.

## 2. Firmware-Analyse-Skripte (historisch, Skripte nicht mehr vorhanden)

Diese sechs Einmal-Skripte wurden zur Auffindung der Modbus-Register-Tabelle im Firmware-Image
eingesetzt. Sie existieren nicht mehr im Projektordner; die jeweiligen Ergebnisse sind in
`Control_FW_Analyse_app_1492_0702_142136.md` dokumentiert.

| Skript | Version | Methode | Ergebnis |
|---|---|---|---|
| `find_registers_v2.py` | v2 | 6 Strategien (Strings, MOVW, Cluster) | MOVW #0x7530 bei 0x0801295e gefunden |
| `find_registers_v3.py` | v3 | Gezielte Analyse bekannter Adressen | String-Pool bei 0x08018000 gefunden |
| `find_registers_v4.py` | v4 | SRAM-Ptr-Validierung | Tabelle nicht gefunden (0 Treffer) |
| `find_registers_v5.py` | v5 | ARM Thumb-2 Disassemblierung | Init-Funktion-Region eingegrenzt |
| `find_registers_v6.py` | v6 | .data-Section-Mapping | 0x08055d4c = MQTT-Strings (falsch) |
| `find_registers_v7.py` | v7 | STR-Offset-Suche + Pointer-Analyse | 0 STR-Treffer; SRAM-Ptr-Blöcke gefunden |

## 3. YAML-Generator (historisch, Skript nicht mehr vorhanden)

`generate_final_yaml.py` existiert nicht mehr im Projektordner. Ursprünglicher Aufruf (zur
Dokumentation des damaligen Workflows):

```bash
python3 generate_final_yaml.py \
    --csv30 register_3000039999_matched.csv \
    --csv40 register_4000049999_matched_csv.csv \
    --out   marstek_venus_registers_final.yaml
```

## 4. Ghidra-Skripte (Jython 2.7, historisch, nicht mehr vorhanden)

| Skript | Beschreibung |
|---|---|
| `MaerstekExtractor.py` | Schreibt Descriptor-Einträge via getReferencesFrom() (0 Treffer ohne SRAM-Block) |
| `MaerstekDecompiler.py` | Nutzt Ghidra-Decompiler + Regex-Parser |
| `FindRouterCallers.py` | Findet Aufrufer von FUN_0801c088 → führt zu Init-Code |

## 5. Sonstige vorhandene Skripte (bisher nicht in dieser Übersicht gelistet)

| Skript | Ort | Beschreibung | Doku |
|---|---|---|---|
| `shell_probe.py` | Projekt-Root | TCP-Shell-Probe (Port 8091), testet Text-CLI-Format und Binary-BLE-Protokoll (`[0x73][len][0x23][cmd][payload][XOR-CRC]`) | siehe `Shell.md` |
| `marstek_rot_cipher.py` | Projekt-Root | ROT-N-Cipher-Tool zur AES-Key-Extraktion (reversiert die ROT-6/7/9-Obfuskierung der Firmware) | bereits dokumentiert in `AES_Crypto_Stack_Analyse.md` |
| `security/brute_force_certs.py`, `security/brute_force_venuse.py`, `security/brute_force_vnsa.py` | `security/` | Repliziert den `marstek-firmware-analyzer`-Brute-Force-Algorithmus (Key- und Base64-Cert-Kandidaten × Caesar/ROT-Shifts) gegen Venus-D/E/A-Firmware-Dumps | bisher **nicht** in einer Analyse-Datei referenziert — thematisch zu `AES_Crypto_Stack_Analyse.md`/`security_problems.md` §4 gehörig, aber nicht Teil dieses Bereinigungslaufs (Skripte betreffen Security-Thema, nicht Modbus/Register-Scanning) |
| `security/build_doc.py`, `security/merge.py` | `security/` | Einmalige Merge-Hilfsskripte (Ghidra-Funktionsdump ↔ Function-Tracking-Doc), referenzieren einen alten Sessionpfad (`/sessions/laughing-focused-volta/...`) | keine laufende Verwendung erkennbar, nicht weiter dokumentiert |

*Anmerkung:* Die drei `brute_force_*.py`-Skripte und `build_doc.py`/`merge.py` wurden bei dieser
Prüfung im `security/`-Ordner gefunden, gehören aber thematisch nicht zu dieser
Modbus/Firmware-Scan-Skript-Übersicht. Da es sich um ein Querschnittsthema handelt (Security-Tooling
vs. Register-Scanning-Tooling), wurden sie hier nur informativ gelistet statt in Abschnitt 1
eingemischt — ob dafür eine eigene Kurz-Doku sinnvoll ist, sollte der Nutzer entscheiden.

---

## Warnung: fehlende Transaction-ID-Prüfung in älteren Scannern (2026-08-22)

`scan_continuous.py` und `scan_known_registers.py` setzen im MBAP-Header zwar
eine Modbus-Transaction-ID, **prüfen sie beim Empfang aber nicht**. `parse()`
validiert nur den Funktionscode. Trifft eine verspätete Antwort auf Anfrage N
ein, während Anfrage N+1 offen ist, wird sie als Antwort auf N+1 gelesen — die
Werte landen im falschen Register.

Nur `scan_registers.py` validiert (`recv_response(..., expect_tid=...)`).

### Nachgewiesener Fall

Register `38003` zeigte in drei Logs den Wert `118`, was zur Vermutung führte,
der CAN-Frame-Puffer werde gelegentlich befüllt. Tatsächlich stammt die 118 aus
Register `37012` (`bms_version`):

| Log | `37012` | `38003` |
|---|---|---|
| `entladen_lang.csv` | 118 in 65/66 Batches, **0 in genau einem** | 0 in 65/66, **118 in genau demselben** |
| `entladen_dc.csv` | 118 in 3/4, 0 in einem | 0 in 3/4, 118 in demselben |
| `unklar_watch discharge ...csv` | 118 in 7/8, 0 in einem | 0 in 7/8, 118 in demselben |

Die Komplementarität ist exakt: Wo der eine Wert verschwindet, taucht er im
anderen Register auf, im selben Batch.

### Konsequenz für die Auswertung

- **Einzelne** abweichende Werte in Logs dieser beiden Skripte sind
  grundsätzlich verdächtig. Vor jeder Schlussfolgerung prüfen, ob im selben
  Batch ein anderes Register seinen üblichen Wert verloren hat.
- Werte, die über viele Batches **stabil** sind, sind davon nicht betroffen.
- Für neue Messungen `scan_registers.py` oder
  `watch_can_frames_38000.py` verwenden — beide validieren die TID.

Der Fehler ist in den beiden Skripten noch **nicht** behoben.
