# Querverweis Modbus-Register ↔ SRAM ↔ BLE-Payload (v150)

**Datum:** 22. August 2026
**Daten:** `Querverweis_Modbus_SRAM_BLE_v150.csv`
**Zweck:** Die drei Endpunkte desselben Geräts nebeneinander stellen — und vor allem
sichtbar machen, welche Werte **nur auf einer Seite** existieren.

---

## 1. Wie die Tabelle entsteht

Die SRAM-Adresse ist der gemeinsame Schlüssel.

| Seite | Quelle | Was sie liefert |
|---|---|---|
| Modbus | `Descriptor_Table_Decoded_v150.csv` | Register → SRAM-Zeiger, Typ, Skala |
| BLE | `FUN_0800b024` (`0x0800b024`), Puffer `0x20018857` | Payload-Offset → SRAM-Quelle |
| App | `StatePayload.ts` aus VenusControl | Payload-Offset → Feldname |

Aus dem Dekompilat von `FUN_0800b024` wurden 81 Zuweisungen in den BLE-Puffer
extrahiert; bei 42 davon ließ sich die Quelle direkt auf eine SRAM-Adresse auflösen.
Der Rest sind Konstanten, Zwischenvariablen oder Rechnungen — die stehen in der Spalte
`herkunft`.

## 2. Ergebnis

| | Zeilen |
|---|---|
| beidseitig belegt (Modbus **und** BLE) | 19 |
| nur BLE | 60 |
| nur Modbus | 362 |

**Der BLE-Payload ist also nicht die ärmere Schnittstelle.** Er trägt 60 Felder, die über
Modbus nicht erreichbar sind — darunter die beiden berechneten Leistungswerte.

### Gesichert beidseitig

| BLE | App-Feld | SRAM | Modbus |
|---|---|---|---|
| `0x00` | BackupLoadPower | `0x20014EB6` | 30007 / 32302 |
| `0x02` | AcOutputPower | `0x20014EB4` | 30006 / 32202 / 37004 |
| `0x04` | InverterState | `0x20014E9C` | 35100 |

Diese drei sind an Messwerten verifiziert (Lasttest 600 W, siehe
`BLE_vs_Modbus_Leistungswerte_2026-08-22.md`).

### Nur BLE, weil berechnet

| BLE | App-Feld | Formel |
|---|---|---|
| `0x8C` | BatteryPower | `32100 (×0,01 V) × 32101 (×0,1 A)` |
| `0x90` | GridPower | `s10 − off_grid_power`, mit `s10` je nach `grid_sample_power` und `inv_state` |
| `0x8E` | — | `MPPT-Summe / 10 − s10` |
| `0x92` | — | `s10` |

Diese Werte brauchen kein fehlendes Register: sie lassen sich aus vorhandenen
Registern nachbilden.

## 3. Einschränkungen — bitte beim Weiterarbeiten beachten

Die Tabelle ist ein **Arbeitsstand**, keine geprüfte Referenz. Drei bekannte Schwächen:

1. **Überdeckende Descriptor-Einträge.** Register mit `elem_size 4` belegen zwei Worte,
   deshalb erscheint z. B. `32202` sowohl bei BLE `0x00` als auch bei `0x02`. Nur die
   exakte Basisadresse ist verlässlich, nicht jede Folgeadresse.
2. **Die App-Feldnamen** stammen aus einer Regex über `StatePayload.ts` und sind nach
   Offset zugeordnet. Wo die App einen Offset nicht dekodiert, bleibt die Spalte leer —
   das heißt nicht, dass dort nichts steht.
3. **Zufallstreffer im Join.** Einige Zuordnungen im 41000er-Bereich (`WorkMode` →
   43101, `CTType` → 41507 …) beruhen auf SRAM-Adressen, die in beiden Welten belegt
   sind, ohne dass ein inhaltlicher Zusammenhang belegt wäre. Sie sind als Hinweis
   brauchbar, als Aussage nicht.

Verlässlich sind die Zeilen, deren SRAM-Adresse exakt einem Descriptor-Basiseintrag
entspricht — und die drei oben, die an Hardware gegengeprüft sind.

## 4. Wozu die Tabelle gut ist

Drei Fragen dieses Abends wären damit in Minuten statt Stunden zu beantworten gewesen:

- *„Gibt es für Grid Power ein Modbus-Register?"* → Zeile `0x90`, Spalte `nur` = BLE,
  Spalte `herkunft` nennt die Formel.
- *„Warum weicht Battery Power ab?"* → Zeile `0x8C`, andere Herkunft als Modbus 30001.
- *„Welches Register hält denselben Wert wie X?"* → über die SRAM-Spalte gruppieren.

Der nächste sinnvolle Ausbau wäre die Gegenrichtung: die 362 Modbus-Register ohne
BLE-Gegenstück danach durchsehen, welche davon überhaupt je einen Wert ungleich null
geliefert haben — dafür liegen mit den beiden Lastscans schon zwei Datenpunkte vor.
