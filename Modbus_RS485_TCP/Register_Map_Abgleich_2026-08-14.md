# Register-Map-Abgleich: Firmware-Analyse ↔ Live-Scans

**Datum:** 14. August 2026
**Eingang:** 31 Scan-Logs (536.570 Datenpunkte), Descriptor-Tabelle v150, BMS v118, Micro v116
**Ausgang:** `Marstek_Venus_D_Register_Map_Final_all_register.csv` (505 Zeilen)

---

## 1. Was die neue Gesamt-Map enthält

| Quelle | Zeilen | Inhalt |
|---|---|---|
| **FC03-Descriptor** | 410 | 246 Descriptor-Einträge, **expandiert** auf alle tatsächlich belegten Register |
| **Write-Handler** | 95 | 41xxx/42xxx Config-/Schreibregister |

Die Expansion ist der Schlüssel: Der Descriptor listet nur **Startregister**. Belegte Register =
`ceil(elem_size × count / 2)`. Damit lösen sich alle vermeintlich „fehlenden" Register auf —
z.B. 30304→30304-30309 (MAC), 31000→31000-31009 (device_name), 34018→34018-34033
(16 Zellspannungen), 33000→33000-33001 (u32). **495 der 505 Register haben Live-Werte.**

## 2. Zwei Skalen — der häufigste Irrtum

Die alte Map und die Descriptor-Tabelle widersprachen sich scheinbar in 162 Fällen. Fast alle
sind **kein Widerspruch**, sondern zwei verschiedene Dinge:

- **`fw_scale`** — was die *Firmware* rechnet (Skalencode aus dem Descriptor)
- **`anzeige_faktor`** — was der *Client* rechnen muss, um die physikalische Einheit zu erhalten

Beispiel 30000: `fw_scale = x1` (die FW skaliert nicht) **und** `anzeige_faktor = 0.1` (der
Rohwert liegt in 0,1 V). Beides ist richtig. Die neue CSV führt daher **beide Spalten**.

Echte Abweichungen bleiben nur dort, wo Typ oder Bedeutung differieren (Abschnitt 4).

## 3. Durch Live-Daten bestätigt

| Register | Interpretation | Entladen | Laden | Urteil |
|---|---|---|---|---|
| 30001 | bat_sample_power, i16, W | **−2676 W** | **+2310 W** | ✓ Vorzeichen korrekt |
| 30006 | grid_sample_power, i16, W | +2511 W (Einspeisung) | −2467 W (Bezug) | ✓ |
| 32100 | bms_battery_voltage, **10 mV** | **53,10 V** | **54,49 V** | ✓ Laden > Entladen |
| 34002 | pack1_soc, 0,1 % | 57,7 % | 70,1 % | ✓ |
| 32204 | grid_pf, 0,1 Hz | 50,0 Hz | 50,0 Hz | ✓ |
| 34x18–34x33 | Zellspannungen, mV | 3177–3441 mV | | ✓ LFP-typisch |
| 34x13–34x16 | NTC-Block, 0,1 °C | 11,6–36,1 °C | | ✓ 4 Elemente bestätigt |
| 34x10 | bms_version | 116 / 118 / 1177 | | ✓ echte FW-Versionen |
| 34x03 | cycle_count | 0/1/6/7/10/12 | | ✓ klein, monoton |
| 34x04 | mos_status | 0..3 | | ✓ genau 2 Flags (Chg/Dsg MOS) |

## 4. Wo die Live-Daten meine Firmware-Hypothese **widerlegt** haben

Aus dem BMS-CAN-Frame-Layout hatte ich abgeleitet: 34x07 = `Max NTC`, 34x08 = `Min NTC`.
Die Scans zeigen etwas anderes:

| Register | Live-Wertebereich | Schluss |
|---|---|---|
| 34x07 | 0..7, fast immer 0 | **keine Temperatur** → Status-/Flagfeld |
| 34x08 | durchgängig 0 | **keine Temperatur** → Schutz-Bitmaske (`protect1`) |
| 34x09 | fast immer 0 | Schutz-Bitmaske (`protect2`) |
| 34x11 / 34x12 | 23,5–45,2 °C / 21,4–56,9 °C | **echte Temperaturen** ✓ |

Eine Temperatur läge konstant bei 200–400 (0,1 °C). Die ältere Live-Analyse
(`Final_claude_generated.csv`) hatte 34x08/34x09 bereits als `protect1/protect2` geführt —
**die Live-Daten behalten recht, meine Frame-Ableitung war falsch.** Korrigiert.

Die Temperaturaussage für 34x11/34x12 bleibt bestehen und ist jetzt beidseitig belegt
(BMS-CAN-Gruppe 0x41 **und** plausible Messwerte).

## 5. Bestätigter Defekt: Register 32101 (bms_battery_current)

| Zustand | Rohwert | Interpretiert | Plausibel? |
|---|---|---|---|
| **Laden** | 42 | 42 A | ✓ 2310 W / 54,49 V = **42,4 A** |
| **Entladen** | 39268…39270 | −26267 A | ✗ unbrauchbar |

Der Entladewert **variiert um ±1**, stammt also aus einem echten Messwert — es ist kein
konstanter Fehlwert, sondern eine falsche Skalierung/Vorzeichenbehandlung im Writer des
SRAM-Slots. Beim Laden ist die Kette korrekt.

**Für die HA-Integration:** 32101 nur beim Laden verwenden; beim Entladen auf 34x01
(`pack_bat_curr`) oder die Leistung 30001 ausweichen.

## 6. Pack-Nummerierung vereinheitlicht

Die Descriptor-Analyse hatte pack0..pack6 verwendet, das restliche Projekt (alte Map,
Scan-Skripte, Live-CSV-Spalten wie `p1_bat_soc`) zählt **pack1..pack7**. Auf die
Projektkonvention umgestellt: **34000er = pack1**, 34100er = pack2, …, 34600er = pack7.

## 7. Datenqualität der Logs

24 der 26 Logs sind in sich konsistent. Nur `entladen_lang.csv` und `laden_lang.csv` enthalten
vereinzelte Ausreißer (z.B. `work_mode` 62859 statt 0, `grid_pf` 49320 statt 500) — jeweils
Einzelmesswerte während Zustandswechseln, kein systematischer Versatz. Die Spalten `min_all`/
`max_all` der neuen CSV enthalten diese Ausreißer bewusst ungefiltert; für die Bewertung sind
die Spalten `v_entladen`/`v_laden`/`v_ref_v150` (Momentaufnahmen aus definierten Zuständen)
aussagekräftiger.

## 8. Konfidenzstand nach dem Abgleich

| Stufe | Anzahl (Descriptor-Einträge) |
|---|---|
| hoch | 129 |
| mittel | 86 |
| niedrig | 24 |
| Hypothese | **7** (von ursprünglich 121 offenen) |
