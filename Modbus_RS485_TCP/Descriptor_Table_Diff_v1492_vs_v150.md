# Descriptor-Tabelle: Diff v149.2 → v150 (Marstek Venus D, Control-FW)

Quellen:
- `VNSD-0_app_1492_0702_142136.bin` (v149.2) → `Descriptor_Table_Decoded_VNSD-0_app_1492.csv`
- `VNSD-0_app_0150_0805_115146.bin` (v150)  → `Descriptor_Table_Decoded_v150.csv`

Beide mit `marstek_descriptor_unpack.py` statisch aus dem LZ77-gepackten
`.data`-Image entpackt.

## Gesamtergebnis

| Kennzahl | v149.2 | v150 |
|---|---|---|
| Einträge | 246 | 246 |
| Registerbereich | 30000 – 38014 | 30000 – 38014 |
| Nur in dieser Version | – | – |
| Typ-Änderungen | \- | **0** |
| Scale-Änderungen | \- | **0** |
| elem_size-Änderungen | \- | **0** |
| count-Änderungen | \- | **0** |

**Die Modbus-Semantik ist zwischen v149.2 und v150 unverändert.** Kein Register
kam hinzu, keines fiel weg, kein Typ und keine Skala wurde geändert. Die einzige
Differenz sind verschobene SRAM-Quellzeiger — also reine Speicherlayout-Drift
durch neu eingefügte Variablen, keine Protokolländerung.

Konsequenz für `marstek_venus_modbus`: **keine versionsabhängige Fallunterscheidung
nötig.** Eine Registerdefinition deckt beide Firmware-Stände ab.

## Pointer-Verschiebungen nach Block

| Delta | Register | SRAM-Bereich | Interpretation |
|---|---|---|---|
| **+12** | 204 Register (30000–37024, ohne die unten genannten) | `0x20014EA0…0x20015236` | Vor dem Inverter-/BMS-Telemetrieblock wurden 12 Byte eingefügt. Der Telemetrie-Struct beginnt jetzt bei `0x20014EAC` statt `0x20014EA0`. |
| **+10** | 33000, 33002, 33004, 33006, 33008, 33010 | `0x20014D92…0x20014DA6` → `0x20014D9C…0x20014DB0` | Energiezähler-Block (u32, ÷10) um 10 Byte verschoben |
| **+16** | 30301, 30302, 30304, 30400 | `0x20018B4C`, `0x2001915D`, `0x2001893E`, `0x2001ADB5` | separate späte SRAM-Puffer, je +16 |
| **+4** | 31000 | `0x20014CDC` → `0x20014CE0` | device_name-Puffer |
| **±0** | 31 Register | `0x200000xx…0x200001xx`, `0x20001F4Cx` | unveränderte Kern-Globals |

## Wichtige Einzelbefunde

**Block 38000–38014 ist NICHT neu in v150.**
Alle 15 Einträge existieren in v149.2 bereits mit identischen Descriptoren —
gleiche Register, gleiche Typen, gleiche Skalen und **identische Quellzeiger**
(`0x20000168`–`0x20000184`, Delta ±0). Der Block gehört zu den unverschobenen
Kern-Globals. Dass er im Live-Scan nur Nullen liefert, ist also kein
Versionsthema, sondern heißt: die Quell-Variablen werden im getesteten
Betriebszustand schlicht nicht beschrieben.

**32101 (dc_current)** ist in beiden Versionen identisch definiert:
`i16`, Skalencode 3 (÷10), count 1.
Quelle: v149.2 `0x20014F84` → v150 `0x20014F90`.
Die Quelle ist bereits 16 Bit breit, es wird im Serializer nichts abgeschnitten.
Der Entladewert `0x9965` (als i16 = −26267, ÷10 = −2626,7) entsteht damit im
**Writer** des SRAM-Slots, nicht im Modbus-Pfad.

**Skalen-Inkonsistenzen (in beiden Versionen gleich, für die HA-Integration relevant):**
- 32104 (globaler SOC): Skalencode 3 → **die Firmware teilt selbst durch 10**
- 34002 (Pack-0-SOC): Skalencode 0 → **Rohwert in 0,1-%-Einheiten**, ×0,1 muss der Client anwenden
- 37005: gleiche Quelle wie 34002 (`0x20014FAC`/`0x20014FB8`), aber Skalencode 3 → liefert denselben Messwert bereits geteilt
- 32200/32204 (ac_voltage, ac_frequency): Skalencode 0 → Rohwert in 0,1 V bzw. 0,1 Hz, keine FW-Skalierung

**Doppelbelegungen (in beiden Versionen):**
- 32102 (`float32`) und 30001 (`i16`) zeigen auf dieselbe Adresse — eine der beiden Typangaben muss falsch interpretiert werden
- 32200/32201 sowie 32300/32301 teilen sich jeweils eine Quelle
- 35000/35001 sind Aliase von 30002/30003; 37013/37015 Aliase von 36100/36102
- 32202: `i16` mit `elem_size` 4 — inkonsistent, nachprüfen
