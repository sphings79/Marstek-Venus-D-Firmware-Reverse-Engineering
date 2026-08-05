# Marstek Venus D – Seriennummern-Aufbau

Analysiert anhand von Ghidra-Reverse-Engineering der Control-Firmware  
(`Control_149.2_VNSD-0_app_1492_0702_142136.bin`)

---

## Format

```
MVD 1 0 4 25 42 00123
│   │ │ │  │  │   └── Laufende Nummer im Batch (5 Stellen)
│   │ │ │  │  └────── Produktionswoche (2 Stellen, ISO-Woche)
│   │ │ │  └───────── Produktionsjahr, 2-stellig (z. B. 25 = 2025)
│   │ │ └──────────── Werk-/Linien-Code (1 Stelle)
│   │ └────────────── HW-Minor-Version (1 Stelle)
│   └────────────────  HW-Major-Version (1 Stelle)
└────────────────────  Modell-Prefix (3 Zeichen: Marstek Venus D)
```

**Gesamtlänge: 15 Zeichen**

---

## Beispiele

| Seriennummer      | HW-Rev | Werk | Jahr | KW | Lfd. Nr. |
|-------------------|--------|------|------|----|-----------|
| MVD1042500001   | 1.0    | 4    | 2025 | 42 | 00123     |
| MVD1042500002   | 1.0    | 4    | 2025 | 42 | 02345     |

Beide Geräte wurden in **KW 42 / 2025** (ca. 13.–19. Oktober 2025) produziert.  
Die laufenden Nummern `00123` und `02345` liegen **xxxx Einheiten** auseinander.

---

## Feldbeschreibung

### Positionen 1–3: Modell-Prefix `MVD`
Steht für **M**arstek **V**enus **D**. Identifiziert die Produktlinie.  
Die Firmware prüft intern via `OTA_Is_VNSD_Model()`, ob der im EEPROM hinterlegte Modell-String `"VNSD-0"` enthält — das ist ausschließlich ein OTA-Kompatibilitätscheck, keine SN-Validierung.

### Position 4: HW-Major-Version
Bisher nur `1` beobachtet.

### Position 5: HW-Minor-Version
Bisher nur `0` beobachtet → Hardware-Revision **1.0**.

### Position 6: Werk-/Linien-Code
Bisher nur `4` beobachtet. Vermutlich Produktionswerk oder Fertigungslinie.

### Positionen 7–8: Produktionsjahr
Zweistellig, ohne Jahrhundertangabe. `25` → **2025**.

### Positionen 9–10: Produktionswoche
ISO-Kalenderwoche. `42` → **KW 42**.

### Positionen 11–15: Laufende Nummer
Fünfstellige fortlaufende Nummer innerhalb des Batches (Werk + Jahr + Woche).

---

## SN in der Firmware

Die SN wird **nicht validiert** — sie wird aus dem EEPROM gelesen und unverändert verwendet:

- **Cloud-Telemetrie**: als `sn=` im Query-String, AES-128-ECB + Base64 verschlüsselt,  
  gesendet an `http://<server>.hamedata.com/prod/api/v1/setVenusDReporting`
- **MQTT**: im selben Telemetrie-Format `di=%s&sn=%s&...&hd=%s&...`
- **BLE-Gerätename**: Format `MST_VNSD_XXXX`, wobei die letzten 4 Ziffern der SN  
  eingesetzt werden (z. B. `MST_VNSD_1234` bzw. `MST_VNSD_3456`)

Das Feld `hd=` in der Telemetrie ist ein **separater Hardware-Descriptor** aus dem EEPROM  
und wird nicht aus der SN abgeleitet.

---

## Analysierte Firmware-Dateien

| Datei | Version | Typ | Größe |
|-------|---------|-----|-------|
| `Control_149.2_VNSD-0_app_1492_0702_142136.bin` | 149.2 | Control (Hauptprozessor) | 376 KB |
| `Control_147_202601281721320b2053125.bin` | 147 | Control | 492 KB |
| `Micro_VNS_116_vd_inv_app_0116_0702_ota_163439.bin` | 116 | Mikro/Inverter | 113 KB |
| `BMS_117.7_20251010135647565eb2036.bin` | 117.7 | BMS | 104 KB |

---

*Erstellt mit Ghidra-Analyse, Juli 2026*
