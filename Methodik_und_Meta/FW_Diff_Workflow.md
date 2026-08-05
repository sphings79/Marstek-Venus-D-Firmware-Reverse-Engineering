# Marstek Venus — Firmware-Diff-Workflow

Anleitung für Claude: Wie bei einer neuen Firmware-Version vorgegangen wird, um Änderungen zu identifizieren, Labels zu übertragen und die Dokumentation zu aktualisieren.

---

## Voraussetzungen

- Ghidra mit ReVa MCP ist verbunden
- Die alte FW-Version ist bereits in Ghidra analysiert und vollständig gelabelt
- Das neue FW-Binary liegt als Datei vor (vom User bereitgestellt oder per OTA-Download)

### Bekannte Ghidra-Projekte (Stand Juli 2026)

| FW | Ghidra-Pfad | Doku-Datei | Funktionen |
|---|---|---|---|
| BMS v117.7 | `/20251010135647565eb2036.bin` | `BMS_FW_Analyse_v117.7.md` | 540 (100% benannt) |
| Control v149.2 | *(Pfad in Ghidra prüfen)* | `Control_FW_Analyse_app_1492_0702_142136.md` | 1.623 (1.619 benannt, s. Control_FW_Function_Tracking_new.md) |
| Micro/Inverter v116 | *(Pfad in Ghidra prüfen)* | `Micro_Inverter_FW_Analyse_vd_inv_app_0116.md` | 452 |

---

## Schritt 1: Neues Binary importieren und analysieren

```
Tool: ghidra:import-file
  filePath: <lokaler Pfad zum neuen Binary>
  programName: <z.B. "BMS_v178" oder "Control_v150">

Tool: ghidra:analyze-program
  programPath: <Ghidra-Pfad des importierten Programms>
  forceFullAnalysis: true
  waitSeconds: 30
```

**Wichtig bei STM32-Binaries (BMS, Micro):**
- Flash-Basis auf `0x08000000` setzen (Memory Block umbenennen zu "flash", write=false)
- Compiler: RVDS/Keil ARM (Thumb-2, Little Endian)
- Nach Import: `analyze-program` mit `forceFullAnalysis: true`

**Bei Control FW:**
- Compiler: GCC (anders als BMS/Micro!)
- Gleiche Flash-Basis `0x08000000`

---

## Schritt 2: Diff-Session erstellen

```
Tool: ghidra:diff-create-session
  sourceProgramPath: <Pfad der ALTEN, vollständig gelabelten FW>
  destinationProgramPath: <Pfad der NEUEN FW>
  waitSeconds: 60
```

Die Source ist immer die alte, bekannte Version — Labels/Markup fließen VON source NACH destination.

Standard-Correlators (werden automatisch ausgeführt):
1. `symbol-name` — Matcht Funktionen mit gleichem Namen
2. `exact-bytes` — Identische Byte-Sequenzen
3. `exact-instructions` — Identische Instruktionen
4. `exact-mnemonics` — Identische Mnemonics
5. `duplicate-instructions` — Duplizierte Instruktionen
6. `function-reference` — Referenz-basiertes Matching

Falls viele Funktionen unmatched bleiben, zusätzlich:
```
Tool: ghidra:diff-add-correlator
  correlator: "combined-reference"
```

---

## Schritt 3: Diff-Summary abrufen

```
Tool: ghidra:diff-summary
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
  topN: 20
  includeBodyByteChanges: true
```

Das liefert:
- Anzahl gematchter/ungematchter Funktionen
- Top-N der am stärksten geänderten Funktionen
- Neue und entfernte Funktionen

---

## Schritt 4: Labels und Markup übertragen

### Automatisch (hohe Konfidenz)

```
Tool: ghidra:diff-transfer-markup
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
  confidence: 0.95
  waitSeconds: 30
```

Überträgt automatisch: Funktionsnamen, Prototypen, Datentypen, Kommentare — für alle Matches mit Similarity >= 95%.

### Manuell (niedrige Konfidenz)

Für Matches unter dem Confidence-Schwellwert einzeln prüfen:

```
Tool: ghidra:diff-function
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
  function: <Funktionsname oder Adresse>
```

Dann bei positivem Match einzeln anwenden:

```
Tool: ghidra:diff-apply-match
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
  sourceAddress: <Adresse in alter FW>
  destinationAddress: <Adresse in neuer FW>
```

---

## Schritt 5: Änderungen im Detail analysieren

### Geänderte Funktionen auflisten

```
Tool: ghidra:diff-list-functions
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
  category: "changed"
  sortBy: "similarity"
  includeBodyByteChanges: true
```

### Neue Funktionen (nur in neuer FW)

```
Tool: ghidra:diff-list-functions
  category: "added"
```

### Entfernte Funktionen (nur in alter FW)

```
Tool: ghidra:diff-list-functions
  category: "removed"
```

### String-Änderungen

```
Tool: ghidra:diff-strings
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
```

Neue Strings deuten oft auf neue Features, Register oder Protokolländerungen hin.

### Daten-Änderungen

```
Tool: ghidra:diff-data
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
```

---

## Schritt 6: Neue Funktionen analysieren und labeln

Für jede neue (ungematchte) Funktion in der neuen FW:

1. Dekompilieren: `ghidra:get-decompilation`
2. Cross-References prüfen: `ghidra:find-cross-references`
3. Caller-Kontext: `ghidra:get-callers-decompiled`
4. Label vergeben nach Naming-Convention (siehe unten)

---

## Schritt 7: Dokumentation aktualisieren

### Doku-Datei bestimmen

Jede Firmware hat ihre eigene Markdown-Datei — Erkenntnisse gehören immer in die passende FW-Datei:

| FW-Typ | Datei |
|---|---|
| BMS | `BMS_FW_Analyse_v<VERSION>.md` |
| Control | `Control_FW_Analyse_app_<VERSION>.md` |
| Micro/Inverter | `Micro_Inverter_FW_Analyse_vd_inv_app_<VERSION>.md` |

### Was aktualisiert werden muss

1. **Binary-Fingerprint (§1):** Neue Version, Größe, Funktionsanzahl
2. **Versionshistorie:** Neuen Changelog-Eintrag hinzufügen (siehe Format unten)
3. **Betroffene Sektionen:** Wenn sich z.B. der SOC-Algorithmus geändert hat → §3/4 aktualisieren
4. **Funktionsliste (§12 bei BMS):** Neue/geänderte/entfernte Funktionen einpflegen

### Changelog-Format

```markdown
### vALT → vNEU (Datum)

**Summary:** Kurzbeschreibung der Hauptänderungen

**Geänderte Funktionen (X):**
- `Funktionsname` (Similarity X%) — Was hat sich geändert
- ...

**Neue Funktionen (X):**
- `Neuer_Name` @ `0xADRESSE` (XB) — Beschreibung

**Entfernte Funktionen (X):**
- `Alter_Name` — Nicht mehr vorhanden

**String-Änderungen:**
- Neu: "neuer string" — Bedeutung
- Entfernt: "alter string"
```

---

## Naming-Conventions

Funktionsnamen folgen dem Schema `PREFIX_Beschreibung`:

| Prefix | Bedeutung | Beispiel |
|---|---|---|
| `APP_` | BMS Applikationslogik | `APP_Get_Protection_Status_Byte` |
| `HAL_` | Hardware Abstraction | `HAL_GPIO_Write_Pin` |
| `LIB_` | Bibliothek/Utility | `LIB_CRC16_Modbus_Calc` |
| `INIT_` | Initialisierung | `INIT_All_Peripherals` |
| `CLI_` | Letter-Shell Debug | `CLI_Parse_Arguments` |
| `KA495XX_` | BMIC SPI-Treiber | `KA495XX_Read_CellVoltages_And_Temps` |
| `SOC_` | State of Charge | `SOC_Algorithm_Orchestrator` |
| `CAN_` | CAN-Bus Protokoll | `CAN_TX_BMS_Status_Reporter` |
| `RS485_` | RS485 Kommunikation | `RS485_Register_Read_Handler` |
| `I2C_EEPROM_` | EEPROM Zugriff | `I2C_EEPROM_Read_WithMutex` |
| `Protect_` | Batterieschutz | `Protect_Update_NTC_MinMax` |
| `NTC_` | Temperatursensoren | `NTC_Calculate_Temperature` |
| `OTA_` | Firmware Update | `BMS_OTA_Upgrade_StateMachine` |
| `RTOS_` | FreeRTOS Kernel | `RTOS_vPortExitCritical` |
| `SoftFloat_` | Software Float | `SoftFloat_Double_To_Int_Low` |
| `FATFS_` | Dateisystem | `FATFS_Find_Dir_Entry` |
| `BMS_` | BMS-spezifische Logik | `BMS_Config_Params_Load_Or_Default` |

Für Control FW zusätzlich:

| Prefix | Bedeutung |
|---|---|
| `WiFi_` | WiFi/WLAN |
| `ETH_` | Ethernet |
| `Modbus_` | Modbus TCP |
| `Cloud_` | Cloud-Telemetrie |
| `BLE_` | Bluetooth LE |
| `SMR_` | Energy Management |
| `MPPT_` | PV-Tracker |

**Regeln:**
- CamelCase nach Prefix: `SOC_Calc_Percentage_From_Range`
- Keine generischen Namen wie `FUN_xxxxxxxx` stehen lassen
- Bei Library-Funktionen (FreeRTOS, printf etc.) den Originalnamen verwenden
- Compiler-Intrinsics behalten: `__adddf3`, `__muldf3`, `__aeabi_*`

---

## Aufräumen nach dem Diff

```
Tool: ghidra:diff-delete-session
  sourceProgramPath: <alte FW>
  destinationProgramPath: <neue FW>
```

Diff-Sessions werden nicht automatisch gelöscht — nach Abschluss der Analyse manuell aufräumen.

---

## Checkliste

- [ ] Neues Binary importiert und analysiert
- [ ] Diff-Session erstellt, Summary geprüft
- [ ] Labels/Markup automatisch übertragen (confidence >= 0.95)
- [ ] Restliche Matches manuell geprüft und übertragen
- [ ] Neue Funktionen analysiert und gelabelt
- [ ] String- und Daten-Änderungen geprüft
- [ ] Changelog in Doku-Datei eingetragen
- [ ] Betroffene Doku-Sektionen aktualisiert
- [ ] Funktionsliste aktualisiert
- [ ] Diff-Session gelöscht
- [ ] Ghidra-Projekt gespeichert (`ghidra:checkin-program`)
