# Marstek Venus D — BMS Firmware Analyse v118
## `20260119100535e43806957.bin`

**Firmware:** BMS v118 (Ghidra-Import 2026-07-14)
**Analysedatum:** 14.07.2026
**Methode:** Statische Analyse (Ghidra + ReVa MCP), Version-Tracking-Diff gegen v117.7
**Basis-Dokument:** `BMS_FW_Analyse_v117.7.md` (Register-/Struct-Layout dort weiterhin gültig, sofern hier nicht abweichend beschrieben)
**Status:** Memory-Map korrigiert, Vollanalyse durchgeführt, Diff zu 117.7 ausgewertet, alle 24 neuen Funktionen manuell dekompiliert, alle 550 Funktionen in Ghidra benannt (2026-07-15)

---

## Binary-Fingerprint

Live aus Ghidra verifiziert (Stand 2026-07-15). Ein Vergleich mit den anderen fünf analysierten
Firmware-Images (Control 149.2/147, VNS 116/115, BMS 117.7) steht in der Projekt-`README.md`.

| Eigenschaft | Wert |
|---|---|
| Datei | `20260119100535e43806957.bin` |
| Version | 118 (aktuell) |
| Größe | 106.496 B (0x1A000, 104 KB) |
| Architektur | ARM Cortex-M4F, Thumb-2, Little-Endian |
| Flash-Bereich | `0x08000000–0x08019FFF` |
| Initial SP | `0x2000CBA0` (~52 KB SRAM) |
| Reset Handler | `0x08002A6D` |
| Funktionen | 550 / 550 benannt (100 % — 526 per Ghidra-Diff-Markup-Transfer von 117.7 übernommen, 24 neue einzeln benannt, s. Abschnitt 9) |
| Strings | 256 |
| Compiler | RVDS/Keil ARM |
| RTOS | FreeRTOS (`heap_4`, `ARM_CM4F`-Port) |
| Crypto | — (keine) |
| Zellmonitoring | KA495XX (BMIC) |
| Kommunikation | CAN + RS485 |

---

## 1. Memory-Map-Korrektur

Der Ghidra-Import hatte einen falschen Default-Speicherblock angelegt:

| | Vorher (Import) | Nachher (korrigiert) |
|---|---|---|
| Name | `ram` | `flash` |
| Bereich | `0x00000000–0x00019FFF` | `0x08000000–0x08019FFF` |
| Rechte | R/W/X | R/X (nicht beschreibbar) |

Durch die falsche Basisadresse (0x0 statt 0x08000000, wie bei 117.7) war die Voranalyse unvollständig: nur 262 von tatsächlich 550 Funktionen und 497 von 1123 Symbolen wurden erkannt (Vektortabelle zeigte auf nicht existente Adressen). Nach Verschieben des Blocks auf die korrekte Flash-Basis und einer erzwungenen Vollanalyse:

- **550 Funktionen / 1123 Symbole** (117.7 zum Vergleich: 551 Funktionen / 1128 Symbole)
- Größe unverändert: 106.496 B (0x1A000), identisch zu 117.7
- Flash-Basis `0x08000000`, Architektur ARM Cortex-M4F Thumb-2 LE — beides identisch zu 117.7

---

## 2. Versions-Fingerprint

Bestätigt über die Per-Pack-Struct-Builder-Funktion (SRAM `0x2000420A`, Per-Pack-Struct-Offset 0x54, `Nachfolger von PerPack_Struct_Builder` → `FUN_08009fdc`):

| Version | Hardcoded Wert | Encoding |
|---|---|---|
| 117.7 | `0x499` = 1177 | Ziffern der Version ohne Punkt (117.7 → "1177") |
| **118** | `0x76` = **118** | Direkter Integer-Wert (kein ×10/Dezimalstellen-Schema) |

Das Encoding-Schema hat sich geändert — 117.7 folgte offenbar "Ziffern ohne Punkt" (117.7 → 1177), v118 kodiert die Versionsnummer dagegen direkt als Ganzzahl. Für die HA-Integration relevant, falls Register 34010 (Pack-FW-Version) zur Anzeige/Auswertung genutzt wird: der rohe Wert für v118 ist **118**, nicht 1180.

---

## 3. Diff-Ergebnis (Ghidra Version Tracking)

Korrelatoren: Symbol-Name, Exact Bytes, Exact Instructions, Exact Mnemonics, Duplicate Instructions, Function Reference.

| | 117.7 | 118 |
|---|---|---|
| Funktionen gesamt | 551 | 550 |
| Identisch (Bytes) | 218 | 218 |
| Gematcht, aber "changed" | 308 | 308 |
| Ohne Gegenstück | 25 | 24 |

Die 308 "changed"-Treffer sind größtenteils **Korrelations-Rauschen**: gleiche Funktion, identische Bytes (similarity 1.0), aber als "geändert" markiert, weil eine oder mehrere ihrer aufgerufenen Callee-Funktionen zur nicht zugeordneten Gruppe (die 24/25 unten) gehören. Echte Logikänderungen bei ansonsten identischen Funktionen wurden keine gefunden — alle inhaltlichen Änderungen stecken in den 24 neuen + 25 entfernten Funktionen.

### 3.1 Entfernte Funktionen (25, nur in 117.7 vorhanden)

| Funktion (117.7) | Adresse | Vermutete Ablösung in v118 |
|---|---|---|
| `System_Reset_And_Halt` | 0x08002198 | `FUN_08002198` (gleiche Adresse, erweitert — s. 4.2) |
| `INIT_RS485_UART_Structs` | 0x0800298c | `FUN_080029c8` (DMA-Ringpuffer-Init, s. 4.4) |
| `USART2_UART4_Init` | 0x08002a24 | `FUN_08002a60` (s. 4.4) |
| `Pack_MasterSelect_Monitor` | 0x08004c6c | Neues Subsystem `FUN_08006fe4` + Helfer (s. 4.1) |
| `INIT_RTC_And_DateTime` | 0x08004fc4 | nicht eindeutig zuordenbar |
| `CAN_RX_Handler` | 0x080059dc | `FUN_08005a40` (bestätigt, s. 4.8 — identische Magic-ID-Tabelle, 1 neue Zeile) |
| `APP_Calc_Pack_SOC_From_Voltage` | 0x08006b54 | vermutlich in `FUN_0800a584`-Umfeld aufgegangen |
| `bms_data_printf` | 0x0800702c | entfernt (Debug-Funktion, s. 3.2) |
| `RS485_Register_Write_Handler` | 0x08007d24 | `FUN_08007d90` (deutlich erweitert, s. 4.5) |
| `voltage_protection_check` | 0x08009548 | vermutlich Kern in `FUN_0800a584` aufgegangen (s. 4.6) |
| `PerPack_Struct_Builder` | 0x08009f70 | `FUN_08009fdc` (s. 2) |
| `Precharge_StateMachine` | 0x0800cb24 | `FUN_0800cb90` (Teil des neuen Pack-Mode-Subsystems, s. 4.1) |
| `CAN_Send_Frame_Log` | 0x08012984 | entfernt (Debug, s. 3.2) |
| `Debug_Print_Battery_Status` | 0x08012c50 | entfernt (Debug) |
| `CAN_RX_State_Flag_Set` | 0x08012d8c | entfernt (Debug) |
| `Nop_Return_Stub` | 0x08012d90 | entfernt (Debug) |
| `Clear_Debug_Print_Flag` | 0x08012d94 | entfernt (Debug) |
| `Debug_Print_MOS_Command_Status` | 0x08012dbc | entfernt (Debug) |
| `Debug_Print_Discharge_MOS_Cmd` | 0x08012dec | entfernt (Debug) |
| `Debug_Print_Nop_Stub` | 0x08012e04 | entfernt (Debug) |
| `Debug_TaskStack_Fragment` | 0x08012ff4 | entfernt (Debug) |
| `Debug_Print_Device_UIDs` | 0x080130f4 | entfernt (Debug) |
| `Debug_Print_EMS_ChgDsg_Flag` | 0x080131b0 | entfernt (Debug) |
| `SOC_Algorithm_Orchestrator` | 0x08013520 | `FUN_08013590` (erweitert, s. 4.7) |
| `soc_algorithm_dump` | 0x08013844 | entfernt (Debug-Dump) |

### 3.2 Debug-Code-Bereinigung

11 der 25 entfernten Funktionen (Adressbereich `0x08012984–0x080131B0`) sind ein zusammenhängender Cluster von CLI-Debug-Print-Helfern (`Debug_Print_*`, `CAN_Send_Frame_Log`, `CAN_RX_State_Flag_Set`, `Nop_Return_Stub`, `Clear_Debug_Print_Flag`). Zusammen mit `bms_data_printf` und `soc_algorithm_dump` sind das **13 reine Debug-/Logging-Funktionen**, die in v118 komplett entfernt wurden — v118 wirkt an dieser Stelle wie ein bereinigter Release-Build. Der freigewordene Flash-Platz erklärt einen Teil des Adress-Shifts, der die 24 neuen Funktionen weiter vorne im Image ermöglicht.

---

## 4. Neue Funktionen (24) — Analyse

Alle 24 in v118 neu hinzugekommenen Funktionen wurden manuell dekompiliert. Sie gruppieren sich in sieben Subsysteme:

### 4.1 Neues Pack-Mode-/Master-Election-Subsystem (11 Funktionen)

**Ersetzt:** `Pack_MasterSelect_Monitor` (117.7). In 117.7 war das Pack-Modus-Register (`DAT_200028CA`, Werte 0=Idle/1=Transitional/2=Active/3=Shutdown/4=Error, s. 117.7-Doku Abschnitt 4.9) ein einfacher CAN-Kommando-getriebener Zustand. In v118 ist daraus eine mehrstufige State-Machine-Kaskade geworden, die bei den Modus-Übergängen zusätzlich aktiv das **Precharge-Relais** steuert:

| Funktion | Rolle |
|---|---|
| `FUN_08006fe4` | Top-Level-Dispatcher: `switch(DAT_200028CA)` — ruft je nach Pack-Modus die passende Sub-State-Machine |
| `FUN_080095e4` | Sub-State-Machine für Modus **1 (Transitional)**: übernimmt neue Pack-Adresse (`DAT_200028DA`), schaltet das Precharge-Relais (3-Phasen-Toggle, s. u.), sendet CAN-Handoff-Meldungen |
| `FUN_08008d28` | Sub-State-Machine für Modus **2 (Active)**: setzt **eigene Pack-Adresse testweise auf 1** (`DAT_200041B6 = 1`), schaltet ebenfalls das Precharge-Relais — sieht aus wie eine Adress-Selbstübernahme/Master-Claim-Prozedur beim Aktivwerden |
| `FUN_0800cb90` | Sub-State-Machine für Modus **3 (Shutdown)**, Nachfolger von `Precharge_StateMachine`: GPIO-Moduswechsel auf GPIOB (s. u.), periodische CAN-Broadcasts, endet mit vollständigem erzwungenem Reset über `FUN_08002198` (s. 4.2) |
| `FUN_0800a9f4` | Läuft im Idle-Zustand (Modus 0): periodisches Relais-Toggle (alle ~2000 Ticks, 20× toggeln) |
| `FUN_08006bbc` | Clamp-/Auswahl-Helfer basierend auf Pack-SOC (`Per-Pack-Struct-Offset 0x0E`) und einem konfigurierbaren Parameter `DAT_200028E0` (per CAN **und** RS485 setzbar, s. 4.8) — SOC-Balance-Kriterium für Pack-Auswahl |
| `FUN_08006c04` | Ermittelt die **minimale Zellspannung über alle aktiven Packs** (`Per-Pack-Struct-Offset 0x48 "Min Cell"`, Aktiv-Bitmaske `DAT_200028DC`) |
| `FUN_08000e20` / `FUN_08000ea8` / `FUN_08000ef0` / `FUN_08000f20` / `FUN_08000f58` | CAN-Kommando-Builder+Sender-Familie (Typen 2/3/6/7 über gemeinsamen Frame-Builder `FUN_08000d70` + Sende-Funktion `FUN_080172d4`), von den State-Machines oben für Handoff-/Broadcast-Nachrichten genutzt |

**Trigger-Kette verifiziert (Cross-Referenz-Check auf `DAT_200028CA`/`DAT_200028DA`):** Der **externe Auslöser bleibt unverändert** — `FUN_0800b770` (Nachfolger von `CAN_CMD_Pack_Activation`, weiterhin über normale VT-Korrelation als "changed" erkannt, nicht Teil der 24 neuen Funktionen) sowie der `0x100101AA`-Zweig im neuen `CAN_RX_Handler`-Nachfolger (`FUN_08005840`, s. 4.8) setzen weiterhin von außen (Micro/Inverter-MCU) Pack-Modus und Ziel-Pack-Adresse. Neu ist ausschließlich die **interne Abarbeitung** dieser Zustände (Relais-Kopplung, Adress-Selbstübernahme) — das Round-Robin-Protokoll zur Micro-MCU selbst (CAN CMD 3/6 aus 117.7-Doku Abschnitt 4.9) hat sich nicht geändert.

**Korrektur ggü. Erstanalyse — kein GPIO-Daisy-Chain, sondern Precharge-Relais:** `0x40010C00` ist **GPIOB** (bestätigt über die Clock-Enable-Tabelle in `FUN_0800167c`: 0x40010800=GPIOA…0x40011400=GPIOD, aufsteigend in 0x400-Schritten, klassisches STM32F1-Layout). Bit `0x1000` (Bit 12) auf GPIOB ist **derselbe Pin, den auch `FUN_0800aedc` (Nachfolger von `OTA_PreCharge_Relay_Sequence`) schaltet** — die "GPIO-Handshakes" in den neuen Pack-Mode-State-Machines sind also **Precharge-Relais-Ansteuerung**, keine Hardware-Adressketten-Signalisierung. v118 verlagert die Relais-Steuerung offenbar direkt in die Pack-Mode-Übergänge (Transitional/Active/Idle), statt sie nur in der separaten Precharge-Sequenz zu behandeln. Der `FUN_0800167c`-Aufruf mit Wert `0x20` in `FUN_0800cb90` (Shutdown-Start) ist keine Pin-Ansteuerung, sondern eine **GPIO-Modus-Rekonfiguration** (Aufruf-Musters identisch zu Pin-Config-Code in `FUN_08002a60`/`FUN_08005028`) — welcher genaue Pin/Modus das ist, bleibt offen (s. Abschnitt 7).

### 4.2 Erweiterter Forced-Reset mit Sicherheitscheck (1 Funktion)

`FUN_08002198` (identische Adresse wie `System_Reset_And_Halt` in 117.7, aber 188 statt 136 Bytes) prüft vor dem Watchdog-Reset erstmals, ob noch nennenswerter Packstrom fließt (SRAM `0x2000406C`). Falls ja: Event mit RTC-Zeitstempel wird geloggt (Code **`0xfc02`**, Helfer `FUN_08004f32`/`FUN_08006480`) bevor der Reset ausgeführt wird. Aufrufer: `RS485_Dispatcher` (Reset-Kommando 0x2A) und `FUN_0800cb90` (Shutdown-State-Machine, s. 4.1).

### 4.3 Neuer Event-Code `0xfc02`

Derselbe Logging-Helfer (`FUN_08004f32` = RTC-Zeitstempel-Encoder, `FUN_08006480` = Event-Log-Schreiber) mit Code `0xfc02` wird an drei Stellen aufgerufen:
- `FUN_08002198` (Forced Reset bei noch fließendem Strom, s. 4.2)
- `FUN_08013590` (SOC-Algorithmus-Nachfolger, 2×, s. 4.7)
- `FUN_08013e34` (OCV-Grenzwert-Check, s. 4.7)

Alle drei Stellen betreffen "unerwarteter/kritischer Zustand" — `0xfc02` ist vermutlich ein neuer generischer Fault-Event-Code für sicherheitsrelevante Ereignisse, der in 117.7 noch nicht existierte.

### 4.4 RS485/UART-Init auf DMA-Ringpuffer umgestellt (4 Funktionen)

**Ersetzt:** `INIT_RS485_UART_Structs` + `USART2_UART4_Init`.

- `FUN_080029c8` / `FUN_08002a60` — initialisieren zwei UART-Kanäle (Register-Basen `0x40004400`, `0x40004c00`) jeweils mit **1024-Byte-Ringpuffer-Deskriptoren** (Puffer-Pointer, Größe `0x400`, Callback-Adressen) statt der bisherigen einfacheren Struktur — Hinweis auf Umstellung von interrupt-basiertem auf DMA-gepuffertes UART-Handling.
- `FUN_08002938` / `FUN_0800d7b0` — neue blockierende Byte-für-Byte-UART-Sende-Routine mit Timeout-Polling (TXE-Flag, 5000 Zyklen) plus Wrapper.

### 4.5 Erweiterter RS485-Register-Write-Handler (1 Funktion, groß)

`FUN_08007d90` (1010 Bytes) ersetzt `RS485_Register_Write_Handler` (0x08007d24). Deutlich mehr Parameter-Block-IDs als in 117.7 werden bedient (`switch` über Block-ID mit vielen `case`-Zweigen, u. a. Block `0x10` → bekannte Strom-Schwellwert-Register `0x200049A6+`, Block `1` → Max/Min-Zell-NTC-Schwellwert-Block `0x20004960–0x20004976` — **dieser Block existierte bereits in 117.7**, s. Korrektur in 4.6). v118 macht damit **mehr Konfigurationsparameter per RS485 beschreibbar** als 117.7.

### 4.6 Neuer Zellspannungs-Über-/Unterspannungsschutz mit Temperaturkompensation (1 Funktion, groß)

**Korrektur ggü. Erstanalyse** (durch Cross-Check mit 117.7 per Subagent verifiziert): `FUN_0800a584` (1048 Bytes) ist **keine Temperaturschutz-, sondern eine Zellspannungs-Schutzfunktion** — Cell-Overvoltage/Undervoltage-Protection (Cell OVP/UVP). Sie vergleicht `_DAT_200041FC`/`_DAT_200041FE` (dokumentierte "Max Cell"/"Min Cell"-Spannung in mV) gegen Schwellwerte im RS485-Konfigblock `0x20004996–0x200049B4` (117.7-Doku Abschnitt 11a, Gruppen `0x40`/`0x10` — dort mit "kein Konsument gefunden" markiert). Die Schwellwerte selbst sind **temperaturkompensiert**: abhängig vom Vorzeichen von `_DAT_20004204` ("Ave NTC", Durchschnittstemperatur) wählt die Funktion andere OV-Grenzwerte (z. B. 3700mV bei warmem, 3800/3850/3900mV bei kaltem Pack) und aktualisiert darüber die Warning-/Protect-Bitmasken (`DAT_200028C1`, `DAT_200028C5`) über Debounce-Zähler.

**Verifiziert per Subagent (Cross-Check gegen 117.7):** Diese Funktion ist in 117.7 **nachweislich nicht vorhanden** — die Schwellwert-Konstante 3800mV (`0xed8`) kommt in der gesamten 117.7-Firmware nicht vor, und die Gruppen `0x40`/`0x10` hatten dort tatsächlich keinen Checker. **Löst damit eine seit der 117.7-Analyse offene Frage** (117.7-Doku Abschnitt 11a: "kein direkter Checker-Konsument gefunden" für diese Gruppen): v118 fügt die fehlende Zellspannungs-Schutzlogik für diese beiden Gruppen komplett neu hinzu.

**Richtigstellung zum Max/Min-Zell-NTC-Block (`0x20004960–0x20004976`):** Dieser Block ist entgegen der ursprünglichen Annahme in dieser Doku **nicht neu** — `Voltage_Temp_Protection_Checker` liest ihn bereits identisch in 117.7 (per Subagent verifiziert, Zeile für Zeile dieselben Vergleiche wie im v118-Nachfolger `FUN_08009924`). Es handelt sich um eine vorbestehende, bereits in 117.7 aktive Schutzfunktion, keine v118-Neuerung.

**Nebenbefund beim Cross-Check:** Die RS485-Gruppen `0x100`/`0x200` (117.7-Doku: "vermutlich Balance-Schwellwerte oder SOC%", niedrige Konfidenz) sind in Wirklichkeit **Lade-/Entlade-Überstromstufen**, konsumiert vom bereits benannten `Current_Protection_Checker` — in beiden Versionen unverändert vorhanden. Gruppe `0x400` bleibt in beiden Versionen ohne identifizierbaren Konsumenten.

### 4.7 SOC-Algorithmus-Erweiterungen (2 Funktionen)

`FUN_08013590` (Nachfolger von `SOC_Algorithm_Orchestrator`, 388 statt 346 Bytes) ruft dieselben SOC-Helfer wie 117.7 auf, zusätzlich aber zwei neue Event-Logging-Aufrufe (Code `0xfc02`, s. 4.3) sowie eine neue Funktion `FUN_08013e34`: Diese prüft, ob die zuletzt gemessenen Zellspannungs-Grenzwerte außerhalb der bekannten OCV-Kalibriertabelle liegen (`_DAT_0801B8D8`/`_DAT_0801B96E`, im dokumentierten Kalibrier-Flash-Bereich `0x0801B73C+`), löst bei Überschreitung eine Rekalibrierung aus (`FUN_08016e24(..,2)`) und schreibt das Ereignis in ein **neues SOC-Event-Log** bei SRAM `0x20004A90` (direkt anschließend an die dokumentierte SOC-SRAM-Map `0x20004A38–0x20004A78`).

`FUN_08009fdc` (Nachfolger von `PerPack_Struct_Builder`) ist inhaltlich identisch bis auf die geänderte Versions-Konstante (s. 2).

### 4.8 CAN_RX_Handler-Nachfolger + sonstige neue Funktionen (3 Funktionen)

- **`FUN_08005a40` = bestätigter Nachfolger von `CAN_RX_Handler`** (117.7, 0x080059dc). Über `diff-function` war kein Match zu finden (VT-Korrelator ist bei dieser Funktion gescheitert, vermutlich weil zu viele ihrer Callees selbst unbenannt/verschoben sind), aber die Magic-ID-Dispatch-Tabelle ist **identisch** zu 117.7 (`0x100101AA…0x100501AA`, `0x180101AA/0x180102AA`, Aufrufer `FUN_08000cd4` = `APP_CAN_RX_Task_Process`, unverändert an gleicher Adresse). Genau **eine Zeile ist neu**: im bisherigen `0xfd00`-Zweig (Pack-Aktivierungs-Konfigurationsnachricht, nur wenn Pack im Idle-Modus) wird zusätzlich ein Byte aus dem CAN-Frame (Offset 0xD) nach `DAT_200028E0` übernommen — **derselbe SOC-Balance-Parameter, den `FUN_08006bbc` in 4.1 für die Pack-Auswahl nutzt.** Auch der `0x100201AA`-Zweig (vorher `CAN_CMD_02_Handler`) schreibt jetzt direkt `DAT_200028E0` und ruft `FUN_0800875e` (loggt den neuen Wert als Event `0x1FE`, falls < 91). **Damit ist `DAT_200028E0` in v118 sowohl per CAN (von der Micro/Inverter-MCU im Rahmen der Pack-Aktivierung) als auch per RS485 setzbar** — ein neuer Konfigurationskanal für das SOC-Balance-Kriterium der Pack-Auswahl.
- `FUN_08005028` — Peripherie-Init/Selbsttest (Register `0x40011400`) mit Fehlercode-Logging: bei fehlgeschlagenem Statusregister-Check (Bit `0x80`) wird ein Fehlerdatensatz mit Code `0x7E7` und mehreren Subwerten (`0xE/0xB/0x17/0x1D`) geschrieben statt eines normalen Event-Log-Eintrags.
- `FUN_08003334` — tickgetriebene periodische Alarm-Broadcast-Funktion: sendet nach ~5s (499 Ticks) bis zu 10× eine CAN-Alarmmeldung (`FUN_08000ef0`, Typ 6), gesteuert u. a. über Protect-Byte `DAT_200028C1`.

---

## 5. Nachkontrolle "changed"-Bucket (308 Funktionen)

Stichprobe über den gesamten Similarity-Bereich (Kopf + Ende der nach Similarity sortierten Liste, 110 von 308 Funktionen, inkl. `includeBodyByteChanges`): **alle** geprüften Einträge haben `similarity 1.0`. Wo `bodyBytesChanged=true` auftritt, ist die Ursache ausschließlich, dass Aufruf-/Literal-Adressen auf verschobene Callees zeigen (Korrelatoren "Exact/Duplicate Instructions Match") — keine echte Logikänderung. Ergebnis: **keine verborgenen Logikänderungen** in den 308 gematchten "changed"-Funktionen; alle inhaltlichen Unterschiede stecken vollständig in den bereits analysierten 24 neuen + 25 entfernten Funktionen.

## 6. Alle drei offenen Punkte aus der Erstanalyse geklärt

- **GPIO `0x40010C00`:** ist **GPIOB** (bestätigt über die Clock-Enable-Zuordnung in `FUN_0800167c`). Bit `0x1000` = **Precharge-Relais** (identischer Pin wie in `FUN_0800aedc`/`OTA_PreCharge_Relay_Sequence`) — keine Adresskette, sondern Relais-Steuerung, jetzt direkt in die Pack-Mode-Übergänge verlagert (s. 4.1, korrigiert). Bit `0x20`-Aufruf in `FUN_0800cb90` (Shutdown-Eintritt) konfiguriert GPIOB Pin 5 auf **Analog-Input** um (vollständig hergeleitet, kein Live-Test nötig, s. Abschnitt 7).
- **Schwellwert-Block `0x20004960–0x20004976`:** vollständig feldweise zugeordnet (Max-/Min-Zell-NTC-Schutzstufen, Warning- + Protect-Bit, je SET+CLEAR+Debounce) — **Korrektur nach Cross-Check mit 117.7 (s. 4.6): dieser Block ist nicht neu**, er wurde schon in 117.7 identisch konsumiert. Tatsächlich neu in v118 ist stattdessen `FUN_0800a584` (Cell-OVP/UVP, s. 4.6) — das war eine Verwechslung in der Erstanalyse.
- **`CAN_RX_Handler`:** Nachfolger identifiziert = `FUN_08005a40` (identische Magic-ID-Tabelle), mit genau einer inhaltlichen Ergänzung: neuer CAN-Konfigurationskanal für den SOC-Balance-Parameter `DAT_200028E0`, s. 4.8.
- `FUN_08000f58` zusätzlich dekompiliert: 5. Mitglied der CAN-Builder-Familie aus 4.1, keine neue Erkenntnis.

## 7. Nachtrag: GPIO-Mechanismus + Trigger-Kette

- **`FUN_08006918`** dekompiliert: generischer STM32-GPIO-Helfer, der CRL/CRH-Modusbits (4-Bit CNF+MODE pro Pin) und optional den Initialzustand über BSRR/BRR schreibt — im ganzen Firmware-Image für praktisch jede Pin-Konfiguration genutzt (UART, SPI, Relais, …), nichts BMS-118-Spezifisches.
- `FUN_0800167c(GPIOB, 0x20)` in `FUN_0800cb90` (Shutdown-Eintritt) ruft darüber **Pin 5 von GPIOB** (Bitmaske `0x20`) mit einer neuen Modus-Konfiguration auf — **jetzt exakt bestimmt, keine Registerspur nötig:** `FUN_0800167c` baut das an `FUN_08006918` übergebene Konfigurationswort aus `CONCAT22(<oberes Halbwort von param_4>, param_2)` und maskiert das Ergebnis anschließend zwingend mit `& 0xFFFFFF`. Dadurch ist **Byte 3 des Konfigurationsworts immer 0**, unabhängig davon, was in den nicht explizit übergebenen Parametern `param_3`/`param_4` steht — und genau dieses Byte 3 ist es, aus dem `FUN_08006918` den 4-Bit-CNF+MODE-Wert für den Pin ableitet. CNF+MODE = `0000` entspricht im STM32-CRL/CRH-Schema **Analog-Input** (kein Push-Pull/Open-Drain-Ausgang, kein BSRR/BRR-Schreibzugriff, da auch dafür Byte 3 herangezogen wird). **Ergebnis: GPIOB Pin 5 wird beim Shutdown-Eintritt in den hochohmigen Analog-Input-Zustand versetzt** — die Relais-/Treiberperipherie an diesem Pin wird damit aktiv deaktiviert/freigegeben, statt nur den Pegel zu wechseln.
- **Trigger-Kette bestätigt:** externe Auslöser für Pack-Modus-Wechsel bleiben `CAN_CMD_Pack_Activation`-Nachfolger `FUN_0800b770` und der `0x100101AA`-CAN-Befehl (`FUN_08005840`) — beide unverändert gegenüber 117.7 (s. 4.1). Die neuen 24 Funktionen sind ausschließlich interne Ausführung, keine Protokolländerung nach außen.

## 8. Verbleibende offene Punkte

- Nur noch Live-Test-Empfehlung: Adress-Selbstübernahme in `FUN_08008d28` (`DAT_200041B6 = 1`) und die neue Precharge-Relais-Ansteuerung in den Pack-Mode-Übergängen sollten an einem realen Multi-Pack-Setup verifiziert werden, bevor daraus HA-Integrations-Annahmen abgeleitet werden. Statisch/per Decompiler ist damit alles aus dem 117.7→118-Diff ausgeschöpft.

## 9. Ghidra-Renaming angewendet (2026-07-15)

Die obige Analyse war bis 2026-07-15 nur dokumentiert, aber nie als Ghidra-Symbolnamen zurückgeschrieben (Funktionen-Zähler stand bei 0/550). Nachgeholt über zwei Schritte:

1. **526 gematchte Funktionen** (218 identisch + 308 "changed"/Korrelations-Rauschen, s. Abschnitt 3) per `diff-transfer-markup` aus der bestehenden 117.7→118-Diff-Session automatisch übernommen (Konfidenzschwelle 0,9999 — alle Matches hatten similarity 1.0).
2. **24 neue Funktionen** (Abschnitt 4) einzeln per Ghidra-Skript benannt, gemäß der oben dokumentierten Analyse:

| Adresse | Name | Rolle |
|---|---|---|
| `0x08006fe4` | `PackMode_Dispatcher` | Top-Level-Dispatcher Pack-Mode-Kaskade |
| `0x080095e4` | `PackMode_Transitional_Handler` | Sub-State-Machine Modus 1 |
| `0x08008d28` | `PackMode_Active_MasterClaim` | Sub-State-Machine Modus 2 |
| `0x0800cb90` | `PackMode_Shutdown_Handler` | Sub-State-Machine Modus 3, Nachfolger `Precharge_StateMachine` |
| `0x0800a9f4` | `PackMode_Idle_RelayToggle` | Idle-Zustand, periodisches Relais-Toggle |
| `0x08006bbc` | `PackSelect_SOCBalance_Clamp` | SOC-Balance-Clamp/Auswahl-Helfer |
| `0x08006c04` | `Pack_MinCellVoltage_AcrossActive` | Min-Zellspannung über aktive Packs |
| `0x08000e20` | `CAN_PackCmd_Build_Type2` | CAN-Kommando-Builder Typ 2 |
| `0x08000ea8` | `CAN_PackCmd_Build_Type3` | CAN-Kommando-Builder Typ 3 |
| `0x08000ef0` | `CAN_PackCmd_Build_Type6` | CAN-Kommando-Builder Typ 6 |
| `0x08000f20` | `CAN_PackCmd_Build_Type7` | CAN-Kommando-Builder Typ 7 |
| `0x08002198` | `System_Reset_And_Halt_WithCurrentCheck` | erweiterter Forced-Reset mit Packstrom-Check (s. 4.2) |
| `0x080029c8` | `RS485_USART2_Init_DMA_RingBuffer` | UART-Init mit 1024B-Ringpuffer (0x40004400) |
| `0x08002a60` | `RS485_UART4_Init_DMA_RingBuffer` | UART-Init mit 1024B-Ringpuffer (0x40004c00) |
| `0x08002938` | `RS485_UART_Send_Byte_Blocking` | blockierendes Byte-Senden mit Timeout-Polling |
| `0x0800d7b0` | `RS485_UART_Send_Byte_Blocking_Wrapper` | Wrapper dazu |
| `0x08007d90` | `RS485_Register_Write_Handler` | erweiterter Nachfolger (mehr Block-IDs, s. 4.5) |
| `0x0800a584` | `Cell_OVP_UVP_TempCompensated_Protection` | neue Zellspannungs-Schutzlogik (s. 4.6) |
| `0x08013590` | `SOC_Algorithm_Orchestrator` | Nachfolger, gleiche Rolle + Event-Logging (s. 4.7) |
| `0x08013e34` | `SOC_OCV_Bounds_Check_And_Recalibrate` | OCV-Grenzwert-Check + Rekalibrierungs-Trigger |
| `0x08009fdc` | `PerPack_Struct_Builder` | inhaltlich identischer Nachfolger (nur Versionskonstante geändert) |
| `0x08005a40` | `CAN_RX_Handler` | manuell bestätigter Nachfolger (VT-Korrelator fand keinen Match) |
| `0x08005028` | `GPIOD_Peripheral_SelfTest_Init` | Peripherie-Init/Selbsttest mit Fehlercode-Logging |
| `0x08003334` | `CAN_Periodic_Alarm_Broadcast` | tickgetriebene periodische CAN-Alarmmeldung |

Verifiziert: 550/550 Funktionen eindeutig benannt, keine Namensdubletten (Ghidra-Skript-Check nach Anwendung).
