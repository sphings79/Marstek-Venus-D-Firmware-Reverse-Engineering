# Marstek Venus D — Firmware-Reverse-Engineering

[English](README.md) · **Deutsch**

Statisches Reverse-Engineering der **Marstek-Venus-D/E**-Firmware — Control-/EMS-Prozessor,
Micro-Inverter/VNS-Controller und BMS — mit **Ghidra**. Ziel ist eine vollständig dokumentierte,
**cloudfreie lokale Modbus-TCP-Schnittstelle** für eine **Home-Assistant-Integration**: komplette
Register-Map, Skalierungsfaktoren, Protokoll-Eigenheiten und die internen CAN-/RS485-Struct-Protokolle
zwischen den MCUs. Alle Erkenntnisse stammen aus statischer Analyse der Firmware-Images (kein
SWD/JTAG-Live-Debug), sofern nicht anders vermerkt.

<p align="center">
  <img src="assets/ghidra-listing.svg" alt="Ghidra-Disassembly und dekompiliertes C des Modbus-Read-Handlers der Marstek-Venus-D-Control-Firmware" width="900">
</p>

**Gerät:** Marstek Venus D/E (VNSD-0) · STM32 (STM32F3-Reihe) · ARM Cortex-M4F · FreeRTOS
**Analysierte Firmware:** Control 149.2 / 150 / 147 · Micro/VNS 116 / 115 · BMS 118 / 117.7
**Schlagworte:** Marstek Venus Firmware, Ghidra Reverse Engineering, STM32 Cortex-M4F, FreeRTOS,
Modbus TCP, Modbus RTU RS485, BMS, KA495XX BMIC, Home Assistant, Batteriespeicher, Balkonkraftwerk.

> [!IMPORTANT]
> Alle geräteidentifizierenden Daten in diesem Repository sind **anonymisiert** — MAC/BT-MAC,
> IP-Adressen, Device-ID, Seriennummer, BLE-Name, WLAN-Zugangsdaten und Live-Werte des
> Credential-Puffers sind durch Platzhalter wie `AA:BB:CC:DD:EE:FF`, `<DEVICE_ID>` oder
> `192.168.1.100` ersetzt.

## Systemarchitektur

Drei STM32-MCUs arbeiten über einen **internen CAN-Bus** und **interne RS485/UART**-Verbindungen
zusammen. Der Control-Prozessor bildet die Außenschnittstelle: **Modbus TCP** (WLAN über ein
Quectel-Modul + Ethernet über einen CH395), einen parallelen **Modbus-RTU**-Stack auf externem RS485,
**BLE** sowie den Hersteller-Cloud-/OTA-Pfad.

<p align="center">
  <img src="assets/architecture.svg" alt="Systemarchitektur: Control/EMS, Micro-Inverter und BMS über internen CAN und RS485, nach außen über Modbus TCP, Modbus RTU und BLE" width="900">
</p>

> **Zwei Bedeutungen von „RS485".** (1) Der **externe** RS485-RTU-Modbus-Stack (47400 Baud,
> FC03/FC06/FC10, dieselben Register wie Modbus TCP) — dokumentiert in
> [`Modbus_RS485_TCP/`](Modbus_RS485_TCP/). (2) Die **internen** RS485/UART-Verbindungen zwischen den
> MCUs (Control ↔ Micro-Inverter für Sollwerte/Modi; BMS-Master ↔ Slave-Packs für 96-Byte-Structs) —
> ein proprietäres Struct-Protokoll, **kein Modbus**, dokumentiert in [`Control_FW/`](Control_FW/)
> bzw. [`BMS/`](BMS/).

## Binary-Fingerprint

Live aus Ghidra verifiziert. Der „Funktionen benannt"-Anteil ist reiner Ghidra-Symbolstatus. BMS 118
und Control 147 wurden per Diff-Markup-Transfer aus der Nachbarversion plus Einzelanalyse der
nur-in-Version-Funktionen vollständig erschlossen.

| Firmware | Version | Größe | Flash-Bereich | Initial SP | Reset-Handler | Funktionen (benannt/gesamt) | Strings |
|---|---|---|---|---|---|---|---|
| Control | **149.2 (aktuell)** | 385.024 B (376 KB) | `0x08000000–0x0805DFFF` | `0x2001F7D8` | `0x08004A71` | 1618 / 1622 (99,8 %) | 1743 |
| Control | 147 | 372.736 B (364 KB) | `0x08000000–0x0805AFFF` | `0x2001F3E0` | `0x08004A71` | 1870 / 1870 (100 %) | 1302 |
| Micro/VNS | **116 (aktuell)** | 115.712 B (113 KB) | `0x08000000–0x0801C3FF` | `0x20009A70` | `0x080042AD` | 392 / 445 (88,1 %) | 251 |
| Micro/VNS | 115 | 115.712 B (113 KB) | `0x08000000–0x0801C3FF` | `0x20009A70` | `0x080042B1` | 13 / 190 (nur Versions-Diff) | 102 |
| BMS | **118 (aktuell)** | 106.496 B (104 KB) | `0x08000000–0x08019FFF` | `0x2000CBA0` | `0x08002A6D` | 550 / 550 (100 %) | 256 |
| BMS | 117.7 | 106.496 B (104 KB) | `0x08000000–0x08019FFF` | `0x2000CB90` | `0x08002A6D` | 552 / 552 (100 %) | 260 |

**Gemeinsam für alle sechs Images:** ARM Cortex-M4F, Thumb-2, Little-Endian, FreeRTOS (`heap_4`,
`ARM_CM4F`-Port), Flash-Basis `0x08000000`.

| Firmware | Compiler | Krypto | Zellmonitoring | Kommunikation |
|---|---|---|---|---|
| Control | GCC | mbedTLS 2.28.10 | — | WLAN + Ethernet (CH395) + RS485 + CAN |
| Micro/VNS | RVDS/Keil ARM | — | — | CAN + RS485 |
| BMS | RVDS/Keil ARM | — | KA495XX (BMIC) | CAN + RS485 |

Auffällig: Micro/VNS 115↔116 und BMS 117.7↔118 belegen trotz unterschiedlichen Funktionsumfangs
exakt denselben Flash-Bereich — spricht für eine feste OTA-Slot-Größe je Firmware-Typ.

## Reverse-Engineering-Workflow

<p align="center">
  <img src="assets/re-workflow.svg" alt="Workflow: Firmware-Image, Ghidra-Autoanalyse, Diff-Markup-Transfer zwischen Versionen, Funktionsbenennung, Register-/Struct-Doku, Home-Assistant-Integration" width="900">
</p>

Die Methodik, die Ghidra-Lessons-Learned und der Firmware-Diff-Workflow liegen in
[`Methodik_und_Meta/`](Methodik_und_Meta/).

## Ordnerstruktur

| Ordner | Inhalt |
|---|---|
| [`Control_FW/`](Control_FW/) | Control-/EMS-Firmware (Hauptprozessor): vollständige Funktionsanalyse für v149.2 und v147, dazu der v150-Cloud-Watchdog und die Ursachenanalyse der 30-Minuten-Netzausfälle |
| [`VNS_Micro_Inverter/`](VNS_Micro_Inverter/) | Micro-Inverter-/VNS-Firmware: Funktionsanalyse, Register-Maps, Fehlercodes, Versions-Diff 115→116 |
| [`BMS/`](BMS/) | BMS-Firmware-Analyse (v117.7, v118) und eine Per-Pack-Fehler-Fallstudie |
| [`Modbus_RS485_TCP/`](Modbus_RS485_TCP/) | Externe Modbus-Schnittstelle (TCP **und** RS485 RTU): Verbindungsreferenz, Protokoll-Eigenheiten, Skalierungsfaktoren, vollständige Register-Map (CSV), Descriptor-Tabellen-Format, rohe Scan-Logs, Read-Serializer-Vorzeichenfehler, Write-Register-Block 46500–46544 |
| [`CAN_Bus/`](CAN_Bus/) | Interner CAN-Bus zwischen den MCUs: Arbitration-ID-Aufbau, Zielklassen, Funktionscode-Tabellen aller 46 Control-Sendestellen gegen die Dispatcher von Micro v116 und BMS v118 |
| [`BLE/`](BLE/) | BLE-Command-Map und BLE↔Modbus-Querverweis |
| [`HM_HIE_FC41D/`](HM_HIE_FC41D/) | FC41D-WLAN/BLE-Kommunikationsmodul: OTA-Analyse, Hamedata-App-API-Recon, Traffic-Capture-Anleitungen (Binaries ausgeschlossen) |
| [`Scripts/`](Scripts/) | Python-Tools zum Scannen/Überwachen der Modbus-Register (Raw-Socket, kein pymodbus) und der Dekompilat-Exporter |
| [`Methodik_und_Meta/`](Methodik_und_Meta/) | Reverse-Engineering-Methodik, Ghidra-Workflow, Firmware-Diff-Workflow, Seriennummern-Format, offene Fragen |

## Modbus-Register-Map

Dieselbe Register-Map ist über Modbus **TCP** (`:502`) und **RS485 RTU** (47400 Baud) erreichbar. Der
Read-Serializer wendet je Register Skalierungsfaktoren an; Reads sind auf **32 Register pro Anfrage**
begrenzt.

<p align="center">
  <img src="assets/register-map.svg" alt="Modbus-Register-Landschaft: Telemetrie, BMS, Per-Pack, Config und WLAN, Command- und Write-Blöcke zwischen Register 30000 und 46544" width="900">
</p>

Die vollständige Map liegt in [`Modbus_RS485_TCP/`](Modbus_RS485_TCP/) als CSV plus Markdown-Notizen,
zusammen mit den Scan-Logs über Lade-/Entlade-/Backup-/DoD-Zustände.

## Firmware-Memory-Map

<p align="center">
  <img src="assets/memory-map.svg" alt="Flash- und SRAM-Memory-Map der Marstek-Venus-D-Control-Firmware, von der Vektortabelle bei 0x08000000 bis zum SRAM bei 0x20000000" width="900">
</p>

## Sicherheitsbefunde

Im Zuge der Analyse wurden sicherheitsrelevante Befunde gemacht — u. a. ein produktlinienübergreifend
geteiltes, hartcodiertes AWS-IoT-Client-Zertifikat samt Private Key sowie ein Firmware-Update-Pfad ohne
Bounds-Check. Diese wurden dem Hersteller per **Responsible Disclosure** gemeldet und werden **bewusst
nicht hier veröffentlicht**, bis eine Behebung vorliegt. Betroffene Textstellen verweisen auf interne,
nicht-öffentliche Notizen.

## Nutzung für eine Home-Assistant-Integration

Am relevantesten ist [`Modbus_RS485_TCP/`](Modbus_RS485_TCP/) (Verbindungsaufbau, Register-Map,
Skalierungsfaktoren, das 32-Register-Batch-Limit) zusammen mit den Register-/Struct-Beschreibungen in
[`Control_FW/`](Control_FW/) und [`VNS_Micro_Inverter/`](VNS_Micro_Inverter/). Cloudfreier Betrieb
vermeidet die 30-Minuten-Netz-Resets der Firmware — siehe die verwandten Projekte unten.

## Verwandte Marstek-Projekte

| Projekt | Was es ist |
|---|---|
| [marstek_venus_modbus_dev](https://github.com/sphings79/marstek_venus_modbus_dev) | Home-Assistant-Integration für Marstek Venus über lokales Modbus TCP — Sensoren, Steuerung, Zeitpläne, volle Register-Map. Ohne Cloud, HACS-kompatibel. |
| [Marstek-offline-endpoint](https://github.com/sphings79/Marstek-offline-endpoint) | Selbstgehosteter Endpunkt, der den Telemetrie-Upload lokal beantwortet und die 30-Minuten-Netz-Resets der Firmware stoppt. |
| [Marstek_Modbus_Register](https://github.com/sphings79/Marstek_Modbus_Register) | Community-Reverse-Engineering der Venus-D-Modbus-TCP-Register (30000–49999), DE/EN, CSV + Markdown. |
| [marstek-firmware-archiv](https://github.com/sphings79/marstek-firmware-archiv) | Firmware-Archiv für Venus E/D/A, Saturn/B2500 & CT002 — Original-OTA-Downloads, Release Notes, SHA-256-Prüfsummen. |
| [marstek-fw-checker](https://github.com/sphings79/marstek-fw-checker) | Firmware für Marstek Venus D/E/C/A und B2500 herunterladen, sichern und archivieren, bevor ein Update installiert wird. |
| [marstek-firmware-analyzer](https://github.com/sphings79/marstek-firmware-analyzer) | Browser-basierter Analyzer für Marstek-Firmware-Images — extrahiert eingebettete Zertifikate, Keys und AWS-IoT-Endpunkte, vollständig clientseitig. |
| [venuscontrol](https://github.com/sphings79/venuscontrol) | Cloudfreies Web-Control-Panel für Venus A/D über Web Bluetooth — OTA-Updates, Peak Shaving, lokales Modbus TCP / Shelly Pro 3EM. |

## Unterstützung

Wenn dir das hier Zeit gespart hat, würde ich mich riesig über einen ⭐ **Stern** für das Repository
freuen — das hilft auch anderen, es zu finden. Und wer die nächste Analyse befeuern möchte, kann mir
einen Kaffee ausgeben: **[buymeacoffee.com/sphings](https://buymeacoffee.com/sphings)**. Danke!

## Haftungsausschluss

Unabhängige Forschung zu Interoperabilität und Sicherheit. Nicht mit Marstek verbunden oder von Marstek
unterstützt. Alle Marken gehören ihren jeweiligen Eigentümern. Firmware-Images und Dekompilate werden
hier **nicht** weiterverbreitet.
