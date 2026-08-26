# Marstek Venus D — Firmware Reverse-Engineering

Statische Reverse-Engineering-Analyse der Marstek-Venus-D-Firmware (Control/EMS, Micro-Inverter/VNS,
BMS) mittels Ghidra, als Grundlage für eine Home-Assistant-Integration über die Modbus-TCP-Schnittstelle
des Geräts. Alle Erkenntnisse basieren auf statischer Analyse der Firmware-Images, nicht auf Live-Debug-
Zugriff (SWD/JTAG), sofern nicht anders vermerkt.

**Gerät:** Marstek Venus D/E (VNSD-0), STM32 ARM Cortex-M, FreeRTOS
**Analysierte Firmware-Versionen:** Control 149.2 (aktuell) / 147, Micro/VNS 116 (aktuell) / 115, BMS
118 (aktuell) / 117.7

## Binary-Fingerprint (alle analysierten Firmware-Images)

Live aus Ghidra verifiziert (Stand 2026-07-15). Der "Funktionen benannt"-Anteil ist reiner
Ghidra-Symbolstatus. BMS 118 wurde inhaltlich vollständig analysiert (Diff, Struct-/Register-Layouts)
und die Erkenntnisse wurden am 2026-07-15 als Ghidra-Symbolnamen zurückgeschrieben (526 per
Diff-Markup-Transfer aus 117.7, 24 neue einzeln benannt) — daher 100 %. Control 147 wurde am selben Tag
komplett neu erschlossen: 1530 Funktionen per Diff-Markup-Transfer aus 149.2, 340 nur-in-147-Funktionen
per Subagenten-Analyse einzeln benannt (davon 23 als Ghidra-Funktionsgrenzen-Artefakte markiert statt
mit erfundener Semantik versehen) — Details in `Control_FW/Control_FW_Analyse_147_202601281721320b2053125.md`.

| Firmware | Version | Datei | Größe | Flash-Bereich | Initial SP | Reset Handler | Funktionen (benannt/gesamt) | Strings |
|---|---|---|---|---|---|---|---|---|
| Control | **149.2 (aktuell)** | `Control_149.2_VNSD-0_app_1492_0702_142136.bin` | 385.024 B (376 KB) | `0x08000000–0x0805DFFF` | `0x2001F7D8` | `0x08004A71` | 1618 / 1622 (99,8 %) | 1743 |
| Control | 147 | `Control_147_...0b2053125.bin` | 372.736 B (364 KB) | `0x08000000–0x0805AFFF` | `0x2001F3E0` | `0x08004A71` | 1870 / 1870 (100 %) | 1302 |
| Micro/VNS | **116 (aktuell)** | `Micro_VNS_116_vd_inv_app_0116_0702_ota_163439.bin` | 115.712 B (113 KB) | `0x08000000–0x0801C3FF` | `0x20009A70` | `0x080042AD` | 392 / 445 (88,1 %) | 251 |
| Micro/VNS | 115 | `Micro_VNS_115_...0c0e30687.bin` | 115.712 B (113 KB) | `0x08000000–0x0801C3FF` | `0x20009A70` | `0x080042B1` | 13 / 190 (6,8 %, nur Versions-Diff gg. 116) | 102 |
| BMS | **118 (aktuell)** | `BMS_118_20260119100535e43806957.bin` | 106.496 B (104 KB) | `0x08000000–0x08019FFF` | `0x2000CBA0` | `0x08002A6D` | 550 / 550 (100 %) | 256 |
| BMS | 117.7 | `BMS_117.7_20251010135647565eb2036.bin` | 106.496 B (104 KB) | `0x08000000–0x08019FFF` | `0x2000CB90` | `0x08002A6D` | 552 / 552 (100 %) | 260 |

**Gemeinsame Eigenschaften aller sechs Images:** ARM Cortex-M4F, Thumb-2, Little-Endian, FreeRTOS
(`heap_4`, `ARM_CM4F`-Port), Flash-Basis `0x08000000`.

| Firmware | Compiler | Crypto | Zellmonitoring | Kommunikation |
|---|---|---|---|---|
| Control | GCC | mbedTLS 2.28.10 | — | WiFi + Ethernet (CH395) + RS485 + CAN |
| Micro/VNS | RVDS/Keil ARM | — (keine) | — | CAN + RS485 |
| BMS | RVDS/Keil ARM | — (keine) | KA495XX (BMIC) | CAN + RS485 |

Auffällig: Micro/VNS 115 und 116 sowie BMS 117.7 und 118 belegen jeweils exakt denselben
Flash-Adressbereich trotz unterschiedlichen Funktionsumfangs — spricht für eine feste OTA-Slot-Größe
pro Firmware-Typ statt variabler Image-Größe.

## Ordnerstruktur

| Ordner | Inhalt |
|---|---|
| `Control_FW/` | Control-/EMS-Firmware (Hauptprozessor): vollständige Funktionsanalyse für v149.2 (Namens-Tracking-Tabelle, ~1600 Funktionen, Batch-Historie) und v147 (Diff-basierte Analyse gg. 149.2, 340 nur-in-147-Funktionen einzeln dokumentiert) |
| `VNS_Micro_Inverter/` | Micro-Inverter-/VNS-Firmware: Funktionsanalyse, Register-Maps, Versions-Diff 115→116 |
| `BMS/` | BMS-Firmware-Analyse (v117.7, v118) |
| `Modbus_RS485_TCP/` | Externe Modbus-Schnittstelle des Geräts (TCP **und** RS485 RTU, paralleler Stack mit gemeinsamer Descriptor-Tabelle): Verbindungsreferenz, Protokoll-Eigenheiten, Scale-Faktoren, RS485-Freischaltung, vollständige Register-Map (CSV), Register-Vermutungen aus Scan-Auswertung, rohe Scan-Logs verschiedener Betriebszustände |
| `Scripts/` | Python-Tools zum Scannen/Überwachen der Modbus-Register (Raw-Socket, kein pymodbus) |
| `Methodik_und_Meta/` | Reverse-Engineering-Methodik, Ghidra-Workflow/Lessons-Learned, Firmware-Diff-Workflow, Seriennummern-Format, offene Fragen |

**Achtung Begriffsverwechslung:** "RS485" taucht in der Firmware in zwei unabhängigen Rollen auf —
(1) der **externe** RS485-RTU-Modbus-Stack (47.400 Baud, FC03/FC06/FC10, paralleler Zugang zu
denselben Registern wie Modbus TCP, in `Modbus_RS485_TCP/` dokumentiert) und (2) **interne**
RS485/UART-Verbindungen zwischen den MCUs (Control↔Micro-Inverter für Leistungssollwerte/Modi, BMS-
Master↔Slave-Packs für 96-Byte-Struct-Transfers) — ein proprietäres Struct-Protokoll, **kein Modbus**,
dokumentiert in `Control_FW/` bzw. `BMS/`.

## Wichtiger Hinweis zu Sicherheitsbefunden

Im Zuge der Analyse wurden sicherheitsrelevante Befunde gemacht (u. a. ein produktlinienübergreifend
geteiltes, hartcodiertes AWS-IoT-Client-Zertifikat samt Private Key sowie ein Firmware-Update-Pfad ohne
Bounds-Check). Diese wurden dem Hersteller per Responsible Disclosure vertraulich gemeldet und werden
**bewusst nicht in diesem Repository veröffentlicht**, bis eine Behebung vorliegt. Betroffene
Textstellen in den obigen Dokumenten sind entsprechend gekennzeichnet und verweisen auf interne,
nicht-öffentliche Dokumentation.

## Nutzung für die Home-Assistant-Integration

Relevant sind vor allem `Modbus_RS485_TCP/` (Verbindungsaufbau, Register-Map, Scale-Faktoren,
Fallstricke wie das 32-Register-Batch-Limit) sowie die Register-/Struct-Beschreibungen in `Control_FW/`
und `VNS_Micro_Inverter/`.

---

## ☕ Support

These tools are built and maintained in my free time, and they stay free, open and cloud-free.
If one of them saved you an afternoon, you can [buy me a coffee](https://buymeacoffee.com/sphings).

[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-sphings-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=000000)](https://buymeacoffee.com/sphings)
