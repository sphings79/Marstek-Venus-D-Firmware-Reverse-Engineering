# SWD/JTAG-Dump-Plan — die letzten Verdrahtungs-Fragen schließen

**Datum:** 16. August 2026
**Zweck:** Alles Funktionale (Handler, Tasks, Feldnamen, Descriptor-Formate) ist statisch aus den
OTA-Images rekonstruiert. Offen bleibt nur die **Verdrahtungs-/Registrierungs-Schicht** und ein paar
Tabellen, die entweder zur Laufzeit im SRAM aufgebaut werden oder in **nicht-verteilten Flash-Sektoren**
liegen. Beides lässt sich mit Gerätezugriff schließen — meist sogar ohne kompletten Flash-Dump.

> **Kernaussage:** Für die *Tabellen-Inhalte* reicht ein **Live-RAM-Read** (Gerät läuft, halten, lesen).
> Ein voller **Flash-Dump** wird nur für den *statischen Code/Strings* in den fehlenden Sektoren gebraucht.

---

## 1. Was genau fehlt (Ziel-Inventar)

### Control-MCU (VNSD-0, Cortex-M, Image 0x08000000–0x0805EFFF)

| Region | Adresse | Größe | Typ | Schließt Frage |
|---|---|---|---|---|
| **0xAA-Handler-Tabelle** | SRAM `0x2000018c` | 17×8 = 136 B | Laufzeit-RAM | Welcher CAN-Gruppen-Slot ruft welchen Handler (Registrar) |
| **Descriptor-Tabelle** | SRAM `0x20000354` | 246×12 = 2952 B | Laufzeit-RAM | Alle Register→SRAM-Quellzeiger + Typ/Scale, ohne Live-Scan |
| **Fehlender Flash-Tail** | `0x0805F000–0x08064000` | ~20 KB | Flash (Sektor 7) | Cloud-Formatstrings, Init-/Registrierungs-Code, Shell-Command-Match-Tabelle `0x08060EF8` |

### Micro-MCU (VNS Inverter, Image 0x08000000–0x0801C3FF)

| Region | Adresse | Größe | Typ | Schließt Frage |
|---|---|---|---|---|
| **Telemetrie-Descriptor** | SRAM `0x200004C0` | ≤70×12 = 840 B | Laufzeit-RAM | Micro-Register→SRAM-Quellzeiger (RS485/Modbus-Interface) |
| **0x10000000-Bereich** | `0x10000000–0x10020000` | ~128 KB | mem-mapped | Descriptor-**Builder**-Code + Konfig-Tabellen (nicht im .bin) |

> **Wichtig:** Die Register-*Bedeutungen* sind bereits geklärt (über Handler, BMS-`CAN_TX_PerPack_10Msgs`
> und Debug-Prints). Diese Dumps liefern nur die **Verdrahtung** (Slot→Handler, Reg→Quellzeiger) und die
> statischen Match-/String-Tabellen.

---

## 2. Zwei Wege — erst der einfache

### Weg A (empfohlen zuerst): Live-RAM-Read der Laufzeit-Tabellen
Kein Flash-Dump nötig, keine Read-Out-Protection-Probleme (RAM ist immer lesbar, wenn Debug-Zugang steht).
Gerät normal booten lassen, per Debugger anhalten (`halt`), dann die drei SRAM-Tabellen auslesen:

- Control `0x2000018c` (136 B) → 17 Einträge `{u16 group_id, u16 pad, u32 handler_ptr}`
- Control `0x20000354` (2952 B) → 246 Einträge `{u16 reg, u16 pad?, u32 src_ptr, u8 type, u8 elem, u8 scale, u8 count}` (12 B; Format s. `Descriptor_Table_Unpack_Format.md`)
- Micro `0x200004C0` (840 B) → 70 Einträge `{u16 reg, u16 pad, u32 src_ptr, u8 type, u8 elem, u8 scale, u8 count}`

**Das allein schließt fast alle offenen Verdrahtungs-Fragen.** Erst wenn die *statischen* Sektoren
(Cloud-Strings, Shell-Command-Match-Werte) gebraucht werden, ist Weg B nötig.

### Weg B: Voll-Flash-Dump der fehlenden Sektoren
Für Control-Tail `0x0805F000+` und die Micro-`0x10000000`-Region.

---

## 3. Voraussetzungen (Hardware & Software)

**Debug-Probe:** ST-Link V2/V3 (günstig, für STM32 ideal) oder SEGGER J-Link.

**SWD-Anschluss (4–5 Leitungen)** an den jeweiligen MCU-Debug-Pins:
- `SWDIO`, `SWCLK`, `GND`, `VDD` (nur als Referenz, NICHT einspeisen wenn Board versorgt ist), optional `NRST`.
- Debug-Pads am PCB suchen (oft 4er-Reihe neben der MCU) oder direkt an den MCU-Pins abgreifen.
- **Board muss versorgt sein** (eigene Speisung); Probe nur SWDIO/SWCLK/GND + VDD-sense.

**Software (eine wählen):**
- **OpenOCD** (universell) — Beispiele unten.
- **pyOCD** (`pip install pyocd`) — komfortabel für STM32.
- **ST-Link Utility / STM32CubeProgrammer** (GUI, Windows/Linux/Mac).

### ⚠️ STM32 Read-Out-Protection (RDP) — ZUERST prüfen!
STM32 kann per RDP-Level das Auslesen des internen Flash **komplett sperren**.
- **RDP Level 0** = offen, Flash lesbar. **Level 1** = Flash-Read via Debugger gesperrt (RAM noch lesbar!).
  **Level 2** = Debug komplett tot.
- **Prüfen** (Option-Bytes / `FLASH_OPTR`): z.B. OpenOCD `stm32f4x option_read 0` bzw. bei CubeProgrammer im Option-Bytes-Tab.
- 🚫 **NIEMALS** versuchen, RDP von Level 1 auf 0 zu senken „um lesen zu können" — das **löscht den kompletten Flash** (Mass-Erase). Nur lesen, nichts an Option-Bytes ändern.
- Falls RDP≥1: **Weg A (RAM-Read) funktioniert trotzdem** — RAM ist nicht RDP-geschützt. Nutze das.

---

## 4. Konkrete Kommandos (OpenOCD)

### 4.1 Verbinden & Chip identifizieren
```bash
# Control (vermutlich STM32F4, 512 KB) — Target-Cfg ggf. anpassen
openocd -f interface/stlink.cfg -f target/stm32f4x.cfg
# in zweitem Terminal:
telnet localhost 4444
```
```
> reset halt
> mdw 0xE0042000 1        ;# DBGMCU_IDCODE -> exaktes Bauteil verifizieren
> stm32f4x option_read 0  ;# RDP/Option-Bytes prüfen (RDP muss 0xAA/Level0 sein)
```
> Für den **Micro** analog mit `target/stm32f3x.cfg` (bzw. dem per IDCODE bestätigten Teil).

### 4.2 Weg A — Laufzeit-Tabellen aus RAM lesen
```
> halt
;# Control 0xAA-Handler-Tabelle (136 B)
> dump_image ctrl_aa_table_2000018c.bin 0x2000018c 136
;# Control Descriptor-Tabelle (2952 B)
> dump_image ctrl_descriptor_20000354.bin 0x20000354 2952
;# Micro Descriptor-Tabelle (840 B) — an der Micro-Probe
> dump_image micro_descriptor_200004c0.bin 0x200004C0 840
```
> Tipp: mehrere Snapshots im Betrieb ziehen (Laden/Entladen), um dynamische vs. statische Felder zu unterscheiden.

### 4.3 Weg B — fehlende Flash-Sektoren dumpen
```
;# Control: kompletten Flash 0x08000000..0x08080000 (512 KB) sichern
> dump_image ctrl_flash_full.bin 0x08000000 0x80000
;# ...oder gezielt nur den fehlenden Tail:
> dump_image ctrl_tail_0805F000.bin 0x0805F000 0x9000     ;# bis 0x08068000

;# Micro: internen Flash + die 0x10000000-Region
> dump_image micro_flash_full.bin 0x08000000 0x40000
> dump_image micro_region_10000000.bin 0x10000000 0x20000  ;# 128 KB
```
> Falls `0x10000000` nicht direkt lesbar (kein mem-mapping im Halt): prüfen, ob es CCM-RAM ist
> (dann nach Boot lesbar) oder externer QSPI/FMC (dann Controller erst initialisieren lassen — Gerät
> normal booten, DANN halten und lesen).

### pyOCD-Äquivalent (falls lieber)
```bash
pyocd cmd -t stm32f429xi        # Chip anpassen
# in der pyOCD-Shell:
savemem 0x2000018c 136 ctrl_aa_table.bin
savemem 0x20000354 2952 ctrl_descriptor.bin
savemem 0x0805F000 0x9000 ctrl_tail.bin
```

---

## 5. In Ghidra einspielen

### 5.1 SRAM-Tabellen als Overlay-Block hinzufügen (schließt die Verdrahtung)
Damit die bisher „nicht gemappten" SRAM-Adressen echte Daten bekommen:
1. Ghidra → **Window ▸ Memory Map** ▸ **+ (Add Block)**
   - Name `sram_live`, Start `0x20000000`, Länge passend (z.B. 0x20000 = 128 KB), **Initialized: From File Import** → die RAM-Dumps an die richtige Offset-Adresse legen.
   - Praktischer: pro Tabelle einen Block (`aa_table` @0x2000018c, `descriptor` @0x20000354) mit dem jeweiligen `.bin` als Inhalt.
2. Die 17 `handler_ptr`-Werte in der 0xAA-Tabelle sind jetzt lesbare Flash-Pointer →
   **Rechtsklick ▸ Data ▸ Pointer**; Ghidra verlinkt sie auf `CAN_Store_PerPack_Grp2x_...` →
   **Slot↔Handler-Zuordnung endgültig belegt** (statt inferiert).
3. Descriptor-Tabelle 0x20000354 mit `marstek_descriptor_unpack.py` bzw. dem 12-B-Format parsen →
   vollständige Register→Quellzeiger-Liste **ohne** Live-Scan.

### 5.2 Fehlenden Flash-Tail an das bestehende Programm anhängen
1. Memory Map ▸ Add Block: Name `flash_tail`, Start `0x0805F000`, **Initialized: From File Import** →
   `ctrl_tail_0805F000.bin`.
2. **Auto-Analysis erneut laufen lassen** (Analysis ▸ Auto Analyze) — jetzt werden:
   - die Cloud-`snprintf`-Formatstrings aufgelöst (Cloud-JSON-Feldnamen final),
   - die Shell-Command-Match-Tabelle `0x08060EF8` sichtbar → Command-IDs der Tool-Shell,
   - der bisher fehlende Init-/Registrierungs-Code disassembliert → die `callerCount 0`-Funktionen
     (Tasks/Callbacks) bekommen ihre Aufrufer/`xTaskCreate`-Registrierung.
3. Für den **Micro**: `micro_region_10000000.bin` als Block @0x10000000 einhängen, Auto-Analyze →
   der Descriptor-**Builder** wird sichtbar (schreibt 0x200004C0).

> **Alternativ (kein Overlay-Import):** Ein zweites Ghidra-Programm aus dem Voll-Dump importieren
> (Base 0x08000000) und per ReVa-Diff/Markup-Transfer die Namen aus dem OTA-Projekt übernehmen.

---

## 6. Was jeder Dump konkret schließt (Checkliste)

- [ ] **Control 0x2000018c (RAM)** → Registrar/Slot→Handler der Per-Pack-CAN-Tabelle (letzter §13-Rest).
- [ ] **Control 0x20000354 (RAM)** → komplette Descriptor-Map ohne Live-Scan; verifiziert `all_register.csv`.
- [ ] **Control-Tail 0x0805F000+ (Flash)** → Cloud-JSON-Feldnamen, Shell-Command-Match-Werte (Shell.md §8.1), `callerCount 0`-Aufrufer (Serial/UART/Modbus/CH395-Tasks).
- [ ] **Micro 0x200004C0 (RAM)** → Micro-Register→Quellzeiger.
- [ ] **Micro 0x10000000 (mem)** → Descriptor-Builder + Konfig-Tabellen.

---

## 7. Sicherheits-/Vorsichtshinweise

- **Nur lesen.** Keine `flash write`/`erase`/Option-Byte-Schreibvorgänge. Ein versehentlicher
  Mass-Erase (z.B. RDP-Downgrade) macht das Gerät leer.
- **Backup zuerst:** direkt nach Verbindungsaufbau einen Voll-Flash-Dump ziehen (falls RDP=0), bevor
  irgendetwas anderes passiert.
- **Spannung:** Probe-VDD nur als Sense; das Board über sein Netzteil versorgen, keine Doppelspeisung.
- **Live-Reads** sind unkritisch und der schnellste Weg zu den Tabellen — damit anfangen.

---

*Verweise: `Modbus_RS485_TCP/Descriptor_Offene_Register_Ghidra_Befund.md` (§11–§13),
`Modbus_RS485_TCP/Descriptor_Table_Unpack_Format.md`, `Methodik_und_Meta/Doku_Audit_Offene_Punkte_2026-08-16.md`,
`Methodik_und_Meta/Shell.md` (§8).*
