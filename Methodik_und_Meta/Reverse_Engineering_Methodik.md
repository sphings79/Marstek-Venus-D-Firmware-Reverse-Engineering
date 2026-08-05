# Marstek Venus D — Reverse Engineering: Methodik & Erkenntnisse

**Projekt:** Marstek Venus D (`VNSD-0`) Reverse Engineering  
**Bezug:** Ausgelagert aus [Control_FW_Analyse_app_1492_0702_142136.md](Control_FW_Analyse_app_1492_0702_142136.md) (ehemals Abschnitt 13)

---

## 1. Firmware beschaffen

### Option A — Marstek FW Checker Tool (empfohlen)

Das einfachste Verfahren ist der **Marstek FW Checker**, ein Community-Tool
von Remko Weijnen. Eine angepasste, selbst-gehostete Instanz ist verfügbar unter:

```
https://sphings-dev.de/marstek/marstek-fw-checker/
```

**Funktionsweise:**

1. Login mit Marstek-Cloud-Zugangsdaten (gleiche wie in der Marstek-App)
2. Alle registrierten Geräte werden aufgelistet
3. Pro Gerät: **„Check Firmware"** klicken — verfügbare Versionen auf dem Marstek-Server werden angezeigt
4. Pro Firmware-Komponente erscheint ein **„📥 Download"-Button** — damit wird die `.bin`-Datei direkt heruntergeladen
5. Im Bereich **„Archive Status"** erscheint pro Komponente entweder:
   - **„✅ Archived"** — Version bereits im Community-Archiv gespeichert
   - **„📥 Not Archived"** + Button **„Submit for Archive"** — Version noch nicht archiviert

**Firmware spenden — warum und wie:**

Marstek löscht ältere Firmware-Versionen gelegentlich vom Server. Wer auf
**„Submit for Archive"** klickt, erstellt automatisch ein GitHub Issue im
Archiv-Repository. Die Firmware wird dann gesichert und bleibt der Community
dauerhaft zugänglich — auch wenn Marstek sie vom Server entfernt.

> Bitte für jede angezeigte Komponente (BMS, Control, Inverter) einzeln auf
> **„Submit for Archive"** klicken, sofern der Status „Not Archived" anzeigt.

**Unterstützte Gerätetypen:**

| Gerätetyp | Beschreibung | Firmware-Komponenten |
|---|---|---|
| **`VNSD-0`** | **Venus D** (dieses Gerät) | Control, Micro (seit Juli 2026 im OTA) |
| `VNSA-0` | Venus A | BMS, Control, Inverter (micro) |
| `VNSE3-0` | Venus E V3 | BMS, Control |
| `HMG-50` | Venus E V1/V2 | BMS, Control |
| `HMG-25` | Venus E V1/V2 klein | BMS, Control |
| `HME-4` / `HME-3` | AC-Couple-Geräte | eigener OTA-Endpunkt |

**Was das Tool pro Komponente liefert:**

| Firmware-Typ | Beschreibung | Beispiel VNSD-0 |
|---|---|---|
| Control (EMS) | Haupt-Controller-Firmware | v149 |
| Micro (Inverter) | Wechselrichter-Firmware | v116 |
| BMS | Battery Management System | — |
| MPPT | Solar-Laderegler (falls vorhanden) | — |

**Anpassungen dieser Instanz gegenüber dem Original:**

- Unterstützt u. a. `VNSD-0` (Venus D) sowie weitere Marstek-Gerätetypen
- Archivierung via GitHub: https://github.com/sphings79/marstek-firmware-archiv
- Dritter Download-Button für Inverter-Firmware (micro) ergänzt
- Läuft als selbst-gehosteter Node.js-Dienst hinter Apache (kein Netlify)

> **Hinweis:** Der Login meldet das Gerät in der Marstek-App aus — beide
> Sitzungen können nicht gleichzeitig aktiv sein. Nach dem Tool-Login
> einfach wieder in der App einloggen.
>
> **Datenschutz & Sicherheit:** Das Tool speichert keine Zugangsdaten —
> Login-Daten werden ausschließlich für die Dauer der Sitzung im Browser
> gehalten und direkt an den Marstek-Server weitergeleitet. Der Quellcode
> der eingesetzten, angepassten Version ist öffentlich einsehbar:
> https://github.com/sphings79/marstek-fw-checker  
> Wer dennoch Bedenken hat, sollte das Marstek-Passwort nach der Nutzung
> des Tools ändern.

> **VNSD-0 (Venus D):** Seit Juli 2026 im OTA-System gelistet (control v149, micro v116).
> Das FW-Checker-Tool zeigt diese Komponenten direkt an.

---

### Option B — OTA-Traffic abfangen (Wireshark)

Falls das Gerät ein Update bezieht oder der OTA-Server direkt befragt wird:

```bash
# OTA-Traffic via Wireshark abfangen (HTTP, unverschlüsselt)
# Server: eu.hamedata.com
# Filter: http && tcp.port == 80

# Binary verifizieren
xxd VNSD-0_app_1492_0702_142136.bin | head -5
# Zeile 1: 18 f3 01 20 71 4a 00 08 → IVT-Start (Stack-Pointer + Reset-Handler)
strings firmware.bin | grep -E "Task_|FreeRTOS|marstek"
```

### Option C — Direkte OTA-API-Abfrage

```bash
# Beispiel: VNSD-0 Firmware-Check (m=100 = alle Versionen abrufen)
curl "https://eu.hamedata.com/ems/api/v2/checkSmallBalconyOTA\
?uid=<devid>&device_type=VNSD-0&m=100&sbv=0&mppt=0&inv=0\
&token=<auth-token>&mailbox=<email>" | python3 -m json.tool

# Download-URL aus der Antwort extrahieren:
# data.control.url → Control-Firmware
# data.micro.url   → Inverter-Firmware
```

## 2. Ghidra-Konfiguration (Pflicht)

```
Import: Raw Binary
Language: ARM → Cortex → 32 → little → default
Base Address: 0x08000000

Memory Map zusätzlich hinzufügen:
  SRAM:   0x20000000  Größe 0x20000  R+W
  PERIPH: 0x40000000  Größe 0x10000000  R+W
  SCS:    0xE000E000  Größe 0x1000  R+W

Auto-Analyze: Decompiler Switch Analysis + Scalar Operand References aktivieren
```

## 3. Modbus-Routing-Schema

```
Eingehender Request:
    FC-Code == 6 (Write Single)?
        uVar6 >= 40000  →  Write-Handler FUN_0804c83c
        uVar6 <  40000  →  Descriptor-Tabelle suchen in FUN_0804b73c
    FC-Code == 3 (Read)?
        Descriptor-Tabelle iterieren, Serializer aufrufen
```

## 4. Warum die Descriptor-Tabelle nicht im Flash gefunden wurde

Die Tabelle wird zur Laufzeit durch Init-Code aufgebaut. Versuche die Quelltabelle zu finden:

| Strategie | Methode | Ergebnis |
|---|---|---|
| Statische Flash-Suche mit SRAM-Ptr | v4 Strategie A | 0 Treffer |
| Ohne SRAM-Ptr (monoton steigend) | v4 Strategie B | 0 Treffer |
| Startup-Literal-Pool | v6 | 0x08055d4c = MQTT-Strings |
| MOVW #0x7530 verfolgen | v5 | Führt zu JSON-Parser (falsch!) |
| STR mit Offset 0x2F8 | v7 Strategie A | 0 Treffer |
| MOVW #0x02F8 (Tabellenadresse) | v7 Strategie B | Nicht gefunden |
| 6-Byte-Stride Tabelle | v4 Strategie D | 0 Treffer |

**Schlussfolgerung:** Der Init-Code lädt die Tabellenadresse indirekt:
```arm
LDR R0, [PC, #literal_pool_offset]  ; lädt SRAM-Basisadresse
ADD R0, R0, #0x2F8                  ; berechnet Tabellenadresse
; → weder MOVW #0x02F8 noch MOVT #0x2000 erscheint im Code
```
