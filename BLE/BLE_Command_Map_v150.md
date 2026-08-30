# BLE-Command-Map — Marstek Venus (Control FW v150)

> **Quelle:** `BLE_Cmd_Dispatch` @0x08007F20 (v150), sauber dekompiliert.
> Der Bereich war in Ghidra nicht als Funktion erschlossen → per `create-function`
> definiert, danach löst der Decompiler den Switch auf. **Command-ID = Byte[3]** des Pakets.
> **Stand:** 2026-08-14

## Paketformat

```
73 | LEN | 23 | CMD | payload… | XOR
```
- `73` Magic, `LEN` Gesamtlänge, `23` fix, `CMD` = Command-ID (Byte[3]), `XOR` = XOR über alle vorherigen Bytes.
- Payload beginnt bei Byte[4]. Im Tool = die Bytes, die die `*Payload`-Klasse serialisiert.
- Mehrbyte-Zahlen sind **little-endian**, außer wo anders vermerkt.

## Legende

**Tool:** ✓ = in venuscontrol vorhanden, ❌ = fehlt.

**Greift?** — wirkt der geschriebene Wert tatsächlich im Betrieb? (Methode: Cross-Reference auf die *Live-SRAM-Config-Variable*, nicht nur auf den Handler. Liest nur der eigene Handler + ein Telemetrie-Builder → „set-and-report". Liest eine Task/Regel-Funktion → funktional.)
- ✓ = **greift** — Wert wird im Regel-/Steuer-Pfad genutzt (code-verifiziert)
- ⚠ = **greift nicht** — set-and-report-only (nur eigener Handler + Telemetrie lesen den Wert)
- 📖 = Lesebefehl (liefert Daten zurück)
- ? = nicht verifiziert

## Vollständige Command-Tabelle (v150)

| CMD | Feature | Payload (ab Byte[4]) | Greift? | Tool |
|---|---|---|---|---|
| 0x02 | Set server type (Cloud-Server 0–4) | u8 | ? | ❌ |
| 0x03 | Get work status info (STATE) | – (read) | 📖 | ✓ |
| 0x04 | Device info | – (read) | 📖 | ✓ |
| 0x05 | Info-Block (resp 0x20) | – | 📖 | ❌ |
| 0x06 | Factory reset | u8 (1/2/3) | ✓ | ✓ |
| 0x08 | Read wifi name | – (read) | 📖 | ❌ |
| 0x09 | Set work mode / economy | u8 mode (+Slot-Daten bei mode=1, economy bei =5) | ✓ | ✓ |
| 0x0A | Get set info | – (read) | 📖 | ✓ |
| 0x0B | **Sys time set (RTC)** | year(u16 BE, -2000), mon,day,hour,min,sec | ✓ | ✓ |
| 0x0C | Set develop mode | magic 0A 0B 0C + u8 (0..6) | ? | ❌ |
| 0x0D | Develop mode info | – (read) | 📖 | ❌ |
| 0x0E | Set work mode auto change | u8 (EEPROM 0x366) | ⚠ | ❌ |
| 0x0F | Set EPS/backup enable | u8 (0/1, EEPROM 0x300) | ✓ | ✓ |
| 0x10 | OTA start | magic + u8 | ✓ | (OTA) |
| 0x11 | Query modem version (AT+QVERSION) | magic | 📖 | ❌ |
| 0x12 | EEPROM clear | magic | ✓ | ❌ |
| 0x13 | Get err code info | – (read) | 📖 | ❌ |
| 0x14 | Get bms data info | – (read) | 📖 | (0x42 im Tool) |
| 0x15 | **Geräte-Leistungsklasse 800/2200/2500** (Config_Write_U16, EEPROM 0x90/0x204, klemmt Zeitpläne bei 800) | u16 ∈ {800, 2200, 2500} | ✓ | ✓ |
| 0x16 | **Max charge power** (EEPROM 0x202, 300–2500 W) | u16 W | ✓ | ✓ |
| 0x17 | **Max discharge power** (EEPROM 0x204, 0–2500 W) | u16 W | ✓ | ✓ |
| 0x18 | CT type (Meter) | u8 | ✓ | ✓ |
| 0x19 | CT mode | u8 (EEPROM 0x367) | ✓ | ✓ |
| 0x1A | CT readings | – (read) | 📖 | ✓ |
| 0x1B | Set url port / OTA-URL | subcmd + Daten | ? | ❌ |
| 0x1C | Get event log info | – (read) | 📖 | ❌ |
| 0x1D | Phase autodetection | – | ✓ | ✓ |
| 0x1E | Config U8 | u8 | ? | ❌ |
| 0x1F | Info active upgrade | magic | 📖 | ❌ |
| 0x20 | **Set parallel machine** | magic + u8 (0/1/2) | ✓ | ❌ |
| 0x21 | **Set/Read meter IP** | 0x0A=set+string / 0x0B=read (EEPROM 0x3500) | ⚠ | ❌ |
| 0x22 | Config Byte 0x36b | u8 | ? | ❌ |
| 0x23 | **Set generator enable/disable** | u8 (0/1) | ⚠ | ❌ |
| 0x24 | VID read | subcmd | 📖 | ❌ |
| 0x25 | Config U16 0x36e | u16 (BE) | ? | ❌ |
| 0x26 | Config capacity factor | u8 | ? | ❌ |
| 0x27 | Power-Daten-Batch | u8 count | 📖 | ❌ |
| 0x28 | **Set local API enable + port** (Local API = UDP JSON-RPC, **NICHT** Modbus TCP; EEPROM 0x371/0x372) | u8 enable + u16 port | ✓ | ✓ |
| 0x29 | **PEAK SHAVING** | u8 peak_state + int16 power(W) | ✓ | ✓ |
| 0x40 | Config-Reg Offset3 | u8 | ? | ❌ |
| 0x41 | Surplus feed-in (Überschuss) | u8 (0/1, EEPROM 0x375) | ✓ | ✓ |
| 0x42 | Battery modules state | u8=1 (read) | 📖 | ✓ |
| 0x43 | Apply work-mode reg | 0x01 + u8 | ? | ❌ |
| 0x50 | Write vid/xid info | subcmd + string | ✓ | ❌ |
| 0x51 | Read vid/xid info | subcmd | 📖 | ❌ |
| 0x52 | OTA-Kommandos | sub-typed (0x0A–0x0D) | ✓ | (OTA) |
| 0x53 | Set BLE adv enable | 0x0A/0x0B + u8 (EEPROM 0x36bd) | ✓ | ✓ |
| 0x54 | Depth of Discharge | (FUN_08002538) | ✓ | ✓ |
| 0x55 | **Set self-control power offset** | int16 (EEPROM 0x383) | ✓ | ✓ |
| 0x59 | LED control | u8 (1=OPEN/0=Close) | ✓ | ✓ |
| 0x5A | Enable-Flag | u8 (=1) | ? | ❌ |
| 0x5B | Config read/apply | 0x01 → resp 0x3a | 📖 | ❌ |

## „Greift nicht" — set-and-report-only Befehle (Details)

Diese Befehle **speichern** den Wert (und melden ihn in der Telemetrie/App zurück), aber **keine Regel- oder Task-Funktion liest ihn** — im v150-Betrieb ohne Wirkung. Deshalb im Tool bewusst **nicht** exponiert:

| CMD | Feature | Warum ohne Wirkung |
|---|---|---|
| 0x0E | Work-mode auto change | Live-Var `0x20014D66` wird nur vom eigenen Handler + Telemetrie gelesen. |
| 0x21 | Meter-IP setzen | Var (EEPROM 0x3500) nur vom eigenen Handler berührt; die Verbindungs-IP wird zur Laufzeit **auto-discovered** — deckt sich damit, dass die Meter-IP auch in der App nicht setzbar ist. |
| 0x23 | Generator enable/disable | Live-Var `0x20014D6C` nur Telemetrie-Reader (kein Lade-/Entlade-Pfad wertet das Generator-Flag aus). |

## Verifikationsnachweise für die „greift"-Wertung (Auswahl)

- **0x55 Self-Control Offset →** `CT_GridPower_Controller @0x0802c680` liest `0x20014D83`:
  `local_10 = grid_power - *(short*)(config+0x83)` → der Regler regelt `grid_power → offset` statt auf 0 W. Aufrufer: `WorkMode_ChangeHandler`, `TimePlan_Evaluate_Setpoint`. **Funktional.**
- **0x28 Local API →** Live-Var `0x20014D71/72` wird von der UDP-Server-Task (`CH395_UDP_ServerTask` / `Quectel_UDP_CommStateMachine`) gelesen → schaltet den lokalen JSON-RPC-Server real. **Funktional.**
- **0x29 Peak Shaving →** `Config_Write_PowerClampMode_0x394` (EEPROM 0x394) → `Inverter_PowerSetpoint_DeadbandClamp` klemmt die Leistung auf die Schwelle. **Funktional.**
- **0x0B Zeit →** direkter `RTC_SetDateTime`-Aufruf. **Funktional.**
- **0x15/0x16/0x17 Leistungsgrenzen →** gehen in die Setpoint-/Zeitplan-Klemmung ein. **Funktional.**

## Peak Shaving (0x29) — Detail

```c
case 0x29:
  peak_state = byte[4];               // 1 = ein, 0 = aus
  peak_power = int16_LE(byte[5..6]);  // Leistung in W (Peak-Schwelle)
  Config_Write_PowerClampMode_0x394(peak_state, peak_power);  // EEPROM 0x394
  // Wirkung: Inverter_PowerSetpoint_DeadbandClamp klemmt Einspeise-/Entladeleistung auf die Schwelle
```

Beispiel-Frame „Peak Shaving ein, 600 W":
`73 08 23 29 01 58 02 <XOR>`  (600 = 0x0258 → LE: 58 02)

## Self-Control Power Offset (0x55) — Detail

```c
case 0x55:
  Config_Write_PowerOffset((int)int16_LE(byte[4..5]));   // clamp gg. Lade-/Entlade-Max, EEPROM 0x383
  // Wirkung: CT_GridPower_Controller rechnet  regel_fehler = netzleistung - offset
  //          → self-consumption regelt auf 'offset' W Netzbezug statt 0 W
```

## Umsetzungsstand im Tool (venuscontrol)

**Neu integriert & code-verifiziert (alle „greift"):**
- 0x29 Peak Shaving · 0x15 Geräte-Leistungsklasse · 0x17 Max discharge power (Bugfix: war fälschlich als 0x15 gemappt) · 0x28 Local API · 0x0B Zeit setzen · 0x55 Self-Control Offset

**Bewusst nicht integriert (greifen nicht, s. o.):** 0x0E Auto-Moduswechsel · 0x21 Meter-IP · 0x23 Generator

**Noch offen / niedrige Prio:** 0x20 Parallelbetrieb (greift, aber Nischen-Setup), diverse Dev-/Config-Befehle (0x0C, 0x1B, 0x1E, 0x22, 0x25, 0x26, 0x40, 0x43, 0x5A) — unverifiziert.
