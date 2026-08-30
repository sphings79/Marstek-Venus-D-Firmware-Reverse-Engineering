# Geräte-Leistungsklasse „Netzleistung" 800 / 2200 / 2500 W (Control FW v150)

> **Firmware:** `VNSD-0_app_0150_0805_115146.bin` (v150)
> **Quelle:** `MQTT_JSON_RPC_Dispatcher` @0x0801ab6c (Case 0x10) + `Config_Write_U16` @0x08006d30
> **Stand:** 2026-08-14

---

## 1. Was es ist

Der App-Selektor „Netzleistung / Geräte-Leistung" ist **kein freier 0–2500-W-Regler**,
sondern eine **Geräte-Leistungsklasse** mit genau drei erlaubten Stufen: **800 / 2200 / 2500 W**.
Er wirkt auf die **Entlade-/Einspeiseseite** (deutscher 800-W-Einspeisedeckel) und wird über
die **Cloud (MQTT/JSON-RPC)** gesetzt — nicht über ein dediziertes Modbus-Register.

## 2. Der Befehl (Cloud / MQTT, Case 0x10)

JSON-RPC-Kommando mit Feld `version`. Nur drei Werte gültig, sonst Fehler `0x1AA`:

| `version` | hex | Tier-Flag → EEPROM 0x90 | Leistungswert → EEPROM 0x204 | Zusatzaktion |
|---|---|---|---|---|
| 800 | 0x320 | `1` | 800 | **`Config_ScheduleEntries_ClampPower800W()`** — klemmt alle Zeitplan-Slot-Leistungen auf 800 W |
| 2200 | 0x898 | `3` | 2200 | — |
| 2500 | 0x9C4 | `0` | 2500 | — |

Ablauf je Stufe (dekompiliert):

```c
case 0x10:                                  // "set device power class"
  version = json["version"];
  if (version == 800)  { flag=1; Config_Write_U16(800);   EEPROM_Write(0x90,flag,1);
                         Config_ScheduleEntries_ClampPower800W(); }
  else if (version==0x898){flag=3; Config_Write_U16(0x898); EEPROM_Write(0x90,flag,1); }
  else if (version==0x9c4){flag=0; Config_Write_U16(0x9c4); EEPROM_Write(0x90,flag,1); }
  else  -> Error 0x1AA;
```

`Config_Write_U16(v)` (@0x08006d30): klemmt `v` auf max. 2500, schreibt bei Änderung
**EEPROM 0x204** (2 Byte) und in das SRAM-Config-Struct (+4).

## 3. Zwei persistierte Größen

| Was | Ort | Bedeutung |
|---|---|---|
| Leistungswert (800/2200/2500) | **EEPROM 0x204** | = Backend von Modbus-Register **44003** (Entlade-/Einspeise-Max) |
| Klassen-/Tier-Flag (1/3/0) | **EEPROM 0x90** | „gewählte Klasse", die die App zurückliest |

## 4. Nachbildung über Modbus (Home Assistant)

Der exakte Cloud-Befehl ist **nicht** als Modbus-Register verfügbar. Die Wirkung lässt
sich aber praktisch nachbilden:

1. RS485 entsperren: `42000 = 0x55AA` (FC06)
2. Einspeise-/Entlade-Max setzen: **`44003 = 800 | 2200 | 2500`** (FC06)
   - trifft dasselbe EEPROM 0x204 und pusht den Wert sofort per **CAN-Reg 0x03** an den Wechselrichter
   - (Lade-Gegenstück: `44002` → CAN-Reg 0x04, EEPROM 0x202)

**Was ein Modbus-Write auf 44003 NICHT mitmacht:**

- Das Klassen-Flag in **EEPROM 0x90** wird nicht gesetzt (App zeigt die Klasse ggf. unverändert an).
- Die Zeitplan-Slots werden **nicht** automatisch auf 800 W geklemmt. Bei Bedarf die Slot-
  Leistungen (43103/43108/43113/43118/43123/43128 bzw. das 41600er-Array) selbst auf ≤800 setzen.

## 5. Richtungs-Hinweis (Laden vs. Entladen) — code-bewiesen

Diese Klasse wirkt auf die **Entladeseite** (44003 / EEPROM 0x204 / CAN-Func 0x03).
**Bewiesen (v150-Dekompilat, 2026-08-14):**

- `Config_ScheduleEntries_ClampPower800W` klemmt in jedem Zeitplan-Slot nur Werte
  `> +800` (Feld +2, signed). Da Zeitplan-Leistung signiert ist (**positiv = Entladen/
  Einspeisen, negativ = Laden**), wird ausschließlich die **Entladeseite** gedeckelt →
  der 800-W-Selektor ist eine Einspeise-/Entladegrenze.
- Derselbe App-Befehl schreibt `Config_Write_U16` → **EEPROM 0x204 = Register 44003** →
  **44003 = Entladen**, per Ausschluss **44002 = Laden**.
- Gegenprobe force_mode (`Remote_Power_Command_Execute`): `force_mode=1` (Laden) nutzt
  SRAM-Feld +4 = **Reg 42020**, `force_mode=2` (Entladen) Feld +6 = **Reg 42021**.

Damit gilt gesichert: **42020/44002 = Laden, 42021/44003 = Entladen** und
**CAN-Func 0x03 = Entladen, 0x04 = Laden**. Die frühere `Write_Handler_Register_Map.csv`
hatte beide Paare vertauscht — **am 2026-08-14 korrigiert**.

## 6. Referenzen

- `MQTT_JSON_RPC_Dispatcher` @0x0801ab6c, Case 0x10 (v150)
- `Config_Write_U16` @0x08006d30 (EEPROM 0x204), `Config_ScheduleEntries_ClampPower800W`
- `Config_Write_U16_0x202` @0x08006c64 (EEPROM 0x202 = Lade-Max / 44002)
- Modbus 44002/44003 → Inverter_Write_Reg_0x04/0x03 (CAN-Reg 0x04/0x03)
