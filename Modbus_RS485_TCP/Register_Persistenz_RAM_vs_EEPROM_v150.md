# Register-Persistenz: RAM vs. EEPROM (Control FW v150)

> **Firmware:** `VNSD-0_app_0150_0805_115146.bin` (v150) · ARM Cortex-M, FreeRTOS
> **Quelle:** Statische Analyse `Write_Handler` @ `0x08051D14` in Ghidra (ReVa)
> **Stand:** 2026-08-14
> **Adressierung:** direkt (PDU = Register-Nummer, kein Offset) · Write via **FC06/FC10**

---

## 1. Fragestellung

Bei einer Nulleinspeisungs-Regelung werden die Leistungs-Sollwerte im Sekunden-
bis Minutentakt neu geschrieben. Landet jeder dieser Writes in einem
nichtflüchtigen Speicher, wäre das ein Verschleißproblem. Diese Doku klärt für
jedes relevante Write-Register, **ob es nur SRAM anfasst oder ins EEPROM
durchschlägt**.

**Kurzantwort:**

| Register | Ziel | Persistent? | Für zyklisches Schreiben geeignet |
|---|---|---|---|
| 42010 `force_mode` | SRAM `0x20000349` | ❌ nein | ✅ ja |
| 42011 `charge_to_soc` | SRAM `0x2000034A` | ❌ nein | ✅ ja |
| **42020** Ladeleistung | SRAM `0x2000034C` | ❌ nein | ✅ ja |
| **42021** Entladeleistung | SRAM `0x2000034E` | ❌ nein | ✅ ja |
| 45008 Leistungs-Sollwert | nur CAN → Micro-MCU | ❌ nein | ✅ ja |
| **44002** `max_charge_power` | SRAM + **EEPROM `0x202`** | ✅ **ja** | ⚠️ **nein** |
| **44003** `max_discharge_power` | SRAM + **EEPROM `0x204`** | ✅ **ja** | ⚠️ **nein** |

---

## 2. 42020 / 42021 — reines SRAM

### Code-Beleg (`Write_Handler`, dekompiliert)

```c
if (param_2 == 0xa424) {                       // Register 42020
    if (param_3 == 0) {                        // Lesemodus (FC03)
        Byte_Swap_Copy(param_1, DAT_0805259c + 4, 2);
        return 0;
    }
    if ((int)param_4 < 0x9c5) {                // Wertebereich 0..2500
        *(ushort *)(DAT_0805259c + 4) = uVar2; // → SRAM 0x2000034C
        return 0;                              // KEIN EEPROM_Write
    }
    return 3;                                  // Exception 3
}
// 42021 (0xa425) analog → *(ushort *)(DAT_0805259c + 6) = SRAM 0x2000034E
```

`DAT_0805259c` = `0x20000348` (Literal-Pool). Der Block ab `0x20000348`:

| SRAM | Inhalt | Register |
|---|---|---|
| `0x20000348` | Reset-/Command-Status | 41000 |
| `0x20000349` | `force_mode` (0/1/2/3) | 42010 |
| `0x2000034A` | `charge_to_soc` (13–100) | 42011 |
| `0x2000034C` | Lade-Leistungsvorgabe (u16, W) | **42020** |
| `0x2000034E` | Entlade-Leistungsvorgabe (u16, W) | **42021** |

### Cross-Reference-Beweis

`find-cross-references` auf `0x2000034C` und `0x2000034E` liefert **je genau drei
Referenzen**, alle aus zwei Funktionen:

| Von | Typ |
|---|---|
| `Write_Handler` @ `0x08051D14` | WRITE (Modbus-Write) |
| `Write_Handler` @ `0x08051D14` | PARAM (Rücklesepfad) |
| `Remote_Power_Command_Execute` @ `0x0801EBA4` | READ |

**Kein** `EEPROM_Write`, **kein** `EEPROM_Read`, **kein** Init aus dem
Config-Block, **kein** Save-on-Shutdown und kein periodischer Config-Flush
(`Config_Save_RuntimeCounters` schreibt EEPROM `0x500`, `Config_Save_UserDataBlock`
schreibt `0x4000` — beide berühren den Block `0x20000348` nicht).

> **Folge:** Nach Reboot/Power-Cycle stehen 42010/42011/42020/42021 auf **0**
> (BSS-Initialisierung). Der Wert überlebt einen Neustart nicht.
> Ein gegenteiliger Eindruck entsteht typischerweise dadurch, dass die
> Automation (HA/Node-RED) nach dem Reconnect sofort wieder schreibt.

### Sicht der Anwendung

```c
void Remote_Power_Command_Execute(void)      // 0x0801EBA4
{
  cVar1 = *(char *)(0x20000348 + 1);          // force_mode
  if      (cVar1 == 0) Inverter_Power_Setpoint_Calc(1,  0);
  else if (cVar1 == 1) Inverter_Power_Setpoint_Calc(1, -(int)*(short *)0x2000034C);
  else if (cVar1 == 2) Inverter_Power_Setpoint_Calc(1, +(int)*(short *)0x2000034E);
  else if (cVar1 == 3) { /* charge_to_soc-Regelung gegen SOC */ }
  else                 Inverter_Power_Setpoint_Calc(1,  0);
}
```

Aufgerufen aus `WorkMode_ChangeHandler` @ `0x0803080C`.

> ### ⚠️ Korrektur der Registerbedeutung
>
> Negativer Setpoint = **Laden**, positiver = **Entladen** (bestätigt durch die
> Klemmlogik in `Inverter_Power_Setpoint_Calc`, s. §4).
> Da `force_mode == 1` (= Laden, live verifiziert) den Wert aus **42020**
> negiert einsetzt und `force_mode == 2` (= Entladen) den Wert aus **42021**
> positiv einsetzt, gilt:
>
> | Register | korrekt | falsch (Altbestand) |
> |---|---|---|
> | **42020** | `charge_power_limit` — **Laden** | ~~discharge_power_limit~~ |
> | **42021** | `discharge_power_limit` — **Entladen** | ~~charge_power_limit~~ |
>
> Der Plate-Kommentar im Ghidra-`Write_Handler` benennt 42020 fälschlich als
> „discharge_power_limit" — korrigiert am 2026-08-14.

---

## 3. 44002 / 44003 — EEPROM-persistent

### Code-Beleg

```c
// Register 44002 (0xABE2)
if ((int)param_4 < 0x9c5) {
    Inverter_Write_Reg_0x04_U32Value(1, param_4);   // CAN-Reg 0x04 → Micro-MCU
    Config_Write_U16_0x202(param_4);                // → EEPROM 0x202
    *(ushort *)0x20000156 = uVar2;                  // Schattenkopie
    return 0;
}

// Register 44003 (0xABE3)
if ((int)param_4 < 0x9c5) {
    Inverter_Write_Reg_0x03_U32Value(1, param_4);   // CAN-Reg 0x03 → Micro-MCU
    Config_Write_U16(param_4);                      // → EEPROM 0x204
    *(ushort *)0x20000158 = uVar2;                  // Schattenkopie
    return 0;
}
```

### Die Persistenz-Helfer

```c
void Config_Write_U16_0x202(uint v)          // 0x08006C64  — Register 44002
{
  if (0x9c4 < (int)v) v = 0x9c4;             // Hard-Clamp auf 2500 W
  if (*(ushort *)0x2000012D != v) {          // ← Change-Guard!
      *(short *)0x2000012D = (short)v;
      EEPROM_Write(0x202, 0x2000012D, 2);
  }
}

void Config_Write_U16(uint v)                // 0x08006D30  — Register 44003
{
  if (0x9c4 < (int)v) v = 0x9c4;
  if (*(ushort *)0x2000012F != v) {          // ← Change-Guard!
      *(short *)0x2000012F = (short)v;
      EEPROM_Write(0x204, 0x2000012F, 2);
  }
}
```

Zwei wichtige Eigenschaften:

1. **Change-Guard:** Ein Write mit dem *bereits gespeicherten* Wert löst **keinen**
   EEPROM-Zyklus aus. Nur echte Wertänderungen kosten Schreibzyklen.
2. **Hard-Clamp** auf `0x9C4` = 2500 W — zusätzlich zum Bereichscheck im
   `Write_Handler`.

### Es ist ein externes I2C-EEPROM, kein MCU-Flash

```c
int EEPROM_Write(offset, src, len)           // 0x08006BBC
{
  if (src == 0) return 1;
  if (xQueueReceive(mutex, 1000) == 0) {
      log_printf(2,3,"Failed to acquire lock during write");
      return 2;
  }
  rc = EEPROM_I2C_WriteBytes(offset, src, len);
  EEPROM_Mutex_Wait(5);
  if (rc != 0) log_printf(1,3,"eeprom write error:%d", rc);
  xQueueSend(mutex, 0, 0);
  return rc;
}
```

`EEPROM_Write` hat **54 Aufrufer** in der FW und geht ausschließlich über
`EEPROM_I2C_WriteBytes` — also ein separater I2C-EEPROM-Baustein (Bitbang-I2C-
Routinen `I2C_BitBang_*` @ `0x08002014`ff), **nicht** der interne STM32-Flash.
Typische Ausdauer eines solchen Bausteins: ~1 Mio. Zyklen je Zelle statt ~10 k
beim MCU-Flash.

> **Trotzdem: nicht zyklisch schreiben.** Es gibt kein Wear-Leveling — 44002 und
> 44003 liegen auf zwei festen Adressen. Wechselnde Werte im 5-Sekunden-Takt
> ergäben ~6 Mio. Zyklen pro Jahr auf derselben Zelle.

---

## 4. Der Config-Block `0x2000012B` (EEPROM `0x200`ff)

Die Feldbedeutungen sind **durch die FW selbst belegt** — `Battery_Config_Debug_Print`
@ `0x080357FC` gibt den Block feldweise mit Klartext-Formatstrings aus:

```c
void Battery_Config_Debug_Print(void)
{
  printf("charge_cutoff_soc  : %d",    *(byte   *)(base + 0));
  printf("discharge_cutoff_soc: %d",   *(byte   *)(base + 1));
  printf("max_charge_power   : %d",    *(ushort *)(base + 2));
  printf("max_discharge_power: %d",    *(ushort *)(base + 4));
  printf("grid_standand      : %d",    *(byte   *)(base + 6));   // [sic]
}
```

| SRAM-Offset | Feld (FW-String) | EEPROM | Modbus-Register | Schreib-Helfer |
|---|---|---|---|---|
| `0x2000012B` +0 | `charge_cutoff_soc` | `0x200` | — | — |
| `0x2000012C` +1 | `discharge_cutoff_soc` | `0x201` | — | `Config_Write_DischargeCutoffSOC` |
| `0x2000012D` +2 | **`max_charge_power`** | `0x202` | **44002** | `Config_Write_U16_0x202` |
| `0x2000012F` +4 | **`max_discharge_power`** | `0x204` | **44003** | `Config_Write_U16` |
| `0x20000131` +6 | `grid_standand` (Netznorm) | `0x206` | — | — |

### Verwendung als Klemmgrenze

`Inverter_Power_Setpoint_Calc` @ `0x08006168` klemmt den finalen Sollwert genau
gegen diese beiden Werte:

```c
  if ((int)*(ushort *)(0x2000012B + 4) < (int)setpoint)      // Obergrenze
      setpoint =  (uint)*(ushort *)(0x2000012B + 4);         // = max_discharge_power (positiv)

  if (setpoint <= -(uint)*(ushort *)(0x2000012B + 2))        // Untergrenze
      setpoint = -(uint)*(ushort *)(0x2000012B + 2);         // = max_charge_power (negativ)
```

Positiver Ast → Offset +4 → 44003 → **Entladen**.
Negativer Ast → Offset +2 → 44002 → **Laden**.

> ### ⚠️ Zweite Korrektur im Ghidra-Plate-Kommentar
>
> Der `Write_Handler`-Header behauptete „REG 44002: discharge_power_max /
> REG 44003: charge_power_max". Das ist **vertauscht**. Belegt durch die
> FW-eigenen Debug-Strings *und* die Klemmrichtung:
> **44002 = max. Ladeleistung, 44003 = max. Entladeleistung.**
> Die bestehende Registerkarte (`44002 max_charge_power`, `44003 max_discharge_power`)
> war also korrekt. Ghidra-Kommentar korrigiert am 2026-08-14.

### Weitere Schreiber desselben Blocks

| Funktion | Was |
|---|---|
| `MQTT_Config_Command_Handler` @ `0x08014278` | Cloud/App setzt `0x2000012D` und `0x2000012F` |
| `Grid_Export_Power_Limiter` @ `0x0801F200` | liest `+4` |
| `WorkMode_State_Machine` @ `0x0802D360` | liest `+4` (4×) |
| `Battery_Forced_Charge_Check` @ `0x080052B0` | liest `+4` |
| `CT_PowerSetpoint_Compute` @ `0x0802C8C4` | liest `+2` und `+4` |
| `MQTT_Telemetry_Struct_Builder` @ `0x0801275C` | liest beide (Telemetrie) |
| `Config_Write_PowerOffset` @ `0x08006EE0` | liest beide |

> Praktische Konsequenz: Eine Änderung von 44002/44003 über Modbus ist
> **äquivalent zur Einstellung in der App/Cloud** — beide landen im selben
> Config-Slot. Die App kann den Wert also jederzeit wieder überschreiben.

---

## 5. 45008 — CAN-Sollwert, ebenfalls flüchtig

Der Vollständigkeit halber, weil 45008 gelegentlich als Alternative zu 42020/42021
benutzt wird:

```c
void Config_PowerSetpoint_Write(int v)       // 0x08005E3A
{
  local = v;
  id = CAN_Build_Arbitration_ID(0x56, 1, 4, 0);
  Register_WriteValue(id, &local, 4);        // reiner CAN-Write, kein EEPROM
}
```

45008 setzt also nur den Live-Sollwert im Wechselrichter-MCU (CAN-Reg `0x56`).
Aus Sicht der Control-MCU **keine Persistenz**. (Ob die Micro-MCU den Wert
ihrerseits ablegt, ist in dieser Analyse nicht untersucht.)

---

## 6. Empfehlung für Nulleinspeisung / HA-Integration

```python
# Sicher im Sekundentakt schreibbar (reines SRAM):
client.write_register(42000, 0x55AA)   # RS485-Steuerung freischalten (einmalig)
client.write_register(42010, 1)        # 1 = Laden, 2 = Entladen, 0 = aus
client.write_register(42020, 1500)     # Ladeleistung  in W  (0..2500)
client.write_register(42021, 800)      # Entladeleistung in W (0..2500)

# NICHT zyklisch schreiben — jeder geänderte Wert = ein EEPROM-Zyklus:
# client.write_register(44002, 2500)   # max. Ladeleistung
# client.write_register(44003, 2500)   # max. Entladeleistung
```

Empfehlung für eine Integration: 44002/44003 als **Konfigurations-Entity**
(z. B. `number` mit `mode: box`) modellieren und vor dem Write auf Gleichheit
mit dem zuletzt gelesenen Wert prüfen — die FW hat zwar einen Change-Guard,
aber ein eigener Guard spart zusätzlich den Modbus-Roundtrip.
42010/42020/42021 dagegen dürfen bedenkenlos als Regelgrößen dienen.

> **Achtung:** Nach jedem Reboot des Geräts sind 42010/42020/42021 auf 0. Eine
> Nulleinspeisungs-Automation muss den Zustand nach Reconnect neu setzen und
> darf sich nicht auf gespeicherte Werte verlassen. Auch das
> RS485-Unlock (42000 = `0x55AA`) ist nach Reboot erneut nötig.

---

## 6a. Was 42000 wirklich ist — und was passiert, wenn es zurückfällt

*(2026-08-25, Write_Handler v150 Zeilen 341–380 plus Messung am Gerät.)*

`Write_Handler_Register_Map.csv` vermerkt bereits „teilt SRAM-Byte mit Reg 43000".
Der dekompilierte Code zeigt, was das bedeutet — beide Register schreiben
dieselbe Variable `DAT_080525c4[1]`:

```c
// 42000
if (param_4 == 0x55aa) { DAT_080525c4[1] = 0x0A; return 0; }        // "Unlock"
if (param_4 == 0x55bb) { EEPROM_Read(0x301, DAT_080525c4+1, 1); }   // aus EEPROM zurück

// 43000 — dieselbe Variable
if (read) { byte==0x01 ? 0 : byte==0x02 ? 2 : 1 }
if (param_4 == 0) byte = 0x01;   // Eigenverbrauch
if (param_4 == 1) byte = 0x00;   // Anti-Einspeisung
if (param_4 == 2) byte = 0x05;   // Handel
EEPROM_Write(0x301, ...);
```

Es gibt also **keinen eigenen RS485-Steuermodus**. Es gibt ein Modus-Byte, das
entweder auf `0x0A` steht — dann liest 42000 `0x55AA` — oder auf einem normalen
Betriebsmodus. Keine der drei Optionen von 43000 schreibt `0x0A`.

**Gemessene Wirkung (Venus D, 2026-08-24):** bei laufender erzwungener Entladung
mit 605 W das Byte von `0x0A` weggeschaltet → Entladung fällt auf **12 W**
(Eigenverbrauch des Wechselrichters). `force_mode` (42010) wird also nur
befolgt, solange das Byte `0x0A` ist.

**Der Write-Handler prüft das Byte dabei nicht.** Die Zweige für 42011 (`0xA41B`)
und 42020 (`0xA424`) validieren ausschließlich den Wertebereich und schreiben
dann. Schreibbefehle werden also weiter bestätigt, während die Regelung sie
ignoriert — der Ausfall ist von außen unsichtbar.

**Praktische Folge für Integrationen:** wer 43000 umstellt, beendet damit die
RS485-Steuerung; wer 42000 auf `0x55AA` setzt, nimmt das Gerät aus dem
eingestellten Betriebsmodus (43000 liest danach `1`, weil `0x0A` in den
else-Zweig des Lesehandlers fällt). Zwei Bedienelemente, ein Zustand.

**Offen:** warum das Byte im Feld von selbst auf den EEPROM-Wert zurückfällt.
Beobachtet auf Venus E v3 (dreimal, jeweils zusammen mit einer
Kommunikationsstörung) und auf Venus D (einmal, rund eine Minute nach einem
Neustart des Modbus-Clients). Der CH395-Reset aus §4a der v150-Control-Analyse
ist es nicht — der trifft nur die Netzwerkseite.

---

## 7. Reproduktion

```
get-decompilation  programPath=/VNSD-0_app_0150_0805_115146.bin
                   functionNameOrAddress=Write_Handler          # 0x08051D14, 968 Zeilen

find-cross-references  location=0x2000034c  direction=to        # 42020 → nur Write_Handler + Reader
find-cross-references  location=0x2000034e  direction=to        # 42021 → dito
find-cross-references  location=0x2000012d  direction=to        # 44002 → 13 Refs, EEPROM-Pfad
find-cross-references  location=0x2000012f  direction=to        # 44003 → 20 Refs, EEPROM-Pfad

get-decompilation  functionNameOrAddress=Config_Write_U16_0x202 # EEPROM 0x202 + Change-Guard
get-decompilation  functionNameOrAddress=Config_Write_U16       # EEPROM 0x204 + Change-Guard
get-decompilation  functionNameOrAddress=EEPROM_Write           # → EEPROM_I2C_WriteBytes
get-decompilation  functionNameOrAddress=Battery_Config_Debug_Print   # Feldnamen im Klartext
get-decompilation  functionNameOrAddress=Inverter_Power_Setpoint_Calc # Klemmrichtung
get-decompilation  functionNameOrAddress=Remote_Power_Command_Execute # Vorzeichenkonvention
```

Literal-Pool-Auflösung (Little-Endian, `read-memory`):

```
0x0805259C → 48 03 00 20  →  0x20000348   (Block 41000/42010/42011/42020/42021)
0x080529BC → 56 01 00 20  →  0x20000156   (Schattenkopie 44002/44003)
0x08006C94 → 2B 01 00 20  →  0x2000012B   (Config-Block, EEPROM 0x200ff)
0x08006D60 → 2B 01 00 20  →  0x2000012B   (dito)
0x080063D8 → 2B 01 00 20  →  0x2000012B   (Klemmgrenzen in Setpoint_Calc)
```

---

## 8. Offene Punkte

1. **Micro-MCU-Seite von 45008 / CAN-Reg `0x56`** nicht untersucht — legt die
   Wechselrichter-Firmware den Sollwert selbst nichtflüchtig ab?
2. **Live-Verifikation:** Gerät auf 42020 = 1234 setzen, Power-Cycle, 42020
   zurücklesen → erwartet **0**. Steht dort 1234, gibt es einen bisher nicht
   gefundenen Persistenzpfad.
3. **EEPROM-Gesamtkarte:** Die Offsets `0x200`–`0x206` sind hiermit belegt.
   Eine vollständige EEPROM-Map (inkl. `0x300`/`0x301`, `0x374`, `0x387`,
   `0x394`, `0x3700`ff, `0x500`, `0x2000`ff, `0x4000`) fehlt noch.
4. **Register 43513 / 41600ff** (Zeitplan-Leistungen) auf Persistenz prüfen —
   im `Write_Handler` sind das SRAM-Arrays ab `0x200025C8`, aber der
   Schedule-Block `0x3700`ff wird andernorts per `EEPROM_Write` persistiert.

---

## Nachtrag 2026-08-22: Backup-Reserve / Entladetiefe — kein Modbus-Zugang

Die App-Einstellung **„Batterieentladetiefe (DOD)"** (Screenshot: „30 % entladene
Energie / 70 % Backup-Kapazität", Einstellbereich 30–88 %) ist über Modbus weder
lesbar noch schreibbar. Vollständige Kette:

| Ort | Inhalt |
|---|---|
| SRAM `0x2000012C` | Backup-Reserve in Prozent (im Screenshot: 70) |
| EEPROM `0x201` | persistente Ablage, 1 Byte |
| Anzeige App/BLE | `100 − Reserve` = Entladetiefe |

**Setter** `Config_Write_DischargeCutoffSOC` @ `0x08006d64`:

```c
if ((param_1 == 0) || (0x1d < param_1 && param_1 < 0x59)) {   // 0 oder 30..88
    cVar2 = (param_1 == 0) ? 12 : ('d' - param_1);            // 100 - Eingabe
    *(char *)0x2000012C = cVar2;
    EEPROM_Write(0x201, ..., 1);
    return 0;
}
return 1;                                                      // Wert abgelehnt
```

Der akzeptierte Bereich 30–88 deckt sich exakt mit dem Hinweistext der App.
Eingabe 0 setzt den Standard 12 (= 88 % Entladetiefe).

**Erreichbar über genau drei Pfade** (`Config_Set_DischargeCutoff_WithRelay`
@ `0x0802dce4`, Cross-Reference-Lauf über `0x2000012C`):

| Aufrufer | Weg |
|---|---|
| `MQTT_JSON_RPC_Dispatcher` @ `0x0801ab6c` | Cloud |
| `FUN_08002538` | BLE-Kommando (`DEPTH_OF_DISCHARGE_CONTROL` `0x54`) |
| `FUN_08007674` | Textkonsole, `atoi` über eine Queue |

**Kein `Write_Handler`** — und damit kein Modbus-Register, auch keines der noch
unbenannten. Die Write-Handler-Map (172 Register) enthält keinen einzigen
SRAM-Zielwert im Konfigblock `0x2000012B..0x20000131`.

Zusätzlich validiert die Boot-Routine `FUN_08004b5c` denselben Block:

```
+0  Prozentwert       0 oder >100          -> 100
+1  Backup-Reserve    0, >70, <12          -> 12
+2  Ladeleistung      0 oder >2500         -> 2500
+4  Entladeleistung   0 oder >2500         -> 800
```

Die Klemmung 12..70 auf `+1` erklärt den App-Bereich 30–88 als `100 − Reserve`.

### Abgrenzung zu Register 42011

42011 (`charge_to_soc`, „Maximaler SoC" in der HA-Integration) ist **nicht** dieser
Parameter. Am Gerät verifiziert: Setzen auf 70 löst sofort eine Entladung aus, die
bei SoC 70 stoppt — eine Zielgrenze, kein Entladeboden. Wertebereich 13–100,
flüchtiges SRAM, nach Neustart 0. Die beiden nicht verwechseln.

