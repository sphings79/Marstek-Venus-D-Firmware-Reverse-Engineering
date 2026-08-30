# BLE-Leistungswerte gegen Modbus — Lasttest und Firmware-Beleg

**Datum:** 22. August 2026
**Anlass:** Die VenusControl-App zeigt Leistungswerte, die im Modbus-Registersatz nicht
auffindbar waren. Zusätzlich stand die Frage offen, ob `bat_sample_power` (30001) korrekt
skaliert ist — im Leerlauf wich es um Faktor 2 von der App ab.
**Eingang:** Zwei vollständige Register-Scans (`--tiers ok,verm,unb`, je 540 von 582
Registern) im Leerlauf und unter 600 W Entladelast, dazu zwei App-Screenshots derselben
Betriebszustände. Parallelbetrieb mit der HA-Integration, störungsfrei.
**Ergebnis:** Alle App-Werte sind erklärt. Zwei davon rechnet die **Firmware** im
BLE-Payload aus, nicht die App. `bat_sample_power` ist korrekt.

---

## 1. Messpunkte

| | Leerlauf (Bypass) | 600 W Entladung |
|---|---|---|
| Uhrzeit App | 00:37 | 01:01 |
| Scan | 00:53–00:55 | 01:01–01:03 |
| `30001` bat_sample_power | −34 | **−648** |
| `30006` grid_sample_power | 0 | **601** |
| `30007` / `32302` off_grid_power | 48 | 50 |
| `35100` inv_state | 6 (Bypass) | 3 (Discharge) |

App-Anzeige derselben Zustände:

| App-Feld | Leerlauf | 600 W |
|---|---|---|
| AC Power | 0 W | 601 W |
| Backup Load | 48 W | 49 W |
| Battery Power | −16 W | −651 W |
| Grid Power | −48 W | 552 W |

## 2. Zuordnung App → Modbus

Der BLE-Payload wird in `FUN_0800b024` (`0x0800b024`, 1104 Byte) zusammengebaut.
Puffer: `0x20018857`. Quellen: `0x20014E9C` (Inverter-Telemetrie), `0x20014F4C`
(MPPT-Array), `0x20014F8E` (BMS-CAN-Aggregat), `0x20014D98` (Energiezähler).

| BLE-Offset | App-Feld | Firmware | Modbus |
|---|---|---|---|
| `0x00` | Backup Load | Telemetrie `+0x1A` `off_grid_power` | **30007 / 32302** |
| `0x02` | AC Power | Telemetrie `+0x18` `grid_sample_power` | **30006 / 32202 / 37004** |
| `0x8C` | Battery Power | berechnet, s. §4 | **kein Register** |
| `0x90` | Grid Power | berechnet, s. §3 | **kein Register** |

Die ersten beiden sind direkte Kopien und decken sich exakt mit den Messwerten
(601 = 601, 49/50 = 50). **HAs `AC-Leistung` entspricht der App-Zeile „AC Power", nicht
„Grid Power".** Diese Verwechslung war der Anlass der ganzen Untersuchung.

## 3. `Grid Power` (BLE `0x90`) — Formel entschlüsselt

Aus `FUN_0800b024`, Zeilen 20–31 und 180:

```c
if (telemetrie[+0x18] /* grid_sample_power */ == 0) {
    if (telemetrie[+0x00] /* inv_state */ == 4)   // 4 = Backup Mode
        s10 = telemetrie[+0x1A];                  // off_grid_power
    else
        s10 = 0;
} else {
    s10 = telemetrie[+0x18];                      // grid_sample_power
}
s1 = telemetrie[+0x1A];                           // off_grid_power

payload[0x90] = s10 - s1;      // Grid Power
payload[0x92] = s10;
```

Gegenprobe an beiden Messpunkten:

| | s10 | s1 | s10 − s1 | App |
|---|---|---|---|---|
| 600 W (`grid_sample_power` = 601) | 601 | 49 | **552** | 552 |
| Leerlauf (`= 0`, inv_state 6 ≠ 4) | 0 | 48 | **−48** | −48 |

Beide exakt. `Grid Power` ist damit **kein eigener Messwert**, sondern eine
Firmware-Rechnung aus zwei Registern, die Modbus bereits liefert. Der Sonderfall
`inv_state == 4` behandelt den Backup-Modus.

**Praktische Folge:** Ein Nulleinspeisungsregler braucht dafür kein fehlendes Register.
`30006 − 30007` reproduziert den Wert, mit der Fallunterscheidung aus §3 für den
Backup-Modus.

## 4. `Battery Power` (BLE `0x8C`) — ist ein Produkt, kein Messwert

Aus `FUN_0800b024`, Zeilen 168–178:

```c
u11 = uint(bms[+0x00]) * 0.01;        // BMS-Spannung   -> Modbus 32100
u12 = int16(bms[+0x02]) * 0.1;        // BMS-Strom      -> Modbus 32101
payload[0x8C] = int(u12 * u11);       // Battery Power
```

`bms` = `0x20014F8E`, das CAN-Aggregat aus PGN 1801.

Damit ist die Leerlaufabweichung erklärt: die App zeigt **Spannung × Strom aus dem
BMS-Aggregat**, Modbus `30001` dagegen den **eigenen Leistungsmesswert des
Wechselrichters** (`bat_sample_power`, Telemetrie `+0x1C`). Zwei unabhängige
Herleitungen. Unter Last decken sie sich auf 0,5 % (−651 gegen −648); im Leerlauf
dominiert der Unterschied, welche Strom-/Spannungspaarung benutzt wird (−16 gegen −34).

**`bat_sample_power` (30001) ist korrekt skaliert.** Ein Faktor 2 hätte sich bei −648 W
nicht verstecken können.

### Offene Frage zu 32101

Die Rückrechnung ergibt für den 600-W-Punkt: −651 W / 53,37 V = −12,2 A, also müsste
`bms[+0x02]` zu diesem Zeitpunkt **−122** enthalten haben (i16 × 0,1 A). Genau diesen
Wert las gleichzeitig `34301` (Pack-4-Strom).

Der Modbus-Scan von `32101` lieferte dagegen 39309 (i16 −26227). Entweder ist der
`source_ptr` von 32101 fehlzugeordnet, oder zwischen SRAM-Feld und Modbus-Ausgabe liegt
eine Umrechnung, die noch nicht verstanden ist. Der `fw_scale` `/10` des Descriptors
erklärt es nicht — dividiert man 39309 durch 10, bleibt kein plausibler Strom.

Das ist der aussichtsreichste offene Punkt: Der Firmware-Pfad in `FUN_0800b024` benennt
Einheit (0,1 A) und Vorzeichenbehandlung (i16) eindeutig.

## 5. Der Venus D entlädt immer nur ein Pack

`bms_active_pack_index` (32111) stand in beiden Scans auf **4**. Im Vergleich beider
Durchläufe bewegte sich genau ein Pack:

```
Pack   Strom (34x01)      Spannung (34x00)     Zellspannungen
 1        0 ->    0        5338 -> 5338         ±1
 2        0 ->    0        5328 -> 5328         ±1
 3        0 ->    0        5332 -> 5332         ±1
 4       -3 -> -122        5250 -> 5195         -34 mV
 5        0 ->    0        5334 -> 5333         ±1
 6        0 ->    0        5334 -> 5334         ±1
```

−122 bei Anzeigefaktor 0,1 A = −12,2 A, deckungsgleich mit −648 W bei 51,95 V.

**Konsequenz für die Registerdeutung:** Eine `0` in einem Pack-Stromregister bedeutet
„Pack inaktiv", **nicht** „Register unbelegt". Eine frühere Notiz zu `30101` / `34001`
behauptete das Gegenteil und ist korrigiert.

## 6. Weitere Beobachtungen aus dem Doppelscan

113 Register änderten sich zwischen Leerlauf und Last. Auffällig:

| Register | Leerlauf → Last | Deutung |
|---|---|---|
| `30028` inv_bat_voltage | 526 → 519 | 52,6 → 51,9 V — Spannungseinbruch unter 12 A |
| `30000`/`34000` bat_volt | 523 → 516 bzw. 5338 → 5338 | die Inverter-Messung sackt, die BMS-Klemmenmessung nicht — Differenz ist Übergangswiderstand |
| `32203` grid_sample_power_w2 | 0 → 601 | bestätigt 32202/32203 als vorzeichenerweiterte 32-Bit-Fassung |
| `32101` bms_battery_current | 39321 → 39309 | Δ −12 bei Δ −11,6 A ⇒ rund 1 A je Zählschritt |
| `42021` | 0 → 600 | Entlade-Sollwert, Rücklesewert des Schreibregisters |
| `32102`/`32103` bat_sample_power | 0 → 0 | **bleibt tot**, obwohl derselbe Zeiger wie 30001 — Descriptor-Widerspruch wie bei 32202 |

## 7. Methodik-Hinweis

Beide Scans liefen parallel zur laufenden HA-Integration über den Proxy
`192.168.1.50:1502`. Die Integration meldete durchgehend 100 % erfolgreiche Reads und
null Timeouts. Der Proxy multiplext also sauber — ein Scan während des Normalbetriebs ist
kein Risiko.

Der Doppelscan unter zwei definierten Lastzuständen hat mehr geklärt als jede
Einzelmessung: Steigungen, aktive Packs und tote Register werden erst im Delta sichtbar.
