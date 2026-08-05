# BLE ↔ Modbus Cross-Reference

Systematischer Abgleich zwischen dem BLE-Protokoll (marstek-venus-monitor) und den Modbus TCP Registern.

## Methodik

1. BLE RuntimeInfo Builder (FUN_0800af78) im Control FW dekompiliert
2. SRAM-Quell-Adressen über Literal-Pool aufgelöst (DAT_0800b380 ff.)
3. Gemeinsame SRAM-Structs zwischen BLE- und Modbus-Handler identifiziert
4. Semantische Korrelation über Feldnamen, Datentypen und Scan-Werte

### Schlüssel-Structs (SRAM v148)

| Literal Pool | SRAM-Adresse | Verwendung |
|---|---|---|
| DAT_0800b380 | 0x20014E90 | Inverter-Status-Struct (workMode, gridPower, batteryPower) |
| DAT_0800b384 | 0x20014F40 | Pack-Status-Array (SOC, Zellspannungen pro Pack) |
| DAT_0800b388 | 0x2001884A | BLE RuntimeInfo Ausgabe-Puffer (0xA4 Bytes) |
| DAT_0800b394 | 0x20014F82 | BMS-Daten-Struct |
| DAT_0800b3a0 | 0x20014CDC | Version-Info-Struct |
| DAT_0800b3a4 | 0x20014D8E | Energie-Zähler-Struct (daily/monthly/total charge/discharge) |
| DAT_0800b3a8 | 0x20014CFC | Konfigurations-Struct (73+ Felder, auch über BLE cmd 0x28 beschrieben) |
| DAT_0800b3b4 | 0x20000136 | EU Power Limit Flag |
| DAT_0800b3b8 | 0x2000012B | Power Rating Struct |

## Bestätigte Mappings

### RuntimeInfo (BLE cmd 0x03) → Modbus Read Register

| BLE Offset | BLE Feld | BLE Typ | Modbus Reg | Modbus Name | FW-Quelle |
|---|---|---|---|---|---|
| 0x00 | gridPower | i16 | 30006 | ac_power | DAT_0800b380+0x1A |
| 0x02 | batteryPower | i16 | 30001 | battery_power | DAT_0800b380+0x18 |
| 0x04 | workMode | u8 | 35100 | inverter_state | *DAT_0800b380 |
| 0x0C | deviceFwVersion | u16 | 30200 | ems_version | DAT_0800b3a0+0x16 |
| 0x0E | dailyCharge | u32/100 | 33004 | daily_charging_energy | DAT_0800b3a4+0x14 |
| 0x12 | monthlyCharge | u32/1000 | 33008 | monthly_charging_energy | DAT_0800b3a4+0x0C |
| 0x16 | dailyDischarge | u32/100 | 33006 | daily_discharging_energy | DAT_0800b3a4+0x18 |
| 0x1A | monthlyDischarge | u32/100 | 33010 | monthly_discharging_energy | DAT_0800b3a4+0x10 |
| 0x29 | totalCharge | u32/100 | 33000 | total_charging_energy | DAT_0800b3a4+0x04 |
| 0x2D | totalDischarge | u32/100 | 33002 | total_discharging_energy | DAT_0800b3a4+0x08 |
| 0x3D | wifiRssi | u8 | 30303 | wifi_signal_strength | DAT_0800b38c[1] |
| 0x4F | bmsVersion | u16 | 30204 | bms_version | DAT_0800b394[0x11] |

### DeveloperModeInfo (BLE cmd 0x0D) → Modbus Read Register

| BLE Offset | BLE Feld | Modbus Reg | Modbus Name |
|---|---|---|---|
| 0x01 | lineFrequency | 32204 | ac_frequency |
| 0x03 | acVoltage | 32200 | ac_voltage |
| 0x07 | temperature1 | 35000 | internal_temperature |
| 0x09 | temperature2 | 35001 | mos1_temperature |
| 0x0B | temperature3 | 35002 | mos2_temperature |
| 0x0D | temperature4 | 35010 | max_cell_temperature |
| 0x0F | temperature5 | 35011 | min_cell_temperature (NEU) |

### BMSData (BLE cmd 0x14) → Pack Register (34000+)

| BLE Offset | BLE Feld | Modbus Pack1 Reg | Scale |
|---|---|---|---|
| 0x00 | bmsVersion | 34010 | ×1 |
| 0x08 | remainingCapacity (SOC) | 34002 | ÷10 % |
| 0x0A | stateOfHealth | — | nicht im Modbus-Scan |
| 0x0C | designCapacity | 32105 | ÷1000 kWh |
| 0x0E | voltage | 34000 | ÷100 V |
| 0x10 | current | 34001 | ÷10 A |
| 0x18 | cycleCount (b_cpc) | 34003 | ×1 |
| 0x26 | mosfetTemperature | 34015 | ÷10 °C |
| 0x28-0x2E | temperature1-4 | 34011-34014 | ÷10 °C |
| 0x30-0x51 | cellVoltages[0-16] | 34018-34033 | ÷1000 V |

## BLE-Felder ohne bekanntes Modbus-Register

Diese Felder existieren im BLE-Protokoll, haben aber kein bekanntes Modbus-Äquivalent. Sie könnten in unbescannten Register-Bereichen liegen oder nur über BLE verfügbar sein.

| BLE Feld | BLE Cmd | Typ | SRAM-Quelle | EEPROM | Beschreibung |
|---|---|---|---|---|---|
| euPowerLimit | 0x03 | u8 | 0x20000136 | — | EU 800W Limit (0=off, 1=active) |
| powerRating | 0x03 | u16 | 0x2000012F | — | Nennleistung in W |
| detectedCtType | 0x03 | u8 | Config+0x68 | — | CT-Meter-Typ (0=none, 3=HME-4, 4=Shelly Pro EM, ...) |
| batteryPhasePos | 0x03 | u8 | Config+0x69 | — | Batterie-Phasenposition (1=A, 2=B, 3=C) |
| parallelMode | 0x03 | u8 | Config+0x67 | — | Parallelbetrieb (0/1) |
| localApiEnabled | 0x03 | u8 | Config+0x71 | 0x371 | Lokale API aktiv (0/1) — steuert Modbus TCP! |
| apiPort | 0x03 | u16 | Config+0x72 | 0x372 | API-Port (Standard: 502) |
| batteryPackCount | 0x03 | u8 | Pack+0x0C (filtered) | — | Anzahl erkannter Batterie-Packs |
| installedPackMask | 0x03 | u8 | Pack+0x08 (bool) | — | Bitmask installierter Packs |
| workingPackIndex | 0x03 | u8 | v156+ | — | Aktuell aktiver Pack-Index |
| userWorkMode | 0x03 | u8 | Config+0x01 | — | Vom Benutzer gewählter Modus |
| autoWorkModeChange | 0x03 | u8 | Config+0x66 | — | Automatischer Moduswechsel (0/1) |
| httpServerType | 0x03 | u8 | DAT_0800b3b0+0x60 | 0x441 | Cloud-Server Subdomain (0-4) |
| stateOfHealth | 0x14 | u16 | — | — | SOH in % (nur BLE, nicht Modbus?) |

## WorkMode Enum (aus BLE-Tool, FW-verifiziert)

| Wert | Modus | Beschreibung |
|---|---|---|
| 0 | Auto | Selbstverbrauch-Optimierung |
| 1 | Standby | Kein Laden/Entladen |
| 2 | Charging | Nur Laden |
| 3 | Sell Electricity | Netzeinspeisung |
| 4 | UPS/EPS | Notstrom-Modus |
| 5 | Force Charge | Zwangsladen |
| 6 | Grid Export | Netz-Export |
| 7 | Schedule/TOU | Zeitplan/Time-of-Use |

## Wichtige Erkenntnis: BLE cmd 0x28 steuert Modbus TCP

Der BLE-Befehl 0x28 aktiviert/deaktiviert die lokale Modbus TCP API und setzt den Port:
- Byte 4: Enable (0/1) → SRAM Config+0x71, EEPROM 0x371
- Bytes 5-6: Port (u16 LE) → SRAM Config+0x72, EEPROM 0x372

Dies bestätigt, dass die Modbus TCP Schnittstelle über BLE steuerbar ist.

## Register-Kandidaten für unbekannte Scan-Werte

| Modbus Reg | Scan-Wert | Mögliches BLE-Feld | Begründung |
|---|---|---|---|
| 30102 | 3198 | max_cell_voltage_aggregate | 3.198V typisch für LiFePO4 |
| 30103 | 3194 | min_cell_voltage_aggregate | 3.194V |
| 30210 | 3 | detectedCtType? | Wert 3 = HME-4 (CT002) |
| 30212 | 2 | batteryPhasePos? | Wert 2 = Phase B |
| 37000 | 1 | batteryPackCount? | 1 Pack installiert |
| 35110 | 576 | euPowerLimit related? | Unklar |
| 35111 | 500 | powerRating/10? | 500×5=2500W? Spekulation |
