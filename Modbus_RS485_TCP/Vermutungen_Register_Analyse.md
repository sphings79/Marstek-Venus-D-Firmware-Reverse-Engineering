# Marstek Venus D — Register-Vermutungen

Stand: 2026-07-07
Basis: 4 Einzelscans + 3 Langzeit-Scans + Boot-Scan + Battery-Disconnect-Tests + Discharge-Steps-Test
FW: EMS:147, VNS:115, MPPT:104, BMS:116 (kein Update zwischen den Scans)
Versionierungsschema: Suffix-basiert (z.B. 149=Release, 1492=Beta von 149)

---

## Übersicht Scan-Bedingungen

| Scan | Zustand | SOC | Dauer |
|------|---------|-----|-------|
| scan1 | Idle, neue FW | 14% | Einzelscan |
| scan2 | Standby, alte FW | 95% | Einzelscan |
| scan3 | Manuell Entladen 500W | ~88-94% | Einzelscan |
| scan4 | Manuell Laden 2200W | ~50% | Einzelscan |
| langzeit1 | Laden | ~65→70% | 16 min |
| langzeit2 | Laden | ~70% | 10 min |
| langzeit3 | Laden | 65%→100% | 2h18min |
| boot_scan | 3x Neustart (Power-Cycle) | ~95% | 18 Scans |
| battery_disconnect | Batterie getrennt + wieder angesteckt | ~95% | 18 Scans, ~2 min |
| power_cycle_no_bat | Batterie entfernt → 2x AC-Cycle → Batterie wieder dran | ~99% | 41 Scans, ~7 min |
| discharge_steps 1-3 | Entladen mit schrittweiser Leistungserhöhung (Zeitplan) | 90-99% | 69 Scans, ~29 min |
| backup_load | Backup-Modus mit verschiedenen Lasten (52W bis 3kW+) | 40-44% | 28 Scans, ~10 min |
| backup_overload | Backup-Überlast ~3.2kW (>2.5kW Limit) | 30-38% | 35 Scans, ~4 min |
| backup_overload_ac_disconnect | Backup-Überlast + AC-Trennung | ~30% | 14 Scans, ~2 min |
| backup_no_discharge | Backup aktiv, aber 42010=0 (kein Force-Discharge nach Reboot) | ~30% | 3 Scans |
| discharge_under_dod | Langzeit-Entladung bis unter DOD, AC-Disconnect, Inselbetrieb, Reserve-Cutoff | 30%→7% | 548 Scans, ~3h17min |
| unter_dod_backup_nicht_aktivierbar | Unter DOD: Backup lässt sich nicht einschalten, Zwangsladung bei AC-Reconnect | 7-8% | 21 Scans (scan_powercycle), ~4 min |
| zwangsladung_unter_dod | Zwangsladung unter DOD — Detail-Scan mit vollen 419 Registern | 8% | 7 Scans, ~2 min |
| fw_upgrade_149_2 | FW-Update von 148 auf 149.2 — Gerät ~25min offline | 60% | 22 Scans (scan_powercycle), ~27 min |
| laden_6pack_149_2 | 6 Packs, FW 149.2, Laden mit massivem SOC-Unterschied, ohne Lüfter | 50-60% | 5 Scans (full), ~7 min |
| nach_bms_upgrade_117_7 | 6 Packs, BMS-Update von v116 auf v117.7, sonst Standby/Idle | ~50% | 4 Scans, ~5 min (15:43-15:48) |

---

## Vermutungen (🔍) mit Begründung

### 30005 — `backup_voltage` (Backup-Ausgangsspannung) ✅ Backup-Test

- **Werte:** ~1V ohne Backup (inaktiv), 236-242V mit Backup (Scale 0.1)
- **Begründung:** Im Backup-Test springt der Wert von ~10 (1.0V = aus) auf ~2418 (241.8V) sobald Backup-Last anliegt. Zeigt typischen Spannungsabfall unter Last: 242V bei geringer Last (<200W), 237V bei hoher Last (>3kW). Das ist exakt das AC-Spannungsverhalten eines belasteten Inverter-Ausgangs.
- **Vorher:** Fälschlich als `comm_queue_depth` vermutet. Die kleinen Werte (2-19) ohne Backup waren Rauschen/Standby-Restspannung.
- **Quelle:** backup_load_activated.csv
- **Sicherheit:** Hoch — Spannungsprofil unter Last ist eindeutig.

### 30006 — `ac_power` (AC Inverter-Ausgangsleistung) ✅ bestätigt + korrigiert

- **Werte:** int16; negativ = Netzbezug (Laden), positiv = AC-Ausgang (Entladen)
- **Begründung Discharge-Steps:** Im Discharge-Steps-Test trackt 30006 exakt den Setpoint aus 43103. Ohne Backup = Einspeiseleistung.
- **KORREKTUR Backup-Test:** 30006 ist NICHT die Netz-Einspeisung, sondern die gesamte AC-Ausgangsleistung des Inverters. Im Backup-Modus bleibt 30006 konstant bei ~2208W, obwohl die tatsächliche Netzeinspeisung sinkt (beobachtet: bei 2kW Backup nur noch ~200W ins Netz, bei 3kW Backup sogar 1kW Netzbezug). Die tatsächliche Netzleistung ergibt sich aus: **Grid = 30006 - 30007**.
- **Ohne Backup:** 30007=0, daher Grid = 30006 (Spezialfall — deswegen war es vorher nicht unterscheidbar)
- **Quelle:** discharge_w_steps 1-3, backup_load_activated.csv
- **Für HA-Integration:** Im Backup-Modus NICHT 30006 direkt als Grid-Sensor verwenden! Stattdessen: `grid_power = 30006 - 30007`
- **Sicherheit:** Hoch — Backup-Test-Rechnung passt exakt zu beobachtetem Verhalten.

### 30007 — `backup_power` (Backup-Ausgangsleistung) ✅ Backup-Test

- **Werte:** 0 ohne Backup, 0-3271W mit Backup
- **Begründung:** War in ALLEN bisherigen Scans (idle, standby, charge, discharge, boot, disconnect) immer 0. Erst im Backup-Test erstmals aktive Werte. Zeigt die Leistungsabgabe am Backup-Ausgang. Werte korrelieren exakt mit der angeschlossenen Last (52W bis 3kW+).
- **Wenn 30007 > 30006:** Der Inverter kann die Backup-Last nicht alleine versorgen, die Differenz wird aus dem Hausnetz bezogen. Bei 30007=3271W und 30006=2208W: 3271-2208 = 1063W Netzbezug (beobachtet: ~1kW).
- **Quelle:** backup_load_activated.csv
- **Sicherheit:** Hoch — Energiebilanz passt exakt.

### 30301 — `active_inverter_state` (Inverter-Zustand?) 🔍 Vermutung

- **Werte:** 1, 2, 3
- **Begründung:** War in allen bisherigen Scans konstant 1 (vorher als bluetooth_status geführt). Im Backup-Test wechselt der Wert 1→2→3→2→3. Der Wechsel korreliert zeitlich lose mit Pack-Rotationen (P1→P2→P4), ist aber kein 1:1-Mapping zum Pack-Index. Könnte ein interner Inverter-Routing-State sein.
- **Vorher:** Als bluetooth_status vermutet (immer 1 = "an"), aber die Wechsel im Backup-Test schließen Bluetooth aus.
- **Quelle:** backup_load_activated.csv
- **Sicherheit:** Niedrig — Funktion unklar, nur Korrelation mit Zustandswechseln sicher.

### 30101 — `pack1_current_mirror` (Pack 1 Strom-Spiegel)

- **Werte:** 0 (Pack1 idle), -25 bis -160 (Pack1 aktiv, Scale 0.1A)
- **Begründung:** Im Discharge-Steps-Test exakt identisch mit 34001 (pack1_current) wenn Pack1 aktiv ist. Bei Pack-Wechsel (Pack1→Pack2) geht 30101 sofort auf 0, obwohl die Entladung weiterläuft. Kein System-Strom, sondern Pack1-Mirror.
- **Vorher:** Als battery_current geführt, aber war in allen Scans immer 0 (weil zufällig nie Pack1 aktiv war oder keine Entladung lief).
- **Quelle:** discharge_w_steps1.csv (Scan 5-32: Pack1 aktiv, Scan 33+: Pack2 aktiv)
- **Sicherheit:** Hoch — exakte Wertübereinstimmung mit 34001.

### 30029 — `battery_power_factor` (Leistungsindex, NICHT linear)

- **Werte:** int16, -18 bis +12
- **Laden (positiv):**
  - 2035W → 11-12
  - 1260W → 6
  - 480W → 1
  - Idle → -1 bis -2
- **Entladen (negativ, Discharge-Steps-Test):**
  - 500W → -5
  - 1000W → -9
  - 1500W → -12
  - 2000W → -16
  - 2200W → -18
- **Linearität geprüft: NEIN.** Das Verhältnis 30029/Leistung ist nicht konstant. Bei niedrigen Leistungen ist der Index pro Watt größer, bei hohen kleiner. Kein linearer Skalierungsfaktor, eher ein interner Leistungsindex oder PWM-Duty-Cycle.
- **Sicherheit:** Mittel — Korrelation klar, aber nicht linear und genaue Bedeutung unklar.

### 30036 — `hardware_version` (Hardware-Version/Konfiguration)

- **Werte:** Konstant 219 über alle Scans und 2+ Stunden Langzeit
- **Begründung:** Absolut stabil = kein Sensor, sondern Konfiguration. 219 könnte HW-Revision, Boardvariante oder Kalibrierparameter sein.
- **Sicherheit:** Mittel — dass es kein Sensor ist, ist sicher. Ob HW-Version oder anderer Parameter, unklar.

### 30205 — `mppt_version` (MPPT Firmware Version) ✅ OTA-bestätigt

- **Wert:** 104 (konstant)
- **Korrektur:** War fälschlich als `bms_version_sub` geführt.
- **Begründung:** OTA-Screenshot zeigt 4 FW-Komponenten: EMS:142→147, VNS:114→115, **MPPT:104**, BMS:116. Register 30205=104 ist die MPPT-Version, nicht die BMS-Sub-Version.
- **OTA bestätigt auch:** 30200=EMS, 30202=VNS (nicht VMS!), 30204=BMS.
- **Sicherheit:** Bestätigt durch OTA-Anzeige.

### 30201 / 30203 — `ems_build` / `vns_build` (Build/Beta-Suffix?)

- **Werte:** 18 / 106 (konstant)
- **Begründung:** Liegen direkt nach den Versionsregistern. Die OTA-Anzeige zeigt keine Sub-Versionen, aber Marstek verwendet ein Suffix-Schema: z.B. "149" = Release, "1492" = Beta von 149 mit Suffix 2. Die Werte 18/106 könnten solche Suffixe oder interne Build-Nummern sein.
- **Alternative:** Könnten Versionen weiterer FW-Module sein (Bootloader etc.) — in der Ghidra-Analyse gab es Flash-Bereiche ohne Zuordnung. Das Kommunikationsmodul (WiFi) ist es aber vermutlich NICHT: dessen Version ist ein Datums-Timestamp (z.B. "202409090159" = 2024-09-09 01:59), der nicht in ein uint16 passt und wahrscheinlich direkt vom WiFi-Chip abgefragt wird, nicht über Modbus.
- **Sicherheit:** Niedrig — Zusammenhang mit Versionierung plausibel, genaues Format unklar.

### 30210 — `active_pack_charge_status` (Spiegel des aktiven Packs)

- **Werte:** 0 oder 3
- **Begründung:** Im Langzeit-Scan exakt identisch mit dem 34x04-Wert des gerade aktiven Packs. Wenn Pack1 lädt: 30210=3 und 34004=3. Wenn Pack2 lädt: 30210=0 (weil es den Pack1-Wert spiegelt, und Pack1 dann idle ist). Alternativ: 30210 spiegelt immer Pack1's Status.
- **Sicherheit:** Hoch für die Korrelation, Interpretation als "Spiegel" sicher.

### 34x04 — `packX_charge_status` (Pack-Ladestatus)

- **Register:** 34004, 34104, 34204, 34304
- **Werte:** 0=idle, 3=aktiv (laden oder entladen)
- **Begründung:** Im Langzeit-Scan: 34x04 =3 genau dann, wenn der jeweilige Pack Strom zieht/liefert (34x01 ≠ 0). =0 wenn der Pack idle ist. Vorher als "max_cell_voltage_delta" gelabelt, was bei Werten 0-3 keinen Sinn ergibt.
- **Offene Frage:** Ob es weitere Werte gibt (1, 2?) — bisher nur 0 und 3 beobachtet. Evtl. 1=Standby, 2=Balancing?
- **Sicherheit:** Hoch — dass es ein Status ist, ist klar. Genaue Bedeutung der Zustände noch offen.

### 35011 — `pack1_env_ntc_mirror` (Pack 1 Umgebungstemperatur)

- **Werte:** 190-326 (Scale 0.1°C → 19.0-32.6°C)
- **Begründung:** Im Langzeit-Scan über 276 Datenpunkte exakt identisch mit 34016 (pack1_env_ntc). Kein Offset, kein Lag.
- **Sicherheit:** Sehr hoch.

### 35110 / 35111 / 35112 — Leistungs-Konfigurationsblock

**35110 — `max_charge_power` (Max Ladeleistung)**
- **Werte:** Konstant 576
- **Begründung:** Zusammen mit 35111/35112 ein Block. 576 könnte ein interner Referenzwert für die maximale Ladeleistung sein (evtl. in internen Einheiten).

**35111 — `power_level` (Leistungsstufe, Laden UND Entladen)**
- **Werte:** 500, 250, 100, 0
- **Begründung:** Beim Laden korrelieren die Stufen mit der CC-CV Ladekurve:
  - SOC < 90% → 500 → Vollast ~2035W
  - SOC 90-95% → 250 → ~1260W (halbe Leistung)
  - SOC 95-100% → 100 → ~480W (CV-Phase)
  - SOC = 100% → 0 → Pack fertig
- **Neu (Discharge-Steps-Test):** Auch beim Entladen aktiv! Wechselt zwischen 100/250/500, vermutlich abhängig von Pack-Rotation und aktueller Leistungsauslastung. Nicht nur charge-spezifisch.
- **Sicherheit:** Sehr hoch für die Korrelation. Allgemeiner Power-Level-Indikator.

**35112 — `max_discharge_power` (Max Entladeleistung)**
- **Werte:** Konstant 500
- **Begründung:** Analog zu 35110, aber für Entladung. 500 = gleicher Wert wie 35111 bei Vollast.

### 37000 — `system_online` (System-Flag)

- **Werte:** Konstant 1
- **Begründung:** Erster Register im 37xxx-Block, immer 1. Könnte "System aktiv" bedeuten.
- **Sicherheit:** Niedrig — reine Spekulation.

### 37012 — `bms_version_mirror` (BMS Version Spiegel)

- **Werte:** Konstant 116 (bis 2026-07-08), **1177 ab 2026-07-09** nach BMS-Update
- **Begründung:** Identisch mit 30204 (bms_version). Redundanter Spiegel im 37xxx-Block.
- **Update 2026-07-09:** Nach BMS-FW-Upgrade auf v117.7 springt der Wert von 116 auf 1177 — exakt synchron mit 30204 und allen 34x10-Registern (s. Abschnitt „BMS-FW-Update 116→117.7" unten). Bestätigt den Spiegel-Charakter erneut, diesmal über einen echten Versionssprung statt nur über einen konstanten Wert.
- **Sicherheit:** Hoch → jetzt ✅ bestätigt statt nur Vermutung.

### 37013 — `fault_status_mirror` (Fault-Status Spiegel)

- **Werte:** 0 (normal), 16 (0x0010) bei Batterie-Disconnect
- **Begründung:** Im Battery-Disconnect-Test exakt identisch mit 36100 (fault_status). Beide springen gleichzeitig auf 16 (Bit 4 = BMS offline), beide gehen gleichzeitig auf 0 zurück. Redundanter Spiegel im 37xxx-Block, analog zu 37012 (bms_version_mirror).
- **Quelle:** battery_disconnect.csv
- **Sicherheit:** Hoch — exakte Übereinstimmung in Timing und Wert.

### 36101 — `fault_status_2` (Fault-Status Word 2, Bit 7 = AC/Grid Disconnect)

- **Werte:** 0 (normal), 128 (0x80) bei AC-Trennung
- **Begründung:** Im Power-Cycle-Test ohne Batterie taucht 36101=128 exakt in den Scans auf, die unmittelbar vor dem AC-Disconnect liegen:
  - Scan 18 (16:01:25): 128 → nächster Scan nach Lücke (AC war getrennt)
  - Scan 26-27 (16:03:23-16:03:30): 128 → danach wieder Lücke (zweites AC-Trennen)
- Der Inverter erkennt den Grid-Verlust offenbar noch bevor die TCP-Verbindung abreißt und setzt Bit 7.
- Nach AC-Reconnect (Reboot): automatisch gecleared.
- **Quelle:** battery_disconnect_and_then_power_cycle_without_battery.csv
- **Sicherheit:** Hoch — exaktes Timing-Pattern, reproduzierbar bei beiden AC-Disconnects.

### 37014 — `fault_status_2_mirror` (Fault-Status-2 Spiegel)

- **Werte:** 0 (normal), 128 (0x80) bei AC-Disconnect
- **Begründung:** Exakt identisch mit 36101 in Timing und Wert. Vervollständigt das Spiegel-Muster im 37xxx-Block:
  - 37012 = 30204 (bms_version_mirror) ✅
  - 37013 = 36100 (fault_status_mirror) 🔍
  - 37014 = 36101 (fault_status_2_mirror) 🔍
- **Quelle:** battery_disconnect_and_then_power_cycle_without_battery.csv
- **Sicherheit:** Hoch.

### 34x09 — `packX_protect2` Bit 1 (0x0002) = Low-SOC Protection ✅ Entlade-Test

- **Werte:** 0 (normal), 0x0002 (Bit 1) bei niedrigem SOC
- **Begründung:** Im Langzeit-Entlade-Test tritt Bit 1 bei jedem Pack auf, sobald der Pack-SOC unter ~11% fällt. Bei Entladung unter 10.5% tritt es erneut auf. Betrifft alle 4 Packs (34009, 34109, 34209, 34309).
- **Sonderwert 0x0C93:** Pack1 protect2 bei Komplett-Shutdown (Scan 225, SOC=0) — mehrere Protection-Bits gleichzeitig.
- **Quelle:** discharge_under_dod.csv
- **Sicherheit:** Hoch — bei allen 4 Packs reproduzierbar.

### 37016 — `offgrid_ac_voltage` (Offgrid AC-Spannung)

- **Werte:** 2416/2393/2401 bei Standby/Entladung, 0 bei Laden
- **Begründung:** Werte ≈ ac_voltage (30004/32200), aber =0 wenn der Inverter Strom aus dem Netz zieht (Laden). Aktiv nur bei Einspeisung oder Standby. Könnte die AC-Spannung am Ausgang des Inverters sein (nicht am Netzanschluss).
- **Sicherheit:** Mittel.

### 37022 — `offgrid_dc_voltage` (Offgrid DC-Spannung)

- **Werte:** 513/534/527 bei Standby/Entladung, 0 bei Laden
- **Begründung:** Analog zu 37016, aber DC-Seite. Werte ≈ dc_bus_voltage (30000/30028). Gleiches Muster: =0 bei Netzbezug.
- **Sicherheit:** Mittel.

---

## Ladekurve CC-CV Analyse

Der Marstek Venus D verwendet ein **gestuftes CC-CV Profil** mit 3 Leistungsstufen:

| Phase | SOC-Bereich | Leistung | Pack-Strom | Reg 35111 |
|-------|-------------|----------|------------|-----------|
| CC (Vollast) | < 90% | ~2035W | 37.6A | 500 |
| CV Stufe 1 | 90-95% | ~1260W | 23A | 250 |
| CV Stufe 2 | 95-100% | ~480W | 9A | 100 |
| Fertig | 100% | 0W | 0A | 0 |

Die Reduktion auf ~550W zum Ende ist also **normales Verhalten** (LiFePO4 CC-CV), kein Defekt.

### Round-Robin Ladung
- Immer nur 1 Pack aktiv, Rotation P1→P2→P3→P4
- ~3 Minuten pro Pack (~10% SOC-Zugewinn)
- Pack-Wechsel erkennbar an 34x04 (charge_status) und 34x01 (current)
- Inverter-State (35100) flackert kurz 2→1→2 beim Wechsel

---

## Discharge-Steps-Test (Entladen mit Leistungsstufen)

Entladung über App-Zeitplan mit schrittweiser Erhöhung der Einspeiseleistung von 100W bis 2200W. 3 CSV-Dateien, 69 Scans über ~29 Minuten bei SOC ~90-99%.

### Erkenntnisse

**30006 = AC Netzleistung (int16, ✅ bestätigt)**
- War in bisherigen Einzelscans 0 oder schien nur Einspeiseleistung zu sein
- Tatsächlich int16 mit Vorzeichen: **negativ = Netzbezug (Laden), positiv = Einspeisung (Entladen)**
  - Laden Vollast: -2172W
  - CV-Phase: -541W
  - Idle: 0
  - Entladen: +852W
- **37004 ≠ exakter Spiegel von 30006!** 37004 reagiert bei Setpoint-Wechsel ~1 Scan schneller als 30006 (zeigt den neuen Wert früher). 37004 ist vermutlich der Soll/Regelwert, 30006 der Ist-Wert

**43xxx = Zeitplan-Konfigurationsblock (✅ bestätigt)**

| Register | Wert | Bedeutung |
|----------|------|-----------|
| 43000 | 0 | work_mode wechselt 1→0 wenn Zeitplan aktiv |
| 43100 | 127 | Wochentage-Bitmask (0b1111111 = alle 7 Tage) |
| 43102 | 2359 | Endzeit (23:59 als HHMM-Integer) |
| 43103 | 100-2200 | Entlade-Leistungs-Setpoint in Watt |
| 43104 | 1 | Entladung aktiv Flag |

**30101 = Pack1-Current-Mirror (🔍 neu identifiziert)**
- War in ALLEN bisherigen Scans 0
- Jetzt klar: spiegelt exakt 34001 (pack1_current) wenn Pack1 aktiv
- Bei Pack-Wechsel (Pack1→Pack2 bei Scan 33) sofort 0
- Kein System-Gesamt-Strom, sondern Pack1-spezifischer Spiegel

**35111 auch beim Entladen aktiv**
- Wechselt zwischen 100/250/500 auch während Entladung
- Nicht nur charge_power_setpoint, sondern genereller Power-Level-Indikator
- Umbenannt zu `power_level`

**30029 skaliert auch beim Entladen**
- Negative Werte proportional zur Entladeleistung: -2 (idle) bis -18 (2331W)
- Bestätigt Rolle als Leistungs-Index/Faktor für beide Richtungen

---

## Battery-Disconnect-Test

Batterie physisch vom Inverter getrennt (DC-Stecker abgezogen) und wieder angesteckt. 18 Scans über ~2 Minuten.

### Erkenntnisse

**36100 — fault_status Bit 4 (0x0010) = BMS offline**
- Normal: 36100 = 0
- Batterie getrennt: 36100 = 16 (0x0010)
- Batterie wieder angesteckt: 36100 = 0 (nach wenigen Sekunden)
- Bestätigt: Bit 4 ist der BMS-Kommunikationsfehler (Batterie nicht erreichbar)

**37013 = fault_status Spiegel**
- Bisher als ❓ unknown geführt, immer 0 in allen vorherigen Scans
- Bei Disconnect: 37013 = 16, exakt wie 36100
- Neues Label: fault_status_mirror (🔍 Vermutung)

**35100 — inverter_state Zustandswechsel**
- Mit Batterie: 35100 = 1 (Standby)
- Ohne Batterie: 35100 = 2 (aktiv/suchend)
- Interpretation: Inverter wechselt in aktiven Suchmodus wenn BMS nicht antwortet

**35111 — charge_power_setpoint Reset**
- Bei Disconnect: 35111 = 0 (logisch, keine Ladung ohne Batterie)

**34x08/34x09 — Schutzregister bleiben 0**
- Auch bei Batterie-Disconnect setzen die Pack-Protection-Bitmasks keine Bits
- Die Schutzregister reagieren offenbar nur auf BMS-interne Events (Überspannung, Übertemperatur), nicht auf Kommunikationsverlust

---

## Power-Cycle ohne Batterie

Batterie physisch entfernt → Inverter ließ sich nicht per Power-Taste ausschalten → 2x AC getrennt/verbunden → Batterie wieder angesteckt. 41 Scans über ~7 Minuten.

### Timeline

| Phase | Scans | Zeit | Zustand |
|-------|-------|------|---------|
| Normal | 1-5 | 15:59:20-15:59:49 | Batterie drin, SOC=99%, state=1 |
| Batterie getrennt | 6-7 | 15:59:57-16:00:04 | SOC→0, 35111→0, Fault noch nicht gesetzt |
| BMS offline | 8-17 | 16:00:11-16:01:18 | 36100=16, state=2, ~15s Verzögerung |
| AC-Disconnect 1 | 18-19 | 16:01:25-16:01:33 | 36101=128, dann Verbindung weg |
| AC-Reconnect 1 | 20-25 | 16:02:39-16:03:16 | Frischer Boot, alle Faults gecleared, state=2 |
| AC-Disconnect 2 | 26-27 | 16:03:23-16:03:30 | 36101=128, dann Verbindung weg |
| AC-Reconnect 2 | 28-38 | 16:04:06-16:05:48 | state=2, 37024=1345 Spike bei Scan 36 |
| Batterie reconnect | 39-40 | 16:05:56-16:06:03 | state→1 |

### Erkenntnisse

**36101 Bit 7 (0x80) = AC/Grid Disconnect**
- Neues Fault-Bit, bisher nie beobachtet (war immer 0)
- Taucht exakt bei AC-Trennung auf, reproduzierbar bei beiden Disconnects
- Der Inverter erkennt Grid-Verlust noch bevor TCP abreißt
- Nach AC-Reconnect (Reboot) automatisch gecleared

**37014 = 36101 Spiegel (neu identifiziert)**
- Vervollständigt das Spiegel-Pattern: 37013=36100, 37014=36101
- Der 37xxx-Block enthält also mindestens 37012-37014 als Mirror-Register

**37024 = 1345 (einzelner Spike)**
- Einmalig bei Scan 36 (16:05:34), ~20s vor Batterie-Reconnect
- Könnte BMS-Handshake, Initialisierungswert oder Timing-artefakt sein
- Bedarf weiterer Beobachtung

**BMS-Fault-Timing**
- ~15 Sekunden Verzögerung zwischen physischem Disconnect und Fault-Bit (Scan 6→8)
- SOC und charge_power_setpoint reagieren sofort (Scan 6), Fault braucht länger

**AC-Reboot cleart Faults**
- Nach AC-Cycle ohne Batterie: 36100=0 (BMS-Fault gecleared), obwohl Batterie immer noch fehlt
- Der Inverter setzt den BMS-Fault erst nach erneutem Timeout neu — im Test wurde AC vorher wieder getrennt

**Inverter ohne Batterie nicht abschaltbar**
- Power-Taste funktioniert nicht ohne Batterie → nur AC-Trennung möglich

---

## Boot-Scan (3x Neustart)

Marstek 3x per Power-Cycle neugestartet, Event-Scanner lief dabei mit.

### Erkenntnisse

- **Immer-0 Register sind tatsächlich Platzhalter** — kein einziges bisher unbekanntes Register hat beim Boot kurzzeitig einen Wert gezeigt
- **42010 (force_mode) wird beim Neustart auf 0 zurückgesetzt** — gesetzter Force-Mode geht bei Stromausfall verloren
- Keine Boot-spezifischen Übergangs-States in den beobachteten Registern

---

## Leistungsfluss und Inverterwirkungsgrad

### Was messen 30001, 30006 und 30007?

Der Marstek Venus hat drei zentrale Leistungsregister. Um zu verstehen was sie anzeigen, hilft es sich den Energiefluss im Gerät vorzustellen:

```
                                              ┌─── Backup-Ausgang (30007)
                                              │    (30005 = Spannung)
Stromnetz (AC 230V)  ←→  [Inverter]  ←→  [AC-Bus]
                          (Verluste)          │
                                              └─── Batterie (DC ~530V)
                                                   (30001 = DC-Leistung)
```

**Register 30001 — Batterieleistung (DC-Seite)**

Zeigt, wie viel Leistung die Batterie gerade aufnimmt oder abgibt. Positiv bedeutet die Batterie wird geladen, negativ bedeutet sie wird entladen. Das ist die Leistung direkt an der Batterie, also auf der Gleichstromseite (DC) des Inverters. Wichtig: Dieser Wert zeigt nur die DC-Leistung des Grid-Inverters, nicht die Backup-Last (siehe unten).

**Register 30006 — Inverter AC-Ausgangsleistung**

Zeigt die gesamte AC-Ausgangsleistung des Inverters. Negativ = Netzbezug (Laden), positiv = AC-Ausgang (Entladen). Ohne Backup-Betrieb entspricht das der Netzeinspeisung. Im Backup-Modus wird dieser AC-Ausgang aber zwischen Netz und Backup-Ausgang aufgeteilt — 30006 bleibt dann konstant am Inverter-Limit (~2200W), auch wenn weniger ins Netz geht.

**Register 30007 — Backup-Ausgangsleistung**

Zeigt die Leistung am Backup-Ausgang (Notstrom). Ist 0 solange kein Backup-Verbraucher angeschlossen ist. Steigt mit der Last am Backup-Ausgang (0-3271W gemessen).

**Tatsächliche Netzleistung berechnen:**

Die tatsächliche Einspeisung bzw. der Netzbezug ergibt sich aus:

`Grid-Leistung = 30006 - 30007`

Beispiel: 30006=2208W, 30007=3271W → Grid = 2208-3271 = -1063W (1kW Netzbezug, weil die Backup-Last den Inverter übersteigt).

### Warum unterscheiden sich die beiden Werte?

Zwischen Batterie und Netz sitzt der Inverter (Wechselrichter). Dieser wandelt Gleichstrom in Wechselstrom um (oder umgekehrt). Bei dieser Umwandlung geht ein Teil der Energie als Wärme verloren. Deshalb sind die beiden Werte nie exakt gleich:

| Vorgang | 30001 (Batterie) | 30006 (Netz) | Verlust | Wirkungsgrad |
|---------|-----------------|-------------|---------|-------------|
| Laden Vollast | +2035W | -2172W | ~137W | ~93.7% |
| Laden CV-Phase | +480W | -541W | ~61W | ~88.7% |
| Entladen 850W | -905W | +852W | ~53W | ~94.1% |
| Entladen 2200W | -2331W | +2209W | ~122W | ~94.8% |

**Wie liest man die Tabelle?**

Beim Laden mit Vollast zieht der Inverter 2172W aus dem Netz (30006 = -2172). Davon kommen 2035W bei der Batterie an (30001 = +2035). Die restlichen 137W gehen als Wärme im Inverter verloren. Der Wirkungsgrad ist also 2035/2172 = 93.7%.

Beim Entladen liefert die Batterie 905W (30001 = -905). Davon werden 852W ins Netz eingespeist (30006 = +852). Wieder gehen ~53W als Wärme verloren. Wirkungsgrad: 852/905 = 94.1%.

### Erkenntnisse

- Der Wirkungsgrad ist bei höheren Leistungen besser (~94-95%) als bei niedrigen (~88-89%)
- Entladen ist etwas effizienter als Laden
- Für die Home Assistant Integration:
  - **Ohne Backup:** 30006 direkt als Grid-Sensor verwenden (30007=0, also Grid=30006)
  - **Mit Backup:** `grid_power = 30006 - 30007` berechnen! 30006 allein zeigt NICHT die Netzleistung
  - **30007** als eigener Sensor "Backup-Leistung" anlegen
  - **30005** (Scale 0.1) als "Backup-Spannung" — zeigt ob Backup aktiv ist und wie stabil die Versorgung
- **30001 ist relevant** wenn man den Ladezustand und die Belastung der Batterie überwachen will
- Über die Differenz lässt sich in HA ein eigener Sensor "Inverterverluste" berechnen: `abs(30001) - abs(30006)`
- **42021** zeigt das aktuelle Inverter-Leistungslimit (2200W im Test)

### 37004 — Netzleistung Soll/Regelwert

Register 37004 zeigt fast den gleichen Wert wie 30006, reagiert aber bei Leistungsänderungen etwa einen Scan-Zyklus (~20-30 Sekunden) schneller. 37004 scheint der interne Sollwert zu sein, auf den der Inverter hinregelt, während 30006 die tatsächlich gemessene Leistung zeigt. Die kleinen Abweichungen (+1 bis +8W) zwischen 30006 und dem Setpoint aus 43103 bestätigen, dass 30006 ein echter Messwert ist und nicht einfach den eingestellten Wert zurückgibt.

---

## Backup-Load-Test (Notstrom mit verschiedenen Lasten)

**Datei:** `backup_load_activated.csv` — 28 Scans, 08:12-08:22, SOC 40-44%, Backup-Modus aktiv, Verbraucher schrittweise erhöht (52W bis 3kW+).

### Timeline

| Phase | Scans | 30007 (Backup-Last) | 30005 (Backup-V) | 30006 (Inverter) | Grid effektiv | 30301 |
|-------|-------|--------------------|--------------------|------------------|---------------|-------|
| Kein Backup | 1-2 | 0W | ~1V | 2209W | 2209W (Einsp.) | 1 |
| ~90W Last | 3-6 | 92-94W | 242V | 2209W | ~2117W | 1 |
| ~2kW Last | 7-9 | 1871-1991W | 238V | 2208W | ~217W | 1→2 |
| ~90W Last | 10-11 | 93-95W | 242V | 2209W | ~2116W | 2 |
| Rampe hoch | 12-13 | 134→647W | 242V | 2208W | ~1561W | 2 |
| ~2.2kW Last | 14-17 | 2209-2226W | 238V | 2208W | ~-1W (neutral) | 2 |
| ~350W Last | 18-21 | 352-354W | 242V | 2209W | ~1856W | 3 |
| ~2.1kW Last | 22 | 2143W | 239V | 2208W | ~65W | 3 |
| ~3.2kW Last | 23-25 | 3247-3271W | 237V | 2208W | ~-1063W (Bezug!) | 2 |
| ~350W Last | 26-28 | 267-366W | 242V | 2209W | ~1845W | 2→3 |

### Erkenntnisse

**Neue Register identifiziert:**

- **30005 = backup_voltage** (0.1V) — Backup-Ausgangsspannung. 0V wenn Backup aus, ~242V bei geringer Last, sinkt auf ~237V bei 3kW (normaler Spannungsabfall unter Last).
- **30007 = backup_power** (W) — Backup-Ausgangsleistung. War in ALLEN bisherigen Tests immer 0. Erstmals aktiv mit Backup-Verbraucher.
- **42021 = inverter_power_limit** — Konstant 2200W. Maximale Inverter-Ausgangsleistung. Erklärt warum 30006 nie über 2209W geht.

**30006-Korrektur — Nicht Netzleistung sondern Inverter-Ausgang:**

30006 zeigt die gesamte AC-Ausgangsleistung des Inverters, NICHT die Netzeinspeisung. Ohne Backup war das nicht unterscheidbar (30007=0, also Grid=30006). Im Backup-Test bleibt 30006 konstant bei ~2208W, obwohl die tatsächliche Netzleistung drastisch schwankt:

- Backup 92W → Grid: 2208-92 = 2116W Einspeisung ✓
- Backup 1991W → Grid: 2208-1991 = 217W Einspeisung ✓ (Beobachtung vor Ort: ~200W)
- Backup 2209W → Grid: 2208-2209 = -1W neutral ✓
- Backup 3271W → Grid: 2208-3271 = -1063W Netzbezug ✓ (Beobachtung vor Ort: ~1kW)

**Energiebilanz:**

30001 (~2335W DC) bleibt ebenfalls konstant — der Grid-Inverter arbeitet unverändert am Limit. Die Backup-Last wird aus der AC-Ausgangsleistung des Inverters bedient. Wenn die Backup-Last die Inverterleistung übersteigt (~2200W), wird die Differenz aus dem Hausnetz gezogen.

**32300/32301/32302 — Offgrid-Block bestätigt:**

- 32300 und 32301 sind in ALLEN 28 Scans identisch — beide zeigen die Backup-Spannung (wie 30005). Die FW-Beschreibung "32301=current" ist falsch, es ist ebenfalls Spannung.
- 32302 spiegelt 30007 (Backup-Leistung) mit leichter Verzögerung.

**30301 — Kein Bluetooth:**

Wechselt 1→2→3→2→3 im Backup-Test. Vorher als bluetooth_status vermutet (immer 1). Korreliert zeitlich lose mit Pack-Rotation (P1→P2→P4) aber kein direktes Pack-Index-Mapping. Funktion noch unklar.

**Spannungsabfall unter Backup-Last:**

| Lastbereich | Ø Spannung (30005) | Ø Leistung (30007) |
|-------------|-------------------|--------------------|
| < 200W | 241.9V | 100W |
| 200-1000W | 241.7V | 382W |
| 1-2.5kW | 238.4V | 2107W |
| > 2.5kW | 236.9V | 3257W |

---

## Backup-Overload-Test (Überlast am Backup-Ausgang)

**Datei:** `backup_overload.csv` — 35 Scans, 08:32-08:36, SOC 30-38%, Backup-Modus mit ~3.2kW Dauerlast.

### Timeline

| Phase | Scans | 30007 (Backup) | 30001 (Batterie) | SOC | Fehler? |
|-------|-------|---------------|------------------|-----|---------|
| ~360W Last | 1-4 | 359-361W | -2340W | 37-38% | Nein |
| ~3.2kW Überlast | 5-29 | 3154-3227W | -2338...-2342W | 31-37% | **Nein!** |
| ~360W Last | 30-34 | 275-382W | -2341W | 30-31% | Nein |
| Verbindung weg | 35 | 361W | -2341W | - | (Scan unvollst.) |

### Erkenntnisse

**Kein Überlastschutz bei 3.2kW!** Der Marstek soll laut Spezifikation bei >2.5kW Backup-Last abschalten. Das passiert nicht:

- **Alle Fault-Register (36000-36103, 37013, 37014): durchgehend 0** — kein einziger Fehler in 4 Minuten Dauerbetrieb bei 3.2kW
- **Alle Pack-Protection-Register (34x08, 34x09): durchgehend 0** — kein BMS-Alarm
- **35100 bleibt bei 3** (aktiver Betrieb), kein Zustandswechsel
- **30001 bleibt bei ~-2340W** — der Grid-Inverter arbeitet unverändert am Limit
- **SOC sinkt schnell** von 38% auf 30% in 4 Minuten (bei 3.2kW Backup + 2.2kW Grid = ~5.4kW Gesamtentnahme)

Die Firmware hat offenbar keinen aktiven Überlastschutz für den Backup-Ausgang, oder das Limit liegt deutlich höher als 2.5kW.

---

## Backup-Overload + AC-Disconnect-Test

**Datei:** `backup_overload_ac_disconnect.csv` — 14 Scans, 08:39-08:41, SOC ~30%, Backup-Überlast mit anschließender AC-Trennung.

### Timeline

| Phase | Scans | 30007 | 30001 | 30005 | 35100 | 36101 | Beschreibung |
|-------|-------|-------|-------|-------|-------|-------|-------------|
| ~360W Backup | 1-4 | 353-362W | -2341W | 242V | 3 | 0 | Normal |
| ~3.2kW Überlast | 5-7 | 3159-3198W | -2340W | 237V | 3 | 0 | Überlast, kein Fehler |
| **AC-Disconnect** | **8** | **3208W** | **-2339W** | **237V** | **1** | **0x0080** | **Netz getrennt!** |
| Alles aus | 9-13 | 0W | -12W | 0.5V | 1 | 0→0 | Komplettabschaltung |
| Verb. weg | 14 | 0W | -12W | 0.7V | - | - | Scan unvollständig |

### Erkenntnisse

**AC-Disconnect unter Backup-Last — Komplettabschaltung:**

- **36101 = 0x0080 (Bit 7)** — AC/Grid disconnect Fault, wie schon im Power-Cycle-Test identifiziert. Bestätigt erneut.
- **37014 = 0x0080** — Spiegel von 36101, bestätigt erneut die Mirror-Vermutung.
- **Fault räumt sich nach ~20s selbst auf** (Scans 8-10 aktiv, ab Scan 11 wieder 0).
- **35100 wechselt 3→1** — Inverter geht von "aktiv" auf "idle/standby".

**Backup-Abschaltung bei AC-Disconnect + Überlast:**

Bei AC-Trennung unter 3.2kW Überlast schaltet der Venus den Backup-Ausgang ebenfalls ab:
- 30005 fällt von 237V auf 0.5V (Backup spannungslos)
- 30007 fällt von 3208W auf 0W
- 30001 fällt von -2339W auf -12W (nur Standby-Verbrauch)

**ACHTUNG:** Dies bedeutet NICHT, dass der Venus keinen Inselbetrieb kann. Der Venus kann grundsätzlich Inselbetrieb. Die Abschaltung hier war vermutlich durch die Kombination aus AC-Disconnect + Überlast (3.2kW >> 2.5kW Limit) verursacht. Nach Neustart musste der WR neu gestartet werden, um die Backup-Steckdose wieder zu aktivieren.

**Auch hier keine Überlast-Fehler** — 3.2kW Backup in Scans 5-8 ohne Warnung, der einzige Fault kommt von der AC-Trennung.

---

## Backup ohne Batterieentladung (nach Reboot)

**Datei:** `backup_load_activated_no_battery_discharge.csv` — 3 Scans, 08:47-08:48, SOC ~30%.

Nach dem Neustart (wegen Backup-Abschaltung durch Überlast + AC-Disconnect) versorgt der Venus die Backup-Steckdose nur aus dem Netz, nicht aus der Batterie.

### Messwerte

| Register | Wert | Bedeutung |
|----------|------|-----------|
| **42010** | **0** | Force-Mode aus! (vorher: 2 = Force-Discharge) |
| 30001 | -34W | Nur Standby-Verbrauch, keine Entladung |
| 30006 | 0W | Keine Netz-Einspeisung |
| 30007 | 122-124W | Backup-Last wird bedient |
| 30005 | 239.2-239.5V | Backup-Spannung aktiv |
| **35100** | **6** | **Neuer Inverter-State!** (bisher nur 1 und 3 gesehen) |

### Ursache

**42010 = 0 nach Reboot** — das ist der bekannte Effekt: Force-Mode wird beim Neustart zurückgesetzt (Boot-Scan-Erkenntnis). Ohne 42010=2 (Force-Discharge) entlädt der Venus die Batterie nicht. Die Backup-Last wird stattdessen komplett aus dem Netz versorgt.

Energiebilanz bestätigt: Grid = 30006 - 30007 = 0 - 124 = -124W → die Backup-Last wird aus dem Netz bezogen.

### Neuer Inverter-State: 35100 = 6

Alle bekannten States:
- **0** = Shutdown (Komplett-Abschaltung, SOC=0)
- **1** = Idle/Standby (nach AC-Disconnect, Boot, Reserve-Cutoff)
- **2** = Charging (Laden)
- **3** = Discharging (aktive Entladung mit Grid-Einspeisung)
- **4** = Inselbetrieb (Backup aus Batterie ohne Grid-Verbindung, 36101=0x0080)
- **6** = Backup-Passthrough (DOD erreicht, Grid→Backup Durchleitung, keine Batterie-Entladung fürs Netz)

---

## Langzeit-Entladung unter DOD + Inselbetrieb + Reserve-Cutoff

**Datei:** `discharge_under_dod.csv` — 548 Scans, 08:53-12:10 (~3h17min), SOC 30%→7%, Backup aktiv, 4 Packs.

Der umfangreichste Test bisher: Entladung bis unter die DOD-Grenze, AC-Disconnect, Inselbetrieb und finale Abschaltung bei Reserve-Limit.

### Phase 1 — Normale Entladung (Scans 1-161, 08:53-09:51, SOC 30%→10%)

35100=3, 42010=2. Grid-Einspeisung ~2209W + Backup ~360W. Standard Round-Robin Entladung:

| Reihenfolge | Pack | SOC vorher | SOC nachher | Dauer |
|-------------|------|-----------|------------|-------|
| 1 | P2 | 30.0% | 20.6% | ~5 min |
| 2 | P4 | 30.8% | 20.7% | ~6 min |
| 3 | P1 | 30.7% | 20.7% | ~5 min |
| 4 | P3 | 30.7% | 10.7% | ~14 min |
| 5 | P4 | 20.7% | 10.7% | ~9 min |
| 6 | P1 | 20.5% | 10.7% | ~18 min |
| 7 | P2 (letzter) | 20.5% | → Phase 2 | weiter |

Jeder Pack wird bis ~10.7% einzeln entladen, dann Wechsel zum nächsten mit höchstem SOC. P2 bleibt als letzter übrig (19.6%).

### Phase 2 — Backup-Only unterhalb DOD (Scans 162-221, 09:51-10:12, SOC=10%)

**35100 springt auf 6** — Grid-Einspeisung stoppt (30006=0), 30001 fällt auf -35W. Backup wird aus dem Netz versorgt (Passthrough). Nur Pack2 hat noch Saft (19.6%), entlädt mit minimalem Strom (-3 bis -4, vermutlich Eigenverbrauch).

DOD-Grenze: System-SOC ~10% = alle Packs bei ~10.7% außer dem letzten aktiven.

### Phase 3 — AC-Disconnect + Crash (Scans 222-225, 10:12-10:14)

35100 wechselt auf **4** (Inselbetrieb-Versuch), 36101=0x0080. Bei ~2kW Backup-Last (30007=1344W Scan 223) bricht das System zusammen: Scan 225 SOC=0, 35100=0.

34009=0x0C93 bei Shutdown — mehrere Protection-Bits gleichzeitig aktiv.

### Phase 4 — Reboot + Inselbetrieb (Scans 226-540, 10:15-12:07)

Nach Reboot: 35100=**4** (Inselbetrieb), 42010=0, 36101=0x0080 **bleibt dauerhaft gesetzt**.

30006=0 (kein Grid), Backup wird NUR aus Batterie versorgt. Das bestätigt: **der Venus KANN Inselbetrieb!** Der Crash in Phase 3 war Überlast, nicht fehlende Fähigkeit.

Pack2 ist der einzige mit Reserven (19.3%) und wird langsam entladen:
- Scans 229-499: Pack2 von 19.3%→12.7%, niedriger Strom (-21 bis -69), Backup ~330W
- Scan 500: Last erhöht auf ~1575W, Pack2-Strom steigt auf ~-345
- Scan 514: Last erhöht auf ~2040W, Pack2 bei 11.1% → Rotation beginnt

### Phase 5 — Rapid-Rotation + Reserve-Cutoff (Scans 514-541, 11:58-12:08)

Wenn alle Packs nahe 11% sind, beginnt **hektisches Pack-Switching** — alle 2-3 Scans (~40-60s) statt der üblichen ~10 Minuten:

```
P2(11.1%)→P4(11.5%)→P1(11.0%)→P3(11.0%)→P1(10.6%)→P4(10.6%)→P2(10.5%)→P1(9.9%)
```

Jeder Pack wird nur 2-3% entladen bevor gewechselt wird. Das System versucht die Last gleichmäßig zu verteilen.

**34x09 Bit 1 (0x0002) = Low-SOC Protection:**

| Pack | Erste Auslösung | SOC | Zweite Auslösung | SOC |
|------|----------------|-----|------------------|-----|
| P3 | Scan 82 | 11.2% | Scan 521 | 10.4% |
| P4 | Scan 107 | 11.8% | Scan 528 | 10.3% |
| P1 | Scan 158 | 11.4% | Scan 526 | 10.1% |
| P2 | Scan 511 | 11.9% | Scan 530 | 10.5% |

Bit 1 tritt bei jedem Pack zweimal auf: einmal beim ersten Erreichen der DOD-Grenze (~11%), und nochmal beim finalen Tiefentladen unter 10.5%.

**Abschaltung bei Pack1 = 7.9%:**

Scan 540 (12:07:41): Pack1 erreicht 7.9% → 35100 wechselt auf 1 (Idle), Backup stoppt. Die anderen Packs standen noch bei 9.8-10.0%. Das Reserve-Limit gilt also **pro Pack**, nicht als Systemdurchschnitt — sobald das **erste** Pack ~8% erreicht, ist Schluss.

### Erkenntnisse DOD und Reserve

```
100% ─────────────── Voll
 │
 │   Normaler Betriebsbereich (Grid + Backup)
 │
12% ── DOD-Grenze ── Grid-Einspeisung stoppt (35100: 3→6)
 │
 │   Backup-Reserve (nur Notstrom, kein Grid)
 │
~8% ── Reserve-Limit ── Komplettabschaltung (pro Pack, nicht System!)
```

- **DOD = 88%** (100% → 12% nutzbar für Grid-Einspeisung)
- **Reserve = ~4%** (12% → ~8% zusätzlich für Backup/Notstrom)
- **Reserve-Cutoff ist pro Pack** — wenn EIN Pack 8% erreicht, stoppt alles (auch wenn andere noch 10% haben)
- **Unter 11% SOC: Rapid-Rotation** — Packs wechseln alle 40-60s statt alle 10 Minuten

### Inselbetrieb bestätigt

Der Venus kann Inselbetrieb (35100=4):
- 36101=0x0080 zeigt fehlende Netzverbindung an
- Backup wird aus Batterie versorgt (30001 negativ, 30006=0)
- Funktioniert bis zum Reserve-Cutoff (~8% pro Pack)
- Einschränkung: Bei Überlast (>2.5kW) während des Umschaltens auf Inselbetrieb kann das System crashen

---

## Backup unter DOD + EMS-Zwangsladung bei AC-Reconnect

**Scans:** `unter_dod_backup_lässt_sich_nicht_einschalten_zwangsladung_bei_ac_connect.csv` (21 Scans, scan_powercycle, 12:11-12:15) + `zwangsladung_unter_dod.csv` (7 Scans, 419 Register, 12:16-12:18)

**Ausgangslage:** System SOC ~7-8%, unter DOD (12%), AC war noch getrennt vom vorherigen Test (36101=0x0080).

### Backup lässt sich unter DOD nicht aktivieren

Scans 1-11 (File 1): Trotz aktiviertem Backup-Modus bleibt 35100=1 (Idle). 30007=0 (kein Backup-Output), 30005=0.4-0.8V (Backup-Ausgang inaktiv). Das EMS verweigert Backup-Aktivierung wenn SOC unter DOD liegt — die Notreserve wird geschützt.

### AC-Reconnect und Fault-Clearing

Scan 6 (12:13:18): 36101 springt von 0x0080 auf 0x0000 — AC wurde wieder verbunden. Der AC-Disconnect-Fault löscht sich selbstständig bei Reconnect (kein Reboot nötig). Trotzdem bleibt 35100=1 — kein sofortiger Zustandswechsel.

### Automatische Zwangsladung durch EMS

Scan 12 (12:14:19, ~60s nach AC-Reconnect): 35100 wechselt auf 2 (Charging). Ab Scan 13: 30001=~920W Ladeleistung, 30006 als int16 = -990W (Netz-Import). Kritisch: **42010=0** — die Zwangsladung wird NICHT über force_mode gesteuert, sondern ist internes EMS-Verhalten. Auch 42011 (charge_to_soc), 42020 (set_charge_power) und 42021 (set_discharge_power) bleiben alle 0.

### Detail-Daten aus vollem Register-Scan (File 2)

7 Scans während aktiver Zwangsladung zeigen:

- **Nur Pack 2 wird geladen:** 34104=3 (charging), alle anderen Packs 34004/34204/34304=0 (idle)
- **Pack SOCs:** P1=8.0%, P2=13→14%, P3=10%, P4=11%
- **Pack 2 Strom:** 34101=178-179 (17.8-17.9A Ladestrom)
- **Ladeleistung:** 30001=919-920W konstant
- **Grid-Import:** 30006 int16 = -990W (Verluste: ~70W für Inverter-Eigenverbrauch)

Auffällig: P1 hat den niedrigsten SOC (8%) aber P2 wird geladen (13→14%). Mögliche Erklärung: P1 wurde bereits vorher geladen (Zwangsladung läuft seit ~2 min), oder das EMS folgt der normalen Pack-Rotation statt den niedrigsten zuerst zu laden.

### Zusammenfassung Zwangsladung

```
Zustandsautomat unter DOD:
  SOC < DOD + AC getrennt → 35100=1 (Idle), Backup blockiert
  SOC < DOD + AC verbunden → ~60s Verzögerung → 35100=2 (Charging)
  Zwangsladung: ~920W, Grid-Import ~990W, 42010=0 (kein force_mode)
  Nur 1 Pack gleichzeitig geladen, normaler charge_status=3
```

Für HA-Integration: Wenn 35100=2 und 42010=0 und SOC < DOD → System befindet sich in EMS-Zwangsladung (nicht user-initiated).

---

## FW-Update 149.2 + 6 Packs

**Scans:** `fw_upgradr_auf_149_2.csv` (22 Scans, scan_powercycle) + `laden_von_unter_dod_mit_6_packs_und_massivem_soc_unterschied_nach_upgrade_auf_149_2_fw.csv` (5 Scans, 419 Register)

### FW-Versionsänderungen

Nur 30200 (EMS) hat sich geändert: 148→1492 (v149.2, neues Format x10). MPPT (30205=104), VNS (30202=115), BMS (30204=116) alle unverändert. Während des Updates war das Gerät ~25 Minuten offline (Scans 11-22 komplett leer).

### 6 Packs bestätigt

Pack 5 (34400-34433) und Pack 6 (34500-34533) zeigen jetzt volle Daten — identische Registerstruktur wie Pack 1-4. Pack 7 (34600+) bleibt leer.

- Pack 5: 54.03-54.27V, 37.5A Ladestrom, SOC 51.3→59.6%, 49 Zyklen, BMS v116
- Pack 6: 52.83-52.85V, 0A (idle), SOC 50.0%, 45 Zyklen, BMS v116

### 30212 und 31003/31004 sind Pack-abhängig

Korrektur zur früheren Analyse: Diese Register hängen von der angeschlossenen Pack-Anzahl ab, nicht von der FW-Version.

| Register | 4 Packs (FW148) | 6 Packs (FW149.2) |
|----------|-----------------|-------------------|
| 30212    | 2               | 5                 |
| 31003    | 0               | 5                 |
| 31004    | 0               | 1543 (0x0607)     |

Die genaue Bedeutung ist noch unklar — 30212=5 und 31003=5 bei 6 Packs ist kein direktes Mapping auf die Pack-Anzahl.

### EMS-Ladestrategie bei SOC-Unterschied

123 Scans über 3,5 Stunden zeigen die komplette Angleichungsstrategie:

1. P5 zuerst geladen (51→60%), dann P6 (50→60%) — niedrigster SOC zuerst, sequenziell
2. Danach Round-Robin durch alle 6 Packs, jeweils auf die nächste 10er-Stufe: 60→70→80→90%
3. Immer nur 1 Pack gleichzeitig aktiv (charge_status=3)
4. Ladeleistung: ~2030W bis 80% SOC, dann manuell auf ~900W reduziert, ab ~90% manuell auf ~440W

### Temperaturvergleich: mit vs. ohne Lüfter (Langzeit)

Pack 1 Zelltemperatur (34011) über 3,5h Laden:
- Start (ohne Lüfter): 39.7°C, steigend
- Peak (ohne Lüfter): **41.9°C** bei Scan 46 (~16:27, nach ~75 min)
- Nach Lüfter-Aufsetzen: kontinuierlicher Abfall
- Ende (mit Lüfter): **36.4°C** bei Scan 123 (~18:35)

Der Lüfter senkt die Zelltemperatur um ~5°C.

### Inverter-Temperaturen (35000/35001/35002)

Die Register 35000 (Inverter-Innentemp), 35001/35002 (MOS-Temps) zeigen die tatsächliche Gehäusewärme — und korrelieren direkt mit der Ladeleistung:

| Ladeleistung | 35000 (intern) | 35001/35002 (MOS) |
|-------------|----------------|-------------------|
| 2030W       | 50→54°C (steigend) | 53→54°C        |
| 1380W       | ~37°C          | ~37°C             |
| 900W        | ~33°C          | ~33°C             |
| 440W        | ~31°C          | ~31°C             |

Peak: **54.2°C** (35001) nach ~17 Minuten bei 2kW Dauerlast. 35001 und 35002 sind in allen Scans identisch. 30002 und 30003 sind Spiegel von 35000 bzw. 35001.

**Anomalie Pack 4+5:** Bei Pack 4 und Pack 5 ist 34x12 (min_cell_temp) teilweise höher als 34x11 (max_cell_temp). Möglicherweise sind die Register bei bestimmten Packs anders belegt, oder max/min beziehen sich auf verschiedene Sensorgruppen.

---

## BMS-FW-Update 116 → 117.7

**Scan:** `nach_bms_upgrade_auf_117_7_fw.csv` — 4 Scans, 15:43-15:48 (2026-07-09), 6 Packs, ~50% SOC, sonst Standby/Idle.

### Nur BMS-Version betroffen

Von allen 419 gescannten Registern haben sich ausschließlich die BMS-Versionsregister geändert. Alle anderen Firmware-Versionsregister blieben unverändert:

| Register | Vorher | Nachher | Bedeutung |
|----------|--------|---------|-----------|
| 30200 (ems_version) | 1492 | 1492 | unverändert (Control-FW weiterhin 149.2) |
| 30202 (vns_version) | 115 | 115 | unverändert (VNS weiterhin v115) |
| 30204 (bms_version) | 116 | **1177** | **v116 → v117.7** |
| 30205 (mppt_version) | 104 | 104 | unverändert |
| 34010/34110/34210/34310/34410/34510 (packX_bms_version) | 116 | **1177** | alle 6 Packs synchron aktualisiert |
| 37012 (bms_version_mirror) | 116 | **1177** | Spiegel bestätigt |

### x10-Encoding-Muster bestätigt (2. Beobachtung)

Der Rohwert-Sprung 116→1177 folgt exakt dem gleichen Muster wie ems_version beim Control-FW-Update auf v149.2 (147→1492, s. Abschnitt „FW-Update 149.2 + 6 Packs"): Solange die Versionsnummer keine Nachkommastelle hat, wird der reine Integer als Rohwert verwendet (116 = v116). Sobald eine Nachkommastelle dazukommt, schaltet das Register auf ×10-Kodierung um (1177 = v117.7). Das ist jetzt bei zwei unabhängigen Versions-Registern (ems_version, bms_version) beobachtet worden — vermutlich ein generelles Verhalten der Descriptor-Tabelle für alle `_version`-Register, nicht nur ein Einzelfall.

### Cross-Validierung mit Static Analysis

Die zuvor per Ghidra analysierte BMS-Binary (`20251010135647565eb2036.bin`, s. `BMS_FW_Analyse_v117.7.md`) hatte bereits einen hardcoded Versionswert `0x499` = 1177 dezimal enthalten — also v117.7, bevor das Update live ausgerollt wurde. Der jetzige Live-Scan bestätigt exakt diesen vorhergesagten Wert. Die Datei war ursprünglich fälschlich als „v177.7" betitelt (Tippfehler); korrigiert auf v117.7.

---

## Noch offene Scan-Szenarien

### Empfohlene weitere Scans
1. **PV-Laden (Solar)** — Falls PV angeschlossen: MPPT-Register 30020-30040 sollten dann Werte zeigen. Komplett anderer Ladepfad.
2. ~~**Fehler-Provokation**~~ — teilweise erledigt: Battery-Disconnect-Test hat 36100 Bit4 und 36101 Bit7 aufgedeckt. Schutzregister 34x08/34x09 bleiben auch bei Disconnect 0 — reagieren offenbar nur auf BMS-interne Events. Echte Überlast/Übertemp noch offen.
3. **Force-Mode Wechsel** — 42010 während des Scans umschalten (Laden→Entladen→Auto) und dabei scannen. Zeigt Übergangsregister.
4. **Mit PV Leistung Scannen** — Da noch kein Scan mit PV Leistung stattgefunden hat müssen die Lade-, Entlade- und Backup-Sczenarien noch gescannt und ergänzt werden. insbesondere im Hinblick auf die Register wo es um AC seitig einspeisen und bezug geht sowie Batterieleistung.
