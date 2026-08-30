# Cloud-Upload-Payload v150 — Feldreferenz

Was der Venus D unter Firmware v150 an
`https://api-eu.marstekcloud.com/data-upload/v1/venus/<uid>` schickt.

**Erhebungsmethode:** kein Mitschnitt gegen die echte Cloud, sondern ein lokaler
Endpunkt, auf den das Geraet per DNS-Umleitung zeigt und der mit `{"code":0}`
antwortet (s. `Control_FW_Analyse_app_0150_0805_115146.md` §4a sowie
<https://github.com/sphings79/Marstek-offline-endpoint>). Aufgezeichnet am
2026-08-25 an einem Venus D, Control 150 / BMS 118 / Inverter 116 / MPPT 104.

**Regionskuerzel bestaetigt:** `eu`. Das Geraet fragte
`http://eu.hamedata.com/app/neng/getDateInfoeu.php?…` — beide `%s` im
Firmware-Template werden mit demselben Kuerzel gefuellt. Damit ist auch
`api-eu.marstekcloud.com` nicht mehr nur erschlossen, sondern gemessen.

## Transport

| | |
|---|---|
| Methode | `POST` |
| Pfad | `/data-upload/v1/venus/<uid>` — `uid` identisch mit dem Parameter aus `getDateInfo` |
| Body | **ein** Formularfeld `d`, darin ein URL-kodierter Query-String |
| Groesse | ~770 Byte |
| Intervall | im Testzeitraum unregelmaessig, ausgeloest ueber die Zustandsmaschine in `FUN_08015bd0` |

## Rohbeispiel

`di`, `sn` und `ip` sind durch Platzhalter ersetzt.

```
d=di=<uid>&sn=<mac>&to=1561&td=1933&ed=0&em=1561&gd=241&gm=1933&wm=10&gy=0&gp=0
&go=591&gt=3&gf=500&gv=2424&ct=0&bs=3&bp=299&eb=0&dn=150&bu=0&t1=268&t2=273&t3=0
&vc=13,14,3248,3245,5,14,3187,3183,7,4,3276,3272,1,6,3281,3279,5,0,3247,3245,3,1,3264,3262
&tc=249,254,252,253&dt=2026-08-25%2004:01:14&no=48&e1=0&ws=39&mt=0&ty=4&sv=0
&mc=2500&md=2500&sc=19&ci=500&ri=500&bv=5247&bi=-121&pb=-634&ds=12&ph=0&bt=1&mq=0
&cy=4&cw=0&cp=0,0,0,0&bm=118&ce=0,0,0,0&up=0&ap=0&nt=1&iv=116&et=4&ea=800
&pv=99,0,0,0,99,0,0,0,99,0,0,0,99,0,0,0,0,0&sk=2,0,6,63,0,0,0,0,0,0,118,118,118,118,118,118
&mv=104&me=0&ma=0&fu=0,0&ms=0,1,0,0,0&im=0,-3,0,0,74,0,590,241,576,2500,57&hd=0,0,0
&pw=600&bl=1&as=0&bke=0,0,0&bkd=0,0,0&ip=<ip>&bt_p=0,0&ival=5&soh=0
```

## Bestaetigte Felder

Bestaetigt heisst: derselbe Wert wurde im selben Zeitraum aus einer zweiten
Quelle gelesen — ueber Modbus (Home Assistant) oder aus der Statusmeldung des
Geraets. Reine Plausibilitaet zaehlt hier nicht.

| Key | Bedeutung | Skalierung | Beleg |
|---|---|---|---|
| `di` | Geraete-UID | — | identisch mit `uid` in `getDateInfo` und dem Upload-Pfad |
| `sn` | Seriennummer/MAC | — | Form `aabbccddeeff` = MAC-Notation |
| `ip` | eigene IP | — | stimmt mit der Quell-IP der Anfrage ueberein |
| `dt` | Geraeteuhr | — | URL-kodiert, `YYYY-MM-DD hh:mm:ss` |
| `wm` | **Modus-Byte** | — | `10` = `0x0A`; identisch mit dem Byte hinter Register 42000/43000 |
| `sc` | Ladezustand | % | 19 gegen Statusmeldung „SoC 19 %" |
| `pb` | Batterieleistung | W | −634 gegen Modbus −629 (Zeitversatz) |
| `bv` | Batteriespannung | ×0,01 V | 5247 → 52,47 V |
| `bi` | Batteriestrom | ×0,1 A | −121 → −12,1 A |
| `go` | AC-/Netzleistung | W | 591 gegen Statusmeldung „AC 591 W · Netz 591 W" |
| `gv` | Netzspannung | ×0,1 V | 2424 → 242,4 V gegen Modbus 242,6 V |
| `gf` | Netzfrequenz | ×0,1 Hz | 500 → 50,0 Hz gegen Modbus 49,9 Hz |
| `mc` | max. Ladeleistung | W | 2500 gegen Register 44002 |
| `md` | max. Entladeleistung | W | 2500 gegen Register 44003 |
| `t1` | Temperatur intern | ×0,1 °C | 268 → 26,8 °C |
| `t2` | Temperatur MOS | ×0,1 °C | 273 → 27,3 °C |
| `tc` | Zelltemperaturen | ×0,1 °C | 254 → 25,4 °C gegen Statusmeldung „Zelle 25,4 °C" |
| `dn` | Control-Firmware | — | 150 |
| `bm` | BMS-Firmware | — | 118 |
| `iv` | Inverter-Firmware | — | 116 |
| `mv` | MPPT-Firmware | — | 104 |

**`wm` ist der interessanteste Eintrag.** Es ist dasselbe Modus-Byte, das
Register 42000 und 43000 teilen (s.
`Modbus_RS485_TCP/Register_Persistenz_RAM_vs_EEPROM_v150.md` §6a). Faellt es
geraeteseitig zurueck, ist das ab sofort auch im Upload sichtbar — mit
Zeitstempel und ohne Polling.

## Noch nicht zugeordnet

31 Keys, hier bewusst ohne Deutung:

```
bp bs bt bu ci ct cy ds e1 eb ed em gd gm gp gt gy ival mq mt no ph ri soh
sv t3 td to ty vc ws
```

dazu die Listenfelder `cp ce fu ms im hd pv sk bke bkd bt_p`.

Zwei Warnungen dazu. `sv` steht im Payload auf `0`, waehrend derselbe
Parametername in der `getDateInfo`-URL die Control-Version `150` traegt — **die
Namen sind nicht ueber die Endpunkte hinweg konsistent.** Und `vc` sieht nach
Zellspannungen in mV aus (Werte um 3250), die Gruppierung ist aber ungeklaert.

## Die Zeit-URL `getDateInfoeu.php` — Parameter sind Versionsstaende

*(Feldmitschnitt 2026-08-25 am eigenen Offline-Endpunkt. Anders als der Upload
laeuft diese Abfrage ueber **plain HTTP auf Port 80** zu `eu.hamedata.com`.)*

```
GET /app/neng/getDateInfoeu.php?uid=<device-id>&fcv=202409090159&aid=VNSD-0
    &sv=150&sbv=118&mv=101&cert=0&boot=18&inv=116&mpptv=104
```

| Parameter | Bedeutung | Register | Beleg |
|---|---|---|---|
| `uid` | Geraete-ID (24 Ziffern) | — | identisch mit dem Pfadsegment des Uploads |
| `aid` | Modellkennung `VNSD-0` | — | entspricht dem Image-Namen `VNSD-0_app_0150_…` |
| `fcv` | Kommunikationsmodul-Firmware | — | Datumsform `202409090159` |
| `sv` | Control-App-Version = 150 | **30200** `ems_ver` | Registerkarte, Konfidenz hoch |
| `boot` | EMS-/Control-**Bootloader** = 18 | **30201** `ems_boot_ver` | `0x20000038`, Versions-Debug-Print `0x08036F52`; Live-Scans zeigen 18 |
| `inv` | Micro-Inverter (VNS) = 116 | **30202** `vns_ver` | `0x2000015E` |
| `sbv` | BMS = 118 | **30204** `bms_ver` | `0x20014FD2` |
| `mpptv` | MPPT = 104 | **30205** `mppt_ver` | `0x20000188` |
| `cert` | 0 | — | konsistent mit `Authmode 0` in `HTTPS_TLS_Session_Init` |

**Offen:** `mv=101`. Im **Upload-Payload** steht `mv` fuer die MPPT-Version (dort
`mv=104`, s. Feldtabelle oben) — in dieser URL kann es das nicht sein, weil
`mpptv=104` bereits danebensteht. Welcher Stand mit 101 gemeint ist, ist nicht
belegt. `vns_boot_ver` (30203, Wert 106) und die Pack-Versionen tauchen in der
URL nicht auf.

**Korrektur:** `boot` wurde zunaechst als Startzaehler gelesen. Das ist falsch —
alle uebrigen Parameter der Reihe sind Versionsstaende, und der Wert stimmt mit
Register 30201 ueberein.

## Methode zum Weiterarbeiten

Ein DEV-Register aendert seinen Wert, danach im naechsten Payload nach genau
diesem Wert suchen. Bleibt ueber zwei, drei Aenderungen ein einziger Key uebrig,
ist die Zuordnung sicher. Ein Decoder-Skript dafuer liegt im Endpoint-Repo
(`decode.py`).

**Das funktioniert aber nicht fuer jedes Register.** Gegenbeispiel aus der
Praxis: 37021/37022 (Inverter-Struct `0x20014F4C` +0x2c) taucht im Upload nicht
auf. Die Funktion, die den Wert liest, heisst zwar `Cloud_Report_FillGridData`,
hat aber genau einen Aufrufer — `MQTT_BuildEsDataResponse`. Der Wert geht also
an **MQTT**, nicht an den HTTP-Upload. Wer alles sehen will, was das Geraet
herausgibt, kommt am MQTT-Pfad nicht vorbei, und der ist mit `Authmode 2` samt
Client-Zertifikat gesichert.

Den Upload-Datensatz selbst baut `MQTT_Telemetry_Struct_Builder` (trotz des
Namens), aufgerufen unmittelbar vor `Telemetry_History_Record_Push`. Das ist der
Einstiegspunkt, wenn die Feldzuordnung statt empirisch aus dem Code kommen soll.
