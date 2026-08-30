# Hamedata-App API-Recon — Marstek Venus D Kommunikationsmodul-OTA

Reverse Engineering der Marstek-App, um die **Kommunikationsmodul-(FC41D-)Firmware** direkt aus der
Cloud zu ziehen — ohne auf den gerätespezifischen Rollout warten zu müssen. **Ergebnis: gelöst.**

> **Anonymisierung:** In diesem Dokument sind reale Kennungen durch Platzhalter ersetzt.
> `<TOKEN>` = Account-Access-Token · `<UID>` = Account-User-ID · `<DEVID>` = Geräte-ID ·
> `<MAILBOX>` = Account-Mailadresse. Die realen Werte gehören nicht in die Doku.

---

## 1. Die App

- Paket `com.hamedata.marstek` (intern `com.hamedata.powerx.cross_power_x`) — **Flutter**-App.
- Business-Logik im **Dart-AOT-Snapshot** `lib/arm64-v8a/libapp.so` (Klartext-String-Literale).
- Archiviert: `fc41d_archive/` → `marstek_base.apk` (Flutter-Hülle, DEX),
  `marstek_arm64.apk` (enthält `libapp.so`), `btsnoop_ble_parser.py`.
- API-Hosts: `eu.hamedata.com` (prod), `eu-dev.hamedata.com`, `eu-staging.hamedata.com`,
  `www.hamedata.com` (Alt-Endpunkte). Firmware-CDN: `static-eu.marstekenergy.com`.

---

## 2. Authentifizierung (empirisch)

- **Token MUSS als Query-Parameter** `?token=<TOKEN>` mitgegeben werden:
  - Token im `Authorization: Bearer`-Header → `{"code":8,"msg":"Unauthorized"}`
  - Token im POST-Body → `{"code":8,"msg":"无访问权限"}` (keine Berechtigung)
  - Token als `?token=` → **kommt durch**
- Der Token ist **NICHT kontogebunden**: Ein gültiger Token akzeptiert auch fremde `uid`/`devid`.
  → Man kann mit der `devid` eines **freigeschalteten** Geräts abfragen und bekommt dessen
  zugewiesene Firmware-URL, unabhängig davon, wem der Token gehört.
- Die App sendet zusätzlich Header `X-User-ID`, `X-Client-Type`, `X-Client-Version`, `X-App-Version`,
  `X-Device-Id` — für die OTA-Endpunkte aber nicht zwingend.

---

## 3. Gelöst: Kommunikationsmodul-OTA-URL abgreifen

### Der richtige Endpunkt
`GET https://eu.hamedata.com/ems/api/v1/getCheckWifiOta`
(„WifiOta" = WLAN-/Kommunikationsmodul = FC41D). Der zunächst vermutete `check_fc4_ota.php` war
falsch — siehe §5.

### Pflicht-Parameter
Der Server meldet fehlende Parameter einzeln als `Undefined array key "<name>"`:

| Parameter | Wert | Anmerkung |
|-----------|------|-----------|
| `token` | `<TOKEN>` | im Query (nicht Bearer/POST) |
| `uid` | `<UID>` | Account-User-ID |
| `devid` | `<DEVID>` | **wählt das Gerät** — entscheidend |
| `version` | z.B. `202001010000` | Wert **egal** (Gating ist gerätegebunden, s.u.) |
| `device_type` | `VNSD-0` | Modellcode Venus D |
| `lang` | `English` | |
| `mailbox` | `<MAILBOX>` | Account-Mail |
| `click` | `false` | **read-only** — `true` würde das echte Update auslösen (nicht verwenden) |

### Funktionierender Aufruf
```bash
MAIL='<MAILBOX>'
curl -sk -G 'https://eu.hamedata.com/ems/api/v1/getCheckWifiOta' \
  --data-urlencode 'uid=<UID>' \
  --data-urlencode 'devid=<DEVID>' \
  --data-urlencode 'lang=English' \
  --data-urlencode 'token=<TOKEN>' \
  --data-urlencode 'device_type=VNSD-0' \
  --data-urlencode "mailbox=$MAIL" \
  --data-urlencode 'click=false' \
  --data-urlencode 'version=202001010000'; echo
```

### Antwort (devid eines freigeschalteten Geräts)
```json
{"code":1,"show":0,"msg":"ok","data":{
  "version":"202512040647",
  "url":"https://static-eu.marstekenergy.com/uploads/ota/20251227/202512271054507d95a7957.rbl"}}
```
→ **Neue FC41D-Firmware `202512040647` (Build 2025-12-04)** vs. installiert `202409090159`.
Der CDN-Download ist **unverschlüsselt und ohne Auth**. Gesichert als
`fc41d_archive/fc41d_new_202512040647.rbl`. Header-/Payload-Analyse: `FC41D_Comm_Modul_OTA_Analyse.md`.

---

## 4. Kernerkenntnis: Gating ist gerätegebunden, nicht versionsgetrieben

Belegt durch Gegentests:

| Test | Ergebnis |
|------|----------|
| `getCheckWifiOta` mit **eigener** (nicht freigeschalteter) devid | `{"code":0,"show":1,"msg":"固件已经最新"}` (= aktuell, kein Update) |
| `getCheckWifiOta` mit **freigeschalteter** devid | liefert `version` + `url` (s.o.) |
| `checkSmallBalconyOTA` mit **eigener** uid, `version=0` | leere Liste (`data.control=""`, …) |
| `checkSmallBalconyOTA` mit **freigeschalteter** uid, `version=0` | volle Liste (control/bms/micro-URLs) |

**Der `version`-Parameter erzwingt nichts.** Der Server kennt die **dem Gerät zugewiesene** Ziel-
Firmware (Rollout-Whitelist) und liefert nur für freigeschaltete Geräte eine URL. Deshalb bekommt
ein nicht freigeschaltetes Gerät nie eine Antwort — egal welche Version man vorgibt.
**Konsequenz:** Man muss mit der `devid` eines bereits **freigeschalteten** Geräts abfragen.

---

## 5. Sackgassen (dokumentiert, damit sie nicht wiederholt werden)

- **`/app/neng/check_fc4_ota.php`** — vermeintlicher Comm-Modul-Check. Auth per `?token=` klappt,
  aber der Endpunkt verlangt einen unbekannten Pflichtparameter (`{"code":"0","msg":"参数为空"}` =
  Parameter leer) für ALLE geratenen Namen (devid, mac, snn, fc4V, fcv, fc41d_ver, …). Falscher Weg —
  `getCheckWifiOta` ist der richtige.
- **`getDateInfoeu.php`** (Klartext-HTTP am Gerät) — nur Zeit-Sync + Update-Flags, liefert keine URL
  und ignoriert die gemeldete Version.
- **MITM des Handys** — Android 7+ vertraut keinen User-CA-Zertifikaten → mitmproxy scheitert an der
  App (ohne Root/Repacking).
- **logcat** — der Release-Build gibt keine Dart-Logs aus (nur Android-System-Rauschen).

---

## 6. System-Firmware-Katalog (zum Vergleich)

`GET https://eu.hamedata.com/ems/api/v2/checkSmallBalconyOTA` — das **System-FW**-Pendant
(control/bms/micro/mppt), **nicht** das Comm-Modul.

Parameter: `uid`, `lang`, `token`, `device_type=VNSD-0`, `mailbox`, `click=false`,
`is_fourDigit={"control":false,"bms":false,"micro":false,"mppt":false}`, `m`, `sbv`, `mppt`, `inv`.

Antwort-Struktur:
`data.{control,bms,micro,mppt,dcdc,bms_pack1,bms_pack2,led,charger}` →
je `{version, url, crc, size, force_update, is_boot, is_http, remark, …}`.
Für ein freigeschaltetes Gerät liefert es die `control/bms/micro`-`.bin`-URLs auf
`static-eu.marstekenergy.com`.

> **⚠️ `click=true` NICHT verwenden** — entspricht dem echten „Update"-Klick und kann auf dem
> Zielgerät ein OTA auslösen. Für reine Recherche immer `click=false`.

---

## 7. Weitere OTA-Endpunkte (in libapp.so gefunden, für später)

```
/ems/api/v1/getCheckWifiOta        ← Comm-Modul (FC41D)          [gelöst]
/ems/api/v2/checkSmallBalconyOTA   ← System-FW (Venus D)         [gelöst]
/ems/api/v1/checkMicroDeviceOTA    ← Micro-Inverter
/ems/api/v1/checkAcCoupleOta       ← AC-Coupler
/ems/api/v2/getScreenOtaUpdate     ← Display/Screen
/ems/api/v2/getCommonOtaUpdate     ← generisch (braucht 'version')
/ems/api/v1/checkDeviceVersion, /ems/api/v1/getDeviceVersion
/ems/api/v1/getCheckAppUpdate      ← App-Update
```

---

## 8. BLE-Fallback (geräteunabhängig)

Beim echten, dem Gerät zugewiesenen Comm-Modul-Update lässt sich die Firmware auch **ohne** Cloud-API
mitschneiden: HCI-Snoop des BLE-Transfers, GATT-Handle `0x0012` (FF01) + `0x0018` (FF06), Frames nach
`73/LEN/23/CMD/…/XOR` zerlegen → Firmware-Blob. Siehe `BLE_Comm_Modul_Update_Mitschnitt_Anleitung.md`.
