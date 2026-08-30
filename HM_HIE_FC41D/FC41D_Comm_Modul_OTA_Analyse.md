# FC41D Kommunikationsmodul — OTA-Firmware-Analyse

Analyse der OTA-`.rbl`-Dateien des WLAN-/Kommunikationsmoduls (Quectel/Realtek **FC41D**) des
Marstek Venus D. Zwei Firmware-Stände liegen vor:

| Kürzel | Version | Datei | Größe | SHA-256 (Anfang) |
|--------|---------|-------|-------|------------------|
| **ALT** (installiert) | 202409090159 | `fc41d_archive/HM_HIE_FC41D_remote_ota_20260819T194315Z_0d10d2a4d467.rbl` | 679.696 B | `0d10d2a4d467…` |
| **NEU** (Rollout-Update) | 202512040647 | `fc41d_archive/fc41d_new_202512040647.rbl` | 682.928 B | `63c2f353130634ce…` |

- **ALT** stammt von der statischen Basis-URL `http://www.hamedata.com/app/download/neng/HM_HIE_FC41D_remote_ota.rbl`
  (Server-Header: Last-Modified 2025-03-10, ETag `67ce80f4-a5f10`) — das ist die **bereits installierte** Version.
- **NEU** wurde über die App-Cloud-API abgegriffen (`getCheckWifiOta`, siehe `Hamedata_App_API_Recon.md`)
  und liegt auf Marsteks CDN: `https://static-eu.marstekenergy.com/uploads/ota/20251227/202512271054507d95a7957.rbl`.

---

## 1. RBL-Header (Klartext) — Format & Vergleich

Beide Dateien beginnen mit einem **unverschlüsselten Realtek-Bootloader-Header** (`RBL`), gefolgt vom
verschlüsselten Payload. Header-Layout:

```
0x00  "RBL\0"                         Magic (Realtek/RTL8710-Familie)
0x04  02 01 00 00                     Formatversion (v1.2)
0x08  u32 (LE)                        Build-Timestamp (Unix, UTC)  — = Versionsnummer
0x0c  "app\0"                         Image-/Segmentname
0x10  00 00 00 00 00 00 00 00
0x18  u32                             differiert je Build → vermutl. CRC/Prüfsumme des Payloads
0x1c  "FC41DAAR18A0xM02_HMVxx\0"      Modul-/HW-Variantenkennung
0x34  "0000000000000…"               Reserved/Padding (UID-Platzhalter, bei generischem Image leer)
~0x60 …                              AES-verschlüsselter Payload (Entropie ~8,0)
```

### Direktvergleich ALT ↔ NEU
| Feld | ALT (installiert) | NEU (Update) |
|------|-------------------|--------------|
| Version | 202409090159 | **202512040647** |
| Build @0x08 (UTC) | 2024-09-09 02:00:01 | **2025-12-04 06:47:58** |
| Magic / Format | `RBL\0` `02 01 00 00` | `RBL\0` `02 01 00 00` |
| Image-Name @0x0c | `app\0` | `app\0` |
| @0x18 (CRC?) | `6337c7ea` | `63c779c3` |
| **Modul-ID @0x1c** | `FC41DAAR18`**`A04M02`**`_`**`HMV02`** | `FC41DAAR18`**`A05M02`**`_`**`HMV01`** |
| Payload-Entropie | 7,99976 | 7,99973 |

**Wichtige Beobachtungen:**
- **Der Build-Zeitstempel IST die Versionsnummer.** ALT: 2024-09-09 01:59/02:00 = `202409090159`.
  NEU: 2025-12-04 06:47 = `202512040647`. Beide Dateien damit als authentisch bestätigt.
- **Die Modul-ID hat sich geändert:** `A04M02→A05M02` (Firmware-/HW-Revision) und `HMV02→HMV01`.
  `HMVxx` ist vermutlich der Hardware-Variantencode, gegen den der Server kompatible Images matcht.
- Gleicher Wrapper, gleiche Struktur → das FC41D nutzt durchgängig den Realtek-RBL-Container.

---

## 2. Wie das Modul-Update tatsächlich ausgeliefert wird

Bestätigt (2026-08-20): Der **eigentliche Update-Weg** ist NICHT die statische www.hamedata.com-Datei,
sondern die App-Cloud-API:

1. Die App fragt `GET /ems/api/v1/getCheckWifiOta` mit der `devid` des Geräts ab.
2. Ist das Gerät für ein Update **freigeschaltet** (Rollout-Whitelist), liefert der Server
   `{"version":…,"url":"https://static-eu.marstekenergy.com/uploads/ota/…/<hash>.rbl"}`.
3. Die neue `.rbl` wird von diesem CDN geladen und dann per **BLE** (App→Modul) bzw. per
   **MQTT-gepushter URL** (`fc41d_url=`) ans Modul übertragen.

Details + reproduzierbarer Aufruf: **`Hamedata_App_API_Recon.md`**.

---

## 3. Warum der frühere Firmware-Checker das Modul nicht sah

- Der **Geräte**-Endpunkt `getDateInfoeu.php` (Klartext-HTTP, siehe §6) kennt zwar `fcv` (FC41D-Version),
  ist aber reiner **Zeit-Sync + Update-Flags** und liefert keine Download-URL.
- Der zunächst vermutete `checkSmallBalconyOTA` ist der **System-Firmware**-Katalog (control/bms/micro/
  mppt) und enthält **kein Comm-Modul**.
- Erst `getCheckWifiOta` ist der richtige Comm-Modul-Endpunkt.
- Zusätzlich: Die Modulversion ist ein **12-stelliger Zeitstempel**, kein Integer wie 150/118/116 —
  ein naiver „neuer als"-Vergleich schlägt fehl.

---

## 4. Verschlüsselung des Payloads

Alles ab dem Header (~Offset 0x60, Payload) ist **hochentropisch verschlüsselt** — in ALT wie NEU:

- Entropie **7,9997 bit/Byte** (8,0 = perfekt zufällig)
- Keine wiederholten 16-Byte-Blöcke → falls Blockchiffre, **kein ECB-Muster**
- Payload-Größe durch 16 teilbar (blockchiffre-kompatibel)
- Chi-Quadrat im Bereich echter Gleichverteilung

**Der bekannte Control-Key `hamedatahamedata` (AES-128-ECB) entschlüsselt den Payload NICHT** —
getestet an mehreren Startoffsets, plus Kandidaten aus der Modul-ID und Null/FF-Keys; Entropie bleibt
~8,0. Das FC41D (eigener Realtek-WiFi-SoC mit eigener Bootloader-Kette) nutzt einen **anderen Schlüssel
und/oder ein anderes Verfahren** als der STM32-Control-Telemetrie-Stack.

---

## 5. Lässt sich der Schlüssel finden?

**Reiner Brute-Force: nein.** Bei AES-128 ist der Schlüsselraum 2^128 — mit keiner denkbaren Hardware
angreifbar. Ein Erkennungskriterium (entschlüsselter `app`-Payload müsste ARM/Xtensa-Code + Strings
enthalten) existiert zwar, hilft aber bei diesem Schlüsselraum nicht.

**Realistisch ist nur Schlüssel-*Extraktion*** — genau wie beim Control-AES-Key `hamedatahamedata`,
der per rohem Byte-Scan im Image gefunden wurde, nicht per Rechenangriff:

1. **Key aus Firmware/Loader ziehen.** Der Entschlüsselungscode läuft im Modul selbst oder in dessen
   Bootloader. Wer die `.rbl` vorverarbeitet, hat den Key.
2. **Realtek-RBL-Struktur nutzen.** Das Format ist dokumentiert (Realtek Ameba / RTL8710). Ist nur ein
   Standard-Realtek-Image in einen Krypto-Wrapper gepackt, ist die *Wrapper*-Schicht der Angriffspunkt.
3. **Schwache Ableitung suchen.** Lohnend nur, falls der Key kurz/ableitbar ist (z.B. aus Modul-ID oder
   Seriennummer via einfachem KDF) → Wörterbuch-/Strukturangriff über wenige tausend Kandidaten. Der
   `hamedatahamedata`-Fund zeigt: Marstek neigt zu schwachen Keys.

**Neu als Angriffsfläche:** Wir haben jetzt **zwei** Firmware-Stände. Die Klartext-Header bestätigen
die Struktur; ein Payload-Diff ist erst nach Entschlüsselung sinnvoll, aber zwei Chiffrate desselben
Verfahrens können bei der Key-Suche helfen.

---

## 6. Live-Verkehr bestätigt (RPi3B+-Mitschnitt, 2026-08-20)

Der Marstek wurde über einen dedizierten Raspberry-Pi-AP (`MarstekCap`) geroutet. Damit sind die
Cloud-Endpunkte des **Geräts** empirisch belegt:

### 6.1 Versions-/Zeit-Check — Klartext-HTTP (Port 80)
```
DNS:  eu.hamedata.com  ->  3.122.27.237   (AWS eu-central-1, Frankfurt)
GET   http://eu.hamedata.com/app/neng/getDateInfoeu.php
      ?uid=<REDACTED>&fcv=202409090159&aid=VNSD-0&sv=150&sbv=118
      &mv=101&cert=0&boot=18&inv=116&mpptv=104
User-Agent: quectel-fc41d
```
| Feld | Wert | Bedeutung |
|------|------|-----------|
| fcv | 202409090159 | Comm-Modul-FW (= .rbl-Build 2024-09-09) |
| sv / sbv / inv / mpptv | 150 / 118 / 116 / 104 | Control / BMS / Micro / MPPT |
| boot | 18 | Bootloader |
| **cert** | **0** | **Zertifikatsprüfung AUS → bestätigt VERIFY_NONE** |

Antwort (HTTP 200, chunked): `_2026_08_20_00_12_20_04_0_0_0`
= `_JJJJ_MM_TT_HH_MM_SS_<Wochentag>_<flag1>_<flag2>_<flag3>`. Reiner **Zeit-Sync**; die drei Flags
`0_0_0` = kein Update. Liefert **keine** Download-URL (dafür ist getCheckWifiOta zuständig, §2).

### 6.2 Push-Kanal — AWS IoT MQTT über TLS (Port 8883)
```
a40nr6osvmmaw-ats.iot.eu-west-3.amazonaws.com -> 13.37.135.170 (AWS Paris), :8883 TLS
```
Persistente MQTT-Verbindung; hierüber pusht die Cloud Befehle/den OTA-Trigger (`fc41d_url=`).

### 6.3 Lokales Discovery
```
UDP  <marstek>:22222 -> <broadcast>:12345   (len 50, App-Discovery im LAN)
```

---

## 7. Status & nächste Schritte

**Erledigt:**
- Beide Firmware-Stände (ALT installiert, NEU Rollout) beschafft und archiviert.
- OTA-Auslieferungsweg vollständig verstanden (getCheckWifiOta → static-eu-CDN → BLE/MQTT ans Modul).
- Header dekodiert, Authentizität + Modul-ID-Änderung dokumentiert.

**Offen:**
- Payload ist AES-verschlüsselt; für Klartext-Code fehlt der Modul-Key (Key-Extraktion aus Loader/
  Modul-FW oder schwache Ableitung — §5).

**Laufend:**
- RPi-Dauermitschnitt + BLE-HCI-Snoop fangen ein echtes, dem Gerät zugewiesenes Update automatisch
  (`BLE_Comm_Modul_Update_Mitschnitt_Anleitung.md`, `RPi3Bplus_Marstek_Capture_Anleitung.md`).
