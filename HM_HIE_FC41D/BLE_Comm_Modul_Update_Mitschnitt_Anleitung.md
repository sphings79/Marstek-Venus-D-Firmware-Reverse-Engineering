# Bluetooth-Mitschnitt des Kommunikationsmodul-Updates (FC41D) — Android + Pi

**Ausgangslage:** Das Update des Kommunikationsmoduls läuft NICHT über die Cloud/WLAN
(`getDateInfo` meldet dauerhaft „kein Update"), sondern über einen **eigenen Button in der App**,
der die Firmware per **Bluetooth (BLE)** vom Handy ins FC41D-Modul schiebt. Im Flugmodus scheiterte
es, weil die App die `.rbl` erst aus dem Netz laden muss → **Update mit Internet AN durchführen.**

**Methode:** Androids eingebauter **Bluetooth-HCI-Snoop-Log** zeichnet auf HCI-Ebene auf — also
*hinter* der BLE-Funkverschlüsselung. Wir sehen die GATT-Writes im Klartext. Die App-Payload selbst
kann trotzdem die verschlüsselte `.rbl` sein; Transportweg + Blob bekommen wir aber sicher.

Analyse headless auf dem Pi 3 B+ mit `adb` + `tshark` (tshark bereits installiert).

---

## 1. Android vorbereiten (einmalig)

1. **Entwickleroptionen freischalten:** Einstellungen → „Über das Telefon" → 7× auf **Build-Nummer** tippen.
2. **Entwickleroptionen** öffnen:
   - **USB-Debugging** einschalten.
   - **„Bluetooth-HCI-Snoop-Protokoll aktivieren"** einschalten (bei manchen Handys ein Dropdown:
     dann **„Aktiviert" / „Full" / „All"** wählen, nicht „Filtered").
3. **Wichtig:** Damit der Snoop-Log wirklich greift, **Bluetooth einmal aus- und wieder einschalten**
   (bei einigen Geräten sogar Neustart). Der Log startet dabei frisch.

---

## 2. Pi vorbereiten

```bash
sudo apt update
sudo apt install -y adb
```
Handy per **USB-Kabel** an den Pi. Am Handy erscheint „USB-Debugging zulassen?" → **Zulassen**
(Haken „Immer von diesem Computer"). Dann:
```bash
adb devices          # muss das Geraet als "device" zeigen (nicht "unauthorized")
```
Snoop-Status gegenchecken (sollte auf 1/„true"/„Full" stehen):
```bash
adb shell settings get secure bluetooth_hci_log 2>/dev/null
adb shell dumpsys bluetooth_manager | grep -i snoop
```

---

## 3. Update mitschneiden

1. **Flugmodus AUS** (Internet an — die App muss die Firmware laden können).
2. Optional, aber empfohlen: das **Handy zusätzlich ins WLAN `MarstekCap`** hängen. Dann fängt der
   Pi-Dauermitschnitt parallel den **Download-Traffic der App** mit (URL/DNS, evtl. die Datei).
3. **Bluetooth am Handy kurz aus/an** (frischer Snoop-Log).
4. In der Marstek-App den **Button „Update Kommunikationsmodul"** drücken und komplett durchlaufen
   lassen. Nicht zwischendrin trennen.

---

## 4. Log auf den Pi ziehen

Direkter Pull (klappt nur mit Root am Handy, einfach probieren):
```bash
adb pull /data/misc/bluetooth/logs/btsnoop_hci.log ~/btsnoop_hci.log
```
Wenn „permission denied" → **Bugreport-Weg** (funktioniert ohne Root):
```bash
cd ~
adb bugreport btbug          # erzeugt btbug.zip (dauert 1-2 Min)
unzip -o btbug.zip 'FS/data/misc/bluetooth/logs/*' -d btbug
find btbug -iname 'btsnoop_hci*'
```
Die gefundene Datei (z.B. `btbug/FS/data/misc/bluetooth/logs/btsnoop_hci.log`) ist unser Mitschnitt.

---

## 5. Firmware aus den GATT-Writes rausziehen

Log-Datei-Variable setzen:
```bash
L=~/btsnoop_hci.log      # bzw. der Pfad aus Schritt 4
```
**a) Überblick — welche GATT-Handles werden beschrieben, und wie oft?**
```bash
tshark -r "$L" -Y 'btatt.opcode.method==0x12 or btatt.opcode.method==0x52' \
  -T fields -e btatt.handle 2>/dev/null | sort | uniq -c | sort -rn
```
Der Handle mit **den meisten Writes** (hunderte/tausende) ist der Firmware-Kanal.

**b) Diesen Handle komplett zu einer Binärdatei zusammensetzen** (H anpassen, z.B. `0x0012`):
```bash
H=0x0012
tshark -r "$L" -Y "btatt.handle==$H and (btatt.opcode.method==0x12 or btatt.opcode.method==0x52)" \
  -T fields -e btatt.value 2>/dev/null | tr -d ' \n:' | xxd -r -p > ~/fc41d_ble_fw.bin
ls -l ~/fc41d_ble_fw.bin
```
**c) Erste Einschätzung:**
```bash
xxd ~/fc41d_ble_fw.bin | head            # Magic? "RBL" am Anfang?
python3 - <<'PY'
import math,collections
d=open('/root/fc41d_ble_fw.bin','rb').read() if False else open(__import__('os').path.expanduser('~/fc41d_ble_fw.bin'),'rb').read()
if d:
    c=collections.Counter(d); H=-sum(v/len(d)*math.log2(v/len(d)) for v in c.values())
    print("Bytes:",len(d),"Entropie:",round(H,4))
PY
```
Entropie ~8.0 = verschlüsselt (wie die bekannte `.rbl`). Magic `RBL\0` am Anfang = Realtek-RBL.

**d) Kontrollpakete / Protokoll ansehen** (kleine Writes, Notifications):
```bash
tshark -r "$L" -Y 'btatt' -T fields -e frame.number -e btatt.opcode -e btatt.handle -e btatt.value \
  2>/dev/null | head -60
```
Zeigt den Handshake vor dem Transfer (oft: Länge/CRC/Version-Kommando) — wichtig, um Chunk-Offsets
und evtl. einen Header/Key-Austausch zu erkennen.

---

## 6. Ergebnis sichern

- `fc41d_ble_fw.bin` + den `btsnoop_hci.log` in den Projektordner `HM_HIE_FC41D/fc41d_archive/` legen.
- Header/Build-Datum/Modul-ID/Version mit der installierten `202409090159` vergleichen.
- Parallel im Pi-WLAN-Mitschnitt nach dem App-Download der `.rbl` suchen (Abschnitt 12 der
  RPi-Anleitung / `marstek-ota-scan.sh`).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `adb devices` zeigt `unauthorized` | am Handy den USB-Debugging-Dialog bestätigen; sonst `adb kill-server && adb start-server` |
| `adb devices` leer | anderes USB-Kabel (Datenkabel!), am Handy USB-Modus auf „Dateiübertragung" |
| Snoop-Log leer/alt | Snoop wirklich auf „Full", danach BT aus/an bzw. Handy-Neustart, dann Update erneut |
| `pull` permission denied | Bugreport-Weg (Schritt 4) |
| kein `btatt` im Log | evtl. „Filtered" statt „Full" gewählt, oder falscher Snoop → Schritt 1.2 |
| viele Handles ähnlich oft | zusätzlich nach großen `btatt.value`-Längen filtern (der Transfer nutzt max. MTU) |

---

## 7. Dekodiertes BLE-Protokoll (aus Mitschnitt 2026-08-20, „kein Update")

**Gerät:** BLE-Name `MST_VNSD_eeff` (= MAC aa:bb:cc:dd:ee:ff des FC41D). Verbindung praktisch
unverschlüsselt (1 btsmp-Frame) → HCI-Snoop zeigt alles im Klartext.

### GATT-Struktur (Vendor-Dienst 0xFF00)
| Handle | Charakteristik | Props | Rolle |
|--------|----------------|-------|-------|
| 0x0012 | **0xFF01** | 0x14 (WriteNoResp+Notify) | App → Gerät (Kommandos) |
| 0x0015 | **0xFF02** | 0x14 | Gerät → App (Antworten/Notify) |
| 0x0018 | **0xFF06** | 0x14 | ungenutzt → **Firmware-Kanal-Kandidat beim echten OTA** |

### Frame-Format
```
73 | LEN | 23 | CMD | [payload...] | XOR
```
- `0x73` ('s') = Startmagic, `0x23` ('#') = Konstante
- `LEN` = Gesamtlänge des Frames (inkl. Header + Checksumme)
- `CMD` = Befehl (Request und Response nutzen dieselbe Nummer)
- letztes Byte = **XOR** aller vorherigen Bytes (in allen Frames verifiziert)

### Beobachtete Kommandos
| cmd | Bedeutung | Antwort (Beispiel) |
|-----|-----------|--------------------|
| 0x03 | Live-Telemetrie (Dauer-Poll) | 172-Byte-Binärblock (BMS/Inverter-Werte) |
| 0x0a | Statistik/Energie | 85 Byte (hier ~0) |
| **0x04** | **Identität + Versionen (ASCII)** | `type=VNSD-0,id=<DEVICE_ID>,mac=aabbccddeeff,dev_ver=150,bms_ver=118,fc_ver=202409090159,inv_ver=116,mppt_v=104` |
| **0x11** | **Comm-Modul-Version einzeln (ASCII)** | `202409090159` |
| 0x24 | Konfig/Status | 6 / 25 Byte |
| 0x42 | Status | 42 Byte |
| 0x51 | (unklar) | 29 Byte `M05VnVC0TVi0rVe0JVBVBVA0` |

### „Kein Update"-Mechanismus (wichtig)
Die App liest per BLE (cmd 0x04/0x11) die Comm-Modul-Version `202409090159`, schickt sie an die
**Cloud** und bekommt die Update-Entscheidung von dort. Deshalb scheiterte der Versuch im
**Flugmodus** („Verbindungsproblem"): ohne Internet keine Cloud-Antwort. Die Update-Logik liegt also
**serverseitig**. → Um überhaupt ein Update angeboten zu bekommen, muss die Cloud eine neuere Version
für genau diese `id`/`fc_ver` freigeben (der Kumpel bekam es angeboten, dieses Gerät noch nicht).

### Für das echte Update mitschneiden
1. Gleicher HCI-Snoop-Aufbau (Abschnitt 1–4).
2. Update mit **Internet an** starten.
3. Danach im btsnoop **FF01 (0x0012) UND FF06 (0x0018)** auswerten — dort laufen dann statt ~115
   kleiner Frames **tausende** Writes mit den Firmware-Chunks.
4. Chunks nach `73/LEN/23/CMD/…/XOR` zerlegen, Payload aneinanderhängen → das ergibt die (vermutlich
   wie die `.rbl` AES-verschlüsselte) Modul-Firmware.

Parser liegt bei: `fc41d_archive/btsnoop_ble_parser.py` (btsnoop → HCI → L2CAP → ATT, mappt Handles
auf UUIDs und dekodiert die 0xFFxx-Frames).
