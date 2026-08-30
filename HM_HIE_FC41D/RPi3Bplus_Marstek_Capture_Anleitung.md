# Marstek-Traffic mitschneiden — Raspberry Pi 3 B+ (getestete Fassung)

**Aufbau:** Der Pi 3 B+ ist ein eigener WLAN-Access-Point. Der Marstek verbindet sich nur mit ihm,
der Pi reicht per LAN-Kabel zum Router weiter und schneidet allen Verkehr **tageweise rotierend**
mit. Läuft wochenlang unbeaufsichtigt; Status jederzeit per SSH über `marstek-status.sh`. Ein
**Auto-Extraktor** (systemd-Timer, alle 10 min) zieht zusätzlich jede per HTTP übertragene Datei
selbstständig aus den Mitschnitten heraus — die neue Firmware landet also von allein als Datei auf
der Platte, ohne dass du pcaps durchsuchen musst.

- `eth0` (Ethernet) = Upstream zum Router
- `wlan0` (eingebautes 2,4-GHz-WLAN) = Access-Point für den Marstek (FC41D funkt nur 2,4 GHz)

> **Live bestätigt (2026-08-20):** Der Modul-Firmware-Check läuft über **Klartext-HTTP** an
> `eu.hamedata.com` (Port 80). URL + Datei liegen offen im Mitschnitt, egal wohin eine MQTT-URL
> zeigt. **MITM ist für die `.rbl` nicht nötig.** Details in `FC41D_Comm_Modul_OTA_Analyse.md` §6.
> Für den MQTT-Push-Kanal (AWS IoT, TLS:8883) siehe optional Anhang B (mitmproxy).

### Wichtige Regeln beim Einrichten (sonst gab es die Fehler von heute)
1. **Jeden `sudo tee …`-Block komplett am Stück einfügen** und danach mit dem gezeigten
   `cat`/`head` prüfen, dass wirklich der Inhalt drinsteht und **nicht** die `tee`-Zeile.
2. In **systemd-Unit-Dateien** muss `%%` stehen (systemd macht daraus `%`). Nur dort, nicht im Skript.
3. `iptables` muss nachinstalliert werden (Bookworm bringt es nicht mehr mit).

---

## 0. Image mit Raspberry Pi Imager

- **Raspberry Pi OS Lite (64-bit)**.
- In den Einstellungen (Zahnrad): **SSH aktivieren**, Benutzer + Passwort, Zeitzone, Land.
- **WLAN-Verbindung (SSID/Passwort) LEER lassen** — `wlan0` wird unser AP, kein Client.
- **„Wireless LAN Country" = DE** setzen (falls möglich; sonst später per raspi-config).
- Upstream per **LAN-Kabel** Pi → Router. Per SSH einloggen.

---

## 1. Pakete + WLAN entsperren

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq tcpdump tshark iw rfkill iptables
sudo systemctl unmask hostapd
sudo rfkill unblock wlan
# Land setzen, falls im Imager nicht geschehen:
sudo raspi-config nonint do_wifi_country DE
```
> `tshark` unbedingt mitinstallieren — der Auto-Extraktor (Abschnitt 9) braucht es. Bei der Frage
> „Should non-superusers be able to capture packets?" reicht **Nein**.

Prüfen (bei „Wireless LAN" muss **Soft blocked: no** stehen):
```bash
rfkill list
```

---

## 2. wlan0 aus dem NetworkManager herausnehmen

```bash
sudo tee /etc/NetworkManager/conf.d/99-marstek.conf >/dev/null <<'NM_EOF'
[keyfile]
unmanaged-devices=interface-name:wlan0
NM_EOF
sudo systemctl restart NetworkManager
```
**Prüfen** — bei `wlan0` muss `unmanaged` stehen:
```bash
nmcli device status
```

---

## 3. IP-Forwarding dauerhaft

```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-marstek.conf
sudo sysctl --system >/dev/null
```

---

## 4. AP-Setup-Skript (setzt IP + NAT) + Dienst

Skript anlegen:
```bash
sudo tee /usr/local/sbin/marstek-ap-up.sh >/dev/null <<'AP_EOF'
#!/usr/bin/env bash
set -e
ip addr flush dev wlan0
ip addr add 192.168.50.1/24 dev wlan0
ip link set wlan0 up
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -C POSTROUTING -o eth0 -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -C FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -i wlan0 -o eth0 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
AP_EOF
sudo chmod +x /usr/local/sbin/marstek-ap-up.sh
```
**Prüfen** — muss mit `#!/usr/bin/env bash` beginnen, NICHT mit `sudo tee`:
```bash
cat /usr/local/sbin/marstek-ap-up.sh
```
Dienst anlegen:
```bash
sudo tee /etc/systemd/system/marstek-ap.service >/dev/null <<'APSVC_EOF'
[Unit]
Description=Marstek AP network setup
After=network.target
Before=hostapd.service dnsmasq.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/marstek-ap-up.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
APSVC_EOF
```

---

## 5. hostapd (der Access-Point)

```bash
sudo tee /etc/hostapd/hostapd.conf >/dev/null <<'HOSTAPD_EOF'
interface=wlan0
driver=nl80211
ssid=MarstekCap
hw_mode=g
channel=6
country_code=DE
ieee80211d=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=<AP_PASSPHRASE>
HOSTAPD_EOF
echo 'DAEMON_CONF="/etc/hostapd/hostapd.conf"' | sudo tee /etc/default/hostapd
```
**Prüfen** — muss mit `interface=wlan0` beginnen:
```bash
head -3 /etc/hostapd/hostapd.conf
```

---

## 6. dnsmasq (DHCP + DNS-Logging)

```bash
sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig 2>/dev/null || true
sudo tee /etc/dnsmasq.conf >/dev/null <<'DNSMASQ_EOF'
interface=wlan0
bind-interfaces
dhcp-range=192.168.50.50,192.168.50.150,12h
dhcp-option=3,192.168.50.1
dhcp-option=6,192.168.50.1
log-queries
log-facility=/var/log/marstek-dns.log
DNSMASQ_EOF
```
**Prüfen** — muss mit `interface=wlan0` beginnen:
```bash
head -3 /etc/dnsmasq.conf
```

---

## 7. AP starten + verifizieren

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now marstek-ap.service
sudo systemctl enable --now hostapd
sudo systemctl enable --now dnsmasq
```
**Kontrolle** — alle drei müssen laufen, wlan0 muss die IP haben:
```bash
systemctl is-active marstek-ap.service hostapd dnsmasq   # -> 3x active
ip addr show wlan0                                        # -> inet 192.168.50.1/24
```
Wenn `marstek-ap.service` fehlschlägt → `sudo bash -x /usr/local/sbin/marstek-ap-up.sh` zeigt die
Zeile. Häufigste Ursache: `iptables` nicht installiert (Schritt 1 nachholen).

---

## 8. Mitschnitt-Dienst (Standard: SD-Karte)

```bash
sudo mkdir -p /var/captures
sudo tee /etc/systemd/system/marstek-capture.service >/dev/null <<'CAP_EOF'
[Unit]
Description=Marstek traffic capture
After=marstek-ap.service
Requires=marstek-ap.service

[Service]
ExecStart=/usr/bin/tcpdump -i wlan0 -n -s 0 -G 86400 -w /var/captures/marstek_%%Y-%%m-%%d_%%H%%M%%S.pcap -Z root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
CAP_EOF
sudo systemctl daemon-reload
sudo systemctl enable --now marstek-capture
```
> **Merke:** In der Unit steht `%%Y-%%m-%%d_%%H%%M%%S` (doppelte `%`). systemd macht daraus `%Y-…`,
> das tcpdump als Datum einsetzt. Einfaches `%` führt zu kaputten Pfaden (Fehler von heute).

**Prüfen:**
```bash
systemctl is-active marstek-capture     # -> active
ls -l /var/captures/                    # Datei marstek_JJJJ-MM-TT_*.pcap (waechst mit Verkehr)
```
> **Aufräumen der SD-Karte** erledigt der OTA-Scanner (Abschnitt 9): er löscht rohe pcaps nach
> 21 Tagen, **behält aber die extrahierten Objekte**. Kein separater Cron nötig.

---

## 9. OTA-Auto-Extraktor (zieht die Firmware selbstständig raus)

Dieses Skript durchsucht alle 10 min die Mitschnitte, exportiert jede per HTTP übertragene Datei
nach `/var/captures/http_objects/`, protokolliert firmware-große Objekte + verdächtige URLs nach
`/var/log/marstek-ota.log` und räumt alte pcaps (>21 Tage) auf.

```bash
sudo tee /usr/local/sbin/marstek-ota-scan.sh >/dev/null <<'OTA_EOF'
#!/bin/bash
set -u
CAPDIR=/var/captures
OUTDIR=/var/captures/http_objects
LOG=/var/log/marstek-ota.log
mkdir -p "$OUTDIR"
for f in "$CAPDIR"/marstek_*.pcap; do
  [ -e "$f" ] || continue
  tshark -r "$f" --export-objects http,"$OUTDIR" >/dev/null 2>&1
  tshark -r "$f" -Y 'http.request' -T fields -e http.host -e http.request.uri 2>/dev/null
done | sort -u > /var/captures/http_urls.txt
BIG=$(find "$OUTDIR" -type f -size +100k 2>/dev/null)
if [ -n "$BIG" ]; then
  echo "[$(date -Is)] MOEGLICHES FIRMWARE-OBJEKT:" >> "$LOG"
  ls -la $BIG >> "$LOG"
fi
grep -Ei 'rbl|ota|upgrade|firmware|\.bin' /var/captures/http_urls.txt >> "$LOG" 2>/dev/null
# rohe pcaps aelter als 21 Tage loeschen (extrahierte Objekte bleiben erhalten)
find "$CAPDIR" -maxdepth 1 -name 'marstek_*.pcap' -mtime +21 -delete 2>/dev/null
OTA_EOF
sudo chmod +x /usr/local/sbin/marstek-ota-scan.sh
```
**Prüfen** — muss mit `#!/bin/bash` beginnen:
```bash
head -1 /usr/local/sbin/marstek-ota-scan.sh
```
Timer + Dienst anlegen und aktivieren:
```bash
sudo tee /etc/systemd/system/marstek-ota-scan.service >/dev/null <<'OTASVC_EOF'
[Unit]
Description=Scan Marstek captures for OTA firmware objects

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/marstek-ota-scan.sh
OTASVC_EOF

sudo tee /etc/systemd/system/marstek-ota-scan.timer >/dev/null <<'OTATIM_EOF'
[Unit]
Description=Run Marstek OTA scan every 10 min

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
OTATIM_EOF

sudo systemctl daemon-reload
sudo systemctl enable --now marstek-ota-scan.timer
sudo /usr/local/sbin/marstek-ota-scan.sh    # einmal probeweise
```
**Prüfen** — Timer geplant, erste Objekte da:
```bash
systemctl list-timers marstek-ota-scan.timer --no-pager
ls -la /var/captures/http_objects
```
Solange kein Update ansteht, liegt hier nur die winzige 29-Byte-Antwort von `getDateInfoeu.php`
(der Zeit-Sync `_JJJJ_MM_TT_…_0_0_0`). Kommt ein OTA, taucht ein **~680-KB-Objekt** (die `.rbl`)
auf und der Log-Eintrag „MOEGLICHES FIRMWARE-OBJEKT" schlägt an.

**Jederzeit reinschauen** (die `.rbl` stünde ganz oben, nach Größe sortiert):
```bash
tail -n 20 /var/log/marstek-ota.log; echo '--- Objekte (groesste zuerst) ---'; ls -laS /var/captures/http_objects | head
```

---

## 10. Status-Skript

```bash
sudo tee /usr/local/sbin/marstek-status.sh >/dev/null <<'STATUS_EOF'
#!/usr/bin/env bash
CAPDIR=/var/captures
echo "=== AP ======================================================"
echo "hostapd:  $(systemctl is-active hostapd)"
echo "dnsmasq:  $(systemctl is-active dnsmasq)"
echo "ap-setup: $(systemctl is-active marstek-ap.service)"
echo "wlan0-IP: $(ip -4 -o addr show wlan0 | awk '{print $4}')"
echo "=== Verbundene Geraete ======================================"
out=$(iw dev wlan0 station dump)
if [ -z "$out" ]; then echo "NICHT verbunden"; else
  echo "$out" | grep -E "Station|signal:|connected time:|rx bytes:|tx bytes:"; fi
echo "=== DHCP-Leases ============================================="
cat /var/lib/misc/dnsmasq.leases 2>/dev/null || echo "keine"
echo "=== Mitschnitt =============================================="
echo "capture: $(systemctl is-active marstek-capture)"
f=$(ls -1t "$CAPDIR"/marstek_*.pcap 2>/dev/null | head -1)
if [ -n "$f" ]; then
  s1=$(stat -c%s "$f"); sleep 2; s2=$(stat -c%s "$f")
  printf "Datei  : %s\nGroesse: %s (waechst: %s Bytes/2s)\n" "$(basename "$f")" "$(numfmt --to=iec "$s2")" "$((s2-s1))"
else echo "noch keine Datei"; fi
echo "=== OTA-Scanner ============================================="
echo "timer  : $(systemctl is-active marstek-ota-scan.timer)"
nobj=$(ls -1 "$CAPDIR"/http_objects 2>/dev/null | wc -l)
big=$(find "$CAPDIR"/http_objects -type f -size +100k 2>/dev/null)
echo "Objekte: $nobj  (Firmware-Verdacht: ${big:-keiner})"
tail -1 /var/log/marstek-ota.log 2>/dev/null
echo "=== letzte 5 DNS-Anfragen ==================================="
grep query /var/log/marstek-dns.log 2>/dev/null | tail -5
STATUS_EOF
sudo chmod +x /usr/local/sbin/marstek-status.sh
```
Aufruf: `sudo marstek-status.sh`  ·  Dauerbeobachtung: `watch -n5 sudo marstek-status.sh`

---

## 11. Marstek verbinden + prüfen

1. Erst mit **Handy** testen: WLAN **MarstekCap** verbinden → Internet muss gehen. `sudo marstek-status.sh`
   zeigt das Handy als `Station`. Damit ist die ganze Kette bewiesen.
2. Dann im **Marstek per App** dasselbe WLAN **MarstekCap** einrichten.
3. Marstek-IP aus `dnsmasq.leases` ablesen (das FC41D-Modul meldet sich mit Hostname `wlan0`),
   dann live prüfen, was er tut:
   ```bash
   sudo tcpdump -i wlan0 -nn 'host <MARSTEK-IP> and not arp and not port 67 and not port 68 and not port 5353'
   ```

**So sieht ein gesunder Cloud-Kontakt aus (2026-08-20 real beobachtet):**
```
DNS  eu.hamedata.com -> 3.122.27.237          (AWS Frankfurt)
GET  http://eu.hamedata.com/app/neng/getDateInfoeu.php?...&fcv=...&cert=0...   (Port 80, Klartext)
     Antwort HTTP 200:  _JJJJ_MM_TT_HH_MM_SS_<Wochentag>_0_0_0   (0_0_0 = kein Update)
MQTT a40nr6osvmmaw-ats.iot.eu-west-3.amazonaws.com -> 8883/TLS   (AWS Paris, Push-Kanal)
UDP  <marstek>:22222 -> ...255:12345                              (lokales App-Discovery)
```
- Der Marstek nutzt den **DNS des Pi** (192.168.50.1) — die Anfrage nach `eu.hamedata.com` steht
  also im DNS-Log. (Manche IoT-Module nutzen fest `8.8.8.8`; dann steht im DNS-Log nichts, aber der
  pcap fängt trotzdem alles.)
- **Direkt nach dem Verbinden ist er oft ein paar Minuten still** und pollt `getDateInfo` erst
  schubweise. „Kein Traffic sofort" heißt also nicht zwingend, dass etwas kaputt ist.
- **Verbindungsaufbau erzwingen ohne Stromziehen** (praktisch, wenn der Marstek am Backup hängt):
  ```bash
  sudo systemctl restart hostapd     # kickt alle WLAN-Clients -> Marstek meldet sich komplett neu an
  ```
  Nur DHCP + Gratuitous-ARP und danach dauerhaft Stille = Marstek hängt noch im alten WLAN / ist in
  der App nicht auf MarstekCap gestellt.

---

## 12. Update auswerten

**Normalfall: nichts zu tun** — der Auto-Extraktor (Abschnitt 9) hat die Firmware schon als Datei in
`/var/captures/http_objects/` gelegt und im Log vermerkt. Kopiere das große Objekt per `scp` auf den
Mac und in den Projektordner → Header, Build-Datum, Modul-ID, Version auslesen und mit der aktuell
installierten `202409090159` vergleichen.

Manuell aus einem pcap ziehen (falls du selbst nachsehen willst):
```bash
# Gab es OTA-verdächtige URLs?
tshark -r marstek_2026-08-20_000000.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.full_uri | grep -iE '\.rbl|\.bin|ota'
# Alle per HTTP übertragenen Dateien herausziehen:
mkdir out && tshark -r marstek_2026-08-20_000000.pcap --export-objects http,out/
ls -lS out/
```

---

## 13. Troubleshooting (die realen Fehler)

| Symptom | Ursache | Fix |
|---|---|---|
| `iptables: command not found` (Status 127) | Bookworm ohne iptables | `sudo apt install -y iptables` |
| Capture-Pfad wird zu `…/etc/systemd/system-…` Müll | einfaches `%` in der Unit | `%%` verwenden (Schritt 8) |
| Datei/Skript enthält die `sudo tee`-Zeile statt Inhalt | Block beim Einfügen verrutscht | Block komplett neu einfügen, mit `cat`/`head` prüfen |
| `marstek-ap.service` failed | `wlan0` down/rfkill/NM | `rfkill list`, `nmcli device status` (unmanaged?), `bash -x` des Skripts |
| hostapd startet nicht | Land nicht gesetzt | `sudo raspi-config nonint do_wifi_country DE`, `sudo rfkill unblock wlan` |
| capture `inactive`/`failed`, „repeated too quickly" | fehlerhafte Unit im Restart-Loop | Unit fixen, dann `sudo systemctl reset-failed marstek-capture && sudo systemctl restart marstek-capture` |
| 0-Byte-Datei | einfach wenig Verkehr | mit Client Verkehr erzeugen, `ls -l /var/captures/` erneut |
| Marstek verbunden, aber nur DHCP/ARP, kein Cloud-Traffic | noch im alten WLAN / Poll-Intervall | `sudo systemctl restart hostapd` (Neuanmeldung erzwingen), sonst abwarten |
| `marstek-ota-scan` findet nichts | `tshark` fehlt | `sudo apt install -y tshark`, dann `sudo /usr/local/sbin/marstek-ota-scan.sh` |

**Reboot-Test:** `sudo reboot`, nach dem Hochfahren `sudo marstek-status.sh` — alles muss von selbst
wieder `active` sein (alle Dienste + der OTA-Timer sind `enabled`).

---

## Anhang A — später auf USB-Stick/SSD umstellen

```bash
sudo apt install -y exfatprogs           # nur falls exFAT
sudo mkdir -p /mnt/cap
lsblk -f                                 # Stick finden (z.B. /dev/sda1) + FSTYPE
sudo blkid /dev/sda1                     # UUID ablesen
echo 'UUID=DEINE-UUID /mnt/cap exfat defaults,nofail,uid=root,gid=root 0 0' | sudo tee -a /etc/fstab
sudo mount -a && df -h /mnt/cap
```
Dann in Capture-Unit, Status-Skript **und OTA-Scanner** den Pfad umstellen:
```bash
sudo sed -i 's#/var/captures#/mnt/cap#g' \
  /etc/systemd/system/marstek-capture.service \
  /usr/local/sbin/marstek-status.sh \
  /usr/local/sbin/marstek-ota-scan.sh
sudo systemctl daemon-reload && sudo systemctl restart marstek-capture
```
Aufbewahrung ändern: im OTA-Scanner den Wert `-mtime +21` anpassen (z.B. `+30` für 30 Tage).

---

## Anhang B — TLS aufbrechen (mitmproxy), für MQTT-Push + HTTPS-Downloads

**Nur optional.** Die `.rbl` selbst kommt über HTTP und wird vom Auto-Extraktor ohnehin erfasst —
mitmproxy brauchst du nur, falls die Download-URL **ausschließlich** über den MQTT-Kanal (8883/TLS)
käme oder ein STM32-Image per HTTPS geladen wird.

**Grundlage:** Die v150-Analyse belegt `MBEDTLS_SSL_VERIFY_NONE` (Serverzertifikat wird nicht
geprüft) → transparenter TLS-Proxy möglich. Der Live-Check bestätigt das zusätzlich (`cert=0` im
HTTP-Request). Client-Zertifikat des Geräts liegt extrahiert vor (`security/VNSD_Certs/`).

> Verify-Level des Quectel/FC41D-Pfads ist noch unbestätigt. Der Versuch ist der Test: kommen Flows
> in mitmproxy an → Prüfung aus. Reset/Timeout → Prüfung an, dann Rückbau (B4). Voll reversibel.

**B1 — Installieren + Client-Cert:**
```bash
sudo apt install -y mitmproxy
cat marstek_device_client_cert.pem marstek_device_private_key.pem | sudo tee /root/marstek_client.pem >/dev/null
sudo chmod 600 /root/marstek_client.pem
# Addon marstek_mitm_addon.py aus dem Projektordner nach /root/ kopieren
```
**B2 — Umleitung nur für die Marstek-IP** (M anpassen):
```bash
M=192.168.50.90
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo iptables -t nat -A PREROUTING -s $M -p tcp --dport 443  -j REDIRECT --to-ports 8080
sudo iptables -t nat -A PREROUTING -s $M -p tcp --dport 8883 -j REDIRECT --to-ports 8080
```
**B3 — Proxy starten:**
```bash
sudo mitmdump --mode transparent --showhost --ssl-insecure --tcp-hosts '.*' \
     --set client_certs=/root/marstek_client.pem \
     -s /root/marstek_mitm_addon.py -w /var/captures/mitm_flows.mitm
```
Firmware landet in `/var/captures/objects/`, OTA-URL-Treffer in `/var/captures/mitm_hits.log`.
**B4 — Rückbau (immer nach dem Test):**
```bash
M=192.168.50.90
sudo iptables -t nat -D PREROUTING -s $M -p tcp --dport 443  -j REDIRECT --to-ports 8080
sudo iptables -t nat -D PREROUTING -s $M -p tcp --dport 8883 -j REDIRECT --to-ports 8080
# mitmdump mit Strg+C beenden
```
