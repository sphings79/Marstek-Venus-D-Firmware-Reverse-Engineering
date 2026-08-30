# Marstek-Traffic dauerhaft mitschneiden — Laptop als WLAN-Access-Point

**Ziel:** Der Marstek verbindet sich mit einem alten Laptop (eigener WLAN-AP), der Laptop reicht
ins Internet weiter und schneidet allen Verkehr **tageweise rotierend** mit. Läuft wochenlang
unbeaufsichtigt. Erfasst DNS (welcher Host), HTTP-Downloads (volle URL + Datei) und MQTT-Timing.

> **Warum das reicht:** Der Modul-Firmware-Download (FC41D `.rbl`) läuft über **Klartext-HTTP** —
> die vollständige URL und die Datei liegen offen im Mitschnitt, egal auf welchen Host die per MQTT
> gepushte URL zeigt. Kein TLS-Bruch nötig. DNS über den Laptop zeigt zusätzlich jeden Host.

---

## 0. Hardware

- **Alter Laptop mit Linux** (Ubuntu Server 24.04 o. ä.). Netzteil dran lassen, Deckel-zu-Suspend aus.
- **Upstream ins Internet per Ethernet-Kabel** Laptop → Router. Das ist am stabilsten und lässt das
  WLAN frei für den AP.
- **WLAN-Adapter im AP-Modus.** Die eingebaute Karte kann das oft nicht sauber. Zuverlässig und billig:
  ein **USB-Stick mit Atheros AR9271** (Treiber `ath9k_htc`, 2,4 GHz) — genau richtig, denn das
  FC41D-Modul funkt nur auf **2,4 GHz**. Alternativen: MT7612U, RTL8812AU (mit Treiber).
- Etwas Speicher: ein idle Marstek erzeugt grob 20–60 MB/Tag; für Wochen reichen wenige GB.

Prüfen, ob der Adapter AP-Modus kann:
```bash
iw list | grep -A10 "Supported interface modes"   # muss "AP" enthalten
```

---

## 1. Software installieren

```bash
sudo apt update
sudo apt install -y hostapd dnsmasq tcpdump tshark iw
sudo systemctl unmask hostapd
```

Interface-Namen merken (z. B. Upstream `eth0`/`enp1s0`, AP-WLAN `wlan0`):
```bash
ip link
```

---

## 2. AP-Interface feste IP geben

`/etc/systemd/network/10-ap.network` (oder per netplan). Beispiel-Subnetz 192.168.50.0/24:
```bash
sudo ip addr add 192.168.50.1/24 dev wlan0
sudo ip link set wlan0 up
```

---

## 3. hostapd — den Access-Point aufsetzen

`/etc/hostapd/hostapd.conf`:
```
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
```
Start-Test (Vordergrund, Strg+C zum Beenden):
```bash
sudo hostapd /etc/hostapd/hostapd.conf
```

---

## 4. dnsmasq — DHCP + DNS-Logging

`/etc/dnsmasq.conf` (vorhandene Zeilen auskommentieren, das ans Ende):
```
interface=wlan0
bind-interfaces
dhcp-range=192.168.50.50,192.168.50.150,12h
dhcp-option=3,192.168.50.1      # Gateway = Laptop
dhcp-option=6,192.168.50.1      # DNS   = Laptop (dnsmasq loggt dann jede Anfrage)
log-queries
log-facility=/var/log/marstek-dns.log
```
```bash
sudo systemctl restart dnsmasq
```
Damit steht in `/var/log/marstek-dns.log` **jede** vom Marstek angefragte Domain — die
Host-Erkennung läuft also nebenbei mit, unabhängig von der MQTT-URL.

---

## 5. Weiterleitung + NAT (damit der Marstek ins Internet kommt)

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```
(`eth0` = dein Upstream-Interface anpassen.) Dauerhaft machen mit `iptables-persistent`.

Jetzt im Marstek per App das WLAN **MarstekCap** einrichten.

---

## 6. Der Mitschnitt — tageweise rotierende Dateien

Genau das, was du willst — eine Datei pro Tag, automatisch benannt:
```bash
sudo mkdir -p /var/captures
sudo tcpdump -i wlan0 -n -s 0 \
     -G 86400 -w '/var/captures/marstek_%Y-%m-%d_%H%M%S.pcap' -Z root
```
- `-G 86400` → alle 24 h eine neue Datei (86400 s = 1 Tag).
- `%Y-%m-%d_%H%M%S` → das Datum steckt im Dateinamen (`marstek_2026-08-20_000000.pcap`).
- `-s 0` → volle Pakete (nötig, um die Firmware-Datei komplett zu bekommen).
- `-Z root` → gibt Rechte nach dem Öffnen ab.

**Stundenweise** statt täglich: `-G 3600`. **Nach Größe** (z. B. 200 MB): `-C 200` statt `-G`.

Nur relevanter Verkehr (kleinere Dateien) — DNS, HTTP, MQTT:
```bash
... 'udp port 53 or tcp port 80 or tcp port 1883 or tcp port 8883'
```
(Die Telemetrie auf 443 fällt dann weg; der FC41D-Download läuft aber auf 80 und bleibt drin.)

---

## 7. Als Dienst dauerhaft laufen lassen

`/etc/systemd/system/marstek-capture.service`:
```
[Unit]
Description=Marstek traffic capture
After=network.target

[Service]
ExecStart=/usr/bin/tcpdump -i wlan0 -n -s 0 -G 86400 -w /var/captures/marstek_%%Y-%%m-%%d_%%H%%M%%S.pcap -Z root
Restart=always

[Install]
WantedBy=multi-user.target
```
```bash
sudo systemctl enable --now marstek-capture
```
(Die `%` müssen im systemd-File verdoppelt werden — oben schon so.)

Alte Dateien automatisch aufräumen (z. B. älter als 30 Tage), täglich per cron:
```bash
echo '0 4 * * * root find /var/captures -name "marstek_*.pcap" -mtime +30 -delete' \
  | sudo tee /etc/cron.d/marstek-cleanup
```

---

## 8. Auswerten — Update finden und Datei herausziehen

**Schnell prüfen, ob an einem Tag ein OTA-Download war** (HTTP-GETs auf .rbl/.bin):
```bash
tshark -r marstek_2026-08-20_000000.pcap -Y 'http.request' \
  -T fields -e ip.dst -e http.host -e http.request.full_uri | grep -iE '\.rbl|\.bin|ota'
```

**Die Firmware-Datei direkt aus dem Mitschnitt exportieren:**
```bash
mkdir out && tshark -r <datei>.pcap --export-objects http,out/
ls -l out/            # hier liegt dann die .rbl / .bin
```

**Neue/auffällige Domains über die Zeit** (aus dem DNS-Log):
```bash
grep query /var/log/marstek-dns.log | awk '{print $6}' | sort | uniq -c | sort -rn
```

Sobald du eine `.rbl` oder `.bin` hast: in den Projektordner legen — dann Header, Build-Datum,
Modul-ID und Version auslesen (wie bei der bisherigen FC41D-Datei) und mit dem Altstand vergleichen.

---

## Merkzettel für den Update-Moment

1. Capture läuft (Schritt 7 als Dienst) — einfach Tage/Wochen laufen lassen.
2. Wenn die App das Modul-Update anbietet: **anstoßen**, während der Laptop mitschneidet.
3. Danach mit Schritt 8 den Tages-`.pcap` auswerten → URL + Datei sind drin.
4. DNS-Log parallel prüfen, falls die URL auf einen unerwarteten Host zeigt.

---

## Anhang: Raspberry Pi 3B statt Laptop (empfohlen für Dauerbetrieb)

Der Pi 3B ist für den unbeaufsichtigten Langzeit-Mitschnitt besser geeignet als ein Laptop:
lautlos, ~3 W, headless, immer an. Und er braucht **keinen USB-WLAN-Stick**, weil er zwei
getrennte Interfaces hat.

**Rollenverteilung:**
- `eth0` (Ethernet) = Upstream zum Router
- `wlan0` (eingebautes WLAN, nur 2,4 GHz → passt zum FC41D) = Access-Point für den Marstek

**Setup:** Raspberry Pi OS **Lite** (headless) aufspielen, SSH aktivieren. Danach gilt die Anleitung
oben **unverändert** — gleiche Pakete (`hostapd dnsmasq tcpdump tshark`), gleiche Configs, gleiche
Interface-Namen (`eth0` Upstream, `wlan0` AP). In `iptables` als Upstream `eth0` verwenden.

**Wichtig — nicht auf die SD-Karte schreiben:**
Dauerhaftes pcap-Schreiben nutzt die SD-Karte ab und der Platz ist knapp. Mitschnitt auf einen
**USB-Stick / eine USB-SSD** legen:
```bash
# USB-Medium einhängen (Beispiel):
sudo mkdir -p /mnt/cap
sudo mount /dev/sda1 /mnt/cap          # Gerätenamen mit 'lsblk' prüfen
# dauerhaft in /etc/fstab eintragen
```
Im tcpdump-Befehl bzw. im systemd-Dienst dann `/mnt/cap/...` als Zielpfad statt `/var/captures/...`.

**Kleinere Hinweise:**
- Onboard-WLAN im AP-Modus ist unter Last gelegentlich zickig — bei einem einzigen Gerät praktisch
  nie ein Thema. Falls doch: AR9271-USB-Stick als `wlan1` dazustecken und den als AP nutzen
  (`interface=wlan1` in hostapd.conf), Onboard-WLAN bleibt ungenutzt.
- Die schwere Auswertung (`tshark --export-objects` über große pcaps) besser auf dem Mac machen —
  der Pi 3B mit SD-Karte ist dafür langsam. pcaps einfach per `scp` rüberziehen.
- Netzteil mit genug Strom (offiz. 2,5 A) verwenden, sonst gibt es unter WLAN-Last Brownouts
  (Blitz-Symbol / Undervoltage im `dmesg`).
