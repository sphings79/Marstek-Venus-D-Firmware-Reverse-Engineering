# Control FW v150 — Analyse und Diff gegen v149.2

**Binary:** `VNSD-0_app_0150_0805_115146.bin`
**Referenz:** `Control_149.2_VNSD-0_app_1492_0702_142136.bin` (v149.2)
**Analysedatum:** 2026-08-13
**Werkzeug:** Ghidra 12.1.1 (pyghidra) + ReVa MCP, Version-Tracking-Diff

---

## 1. Binary-Fingerprint

| | v149.2 | v150 |
|---|---|---|
| Datei | `Control_149.2_VNSD-0_app_1492_0702_142136.bin` | `VNSD-0_app_0150_0805_115146.bin` |
| MD5 | `59c0c9f15c43e442c2861e592aafd11a` | `0c21645b9dc622a08e7de5ac1d269bd5` |
| Größe | 385.024 B | 389.120 B (**+4.096 B**) |
| Flash-Basis | `0x08000000` | `0x08000000` |
| Adressbereich | `0x08000000`–`0x0805DFFF` | `0x08000000`–`0x0805EFFF` |
| Sprache | ARM:LE:32:Cortex (Thumb-2) | ARM:LE:32:Cortex (Thumb-2) |
| Initial SP | — | `0x2001F7E8` (SRAM ab `0x20000000`) |
| Reset-Vektor | — | `0x08004A70` (Thumb) |
| Funktionen | 1.622 | **1.618** |
| Benannt | 1.618 | **1.618 (100 %)** |
| Symbole | 4.381 | 4.200 |
| Versions-String | `VNSD-0 v1492` | `VNSD-0 v150` |
| Build-Stempel | `Jul  2 2026 14:20:03` | **`Aug  5 2026 11:51:21`** |

### Ghidra-Aufbereitung

Das Image wurde ursprünglich auf Basis `0x00000000` importiert. Korrigiert per
`setImageBase(0x08000000, commit=True)`; der Vektortabellen-Check bestätigt die Basis
(Initial SP `0x2001F7E8`, Reset `0x08004A71`, alle Exception-Vektoren im Bereich `0x080xxxxx`).
Danach Full-Analysis (1.029 → 1.618 Funktionen).

**Version-Tracking-Diff** (Source = v149.2, Destination = v150), Korrelatoren:
`symbol-name`, `exact-bytes`, `exact-instructions`, `exact-mnemonics`,
`duplicate-instructions`, `function-reference` und zusätzlich `combined-reference`.

| Ergebnis | Anzahl |
|---|---|
| Gematcht | 1.567 |
| davon identisch | 1.511 |
| davon geändert | 56 |
| Nur in v149.2 (entfallen/verschoben) | 55 |
| Nur in v150 (neu/nicht gematcht) | 51 |
| Markup automatisch übertragen | 1.566 Funktionen |
| Manuell nachbenannt | 52 |
| **Namens-Dubletten nach Abschluss** | **0** |
| Plate-Kommentare in v150 | 89 |

---

## 2. Kernaussage — was hat sich geändert?

v150 ist **kein Bugfix-Release**, sondern bringt drei substanzielle Neuerungen:

1. **Cloud-Migration von `hamedata.com` (HTTP) nach `marstekcloud.com` (HTTPS).**
2. **Ein komplett neuer HTTPS/TLS-Stack über den CH395-Ethernet-Chip** (mbedTLS,
   eigene Socket-, Request-Bau- und Parse-Funktionen).
3. **Neues Feature „Peak Shaving" (Lastspitzenkappung)**, konfigurierbar über BLE
   *und* MQTT, mit zwei neuen Telemetriefeldern.

Dazu kommen zahlreiche kleinere Änderungen (EEPROM-Layout, Klemmlogik der
Leistungsvorgabe, Puffergrößen) und die Aktivierung von Code, der in v149.2 bereits
im Flash lag, aber von keiner Funktion referenziert wurde (toter Code).

---

## 3. Cloud-Reporting: hamedata → marstekcloud

### Entfallen (v149.2)

```
http://%s.hamedata.com/prod/api/v1/setVenusDReporting?v=%s
AT+QHTTPCFG="url","http://%s.hamedata.com/prod/api/v1/setVenusDReporting?v=%s"
[URL Base64 data (%d byte)]: %s.
[HTTP] URL err, need %d bytes(all:%zu)
[HTTP] Upload data_len : %d, buf_size: %d, data: %s, key: %s.
"de":                                   (Upload-Decrypt-Result-Flag)
```

### Neu (v150)

```
https://api-%s.marstekcloud.com/data-upload/v1/venus/%s
AT+QHTTPCFG="url","https://api-%s.marstekcloud.com/data-upload/v1/venus/%s"
AT+QHTTPCFG="header","Content-Type","application/json"
AT+QHTTPPOST=%d,60,60
{"d":"di=%s&sn=%s&to=%d&td=%d&ed=%d&…&soh=%d"}
```

**Bedeutung:** Der Telemetrie-Upload lief in v149.2 als **HTTP-GET mit
AES-128-ECB-verschlüsselter, Base64-kodierter Query** gegen `*.hamedata.com`
(Funktion `Cloud_Reporting_setVenusDReporting`). In v150 wird stattdessen ein
**HTTPS-POST mit JSON-Body** (`{"d":"<key=value&…>"}`) an
`api-<region>.marstekcloud.com/data-upload/v1/venus/<sn>` gesendet.
Der Base64-/AES-Pfad für die URL entfällt ersatzlos, ebenso die Auswertung des
Server-Flags `"de":` (Upload-Decrypt-Result).

Neue zentrale Funktion: **`Cloud_Report_MarstekCloud_Upload` @ `0x08016B98`** (1.548 B).

Zusätzlich neu für den Modem-Pfad:

* `Quectel_SSL_Set_SNI` @ `0x08010684` — `AT+QSSLCFG="sni",<ctx>,<en>`
* String `"CA",1` — CA-Konfiguration für die Modem-TLS-Session

---

> **Was dort tatsächlich hochgeladen wird**, ist seit 2026-08-25 gemessen und in
> `Cloud_Upload_Payload_v150.md` dokumentiert — inklusive der Bestätigung, dass
> das Regionskürzel `eu` lautet.

## 4. Neuer HTTPS-Stack über CH395 (Ethernet)

In v150 existiert ein zweiter, vollständiger HTTP-Pfad, der **TLS in Software
(mbedTLS) direkt über den CH395-TCP-Socket** fährt — parallel zum bestehenden
HTTP-Pfad. Die Firmware enthält dazu sogar die Original-Quellfunktionsnamen als
Strings: `Init_ch395_https`, `Pack_https_post_req`, `Parse_https_data`, `on_bodys_cb`.

| Adresse | Name (neu vergeben) | Größe | Funktion |
|---|---|---|---|
| `0x080174E8` | `HTTPS_Request_Execute_CH395` | 398 B | Orchestrator: Socket → TLS → Request → Parse |
| `0x080370A0` | `HTTPS_TLS_Session_Init` | 264 B | mbedTLS-Session, **Authmode 0 = keine Zertifikatsprüfung**, TLS 1.2, SNI |
| `0x080158D0` | `HTTPS_TLS_Context_Reset` | 52 B | Kontext-Reset des HTTPS-Pfads |
| `0x080474BC` | `mbedTLS_SSL_CloseNotify` | 58 B | TLS `close_notify` |
| `0x0801821C` | `CH395_TCP_Socket_Open_HTTPS` | 150 B | Zwilling von `CH395_TCP_Socket_Open_HTTPPort80` |
| `0x080270E8` | `HTTPS_BuildRequestBuffer` | 174 B | Zwilling von `HTTP_BuildRequestBuffer` |
| `0x08027564` | `HTTPS_Response_Parse` | 80 B | byte-identischer Zwilling von `HTTP_Response_Parse` (llhttp) |
| `0x08027478` | `HTTPS_Response_Marker_Matcher` | 218 B | Mustervergleich im Antwortstrom (Confidence: low) |
| `0x08015914` | `mbedTLS_SSL_Recv_WithRetry` | 114 B | `mbedTLS_SSL_Read` mit Retry |
| `0x0801598C` | `mbedTLS_SSL_Send_WithRetry` | 118 B | `mbedTLS_SSL_Write` mit Retry |

Neue Request-Templates:

```
POST %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: CH395-Client\r\n
Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s

POST %s HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nUser-Agent: CH395-Client\r\n…
```

Neue Log-Strings: `[HTTPS] Url(%d) : %s.`, `[HTTPS] TCP connect timeout, state=0x%02X`,
`[HTTPS] SSL send failed: %d`, `[HTTPS] SSL recv failed: %d`,
`[HTTPS] Parse http data failed`, `SSL send error: -0x%04X`,
`SSL send timeout, written=%d/%d`, `ssl setup fail -0x%04X`.

> **Sicherheitsrelevant:** `HTTPS_TLS_Session_Init` ruft
> `mbedTLS_SSL_Conf_Authmode(conf, 0)` — also `MBEDTLS_SSL_VERIFY_NONE`.
> Der neue HTTPS-Pfad prüft das Serverzertifikat **nicht**. Die MQTT-Session
> (`mbedTLS_SSL_Connection_Init` @ `0x08018934`) nutzt weiterhin gegenseitige
> Authentifizierung mit Client-Zertifikat und CA-Chain.

---

## 4a. Der 30-Minuten-Reset der Ethernet-Bridge — Mechanismus

*(2026-08-25. Ausloeser: Feldmeldungen ueber Modbus-Aussetzer im exakten
30-Minuten-Takt auf Venus E v3 und Venus D unter v150. Der Log-String
`[HTTP]ch395 reset!!!!` war in §6 bereits als „neuer Recovery-Pfad" notiert; hier
steht, wann er feuert.)*

`FUN_08015bd0` (HTTP-/Cloud-Task, 2048 B) enthaelt in Zeile 44 der Dekompilation:

```c
if (((1 < *(ushort *)(DAT_08015fcc + 2)) &&
     (Tick_Timer_Check_Elapsed(DAT_0801600c, 0x708) != 0)) &&
    (*_DAT_08016010 == 0)) {
    CH395_Reset_And_Reinit(0);
    log_printf(3, 1, "[HTTP]ch395 reset!!!!");
    *DAT_0801600c = 0;
    *DAT_08015fc0 = '\0';
}
```

`0x708` = **1800 Sekunden**. `CH395_Reset_And_Reinit` zieht die Reset-Leitung des
Chips (100 ms low, 50 ms nach dem Loslassen), initialisiert ihn neu und oeffnet
danach Modbus-TCP-Socket, Broadcast-Listener und TCP-Server wieder. Waehrend des
Resets ist die Bridge komplett weg — **auch ICMP**, was Feldmessungen per Ping
ueber LAN-Kabel bestaetigen.

### Die drei Bedingungen

| Bedingung | Adresse | Befund |
|---|---|---|
| `1 < count` | u16 @ **0x2000100C** | Zahl der gepufferten Telemetrie-Datensaetze |
| 1800 s abgelaufen | Tick @ 0x20001FD6 | fester Timer, wird nach dem Reset genullt |
| `flag == 0` | u16 @ **0x2000014C** | = Modbus-Register **37001** (`status_block_offset8`) |

**Der Zaehler.** `DAT_08015fcc`, `DAT_0800c3b8` (in `Telemetry_History_Record_Push`)
und `DAT_08016b20` (in `HTTP_Economy_TOU_PeriodicHandler`) enthalten alle drei
`0x2000100A` — es ist derselbe Ringpuffer-Header. `Telemetry_History_Record_Push`
@ `0x0800C2F0` legt Datensaetze zu je `0x35D` Bytes ab (max. `0x90` = 144) und
erhoeht dabei `+2`.

**Entwertet wird nur bei erfolgreichem Upload.** In `FUN_08015bd0`:

```c
iVar6 = FUN_0801774c(_DAT_080160c0);        // Antwort-Body auswerten
if (iVar6 == 0) {                            // akzeptiert
    ...
    memcpy(record[count-1], record[count], 0x35d);
    *(short *)(base + 2) = *(short *)(base + 2) + -1;   // Zaehler minus 1
}
```

`FUN_0801774c` @ `0x0801774C` ist dabei denkbar simpel:

```c
iVar2 = strstr(param_1, "\"code\":");     // String @ 0x08017784, verifiziert
if (iVar2 == 0) return 0;
return atoi(iVar2 + 7);                     // Log: "[HTTP] Upload decrypt result = %d."
```

Der Server muss also im Body `"code":0` liefern, damit der Datensatz als
zugestellt gilt. Schlaegt der Upload fehl, bleibt der Zaehler stehen und waechst
mit jedem weiteren Datensatz.

**Das dritte Flag ist praktisch wirkungslos.** `0x2000014C` ist laut
`Modbus_RS485_TCP/Marstek_Venus_D_Register_Map_Final_all_register.csv` das
Register **37001** (Status-Block `0x20000144` +8, Writer
`Protocol_AA_SetDeviceParams` @ `0x0802FC48`, Leser `Grid_Export_Power_Limiter`).
In **allen** vorhandenen Scan-Logs — `langzeit2`, `pack1_bms_fault_2026-08-21`,
`unter_dod_backup…` — steht 37001 durchgehend auf **0**, ueber alle
Betriebszustaende hinweg. Die Bedingung ist damit auf diesem Geraet immer erfuellt;
was das Feld semantisch bedeutet, bleibt offen (Konfidenz in der Registerkarte:
niedrig).

### Der WLAN-Zwilling: `FUN_0800c420` — 900 s statt 1800 s

Dieselbe Mechanik existiert ein zweites Mal fuer den FC41D-/Quectel-Weg. Die
Task `FUN_0800c420` (aufgerufen aus `LAB_0802E76E`) ist der Zwilling von
`FUN_08015bd0` (aus `LAB_0802E6F4`) — gleiche Struktur, gleicher Ringpuffer,
anderer Transport (`Quectel_HTTP_GET_StateMachine` statt CH395). Zeile 127:

```c
if ((*(short *)(DAT_0800c814 + 2) != 0) &&
    (Tick_Timer_Check_Elapsed(_DAT_0800c920, 900) != 0)) {
    Quectel_Modem_HardwareReset_Handler(0);
    log_printf(3, 1, "[HTTP]fc41d reset!!!!");   // String @ 0x0800C923
    *_DAT_0800c920 = 0;
    *DAT_0800c818 = 0;
}
```

`DAT_0800c814` enthaelt `0x2000100A` — **derselbe Ringpuffer-Header** wie auf der
Ethernet-Seite (verifiziert). Der Vergleich:

| | Ethernet (CH395) | WLAN (FC41D/Quectel) |
|---|---|---|
| Task | `FUN_08015bd0` | `FUN_0800c420` |
| Reset | `CH395_Reset_And_Reinit` | `Quectel_Modem_HardwareReset_Handler` |
| Timer | **1800 s** (`0x708`) | **900 s** |
| Rueckstau | `> 1` Datensatz | `!= 0` — ein Datensatz genuegt |
| Zusatzbedingung | Reg. 37001 == 0 | keine |

**WLAN ist also die haertere Variante**, nicht die mildere: doppelt so haeufig und
mit niedrigerer Schwelle. Ein Wechsel des Anschlusses ist keine Umgehung.

Die uebrigen Zeilen 134–1086 von `FUN_0800c420` sind die Quectel-AT-Zustands-
maschine (Cases 0–0x23) mit kurzen Protokoll-Timeouts (300/600/5000 ms); Case 9
enthaelt den Entwertungspfad inklusive einer Sammel-Loeschung
(`[HTTP] Delete data upload_cnt`). Zwei weitere Modem-Resets in Zeile 67–78 sind
zaehlergetrieben (`> 6`, `> 10`), nicht zeitgesteuert. `CH395_Reset_And_Reinit`
kommt in dieser Task nicht vor. **Vollstaendig gelesen 2026-08-25.**

**Nicht geprueft:** ob beide Tasks parallel laufen oder nur die zum aktiven Link
passende.

### Konsequenz

**Der 30-Minuten-Reset ist ein Cloud-Upload-Watchdog.** Solange die Telemetrie
nicht erfolgreich an `https://api-%s.marstekcloud.com/data-upload/v1/venus/%s`
zugestellt wird, waechst der Puffer, und die Firmware setzt alle 1800 s den
Ethernet-Chip zurueck — in der Annahme, der Netzwerkweg sei defekt. Er ist es
nicht; nur die Cloud antwortet nicht.

Das erklaert die Feldbeobachtungen vollstaendig:

- **warum es nicht jeden trifft** — bei erreichbarer Cloud wird der Puffer geleert,
  der Zaehler bleibt ≤ 1, die Bedingung greift nie
- **warum neuere Kommunikationsmodul-Firmware nichts aendert** — der Reset kommt aus
  der Control-Firmware, das Modul fuehrt ihn nur aus
- **warum der Takt exakt ist** — es ist ein Timer, kein Fehlerfall

Korrelation, nicht bewiesen: auf einem betroffenen Venus D steht
`cloud_status` (Register 30302) auf 0 bei intakter WLAN-/LAN-Verbindung. Dass
30302 genau diesen Upload-Pfad abbildet, ist nicht nachgeprueft.

### Warum der Takt bleibt — Zaehlerdynamik (2026-08-25, Feldtest)

*(Diese Unterabschnitt korrigiert eine fruehere Fassung. Die dort formulierte
Vorhersage "ein Kaltstart beendet den Takt" wurde im Feld **widerlegt**; die
Begruendung dafuer stand auf einer ungeprueften Annahme ueber die
Anforderungsflaggen. Der Ablauf ist unten korrigiert und belegt.)*

#### Der Feldtest

Offline-Endpunkt antwortet korrekt (`{"code":0,...}`, Zeitantwort in UTC im
Originalformat). Venus D per LAN, Kaltstart um 12:11:51. Ping im Sekundentakt:

| Ereignis | Zeit | Abstand |
|---|---|---|
| Kaltstart (Geraet weg) | 12:11:51 | — |
| Reset 1 | 12:47:24 | **2133 s** |
| Reset 2 | 13:17:47 | 1823 s |
| Reset 3 | 13:48:11 | 1824 s |
| Reset 4 | 14:18:35 | 1824 s |

Der Takt ueberlebt den Kaltstart. **Aber das erste Intervall ist 309 s laenger
als die folgenden**, und das ist kein Rauschen: `Tick_Timer_Check_Elapsed` bleibt
wahr, sobald die 1800 s um sind — genullt wird der Tick erst vom Reset selbst
(`FUN_08015bd0`, Zeile 50). Der Reset feuert also, sobald die *letzte* noch
offene Bedingung wahr wird. Nach dem Kaltstart war das `1 < count`.

**Belegt damit:** `count` wird beim Boot tatsaechlich auf 0 gesetzt (konsistent
mit `.bss`), steigt in den ersten Minuten wieder ueber 1 und bleibt dann oben.
Die Steady-State-Periode betraegt 1823–1824 s, also 1800 s plus ~24 s
Schleifenlatenz.

#### Wer Datensaetze erzeugt und wer Uploads anfordert

Beides macht `HTTP_Economy_TOU_PeriodicHandler` @ `0x080169B4`, aufgerufen in
`FUN_08015bd0` Zeile 34 bei jedem Task-Durchlauf.

**Datensatz** (Zeile 22–30): sobald der 5-Minuten-Slotindex
(`RTC_TimeOfDay_To5MinSlotIndex`) vom zuletzt gespeicherten abweicht und 20 s
vergangen sind → `Telemetry_History_Record_Push` → `count + 1`.

**Upload-Anforderung** — zwei Pfade:

```c
iVar3 = HexChar_To_TimeOffsetIndex();
if (iVar3 == 0) { f_0x10 = 3; f_0x0f = 1; }        // sofort
else FreeRTOS_xTimerCreate("HTTP_TIMER", iVar3*60000, 0 /*one-shot*/, 1, cb);
```

und zusaetzlich Zeile 52–56, unabhaengig davon:

```c
if (f_0x11 == 0 && count != 0 && elapsed(DAT_08016b94, 300)) {
    f_0x11 = 1; f_0x10 = 3;
}
```

`HexChar_To_TimeOffsetIndex` @ `0x0801E50C` liest **ein einzelnes Zeichen** an
`0x20018959` (= `*0x0801E550` + 0xB = `0x2001894E` + 0xB), dekodiert es als
Hex-Ziffer (0-9, A-F, a-f) und liefert `wert % 5`, also **0..4 Minuten**. Das ist
ein geraeteabhaengiger Versatz — vermutlich zur Lastverteilung der Cloud.

**Nicht aufgeloest:** welcher Puffer bei `0x2001894E` liegt. Es gibt keine
Ghidra-Referenzen darauf, weil die Adresse ueber einen Thumb-2-Literal-Pool
erreicht wird (bekannte Einschraenkung, s. `Methodik_und_Meta`). Kandidaten waeren
Seriennummer oder Device-ID. **Falls der Versatz je nach Geraet 0 oder 1..4
ist, waere das ein Kandidat dafuer, warum nur ein Teil der Geraete betroffen
ist** — das ist eine Hypothese, kein Befund.

#### Korrektur: der Puffer *kann* leerlaufen

Die fruehere Fassung behauptete "ein Upload pro Datensatz, der Zaehler kann nicht
sinken". Das ist falsch. Das Eingangstor von `case 1` lautet:

```c
if (f_0x11 == 0 && f_0x0f == 0 && f_0x10 == 0) { state++; break; }
```

Nach erfolgreichem Upload werden nur `f_0x11` und `f_0x0f` geloescht (Zeile
133–134). **`f_0x10` bleibt stehen** — es wird ausschliesslich bei Fehlschlaegen
dekrementiert (Zeile 123 und 174) und komplett geloescht, wenn `count == 0`
erreicht ist (Zeile 91–94). Da der periodische Handler `f_0x10 = 3` setzt, bleibt
das Tor also offen und die Zustandsmaschine laedt in aufeinanderfolgenden
Durchlaeufen weiter hoch, bis der Puffer leer ist.

Ab `count > 3` greift zusaetzlich eine Drossel von 60 s pro Upload
(Zeile 102–106).

**Konsequenz fuer die Diagnose:** Wenn der Puffer leerlaufen *kann*, aber im Feld
dauerhaft ueber 1 steht, dann werden Uploads entweder nicht angefordert oder
nicht akzeptiert. Genau drei Zaehlfehlschlaege (`f_0x10 = 3`) schliessen das Tor
wieder.

**Naechster Schritt:** Uploadfrequenz am Endpunkt messen. Erwartung bei
ausgeglichenem Betrieb sind 12 Uploads/h (ein 5-Minuten-Slot pro Datensatz).
Deutlich weniger belegt, dass Uploads scheitern oder ausbleiben; deutlich mehr
waere mit einem stehenden Zaehler unvereinbar.

### Die Empfangsschleife verlangt CR LF am Ende (2026-08-25)

*(Das ist die Wurzel der Feldbeobachtungen oben. Gefunden, nachdem der eigene
Endpunkt korrekt antwortete und der 30-Minuten-Takt trotzdem blieb.)*

Die Aufrufkette einer Cloud-Abfrage lautet:

```
FUN_08015bd0 case 0
  -> Cloud_Report_URL_Builder(1, 0x14)        @ 0x080151AC   (0x14 = 20 s Timeout)
     -> HTTPS_POST_Request(6, 20, url, len, 0) @ 0x08015094
        -> HTTPS_POST_ReceiveResponseData(...) @ 0x08015744
        -> HTTP_Response_Parse()               @ 0x080273F0   (llhttp, Typ 2)
```

Fehlercodes von `HTTPS_POST_Request`: `-2` Pfad, `-3` Anfragepuffer, `-4`
DNS/CH395-Kommando, `-5` SPI-Senden, **`-6` Empfang lieferte 0 Bytes**,
**`-7` llhttp-Parse fehlgeschlagen**. `0` = Erfolg.

Die Empfangsschleife (`param_6 == 0`, der Nicht-OTA-Zweig):

```c
do {
    vTaskDelay(0x32);
    len = CH395_GetRecvLen(sock);
    if (len == 0) idle++;
    else { idle = 0; len = CH395_ReadRecvBuf(sock, buf + total, len); total += len; }
} while ( ( (total == 0) || (idle < 0x15) ||
            (buf[total-1] != '\n') || (buf[total-2] != '\r') )
          && (Tick_Timer_Check_Elapsed(&t, timeout) == 0) && total < maxlen );
```

**Der vorzeitige Ausstieg verlangt drei Dinge gleichzeitig:** Daten sind
eingetroffen, `0x15` = 21 aufeinanderfolgende Leerabfragen (bei `vTaskDelay(0x32)`
rund eine Sekunde Stille), **und die letzten beiden Bytes im Puffer sind
`CR LF`**. Sonst laeuft die Schleife in den vollen Timeout.

#### Wie die echte Cloud antwortet

Rohmitschnitt von `eu.hamedata.com` (Port 80, plain HTTP), 2026-08-25:

```
Content-Type: text/html; charset=utf-8\r\n
Transfer-Encoding: chunked\r\n
Connection: keep-alive\r\n
Trace-Id: <TRACE_ID>\r\n
\r\n
1d\r\n
_2026_08_25_15_16_11_04_0_0_0\r\n
0\r\n
\r\n
```

**Chunked, nicht `Content-Length`.** Der Abschluss-Chunk `0\r\n\r\n` sorgt dafuer,
dass die Antwort auf `CR LF` endet — die Bedingung ist damit erfuellt, ohne dass
der Rumpf selbst einen Umbruch traegt. `Connection: keep-alive`, also **kein**
Verbindungsabschluss durch den Server.

#### Feldbeleg

Ein Endpunkt, der mit `Content-Length` antwortet und dessen Rumpf auf `0` endet,
laeuft in jeden Timeout. Messung am eigenen Endpunkt:

```
12:31:48  time   +620 s      <- 600-s-Ausloeser
12:32:08  time   + 20 s
12:32:28  time   + 20 s
12:32:48  time   + 20 s      <- vier Versuche, dann Aufgabe (retry > 3)
```

Der Abstand ist exakt der Timeout-Parameter `0x14`. Und zwischen den vier
Versuchen laeuft **kein** Upload — die Zustandsmaschine haengt die ganze Minute in
`case 0`, statt ihre Faelle durchzulaufen. Bei Erfolg macht der Code genau **eine**
Abfrage (Zeile 61–68 von `FUN_08015bd0`).

`Connection: close` allein behebt es nicht: nachgemessen am 2026-08-25, das Geraet
spricht HTTP/1.1, der Server schloss danach sofort — die Vierergruppen blieben.
Es ist das Zeilenende, nicht die Verbindung.

#### GELOEST 2026-08-26: es waren die Kopfzeilen

Die CR-LF-Bedingung oben steht so im Code und ist korrekt beschrieben — sie war
aber **nicht** die Ursache. Angleichen des Framings (chunked, keep-alive, kein
`Content-Length`, byte-gleich mit der echten Cloud) aenderte nichts: weiterhin
Vierergruppen im 20-Sekunden-Abstand.

Entschieden hat ein **Durchreichversuch**: Der eigene Endpunkt leitete die
Zeitabfrage an die echte Cloud weiter und gab deren Antwort woertlich zurueck,
direkt auf den Socket geschrieben.

| Antwort | Verhalten des Geraets |
|---|---|
| selbst gebaut, gleicher Rumpf, gleiches Chunked-Framing | vier Anfragen, 20 s Abstand, dann Aufgabe |
| echt, durchgereicht | **eine** Anfrage, akzeptiert |

Der Unterschied lag ausschliesslich in den Kopfzeilen:

```
unsere  HTTP/1.1 200 OK · Content-Type · Date · Connection · Keep-Alive · Transfer-Encoding
echte   HTTP/1.1 200 OK · Date · Content-Type · Transfer-Encoding · Connection · Trace-Id
```

Node haengt `Keep-Alive: timeout=5` an, das der echte Endpunkt nicht sendet, und
sortiert anders. **Welches der beiden Details die Firmware stoert, ist offen** —
der Endpunkt bildet seither die mitgeschnittene Antwort vollstaendig nach.

Der Upload-Host verlangte dieselbe Behandlung. Er steht hinter einem
Kong-API-Gateway und sendet sieben Kopfzeilen, die der Zeitendpunkt nicht sendet
(`vary`, `Access-Control-Allow-Credentials`, zwei `X-Kong-*-Latency`, `Via`,
`X-Kong-Request-Id`, HSTS). Mitgeschnitten mit einem POST ohne Nutzlast, den das
Gateway mit `{"code":51,"message":"The d field is required"}` ablehnt.

#### Der 86-Sekunden-Takt war eine Drossel, kein Timeout

Ueber weite Teile des 2026-08-25 kamen die Uploads exakt 86 Sekunden auseinander,
was als Wiederholungsrhythmus gelesen wurde. Es ist Zeile 102 aus `case 1`:

```c
if ((3 < count) && (Tick_Timer_Check_Elapsed(DAT_0801608c, 0x3c) == 0)) { state++; break; }
```

Ab vier gepufferten Datensaetzen drosselt die Firmware auf einen Upload pro
60 Sekunden. **Das Verschwinden dieses Rasters ist damit der direkte Anzeiger,
dass der Rueckstau unter vier gefallen ist** — und war das erste Signal, dass die
Korrektur greift, noch bevor die Ping-Messung nachzog.

#### Bestaetigung im Feld

Nach Aufspielen des korrigierten Endpunkts um 00:03 Uhr:

| Groesse | vorher | nachher |
|---|---|---|
| Zeitabfragen | 4 pro Ausloeser, 20 s Abstand | **1** pro ~600 s |
| Upload-Abstand | starr 86 s | **~300 s**, dem 5-Minuten-Raster folgend |
| CH395-Resets | alle 1804–1836 s | **keiner in sieben Stunden** |
| RS485-Steuermodus (42000) | mehrfach taeglich abgefallen | seit 02:13 unveraendert |

Die Ping-Reihe:

```
21:55:14           23:56:43   +1804
22:25:39   +1825   00:27:08   +1825
22:56:03   +1824   ——— korrigierter Endpunkt ———
23:26:39   +1836   nichts mehr
```

Ein Upload pro 300 s entspricht genau dem Push-Intervall aus
`HTTP_Economy_TOU_PeriodicHandler` — ein Upload pro Datensatz, also ein Zaehler,
der zwischen 0 und 1 pendelt. Damit ist `1 < count` dauerhaft falsch und die
Reset-Bedingung unerfuellbar.

#### Weiterhin offen

1. **Welche Kopfzeile genau** die Firmware ablehnt. Nicht eingegrenzt.
2. ~~**Ein zweiter Reset-Ausloeser.**~~ **Erledigt 2026-08-27.** Zwei Ausfaelle
   kurz nach der Korrektur lagen 1293 s und 1052 s auseinander, also unter der
   Untergrenze von 1800 s, die dieser Mechanismus einhalten muss. Beide fielen in
   die Phase, in der der Container mehrfach neu gestartet wurde — einer davon vier
   Minuten danach. Seither, ueber mehr als 24 h ohne Eingriff, **kein einziger
   Ausfall mehr**. Es waren unsere eigenen Neustarts, kein zweiter Ausloeser.
   Weitere Aufrufer von `CH395_Reset_And_Reinit` existieren (`BLE_Cmd_Dispatch`
   case 6, `FUN_0801fa3c` case 6, sowie die referenzlosen Wrapper `FUN_0802e1ac`
   und `FUN_0804c364`), sind aber Befehlspfade und im Feld nicht beobachtet.
3. **Uebertragbarkeit.** Ein Geraet, eine Firmwareversion, LAN. Meldungen von
   Venus E v3 passen ins Bild, aber kein anderer Build ist dekompiliert.

Vollstaendige Fallstudie mit allen widerlegten Zwischenhypothesen:
`Cloud_Watchdog_Fallstudie_2026-08-26.md`.

### Der zweite Preis von v150: vier Sekunden Modbus pro Upload

*(Bestaetigt 2026-08-27 an einem zweiten, fremden Geraet — Venus D, v150, LAN,
11,7 h Mitschnitt.)*

Unabhaengig vom Watchdog kostet v150 bei **jedem** Telemetrie-Upload rund vier
Sekunden, in denen das Geraet seinen Modbus-Server nicht bedient.

**Ursache: v150 hat den Upload von Klartext-HTTP auf TLS umgestellt.**

| | v149.2 | v150 |
|---|---|---|
| Endpunkt | `http://%s.hamedata.com/prod/api/v1/setVenusDReporting` | `https://api-%s.marstekcloud.com/data-upload/v1/venus/%s` |
| Transport | Klartext | TLS, `HTTPS_Request_Execute_CH395` @ `0x080174E8` |
| TLS-Session | — | `HTTPS_TLS_Session_Init` @ `0x080370A0`, *"in v149.2 nicht vorhanden"* |
| Uploadfunktion | — | `Cloud_Report_MarstekCloud_Upload` @ `0x08016B98`, neu |

Vor v150 kostete ein Upload praktisch keine Rechenzeit. Seit v150 faellt pro
Upload ein Schluesselaustausch an, und der dauert auf diesem Cortex-M in Software
mehrere Sekunden.

#### Messung

Rohmitschnitt eines fremden Geraets, 11,7 h nach einem Kaltstart, mit
antwortendem Offline-Endpunkt und abgeschaltetem MQTT:

| Groesse | Wert |
|---|---|
| Modbus-Antworten | 27 627 |
| Normalabstand (Median) | 2,44 s |
| Luecken > 3,5 s | **141** = 12,0/h |
| TLS-ClientHellos | **141** |
| Luecken, die mit einem Handshake zusammenfallen | **141 von 141** |
| laengste Luecken | 6,7–6,9 s |

**Kein einziger unerklaerter Ausfall.** Zwoelf pro Stunde entspricht exakt dem
5-Minuten-Push-Intervall — ein Handshake pro Datensatz.

Im Paketmitschnitt sieht man den Rechenaufwand direkt: zwischen
`Server Hello Done` und `Client Key Exchange` vergehen 4,4 s, waehrend derer das
Geraet ARP und UDP weiter beantwortet, aber Modbus nicht.

#### Abgrenzung zum Watchdog

Beides sieht von aussen nach "Modbus faellt aus" aus, ist aber verschieden:

| | Watchdog (§4a) | TLS-Rechenpause |
|---|---|---|
| Dauer | 2–5 s | 4–7 s |
| ICMP/ARP waehrenddessen | **weg** | laeuft weiter |
| Signatur | DHCP-Neuanforderung, mehrere ARP-Probes | keine |
| Takt | 1800 s | pro Upload, also ~300 s |
| behebbar | ja, Puffer leer halten | **nein** |

Als Detektor eignet sich der ARP-Eigenprobe-Takt des Geraets (eine pro Minute):
Bricht er ab, war es ein Stack-Neustart; laeuft er durch, war es Rechenzeit.

#### Konsequenz fuer Modbus-Clients

Ein Antwort-Timeout unter etwa **8 Sekunden** erzeugt auf v150 zwangslaeufig alle
fuenf Minuten einen Fehler, egal wie das Netz aussieht. Das betrifft jeden
v150-Venus, auch ohne Offline-Endpunkt und mit erreichbarer Cloud.

### Folge fuer Offener Punkt 5 (§12): Authmode 0 ist auch die Loesung

Weil `HTTPS_TLS_Session_Init` mit `MBEDTLS_SSL_VERIFY_NONE` arbeitet, ohne
CA-Kette und ohne Client-Zertifikat, laesst sich der Upload auf einen **eigenen
Endpunkt** umleiten:

| Schritt | Belegt durch |
|---|---|
| DNS-Override auf den api-Hostnamen | String @ `0x08017214` |
| TLS auf **Port 443**, Zertifikat beliebig | `CH395_TCP_Socket_Open_HTTPS`: `desc+8 = 0x1BB`; Authmode 0 |
| Antwort mit `{"code":0}` | `FUN_0801774c` |

Dann leert sich der Puffer, der Reset feuert nie, und kein Datensatz verlaesst
das lokale Netz. **Nicht abgedeckt:** der MQTT-Pfad
(`mbedTLS_SSL_Connection_Init`, Authmode 2 mit Client-Zertifikat) — der laeuft
unabhaengig weiter.

Der Regions-Platzhalter `%s` im Hostnamen wird aus einer Zeigertabelle bei
`0x20000FD0` gefuellt (Zeiger steht in `DAT_08017250`), Index aus EEPROM `0x441`
(`Cloud_Report_MarstekCloud_Upload`, Zeilen 22–32). Die Tabelle liegt im **RAM**
und ist aus dem Image heraus nicht aufloesbar — s. Offener Punkt 7.

---

## 5. Neues Feature: Peak Shaving

Komplett neu in v150, ansteuerbar über zwei Wege:

**BLE:**
```
[BLE] Set Peak shaving, power = %d, peak_state = %d.
```

**MQTT:**
```
[MQTT] Type: %d, Set peak status = %d, peak power = %d.
[MQTT] Set peak shaving err.
[MQTT] Type: %d, Set peak status = %d.
[MQTT] Set peak power err.
[MQTT] Type: %d, Get INV data info...
```

**Telemetrie:** Der große Reporting-String wurde um zwei Felder erweitert:

```
… ,soh=%d,peak_status=%d,peak_power=%d
```

Entfallen ist im Gegenzug der MQTT-Befehl
`[MQTT] Type: %d, Set manual mode or economy mode info...` samt Nutzlast `cd=%d,md=%d`.

> **Für die HA-Integration relevant:** `peak_status` und `peak_power` sind neue
> steuerbare Größen. Ob sie zusätzlich über Modbus (RS485/TCP) erreichbar sind,
> ist noch nicht verifiziert — die Register-Deskriptortabelle wird zur Laufzeit
> aufgebaut und wurde für v150 noch nicht gescannt. **Offener Punkt.**

---

## 6. Weitere Telemetrie-Änderungen

| String | Änderung |
|---|---|
| BMS-Block `cd=%d,b_ver=…` | **+ `self_check=%d,mos=%d`** |
| Haupt-Block `cd=%d,tot_i=…` | **+ `peak_status=%d,peak_power=%d`** |
| `g_st=%d,g_flag=%d,g_bau=%d,…,g_minpw=%d,g_maxpw=%d` | **neu** — Generator-/Grid-Parameterblock |
| `bms_ver=\t%d`, `vns_ver=\t%d` | **neu** (Shell/Debug-Ausgabe) |
| `bat_mode=%d` | entfallen |
| `[HTTP] Read Eco-Tracker ip: %s.` | verschoben (`0x0800D817` → `0x0800DA40`) |
| `[HTTP]fc41d reset!!!!`, `[HTTP]ch395 reset!!!!` | **neu** — Recovery-Pfade |
| `[FC41D] HTTP P1 meter data: %s.` | jetzt referenziert |
| `+QMTSUB: 0,1,0,0`, `+QMTPUB: 0,0,0`, `+QHTTPGET: 9` | entfallen |
| `Tmr Svc` | entfallen; **neu** `FreeRtos_mem` |

---

## 7. Inhaltlich geänderte Funktionen (Decompiler-Diff verifiziert)

| Funktion | v149.2 | v150 | Sim. | Δ Byte | Änderung |
|---|---|---|---|---|---|
| `MQTT_Credential_Buffer_Decode` | `0x08005860` | `0x080057CC` | 0.58 | +54 | **Verfahren gewechselt** (s. u.) |
| `Quectel_MQTT_Unsubscribe` | `0x0800E6F4` | `0x0800C21C` | 0.58 | −24 | `log_printf`/`memset`/`sprintf` entfallen |
| `Quectel_HTTP_AT_SendAndVerify` | `0x0800BCC4` | `0x0800BEF4` | 0.62 | +6 | Timing-/Prüflogik leicht umgebaut |
| `Write_Handler` | `0x08050F20` | `0x08051D14` | 0.63 | 0 | FreeRTOS-Write-Handler umgebaut |
| `Modem_ConnInfo_UpdateMeterIP` | `0x0801379C` | `0x08013A50` | 0.65 | 0 | Meter-IP-Übernahme umgebaut |
| `Inverter_PowerSetpoint_DeadbandClamp` | `0x08013CC8` | `0x08013F7C` | 0.69 | +30 | **neue Klemmrichtung** (s. u.) |
| `mbedTLS_SSL_Connection_Init` | `0x08018364` | `0x08018934` | 0.73 | −6 | ruft `MQTT_TLS_Context_Reset` nicht mehr |
| `HTTP_Response_Parse` | `0x08026930` | `0x080273F0` | 0.74 | +2 | minimal |
| `Parse_IP_Address_String` | `0x08004CD0` | `0x08004C3C` | 0.81 | 0 | nur Quellzeilennummer im Log (0x182 → 0x2C9) |
| `HTTPS_POST_Request` | `0x08014DC0` | `0x08015094` | 0.83 | 0 | **Puffer 0x1958 → 0x1DC0 B** (6488 → 7616) |
| `MQTT_TLS_Context_Reset` | `0x08012984` | `0x08012C38` | 0.84 | 0 | — |
| `Config_Write_String_0x388` | `0x08006E3C` | `0x08006E04` | 0.86 | 0 | **EEPROM 0x388 → 0x387** |

### 7.1 `Inverter_PowerSetpoint_DeadbandClamp` — neue Klemmrichtung

```c
      else if (*(char *)(configBase + 0x85) == '\x01') {   // NEU in v150
        if (param_3 < local_1e) { param_3 = local_1e; }    // untere Grenze
      }
      else if (local_1e <= param_3) {                      // wie v149.2
        param_3 = local_1e;                                // obere Grenze
      }
```

Ein neues Konfigurationsbyte bei **Struct-Offset `+0x85`** (SRAM-Basis `0x20014D00`)
kehrt die Klemmrichtung der Leistungsvorgabe um. Geschrieben wird es von der
ebenfalls neuen Funktion **`Config_Write_PowerClampMode_0x394` @ `0x08006B84`**,
die Byte `+0x85` und Halbwort `+0x87` setzt und **6 Byte ab EEPROM-Adresse `0x394`**
persistiert.

> Sehr wahrscheinlich der Persistenz-Slot des Peak-Shaving-Features
> (`peak_state` + `peak_power` = 1 Byte + 2 Byte). **Noch zu verifizieren.**

### 7.2 `MQTT_Credential_Buffer_Decode` — Deobfuskierung ersetzt

v149.2 rief eine feste Routine `Flash_Obfuscated_String_Decode` auf. In v150 ist
diese Funktion **komplett entfallen** (auch der zweite Aufrufer
`sscanf_Format_Parser` ruft sie nicht mehr). Stattdessen:

```c
    local_28 = 0;
    for (i = 0; i < ((len - off) - 1 & 0xffff); i++) {
      r = Flash_ReadWords(&local_28, 1);
      if (r != 0x5a5a5a5a) return;                     // Abbruch bei Fehler
      buf[off + i] = alphabet64[local_28 % 0x40];      // 64-Zeichen-Tabelle
    }
    buf[len - 1] = 0;
```

Der Rest des Credential-Puffers wird aus einer 64-Zeichen-Tabelle
(`DAT_08005848`) gefüllt, indexiert über einen aus dem Flash gelesenen Wert
(Magic `0x5A5A5A5A` als Gültigkeitsprüfung).

---

## 8. In v149.2 toter Code — in v150 aktiviert

Diese Funktionen bzw. String-Kopien lagen bereits in v149.2 im Flash, waren dort
aber **von keiner Funktion referenziert**. In v150 sind sie aktiv:

| Adresse (v150) | Name | Beleg |
|---|---|---|
| `0x0801479C` | `Quectel_HTTP_GET_StateMachine` | `[HTTP] GET success/timeout/retry`, `[HTTP] Data read OK.` |
| `0x0800AE48` | `BLE_GATT_Add_Service` | `AT+QBLEGATTSSRV=%s` |
| `0x0800AFC0` | `BLE_GATT_Add_Characteristic` | `AT+QBLEGATTSCHAR=%s` |
| `0x0800AD08` | `BLE_Query_Device_Name` | `AT+QBLENAME?`, `MST_VNSD_` |
| `0x0800221C` | `Timer_Callback_BLE_Modem_Supervisor` | `*** xTimerStart end 1..........` |
| `0x0802A898` | `CLI_Cmd_FactoryReset` | `Reset, clear all/cert/part...` |
| `0x08002CD4` | `CH395_SPI_Cmd_WithResponse` | zweite Kopie des Mutex-Fehlerstrings |

Ergänzend neu: **`BLE_Stack_Init_Sequence` @ `0x0800A4DC`** (678 B) — orchestriert
`BLE_Module_Init`, `BLE_Set_Device_Name`, `BLE_Query_Device_Name`,
`BLE_Set_AdvParams`, `BLE_AdvertisingControl` und `Quectel_AT_QVERSION_Query`.

> Die BLE-GATT-Server-Konfiguration (Service + Characteristic) wird in v150
> also erstmals tatsächlich abgesetzt. Für BLE-basierte Integrationen relevant.

---

## 9. Code-Duplikate / Zwillinge

v150 enthält mehrere Funktionen doppelt — identische Instruktionsfolge, aber
eigener Daten-/Kontextbezug. Ursache ist offenbar die Verdopplung des
HTTP-Moduls für den HTTPS-Pfad.

| Original | Zwilling | Rolle des Zwillings |
|---|---|---|
| `HTTP_Response_Parse` `0x080273F0` | `HTTPS_Response_Parse` `0x08027564` | byte-identisch, HTTPS-Pfad |
| `HTTP_BuildRequestBuffer` `0x08027028` | `HTTPS_BuildRequestBuffer` `0x080270E8` | HTTPS-Pfad |
| `CH395_TCP_Socket_Open_HTTPPort80` `0x08018164` | `CH395_TCP_Socket_Open_HTTPS` `0x0801821C` | HTTPS-Pfad |
| `MQTT_TLS_Context_Reset` `0x08012C38` | `HTTPS_TLS_Context_Reset` `0x080158D0` | HTTPS-Pfad |
| `RCC_LSICmd` `0x08017D84` | `RCC_LSICmd_Alias` `0x08028B8C` | von `RTC_ConfigClockSource` genutzt |
| `RCC_RTCCLKCmd` `0x08017D90` | `RCC_RTCCLKCmd_Alias` `0x08028B98` | von `RTC_ConfigClockSource` genutzt |
| `fp_Set_Exception` `0x08028B80` | `fp_Set_Exception_Alias` `0x08031FF0` | von `fp64_pow`/`fp64_sqrt_…` genutzt |
| `Quectel_HTTP_AT_SendAndVerify` `0x0800BEF4` | `…_Unused` `0x0800BD98` | **0 Aufrufer — toter Code** |

> **Fallstrick beim Version-Tracking:** Der `combined-reference`-Korrelator hat
> drei dieser Zwillingspaare zunächst vertauscht zugeordnet
> (`MQTT_TLS_Context_Reset`, `mbedTLS_SSL_Connection_Init`,
> `Quectel_HTTP_AT_SendAndVerify`). Die Zuordnung wurde anhand der
> String-Referenzen und Aufrufer-Ketten korrigiert; die betroffenen Funktionen
> tragen einen entsprechenden Plate-Kommentar in Ghidra.

---

## 10. Weitere neu benannte Funktionen (Auswahl)

| Adresse | Name | Herkunft |
|---|---|---|
| `0x08003DC0` | `SMR_TIC_SelfUse_PowerController` | v149.2 `0x08003E54` |
| `0x080074AC` | `CH395_SendData_WaitResponse` | v149.2 `0x080074E4` (+54 B) |
| `0x0800584C` | `MQTT_Topic_Builder` | v149.2 `0x080058E0` (−24 B) |
| `0x080058CC` | `MQTT_Topic_Log_XidDevice` | Log-Helfer ausgelagert |
| `0x0800DCF4` | `HTTP_Cloud_Reporting_Dispatcher` | v149.2 `0x0800DAC8` |
| `0x080151AC` | `Cloud_Report_URL_Builder` | v149.2 `0x08014ED8` |
| `0x08018698` | `MQTT_Connect_And_Subscribe` | v149.2 `0x080180C8` |
| `0x0801F698` | `MQTT_Publish_BMS_Full_Data` | v149.2 `0x0801F0D0` (−98 B) |
| `0x08022A14` | `MQTT_Publish_DevelopModeInfo` | neu benannt |
| `0x08022B34` | `MQTT_Publish_ErrorEventLog` | `err%d=%d|…` über Modem |
| `0x08026C70` | `DeviceInfo_BuildStatusString` | v149.2 `0x08026344` (**+136 B**) |
| `0x08029FB0` | `Remote_Power_Setpoint_Process` | v149.2 `0x08029458` (**+62 B**) |
| `0x0802D360` | `WorkMode_State_Machine` | v149.2 `0x0802C784` (−18 B) |
| `0x0802D6BC` | `Cloud_EdgeDetectAndWatchdog` | v149.2 `0x0802CAF4` (+18 B) |
| `0x0802E874` | `Tick_Timer_Check_Elapsed` | Rollentausch mit `Tick_Timer_Expired` |
| `0x0802FECC` | `MQTT_Telemetry_String_Formatter` | v149.2 `0x0802F2F0` (**852 → 370 B**) |
| `0x0800B4F4` | `BLE_Build_BMS_Data_Response` | v149.2 `0x0800B430` (+10 B) |
| `0x0800C090` | `Energy_TOU_Counters_Load` | Lesepfad aus v149.2 `0x0800BE50` |
| `0x08017D64` | `IWDG_Start` | schreibt `0xCCCC` in `IWDG_KR` (`0x40003000`) |
| `0x08017D74` | `IWDG_ReloadCounter` | schreibt `0xAAAA` in `IWDG_KR` |
| `0x0802A888` / `0x0802E1B8` / `0x08013920` | `Http_BusyFlag_Clear` / `_Set` / `_Get` | Byte `+0x39` bei `0x20017D8C` |
| `0x08002750` | `RCC_PeripheralReset_Pulse` | `RCC_APB1PeriphResetCmd` |
| `0x0800B7F4` | `Stub_Return_One` | Stub, 0 Aufrufer |

---

## 11. Entfallene Funktionen (in v150 nicht mehr auffindbar)

`Base64_Encode`, `Flash_Obfuscated_String_Decode`, `Cloud_Reporting_setVenusDReporting`,
`HTTP_ParseUploadDecryptResultFlag`, `MQTT_Telemetry_EnergyCounter_Update`
(nur Lesepfad überlebt), `BLE_Recv_Cmd_Dispatcher` in der alten Form,
`Task_Init_CreateAll`, `WiFi_*`-Reset-Familie (`WiFi_Module_RestartStateMachine`,
`WiFi_HardwareResetSequence`, `WiFi_ModuleResetDispatcher`, `WiFi_ResetWithRecoveryWait`,
`WiFi_PowerCycleSequence`), `Relay_StagedTimingControl`, `Register_ToggleBit15`,
`ConditionalSystemReboot`, `Standby_Wakeup_Debounce`, `Config_Get_WorkMode`,
`Config_Read_ProductionDate`, `Debug_PrintModbusAddress`,
`Register_Write_PackedAsciiValue_Group0xCC`, `GPIO_TogglePin_Periodic`,
`System_SoftReset`, `FPU_EnableCoprocessorAccess`, `vPortSetupTimerInterrupt`,
`vTaskStartScheduler`, `FreeRTOS_StartScheduler`, `FreeRTOS_xTimerCreateTimerTask`.

> Ein Teil dieser Einträge ist **kein echter Wegfall**, sondern eine
> Nicht-Zuordnung durch das Version-Tracking (Ghidra VT hat keinen
> Körperähnlichkeits-Korrelator). Die FreeRTOS-Scheduler-Funktionen und die
> WiFi-Reset-Familie sind mit hoher Wahrscheinlichkeit weiterhin vorhanden,
> nur unter anderer Adresse und in v150 bereits über andere Namen erfasst.
> **Offener Punkt für eine Folgesitzung:** gezielte Gegenprüfung dieser 25 Namen.

---

## 12. Offene Punkte

1. **Modbus-Registerkarte für v150 nicht gescannt.** Ob `peak_status` / `peak_power`
   über Modbus TCP/RS485 erreichbar sind (und unter welchen Registern), ist offen.
   Die Deskriptortabelle wird zur Laufzeit aufgebaut — ein Live-Scan gegen ein
   Gerät mit v150 ist nötig.
2. **EEPROM-Layout-Verschiebung `0x388 → 0x387`** und der neue Block ab `0x394`
   (6 Byte) sind noch nicht vollständig gegen die bestehende EEPROM-Map abgeglichen.
   *(Teilweise erledigt 2026-08-14: Der Config-Block `0x200`–`0x206` ist belegt —
   s. `Modbus_RS485_TCP/Register_Persistenz_RAM_vs_EEPROM_v150.md`.)*
3. **`HTTPS_Response_Marker_Matcher` @ `0x08027478`** — 0 Aufrufer, Zweck nur
   vermutet (Confidence: low).
4. **25 als „entfallen" gelistete Funktionen** gegenprüfen (s. §11).
5. **`Authmode 0` im neuen HTTPS-Pfad** — praktische Auswirkung (MITM-Risiko beim
   Cloud-Upload) bewerten; ggf. für die Security-Dokumentation aufnehmen.
   *(Bewertet 2026-08-25, s. §4a: der Upload lässt sich ohne jedes Zertifikat auf
   einen beliebigen Endpunkt umleiten. Kehrseite derselben Medaille — genau das
   ist der einzige Weg, den 30-Minuten-Reset ohne Firmware-Patch abzustellen.)*
6. **Semantik von Register 37001 / `0x2000014C`** offen. Es torwächtert den
   CH395-Reset (§4a), steht in allen Scan-Logs auf 0, und die Registerkarte führt
   es mit Konfidenz „niedrig". Writer `Protocol_AA_SetDeviceParams`, Leser
   `Grid_Export_Power_Limiter`.
7. **Regions-Tabelle bei `DAT_08017250`** nicht aus dem Image auflösbar.
   `0x08017250` enthält den Zeiger `0x20000FD0` — die Tabelle liegt also im **RAM**
   und wird zur Laufzeit gefüllt; auf `0x20000FD0` gibt es keine Querverweise.
   Der konkrete api-Hostname pro Region ist damit statisch nicht belegbar. Wege:
   DNS-Anfrage des Geräts mitschneiden, oder SWD-Dump (s.
   `Methodik_und_Meta/SWD_JTAG_Dump_Plan.md`).

---

## 13. Reproduktion

```
# 1. Image-Basis korrigieren
setImageBase(0x08000000, commit=True)

# 2. Full-Analysis
analyze-program  programPath=/VNSD-0_app_0150_0805_115146.bin  forceFullAnalysis=true

# 3. Diff-Session
diff-create-session
  source=/Control_149.2_VNSD-0_app_1492_0702_142136.bin
  destination=/VNSD-0_app_0150_0805_115146.bin
diff-add-correlator  correlator=combined-reference

# 4. Markup übertragen
diff-transfer-markup  confidence=0.5

# 5. Restliche Funktionen manuell zuordnen (String-Referenzen + Aufrufer-Ketten)
```
