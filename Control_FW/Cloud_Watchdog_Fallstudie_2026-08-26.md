# Fallstudie: der 30-Minuten-Reset — von der Beobachtung bis zur Ursache

*Erstellt 2026-08-26. Geraet: Venus D, Control-Firmware v150, LAN.
Zugehoerige Analyse: `Control_FW_Analyse_app_0150_0805_115146.md` §4a.*

Diese Datei haelt den **Weg** fest, nicht nur das Ergebnis. Vier Erklaerungen
hielten sich ueber einen ganzen Tag, jede mit einem echten Mechanismus im Code
und einer Zahl, die zur Messung passte. Alle vier waren falsch. Ein einziges
Kontrollexperiment hat sie in zehn Minuten erledigt. Der Fehler in der Methodik
ist uebertragbarer als der Befund.

---

## 1. Ausgangslage

Der Mechanismus war bekannt (`FUN_08015bd0`, §4a):

```c
if (((1 < *(ushort *)(DAT_08015fcc + 2)) &&
     (Tick_Timer_Check_Elapsed(DAT_0801600c, 0x708) != 0)) &&
    (*_DAT_08016010 == 0)) {
    CH395_Reset_And_Reinit(0);
    log_printf(3, 1, "[HTTP]ch395 reset!!!!");
    *DAT_0801600c = 0;
}
```

Mehr als ein gepufferter Telemetrie-Datensatz, 1800 s abgelaufen, Statusregister
37001 gleich null → Hardware-Reset der Ethernet-Bruecke. 2–3 s ohne Netz, ohne
Modbus, ohne ICMP.

Die Folgerung lag nahe: Upload beantworten, Puffer leert sich, Bedingung nie
erfuellt. Ein Container wurde gebaut, der genau das tut, und die Uploads kamen
auch nachweislich an.

**Die Resets liefen weiter.** Zwoelf Stueck in fuenfeinhalb Stunden, Mittel
1829 s, Streuung 43 s.

---

## 2. Vier widerlegte Hypothesen

### 2.1 Die Zeitantwort war fehlerhaft

Sie war es tatsaechlich — abgeschnitten und in Lokalzeit statt im Format des
Originals. Die Korrektur war noetig und richtig.

**Sie aenderte nichts.** Der naechste Reset lag 34 s neben einer Vorhersage aus
dem vorherigen Intervall, deutlich innerhalb der Streuung von 43 s. Der Takt lief
sogar durch einen vollstaendigen Container-Neustart hindurch, waehrend dessen
ueberhaupt nichts antwortete.

*Lehre:* Einen echten Defekt zu beheben beweist nicht, dass es **der** Defekt war.

### 2.2 Ein Kaltstart raeumt den Zaehler ab

Der Zaehler liegt auf `0x2000100C` im regulaeren SRAM. Kein Codepfad stellt ihn
aus nichtfluechtigem Speicher wieder her — nur drei Funktionen fassen den
Ringpuffer-Header ueberhaupt an.

Der Teil stimmte, und die Messung belegte ihn: Nach dem Kaltstart war das erste
Intervall **2133 s** gegen 1824 s im eingeschwungenen Zustand. Die zusaetzlichen
309 s sind der Zaehler, der wieder ueber seine Schwelle steigt —
`Tick_Timer_Check_Elapsed` bleibt wahr, sobald abgelaufen, der Reset feuert also,
sobald die *letzte* offene Bedingung wahr wird.

**Aber er stieg binnen 35 Minuten zurueck, und der Takt kehrte wieder.** Ein
Neustart ist keine Loesung.

### 2.3 Nodes Keep-Alive blockiert das Geraet

Gegen die echte Serverdatei nachgemessen: Bei HTTP/1.1 hielt Node die Verbindung
offen, ein Testclient wartete bis zu seinem eigenen Timeout. Das Geraet spricht
HTTP/1.1 (spaeter aus `req.httpVersion` protokolliert). Die Theorie passte.

`Connection: close` wurde eingebaut und nachgewiesen, dass der Socket sofort
schliesst. **Die Vierergruppen blieben unveraendert.**

### 2.4 Die Empfangsschleife braucht CR LF am Ende

Diese Bedingung ist real und steht so im Code
(`HTTPS_POST_ReceiveResponseData` @ `0x08015744`):

```c
} while ( ( (total == 0) || (idle < 0x15) ||
            (buf[total-1] != '\n') || (buf[total-2] != '\r') )
          && !elapsed(timer, timeout) && total < maxlen );
```

Vorzeitiger Ausstieg nur, wenn Daten da sind, 21 Leerabfragen vergangen sind
**und** die letzten zwei Bytes CR LF lauten. Eine Antwort, die auf `0` endet,
laeuft in den vollen Timeout — und der ist `Cloud_Report_URL_Builder(1, 0x14)`,
also 20 s, exakt der beobachtete Wiederholungsabstand.

Der Endpunkt wurde auf CR-LF-Ende umgestellt, dann auf chunked mit
Abschluss-Chunk, byte-gleich mit einem Rohmitschnitt der echten Cloud.

**Weiterhin vier Versuche. Weiterhin 20 Sekunden Abstand.**

---

## 3. Warum sich alle vier so lange hielten

Jede hatte einen Mechanismus im Code, Belege und eine passende Zahl. Und jeder
Test bestand darin, **etwas zu aendern**. Eine Aenderung, die nicht hilft, sagt
fast nichts aus — sie kann richtig und trotzdem unzureichend sein.

Was fehlte, war eine **Kontrolle**: derselbe Vorgang mit einer bekannten guten
Gegenstelle, bei nur einer geaenderten Variable.

---

## 4. Das entscheidende Experiment

Der Container bekam einen Durchreichmodus: Die Zeitabfrage wird an die echte
Cloud weitergereicht und deren Antwort **woertlich** zurueckgegeben, direkt auf
den Socket geschrieben, damit Node nichts umformt. Der Telemetrie-Upload blieb
dabei lokal.

Das Ergebnis kam in einem Zehn-Minuten-Fenster:

| Antwort | Verhalten |
|---|---|
| selbst gebaut, gleicher Rumpf, gleiches Chunked-Framing | vier Anfragen, 20 s Abstand, dann Aufgabe |
| echt, durchgereicht | **eine** Anfrage, akzeptiert |

Der Unterschied lag ausschliesslich in den Kopfzeilen:

```
unsere  HTTP/1.1 200 OK · Content-Type · Date · Connection · Keep-Alive · Transfer-Encoding
echte   HTTP/1.1 200 OK · Date · Content-Type · Transfer-Encoding · Connection · Trace-Id
```

Node haengt `Keep-Alive: timeout=5` an, das das Original nicht sendet, und
sortiert anders. Welches Detail die Firmware stoert, ist **nicht eingegrenzt**;
der Endpunkt bildet seither die gesamte mitgeschnittene Antwort nach.

### Der Upload-Host

Ein anderer Rechner hinter einem Kong-API-Gateway, mit sieben zusaetzlichen
Kopfzeilen: `vary`, `Access-Control-Allow-Credentials`, `X-Kong-Upstream-Latency`,
`X-Kong-Proxy-Latency`, `Via: 1.1 kong/3.9.1`, `X-Kong-Request-Id`,
`Strict-Transport-Security`.

Mitgeschnitten **ohne** Telemetrie: Ein POST mit `{}` als Rumpf wird mit
`{"code":51,"message":"The d field is required"}` abgelehnt — das Framing ist,
worauf es ankam.

---

## 5. Aufrufkette und Fehlercodes (fuer die naechste Untersuchung)

```
FUN_08015bd0 case 0 (Zeit)          FUN_08015bd0 case 1 (Upload)
  Cloud_Report_URL_Builder(1,0x14)    Cloud_Report_MarstekCloud_Upload
    @0x080151AC                         @0x08016B98
  HTTPS_POST_Request @0x08015094      HTTPS_Request_Execute_CH395 @0x080174E8
    HTTPS_POST_ReceiveResponseData      mbedTLS_SSL_Recv_WithRetry @0x08015914
      @0x08015744  (CR-LF-Bedingung)      (nur close_notify oder Timeout)
    HTTP_Response_Parse @0x080273F0     HTTPS_Response_Parse @0x08027564
      llhttp, Typ 2                       llhttp, Typ 2
```

`HTTPS_POST_Request` / `HTTPS_Request_Execute_CH395`, Rueckgabe `0` = Erfolg:

| Code | Ursache |
|---|---|
| −1 | Argumente |
| −2 | `HTTP_URL_ExtractPath` |
| −3 | Anfragepuffer |
| −4 | DNS / CH395-Kommando |
| −5 | SPI-Senden bzw. TCP-Connect-Timeout |
| −6 | TLS-Session-Init |
| −8 | SSL-Send |
| −9 | Empfang lieferte 0 Bytes |
| **−10** | **llhttp-Parse fehlgeschlagen** |

`Cloud_Report_MarstekCloud_Upload` bildet jeden Wert ungleich 0 auf `0` ab, und
`FUN_08015bd0` nimmt bei `0` den Fehlerzweig — **dort wird `count` nie
dekrementiert**, nur der Wiederholungszaehler `+0x10`.

### Der TLS-Empfang bricht Daten weg

```c
if ((int)uVar1 < 1) {
    if (uVar1 == 0xffff8780) { ... }                       // close_notify: sauber
    if ((uVar1 != 0xffff9700) && (uVar1 != 0xffff9780)) {
        return uVar1;        // gibt den FEHLER als Ergebnis zurueck
    }
}
```

Der Aufrufer schreibt diesen Wert als **Laenge** weiter. Ein harter
Verbindungsabriss nach sechs Sekunden liess llhttp deshalb zehntausende Bytes aus
einem 3-KB-Puffer parsen — garantierter Parse-Fehler, Code −10, Fehlerzweig, kein
Dekrement.

Die echte Cloud antwortet mit `keep-alive` und schliesst **nie**. Das Geraet
wartet dort also bei jedem Upload seinen vollen 20-Sekunden-Timeout ab. Das ist
normal.

---

## 6. Der 86-Sekunden-Takt

Ueber einen ganzen Tag kamen die Uploads exakt 86 s auseinander, gelesen als
Wiederholungsrhythmus. Es ist eine Drossel (`case 1`, Zeile 102):

```c
if ((3 < count) && (Tick_Timer_Check_Elapsed(DAT_0801608c, 0x3c) == 0)) { state++; break; }
```

Ab vier gepufferten Datensaetzen: hoechstens ein Upload pro 60 s. Das
**Verschwinden** dieses Rasters ist damit ein direkter Indikator fuer einen
Rueckstau unter vier — und war das erste Signal, dass die Korrektur greift.

---

## 7. Ergebnis

| Groesse | vorher | nachher |
|---|---|---|
| Zeitabfragen | 4 pro Ausloeser, 20 s Abstand | 1 pro ~600 s |
| Upload-Abstand | starr 86 s | ~300 s, dem 5-Minuten-Push folgend |
| CH395-Resets | alle 1804–1836 s | keiner in sieben Stunden |
| Register 42000 | mehrfach taeglich abgefallen | seit 02:13 unveraendert |

Ein Upload pro 300 s entspricht dem Push-Intervall aus
`HTTP_Economy_TOU_PeriodicHandler` — ein Upload pro Datensatz, Zaehler zwischen 0
und 1. `1 < count` ist damit dauerhaft falsch.

Der Rueckstau brauchte nach der Korrektur rund 45 Minuten zum Leerlaufen.

---

## 8. Offene Punkte

1. **Welche Kopfzeile** die Firmware ablehnt — nicht eingegrenzt.
2. ~~**Ein zweiter Reset-Ausloeser.**~~ **Erledigt 2026-08-27.** Die beiden
   Ausfaelle mit 1293 s und 1052 s Abstand fielen in die Phase mehrerer
   Container-Neustarts; einer lag vier Minuten nach einem davon. Ueber mehr als
   24 h ohne Eingriff kam keiner mehr. Es war unsere eigene Stoerung. Die uebrigen
   Aufrufer von `CH395_Reset_And_Reinit` (`BLE_Cmd_Dispatch` case 6,
   `FUN_0801fa3c` case 6, die referenzlosen Wrapper `FUN_0802e1ac` und
   `FUN_0804c364`) bleiben unbeobachtet — es sind Befehlspfade.
3. **Uebertragbarkeit.** Ein Geraet, eine Firmwareversion, LAN.
4. **Ob das Framing des Upload-Hosts genauso streng ist** wie das des
   Zeitendpunkts. Die Kong-Kopfzeilen wurden aus der Ueberlegung heraus ergaenzt,
   dass ein ebenso harmlos wirkender Unterschied schon einmal entscheidend war.
   Das ist eine Abwaegung, keine Messung.

---

## 9. Methodische Lehre

**Eine Aenderung, die nicht hilft, ist kein Test.** Sie kann richtig und
unzureichend zugleich sein. Vier Hypothesen ueberlebten einen Tag, weil sie
ausschliesslich so geprueft wurden.

Was sie erledigt hat, war ein Vergleich gegen eine **bekannte gute Gegenstelle**
bei einer einzigen geaenderten Variable. Aufwand: eine Stunde Bauen, zehn Minuten
Messen.

Wenn eine Imitation nicht akzeptiert wird und alle inhaltlichen Unterschiede
ausgeschlossen sind, liegt es an dem, was man **nicht** vergleicht — hier an dem,
was die eigene Bibliothek von sich aus hinzufuegt.
