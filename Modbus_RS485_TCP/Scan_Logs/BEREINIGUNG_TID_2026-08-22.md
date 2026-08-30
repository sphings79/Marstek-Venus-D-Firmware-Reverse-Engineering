# Bereinigung verschobener Scans (TID-Fehler), 2026-08-22

Entfernt wurden Scan-Zyklen, in denen Werte durch eine fehlzugeordnete
Modbus-Antwort im falschen Register standen.

**Die Originale liegen unveraendert in `_backup_vor_tid_bereinigung_20260822/`.**

## Ursache

`scan_continuous.py`, `scan_known_registers.py` und `scan_powercycle.py` setzten im
MBAP-Header eine Transaction-ID, prueften sie beim Empfang aber nicht. Eine verspaetete
Antwort auf Anfrage N wurde dadurch als Antwort auf N+1 gelesen. Alle drei Skripte sind
seit 2026-08-22 korrigiert; `scan_registers.py` war bereits korrekt.

## Erkennung und Entscheidung

Ein Treffer verlangt: Traegerregister stabil (Modusanteil >= 90 %, mind. 6 Messungen),
der auffaellige Wert kommt dort hoechstens 2x im Log vor, und ein anderes stabiles
Register verliert im selben Zyklus genau diesen Wert.

Treffer gelten als **hart**, wenn der Fremdwert weit genug vom Normalwert des Traegers
entfernt liegt (Abstand > max(5, 25 % des Normalwerts)) — ein echter Frame-Versatz
bringt einen voellig fremden Wert. Andernfalls **schwach**: das kann auch Messrauschen
oder ein realer Zustandswechsel sein.

**Entfernt wurden alle Treffer-Zyklen in Logs, die mindestens einen harten Treffer
enthalten** — auch die schwachen. Begruendung: Eine Desynchronisation laeuft ueber
mehrere aufeinanderfolgende Anfragen; ist sie fuer ein Log belegt, sind auch dessen
schwache Treffer nicht mehr vertrauenswuerdig.

Logs **ohne** harten Treffer bleiben unveraendert. Betroffen ist nur
`discharge_w_steps1.csv`: dort wechselt Pack 1 seine MOSFETs von 3 auf 0 und Pack 2
gleichzeitig von 0 auf 3, ueber zwei Zyklen 30 s auseinander — ein realer
Zustandswechsel, keine Verschiebung. Ebenso ein Tausch benachbarter Zelltemperaturen
(233/234).

## Validierung der Methode

`watch_update.csv` (10.249 Zyklen, mit TID-Pruefung aufgenommen) ist sauber,
`watch_update_vor_tid_fix.csv` aus derselben Messreihe nicht. Die Treffer treten
ausserdem in *aufeinanderfolgenden* Zyklen auf — das erwartete Verhalten einer
Desynchronisation, die erst nach einem Timeout wieder einrastet.

## discharge_under_dod.csv

- Format: breit, 548 Zyklen, davon **2 entfernt** (2 Spalten)
- Harte Treffer in: 10:14:04, 10:15:23

| Zyklus | Register | falscher Wert | gehoert zu | zeigt sonst | hart |
|---|---|---|---|---|---|
| 10:14:04 | 34007 | 7 | 34003 | 0 | ja |
| 10:14:04 | 34410 | 116 | 37012 | 0 | ja |
| 10:14:04 | 34502 | 116 | 37012 | 0 | ja |
| 10:14:04 | 34503 | 45 | 34303 | 0 | ja |
| 10:14:04 | 34510 | 116 | 37012 | 0 | ja |
| 10:14:04 | 37000 | 0 | 44002 | 1 | nein |
| 10:14:04 | 37002 | 1 | 41100 | 0 | nein |
| 10:14:04 | 37003 | 1 | 41100 | 0 | nein |
| 10:14:04 | 37012 | 0 | 44002 | 116 | ja |
| 10:14:04 | 37015 | 116 | 37012 | 0 | ja |
| 10:14:04 | 41100 | 0 | 44002 | 1 | nein |
| 10:14:04 | 43100 | 1 | 41100 | 127 | ja |
| 10:14:04 | 44002 | 127 | 43100 | 0 | ja |
| 10:15:23 | 30200 | 0 | 41200 | 147 | ja |

## entladen_lang.csv

- Format: lang, 669 Zyklen, davon **6 entfernt** (54 Zeilen)
- Harte Treffer in: 14:16:34
- Zusaetzlich entfernt (nur schwache Treffer): 14:16:33, 14:16:35, 14:24:17, 14:42:15, 14:42:16

| Zyklus | Register | falscher Wert | gehoert zu | zeigt sonst | hart |
|---|---|---|---|---|---|
| 14:16:33 | 37000 | 0 | 36000 | 1 | nein |
| 14:16:34 | 37009 | 1 | 41100 | 0 | nein |
| 14:16:34 | 37012 | 0 | 38003 | 118 | ja |
| 14:16:34 | 38003 | 118 | 37012 | 0 | ja |
| 14:16:34 | 41100 | 0 | 38003 | 1 | nein |
| 14:16:35 | 42010 | 1 | 43000 | 2 | nein |
| 14:16:35 | 42020 | 2 | 42010 | 0 | nein |
| 14:16:35 | 43000 | 0 | 43101 | 1 | nein |
| 14:16:35 | 43101 | 1 | 43000 | 0 | nein |
| 14:24:17 | 42010 | 1 | 43000 | 2 | nein |
| 14:24:17 | 42020 | 2 | 42010 | 0 | nein |
| 14:24:17 | 43000 | 0 | 43101 | 1 | nein |
| 14:24:17 | 43101 | 1 | 43000 | 0 | nein |
| 14:42:15 | 30212 | 0 | 30110 | 5 | nein |
| 14:42:16 | 30300 | 0 | 32102 | 1 | nein |
| 14:42:16 | 30301 | 0 | 32102 | 1 | nein |
| 14:42:16 | 32102 | 5 | 31003 | 0 | nein |

## laden_lang.csv

- Format: lang, 124 Zyklen, davon **3 entfernt** (27 Zeilen)
- Harte Treffer in: 15:44:07, 15:44:09
- Zusaetzlich entfernt (nur schwache Treffer): 15:44:06

| Zyklus | Register | falscher Wert | gehoert zu | zeigt sonst | hart |
|---|---|---|---|---|---|
| 15:44:06 | 30212 | 0 | 30110 | 5 | nein |
| 15:44:07 | 30300 | 0 | 32102 | 1 | nein |
| 15:44:07 | 30301 | 0 | 32102 | 1 | nein |
| 15:44:07 | 32101 | 0 | 32102 | 42 | ja |
| 15:44:07 | 32102 | 5 | 31003 | 0 | nein |
| 15:44:09 | 34502 | 0 | 36000 | 601 | ja |
| 15:44:09 | 36000 | 601 | 34502 | 0 | ja |

## watch_update_vor_tid_fix.csv

- Format: lang, 124 Zyklen, davon **5 entfernt** (46 Zeilen)
- Harte Treffer in: 2026-08-21 16:14:36, 2026-08-21 16:22:28, 2026-08-21 16:22:29, 2026-08-21 16:22:30
- Zusaetzlich entfernt (nur schwache Treffer): 2026-08-21 16:14:39

| Zyklus | Register | falscher Wert | gehoert zu | zeigt sonst | hart |
|---|---|---|---|---|---|
| 2026-08-21 16:14:36 | 34000 | 117 | 30204 | 5256 | ja |
| 2026-08-21 16:14:36 | 34002 | 12848 | 30350 | 477 | ja |
| 2026-08-21 16:14:39 | 34503 | 62 | 34403 | 56 | nein |
| 2026-08-21 16:22:28 | 34210 | 0 | 34308 | 118 | ja |
| 2026-08-21 16:22:28 | 34310 | 0 | 34308 | 118 | ja |
| 2026-08-21 16:22:29 | 34407 | 695 | 34502 | 0 | ja |
| 2026-08-21 16:22:29 | 34410 | 0 | 34508 | 118 | ja |
| 2026-08-21 16:22:29 | 34507 | 695 | 34502 | 0 | ja |
| 2026-08-21 16:22:30 | 34510 | 0 | 37023 | 118 | ja |

