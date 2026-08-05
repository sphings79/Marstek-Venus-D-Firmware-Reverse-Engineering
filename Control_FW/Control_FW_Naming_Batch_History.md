# Control FW — Namensvergabe: Prozess-Historie & Lektionen

Archiv der Batch-für-Batch-Vorgehensnotizen aus dem inzwischen gelöschten `Control_FW_Function_Tracking.md`
(chronologisches Batch-Log). Die reinen Adresse→Name-Daten sind vollständig und aktueller in
[Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md) enthalten — diese Datei hier
bewahrt nur die **Prozess-Reflexionen** ("Lektion:"-Abschnitte) und den Kontext der größeren Korrektur-Batches,
falls die Methodik für künftige Namensvergabe-Sessions relevant wird.

---

## Batches 1–17 (2026-07-07 bis 2026-07-08): Erstvergabe

Alle 1.615 damals unbenannten `FUN_`-Funktionen wurden in 17 Batches à ~50–108 Funktionen von parallelen
Sub-Agenten benannt, mit wenig Cross-Checking zwischen den Agenten. Batch 5 stellte fest, dass 20 von 50
angefragten Adressen im Bereich `0x08012xxx`–`0x08013xxx` bereits benannt, Mid-Function-Offsets oder
String-Daten waren (effektiv nur 30 neue Namen) — ein früher Hinweis darauf, dass Adress-Listen vor der
Vergabe gegen den aktuellen Ghidra-Stand geprüft werden sollten.

## Batch 18 — Verifikations-Korrekturpass (2026-07-09)

**Auslöser:** Hinweis, dass Funktionen in der Control-FW 149.2 falsch identifiziert/dekompiliert sein
könnten, da Batches 1–17 von vielen parallelen Sub-Agenten mit wenig Cross-Checking erzeugt wurden.

**Methode:** Direkter Ghidra-Funktionsvergleich (frische Dekompilierung, nicht nur die Doku-Beschreibung)
für den kompletten `mbedTLS_MPI_*`/`ECP_*`/`RSA_*`/`PK_`/`OID_`/`Cipher_`/`SSL_`/`X509_`-Cluster
(142+ Funktionen) sowie alle 153 mit `medium`/`low` Confidence markierten Nicht-Crypto-Funktionen.
Fokus: doppelt vergebene Namen (starkes Fehlersignal — echte mbedTLS-Quellen haben nie zwei Funktionen
mit demselben Namen), Parameter-Anzahl/-Reihenfolge gegen die reale mbedTLS-2.28-API, Verhalten vs.
Namensbehauptung.

**Ergebnis:** 62 falsch benannte Funktionen gefunden und direkt in Ghidra korrigiert (nicht nur in der
Doku). Auslöser war ein bereits früher dokumentierter, aber nie tatsächlich behobener Naming-Konflikt
(`0x08042c2e`), der sich als Kaskade von 3 verschobenen MPI-Funktionsnamen entpuppte; die systematische
Prüfung des gesamten Clusters fand danach 58 weitere solcher Fehlbenennungen, teils in längeren
Verschiebungsketten (z. B. Add_Abs/Grow/Cmp_Abs/Lset/Add_Int im MPI-Cluster).

**Lektion:** Ein doppelt vergebener Name war in praktisch 100% der geprüften Fälle das zuverlässigste
Signal für eine Fehlbenennung — echte mbedTLS-Funktionen kollidieren nie im Namen.

## Batch 19 — Vollständige Doppelnamen-Auflösung (2026-07-09)

**Auslöser:** Beim Aufbau von `Control_FW_Function_Tracking_new.md` (thematische Neuordnung) wurde
zusätzlich zum Adress/Name-Abgleich ein vollständiger Namens-Dublettencheck über alle damals 1.417
benannten Funktionen durchgeführt (nicht nur eine Stichprobe wie in Batch 18). Ergebnis: über die
bereits bekannten 6 Dubletten hinaus wurden **8 weitere** in den llhttp-Interna gefunden. Insgesamt
14 Doppelnamen in dieser Runde aufgelöst (6 App-/Bibliotheks-Funktionen + 8 llhttp-Bit-Test-Helfer,
nach Struct-Offset statt vermuteter Bit-Semantik benannt, da der Code strukturell identisch war).

**Nebenbefund:** Die Gesamtzahl benannter Funktionen stieg zwischen zwei Ghidra-Abfragen von 1411 auf
1417 (vermutlich laufende Hintergrund-Analyse in Ghidra, nicht auf die Session zurückzuführen).

**Ergebnis:** 0 verbleibende Namensdubletten (verifiziert per Vollscan über alle 1417 Funktionen).

**Lektion:** Der Dublettencheck aus Batch 18 wurde nur auf eine Stichprobe angewandt, nicht als
erschöpfender Scan über *alle* benannten Funktionen — erst der Vollscan in Batch 19 deckte die
zusätzlichen 8 llhttp-Dubletten auf. **Für künftige Batches: Dublettencheck immer als vollständigen
Scan (`getFunctions()` + Namens-Häufigkeitszählung), nicht nur stichprobenartig.** (Siehe auch
Memory-Eintrag `feedback_batch-naming-duplicate-check`.)

## Batch 20 — Identifikation der letzten 206 unbenannten FUN_-Funktionen (2026-07-09)

**Auslöser:** Auftrag, die letzten noch unidentifizierten Funktionen unter Einsatz von Subagenten zur
parallelen Bearbeitung zu analysieren.

**Ausgangslage:** Nach Batch 19 waren 1417 von 1623 Funktionen benannt — 206 trugen noch `FUN_0xxxxxxx`.
Eine Prüfung der Speicherbereiche ergab nur einen einzigen Block (`0x08000000`–`0x0805dfff`, flach
gemapptes Executable-Image) — keine separaten „unidentifizierten Speicherbereiche" jenseits dieser 206
Funktionen. Zusätzlich 66 `LAB_*`-Label (Sprungziele ohne eigenen Funktionskopf) gefunden, als niedrigere
Priorität eingestuft und nicht bearbeitet.

**Vorgehen:** Die 206 Adressen wurden in 6 Chunks à ~35 Funktionen an 6 parallele Subagenten vergeben
(je mit vollem Kontext zu Namenskonvention, Projektstruktur, Nachbar-Funktionen). Jeder Agent hat pro
Funktion vollständig dekompiliert (inkl. Caller/Callee) und einen Namen mit Konfidenz + Begründung
vorgeschlagen, aber NICHT selbst umbenannt — die 202 Vorschläge wurden zentral gegen Dubletten
(untereinander UND gegen alle 1417 bereits vergebenen Namen) geprüft (0 Kollisionen) und dann gesammelt
in einer einzigen Ghidra-Transaktion angewendet.

**4 Funktionen bewusst NICHT umbenannt** (Padding/Stubs ohne sinnvolle Semantik): `0x0800bcc0` (4 Byte,
Konstante-1-Rückgabe als Funktionszeiger-Callback), `0x0802da14` (1 Byte, wahrscheinlich fehlerhaft
abgegrenztes Fragment), `0x0802db54` (1 Byte, dito), `0x0802dc50` (2 Byte, reiner `return;`-Stub).

**Ergebnis:** 202 von 206 Funktionen umbenannt. Stand danach: 1619 von 1623 Funktionen benannt (nur noch
4 bewusst zurückgestellte Mini-Stubs). Vollscan bestätigt: 0 Namensdubletten.

**Lektion:** Subagenten-Parallelisierung funktionierte gut für dieses Volumen (206 Funktionen in 6 Chunks)
— jeder Agent bekam genug Kontext, um auch bei fehlender Handschrift-Referenz (z. B. mbedTLS
X.509/ASN.1-Cluster, FreeRTOS-Kernel-Cluster) konsistente, konventionsgetreue Namen zu produzieren.
Der zentrale Dublettencheck vor dem Anwenden blieb wichtig: auch wenn diesmal 0 Kollisionen auftraten,
hätte er bei paralleler Arbeit mehrerer Agenten leicht welche übersehen können, wenn er nicht
durchgeführt worden wäre.

---

*Gelöscht am 2026-07-11: `Control_FW_Function_Tracking.md` (chronologisches Batch-Log, 3.649 Zeilen).
Grund: redundant zu `Control_FW_Function_Tracking_new.md` (thematische Ordnung, vom Nutzer als einzige
maßgebliche Quelle gewünscht) — per Diff-Check bestätigt, dass alle Adresse→Name-Paare der alten Datei
in der neuen enthalten sind (58 nur in der alten Datei gefundene Adressen waren reiner Adress-Drift,
in der neuen Datei unter der aktuellen Adresse per Namens-Match korrekt erfasst).*
