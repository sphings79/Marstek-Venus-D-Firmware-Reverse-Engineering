# Dekompilat-Export — Suchindex neben Ghidra

## Warum

Ghidras eigene Suche hat eine Luecke, die uns Zeit gekostet hat. `find-constant-uses`
findet Konstanten nur, wenn sie als Immediate im Befehl stehen. Wird ein Wert ueber
einen Literal-Pool geladen — bei Thumb-2 der Normalfall fuer alles ueber 8 Bit —
taucht er dort nicht auf.

Konkret: die Suche nach `1800` bzw. `0x708` lieferte **null Treffer**, obwohl die
Konstante viermal im Control-Code steht. Erst eine Volldekompilation aller 1884
Funktionen brachte sie zum Vorschein, und ein `grep` ueber den Export fand sogar
eine vierte Stelle, die die Regex-Suche ueber die Dekompilation verpasst hatte.

Der Export macht solche Fragen zu einem `grep`.

## Ausfuehren

Ueber ReVa, je Programm einmal:

```
run-script(programPath="/VNSD-0_app_0150_0805_115146.bin",
           scriptName="MarstekExportDecompilation.py")
```

`~/ghidra_scripts/MarstekExportDecompilation.py` ist nur ein Loader — ReVa fuehrt
keine Skripte ausserhalb registrierter Skriptverzeichnisse aus. Gepflegt wird die
Projektfassung unter `Scripts/export_decompilation.py`.

Dauer: rund 35 s fuer 1884 Funktionen, 7 s fuer die kleineren Images.

Das Skript loescht vor dem Schreiben alle vorhandenen `.c`-Dateien im Zielordner.
Das ist Absicht: sonst bleiben Dateien umbenannter Funktionen unter ihrem alten
Namen liegen und man sucht spaeter in Leichen.

## Zielordner

| Programm | Export |
|---|---|
| Control v150 | `Dekompilate/Control_v150/` |
| Micro/VNS 116 | `Dekompilate/Micro_VNS_116/` |
| BMS 118 | `Dekompilate/BMS_118/` |

Zugeordnet wird per **Teilstring gegen `currentProgram.getName()`** — Vorsicht,
der Ghidra-Programmname ist nicht der Projektpfad: das Micro-Image heisst dort
`vd_inv_app_0116_0702_ota_163439.bin`, nicht `Micro_VNS_116_...`. Ein Praefix-
Abgleich ging genau daran vorbei und legte den Export unter dem Dateinamen ab.

**Keine Zeitstempel-Unterordner.** Mehrere Momentaufnahmen nebeneinander
vervielfachen jedes `grep` und laden dazu ein, veralteten Code zu lesen. Die
Trennachse ist die Firmware-Version.

Dateiname ist `<adresse>_<funktionsname>.c`. Die Adresse steht vorn, damit die
Sortierung der Speicherlage folgt und eine Umbenennung die Reihenfolge nicht
zerschiesst. Jede Datei traegt oben Name, Adresse und Groesse als Kommentar.

`_index.md` listet alle Funktionen mit Adresse, Groesse, Anzahl Aufrufer und
Dateiname, dazu Erzeugungsdatum und Symbolstand.

## Die Regel

**Der Export ist eine Momentaufnahme. Quelle der Wahrheit bleibt das
Ghidra-Projekt.**

Nach jeder dieser Aenderungen ist er veraltet und muss neu erzeugt werden:

- eine Funktion umbenannt
- eine Variable oder ein Typ gesetzt (aendert das Dekompilat sichtbar)
- eine neue Funktion definiert oder eine geloescht
- Daten zu Code umgewandelt oder umgekehrt
- Firmware-Version gewechselt oder Markup uebertragen

Am besten direkt nach einer Analysesitzung mitlaufen lassen, dann bleibt der
Baum ehrlich. Das Erzeugungsdatum oben in `_index.md` ist die Kontrolle: ist es
aelter als die letzte Ghidra-Arbeit, ist der Export nicht mehr verlaesslich.

## Wofuer der Export **nicht** taugt

- **Nicht als Beleg in der Doku.** Zitate gehoeren mit Adresse belegt, und die
  Adresse gilt in Ghidra. Der Export kann veraltet sein, ohne dass man es sieht.
- **Nicht fuer Bereiche, die Ghidra als Daten fuehrt.** Was nie disassembliert
  wurde, ist auch nicht im Export. Der Bereich `0x0802E684`–`0x0802E730` etwa
  enthaelt FreeRTOS-Task-Ruempfe, die als Rohdaten markiert waren — sie tauchten
  in keinem Dekompilat auf, obwohl sie ausgefuehrt werden.
- **Nicht als Diff-Grundlage zwischen Firmware-Versionen**, solange die
  Symbolstaende auseinanderlaufen. Erst Markup uebertragen, dann beide Seiten
  exportieren, dann `diff -r`.

## Nebenwirkung beim Aufraeumen

Wer im undefinierten Bereich Code sichtbar machen will, muss dort Daten loeschen
und disassemblieren. **Vorsicht:** `clearCodeUnits` ueber einen Bereich entfernt
auch bestehende Instruktionen und deren Referenzen. Am 2026-08-25 sind dabei die
Aufrufe bei `0x0802E6E0` und `0x0802E6F4` samt Referenzen verlorengegangen und
mussten per gezieltem `ArmDisassembleCommand` ab der bekannten Instruktionsgrenze
wiederhergestellt werden.

Regel daraus: **nie einen ganzen Bereich raeumen**, sondern ab einer Adresse
disassemblieren, von der bekannt ist, dass sie eine Instruktionsgrenze ist — etwa
weil eine Referenz darauf zeigt.
