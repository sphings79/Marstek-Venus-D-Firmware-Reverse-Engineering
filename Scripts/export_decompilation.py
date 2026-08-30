# Exportiert alle dekompilierten Funktionen des aktuell geoeffneten Programms
# als .c-Dateien plus _index.md.
#
# Ausfuehren ueber ReVa:
#     run-script(programPath="/<programm>.bin", scriptName="MarstekExportDecompilation.py")
# Der Loader in ~/ghidra_scripts/ liest genau diese Datei. ReVa fuehrt keine
# Skripte ausserhalb registrierter Skriptverzeichnisse aus.
#
# Zielverzeichnis wird aus dem Programmnamen abgeleitet; unbekannte Programme
# landen in Control_FW/decompiled_<name>/.
#
# WICHTIG: Der Export ist eine Momentaufnahme. Nach Umbenennungen, Typaenderungen
# oder neu definierten Funktionen in Ghidra ist er veraltet und muss neu laufen.

import os, re, time, datetime
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

PROJECT = "/Users/<user>/Claude/Projects/Marstek Venus D FW Debug"

# Ein Unterordner je Firmware-VERSION. Bewusst keine Zeitstempel-Ebene: der Export
# ist ein Suchindex, und mehrere Momentaufnahmen nebeneinander wuerden jedes grep
# vervielfachen. Das "wann" steht im Kopf von _index.md, Historie macht Git.
# Abgeglichen wird per Teilstring gegen currentProgram.getName(). Achtung: der
# Ghidra-Programmname ist nicht der Pfad im Projekt — das Micro-Image heisst dort
# z.B. "vd_inv_app_0116_0702_ota_163439.bin", nicht "Micro_VNS_116_...".
TARGETS = (
    ("app_0150",     "Dekompilate/Control_v150",  "Control v150"),
    ("inv_app_0116", "Dekompilate/Micro_VNS_116", "Micro/VNS 116"),
    ("app_1492",     "Dekompilate/Control_1492",  "Control 149.2"),
    ("2026011910",   "Dekompilate/BMS_118",       "BMS 118"),
    ("BMS_118",      "Dekompilate/BMS_118",       "BMS 118"),
)


def target_for(name):
    for key, rel, label in TARGETS:
        if key in name:
            return os.path.join(PROJECT, rel), label
    slug = re.sub(r"[^A-Za-z0-9_.-]", "_", name)[:40]
    return os.path.join(PROJECT, "Dekompilate", slug), name


def main():
    name = currentProgram.getName()
    out, label = target_for(name)
    if not os.path.isdir(out):
        os.makedirs(out)

    fm = currentProgram.getFunctionManager()
    funcs = sorted([f for f in fm.getFunctions(True) if not f.isExternal()],
                   key=lambda f: f.getEntryPoint().getOffset())

    # alte .c-Dateien entfernen, sonst bleiben umbenannte Funktionen doppelt liegen
    removed = 0
    for old in os.listdir(out):
        if old.endswith(".c"):
            os.remove(os.path.join(out, old))
            removed += 1

    d = DecompInterface()
    d.openProgram(currentProgram)
    mon = ConsoleTaskMonitor()
    safe = re.compile(r"[^A-Za-z0-9_.-]")
    t0 = time.time()
    rows = []
    failed = 0

    for f in funcs:
        addr = "%08x" % f.getEntryPoint().getOffset()
        n = f.getName()
        fname = "%s_%s.c" % (addr, safe.sub("_", n)[:80])
        r = d.decompileFunction(f, 60, mon)
        if r.decompileCompleted():
            code = r.getDecompiledFunction().getC()
        else:
            code = "/* decompilation failed: %s */\n" % r.getErrorMessage()
            failed += 1
        with open(os.path.join(out, fname), "w") as fh:
            fh.write("/* %s @ 0x%s  size=%d bytes */\n\n%s"
                     % (n, addr, f.getBody().getNumAddresses(), code))
        try:
            callers = len(set(f.getCallingFunctions(None)))
        except Exception:
            callers = -1
        rows.append("| `%s` | `%s` | %d | %d | `%s` |"
                    % (addr, n, f.getBody().getNumAddresses(), callers, fname))
    d.dispose()

    named = sum(1 for f in funcs if not f.getName().startswith("FUN_"))
    header = """# Dekompilat-Index — %s

**Erzeugt:** %s
**Programm:** `%s`
**Funktionen:** %d (davon %d benannt, %d noch `FUN_*`)
**Ghidra-Symbole:** %d
**Dekompilation fehlgeschlagen:** %d

## Wie das hier entstanden ist

Erzeugt aus dem geoeffneten Ghidra-Projekt mit `Scripts/export_decompilation.py`:

```
run-script(programPath="/%s", scriptName="MarstekExportDecompilation.py")
```

`MarstekExportDecompilation.py` in `~/ghidra_scripts/` ist nur ein Loader, der dieses
Skript aus dem Projekt liest und ausfuehrt — ReVa fuehrt keine Skripte ausserhalb
registrierter Skriptverzeichnisse aus, gepflegt wird aber die Projektfassung.

Das Skript laeuft in Ghidras PyGhidra-Laufzeit (ueber ReVa oder den Script Manager),
holt sich alle Funktionen ueber `FunctionManager.getFunctions()`, dekompiliert jede
einzeln mit `DecompInterface.decompileFunction(f, 60, monitor)` und schreibt das
Ergebnis von `getDecompiledFunction().getC()` in eine Datei je Funktion. Vorhandene
`.c`-Dateien im Zielordner werden vorher geloescht, damit umbenannte Funktionen
nicht unter ihrem alten Namen liegenbleiben. Die Aufruferzahl kommt aus
`getCallingFunctions()`.

> **Momentaufnahme, nicht Quelle der Wahrheit.** Die Quelle ist das Ghidra-Projekt.
> Dieser Baum ist ein *Suchindex* fuer Abfragen, die in Ghidra teuer oder unmoeglich
> sind — etwa `grep -rn "0x708"` fuer Konstanten, die `find-constant-uses` nicht
> findet, weil sie ueber einen Literal-Pool geladen werden.
>
> **Nach jeder Umbenennung, Typaenderung oder neu definierten Funktion in Ghidra ist
> dieser Export veraltet.** Neu erzeugen mit `Scripts/export_decompilation.py`,
> siehe `Methodik_und_Meta/Dekompilat_Export.md`.

| Adresse | Funktion | Bytes | Aufrufer | Datei |
|---|---|---|---|---|
""" % (label, datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), name,
       len(funcs), named, len(funcs) - named,
       currentProgram.getSymbolTable().getNumSymbols(), failed, name)

    with open(os.path.join(out, "_index.md"), "w") as fh:
        fh.write(header + "\n".join(rows) + "\n")

    print("%s: %d Funktionen exportiert (%d alte entfernt, %d fehlgeschlagen) in %.1fs -> %s"
          % (label, len(funcs), removed, failed, time.time() - t0, out))


main()
