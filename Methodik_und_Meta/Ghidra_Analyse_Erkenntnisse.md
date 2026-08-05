# Marstek Venus D — Ghidra-Analyse-Erkenntnisse

**Projekt:** Marstek Venus D (`VNSD-0`) Reverse Engineering  
**Bezug:** Ausgelagert aus [Control_FW_Analyse_app_1492_0702_142136.md](Control_FW_Analyse_app_1492_0702_142136.md) (ehemals Abschnitte 14 + 15)

---

## 1. Falsch identifizierte Funktion #1

```
Adresse: FUN_080128a0 (enthält MOVW #0x7530 bei 0x0801295e)
NICHT: Descriptor-Init-Funktion
IST:   JSON-Config-Parser

Beweis: Decompilierter Code zeigt
  DAT_20018b6b = 30000;  // ← 0x7530 ist hier ein Standard-API-Port!
  FUN_08045340(param_1, &DAT_08012b04, &DAT_20018b68);  // JSON-Parser
```

## 2. Falsch identifizierte Funktion #2

```
Adresse: FUN_0801bcb0
NICHT: Descriptor-Init-Funktion
IST:   RS485/RTU Paket-Handler

Beweis: Verarbeitet Modbus-RTU-Frames (CRC-Check, FC03/FC06/FC10 Routing)
  DAT_200151ec  = RS485-Empfangspuffer
  FUN_08025f3c  = Modbus FC03 Handler
  FUN_08026080  = Modbus FC06 Handler
  FUN_08026154  = Modbus FC16 Handler
```

## 3. Korrekt identifizierte Funktionen

| Funktion | Status | Quelle |
|---|---|---|
| `FUN_0801c088` = Router | ✅ Bestätigt | TCPRouter.c dekompiliert |
| `FUN_0804b73c` = Serializer | ✅ Bestätigt | Serializer.c dekompiliert |
| `FUN_0804c83c` = Write-Handler | ✅ Bestätigt | WriteHandler.c dekompiliert |

## 4. Ghidra-Skript-Probleme

- `getReferencesFrom()` findet keine **berechneten** SRAM-Adressen
- Nur direkte Literal-Referenzen werden von Ghidra getrackt
- Lösung: SRAM-Block hinzufügen + Re-Analyse → danach Decompiler nutzen
- Jython 2.7: Keine Umlaute/Sonderzeichen ohne `# -*- coding: utf-8 -*-`

---

## 5. Netzwerk-Architektur (CH395 Ethernet, CLI-Shell, Modbus TCP)

### 5.1 CH395 Ethernet-Chip: Socket-Belegung

Die Initialisierung erfolgt in `CH395_Reset_And_Reinit @ 0x08029964` (144 Bytes).
Reihenfolge der Initialisierung: HardwareReset → Init_Basic → RS485_Modbus_RegisterMap_Init → Init_Full → Init_Modbus_TCP_Socket → Init_BroadcastListener_Socket → **Init_TCPServer_Socket**.

| Socket | Port | Funktion | Init-Funktion |
|--------|------|----------|---------------|
| 0 | **502** (0x1F6) | Modbus TCP | `CH395_Init_Modbus_TCP_Socket @ 0x08048754` |
| 1 | **8091** (0x1F9B) | TCP Debug/CLI Shell | `CH395_Init_TCPServer_Socket @ 0x08032C0C` |

**`CH395_Init_TCPServer_Socket` (66 Bytes @ 0x08032C0C):**
```c
void CH395_Init_TCPServer_Socket(void) {
  CH395_SPI_CmdWaitReady(1);
  *(uint8*)(descriptor + 0x40) = 2;    // protocol = TCP
  *(uint8*)(descriptor + 0x41) = 1;    // socket = 1
  *(uint16*)(descriptor + 0x48) = 0x1F9B; // src port = 8091
  *(uint16*)(descriptor + 0x4A) = 0x1F9B; // dst port = 8091
  *(uint8*)(descriptor + 0x42) = 2;    // mode = server/listen
  CH395_Socket_Open_ByDescriptor(descriptor + 0x40);
}
```

**`CH395_Init_Modbus_TCP_Socket` (50 Bytes @ 0x08048754):**
```c
void CH395_Init_Modbus_TCP_Socket(void) {
  *(uint8*)(descriptor + 0x1C) = 2;    // protocol = TCP
  *(uint8*)(descriptor + 0x1D) = 0;    // socket = 0
  *(uint16*)(descriptor + 0x24) = 0x1F6; // src port = 502
  *(uint16*)(descriptor + 0x26) = 0x1F6; // dst port = 502
  CH395_Socket_Open_ByDescriptor(descriptor + 0x1C);
}
```

### 5.2 CLI-Architektur: Datenpfad TCP → Dispatcher

```
TCP Socket 1 (Port 8091)
    ↓  [CH395 empfängt Daten]
RAM-Flag @ 0x20000132 = 1  (socket-type selector)
    ↓  [Dispatch-Loop bei ~0x0802DACC]
Network_ReceiveAndDispatchData @ 0x0804D4E8  (via BL @ 0x0802DBE2)
    ↓  [liest CH395-Daten oder Queue]
BLE_GATT_DispatchCommandByte @ 0x0804C4B4  (byte-by-byte CLI dispatch)
    ↓
CLI_TabComplete / CLI_ListCommands / Command-Handler
```

**Callers von `Network_ReceiveAndDispatchData`:**
- Kein Caller in Ghidras Referenz-Manager (BL wurde nicht erkannt)
- Manueller BL-Scan: BL **@ 0x0802DBE2** → 0x0804D4E8
- Bedingung: `LDRB R0, [0x20000132]; CMP R0, #1; BEQ → BL`

**Caller-Kontext bei 0x0802DBE2 (Dispatch-Loop, Funktion nicht von Ghidra erkannt):**
```c
// ~0x0802DBD0: Dispatch-Block (Socket-Type-Selektor)
if (RAM[0x20000270] != 0) {
    SomeFunctionA();           // socket type 0 path
} else if (RAM[0x20000132] == 1) {
    Network_ReceiveAndDispatchData();  // TCP socket 1 path → CLI port 8091
} else if (RAM[0x20000132] == 2) {
    SomeFunctionB();           // socket type 2 path
}
```

**`Network_ReceiveAndDispatchData @ 0x0804D4E8` (184 Bytes) — Dualer Eingangspfad:**
- Liest Daten aus CH395 TCP Socket 1 (Port 8091) **oder** aus einer Queue (BLE/RS485-Pfad)
- Leitet Bytes an `BLE_GATT_DispatchCommandByte` weiter (Byte-für-Byte CLI-Parser)
- Callers aus Ghidra: 0x0804D552 + 0x0804D598 in sich selbst → beide innerhalb der Funktion

### 5.3 Unerkannte Haupt-Task-Funktion (~0x0802DA0C)

Der Code-Bereich **0x0802DA0C–0x0802DC20** wurde von Ghidra nicht als Funktion erkannt (alle Versuche, dort Funktionen zu erstellen, schlugen fehl oder ergaben 1-Byte-Stubs). Inhalt (aus Raw-Bytes rekonstruiert):

- **GPIO/Hardware-Init**: Bit-Setzen auf 0x40021000 (GPIOE) → wahrscheinlich RS485-Transceiver-Enable
- **Innere Schleife bei 0x0802DACC**: Prüft Zustand, ruft `vTaskDelay(100)` auf, loopt zurück → FreeRTOS-Task-Hauptloop
- **Dispatch-Block**: Liest RAM-Flags, ruft entweder CLI-Pfad oder andere Handler auf
- Enthält auch `BL Modbus_Drain_RxBuffer @ 0x080292D4` → Modbus-Puffer-Leeren

**`App_MainLoopDispatcher @ 0x08034812` (24 Bytes)** — wird wahrscheinlich aus diesem Bereich aufgerufen (0 Ghidra-Callers, kein Pointer in Flash):
```c
void App_MainLoopDispatcher(void) {
  Shutdown_Sequence_Handler();
  FUN_080151c8();
  CAN_Update_StateMachine();
  MainLoop_Periodic_Tasks();
  Cloud_EdgeDetectAndWatchdog();
}
```

### 5.4 FreeRTOS xTaskCreate — Task-Tabellen-Problem (ungelöst)

`FUN_080545fc @ 0x080545FC` = **xTaskCreate** (bestätigt durch pvPortMalloc×2 + Task_InitNewTask + prvAddNewTaskToReadyList).

`Task_Init_CreateAll @ 0x0801947C` erstellt 14 Tasks via Loop:
```c
for (i = 0; i < 14; i++) {
    xTaskCreate(TABLE[i].pvTaskCode,  // entry + 0x00
                TABLE[i].pcName,     // entry + 0x04
                TABLE[i].stackDepth, // entry + 0x08 (uint16)
                TABLE[i].pvParam,    // entry + 0x0C
                TABLE[i].priority,   // entry + 0x10
                TABLE[i].handle);    // entry + 0x14
}
```

- **TABLE_BASE** = `Mem[0x08019518]` = **0x08059958**
- **Stride** = 24 Bytes (0x18) ← durch Instruktion `ADD.W R0, R4, R4, LSL#1; ADD.W R0, TABLE, R0, LSL#3` bestätigt
- **Problem**: 0x08059958 enthält in Flash ASCII-Text (`"[BLE] URL count sequence error!"`) — keine gültigen Funktionszeiger
- **Hypothese**: Task-Tabelle liegt im `.data`-Abschnitt (RAM-VMA ≠ Flash-LMA) oder die Funktion wird mit einem RAM-Pointer als Parameter aufgerufen, der in der Flash-Analyse nicht sichtbar ist

**xTaskCreate-Aufrufstellen (manueller BL-Scan):**
| Adresse | Funktion | Task |
|---------|----------|------|
| 0x080194CE | Task_Init_CreateAll | 14 App-Tasks (Tabelle) |
| 0x08050A8A | (FreeRTOS intern) | IDLE task (Prio 0, Stack 128) |
| 0x08054FBC | (FreeRTOS intern) | Timer task (`FUN_0804f910`) |

---

## 7. Falsche Fährten & Lektionen

### 7.1 MOVW #0x7530 ist kein verlässlicher Anker

Der Wert 0x7530 = 30.000 erscheint mehrfach im Code mit unterschiedlichen Bedeutungen:
- **API-Port** (30000 als Default-Port in JSON-Config-Parser)
- **Vergleichswert** (Bereichsprüfung: `if reg < 30000`)
- Möglicherweise auch als erste Register-Adresse im Init-Code

### 7.2 0x9C40 (40.000) dient als Range-Check

In WriteHandler.c und TCPRouter.c erscheint 0x9C40 als Grenzwert zwischen Read- und Write-Registern. Das macht es ungeeignet als Anker für den Descriptor-Init.

### 7.3 MOVW mit "Tabellen-Offset-Werten"

75 MOVW-Instruktionen mit Werten 0x02F8–0x0DCC wurden gefunden. Diese sind jedoch alle **Leistungsgrenzen** (0x09C4 = 2500W, 0x0BB8 = 3000W), keine Tabellen-Offsets.

### 7.4 Startup-Literal-Pool bei 0x08055c8c

Erschien vielversprechend als .data-Section-Quelle. Enthält tatsächlich nur MQTT-Debug-Strings, keine Register-Descriptor-Daten.

### 7.5 Register 34010 / 34110 / 37012 als Temperatur fehlinterpretiert

**Symptom:** Rohwert 116 wurde mit Scale 0.1 als 11.6 °C interpretiert —
ein zur Jahreszeit (Mai, kühle Batterie) plausibel erscheinender Wert.

**Korrektur:** Alle drei Register enthalten die **BMS-Firmware-Version (116)**,
identisch mit Reg 30204 (`bms_version = 116`).

| Register | Falsch | Richtig |
|---|---|---|
| 34010 | pack1_temp_avg = 11.6 °C | **pack1_bms_version = 116** |
| 34110 | battery_2_temperature = 11.6 °C | **battery_2_bms_version = 116** |
| 37012 | max_temp_all_packs = 11.6 °C | **bms_version (Systemebene) = 116** |

**Lektion:** Wenn ein Rohwert eine Temperatur-Interpretation zufällig plausibel macht,
immer gegen bekannte Werte gleicher Bedeutung (hier Reg 30204) gegenchecken.
Die dreifache Übereinstimmung mit 30204 hätte früher auffallen sollen.
Die eigentliche Pack-Durchschnittstemperatur liegt wahrscheinlich bei 34012–34016
(Rohwerte 192–198 → 19.2–19.8 °C), was für eine indoor-betriebene Batterie besser passt.

## 8. Batch 18 — Systematischer Verifikationspass (2026-07-09)

Der Nutzer wies darauf hin, dass in einer früheren Session bereits von falsch identifizierten/
dekompilierten Funktionen die Rede war. Stichprobe ergab: der schon dokumentierte
Naming-Konflikt #66 (`mbedTLS_MPI_Mul_MPI`/`Exp_Mod`, ursprünglich aus Batch 13) war
**nie tatsächlich in Ghidra behoben** worden — nur die Doku-Zeile "Interessante
Funde" erwähnte ihn. Vollständige Nachprüfung des kompletten `mbedTLS_MPI_*`/`ECP_*`/`RSA_*`/
`PK_`/`SSL_`/`X509_`-Clusters (142+ Funktionen) sowie aller 153 medium/low-confidence
Nicht-Crypto-Funktionen (parallele Ghidra-Re-Dekompilierung je Adresse) fand **62 falsch
benannte Funktionen** insgesamt, mehrere davon in mehrstufigen Verschiebungsketten
(z. B. Div_MPI ↔ Exp_Mod ↔ Inv_Mod; Add_Abs ↔ Grow ↔ Cmp_Abs ↔ Lset im MPI-Cluster;
SSL Conf_Authmode ↔ Derive_Keys ↔ SessionFree ↔ TransformFree). Bei 8 Adressen war der in der
Doku stehende Name nie tatsächlich in Ghidra gesetzt worden (Funktion hieß dort weiterhin
`FUN_0xxxxxxx`) — Doku und Ghidra-Stand waren bereits vorher auseinandergelaufen.

Alle 62 wurden in Ghidra umbenannt. Die aktuellen Namen stehen in
[Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md); eine Zusammenfassung
des Batch-18-Vorgehens (die vollständige Alt/Neu-Tabelle existiert nicht mehr, s. u.) findet sich in
[Control_FW_Naming_Batch_History.md](Control_FW_Naming_Batch_History.md).

**Lektion (Ergänzung zu Abschnitt 7):** Ein Funktionsname, der an **zwei verschiedenen Adressen**
vorkommt, war in dieser Prüfung praktisch immer ein Fehlersignal — in jedem gefundenen Fall
war genau einer der beiden Namensträger falsch. Bei künftigen Batch-Läufen sollte am Ende
automatisch auf Namensdubletten über den gesamten Funktionsbestand geprüft werden, statt das
erst durch eine spätere Vollprüfung zu entdecken. Außerdem sollte ein "in Doku benannt, aber
in Ghidra nicht umgesetzt"-Check ergänzt werden (kam bei 8 Funktionen in diesem Pass vor).

## 9. Batch 19 — Vollständige Doppelnamen-Auflösung (2026-07-09)

Beim Aufbau der thematisch neu gruppierten [Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md)
wurde diesmal ein **vollständiger** Namens-Dublettenscan über alle 1417 zu diesem Zeitpunkt
benannten Ghidra-Funktionen durchgeführt (nicht nur eine Stichprobe wie in Batch 18). Ergebnis:
neben den bereits bekannten 6 Dubletten (MQTT_Decode_RemainingLength, CH395_Socket_SendData,
mbedTLS_ASN1_Get_Int, mbedTLS_ECP_Group_Load, prvCopyDataToQueue, CLI_Backspace) fanden sich
**8 weitere** in den llhttp-Interna (`llhttp__internal__c_test_flags` und `_1`/`_2`/`_3`, je an
zwei Adressen mit identischem Bit-Test-Code, aber unterschiedlichem Struct-Feld-Offset).

Alle 14 wurden dekompiliert, verglichen und disambiguiert: in jedem App-/Bibliotheks-Paar
entspricht eine Instanz der "kanonischen" Funktion (z. B. der echten mbedTLS-Public-API-Signatur,
oder dem tatsächlich referenzierten FreeRTOS-Static-Function-Verhalten) und behält den Namen,
während die andere Instanz einen präzisierenden Suffix bekommt (`_ViaCallback`, `_RawParams`,
`_Core`, `_AndNotify`, `_EchoOnly`, `_ViaSocketPtr`). Die llhttp-Paare wurden nach dem
unterscheidbaren Fakt benannt, den die Dekompilierung hergab (Struct-Offset `_Off32`/`_Off2e`),
statt eine nicht verifizierbare Bit-Semantik zu erraten.

Volle Tabelle mit Begründungen: [Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md),
Abschnitt "Batch 19". Ergebnis: 0 verbleibende Namensdubletten im gesamten Projekt (verifiziert).

**Nebenbefund:** Die Gesamtzahl benannter Funktionen stieg zwischen den beiden Ghidra-Abfragen
in dieser Session von 1411 auf 1417 (6 neue: `OTA_Update_Dispatcher`, `vTaskEnterCritical`,
`vTaskExitCritical`, `xTimerStop_Internal`, `FreeRTOS_StartScheduler`, `FreeRTOS_SysTick_TaskUnblock`) —
vermutlich lief Ghidras Hintergrund-Analyse während der Session weiter. Kein Anlass zur Sorge,
aber ein Hinweis darauf, dass Funktions-Snapshots in aktiven Ghidra-Projekten nicht als
statisch/final behandelt werden sollten.

**Lektion (Ergänzung zu Abschnitt 8):** Ein Dublettencheck ist nur dann verlässlich, wenn er über
*alle* benannten Funktionen läuft, nicht nur über einen vermuteten Risikobereich (in Batch 18 lag
der Fokus auf dem Crypto-Cluster + medium/low-confidence-Funktionen, wodurch die llhttp-Interna
durchrutschten). Für künftige Audits: `getFunctions()` vollständig ziehen, nach Name gruppieren,
jede Gruppe mit >1 Eintrag einzeln disambiguieren — unabhängig davon, wie "sicher" der jeweilige
Codebereich eingeschätzt wird.

## 10. Batch 20 — Identifikation der letzten 206 unbenannten Funktionen (2026-07-09)

**Auslöser:** Der Nutzer bat darum, die letzten verbleibenden nicht identifizierten Funktionen bzw.
Speicherbereiche zu analysieren und dafür Subagenten zur parallelen Bearbeitung einzusetzen.

**Vorprüfung der "Speicherbereiche":** `get-memory-blocks` zeigt nur einen einzigen Block `ram`
(`0x08000000`–`0x0805dfff`) — die Firmware ist ein flach gemapptes Image, es gibt also keine
separaten unidentifizierten Speicherregionen jenseits der 206 noch unbenannten Funktionen.
`get-undefined-function-candidates` lieferte zusätzlich 66 `LAB_*`-Sprungziele ohne eigenen
Funktionskopf (Datenreferenzen/Jump-Table-artige Ziele) — als geringere Priorität eingestuft und
in diesem Batch nicht bearbeitet.

**Methodik:** Die 206 `FUN_0xxxxxxx`-Adressen wurden nach Adresse sortiert in 6 Chunks à ~35
aufgeteilt und an 6 parallele Subagenten vergeben. Jeder Agent bekam denselben Projekt- und
Namenskonventions-Kontext (Beispiele aus bereits benannten Nachbarfunktionen) plus seine
spezifische Adressliste, dekompilierte jede Funktion vollständig (inkl. Caller/Callee) und schlug
einen Namen mit Konfidenz + Begründung vor — Umbenennungen wurden NICHT von den Subagenten selbst
vorgenommen, sondern zentral gesammelt.

Vor dem Anwenden wurden alle 202 Vorschläge automatisiert geprüft: (1) auf Dubletten untereinander,
(2) auf Kollision mit den bereits vergebenen 1417 Namen. Beide Prüfungen ergaben 0 Treffer. Die
Umbenennungen wurden anschließend in einer einzigen Ghidra-Transaktion angewendet.

4 Funktionen wurden bewusst nicht umbenannt (zu trivial für eine sinnvolle Namensvergabe):
`0x0800bcc0` (Konstante-Rückgabe-Callback, 4 Byte), `0x0802da14`/`0x0802db54` (1-Byte-Fragmente,
vermutlich fehlerhafte Funktionsgrenzen) und `0x0802dc50` (2-Byte-`return;`-Stub).

**Ergebnis:** 202/206 Funktionen erfolgreich umbenannt. Neuer Projektstand: 1619 von 1623
Funktionen benannt (99,75%), 0 Namensdubletten (Vollscan-verifiziert). Die neu identifizierten
Funktionen decken u. a. den kompletten mbedTLS X.509/ASN.1-Zertifikatsverifikations-Cluster
(33 Funktionen, exakter Abgleich gegen mbedtls 2.28 `x509_crt.c`/`asn1parse.c`), den kompletten
FreeRTOS-Kernel-Cluster (41 Funktionen: Task-/Queue-/Timer-/List-Primitiven wie `vTaskSwitchContext`,
`xQueueGenericSend`, `vListInsert`), den EEPROM-I2C-Bittreiber (14 Funktionen) sowie diverse
Quectel-AT-Befehls-Handler (23 Funktionen) ab. Volle Tabelle mit allen 202 Umbenennungen nach
Themengebiet: [Control_FW_Function_Tracking_new.md](Control_FW_Function_Tracking_new.md), Abschnitt
"Batch 20".

**Lektion:** Für große, klar abgrenzbare Restmengen (hier: alle verbliebenen `FUN_`-Funktionen)
lässt sich Subagenten-Parallelisierung gut nutzen, wenn (a) jeder Agent genug Kontext bekommt, um
die etablierten Namenskonventionen korrekt fortzusetzen, und (b) der Dublettencheck zentral NACH
dem Sammeln aller Vorschläge läuft, nicht pro Agent — sonst können zwei Agenten unabhängig
voneinander denselben Namen für unterschiedliche Funktionen vorschlagen, ohne dass es einer von
ihnen bemerkt.

## 11. Prüfung LAB_-Kandidaten + Machbarkeit TLS-Zertifikat-Extraktion (2026-07-10)

**Auslöser:** Der Nutzer fragte, ob es noch mehr zu analysieren gibt und ob sich die 3 im Gerät
hinterlegten TLS-Zugangsdaten (CA-Zertifikat, User/Client-Zertifikat, User-Private-Key) aus der
Firmware extrahieren lassen.

**Teil A — LAB_-Kandidaten:** `get-undefined-function-candidates` erneut abgefragt (die 66 aus
Batch 20 zurückgestellten Kandidaten). Alle 66 haben `hasDataReference:true` und
`hasCallReference:false` — sie werden ausschließlich als Datenadressen referenziert (Jump-Table-
Ziele, Konstanten-Pool-Einträge, Literal-Pool-Werte innerhalb bestehender Funktionen), nie als
Funktionsaufruf. Das bestätigt die Einstufung aus Batch 20: keiner dieser 66 ist eine echte
übersehene Funktion. Damit sind alle sinnvoll identifizierbaren Funktionen/Speicherbereiche in
diesem Firmware-Dump abgearbeitet.

**Teil B — TLS-Zertifikat-Extraktion:** Der Entschlüsselungs-Pfad wurde vollständig nachvollzogen
(`CH395_MQTT_Init_And_CertSetup` → `TLS_Cert_Decrypt_All` (0x08024b54), `KeyDerive_CopyAndROT` +
`AES128_ECB_Decrypt`, eigene AES-128-ECB-Implementierung, NICHT mbedTLS). Die statische Extraktion
der 3 TLS-Credentials (CA-Root, Device-Zertifikat, Private Key) war erfolgreich.

> **Sicherheitsrelevanter Befund — bewusst nicht öffentlich dokumentiert.** Der zur Entschlüsselung
> nötige Schlüssel sowie die vollständige Extraktions-Methodik und die extrahierten Credentials sind
> **nicht Teil dieses öffentlichen Repos**. Der Nutzer hat den Befund (ein produktlinienübergreifend
> geteiltes, hartcodiertes AWS-IoT-Client-Zertifikat samt Private Key) im Rahmen einer Responsible
> Disclosure vertraulich an den Hersteller gemeldet; die Details werden zurückgehalten, bis eine
> Behebung vorliegt. Interne, nicht-öffentliche Dokumentation dazu liegt lokal im `security/`-Ordner
> (nicht Teil dieses Repos).

**Lektion (allgemein, ohne Bezug auf die konkreten Schlüsseldaten):** Bei stark verschachtelten/dicht
gepackten Konstanten-Pools ist Ghidras Decompiler-Pointer-Auflösung nicht immer vertrauenswürdig. Für
bytegenaue Vollkopien großer Binärdaten aus Ghidra: `run-script` (PyGhidra, `jpype.JArray`) direkt in
eine Datei schreiben lassen, NICHT über mehrere Subagenten per Hex-Text-Retyping — Letzteres hat kein
verlässliches Fehlererkennungsverfahren gegen einzelne falsch reproduzierte Bytes.
