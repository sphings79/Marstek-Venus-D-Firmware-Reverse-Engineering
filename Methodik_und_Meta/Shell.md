# Marstek Venus D — CLI Shell: Architektur, Befehle, Zugangswege

**Firmware:** v149.2 (`Control_149.2_VNSD-0_app_1492_0702_142136.bin`)  
**Bezug:** [Ghidra_Analyse_Erkenntnisse.md](Ghidra_Analyse_Erkenntnisse.md)

---

## 0. Praktisches Fazit (nach Live-Tests, Juli 2026)

> **Die CLI-Shell auf TCP Port 8091 ist von außen nicht nutzbar** — zumindest nicht interaktiv.
>
> Live-Tests (`nc`, Python-Probe, Binary-VenusPacket-Format) ergaben auf **alle** Eingabeformate
> vollständige Stille. Ursache: Der `printf`-Output der Handler geht auf den internen UART-Debug-Port,
> nicht zurück durch den TCP-Socket. Ohne physischen Zugang zum UART (Platine öffnen) ist kein
> Shell-Output sichtbar.
>
> Zusätzlich sind die 4-Byte-Match-Muster der Befehlstabelle nicht bekannt — sie liegen in
> Flash-Sektor 7 (0x08060000–0x0807FFFF), der nicht im verteilten Binary enthalten ist.
>
> **Interface-Übersicht:**
>
> | Port | Protokoll | Status | Fazit |
> |------|-----------|--------|-------|
> | 502 | Modbus TCP | ✅ aktiv | HA-Integration, voll nutzbar |
> | 8091 | TCP CLI-Shell | verbindet, aber stumm | Output auf UART, nicht zugänglich |
> | 30000 | **UDP** JSON-RPC | ⛔ nicht aktivieren | zerstört Modbus-Register dauerhaft |
> | BLE | Binary VenusPacket | ✅ aktiv | `[0x73][len][0x23][cmd][payload][xor]` |

---

## 1. Überblick: Zwei getrennte Befehlssysteme

Das Gerät hat ZWEI vollständig unabhängige Befehlssysteme, die NICHT verwechselt werden dürfen:

| System | Funktion | Protokoll | Kanal |
|--------|----------|-----------|-------|
| **Binäres BLE-Protokoll** | `BLE_Recv_Cmd_Dispatcher @ 0x08007F58` | `[0x73][len][0x23][cmd][payload][xor]` | BLE (Quectel FC41D, UUIDs ff01/ff02) |
| **Text-CLI-Shell** | `BLE_GATT_DispatchCommandByte @ 0x0804C4B4` | 4-Byte-Muster, zeichenweise | TCP Port 8091 (Output auf UART!) |

Dieses Dokument behandelt ausschließlich das **Text-CLI-Shell-System**.

---

## 2. Datenpfad: Wie Bytes zur Shell gelangen

```
┌─────────────────────────────────────────────────────────────┐
│  EINGANGSQUELLEN                                            │
│                                                             │
│  CH395 TCP Socket 1 (Port 8091)    BLE GATT (Quectel FC41D)│
│         ↓                                    ↓             │
│  CH395_ReadRecvBuf(socket=1)         Queue @ 0x200000F0    │
│         └────────────────┬───────────────────┘             │
│                          ↓                                  │
│         Network_ReceiveAndDispatchData @ 0x0804D4E8         │
│              (184 Bytes, Dual-Pfad-Dispatcher)              │
│                          ↓  (Byte für Byte)                 │
│           Sonderbehandlung: Byte 0x03 → log_SetModeAndLevel(0) │
│                          ↓                                  │
│         BLE_GATT_DispatchCommandByte @ 0x0804C4B4           │
│              (232 Bytes, 4-Byte-Mustererkennung)            │
│                          ↓                                  │
│           Befehlstabelle @ 0x08060EF8 (78 Einträge)        │
│                          ↓                                  │
│              Command-Handler-Funktion(ctx)                  │
└─────────────────────────────────────────────────────────────┘
```

**Dual-Pfad-Logik in `Network_ReceiveAndDispatchData`:**
```c
if (RAM[0x20000132] == 1) {
    // TCP-Pfad: Daten von CH395 Socket 1 (Port 8091) lesen
    CH395_ReadRecvBuf(1, buf, len);
    for each byte in buf:
        if (byte == 0x03) log_SetModeAndLevel(0);
        BLE_GATT_DispatchCommandByte(ctx, byte);
} else {
    // Queue-Pfad: BLE/RS485-Queue lesen
    Modbus_Response_Builder(queue, buf, timeout=10000);
    if (buf[0] == 0x03) log_SetModeAndLevel(0);
    BLE_GATT_DispatchCommandByte(ctx, buf[0]);
}
```

**RAM-Adressen:**
- `0x20000132` — Socket-Type-Selektor (1 = TCP-Modus)
- `0x2000010C` — TCP-Queue-Handle
- `0x200000F0` — BLE/RS485-Queue-Handle
- `0x20014A70` — CLI-Kontext-Struktur (RAM, dynamisch alloziert)

---

## 3. Befehlstabellen-Format (16 Bytes pro Eintrag)

**Adresse:** 0x08060EF8 – 0x080613D8 (78 Einträge × 16 Bytes = 1248 Bytes)

```
Offset  Größe  Bedeutung
+0x00   1      Flags/Berechtigungen
+0x01   1      Typ-Byte  (low nibble == 9 → aktiver Befehl)
+0x02   2      Padding
+0x04   4      4-Byte-Match-Muster (big-endian, erstes Byte = MSB)
+0x08   4      Zeiger auf Handler-Funktion (aufgerufen als handler(ctx))
+0x0C   4      Zeiger auf Anzeigename-String (→ Strings bei 0x08055xxx)
```

**Erkannt durch Decompilierung von `BLE_GATT_DispatchCommandByte`:**
```c
// Loop über alle 78 Einträge (stride 0x10):
if ((entry[+1] & 0xF) == 9 &&                          // Typ-Check
    BLE_GATT_EntryFilter(ctx, entry) == 0 &&            // Berechtigungs-Check
    (entry[+4] & accumulated_mask) == ctx->accumulator && // Präfix stimmt
    (entry[+4] & byte_mask) == new_byte << shift) {     // neues Byte stimmt
    
    ctx->accumulator |= new_byte << shift;
    if (shift == 0 || entry[+4].next_byte == 0) {
        entry[+8]();  // Handler aufrufen
        ctx->accumulator = 0;
    }
}
```

Das Muster wird **byte-weise von MSB nach LSB** akkumuliert. 4 Bytes ergeben einen vollständigen Match.

**Wichtig:** Die Befehlstabelle selbst liegt in **Flash-Sektor 7 (0x08060000–0x0807FFFF)**, der **nicht** im verteilten Binary (`_app_1492_...bin`, 385 024 Bytes) enthalten ist. Nur die Anzeigenamen-Strings bei 0x08055xxx sind im Binary vorhanden (erkennbar an `referenceCount=0` — sie werden ausschließlich aus der fehlenden Tabelle referenziert).

---

## 4. Bekannte Befehle (aus String-Analyse)

Die folgenden Strings liegen bei **0x08055xxx** im Binary mit `referenceCount=0`. Das ist der sichere Beweis, dass sie CLI-Befehlsnamen sind — die Zeiger aus der Tabelle bei 0x08060EF8 fehlen im Ghidra-Modell.

### 4.1 Debug & Diagnose

| Befehlsname | Flash-Adresse | Handler-Funktion | Beschreibung |
|-------------|---------------|------------------|--------------|
| `err_code` | 0x080559CA | `Debug_PrintErrorAndEventLog(0)` @ 0x0804D2D4 | Fehlercode-Tabelle (20 Einträge × 14 Bytes) |
| `get_log` | 0x08055853 | `Debug_PrintErrorAndEventLog(1)` @ 0x0804D2D4 | Event-Log (20 Einträge × 9 Bytes) |
| `wifi_info` | 0x0805589E | `Debug_PrintWifiStatus` @ 0x0804D498 | WLAN-Signalstärke + Verbindungsstatus |
| `show_modbus` | 0x08055834 | `Debug_PrintModbusAddress` @ 0x0804D7E4 | Modbus-Register-Adressen ausgeben |
| `ext_info` | 0x080559E9 | `SSL_PrintCertInfo` @ 0x0804D21C | SSL/TLS-Zertifikat-Info |
| `g_ext_info` | 0x080559F8 | `SSL_PrintCertVersion` @ 0x0804D25C (mittel-hoch) | Globale Extended-Info — liegt direkt nach `ext_info`-Handler im selben Block, druckt `"SSL cert version: %d"` |
| `rtos_status` | 0x080554CC | — | FreeRTOS-Task-Status |
| `reset_reason` | 0x08055A03 | — | Letzter Reset-Grund (Watchdog/POR/etc.) |
| `energy_show` | 0x080559A5 | `Debug_PrintPowerStatistics` @ 0x08034974 (hoch) | Energie-Statistiken — druckt all/mon/day_charge_power + all/mon/day_discharge_power |
| `get_time` | 0x0805592C | — | RTC-Zeit lesen |
| `rtc_show` | 0x080554BA | — | RTC-Detailinfo |
| `get_ota_log` | 0x08055C34 | — | OTA-Update-Log |
| `power_check` | 0x08055C0F | `PowerPercent_WriteCallback` @ 0x0804D204 | Leistungs-Check |
| `debug_fc` | 0x08055343 | — | FC41D BLE-Modul debug |
| `trace_debug` | 0x080557EA | — | Trace-Ausgabe |
| `mars_debug` | 0x08032BA8 | — | Marstek-Debug-Modus |

### 4.2 Konfiguration & Steuerung

| Befehlsname | Flash-Adresse | Handler-Funktion | Beschreibung |
|-------------|---------------|------------------|--------------|
| `set_level` | 0x0805530C | `Log_SetModeAndLevelCallback` @ 0x0804D210 | Log-Level setzen |
| `api_port` | 0x080558F4 | `Config_SetLocalApiPort` @ 0x0804D6EC | Lokalen API-Port ändern (schreibt EEPROM @ 0x372) |
| `api_set` | 0x080558B9 | — | API-Einstellungen |
| `set_wifi` | 0x08055772 | — | WLAN-Konfiguration setzen |
| `debug_mode` | 0x080555EA | `Inverter_SetWorkMode` @ 0x0804D76C | Debug-/Arbeitsmodus |
| `modbus` | 0x08055820 | — | Modbus-Steuerung |
| `mac_ble` | 0x0805578C | — | BLE-MAC-Adresse anzeigen |
| `full_dischrg` | 0x08055B6C | — | Vollständige Entladung erzwingen |
| `change_soc` | 0x08055418 | — | Batterie-SOC ändern |
| `button_ctrl` | 0x08055A23 | — | Tastenbelegung / Tastensteuerung |
| `key_state` | 0x08055AE8 | — | Tastenstatus anzeigen |
| `reset` | 0x0805542D | — | Gerät zurücksetzen |
| `venus_rfd` | 0x08055645 | — | Venus RFD (Recovery/Factory Default?) |
| `get_ver` | 0x080553C1 | — | Firmware-Version |
| `set_old` | 0x080553E2 | — | Legacy-Modus aktivieren |
| `get_old` | 0x080553FD | — | Legacy-Wert lesen |

### 4.3 OTA-Updates

| Befehlsname | Flash-Adresse | Beschreibung |
|-------------|---------------|--------------|
| `update_ems` | 0x080554E3 | OTA-Update: EMS-Steuerboard |
| `update_vns` | 0x08055517 | OTA-Update: Venus D (dieses Gerät) |
| `update_bms` | 0x0805552D | OTA-Update: BMS (Batterie-Management) |
| `update_mppt` | 0x08055543 | OTA-Update: MPPT/Solar-Laderegler |

### 4.4 Produktions-/Fertigungstests

| Befehlsname | Flash-Adresse | Handler-Funktion | Beschreibung |
|-------------|---------------|-------------------|--------------|
| `check_periph` | 0x08055386 | `EEPROM_ReadWrite_Test` @ 0x08006FB4 (mittel) | Peripherie-Selbsttest — testet nur EEPROM (Name passt nicht perfekt, evtl. Teil eines größeren Testablaufs) |
| `xfmc_test` | 0x080553A6 | — | XFMC-Speicher-Test |
| `flash_test` | 0x08055440 | `Flash_ReadWriteErase_SelfTest` @ 0x08034D08 (hoch) | Flash-Speicher-Test — interaktiver Write/Read-Test mit Adress-Parameter, `"Write and read OK"` |
| `vns_ate_test` | 0x08055948 | ATE-Fertigungstest (Automated Test Equipment) |
| `code_test` | 0x08055AFF | Code-/Logiktest |

### 4.5 Terminal-Steuerung (Sondertasten)

Diese Namen befinden sich bei **0x08056790** und repräsentieren wahrscheinlich Terminal-Sondertasten-Handler:

| Name | Flash-Adresse |
|------|---------------|
| `right` | 0x08056790 |
| `backspace` | 0x0805679F |
| `delete` | 0x080567B3 |
| `enter` | 0x080567BA |
| `clear` | 0x080567E9 |

---

## 5. Zugangswege zur Shell

### 5.1 TCP Port 8091 (primärer Zugang)

**Einrichtung:** `CH395_Init_TCPServer_Socket @ 0x08032C0C`

```c
CH395_SPI_CmdWaitReady(1);
socket_descriptor.protocol = 2;   // TCP
socket_descriptor.socket   = 1;   // CH395 Socket 1
socket_descriptor.src_port = 0x1F9B;  // 8091
socket_descriptor.dst_port = 0x1F9B;  // 8091
socket_descriptor.mode     = 2;   // Server (Listen)
CH395_Socket_Open_ByDescriptor(socket_descriptor);
```

**Verbindung:**
```
telnet <device-ip> 8091
nc <device-ip> 8091
```

**Besonderheiten:**
- Aktivierung: RAM-Flag `0x20000132 == 1` muss gesetzt sein (Socket-Type-Selektor)
- Byte `0x03` (Ctrl+C/ETX) setzt den Log-Modus zurück: `log_SetModeAndLevel(0)`
- Verbindungsaufbau läuft über `CH395_Recv_Buffer_Setup @ 0x080195A4`, der auch `CLI_InitSession` aufruft

### 5.2 BLE GATT (zweiter Zugangsweg — sehr wahrscheinlich nutzbar)

**Registrierung:** `CLI_InitSession @ 0x0804C708`, aufgerufen von `CH395_Recv_Buffer_Setup`:

```c
void CLI_InitSession(ctx, param_2, param_3=0x200) {
    // ... Kontext initialisieren ...
    ctx[0x16] = 0x08060EF8;          // Zeiger auf Befehlstabelle
    ctx[0x17] = 78;                   // Anzahl Einträge
    BLE_ServiceSlot_Register(ctx);    // ← CLI als BLE-Dienst registrieren
    entry = BLE_GATT_FindEntryByName(ctx, "VNSD-0 v1492", ctx[0x16], 0);
    BLE_GATT_SelectEntry(ctx, entry);
}
```

**BLE-Hardware:** Quectel FC41D (UART-Schnittstelle, AT-Befehle)  
**AT-Befehlsmuster** (aus IDA-Analyse eines verwandten Firmwares):
- GATT-Server: `AT+QBLEGATTSSRV=...`
- Characteristic: `AT+QBLEGATTSCHAR=...`
- Notification: `AT+QBLEGATTSNTFY=ff02,...`

**Bewertung:** Die CLI ist offiziell als BLE-Dienst registriert (`BLE_ServiceSlot_Register`). Der Queue-Pfad in `Network_ReceiveAndDispatchData` leitet BLE-Bytes durch exakt denselben `BLE_GATT_DispatchCommandByte`-Aufruf wie der TCP-Pfad. Die BLE-Characteristic-UUID ist wahrscheinlich `ff02` (aus GATT-Notification-Befehlsmuster).

**Zugangsschritte (experimentell, zu verifizieren):**
1. BLE-Verbindung mit FC41D aufbauen (Gerätename: "VNSD-0 v1492" oder ähnlich)
2. Characteristic `ff02` schreiben (Service UUID: `ff00` oder ähnlich)
3. Bytes werden in die BLE-Queue (`0x200000F0`) eingereiht
4. Queue-Pfad in `Network_ReceiveAndDispatchData` verarbeitet sie

### 5.3 RS485 / Queue-Pfad (theoretisch)

Der Queue-Pfad (`else`-Zweig in `Network_ReceiveAndDispatchData`) liest aus `queue @ 0x200000F0`. Diese Queue kann grundsätzlich auch über RS485 befüllt werden, wenn der entsprechende Modbus-Task Bytes weitergibt. In der Praxis ist das für die Shell unwahrscheinlich (RS485 ist für Modbus RTU reserviert).

---

## 6. Bekannte Handler-Decompilierungen

### `Debug_PrintErrorAndEventLog @ 0x0804D2D4` (230 Bytes)

```c
void Debug_PrintErrorAndEventLog(int param_1) {
    if (param_1 == 0) {
        // "err_code": 20 Fehler-Einträge (14 Bytes each)
        printf("Error code info:\n");
        for (uint i = 0; i < 20; i++) {
            printf("err %d: %d %d %d %d %d %lld\n",
                   i, error_table[i].code, error_table[i].f2,
                   error_table[i].f3, error_table[i].f4, error_table[i].f5);
        }
    } else {
        // "get_log": 20 Event-Einträge (9 Bytes each)
        printf("Event info:\n");
        for (uint i = 0; i < 20; i++) {
            printf("event %d: %d %d %d %d %d %d %d\n",
                   i, event_table[i*9], ...);
        }
    }
}
// Error-Tabelle: DAT_0804d3d0, stride 14 Bytes
// Event-Tabelle: DAT_0804d400, stride  9 Bytes
```

### `Debug_PrintWifiStatus @ 0x0804D498` (24 Bytes)

```c
void Debug_PrintWifiStatus(void) {
    printf("wifi_strength: %d\n", wifi_strength_var);
    printf("wifi_connect_status: %d\n", wifi_connect_status_var);
}
```

### `Config_SetLocalApiPort @ 0x0804D6EC` (66 Bytes)

```c
void Config_SetLocalApiPort(uint16_t new_port) {
    config_base[0x72] = new_port;             // In RAM schreiben
    EEPROM_Write(0x372, &config_base[0x72], 2); // EEPROM persistieren
    if (work_mode != 3 && work_mode != 4)
        work_mode = 5;                        // Neustart-Modus setzen
    printf("Set local api port: %d, read port: %d, mode: %d\n",
           new_port, config_base[0x72], work_mode);
}
```

### `SSL_PrintCertInfo @ 0x0804D21C` (34 Bytes)

```c
undefined8 SSL_PrintCertInfo(void) {
    // Gibt SSL-Zertifikat-Metadaten aus (7 Felder via printf)
    printf(format_string, cert_field[0], cert_field[1], ..., cert_field[6]);
}
```

---

## 7. CLI-Kontext-Struktur (rekonstruiert)

Basis: `param_1` in `CLI_InitSession` und `BLE_GATT_DispatchCommandByte`

```c
struct CLI_Context {
    // +0x00: uint32   - Flags/Status
    // +0x03: uint16   - Feld (init auf 0)
    // +0x0E: uint16   - Feld (init auf 0)
    // +0x10: uint32   - param_2 (Buffer-Zeiger)  [= param_1[4]]
    // +0x34: uint8    - Flags (Bit 0 gesetzt in Init)  [param_1+0x18]
    // +0x38: uint32   - 4-Byte-Akkumulator für Mustervergleich ← wichtig
    // +0x52: uint16   - Feld (init auf 0)
    // +0x54: uint16   - Feld (= param_3/6, z.B. 0x200/6 ≈ 85)
    // +0x58: ptr32    - Zeiger auf Befehlstabelle (= 0x08060EF8)  [param_1[0x16]]
    // +0x5C: uint16   - Anzahl Einträge (= 78)  [param_1[0x17]]
    // +0x3C - 0x53: 5× uint32 - Puffer-Offsets (berechnet)
};
```

---

## 8. Offene Fragen / Nächste Schritte

1. **4-Byte-Befehlsmuster**: Die genauen Match-Werte (entry+4) liegen in Flash-Sektor 7 (0x08060EF8), der nicht im Binary enthalten ist. Ohne vollständiges Flash-Dump (inkl. Sektor 7) nicht ermittelbar. → Mögliche Quellen: OTA-Update-Paket, vollständiger Flash-Dump via JTAG/SWD.

2. **BLE-Zugang verifizieren**: Tatsächliche BLE-Verbindung aufbauen und Characteristic `ff02` beschreiben, dann prüfen ob Shell-Output zurückkommt.

3. **Shell-Prompt**: Unbekannt ob die Shell einen Prompt/Echo ausgibt oder stumm ist.

4. **Befehlsformat mit Parametern**: `Config_SetLocalApiPort` nimmt einen Parameter (`new_port`). Wie Parameter-Übergabe über die Byte-Schnittstelle funktioniert, ist nicht vollständig klar (möglicherweise folgen Parameter-Bytes nach dem 4-Byte-Muster-Match).

5. **Fehlende Handler**: **2026-07-10 Update** — per statischer Ghidra-Analyse (Orphan-Function-Heuristik: `callerCount=0`, da einziger Aufrufer die fehlende Tabelle in Sektor 7 ist) wurden 4 weitere Handler identifiziert: `energy_show`→`Debug_PrintPowerStatistics` (hoch), `flash_test`→`Flash_ReadWriteErase_SelfTest` (hoch), `g_ext_info`→`SSL_PrintCertVersion` (mittel-hoch), `check_periph`→`EEPROM_ReadWrite_Test` (mittel, Name passt nicht perfekt). Widerlegt: `set_wifi` ist **kein** Orphan (`Quectel_WiFi_SetSTAInfo_NoSave` @ 0x08012068 hat einen aktiven Aufrufer im WiFi-Reconnect-Code, gehört nicht zur CLI). Für die übrigen ~26 Befehle (`rtos_status`, `reset_reason`, `get_time`, `rtc_show`, `get_ota_log`, `debug_fc`, `trace_debug`, `api_set`, `set_wifi`, `modbus`, `mac_ble`, `full_dischrg`, `change_soc`, `button_ctrl`, `key_state`, `reset`, `venus_rfd`, `get_ver`, `set_old`, `get_old`, `update_ems/_vns/_bms/_mppt`, `xfmc_test`, `vns_ate_test`, `code_test`) blieb die Zuordnung trotz Keyword-/Similarity-Suche unsicher — **blockiert, benötigt Live-Test** (entweder reine Wrapper um bereits verdrahtete Funktionen oder Code liegt im fehlenden Flash-Sektor 7).

---

## 9. Cheat Sheet: Shell-Zugang testen

```bash
# TCP-Zugang testen (Voraussetzung: Gerät im Netzwerk, IP bekannt)
nc -v <device-ip> 8091

# Mit timeout und Logging
nc -v -w 10 <device-ip> 8091 | xxd

# NMAP Portprüfung
nmap -p 8091 <device-ip>

# Ctrl+C Reset: Byte 0x03 senden
printf '\x03' | nc -w 1 <device-ip> 8091
```

---

*Stand: v149.2 Analyse, Juli 2026*  
*Analyse-Tool: Ghidra + manueller BL-Scan*
