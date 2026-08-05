# Control FW — Function Tracking (nach Themen)

**Binary:** `VNSD-0_app_1492_0702_142136.bin` (v149.2)  
**Gesamt benannte Funktionen (Ghidra, Stand 2026-07-09 nach Batch 20):** 1619

**Dies ist die maßgebliche Referenz für Funktionsnamen/Adressen der Control-FW** — gruppiert nach
Themengebiet (mbedTLS-Cluster, MQTT, BLE, Hardware, ...) statt nach chronologischem Batch. Adressen und
Namen sind direkt aus Ghidra gezogen (Stand nach Batch 19/20, 2026-07-09), inklusive der Korrekturen aus
Batch 18 (62 mbedTLS/Sonstige-Umbenennungen) und Batch 19 (14 aufgelöste Doppelnamen, s. u.).
Beschreibungen wurden aus der ehemaligen Batch-Doku übernommen, wo sie noch zur aktuellen Adresse/Namen
passen; wo das nicht der Fall war, ist die Beschreibungsspalte leer.

> **Hinweis (2026-07-11):** Das ursprüngliche chronologische Batch-Log (`Control_FW_Function_Tracking.md`)
> wurde gelöscht, da es zu dieser Datei redundant war (gleiche Adresse→Name-Paare, aber nach Batch statt
> nach Thema geordnet) und auf Wunsch des Nutzers nicht mehr weitergeführt werden soll — neue Namensvergaben
> werden künftig direkt hier gepflegt. Die Prozess-Notizen/Lektionen aus den Batches sind archiviert in
> [Control_FW_Naming_Batch_History.md](Control_FW_Naming_Batch_History.md).

## Batch 19 — Auflösung aller Doppelnamen (2026-07-09)

Beim Aufbau dieses Dokuments wurde zusätzlich zur Adress-Abgleichsprüfung ein vollständiger Scan auf doppelte
Funktionsnamen im *aktuellen* Ghidra-Stand durchgeführt (nicht nur auf den zuvor bekannten 6). Ergebnis: **14**
Funktionen trugen doppelte Namen, alle wurden in Ghidra umbenannt und in beiden Tracking-Dokumenten aktualisiert:

| Adresse | Alter Name | Neuer Name | Begründung |
|---|---|---|---|
| `0x0801d6cc` | MQTT_Decode_RemainingLength | MQTT_Decode_RemainingLength_ViaCallback | Liest Bytes über einen übergebenen Funktionszeiger (Callback), separat vom Transport-Objekt-Pfad; nur 1 Aufrufer (Wrapper) |
| `0x08033044` | MQTT_Decode_RemainingLength | MQTT_Decode_RemainingLength (unverändert) | Kanonische Variante: liest über Transport-Vtable-Call in MQTT_ReceivePacket — behält den Namen |
| `0x080329b2` | CH395_Socket_SendData | CH395_Socket_SendData_ViaSocketPtr | Dünner Wrapper, dereferenziert Socket-Pointer und ruft direkt CH395_SPI_Send_Data auf, kein Mutex/Polling, 0 Aufrufer |
| `0x0802d12c` | CH395_Socket_SendData | CH395_Socket_SendData (unverändert) | Vollständige Implementierung mit Mutex-Warteschlange, Byte-für-Byte-Versand und Status-Polling — behält den Namen |
| `0x080320ba` | mbedTLS_ASN1_Get_Int | mbedTLS_ASN1_Get_TaggedInt_Core | Generischer interner Helfer, Tag als Parameter (nicht hartkodiert) — von Get_Int UND vermutlich Get_Bool genutzt |
| `0x0803e8c8` | mbedTLS_ASN1_Get_Int | mbedTLS_ASN1_Get_Int (unverändert) | 2-Zeilen-Wrapper, ruft Core mit hartkodiertem Tag=2 (INTEGER) auf — entspricht exakt der echten mbedtls-Public-API |
| `0x08033434` | mbedTLS_ECP_Group_Load | mbedTLS_ECP_Group_Load (unverändert) | 2 Parameter (grp, id), ruft Group_SetById — entspricht der echten mbedtls_ecp_group_load(grp,id) Public-API |
| `0x08033db8` | mbedTLS_ECP_Group_Load | mbedTLS_ECP_Group_Load_RawParams | 13 Parameter (P/A/B/Gx/Gy/N je als Ptr+Len) — entspricht dem internen statischen ecp_group_load() aus ecp_curves.c |
| `0x0804a6fa` | prvCopyDataToQueue | prvCopyDataToQueue (unverändert) | Reine memcpy/Wraparound-Logik auf den Queue-Speicherblock — entspricht dem echten FreeRTOS-internen prvCopyDataToQueue |
| `0x0804abdc` | prvCopyDataToQueue | prvQueueSend_CopyAndNotify | Ruft den echten prvCopyDataToQueue selbst auf und behandelt zusätzlich Lock-Count/Notify-Logik — vermutlich vom Compiler ausgelagerter Teil von xQueueGenericSend/-Receive |
| 0x08036a8e/0x08036b18 | llhttp__internal__c_test_flags (×2) | …_Off32 / …_Off2e | Identischer Bit-Test-Code, aber auf zwei verschiedenen Struct-Feldern (Offset 0x32 bzw. 0x2e) — Suffix benennt das getestete Feld |
| 0x08036a9a/0x08036ade, 0x08036aa6/0x08036ad2, 0x08036ab2/0x08036af6 | llhttp__internal__c_test_flags_{1,2,3} (je ×2) | …_Off32 / …_Off2e | Gleiches Muster wie oben, je einmal für Feld @0x32 und @0x2e |

Damit sind **alle** zum Zeitpunkt der Erstellung dieses Dokuments bekannten Doppelnamen im Ghidra-Projekt aufgelöst
(0 verbleibend, verifiziert per Full-Scan über alle 1417 benannten Funktionen).

Zusätzlich wurden beim erneuten Abfragen von Ghidra 6 Funktionen sichtbar, die zuvor noch nicht (oder unter einem
Default-Namen) erfasst waren — vermutlich durch im Hintergrund fortlaufende Auto-Analyse: `OTA_Update_Dispatcher`,
`vTaskEnterCritical`, `vTaskExitCritical`, `xTimerStop_Internal`, `FreeRTOS_StartScheduler`,
`FreeRTOS_SysTick_TaskUnblock`. Diese sind in diesem Dokument bereits enthalten, aber noch ohne Beschreibung.

## Batch 20 — Identifikation der letzten FUN_-Funktionen (2026-07-09)

Von den zu diesem Zeitpunkt verbliebenen 206 `FUN_`-Funktionen konnten 202 über 6 parallel arbeitende Subagenten identifiziert und in Ghidra umbenannt werden. Ein anschließender Full-Scan ergab dabei weder vor noch nach Anwendung der Umbenennungen doppelte Funktionsnamen (0 Duplikate). Die verbleibenden 4 Funktionen (`0x0800bcc0`, `0x0802da14`, `0x0802db54`, `0x0802dc50`) wurden als Padding/Stub eingestuft und bewusst als `FUN_` belassen. Die vollständigen Details zu allen 202 Umbenennungen finden sich im Abschnitt „Batch 20" von [Control_FW_Function_Tracking.md](Control_FW_Function_Tracking.md).

## Hinweise zur Datenlage

- **992** Funktionen: Beschreibung 1:1 aus der bestehenden Doku übernommen (Adresse *und* Name stimmen überein).
- **58** Funktionen: Beschreibung über den **Namen** gematcht, nicht über die Adresse — d. h. die alte Doku
  hat für diesen Funktionsnamen eine andere Adresse verzeichnet (Adress-Drift, s. Memory-Eintrag zum Thema).
- **165** Funktionen: **keine Beschreibung gefunden** (weder über Adresse noch über Namen) — Spalte
  bleibt leer. Überwiegend llhttp-Interna, weitere Quectel/CH395-Helfer, sowie die 6 neu aufgetauchten FreeRTOS-Funktionen.
- **202** Funktionen: Batch 20 (2026-07-09) — neu identifiziert und benannt, Beschreibung aus Dekompilierung durch Subagenten abgeleitet.

**Re-Audit 2026-07-14 (autonome Session):** Adress-Drift-Vollcheck (alle 1619 Namen gegen Live-Ghidra-Dump
per Skript verglichen — 0 echte Drift-Fälle, 0 fehlende Live-Zuordnung; die zuvor befürchteten "201 stale
addresses" existieren in dieser Datei nicht, da beim Aufbau bereits live-aufgelöste Adressen verwendet
wurden) sowie gezielte Re-Verifikation von 218 Funktionen in bisher nie einzeln auditierten Clustern
(Modbus/RS485, Inverter/Register/Energie, CAN, BLE, Config/EEPROM, OTA/Flash — s. jeweilige Tabellen) gegen
frische Dekompilierung. Ergebnis: 30 fehlerhafte Namen korrigiert (Adresse+Alt-/Neuname s. u. in den
jeweiligen Cluster-Tabellen, Quelle-Spalte "Re-Audit 2026-07-14"), u. a. wurde ein komplett falsch
einsortierter 18-Funktionen-Block (`0x0804bd58`–`0x0804cc40`) von "BLE_GATT_*" auf "CLI_*" korrigiert — es
handelt sich um eine generische CLI/AT-Command-Engine (erreichbar über CH395/Modbus-TCP), nicht um
BLE-GATT-Handling. Diese Funktionen stehen weiterhin im BLE-Abschnitt unten (Umbenennung, aber keine
Abschnitts-Verschiebung vorgenommen); **offener Punkt für den Nutzer:** ob dafür ein eigener Cluster
"CLI/AT-Command-Engine" angelegt werden soll. Nach Anwendung aller Umbenennungen: Vollscan bestätigt weiterhin
0 doppelte Funktionsnamen (1619/1623 benannt, unverändert). Details und vollständige Vorschlagslisten (auch
nicht angewendete, z. B. `0x0802f2b4` und `0x08008000` — beide bewusst unverändert gelassen, s. Begründung im
Session-Log) in der Projekt-Memory. **Update 2026-07-15: beide abgeschlossen** — `0x0802f2b4` umbenannt zu
`BatteryParams_PowerFlowState_Get`, `0x08008000` als Ghidra-Funktionsgrenzen-Artefakt identifiziert und aus
Ghidra entfernt (Details: Control_FW_Analyse_app_1492_0702_142136.md §13.46).

**Re-Audit 2026-07-14, Teil 2 (Cluster „Hardware / HAL", 81 Funktionen, zuvor nie einzeln geprüft):**
Alle 81 Funktionen einzeln per Dekompilierung (inkl. Caller/Callee) gegen die STM32F1-Standard-Peripherie-
Basisadress-Map geprüft (RCC=0x40021000, SPI1=0x40013000/APB2, SPI2=0x40003800/APB1, SPI3=0x40003C00/APB1,
USART1=0x40013800/APB2, I2C1=0x40005400, GPIOA–E=0x40010800–0x40011800, FLASH=0x40022000). Ergebnis: **13
klare Namensfehler gefunden** (bislang nicht angewendet, s. Vorschlagstabelle im Session-Log/Memory), u. a.
ein 4er-Block `ADC_*`/`SPI_Timer_*`, der tatsächlich SPI2- bzw. I2C1-Peripherie anspricht (keine ADC-, kein
SPI/Timer-Register), ein RTC-Get/Set-Vertauschungspaar (RTC_GetTime↔RTC_GetDate, RTC_SetTime↔RTC_SetDate,
Zieladresse und Caller-Semantik bestätigen den Tausch übereinstimmend), zwei Funktionen (`RCC_EnablePeripheralClock`,
`STM32_RCC_Clock_Config`), die tatsächlich FLASH- bzw. AFIO-Register statt RCC ansprechen, sowie zwei
Bit-Band-Alias-Fälle (`GPIO_PulsePin`/`GPIO_WritePinValue`), die RCC_BDCR.BDRST statt eines GPIO-Pins
schreiben. Der befürchtete I2C↔CAN-Verwechslungsfall im I2C-Bitbang/EEPROM_I2C-Cluster (21 Funktionen) wurde
**nicht bestätigt** — alle Basisadressen (I2C1=0x40005400, GPIOB/GPIOC für Bitbang) stimmen mit den Namen
überein; einzig ein veralteter Aufrufer-Hinweis ("CAN_SendWorkModeFrame" statt korrekt "I2C_SendWorkModeFrame")
in der Beschreibung von `I2C_BitBang_WriteBytes` wurde korrigiert. Zusätzlich 7 fehlende/falsche
Beschreibungen direkt korrigiert (GPIO_ConfigPinAsInput, RCC_AHBPeriphResetCmd, RCC_APB1PeriphResetCmd,
RCC_PeriphBitControl, RCC_GetFlagStatus, GPIOD_Pin9_Write, I2C_BitBang_WriteBytes — Quelle-Spalte „Ghidra
(Re-Audit 2026-07-14)"). Offener Punkt: `USART_Init` prüft neben USART1 (0x40013800, korrekt) auch zwei
Konstanten `0x40015000`/`0x40015400`, die **nicht** den Standard-STM32F103-Adressen für USART2/3
(0x40004400/0x40004800) entsprechen — deutet auf zusätzliche APB2-getaktete UART-Instanzen eines
STM32F1-kompatiblen Derivats (z. B. GD32F103/AT32F403-Klasse) hin; nicht abschließend geklärt, s.
Control_FW_Analyse_app_1492_0702_142136.md §13.35. Alle Umbenennungsvorschläge s. Antwort/Memory dieser
Session — noch nicht in Ghidra angewendet (Nutzerentscheidung ausstehend).

---

## mbedTLS — MPI / Bignum (54)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08031cce` | mbedTLS_MPI_Add_Sub_Signed | MPI Signed Add/Sub mit Vorzeichen-Logik | high | Doku |
| `0x08033ee4` | mbedTLS_MPI_Init_Static | MPI aus statischem ROM-Buffer | high | Doku |
| `0x0803f16a` | mbedTLS_MPI_CT_CondAssign | Conditional MPI-Limb Copy mit Maske | high | Doku |
| `0x080408a2` | mbedTLS_MPI_Int_Div_Int | 64-Bit Division mit Rest, Overflow-Check | high | Doku |
| `0x0804247c` | mbedTLS_MPI_Add_Abs | Limb-Addition mit Carry (echte Implementierung) | high | Doku |
| `0x08042584` | mbedTLS_MPI_Add_Int | MPI aus signed Integer konstruieren  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x08042612` | mbedTLS_MPI_Add_MPI | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08042628` | mbedTLS_MPI_Bitlen | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08042660` | mbedTLS_MPI_Cmp_Abs | Leading-Zero Trim + MSB-First Vergleich | high | Doku |
| `0x080426f2` | mbedTLS_MPI_Cmp_Int | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08042726` | mbedTLS_MPI_Cmp_MPI | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080427da` | mbedTLS_MPI_Copy | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08042866` | mbedTLS_MPI_Div_MPI | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08042c2e` | mbedTLS_MPI_Exp_Mod | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080430e4` | mbedTLS_MPI_Fill_Random_Sized | Byte→Limb Konvertierung + Grow  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0804313c` | mbedTLS_MPI_Free | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08043164` | mbedTLS_MPI_GCD | Stein's Binary-GCD Algorithmus | high | Doku |
| `0x080432cc` | mbedTLS_MPI_Get_Bit | Bit-Position aus MPI extrahieren | high | Doku |
| `0x080432f2` | mbedTLS_MPI_Mont_Compute_RR | R² mod N für Montgomery Setup | high | Doku |
| `0x0804334e` | mbedTLS_MPI_Grow | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080433a4` | mbedTLS_MPI_Init | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080433b4` | mbedTLS_MPI_Inv_Mod | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080436f2` | mbedTLS_MPI_LSB | Trailing-Zero Bits zählen | high | Doku |
| `0x0804372a` | mbedTLS_MPI_Lset | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08043772` | mbedTLS_MPI_Lt_MPI_CT | **CT** Less-Than Vergleich (Side-Channel sicher) | high | Doku |
| `0x0804381e` | mbedTLS_MPI_Mod_MPI | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080438ac` | mbedTLS_MPI_Mont_Mul | Montgomery-Multiplikation (CT CondAssign) | high | Doku |
| `0x0804396a` | mbedTLS_MPI_Mont_Init | mm = -N⁻¹ mod 2³² (Newton-Iteration) | high | Doku |
| `0x08043994` | mbedTLS_MPI_Mul_Int | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08043a08` | mbedTLS_MPI_Mul_Mod | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08043a4e` | mbedTLS_MPI_Mul_MPI | Echte Schoolbook-Multiplikation (8 Aufrufer) — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08043b68` | mbedTLS_MPI_Random | Rejection-Sampling [min, N), max 250 Retries | high | Doku |
| `0x08043c7c` | mbedTLS_MPI_Read_Binary | Big-Endian Bytes → MPI (6 Aufrufer) | high | Doku |
| `0x08043cdc` | mbedTLS_MPI_Grow_Clear | Resize + Zero (Daten nicht erhalten) | high | Doku |
| `0x08043d14` | mbedTLS_MPI_Safe_Cond_Assign | **CT** Conditional Copy (ECP Side-Channel) | high | Doku |
| `0x08043d82` | mbedTLS_MPI_Shift_Left | Links-Shift: Word+Bit mit Carry | high | Doku |
| `0x08043e96` | mbedTLS_MPI_Shift_R | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08043f40` | mbedTLS_MPI_Shrink_Realloc | Allokation verkleinern (10001-Limb Limit) | high | Doku |
| `0x08043fc2` | mbedTLS_MPI_Size | Byte-Count: (bitlen+7)>>3 | high | Doku |
| `0x08043fd2` | mbedTLS_MPI_Sub_Abs_Core | Unsigned Subtraktion mit Borrow | high | Doku |
| `0x080440ba` | mbedTLS_MPI_Sub_Int | Integer von MPI subtrahieren | medium | Doku |
| `0x080440f6` | mbedTLS_MPI_Sub_Mod | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804414e` | mbedTLS_MPI_Sub_MPI | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08044166` | mbedTLS_MPI_Write_Binary | MPI → Big-Endian Bytes (5 Aufrufer) | high | Doku |
| `0x080441e8` | mbedTLS_MPI_Write_Binary_LE | MPI → Little-Endian Bytes | high | Doku |
| `0x08044252` | mbedTLS_MPI_Zeroize | Limb-Array zeroizen (Security) | high | Doku |
| `0x08048794` | mbedTLS_MPI_Reverse_Words | In-place Word-Array Reversal (Endianness) | high | Doku |
| `0x080487cc` | mbedTLS_MPI_Fill_Random | Limbs via RNG füllen, Padding, Reversal | high | Doku |
| `0x0804883a` | mbedTLS_MPI_Mont_Mul_One | MPI=1 konstruieren → Mont_Mul (Montgomery Identity) | high | Doku |
| `0x08048866` | mbedTLS_MPI_Mul_Helper | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08048e92` | mbedTLS_MPI_CT_Select | **Constant-Time** Window-Tabellen Lookup (Side-Channel resistent) | high | Doku |
| `0x08048edc` | mbedTLS_MPI_Uint_Abs | Einfacher Absolutwert | high | Doku |
| `0x08048eea` | mbedTLS_MPI_Sub_Helper | Multi-Precision Subtraction mit Borrow Propagation | high | Doku |
| `0x0804baec` | mbedTLS_MPI_Montgomery_Convert | Montgomery-Domain Konvertierung, RR berechnen  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |

## mbedTLS — ECP / ECDH (67)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08033200` | mbedTLS_ECP_Write_Reduced_Coordinate | Punkt → Binary (compressed/uncompressed)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08033298` | mbedTLS_ECDH_Compute_Shared_Restartable | Modulare Reduktion mit Temp-MPI  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0803330c` | mbedTLS_ECP_Group_Free | ECP-Gruppen-Struct freigeben | high | Doku |
| `0x08033338` | mbedTLS_ECDH_Gen_Public_Restartable | Jacobian normalisieren (Z^-1)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08033394` | mbedTLS_ECP_Group_Init | ECP-Gruppen-Struct initialisieren | high | Doku |
| `0x080333c0` | mbedTLS_ECDH_Make_Public | Binary → ECP-Punkt  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08033418` | mbedTLS_ECP_TLS_Read_Point_Alt | TLS Wire-Format Punkt schreiben  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08033434` | mbedTLS_ECP_Group_Load | Kurvenparameter laden | high | Doku |
| `0x080334dc` | mbedTLS_ECP_Add_Mixed | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080337d0` | mbedTLS_ECP_Check_Point_On_Curve | y²=x³+ax+b mod P verifizieren | high | Doku |
| `0x080338fc` | mbedTLS_ECP_Comb_Recode_Core | Comb-Methode Scalar-Bits extrahieren | high | Doku |
| `0x0803398c` | mbedTLS_ECP_Comb_Recode_Scalar | Scalar vorbereiten für Comb-Multiplikation | high | Doku |
| `0x08033a40` | mbedTLS_ECP_Point_Zeroize | Punkt = Infinity setzen  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x08033a54` | mbedTLS_ECP_Double_Jac | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08033d52` | mbedTLS_ECP_RNG_Wrapper | MPI-Read Wrapper für Punkt  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x08033d68` | mbedTLS_ECP_DRBG_Seed_From_Scalar | Private Key aus Binary (max 32B)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08033db8` | mbedTLS_ECP_Group_Load_RawParams | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08033e44` | mbedTLS_ECP_Modp | Modulare Reduktion (Fast-Path oder MPI_Mod) | high | Doku |
| `0x08033ef0` | mbedTLS_ECP_Mul_Restartable | Haupt-Skalarmultiplikation (Comb-Methode) | high | Doku |
| `0x08034074` | mbedTLS_ECP_Mul_Comb | Comb-Methode Orchestrator | high | Doku |
| `0x08034126` | mbedTLS_ECP_Mul_Comb_Core | Inner Comb Loop (Double+Add) | high | Doku |
| `0x080341f0` | mbedTLS_ECP_Normalize_Jac | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080342b4` | mbedTLS_ECP_Normalize_Jac_Many | Batch-Normalisierung (Montgomery's Trick) | high | Doku |
| `0x080344d4` | mbedTLS_ECP_PickWindowSize | Window 4 oder 5 nach Bit-Länge | high | Doku |
| `0x080344fc` | mbedTLS_ECP_PrecomputeComb | Comb-Tabelle vorberechnen | high | Doku |
| `0x08034640` | mbedTLS_ECP_RandomizeJac | Z^-1 berechnen, X/Z², Y/Z³  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08034718` | mbedTLS_ECP_SafeInvertJac | Y bedingt negieren (Constant-Time) | high | Doku |
| `0x0803477c` | mbedTLS_ECP_SelectComb | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0803f638` | mbedTLS_ECP_TLS_Write_Point | TLS Point-Serialisierung (Named Curve Check) | high | Doku |
| `0x0803f67c` | mbedTLS_ECP_Mod_Reduce_NoRestart | Wrapper → ModReduce(restart=0) | high | Doku |
| `0x0803f6b4` | mbedTLS_ECP_KeyInfo_Free | KeyInfo-Wrapper Free (Marstek-spezifisch, 0xe0B) | high | Doku |
| `0x0803f6da` | mbedTLS_ECP_Normalize_Jac_NoRestart | Wrapper → NormalizeJac(restart=0) | high | Doku |
| `0x0803f710` | mbedTLS_ECP_KeyInfo_Init | KeyInfo memset(0, 0xe0) | high | Doku |
| `0x0803f728` | mbedTLS_ECP_KeyInfo_Read_Point | Binary Point lesen via KeyInfo-Wrapper | high | Doku |
| `0x0803f770` | mbedTLS_ECP_TLS_Read_GroupAndPoint | TLS Group-ID + Point serialisieren  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0803f7cc` | mbedTLS_ECP_KeyInfo_LoadGroup | Curve-ID → Group laden + Flag setzen | high | Doku |
| `0x0803f7f4` | mbedTLS_ECP_Check_PrivKey | key >= 1 && key < N validieren | high | Doku |
| `0x0803f83c` | mbedTLS_ECP_Check_PubPriv | **0 Aufrufer** — Pub/Priv Konsistenz-Check | high | Doku |
| `0x0803f900` | mbedTLS_ECP_Check_PubKey | Z==1, Group valid, Point on Curve | high | Doku |
| `0x0803f940` | mbedTLS_ECP_Point_Copy | 3 MPI-Kopien (X, Y, Z) | high | Doku |
| `0x0803f996` | mbedTLS_ECP_CurveInfo_FromGrpId | Tabellen-Lookup nach Group-ID | high | Doku |
| `0x0803f9b8` | mbedTLS_ECP_CurveInfo_FromTlsId | Tabellen-Lookup nach TLS Named Curve ID | high | Doku |
| `0x0803f9dc` | mbedTLS_ECP_CurveInfo_GetList | 4B Stub → statische Tabelle | high | Doku |
| `0x0803f9e4` | mbedTLS_ECP_Gen_Privkey | Mod-Reduktion Dispatcher (Short Weierstrass)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0803fa20` | mbedTLS_ECP_Gen_Privkey_ShortWeierstrass | mpi_mod_mpi mit Error-Remapping  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0803fa50` | mbedTLS_ECP_GetType | Curve-Type: 0=none, 1=SW, 2=Montgomery | high | Doku |
| `0x0803fa66` | mbedTLS_ECP_Group_SetFromInfo | Thin Wrapper → Group_SetById | high | Doku |
| `0x0803fa7e` | mbedTLS_ECP_Group_FreeFields | Alle MPIs + T-Table freigeben, 0x7C zeroize | high | Doku |
| `0x0803fae2` | mbedTLS_ECP_Group_InitFields | Alle Group-Felder initialisieren | high | Doku |
| `0x0803fb2c` | mbedTLS_ECP_Group_SetById | **Nur SECP256R1 (ID=3)** — kein Fallback | high | Doku |
| `0x0803fb98` | mbedTLS_ECP_BuildSupportedCurvesList | Lazy-Init Cached Curve-Liste | high | Doku |
| `0x0803fbd4` | mbedTLS_ECP_Point_IsZero | Z==0 → Point at Infinity | high | Doku |
| `0x0803fbf0` | mbedTLS_ECP_Keypair_Free | Group + MPI d + Point Q freigeben | high | Doku |
| `0x0803fc12` | mbedTLS_ECP_Keypair_Init | Keypair Init (0 Aufrufer → Funktionspointer) | high | Doku |
| `0x0803fc32` | mbedTLS_ECP_Mul | Wrapper → Mul_Checked(restart=0) | high | Doku |
| `0x0803fc6c` | mbedTLS_ECP_Mul_Checked | Curve-Type + Point validieren, → Mul_Restartable | high | Doku |
| `0x0803fcf4` | mbedTLS_ECP_Point_Free | 3 MPIs freigeben (X, Y, Z), 7 Aufrufer | high | Doku |
| `0x0803fd16` | mbedTLS_ECP_Point_Init | 3 MPIs initialisieren (X, Y, Z), 7 Aufrufer | high | Doku |
| `0x0803fd38` | mbedTLS_ECP_Point_ReadBinary | 0x00=Infinity, 0x04=Uncompressed | high | Doku |
| `0x0803fdf0` | mbedTLS_ECP_Point_WriteBinary | Uncompressed (0x04) + Compressed (0x02/0x03) | high | Doku |
| `0x0803fee4` | mbedTLS_ECP_Point_SetZero | X=1, Y=1, Z=0 (Jacobian Infinity) | high | Doku |
| `0x0803ff30` | mbedTLS_ECP_TLS_ReadGroup | TLS NamedCurve lesen (Tag 0x03, 2B ID) | high | Doku |
| `0x0803ff94` | mbedTLS_ECP_TLS_Read_Point | Length-Prefixed Point aus TLS-Buffer | high | Doku |
| `0x0803ffec` | mbedTLS_ECP_TLS_Write_Point_Inner | Point + Length-Prefix in TLS-Buffer schreiben | high | Doku |
| `0x080425c0` | mbedTLS_ECP_Mod_Reduce | MPI grow + Subtraktion in Schleife bis < P | high | Doku |
| `0x08043e4c` | mbedTLS_ECP_Mod_Reduce_ShiftSub | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f7dc` | mbedTLS_ECP_SupportedCurves_Write | Schreibt Supported-Curves-Extension in TLS-ClientHello | high | Doku (Name-Match) |

## mbedTLS — RSA (36)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0803f1b2` | mbedTLS_RSA_PKCS1v15_Unpad | **SECURITY** CT PKCS#1 v1.5 Unpadding (Bleichenbacher-Schutz) | high | Doku |
| `0x08044bb8` | mbedTLS_RSA_Alt_SetCallbacks | Alternative RSA-Callbacks setzen | medium | Doku |
| `0x08044bd0` | mbedTLS_RSA_Alt_InitOnce | One-Shot Guard → SetCallbacks | medium | Doku |
| `0x08044c14` | mbedTLS_RSA_CheckPrivkey | P, Q, D, DP, DQ, QP validieren | high | Doku |
| `0x08044c84` | mbedTLS_RSA_CheckPubPriv | N und E von Pub/Priv vergleichen | high | Doku |
| `0x08044cd0` | mbedTLS_RSA_CheckPubkey | N>127bit, E ungerade, E>1, E<N | high | Doku |
| `0x08044d2c` | mbedTLS_RSA_Complete | Key aus Partial-Components vervollständigen | high | Doku |
| `0x08044f78` | mbedTLS_RSA_DeduceCrt | CRT: DP, DQ, QP berechnen | high | Doku |
| `0x08045018` | mbedTLS_RSA_DeducePrimes | P, Q aus N, E, D rekonstruieren (540B) | high | Doku |
| `0x0804526c` | mbedTLS_RSA_DeduceD | D = E⁻¹ mod LCM(P-1, Q-1) | high | Doku |
| `0x08045360` | mbedTLS_RSA_Export | N/E/D/P/Q via MPI_Copy exportieren | high | Doku |
| `0x08045440` | mbedTLS_RSA_Free | 13 MPI-Felder freigeben (0xAC Context) | high | Doku |
| `0x080454b4` | mbedTLS_RSA_Get_Len | Key-Länge in Bytes aus ctx+4 | high | Doku |
| `0x080454bc` | mbedTLS_RSA_Import | MPI-Werte in RSA-Context importieren | high | Doku |
| `0x08045584` | mbedTLS_RSA_Import_Raw | Raw-Binary → RSA-Context | high | Doku |
| `0x08045680` | mbedTLS_RSA_Init | 0xAC Context nullen (0 Aufrufer) | high | Doku |
| `0x080456a4` | mbedTLS_RSA_PKCS1_Encrypt | Padding-Mode Check → RSAES Dispatch | high | Doku |
| `0x080456f0` | mbedTLS_RSA_PKCS1_Decrypt | Padding-Mode Check → Decrypt Dispatch | high | Doku |
| `0x08045738` | mbedTLS_RSA_PKCS1v15_Sign | Padding-Mode Check → RSASSA Dispatch | high | Doku |
| `0x08045780` | mbedTLS_RSA_PKCS1v15_Verify | **0 Aufrufer** — Dead Code oder Ptr-Tabelle | high | Doku |
| `0x080457c8` | mbedTLS_RSA_Private | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08045b18` | mbedTLS_RSA_Public | RSA Public-Key Op (MPI Exp Mod), 4 Aufrufer | high | Doku |
| `0x08045bf8` | mbedTLS_RSA_RSAES_PKCS1v15_Decrypt | Decrypt + Unpad + Zeroize | high | Doku |
| `0x08045c98` | mbedTLS_RSA_RSAES_PKCS1v15_Encrypt | Padding (0x02 random / 0x01 0xFF) + RSA Op | high | Doku |
| `0x08045dcc` | mbedTLS_RSA_RSASSA_PKCS1v15_Sign | **Sign mit Blinding + Verify-After-Sign** (Fault-Attack Schutz) | high | Doku |
| `0x08045edc` | mbedTLS_RSA_RSASSA_PKCS1v15_Verify | Verify: encode + RSA Public + CT Compare | high | Doku |
| `0x08045fbc` | mbedTLS_RSA_SetPadding | Padding-Mode (+0xa4) + Hash-ID (+0xa8) | high | Doku |
| `0x08045fd0` | mbedTLS_RSA_CheckCRT | DP, DQ, QP Konsistenz prüfen | high | Doku |
| `0x08046120` | mbedTLS_RSA_ValidateParams | N==P*Q, D*E mod LCM Check (452B) | high | Doku |
| `0x0804b610` | mbedTLS_RSA_Check_Context | **Max 2048-bit** RSA (N ≤ 256B), 5 Aufrufer — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0804b6dc` | mbedTLS_RSA_CheckPubPriv_Wrapper | Thin Wrapper, 0 Aufrufer (Fn-Pointer) | high | Doku |
| `0x0804b7a8` | mbedTLS_RSA_Context_Free | RSA_Free + Platform_Free, 0 Aufrufer (Fn-Pointer) | high | Doku |
| `0x0804b7ba` | mbedTLS_RSA_Get_Bitlen | N Export → Bitlen, Fallback Get_Len*8 | high | Doku |
| `0x0804b7fc` | mbedTLS_RSA_Prepare_Blinding | Modulare Reduktion mit Retry-Loop (max 10x)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0804b96c` | mbedTLS_RSA_PKCS1v15_Encode_DigestInfo | PKCS#1 v1.5 Signatur-Encoding (00 01 FF..FF 00 DI hash) | high | Doku |
| `0x0804bab0` | mbedTLS_RSA_Sign_PKCS1v15_Wrapper | Wrapper → Sign(mode=1, private), 0 Aufrufer | high | Doku |

## mbedTLS — SSL/TLS Handshake (137)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080128c4` | mbedTLS_SSL_Recv_WithTimeout | SSL-Empfang mit Timeout | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08012924` | mbedTLS_SSL_Send_WithTimeout | SSL-Versand mit Timeout | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08018364` | mbedTLS_SSL_Connection_Init | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08032e14` | SSL_RecordLen_ToHighWord | 6B Shift-Helper für SSL Record | medium | Doku |
| `0x0803658e` | mbedTLS_CheckCompressionMethod | param != 0 prüfen (TLS ServerHello) | high | Doku |
| `0x0804664e` | mbedTLS_SSL_CheckSigHash | Erlaubte Sig-Hashes prüfen (config+0x58) | high | Doku |
| `0x0804667a` | mbedTLS_SSL_CheckCurve | Erlaubte Curves prüfen (config+0x54) | high | Doku |
| `0x080466a6` | mbedTLS_SSL_CheckTimer | Timer-Callback abrufen | high | Doku |
| `0x080466c8` | mbedTLS_SSL_BoundsCheck | Buffer-Bounds Check (11 Aufrufer) | high | Doku |
| `0x080466dc` | mbedTLS_Ciphersuite_Uses_SrvCert | Key-Exchange → Server-Cert nötig? | high | Doku |
| `0x08046708` | mbedTLS_SSL_Read_RecordLen | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08046728` | mbedTLS_Ciphersuite_Uses_EC | Key-Exchange → EC nötig? | high | Doku |
| `0x08046752` | mbedTLS_Ciphersuite_CertReq_Allowed | CertRequest erlaubt? | high | Doku |
| `0x0804677e` | mbedTLS_SSL_Conf_Authmode | Authmode setzen (+6) | high | Doku |
| `0x08046782` | mbedTLS_SSL_Conf_CA_Chain | CA Chain + CRL setzen (+0x4c/+0x50) | high | Doku |
| `0x08046788` | mbedTLS_SSL_Conf_Ciphersuites | 4× Ciphersuite-Liste (+0x10-+0x1c) | high | Doku |
| `0x08046792` | mbedTLS_SSL_Conf_Curves | Curve-Liste (+0x58) | medium | Doku |
| `0x08046796` | mbedTLS_SSL_Conf_Endpoint | Client/Server (+4) | medium | Doku |
| `0x0804679a` | mbedTLS_SSL_Conf_MaxVersion | Max TLS Version (+0,+1) | high | Doku |
| `0x080467a0` | mbedTLS_SSL_Conf_MinVersion | Min TLS Version (+2,+3) | high | Doku |
| `0x080467a6` | mbedTLS_SSL_Conf_OwnCert | Cert+Key registrieren | medium | Doku |
| `0x080467bc` | mbedTLS_SSL_Conf_Rng | RNG Callback setzen (+0x28/+0x2c) | high | Doku |
| `0x080467c2` | mbedTLS_SSL_Conf_SigHashes | Sig-Hash Liste (+0x54) | medium | Doku |
| `0x080467c6` | mbedTLS_SSL_Conf_Transport | Authmode (+5)  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x080467cc` | mbedTLS_SSL_Config_Defaults | **TLS 1.2 forced** (alle Version-Bytes = 3) | high | Doku |
| `0x0804685c` | mbedTLS_SSL_Config_Free | 0x5c Config zeroize | high | Doku |
| `0x08046870` | mbedTLS_SSL_Config_Init | memset(0, 0x5c) | high | Doku |
| `0x08046880` | mbedTLS_SSL_Decrypt_Buf | **AEAD-only** (GCM/CCM/ChaCha20, kein CBC!) | high | Doku |
| `0x080469d4` | mbedTLS_SSL_Derive_Keys | Master Secret + Transform Setup | high | Doku |
| `0x08046a90` | mbedTLS_SSL_Encrypt_Buf | AEAD Encrypt + Explicit IV | high | Doku |
| `0x08046c14` | mbedTLS_SSL_Fetch_Input | f_recv Loop, max 0x182f Bytes | high | Doku |
| `0x08046ce0` | mbedTLS_SSL_Flush_Output | f_send Loop, out_left tracking | high | Doku |
| `0x08046d78` | mbedTLS_SSL_Free | 5 Felder + 0xC4 zeroize  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x08046e20` | mbedTLS_SSL_FreeHostname | Hostname zeroize+free | high | Doku |
| `0x08046e5c` | mbedTLS_SSL_GetKeyExchangeType | Ciphersuite → KE Type (1/2/4) | high | Doku |
| `0x08046e8c` | mbedTLS_SSL_GetHostname | Hostname aus +0xbc | high | Doku |
| `0x08046ea8` | mbedTLS_SSL_CalcVerifyHash | Handshake-Hash berechnen | high | Doku |
| `0x08046f50` | mbedTLS_SSL_GetOutputMaxFragLen | Max Fragment = 0x800 (2048B) | high | Doku |
| `0x08046f6a` | mbedTLS_SSL_GetMaxFragLenInternal | Min über 3 Transforms | high | Doku |
| `0x08046fb0` | mbedTLS_SSL_CheckRecordType | 0x16=HS, 0x14=CCS, 0x15=Alert | high | Doku |
| `0x08047060` | mbedTLS_SSL_Handshake | Loop bis State 0x10 (OVER) | high | Doku |
| `0x08047098` | mbedTLS_SSL_HandshakeClientStep | **16-Case Client State Machine** | high | Doku |
| `0x08047184` | mbedTLS_SSL_HandshakeParamsFree | ECP + PK + 0x1DC zeroize | high | Doku |
| `0x080471bc` | ssl_HandshakeStepDispatch | Context-Validierung + Dispatch | high | Doku |
| `0x080471e4` | ssl_HandshakeWrapup | Session rotieren, SNI Callback | high | Doku |
| `0x08047238` | ssl_HandshakeWrapupFreeTransform | Transform freigeben, Buffers rotieren | high | Doku |
| `0x0804726e` | mbedtls_ssl_check_pending | Buffered data? (offset 0xBC) | high | Doku |
| `0x0804727e` | ssl_HashFromMdAlg | SHA224→3, SHA256→4 | high | Doku |
| `0x08047296` | ssl_HandshakeParamsInit | memset(0, 0xC4) | high | Doku |
| `0x080472a4` | ssl_BuildSupportedCipherList | Lazy-Init gefilterte Cipher-Liste | medium | Doku |
| `0x080472f4` | ssl_MdAlgFromHash | 3→SHA224, 4→SHA256 | high | Doku |
| `0x0804730c` | ssl_ApplyEncryptThenMac | ETM Extension Flag setzen | medium | Doku |
| `0x08047328` | ssl_GetRemainingPayloadLen | Output-Buffer Restplatz | high | Doku |
| `0x08047336` | ssl_GetOwnPrivateKey | PK Key aus Session oder Config | high | Doku |
| `0x0804735c` | mbedTLS_SSL_ProcessCertificateKeyExchange | Server-Cert parsen + Key-Exchange | high | Doku |
| `0x08047450` | mbedTLS_SSL_ParseChangeCipherSpec | CCS validieren (0x14, len=1) | high | Doku |
| `0x080474b4` | mbedTLS_SSL_ParseFinishedMessage | **CT Compare** 12B Verify Data | high | Doku |
| `0x08047588` | mbedTLS_SSL_IsDTLS | Transport==1? | high | Doku |
| `0x08047594` | mbedTLS_SSL_ValidateHandshakeHeader | Length Check (>3, total_len+4 <= record) | high | Doku |
| `0x080475dc` | mbedTLS_SSL_Read | App-Data lesen + Alert/HS dispatch | high | Doku |
| `0x08047754` | mbedTLS_SSL_ReadRecord | Core Record-Reader (8 Aufrufer) | high | Doku |
| `0x080477ea` | mbedTLS_SSL_ReadVersion | 2 Bytes → major/minor | high | Doku |
| `0x080477f6` | mbedTLS_SSL_UpdateRecordPointers | In/Out Buffer +8 | medium | Doku |
| `0x0804781c` | mbedTLS_SSL_SendAlertMessage | Alert senden (15 Aufrufer!) | high | Doku |
| `0x08047880` | mbedTLS_SSL_SessionFree | Cipher + 0x70 zeroize  — **korrigiert 2026-07-09**, s. Batch 18 | high | Doku |
| `0x0804789a` | mbedTLS_SSL_HandshakeParams_Init | memset(0, 0x70) | high | Doku |
| `0x080478a8` | mbedTLS_SSL_Set_Transport_Params | 4 Transport-Felder setzen | high | Doku |
| `0x080478b8` | mbedTLS_SSL_Set_Hostname | Hostname setzen (max 256 Zeichen) | high | Doku |
| `0x08047920` | mbedTLS_SSL_Debug_Callback_Invoke | Debug Callback (+0x50) | high | Doku |
| `0x08047940` | mbedTLS_SSL_Setup | Alloc in/out Buffer (0x182f/0x82d) | high | Doku |
| `0x080479dc` | mbedTLS_SSL_PK_Can_Do_RSA | PK_Can_Do(ctx, RSA) Wrapper | high | Doku |
| `0x080479f2` | mbedTLS_SSL_Verify_Flags_Init | 2 Bytes gleich setzen | medium | Doku |
| `0x080479f8` | mbedTLS_SSL_Transform_Free | 2× Cipher Free + 0xa8 zeroize | high | Doku |
| `0x08047a1c` | mbedTLS_SSL_Transform_Init | 0xa8 memset + 2× Cipher Init | high | Doku |
| `0x08047a3a` | mbedTLS_SSL_Flight_Retransmit | DTLS Flight Retransmit | high | Doku |
| `0x08047a58` | mbedTLS_SSL_Reset_Record_Pointers | Header/Content/Payload Offsets | high | Doku |
| `0x08047a70` | mbedTLS_SSL_SetOutMsgPointers | Output-Buffer Offsets berechnen | high | Doku |
| `0x08047aa4` | mbedTLS_SSL_Write | App-Data schreiben (State 0x10 check) | high | Doku |
| `0x08047af4` | mbedTLS_SSL_WriteClientCertificate | Cert-Chain serialisieren (Type 0x0b) | high | Doku |
| `0x08047c04` | mbedTLS_SSL_WriteChangeCipherSpec | CCS senden (0x14, 0x01) | high | Doku |
| `0x08047c42` | mbedTLS_SSL_WriteFinished | Finished senden (Type 0x14) | high | Doku |
| `0x08047cd8` | mbedTLS_SSL_WriteRecord | Record senden (6 Aufrufer) | high | Doku |
| `0x08047d84` | mbedTLS_SSL_FlushOutput | Version + Encrypt + MAC + Send | high | Doku |
| `0x08047f14` | mbedTLS_SSL_WriteVersion | major/minor → 2 Bytes | high | Doku |
| `0x0804d21c` | SSL_PrintCertInfo | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d25c` | SSL_PrintCertVersion | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804da38` | mbedTLS_KeyCert_AppendToList | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804da7c` | mbedTLS_BuildAeadNonce | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dabc` | mbedTLS_ComputeFinishedVerifyData | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804db54` | mbedTLS_CalcHandshakeHash | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804db94` | mbedTLS_ValidateContentType | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dbb4` | mbedTLS_SSL_CheckCurveAndSigHash | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dbf0` | mbedTLS_SSL_FreeSessionBuffer | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dc0c` | mbedTLS_SSL_DeriveMasterSecret | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dc80` | mbedTLS_SSL_UpdateRecordBuffer | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dce0` | mbedTLS_SSL_BuildAeadNonce | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dd16` | mbedTLS_SSL_GeneratePremasterRandom | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dd52` | mbedTLS_SSL_GetHandshakeLength | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dd6a` | mbedTLS_SSL_ReadRecordLayer | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804de04` | mbedTLS_SSL_AllocSessionStructs | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804de9c` | mbedTLS_SSL_HandshakeInit | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804dee4` | mbedTLS_SSL_FreeLinkedList | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804defc` | mbedTLS_SSL_MflCodeToLength | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804df30` | mbedTLS_SSL_ParseCertificateChain | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e08c` | mbedTLS_SSL_CrtReqNotAllowed | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e0a8` | mbedTLS_TLS_CertificateRequest_Parse | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e210` | mbedTLS_SSL_VerifyCertificateChain | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e3fc` | mbedTLS_SSL_ParseMaxFragLenExt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e434` | mbedTLS_TLS_ServerHello_ParseHeader | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e4f8` | mbedTLS_SSL_ParseExtendedMsExt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e528` | mbedTLS_SSL_ReadServerEcdhParams | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e56c` | mbedTLS_TLS_ServerHello_Parse | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e95c` | mbedTLS_TLS_ServerHelloDone_Parse | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804e9c8` | mbedTLS_TLS_ServerKeyExchange_Parse | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804ec18` | ssl_ParseSignHashAlg | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804ec9c` | ssl_ParseEcPointFormatsExt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804ed04` | ssl_PopulateCipherTransform | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804eee0` | ssl_DecryptVerifyRecord | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804efb0` | ssl_IsHandshakeActive | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804efc0` | ssl_CalcCertificateHash | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f024` | ssl_ParsePeerPublicKey | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f05c` | ssl_SetPrfFunction | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f088` | ssl_TransformUsesExplicitIv | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f09a` | ssl_GetExplicitIvLen | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f0b0` | ssl_UpdateHandshakeHash | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f0c8` | mbedTLS_SSL_UpdateChecksum_SHA256 | Handshake-Checksumme mit SHA-256 aktualisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f0e0` | mbedTLS_SSL_Check_ECDH_Param_Bitlen | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f100` | mbedTLS_SSL_Write_CertificateVerify | CertificateVerify-Nachricht schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f284` | mbedTLS_SSL_Parse_ServerKex | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804f574` | mbedTLS_SSL_Write_ClientKeyExchange | ClientKeyExchange-Nachricht schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f644` | mbedTLS_SSL_Write_MaxFragmentLengthExt | Max-Fragment-Length-Extension schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f6a4` | mbedTLS_SSL_Write_Real | Eigentliches Schreiben der SSL-Nutzdaten | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f714` | mbedTLS_SSL_Write_SignatureAlgorithmsExt | Signature-Algorithms-Extension schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f8b4` | mbedTLS_SSL_Write_SupportedPointFormatsExt | Supported-Point-Formats-Extension schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f910` | mbedTLS_Util_ReallocViaCallbacks | Speicher über konfigurierte Callback-Funktionen reallozieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804f948` | mbedTLS_SSL_TLS_PRF_Generic | Generische TLS-PRF-Implementierung | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0804fabc` | mbedTLS_SSL_TLS_PRF_SHA256 | TLS-PRF mit SHA-256 | Batch 20 | Ghidra (Batch 20, 2026-07-09) |

## mbedTLS — X.509 / ASN.1 / PEM / OID / PK (102)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08032048` | mbedTLS_ASN1_Get_MPI | ASN.1 Big-Integer lesen (8 Aufrufer in RSA-Key Parsing) | very high | Doku |
| `0x0803207c` | mbedTLS_ASN1_Sequence_Append | 16B Linked-List Nodes, ALLOC_FAILED=-106 | high | Doku |
| `0x080320ba` | mbedTLS_ASN1_Get_TaggedInt_Core | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0803e728` | mbedTLS_ASN1_Get_Alg | SEQUENCE → OID + optionale Parameter | high | Doku |
| `0x0803e7da` | mbedTLS_ASN1_Get_Bitstring | BIT STRING parsen (Tag 0x03), unused-bits extrahieren | high | Doku |
| `0x0803e83e` | mbedTLS_ASN1_Get_Bitstring_Null | BIT STRING mit 0 unused bits (byte-aligned) | high | Doku |
| `0x0803e884` | mbedTLS_ASN1_Get_Bool | BOOLEAN parsen (Tag 0x01), genau 1 Byte | high | Doku |
| `0x0803e8c8` | mbedTLS_ASN1_Get_Int | Wrapper: Get_Tag mit Tag=2 (INTEGER) | high | Doku |
| `0x0803e8de` | mbedTLS_ASN1_Get_Len | Core DER Length-Decoder (short/long form, 1-4 Bytes) | high | Doku |
| `0x0803e9dc` | mbedTLS_ASN1_Get_Tagged_Data | INTEGER Tag lesen + Raw-Bytes für MPI Import | medium | Doku |
| `0x0803ea14` | mbedTLS_ASN1_Get_Sequence_Of | SEQUENCE traversieren mit Tag-Filter (z.B. OID) | high | Doku |
| `0x0803ea50` | mbedTLS_ASN1_Get_Tag | Core Tag-Check + Get_Len (25 Aufrufer) | high | Doku |
| `0x0803ea88` | mbedTLS_ASN1_Traverse_Sequence_Of | SEQUENCE-Elemente iterieren mit Callback | high | Doku |
| `0x08044262` | mbedTLS_OID_Get_Md_Alg | OID → md_type Lookup | medium | Doku |
| `0x08044280` | mbedTLS_OID_Get_OID_By_Md | Reverse-Lookup: md_type → OID | medium | Doku |
| `0x080442b0` | mbedTLS_OID_Get_Pk_Alg | OID → pk_type Lookup | medium | Doku |
| `0x080442ce` | mbedTLS_OID_Get_Sig_Alg | OID → md_type + pk_type | high | Doku |
| `0x080442f6` | mbedTLS_OID_Get_Ec_Grp | OID → ecp_group_id | medium | Doku |
| `0x08044314` | mbedTLS_PEM_Free | PEM-Context freigeben + zeroize | high | Doku |
| `0x0804433a` | mbedTLS_PEM_Init | PEM-Context (12B) nullen | high | Doku |
| `0x08044344` | mbedTLS_PEM_Read_Buffer | PEM parsen, Base64 decode. **Encrypted Keys nicht unterstützt** | high | Doku |
| `0x080444d8` | mbedTLS_PK_Can_Do | Vtable 0x0c: Algorithmus-Support prüfen | high | Doku |
| `0x080444f4` | mbedTLS_PK_Check_Pair | Vtable 0x20: Pub/Priv Key Match | high | Doku |
| `0x08044550` | mbedTLS_PK_EC | EC-Context Accessor (Type 2/3/4) | high | Doku |
| `0x08044572` | mbedTLS_PK_Free | Vtable ctx_free + 8B zeroize (7 Aufrufer) | high | Doku |
| `0x08044592` | mbedTLS_PK_Get_Bitlen | Vtable 0x08: Key-Größe in Bits | high | Doku |
| `0x080445aa` | mbedTLS_PK_Get_Type | pk_type Enum aus pk_info[0] | high | Doku |
| `0x080445bc` | mbedTLS_PK_Info_From_Type | Type→pk_info: nur RSA(1), ECKEY(2), ECKEY_DH(3) | high | Doku |
| `0x080445e8` | mbedTLS_PK_Init | pk_info=0, pk_ctx=0 | high | Doku |
| `0x080445f4` | mbedTLS_PK_Parse_Key | Private Key parsen (RSA/EC PEM, PKCS8, DER) | high | Doku |
| `0x080448b4` | mbedTLS_PK_Parse_SubPubKey | SubjectPublicKeyInfo ASN.1 parsen | high | Doku |
| `0x08044a30` | mbedTLS_PK_RSA | RSA-Context Accessor (Type==1) | high | Doku |
| `0x08044a44` | mbedTLS_PK_Setup | pk_info setzen + ctx_alloc via Vtable | high | Doku |
| `0x08044a74` | mbedTLS_PK_Sign | Vtable 0x14: Signieren | high | Doku |
| `0x08044ad0` | mbedTLS_PK_Verify | Wrapper → Verify_Restartable(NULL) | high | Doku |
| `0x08044af8` | mbedTLS_PK_Verify_Ext | Extended Verify mit Algorithmus-Check | medium | Doku |
| `0x08044b5c` | mbedTLS_PK_Verify_Restartable | Core Verify via Vtable 0x10 | high | Doku |
| `0x08047f1c` | mbedTLS_X509_CRT_Free | Cert-Chain freigeben (0x154B Structs) | high | Doku |
| `0x08048008` | mbedTLS_X509_CRT_Init | memset(0, 0x154) | high | Doku |
| `0x08048018` | mbedTLS_X509_CRT_Parse | PEM vs DER Erkennung, Loop über PEM-Blöcke | high | Doku |
| `0x08048150` | mbedTLS_X509_CRT_Parse_DER | Wrapper → _Internal(flag=1, make_copy) | high | Doku |
| `0x0804816c` | mbedTLS_X509_CRT_Parse_DER_Internal | Core Chain Parser, 0x154B Cert-Nodes allozieren | high | Doku |
| `0x0804820c` | mbedTLS_X509_CRT_Parse_DER_NoCopy | Wrapper → _Internal(flag=0, kein Buffer-Kopie) | high | Doku |
| `0x08048228` | mbedTLS_X509_CRT_Verify | Wrapper → verify_restartable(NULL,NULL) | high | Doku |
| `0x08048254` | mbedTLS_X509_Get_Alg | ASN1_Get_Alg + X.509 Error Layer | high | Doku |
| `0x080482b8` | mbedTLS_X509_Get_Ext | Context-Specific Tag 0xA0, v3 Extensions | high | Doku |
| `0x08048370` | mbedTLS_X509_Get_Name | Distinguished Name → Linked-List (0x20B Nodes) | high | Doku |
| `0x08048460` | mbedTLS_X509_Get_Serial | Serial Number (Tag 0x82/0x02) | high | Doku |
| `0x0804850c` | mbedTLS_X509_Get_Sig | Signature Value via Bitstring_Null | high | Doku |
| `0x0804859c` | mbedTLS_X509_Get_Sig_Alg | OID → Sig Algorithm, Param-Validierung | high | Doku |
| `0x08048628` | mbedTLS_X509_Get_Time | UTCTime (0x17) / GeneralizedTime (0x18) | high | Doku |
| `0x080486dc` | mbedTLS_X509_Name_Parse_Der | DER Name → 40B Structs, Encoding-Type Bitmask | high | Doku |
| `0x08048748` | mbedTLS_X509_Check_Cert_Validity | Cert Validity Check (+0x90) | medium | Doku |
| `0x0804874e` | mbedTLS_X509_Check_Cert_Extensions | Extensions Check (+0xa8) | medium | Doku |
| `0x08048fc4` | mbedTLS_OID_SearchMdAlgTable | OID → MD Algorithm | high | Doku |
| `0x08049000` | mbedTLS_OID_SearchPkAlgTable | OID → PK Algorithm | high | Doku |
| `0x0804903c` | mbedTLS_OID_SearchSigAlgTable | OID → Sig Algorithm | high | Doku |
| `0x08049078` | mbedTLS_OID_SearchEcGrpTable | OID → EC Group | high | Doku |
| `0x080498d4` | mbedTLS_PK_Get_ECParams | EC Params OID aus ASN.1 (Tag 0x06) | high | Doku |
| `0x0804998c` | mbedTLS_PK_Get_ECPubKey | EC Public Key → ReadBinary + Check_PubKey | high | Doku |
| `0x080499c4` | mbedTLS_PK_Get_PkAlg | AlgorithmIdentifier → PK Algorithm | high | Doku |
| `0x08049a60` | mbedTLS_PK_Get_RSAPubKey | RSA Public Key (N,E) aus DER SEQUENCE | high | Doku |
| `0x08049ba8` | mbedTLS_PK_HashLenHelper | Hash-Länge vs MD Type validieren | high | Doku |
| `0x08049be8` | mbedTLS_PK_ParseKey_PKCS1_DER | PKCS#1 RSAPrivateKey (8x ASN1_Get_MPI) | high | Doku |
| `0x08049df8` | mbedTLS_PK_Parse_Key_PKCS8_Unencrypted_DER | PKCS#8 → RSA(type1) / EC(type2/3) | high | Doku |
| `0x08049f88` | mbedTLS_PK_Parse_Key_SEC1_DER | SEC1 EC Private Key (d scalar, optional pubkey) | high | Doku |
| `0x0804a1b8` | mbedTLS_PK_Use_ECParams | EC Params OID → Group ID setzen | high | Doku |
| `0x08052004` | mbedTLS_X509_CheckWildcard | Wildcard-Match für X.509-Hostnamen prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052078` | mbedTLS_X509_Crt_CheckCN | Common-Name des Zertifikats prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080520aa` | mbedTLS_X509_Crt_CheckSelfSignedLoop | Selbstsignatur-Schleife im Zertifikat erkennen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080520ec` | mbedTLS_X509_Crt_CheckParent | Prüfen ob Parent-Zertifikat passt | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805212a` | mbedTLS_X509_Crt_CheckSAN_DNSName | DNS-Name in Subject-Alternative-Name prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052152` | mbedTLS_X509_Crt_CheckSignature | Zertifikatssignatur prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080521c8` | mbedTLS_X509_Crt_FindParent | Parent-Zertifikat in Kette suchen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805222e` | mbedTLS_X509_Crt_FindParentIn | Parent-Zertifikat in gegebener Liste suchen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080522dc` | mbedTLS_X509_Crt_ApplyVerifyCallback | Anwendungsseitigen Verify-Callback aufrufen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052328` | mbedTLS_ASN1_X509_Parse | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080526e8` | mbedTLS_X509_Crt_VerifyChain | Zertifikatskette verifizieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052818` | mbedTLS_X509_Crt_VerifyChain_Init | Verifikationskontext für Zertifikatskette initialisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052838` | mbedTLS_X509_Crt_VerifyCN | Common-Name gegen erwarteten Hostnamen verifizieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080528c8` | mbedTLS_X509_Crt_VerifyRestartable | Unterbrechbare Zertifikatsverifikation | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052998` | mbedTLS_X509_DateIsValid | Gültigkeitsdatum des Zertifikats prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052a7c` | mbedTLS_X509_Get_AttrTypeValue | AttributeTypeAndValue aus ASN.1 lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052bf4` | mbedTLS_X509_Get_BasicConstraints | BasicConstraints-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052d10` | mbedTLS_X509_Get_CertificatePolicies | CertificatePolicies-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08052ee8` | mbedTLS_X509_Get_CrtExt | Zertifikats-Extensions lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805319c` | mbedTLS_X509_Get_Dates | Gültigkeits-Zeitraum (NotBefore/NotAfter) lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053244` | mbedTLS_X509_Get_ExtKeyUsage | ExtendedKeyUsage-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080532c0` | mbedTLS_X509_Get_KeyUsage | KeyUsage-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053364` | mbedTLS_X509_Get_NsCertType | Netscape-Cert-Type-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080533e8` | mbedTLS_X509_Get_OtherName | OtherName-Feld aus SAN lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080535a8` | mbedTLS_X509_Get_SubjectAltName | SubjectAltName-Extension lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805372c` | mbedTLS_X509_Get_UID | Issuer/Subject Unique-ID lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080537bc` | mbedTLS_X509_Get_Version | Zertifikats-Version lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053868` | mbedTLS_X509_NameCompare_CaseInsensitive | Namen ohne Groß-/Kleinschreibung vergleichen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080538b4` | mbedTLS_X509_Name_Compare | X.509-Namen vergleichen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805391c` | mbedTLS_ASN1_ParseDecimalDigits | Dezimalstellen aus ASN.1-Zeitstring parsen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053964` | mbedTLS_X509_ParseTime_Internal | Internes Parsen der ASN.1-Zeitfelder | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053a7c` | mbedTLS_X509_Profile_CheckPubkeyAlg | Public-Key-Algorithmus gegen X.509-Profil prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053b04` | mbedTLS_X509_Profile_CheckMdAlg | Hash-Algorithmus gegen X.509-Profil prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053b26` | mbedTLS_X509_Profile_CheckPkAlg | Signaturalgorithmus gegen X.509-Profil prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053b48` | mbedTLS_X509_Name_CompareAttribute | Einzelnes Namensattribut vergleichen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |

## mbedTLS — Symmetric Crypto / Hash / RNG (91)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08031d68` | mbedTLS_AES_Crypt_ECB_Wrapper | cipher_info_t Funktionspointer-Target | high | Doku |
| `0x08031d84` | mbedTLS_AES_Context_Alloc | 280B AES-Kontext allokieren + initialisieren | high | Doku |
| `0x08031da2` | mbedTLS_AES_Context_Free | AES-Kontext cleanup + free | high | Doku |
| `0x08031db4` | mbedTLS_AES_Gen_Tables | 574B S-Box/T-Tables in Software generieren (kein HW-AES!) | very high | Doku |
| `0x08032020` | mbedTLS_AES_Setkey_Dec_Wrapper | Decrypt-Key-Schedule Wrapper | high | Doku |
| `0x08032034` | mbedTLS_AES_Setkey_Enc_Wrapper | Encrypt-Key-Schedule Wrapper | high | Doku |
| `0x08032194` | mbedTLS_AES_CMAC_PRF_KDF | CMAC-basierte KDF, 3×16=48B Output | high | Doku |
| `0x08032e30` | mbedTLS_CTR_DRBG_Update | Counter inkrementieren, AES verschlüsseln, XOR | high | Doku |
| `0x08034a60` | mbedTLS_Entropy_Gather | Registrierte Entropy-Quellen abfragen | high | Doku |
| `0x08034b0e` | mbedTLS_Entropy_Update | SHA-256 Hash + Akkumulator-Update | high | Doku |
| `0x08034fd6` | GCM_Setup_Hash_Subkey | GF(2^128) Multiplikationstabellen aufbauen | high | Doku |
| `0x08035168` | GCM_GHASH_Multiply | 4-Bit Nibble Table-Lookup GF-Multiplikation (3 Aufrufer) | high | Doku |
| `0x0803e3a0` | mbedTLS_AES_Crypt_ECB | ECB Encrypt/Decrypt Dispatcher | high | Doku |
| `0x0803e3da` | mbedTLS_AES_Free | 0x118B AES-Kontext zeroizen + NULL-Check | high | Doku |
| `0x0803e3f0` | mbedTLS_AES_Init | 0x118B AES-Kontext nullen | high | Doku |
| `0x0803e404` | mbedTLS_AES_RoundKey_Offset | Round-Key Tabelle Basis-Offset berechnen | high | Doku |
| `0x0803e40c` | mbedTLS_AES_Setkey_Dec | Decrypt Key-Schedule + InvMixColumns | high | Doku |
| `0x0803e500` | mbedTLS_AES_Setkey_Enc | Encrypt Key-Schedule (128/192/256-Bit, RCON+S-Box) | high | Doku |
| `0x0803eb2a` | mbedTLS_Base64_Decode | Full Base64-Decoder (364B), Input-Validierung | high | Doku |
| `0x0803ec98` | mbedTLS_Calloc | Heap-Allocator via Funktionspointer (22 Aufrufer) | high | Doku |
| `0x0803ecb0` | mbedTLS_Cipher_AuthDecryptUpdate | Inner AEAD Decrypt via Vtable | high | Doku |
| `0x0803ed18` | mbedTLS_Cipher_AuthEncryptUpdate | Inner AEAD Encrypt via Vtable | high | Doku |
| `0x0803ed64` | mbedTLS_Cipher_AuthDecryptExt | Outer Wrapper mit Buffer-Size Validierung | high | Doku |
| `0x0803edcc` | mbedTLS_Cipher_AuthEncryptExt | Outer Wrapper mit Buffer-Size Validierung | high | Doku |
| `0x0803ee34` | mbedTLS_Cipher_Free | Vtable-Free + 0x38B Context zeroizen | high | Doku |
| `0x0803ee56` | mbedTLS_Cipher_GetType | Cipher-Type Enum aus cipher_info+1 | high | Doku |
| `0x0803ee6c` | mbedTLS_Cipher_InfoFromSuiteId | Tabellen-Lookup nach Suite-ID (8B Einträge) | high | Doku |
| `0x0803ee8c` | mbedTLS_Cipher_InfoFromValues | 3-Feld Match (cipher_id, key_bits, mode) | high | Doku |
| `0x0803eec4` | mbedTLS_Cipher_Init | Context memset(0, 0x38) | high | Doku |
| `0x0803eed8` | mbedTLS_Cipher_SetKey | Key via Vtable, Mode 3/4/5 → immer Encrypt | high | Doku |
| `0x0803ef5c` | mbedTLS_Cipher_Setup | Alloc + ctx_alloc via Vtable | high | Doku |
| `0x0803ef90` | mbedTLS_Cipher_ProcessBlock | ECB/Stream Dispatch via Vtable | high | Doku |
| `0x0803f054` | mbedTLS_CT_CountLeadingZeros | CLZ-Loop mit 0x80000000 Maske | high | Doku |
| `0x0803f072` | mbedTLS_Base64_DecodeChar | Constant-Time Char→6-Bit Wert (A-Z, a-z, 0-9, +, /) | high | Doku |
| `0x0803f0d6` | mbedTLS_CT_MemMoveToLeft | Constant-Time Linksverschiebung (RSA Unpadding) | high | Doku |
| `0x0803f134` | mbedTLS_CT_MemCompare | **SECURITY** Timing-safe Compare (XOR-OR, 4 Aufrufer) | high | Doku |
| `0x0803f18e` | mbedTLS_CT_MpiUintLt | Constant-Time "a < b" für MPI-Limbs | high | Doku |
| `0x0803f1a6` | mbedTLS_CT_IsNonZero | `(-x\|x)>>31` → -1 oder 0 | high | Doku |
| `0x0803f308` | mbedTLS_CT_UintEqual | `(x^y\|-(x^y))>>31^1` | high | Doku |
| `0x0803f31e` | mbedTLS_CT_UintLt | `(a-b)>>31` einfache Variante | high | Doku |
| `0x0803f326` | mbedTLS_ConstantTime_InRange | Branchless Range-Check für Base64 | high | Doku |
| `0x0803f33c` | mbedTLS_ConstantTime_Select | Conditional Select via IsNonZero-Maske | high | Doku |
| `0x0803f356` | mbedTLS_ConstantTime_IsNonZero | Zweite IsNonZero-Variante (12B) | high | Doku |
| `0x0803f362` | mbedTLS_CTR_DRBG_Free | AES_Free + 0x140B zeroize, reseed=10000 | high | Doku |
| `0x0803f38c` | mbedTLS_CTR_DRBG_Init | memset(0, 0x140), reseed_interval=10000 | high | Doku |
| `0x0803f3a8` | mbedTLS_CTR_DRBG_Random | Public Wrapper → Random_WithAdd(0,0) | high | Doku |
| `0x0803f3d0` | mbedTLS_CTR_DRBG_Random_WithAdd | Core DRBG: AES-256-ECB Counter, Auto-Reseed | high | Doku |
| `0x0803f4ce` | mbedTLS_CTR_DRBG_Reseed | Wrapper → Reseed_Internal(nonce=0) | high | Doku |
| `0x0803f4e4` | mbedTLS_CTR_DRBG_Reseed_Internal | Entropy via Callback, State-Update | high | Doku |
| `0x0803f5b8` | mbedTLS_CTR_DRBG_Seed | Seed: Entropy-Ptr + AES-256-Init + Reseed | high | Doku |
| `0x0804004c` | mbedTLS_Entropy_Add_Source | Source-Array (max 20, Stride 0x14) | high | Doku |
| `0x0804009e` | mbedTLS_Entropy_Free | SHA-Free + 400B zeroize | high | Doku |
| `0x080400ca` | mbedTLS_Entropy_Func | Main Entropy Gathering (0 Aufrufer → DRBG Ptr) | high | Doku |
| `0x08040206` | mbedTLS_Entropy_Init | State=0, SHA-Init | high | Doku |
| `0x08040226` | mbedTLS_Error_Add_PK | `return p1+p2` für PK-Modul | high | Doku |
| `0x0804022e` | mbedTLS_Error_Add_PEM | `return p1+p2` für PEM-Modul (7 Aufrufer) | high | Doku |
| `0x08040236` | mbedTLS_Error_Add_RSA | `return p1+p2` für RSA-Modul | high | Doku |
| `0x0804023e` | mbedTLS_Error_Add_X509 | `return p1+p2` für X.509 (8 Aufrufer) | high | Doku |
| `0x08040246` | mbedTLS_Error_Add_X509_Parse | `return p1+p2` für X.509 Parsing (12 Aufrufer) | high | Doku |
| `0x08040250` | mbedTLS_Platform_Free | Free via Funktionspointer (28 Aufrufer) | high | Doku |
| `0x08040264` | mbedTLS_GCM_Auth_Decrypt | Decrypt + Tag-Verify, zeroize bei Mismatch | high | Doku |
| `0x080402e8` | mbedTLS_GCM_Crypt_And_Tag | Orchestrator: Starts→Update→Finish | high | Doku |
| `0x0804035e` | mbedTLS_GCM_Finish | Final Tag: AAD/CT Bitlength + GHASH + J0 XOR | high | Doku |
| `0x080404e8` | mbedTLS_GCM_Free | cipher_free + 0x180B zeroize | high | Doku |
| `0x08040504` | mbedTLS_GCM_Init | memset(0, 0x180) — 384B Context | high | Doku |
| `0x08040518` | mbedTLS_GCM_SetKey | Cipher-Info + Key + GHASH-Subkey H berechnen | high | Doku |
| `0x08040598` | mbedTLS_GCM_Starts | IV-Processing (12B direct / GHASH) + AAD | high | Doku |
| `0x08040766` | mbedTLS_GCM_Update | Core CTR-Mode Loop + GHASH | high | Doku |
| `0x08041224` | SHA256_Internal_Transform | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080420e8` | mbedTLS_MD_Digest | One-Shot Hash (SHA-224/256 Dispatch) | high | Doku |
| `0x0804212c` | mbedTLS_MD_Finish | Hash finalisieren → Digest-Buffer | high | Doku |
| `0x08042160` | mbedTLS_MD_Free | MD-Context freigeben + zeroize | high | Doku |
| `0x080421b4` | mbedTLS_MD_GetSize | Digest-Größe aus md_info+5 | high | Doku |
| `0x080421c0` | mbedTLS_MD_HMAC_Finish | HMAC: Inner-Hash → opad → Outer-Hash | high | Doku |
| `0x08042238` | mbedTLS_MD_HMAC_Reset | HMAC Reset: State + ipad neu starten | high | Doku |
| `0x08042270` | mbedTLS_MD_HMAC_Starts | HMAC Key-Setup (0x36/0x5c ipad/opad) | high | Doku |
| `0x08042348` | mbedTLS_MD_HMAC_Update | Wrapper → MD_Update | high | Doku |
| `0x08042370` | mbedTLS_MD_InfoFromType | Type-Enum → md_info Struct (nur SHA-224/256) | high | Doku |
| `0x08042390` | mbedTLS_MD_Init | Context 3-Felder nullen | high | Doku |
| `0x0804239c` | mbedTLS_MD_Setup | Alloc 0x6c + optional HMAC-Pads | high | Doku |
| `0x0804240c` | mbedTLS_MD_Starts | Digest-Engine starten (Typ 5/6 Dispatch) | high | Doku |
| `0x08042444` | mbedTLS_MD_Update | Daten in Digest einbringen (5 Aufrufer) | high | Doku |
| `0x08044bf4` | mbedTLS_Platform_Zeroize | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080462ec` | mbedTLS_SHA256_Clone | memcpy 0x6c (Context-Klon) | high | Doku |
| `0x08046306` | mbedTLS_SHA256_Finish | Padding + 64-Bit Länge + Final Transform | high | Doku |
| `0x08046480` | mbedTLS_SHA256_Free | 0x6c zeroize | high | Doku |
| `0x08046494` | mbedTLS_SHA256_Init | memset(0, 0x6c) | high | Doku |
| `0x080464a6` | mbedTLS_SHA256_Digest | One-Shot: Init→Starts→Update→Finish→Free | high | Doku |
| `0x0804650c` | mbedTLS_SHA256_Starts | 8 IV-Konstanten laden (SHA-224 vs SHA-256) | high | Doku |
| `0x080465a8` | mbedTLS_SHA256_Update | 64B-Block Buffering + Transform | high | Doku |
| `0x08046646` | mbedTLS_Cipher_SetupNoop | Null-Cipher Stub (return 0) | medium | Doku |

## App-Crypto (non-mbedTLS: AES/RC4/Base64/ROT) (28)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080004d4` | RC4_KSA_Init | RC4-style Key Scheduling Algorithm (Identity-Fill + Fisher-Yates-Swap) | high | Doku |
| `0x080018f0` | AES_SubBytes | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0800192c` | AES128_ECB_Decrypt_Raw | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08001a2c` | AES128_ECB_Encrypt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08001b5c` | AES_InvMixColumns | AES InvMixColumns (Decrypt-Seite) | high | Doku |
| `0x08001bec` | AES_InvSBoxLookup | Inverse S-Box Byte-Lookup (Decrypt) | high | Doku |
| `0x08001bf8` | AES_InvShiftRows | Inverse ShiftRows (Decrypt) | high | Doku |
| `0x08001c58` | AES_InvSubBytes | Inverse S-Box auf gesamte State-Matrix (Decrypt) | high | Doku |
| `0x08001c90` | AES_KeyExpansion | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08001d6c` | AES_MixColumns_Fwd | MixColumns (Encrypt-Seite) | high | Doku |
| `0x08001dfc` | AES_GF256_Multiply | GF(2^8)-Multiplikation für MixColumns | high | Doku |
| `0x08001e90` | AES_RotWord | 32-Bit-Wort 8 Bit links rotieren (Key Expansion) | high | Doku |
| `0x08001e9c` | AES_SBoxLookup | S-Box Byte-Lookup (Encrypt) | high | Doku |
| `0x08001ea8` | AES_ShiftRows | ShiftRows (Encrypt) | high | Doku |
| `0x08001f00` | AES_SubBytes_Fwd | S-Box auf gesamte State-Matrix (Encrypt) | high | Doku |
| `0x08001f38` | AES_SubWord | S-Box auf 4 Bytes eines 32-Bit-Worts (Key Expansion) | high | Doku |
| `0x08001f6c` | AES_ByteSwap32 | 32-Bit Byte-Order umkehren (Key Expansion) | high | Doku |
| `0x08001f86` | AES_GF256_xtime | GF(2^8) xtime: Links-Shift mit XOR 0x1b | high | Doku |
| `0x08001f9a` | AES_GF256_Pow2 | Iteriert xtime N-mal für x^(2^N) in GF(2^8) | high | Doku |
| `0x08002118` | Base64_Decode | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0800221c` | Base64_Encode | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08003e10` | ROT_N_PrintableASCII | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0800b630` | KeyDerive_CopyAndROT | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08024b54` | TLS_Cert_Decrypt_All | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0802d4d0` | AES128_ECB_Decrypt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x080358b0` | Crypto_Validate_And_Dispatch | TLS Session validieren | medium | Doku |
| `0x0804090c` | AES_Encrypt_Block | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08040d98` | AES_Decrypt_Block | *(keine Beschreibung — s. Hinweise oben)* | - | — |

## llhttp — HTTP-Parser (Vendor-Lib) (96)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080366a8` | llhttp__AfterHeadersComplete | Body-Parsing-Modus bestimmen (chunked/content-length/EOF); verifiziert per Dekompilierung (256B, ruft message_needs_eof) | high | Re-Audit 2026-07-14 |
| `0x080367a8` | llhttp__AfterMessageComplete | Ruft ShouldKeepAlive, resettet dann finish-Byte @0x31 und Flags-Word @0x32 für nächste Message | high | Re-Audit 2026-07-14 |
| `0x080367c4` | llhttp__BeforeHeadersComplete | Setzt Upgrade-Kandidat-Byte @0x30 (Method==CONNECT bzw. Status 101/204-Sonderfall) | high | Re-Audit 2026-07-14 |
| `0x0803680a` | llhttp__ClearChunkedFlag | Bit 3 (F_CHUNKED) in Flags clearen | high | Doku |
| `0x08036818` | llhttp__IsContentLengthZero | 64-Bit Content-Length (@0x20/0x24) == 0 prüfen | high | Re-Audit 2026-07-14 |
| `0x08036834` | llhttp__IsMethodConnect | Method-Byte @0x29 == 0x05 (HTTP_CONNECT) prüfen | high | Re-Audit 2026-07-14 |
| `0x08036846` | llhttp__IsUpgrade | Upgrade-Kandidat-Byte @0x30 == 1 prüfen | high | Re-Audit 2026-07-14 |
| `0x08036856` | llhttp__GetHeaderState | Header-State Byte @0x2c lesen (nur Signatur/Größe 8B verifiziert, Timeout bei Volldekompilierung) | high | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x0803685e` | llhttp__GetHttpMajor | HTTP Major Version lesen | high | Doku |
| `0x08036866` | llhttp__GetHttpMinor | HTTP Minor Version lesen | high | Doku |
| `0x0803686e` | llhttp__LoadInitialMessageCompleted | Liest Byte @0x36 (message_completed-Flag) | high | Re-Audit 2026-07-14 |
| `0x08036876` | llhttp__LoadMethod | Liest Byte @0x29 (Method-Feld) | high | Re-Audit 2026-07-14 |
| `0x0803687e` | llhttp__LoadType | Liest Byte @0x28 (Type: Request/Response) | high | Re-Audit 2026-07-14 |
| `0x08036886` | llhttp__MulAddContentLengthHex | 64-Bit Content-Length ×16 + Hex-Ziffer, mit Overflow-Check | high | Re-Audit 2026-07-14 |
| `0x0803690c` | llhttp__MulAddContentLength | 64-Bit Content-Length ×10 + Dezimalziffer, mit Overflow-Check | high | Re-Audit 2026-07-14 |
| `0x08036998` | llhttp__MulAddStatusCode | 16-Bit Status-Code ×10 + Ziffer, mit Overflow-Check | high | Re-Audit 2026-07-14 |
| `0x080369e0` | llhttp__OrFlags_Trailing | Bit 0x80 in Flags @0x32 setzen (F_TRAILING) | high | Re-Audit 2026-07-14 |
| `0x080369ee` | llhttp__OrFlags_SkipBody | Bit 0x40 in Flags @0x32 setzen (F_SKIPBODY) | high | Re-Audit 2026-07-14 |
| `0x080369fc` | llhttp__OrFlags_ContentLength | Bit 0x20 in Flags @0x32 setzen (F_CONTENT_LENGTH) | high | Re-Audit 2026-07-14 |
| `0x08036a0a` | llhttp__OrFlags_TransferEncoding | Bit 0x200 in Flags @0x32 setzen (F_TRANSFER_ENCODING) | high | Re-Audit 2026-07-14 |
| `0x08036a18` | llhttp__OrFlags_Upgrade | Bit 0x10 in Flags @0x32 setzen (F_UPGRADE) | high | Re-Audit 2026-07-14 |
| `0x08036a26` | llhttp__internal__c_or_flags | Bit 0x01 in Flags @0x32 setzen (F_CHUNKED) | high | Re-Audit 2026-07-14 |
| `0x08036a34` | llhttp__internal__c_or_flags_1 | Bit 0x02 in Flags @0x32 setzen (F_CONNECTION_KEEP_ALIVE) | high | Re-Audit 2026-07-14 |
| `0x08036a42` | llhttp__internal__c_or_flags_2 | Bit 0x04 in Flags @0x32 setzen (F_CONNECTION_CLOSE) | high | Re-Audit 2026-07-14 |
| `0x08036a50` | llhttp__internal__c_or_flags_3 | Bit 0x08 in Flags @0x32 setzen (F_CONNECTION_UPGRADE) | high | Re-Audit 2026-07-14 |
| `0x08036a5e` | llhttp__internal__c_store_header_state | Byte @0x2c = Parameter (header_state setzen) | high | Re-Audit 2026-07-14 |
| `0x08036a6a` | llhttp__internal__c_store_http_major | Byte @0x2a = Parameter (http_major setzen) | high | Re-Audit 2026-07-14 |
| `0x08036a76` | llhttp__internal__c_store_http_minor | Byte @0x2b = Parameter (http_minor setzen) | high | Re-Audit 2026-07-14 |
| `0x08036a82` | llhttp__internal__c_store_method | Byte @0x29 = Parameter (method setzen) | high | Re-Audit 2026-07-14 |
| `0x08036a8e` | llhttp__internal__c_test_flags_Off32 | Bit 7 (MSB) von Flags-Byte @0x32 testen | high | Re-Audit 2026-07-14 |
| `0x08036a9a` | llhttp__internal__c_test_flags_1_Off32 | Bit 5 (maskiert 0x3f) von Flags @0x32 testen | high | Re-Audit 2026-07-14 |
| `0x08036aa6` | llhttp__internal__c_test_flags_2_Off32 | Bit 3 (maskiert 0xf) von Flags @0x32 testen | high | Re-Audit 2026-07-14 |
| `0x08036ab2` | llhttp__internal__c_test_flags_3_Off32 | Bit 9 (16-Bit, maskiert 0x3ff) von Flags @0x32 testen | high | Re-Audit 2026-07-14 |
| `0x08036abc` | llhttp__internal__c_load_upgrade | Vermutlich Upgrade-Feld lesen — Ghidra-Timeout bei Volldekompilierung, nur Signatur/Größe (12B) verifiziert, Name/Muster passt zu Nachbarfunktionen | medium | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x08036ac8` | llhttp__internal__c_test_lenient_flags | Vermutlich Lenient-Flags-Bit testen — Ghidra-Timeout bei Volldekompilierung, nur Signatur/Größe (10B) verifiziert, Name/Muster passt zu Nachbarfunktionen | medium | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x08036ad2` | llhttp__internal__c_test_flags_2_Off2e | Bit 2 (maskiert 7) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036ade` | llhttp__internal__c_test_flags_1_Off2e | Bit 3 (maskiert 0xf) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036aea` | llhttp__internal__c_test_flags_6 | Bit 1 (maskiert 3) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036af6` | llhttp__internal__c_test_flags_3_Off2e | Bit 4 (maskiert 0x1f) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036b02` | llhttp__internal__c_test_flags_5 | Bit 5 (maskiert 0x3f) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036b0e` | llhttp__internal__c_test_lenient_flags_1 | Bit 9 (16-Bit, maskiert 0x3ff) von Flags @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036b18` | llhttp__internal__c_test_flags_Off2e | Bit 7 (MSB) von Flags-Byte @0x2e testen | high | Re-Audit 2026-07-14 |
| `0x08036b24` | llhttp__internal__c_test_flags_4 | Vermutlich Bit-Test auf Flags @0x2e — Ghidra-Timeout bei Volldekompilierung, nur Signatur/Größe (12B) verifiziert, Name/Muster passt zu Nachbarfunktionen | medium | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x08036b30` | llhttp__internal__c_update_content_length | 64-Bit Content-Length @0x20/0x24 auf 0 zurücksetzen | high | Re-Audit 2026-07-14 |
| `0x08036b3e` | llhttp__internal__c_update_finish | Byte @0x31 = 2 (finish-State) | high | Re-Audit 2026-07-14 |
| `0x08036b4a` | llhttp__internal__c_update_finish_safe | Byte @0x31 = 0 (finish-State zurücksetzen) | high | Re-Audit 2026-07-14 |
| `0x08036b54` | llhttp__internal__c_update_finish_1 | Byte @0x31 = 1 (finish-State) | high | Re-Audit 2026-07-14 |
| `0x08036b60` | llhttp__internal__c_update_header_state | Byte @0x2c = 1 (header_state) | high | Re-Audit 2026-07-14 |
| `0x08036b6c` | llhttp_ClearHeaderState | Vermutlich Byte @0x2c = 0 — Ghidra-Timeout bei Volldekompilierung, nur Signatur/Größe (10B) verifiziert, passt zu Set/Clear-Familie @0x2c | medium | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x08036b76` | llhttp_SetHeaderState_ConnClose | Byte @0x2c = 6 (header_state = connection: close) | high | Re-Audit 2026-07-14 |
| `0x08036b82` | llhttp_SetHeaderState_ConnKeepAlive | Byte @0x2c = 5 (header_state = connection: keep-alive) | high | Re-Audit 2026-07-14 |
| `0x08036b8e` | llhttp_SetHeaderState_ConnUpgrade | Byte @0x2c = 7 (header_state = connection: upgrade) | high | Re-Audit 2026-07-14 |
| `0x08036b9a` | llhttp_SetHeaderState_TEChunked | Byte @0x2c = 8 (header_state = transfer-encoding: chunked) | high | Re-Audit 2026-07-14 |
| `0x08036ba6` | llhttp_ClearHttpMajor | Byte @0x2a = 0 (http_major zurücksetzen, HTTP/0.9-Sonderfall) | high | Re-Audit 2026-07-14 |
| `0x08036bb0` | llhttp_SetHttpMinor9 | Byte @0x2b = 9 (http_minor=9, HTTP/0.9 Simple-Request-Sonderfall) | high | Re-Audit 2026-07-14 |
| `0x08036bbc` | llhttp_SetInitialMessageCompleted | Byte @0x36 = 1 (message_completed-Flag setzen) | high | Re-Audit 2026-07-14 |
| `0x08036bc8` | llhttp_ClearStatusCode | Wort @0x34 = 0 (status_code zurücksetzen) | high | Re-Audit 2026-07-14 |
| `0x08036bd0` | llhttp_SetTypeRequest | Byte @0x28 = 1 (type = HTTP_REQUEST) | high | Re-Audit 2026-07-14 |
| `0x08036bdc` | llhttp_SetTypeResponse | Byte @0x28 = 2 (type = HTTP_RESPONSE) | high | Re-Audit 2026-07-14 |
| `0x08036be8` | llhttp__internal__c_or_flags_4 | Byte @0x30 = 1 (Skip-Body-Kontext-Flag) — **Re-Audit-Hinweis:** direkte Zuweisung statt Bit-OR, trotz Namensfamilie keine echte OR-Operation (Feld hält nur dieses eine Flag) | high | Re-Audit 2026-07-14 |
| `0x08036bf4` | llhttp_Parser_Execute | Haupt-State-Machine des generierten llhttp-Parsers (22.470 Bytes!) — dispatcht per State-Byte, ruft alle internen Helfer (c_*, Or/Test/Store/Update-Flags) sowie sämtliche Settings-Callbacks auf | high | Re-Audit 2026-07-14 |
| `0x0803d538` | llhttp_Parse_Wrapper | Äußerer Wrapper: cached Fehlerstatus (@0xc), ruft Parser_Execute, verwaltet Pause/Reexec via State-Handler-Funktionszeiger @0x08 (entspricht llhttp__internal_execute) | high | Re-Audit 2026-07-14 |
| `0x0803d588` | llhttp_ParserInternalInit | 0x40B Struct nullen (memclr-Intrinsic), State 0xec setzen — verifiziert, Beschreibung korrekt | high | Re-Audit 2026-07-14 |
| `0x0803d59c` | llhttp_InvokeCallback_OnBody | settings+0x28, Span (übergibt Länge als param_3-param_2) | high | Re-Audit 2026-07-14 |
| `0x0803d5fc` | llhttp_InvokeCallback_OnChunkComplete | settings+0x54, Lifecycle  — **korrigiert 2026-07-09**, s. Batch 18; per Dekompilierung erneut verifiziert | high | Re-Audit 2026-07-14 |
| `0x0803d628` | llhttp_InvokeCallback_OnChunkExtName | settings+0x1c, Span | high | Doku |
| `0x0803d698` | llhttp_InvokeCallback_OnChunkExtNameComplete | settings+0x48, Lifecycle  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0803d6c4` | llhttp_InvokeCallback_OnChunkExtValue | settings+0x20, Span | high | Doku |
| `0x0803d734` | llhttp_InvokeCallback_OnChunkExtValueComplete | settings+0x4c, Lifecycle  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0803d75e` | llhttp_InvokeCallback_OnChunkHeader | settings+0x50, Lifecycle  — **korrigiert 2026-07-09**, s. Batch 18; per Dekompilierung erneut verifiziert | high | Re-Audit 2026-07-14 |
| `0x0803d788` | llhttp_InvokeCallback_OnHeaderField | settings+0x14, Span | high | Doku |
| `0x0803d7f0` | llhttp_InvokeCallback_OnHeaderFieldComplete | settings+0x40, Lifecycle; per Dekompilierung verifiziert | high | Re-Audit 2026-07-14 |
| `0x0803d81c` | llhttp__on_header_value | settings+0x18, Span | high | Doku |
| `0x0803d884` | llhttp__on_header_value_complete | settings+0x44, Lifecycle | high | Doku |
| `0x0803d8ae` | llhttp__on_headers_complete | settings+0x24, Lifecycle | high | Re-Audit 2026-07-14 |
| `0x0803d8d8` | llhttp__on_message_begin | settings+0x00, Lifecycle | high | Re-Audit 2026-07-14 |
| `0x0803d902` | llhttp__on_message_complete | settings+0x2c, Lifecycle | high | Doku |
| `0x0803d92c` | llhttp__on_method | settings+0x0c, Span | high | Doku |
| `0x0803d990` | llhttp__on_method_complete | settings+0x38, Lifecycle | high | Doku |
| `0x0803d9ba` | llhttp_InvokeCallback_OnReset | settings+0x58, Lifecycle  — **korrigiert 2026-07-09**, s. Batch 18; per Dekompilierung erneut verifiziert | high | Re-Audit 2026-07-14 |
| `0x0803d9e4` | llhttp__on_status | settings+0x08, Span | high | Doku |
| `0x0803da48` | llhttp__on_status_complete | settings+0x34, Lifecycle | high | Doku |
| `0x0803da74` | llhttp__InvokeOnUrl | settings+0x10, Span | high | Doku |
| `0x0803dad4` | llhttp__InvokeOnUrlComplete | settings+0x30, Lifecycle | high | Doku |
| `0x0803db00` | llhttp__InvokeOnVersion | settings+0x04, Span | high | Doku |
| `0x0803db64` | llhttp__InvokeOnVersionComplete | settings+0x3c, Lifecycle | high | Doku |
| `0x0803db90` | llhttp_errno_name | HPE_* Error-Codes (0x00-0x23) → Strings, 440B Switch | high | Re-Audit 2026-07-14 |
| `0x0803df88` | llhttp_execute | Public API: parser+data+len → Parse_Wrapper | high | Re-Audit 2026-07-14 |
| `0x0803dfa2` | llhttp_init | Ruft ParserInternalInit, setzt type @0x28 und settings-Pointer @0x38 | high | Re-Audit 2026-07-14 |
| `0x0803dfb8` | llhttp_message_needs_eof | Body-Ende bei EOF? (1xx/204/304, content-length, chunked) | high | Re-Audit 2026-07-14 |
| `0x0803e016` | llhttp_set_error_reason | Error-String in parser+0x10 speichern (9 Aufrufer, alle bestätigt) | high | Re-Audit 2026-07-14 |
| `0x0803e01a` | llhttp_settings_init | settings memset(0, 0x5c) — 23 Callback-Pointer | high | Re-Audit 2026-07-14 |
| `0x0803e028` | llhttp_ShouldKeepAlive | HTTP Version + Connection-Flags → Keep-Alive?; ruft message_needs_eof | high | Re-Audit 2026-07-14 |
| `0x0803e068` | llhttp_MatchSequence | Case-sensitiver Token-Matcher (96B, nur Signatur/Größe verifiziert, Timeout bei Volldekompilierung) | high | Re-Audit 2026-07-14 (Teilverifikation) |
| `0x0803e0c8` | llhttp_MatchSequenceToLower | Case-insensitiv (mit A-Z Range-Check) | high | Doku |
| `0x0803e14a` | llhttp_MatchSequenceToLowerUnsafe | Case-insensitiv (ohne Range-Check) | high | Doku |

## HTTP/HTTPS — App-Layer (19)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0800bcc4` | Quectel_HTTP_AT_SendAndVerify | Name korrigiert (2026-07-15, vormals HTTP_POST_Request): generischer Quectel-AT-Executor, keine POST-spezifische Logik: sendet Kommando (param_1) per UART, wartet auf Notify (max. 400 Ticks) + Delay (param_4), prüft Antwortpuffer auf Substring(s) param_2/param_3. Wird für HTTP-POST (Cloud-Reporting), HTTP-GET (Quectel_HTTP_GET_Request), HTTP-READ (Quectel_HTTP_ReadResponse) UND SSL-Config (Quectel_HTTP_Config_SSLCtxId) gleichermaßen verwendet | medium | Re-Audit 2026-07-15 |
| `0x0800dac8` | HTTP_Cloud_Reporting_Dispatcher | Cloud-Reporting-Dispatcher: liest Server-Typ aus EEPROM 0x441 (0-4, versch. Cloud-Subdomains), param_1 wählt Report-Typ per Switch (1=volle Telemetrie, 2=Kurzstatus, 3-7 weitere Report-Typen), baut JSON via Cloud_Telemetry_JSON_Builder (=generischer sprintf-Wrapper), sendet über HTTP_POST_Request (7 Aufrufstellen) | high | Re-Audit 2026-07-15 |
| `0x08013678` | HTTP_URL_ExtractPath | Pfad-Anteil aus URL extrahieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x080139ac` | Meter_ExtractValue_ByKey | Meter-Wert anhand Schlüssel aus Antwort extrahieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x080143c4` | HTTP_ParseContentLengthHeader | Content-Length Header parsen | Batch 20 | Re-Audit 2026-07-15 |
| `0x08014458` | HTTP_FindHeaderBodySeparator | Trennstelle zwischen HTTP-Header und Body finden | Batch 20 | Re-Audit 2026-07-15 |
| `0x080148f8` | HTTP_EcoTracker_ParsePower | EcoTracker-Leistungswert aus HTTP-Antwort parsen | Batch 20 | Re-Audit 2026-07-15 |
| `0x080149f8` | HTTP_Economy_TOU_Parser | Parst Economy/Time-of-Use HTTP-Antwort (Strompreis-Zeitfenster): extrahiert Werte via strstr/atoi_u16 aus Antwortstring, Fehlerzähler bei "ERROR"-String (nach 4 Fehlversuchen Reset+Skip) | high | Re-Audit 2026-07-15 |
| `0x08014dc0` | HTTPS_POST_Request | Vollständiger CH395/Ethernet-TCP-HTTP(S)-Request (eigenständiger Pfad zum Quectel-AT-basierten HTTP_POST_Request @0x0800bcc4): extrahiert Pfad aus URL, baut Request-Buffer, öffnet TCP-Socket Port 80 über CH395, sendet Request per SPI, empfängt Antwort via HTTPS_POST_ReceiveResponseData, optional llhttp-Response-Parse | high | Re-Audit 2026-07-15 |
| `0x080152a0` | HTTP_P1Meter_ParseActivePower | P1-Meter Wirkleistung aus HTTP-Antwort parsen | Batch 20 | Re-Audit 2026-07-15 |
| `0x08015474` | HTTPS_POST_ReceiveResponseData | HTTPS-POST Antwortdaten empfangen | Batch 20 | Re-Audit 2026-07-15 |
| `0x080155d0` | HTTP_ParseUploadDecryptResultFlag | Entschlüsselungs-Ergebnis-Flag beim Upload parsen | Batch 20 | Re-Audit 2026-07-15 |
| `0x08015668` | HTTP_StormOneMeter_ParseData | StormOne-Meter Daten aus HTTP-Antwort parsen | Batch 20 | Re-Audit 2026-07-15 |
| `0x08016444` | HTTP_ParseServerDateTime_UpdateRTC | Server-Datum/Zeit parsen und RTC aktualisieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x08016580` | HTTP_Economy_TOU_PeriodicHandler | Periodischer Handler für Economy/Time-of-Use HTTP-Daten | Batch 20 | Re-Audit 2026-07-15 |
| `0x08017010` | HTTP_ExternalMeter_TimeoutMonitor | Timeout-Überwachung für externen HTTP-Meter | Batch 20 | Re-Audit 2026-07-15 |
| `0x08026644` | HTTP_BuildRequestBuffer | HTTP-Request-Buffer aufbauen | high | Re-Audit 2026-07-15 |
| `0x08026930` | HTTP_Response_Parse | Initialisiert llhttp-Parser (Response-Modus) und parst empfangene HTTP-Antwort via llhttp_execute; loggt llhttp-Fehlername bei Parse-Fehler. Einziger Aufrufer: HTTPS_POST_Request | high | Re-Audit 2026-07-15 |
| `0x08026344` | DeviceInfo_BuildStatusString | Baut formatierten Geräte-Status-String (Seriennummer, FW-Version, Herstelldatum) inkl. XOR-Checksumme für Telemetrie (Ethernet/Modem) | high | Re-Audit 2026-07-14 |

## cJSON — Vendor-Lib (30)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08013e04` | JSON_ExtractFieldValue | Eigenständiger, NICHT zu cJSON gehörender Textscanner: sucht Feldname per strstr im rohen JSON-Text, kopiert Wert bis `,`/`}`/`"`/`\0` per strncpy in Ausgabepuffer, keine echte Verschachtelungs-/Escape-Behandlung, Sonderfall Feld `device_id` (Offset +10); nur für HTTP_StormOneMeter_ParseData | high | Re-Audit 2026-07-14 |
| `0x0802a1a8` | cJSON_CreateBool | Erzeugt Bool-Knoten mit 2 Parametern (Name-String, Bool-Wert); Name wird per cJSON_strdup dupliziert; Type=4 (false) / 0x104 (true) | high | Re-Audit 2026-07-14 |
| `0x0802a1f4` | cJSON_CreateDouble | Erzeugt Double-Knoten mit 3 Parametern (val_lo, val_hi als 64-Bit via CONCAT44, Name-String); Name strdup't; Type=8 | high | Re-Audit 2026-07-14 |
| `0x0802a248` | cJSON_CreateInt | Integer-Node: Type 0x208, 10 Aufrufer | high | Doku |
| `0x0802a290` | cJSON_AddItemToObject | Named-Item mit Child-Node anhängen, 11 Aufrufer | high | Doku |
| `0x0802a32c` | cJSON_NewObject | Wrapper: cJSON_New_Item(0x40, 0), echte Object-Erzeugung | high | Doku |
| `0x0802a338` | cJSON_CreateString | Erzeugt String-Knoten mit 2 Parametern (Name, Value); beide separat per cJSON_strdup dupliziert; Type=0x10 | high | Re-Audit 2026-07-14 |
| `0x0802a3ac` | cJSON_Delete | Rekursive Freigabe eines cJSON-Knotens: bei Array/Object (0x20/0x40) rekursiver Delete der Kindliste, bei String (0x10) Freigabe des Value-Strings, bei Name-Flag (0x400) Freigabe des Name-Strings, danach Freigabe des Knotens selbst — entspricht cJSON_Delete(cJSON*) | high | Re-Audit 2026-07-14 |
| `0x0802a420` | cJSON_FindChildByName | Child via strcmp in Linked-List suchen | high | Doku |
| `0x0802a46c` | cJSON_GetObjectItem | Sucht Kind-Knoten per Name im Object via cJSON_FindChildByName. Dekompiliert mit 4 Parametern; param_3/param_4 realisieren eine potenzielle Pfad-Verkettung, werden aber von allen bekannten Aufrufstellen ungenutzt gelassen (=0) — effektiv identisch zu cJSON_GetObjectItem(object,name) | high | Re-Audit 2026-07-14 |
| `0x0802a4be` | cJSON_GetValue | Interner Low-Level-Accessor ohne Public-API-Pendant: liefert Pointer auf das value/child-Feld eines Knotens, berücksichtigt Name-Flag (0x400) für Offset-Verschiebung; liefert 0 bei NULL/True/False-Typen. Von praktisch allen anderen cJSON_*-Funktionen zum Lesen/Schreiben genutzt | high | Re-Audit 2026-07-14 |
| `0x0802a4ec` | cJSON_InitHooks | Initialisiert 3 globale Funktionspointer direkt als Parameter (malloc_fn, free_fn, realloc_fn) statt über einen cJSON_Hooks-Struct-Pointer wie im Original; 3. Parameter optional (0=Default behalten) | high | Re-Audit 2026-07-14 |
| `0x0802a520` | cJSON_AddItemToArray | Item an Array/Object anhängen, 93 Aufrufer (!) | high | Doku |
| `0x0802a598` | cJSON_New_Item | Interner Knoten-Allokator mit 2 Parametern (Type-Bitmask, optionaler Name-Pointer). Größe wird aus Type-Bitmask berechnet; ist Name≠0, wird 0x400-Flag gesetzt, Größe +4 Byte, Name direkt im Knoten abgelegt | high | Re-Audit 2026-07-14 |
| `0x0802a610` | cJSON_Parse_Array | '[' Parser, rekursiv, max Tiefe 30000 | high | Doku |
| `0x0802a7b2` | cJSON_ParseHex4 | 4 Hex-Chars → uint16 für \uXXXX Escapes | high | Doku |
| `0x0802a874` | cJSON_Parse_Number | Rekursiver Number-Parser: manuelles Parsen von Vorzeichen/Ganzzahl/Nachkomma/Exponent (kein strtod), Akkumulation via fp64-Helper; erzeugt Integer-Knoten (0x208) oder Double-Knoten (8) je nach Wertebereich/Nachkommastellen | high | Re-Audit 2026-07-14 |
| `0x0802ab9c` | cJSON_Parse_Object | '{' Parser, Key-Value-Paare, rekursiv | high | Doku |
| `0x0802adfc` | cJSON_Parse | Einstiegspunkt: überspringt Whitespace, ruft cJSON_Parse_Value auf, prüft optional auf Trailing-Garbage/NUL-Terminierung. 4 Parameter (Text, Länge, require-null-terminated, optionaler return-parse-end) — funktional näher an cJSON_ParseWithOpts+Länge als am 1-Parameter-Original; einziger Aufrufer übergibt nur 3 Argumente | high | Re-Audit 2026-07-14 |
| `0x0802aec8` | cJSON_Parse_String | '"' Parser, String extrahieren und Node anlegen | high | Doku |
| `0x0802af10` | cJSON_Parse_Value | Top-Level Dispatcher: String/Object/Array/Number/Literal | high | Doku |
| `0x0802b038` | cJSON_PrintBuffered | Top-Level Serializer: Buffer allok, PrintValue, null-terminieren | high | Doku |
| `0x0802b0cc` | cJSON_PrintArray | Array serialisieren mit Komma-Trennung | high | Doku |
| `0x0802b254` | cJSON_PrintNumber | Number formatieren (adaptive Precision, trailing Zeros strip) | high | Doku |
| `0x0802b410` | cJSON_PrintObject | Object serialisieren mit Key:Value Paaren | high | Doku |
| `0x0802b580` | cJSON_PrintValue | Zentraler Type-Dispatcher für Serialisierung | high | Doku |
| `0x0802b6a0` | cJSON_strdup | strlen+malloc+memcpy String-Duplikation | high | Doku |
| `0x08034bd0` | cJSON_EnsureBuffer | Print-Buffer Kapazität prüfen/reallokieren (18 Aufrufer) | high | Doku |
| `0x08049310` | cJSON_ParseStringValue | JSON String Parser mit Escape + UTF-16 Surrogate Pairs | high | Doku |
| `0x0804a2e0` | cJSON_PrintStringPtr | JSON String Printer mit Escape + \uXXXX | high | Doku |

## MQTT — Client/Protokoll/Payload (102)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080058e0` | MQTT_Topic_Builder | MQTT-Topic-String aus Parametern zusammenbauen | high | Re-Audit 2026-07-14 |
| `0x0800be50` | MQTT_Telemetry_EnergyCounter_Update | Energiezähler in MQTT-Telemetrie aktualisieren | Batch 20 | Re-Audit 2026-07-14 |
| `0x080109d8` | Config_ScheduleEntries_ClampPower800W | **Namens-Verdacht (Re-Audit 2026-07-14):** Code hat NICHTS mit Subscribe zu tun — klemmt 10 Schedule-Slots (Power-Feld, Offset+2) auf max. 800 und ruft Config_Notify_Change() je geänderten Slot; aufgerufen aus BLE_Recv_Cmd_Dispatcher und MQTT_JSON_RPC_Dispatcher direkt nach EEPROM_Write(0x90,...) als Config-Postprocessing. Umbenennungsvorschlag s. Session-Ergebnis (nicht angewendet, Duplikat-Check ausstehend) | medium | Re-Audit 2026-07-14 |
| `0x08010a28` | MQTT_DeviceID_Encrypt | Verschlüsselt Device-ID (max 33B) mit sekundärem AES-128-ECB-Key (SRAM-Key, ROT(-9)) für MQTT-Topic-Konstruktion; Ausgabe als Hex-String, Aufrufer: BLE_MQTT_Command_Execute, MQTT_Config_VID_Init | high | Re-Audit 2026-07-14 |
| `0x080124a4` | MQTT_Telemetry_Struct_Builder | Sammelt aktuellen Gerätezustand (Energiezähler ÷10, WorkMode, Spannung/Frequenz/Leistung, Pack-SOC/Zellspannungen) in flaches Telemetrie-Struct für Cloud/HTTP-Reporting; Aufrufer: HTTP_Economy_TOU_PeriodicHandler | high | Re-Audit 2026-07-14 |
| `0x080127c4` | MQTT_JSON_Payload_EnsureBracePrefix | Sicherstellen dass JSON-Payload mit '{' beginnt | Batch 20 | Re-Audit 2026-07-14 |
| `0x08012984` | MQTT_TLS_Context_Reset | Reset des mbedTLS/SSL-Kontexts für MQTT: SSL_Free, Config_Free, 2× X509_CRT_Free, PK_Free, CTR_DRBG_Free, Entropy_Free + memset(0x16ec); Aufrufer: CH395_MQTT_Socket_Close_And_TLS_Reset, mbedTLS_SSL_Connection_Init | high | Re-Audit 2026-07-14 |
| `0x08013fa4` | MQTT_Config_Command_Handler | Parst JSON-Cloud-Config-Payload: work_mode, ble_status (adv enable), local_api_en, api_port, version_num u.a. über MQTT_Config_Extract*-Helfer, ruft bei work_mode==1 MQTT_Config_ParseScheduleEntries | high | Re-Audit 2026-07-14 |
| `0x080180c8` | MQTT_Connect_And_Subscribe | MQTT Connect-Sequenz: Topics, Broker, Subscribe | high | Re-Audit 2026-07-14 |
| `0x080187fc` | MQTT_Session_Init | Top-Level: DNS→Socket→TLS→Connect→Subscribe | high | Re-Audit 2026-07-14 |
| `0x080197a4` | MQTT_JSON_AddTypedValue | cJSON Add Number/String Dispatch (10 Callers) | high | Re-Audit 2026-07-14 |
| `0x080197f4` | MQTT_SetWorkMode | EEPROM 0x301: Auto=0, AI=5 | high | Re-Audit 2026-07-14 |
| `0x08019860` | MQTT_ParseTypedField | Payload-Feld nach Typ extrahieren (8 Callers) | high | Re-Audit 2026-07-14 |
| `0x08019898` | MQTT_BuildBatteryDataResponse | "Bat_data": SOC, Temp, Capacity, Flags | high | Re-Audit 2026-07-14 |
| `0x08019a48` | MQTT_BuildBleDataResponse | "Ble_data": State + MAC | high | Re-Audit 2026-07-14 |
| `0x08019b2c` | MQTT_JSON_CreateResponseEnvelope | JSON-RPC Envelope: Root + ID + Result (11 Callers) | high | Re-Audit 2026-07-14 |
| `0x08019b90` | MQTT_JSON_SerializeAndSend | cJSON→String→MQTT Publish→Free (11 Callers) | high | Re-Audit 2026-07-14 |
| `0x08019c00` | MQTT_BuildDeviceDataResponse | "Device_data": Name, MAC, WiFi | high | Re-Audit 2026-07-14 |
| `0x08019d2c` | MQTT_BuildEnergyMeterResponse | "Em_data": CT-State, Phase-Power, Energy | high | Re-Audit 2026-07-14 |
| `0x08019e9c` | MQTT_BuildErrorResponse | JSON-RPC Error (42 Callers!) | high | Re-Audit 2026-07-14 |
| `0x08019f64` | MQTT_BuildEsModeDataResponse | "Es_mode_data": On/Offgrid, SOC, CT | high | Re-Audit 2026-07-14 |
| `0x0801a1b8` | MQTT_BuildEsDataResponse | "Es_data": SOC, PV, Grid, Load Energy | high | Re-Audit 2026-07-14 |
| `0x0801a3a0` | MQTT_BuildMarstekDataResponse | "Marstek_data": Vollstatus-Report | high | Re-Audit 2026-07-14 |
| `0x0801a5a4` | MQTT_JSON_RPC_Dispatcher | JSON-RPC-Kommando-Dispatcher für Cloud/MQTT (5024B, 40 Callees); Method-Lookup-Tabelle, Cases u.a. ble_mac-Query, Device-Control, Config (Auto/AI/Manual-Mode); Error-Codes 0x191-0x198; Aufrufer: Quectel_UDP_DataReceive, CH395_UDP_DataHandler | high | Re-Audit 2026-07-14 |
| `0x0801bc64` | MQTT_ParseRpcParams | JSON-RPC Param-Extraktor (9 Case-Handler) | high | Re-Audit 2026-07-14 |
| `0x0801bda4` | MQTT_PassiveModeHandler | Callback: WorkMode 3 + Power-Setpoint | high | Re-Audit 2026-07-14 |
| `0x0801be60` | MQTT_PassiveModeStart | Passive-Mode aktivieren mit Timeout | high | Re-Audit 2026-07-14 |
| `0x0801becc` | MQTT_PassiveModeTimeoutCheck | Watchdog: Timeout → Callback(1) | high | Re-Audit 2026-07-14 |
| `0x0801bf08` | MQTT_BuildPvDataResponse | "Pv_data": 4 PV-Strings (PV1-4), je Power/Voltage/Current/State als int | high | Re-Audit 2026-07-14 |
| `0x0801c1b8` | MQTT_RPC_BuildSetResult | "set_result" Response (16 Callers) | high | Re-Audit 2026-07-14 |
| `0x0801cca0` | MQTT_ResetTimeslotConfig | Timeslot-Config auf Default zurücksetzen | high | Re-Audit 2026-07-14 |
| `0x0801cd1c` | MQTT_BuildWifiDataResponse | "Wifi_data": MAC, IP, Gateway, DNS | high | Re-Audit 2026-07-14 |
| `0x0801d342` | MQTT_Clear_SubscriptionSlots | 5 Subscription-Slots (Stride 8B): jeweils erstes 4B-Feld (Topic-Pointer) auf 0 gesetzt | high | Re-Audit 2026-07-14 |
| `0x0801d35c` | MQTT_Client_Init | Client-Context: Buffer, Semaphoren, Mutex | high | Re-Audit 2026-07-14 |
| `0x0801d3c2` | MQTT_Reset_ConnectionState | Connected-Flag + Subscriptions löschen | high | Re-Audit 2026-07-14 |
| `0x0801d3d8` | MQTT_Connect_Wrapper | Thin Wrapper → MQTT_Connect | high | Re-Audit 2026-07-14 |
| `0x0801d3ec` | MQTT_Connect | CONNECT-Paket bauen, senden, CONNACK parsen | high | Re-Audit 2026-07-14 |
| `0x0801d4b0` | MQTT_Parse_FixedHeader | Fixed Header + Variable-Length + Packet-ID | high | Re-Audit 2026-07-14 |
| `0x0801d51c` | MQTT_Parse_ConnAck | CONNACK: Session-Present + Return-Code | high | Re-Audit 2026-07-14 |
| `0x0801d592` | MQTT_Deserialize_Publish | PUBLISH: DUP/QoS/Retain, Topic, Payload | high | Re-Audit 2026-07-14 |
| `0x0801d63a` | MQTT_Deserialize_Suback | SUBACK: Packet-ID + Return-Codes | high | Re-Audit 2026-07-14 |
| `0x0801d6cc` | MQTT_Decode_RemainingLength_ViaCallback | Dekodiert MQTT Variable-Length-Integer (max 4 Bytes) über übergebenen Read-Funktionszeiger statt Transport-Objekt; einziger Aufrufer MQTT_Decode_RemainingLength_Wrapper | high | Re-Audit 2026-07-14 |
| `0x0801d724` | MQTT_Decode_RemainingLength_Wrapper | Indirection mit Read-Function-Pointer | high | Re-Audit 2026-07-14 |
| `0x0801d740` | MQTT_Encode_RemainingLength | Variable-Length Encoder (6 Callers) | high | Re-Audit 2026-07-14 |
| `0x0801d776` | MQTT_Topic_StringCompare | Topic-String Vergleich (strlen+memcmp) | medium | Re-Audit 2026-07-14 |
| `0x0801d7b8` | MQTT_CalcPacketSize | Paketgröße: Payload + Header + VarLen | high | Re-Audit 2026-07-14 |
| `0x0801d7e0` | MQTT_Client_SendAndReceive | Mutex, Serialize, Send, Wait PUBACK | high | Re-Audit 2026-07-14 |
| `0x0801d8ec` | MQTT_Serialize_Ack | PUBACK/PUBREC/PUBREL/PUBCOMP (Typen 4-7) | high | Re-Audit 2026-07-14 |
| `0x0801d960` | MQTT_Serialize_Connect | CONNECT: "MQIsdp" v3.1, Credentials, Will | high | Re-Audit 2026-07-14 |
| `0x0801dac8` | MQTT_Calc_Remaining_Length | Remaining-Length für CONNECT (nicht PUBLISH/PUBACK): Protokollname+Version (10/12B) + Client-ID + optional Will-Topic/Message + Username/Password via MQTT_String_ResolveLength; einziger Aufrufer MQTT_Serialize_Connect | high | Re-Audit 2026-07-14 |
| `0x0801db3e` | MQTT_Build_PingReq | PINGREQ (0xC0) via Simple-Packet | high | Re-Audit 2026-07-14 |
| `0x0801db50` | MQTT_Build_Publish_Packet | PUBLISH: Header+Topic+Payload, QoS-Check | high | Re-Audit 2026-07-14 |
| `0x0801dc00` | MQTT_Calc_Publish_Size | PUBLISH Paketgröße vorberechnen | high | Re-Audit 2026-07-14 |
| `0x0801dc22` | MQTT_Build_Subscribe_Packet | SUBSCRIBE (0x82): Topics + QoS | high | Re-Audit 2026-07-14 |
| `0x0801dcd2` | MQTT_Calc_Subscribe_Size | SUBSCRIBE Paketgröße vorberechnen | high | Re-Audit 2026-07-14 |
| `0x0801dd00` | MQTT_Build_Simple_Packet | PINGREQ/DISCONNECT (Fixed Header only) | high | Re-Audit 2026-07-14 |
| `0x0801dd4c` | MQTT_Manage_Topic_Handler | 5-Slot Topic-Handler-Tabelle (Add/Remove) | high | Re-Audit 2026-07-14 |
| `0x0801ddd6` | MQTT_Subscribe | Public API Wrapper für Subscribe | high | Re-Audit 2026-07-14 |
| `0x0801ddf6` | MQTT_Subscribe_Impl | Subscribe-Flow: Mutex→Build→Send→SUBACK→Register | high | Re-Audit 2026-07-14 |
| `0x0801df2c` | MQTT_String_ResolveLength | String-Pointer → (ptr, len) Paar | high | Re-Audit 2026-07-14 |
| `0x0801eeb8` | MQTT_Publish_AI_Data | Analog-Input-Daten an Cloud publizieren | high | Re-Audit 2026-07-14 |
| `0x0801f0d0` | MQTT_Publish_BMS_Full_Data | Vollständige BMS-Daten (Zellen, Temp, SOC) | high | Re-Audit 2026-07-14 |
| `0x0801f2a0` | MQTT_Config_VID_Init | Initialisiert Topic-ID (VID) aus Flash; falls Device-ID <6 Zeichen → MQTT_DeviceID_Encrypt-Fallback, sonst direkte Übernahme; Aufrufer: MQTT_Session_Init | high | Re-Audit 2026-07-14 |
| `0x080224c8` | MQTT_Publish_Event_Log | Event-Log-Einträge an Cloud senden | high | Re-Audit 2026-07-14 |
| `0x08022a38` | MQTT_Publish_Telemetry | Publiziert Telemetrie über Quectel-Modem: param_2==1 direkt via Quectel_Modem_DataSend, sonst AT+QMTPUB zu Topic "marstek_energy/{xid}/device/{sn}/ctrl" (Format "cd=%d&data=%s"); Aufrufer: Cloud_Reporting_setVenusDReporting | high | Re-Audit 2026-07-14 |
| `0x0802340c` | MQTT_Publish_Network_Status | Netzwerk-Statusdaten | high | Re-Audit 2026-07-14 |
| `0x08023618` | MQTT_Send_Data_Buffer | Generischer Publish-Helfer: sendet Byte-Buffer via Quectel_Modem_DataSend oder AT+QMTPUB je nach Modus; Aufrufer: Cloud_HTTP_Response_Parser u.a. | high | Re-Audit 2026-07-14 |
| `0x08023dac` | MQTT_Publish_BMS_Version | BMS-Versionsinformationen | high | Re-Audit 2026-07-14 |
| `0x08023ee4` | MQTT_Publish_Grid_Power | Netz-Leistungsdaten publizieren | high | Re-Audit 2026-07-14 |
| `0x08023ffc` | MQTT_Publish_VNS_MPPT_Data | MPPT Solar-Tracker-Daten | high | Re-Audit 2026-07-14 |
| `0x080244a8` | MQTT_Publish_Inverter_Telemetry | Inverter-Betriebsdaten | high | Re-Audit 2026-07-14 |
| `0x0802545c` | MQTT_Session_BLE_Notify | MQTT-Session BLE-Benachrichtigung senden | high | Re-Audit 2026-07-14 |
| `0x08025cbc` | MQTT_Mutex_Create | FreeRTOS Mutex für MQTT-Session erstellen | high | Re-Audit 2026-07-14 |
| `0x08025cca` | MQTT_Mutex_Take | MQTT Mutex anfordern (blockierend) | high | Re-Audit 2026-07-14 |
| `0x08025cda` | MQTT_Mutex_Give | MQTT Mutex freigeben | high | Re-Audit 2026-07-14 |
| `0x08025e5c` | MQTT_Server_Config_Select | Wählt Broker-Konfiguration (Custom-Server vs. Default) je nach Flag +0xe4 und schreibt Host/Port-Felder in Client-Struct; Aufrufer: MQTT_Connect_And_Subscribe | high | Re-Audit 2026-07-14 |
| `0x0802735c` | MQTT_DataPublish | Dünner Wrapper: baut kleines Stack-Struct und ruft MQTT_Client_SendAndReceive; Aufrufer: Network_TransportDispatch (Transport-Typ 3) | high | Re-Audit 2026-07-14 |
| `0x0802f2f0` | MQTT_Telemetry_String_Formatter | Formatiert IP-Adressen und Zellspannungs-Strings via 12× snprintf für Telemetrie-Struct; filtert Zellspannungen <101 als ungültig; Aufrufer: MQTT_Telemetry_Struct_Builder | high | Re-Audit 2026-07-14 |
| `0x0802fa18` | Config_URLSlot_AddressSelect | **Namens-Verdacht (Re-Audit 2026-07-14):** Kein MQTT-Topic-Bezug — liefert je nach Index (1-4) eine von mehreren Flash/RAM-Adressen zurück, die anschließend mit Flash_EraseAddressRange(…,0xfb) als OTA-/Config-URL-Slot gelöscht werden (Aufrufer: OTA_ValidateUrlSlots, BLE_Recv_Cmd_Dispatcher, Quectel_AT_Response_Parser, MQTT_JSON_RPC_Dispatcher). Eher Slot-Adress-Selektor als Topic-Builder. Umbenennungsvorschlag s. Session-Ergebnis (nicht angewendet, Duplikat-Check ausstehend) | medium | Re-Audit 2026-07-14 |
| `0x08032edc` | MQTT_Process_IncomingPacket | PUBLISH/PUBREC/PUBREL/PINGRESP/DISCONNECT Handler | high | Re-Audit 2026-07-14 |
| `0x08033044` | MQTT_Decode_RemainingLength | Variable-Length Integer (max 4 Bytes) | high | Re-Audit 2026-07-14 |
| `0x080330ae` | MQTT_Dispatch_PublishCallback | 5 Subscription-Slots, Wildcard-Match, Callback | high | Re-Audit 2026-07-14 |
| `0x080353ac` | MQTT_Next_PacketId | ID++ mit Wrap 0xFFFF→1 (nie 0, per MQTT-Spec) | high | Re-Audit 2026-07-14 |
| `0x08036518` | MQTT_TopicFilter_Match | '+' und '#' Wildcard-Support, '/'-Separator | high | Re-Audit 2026-07-14 |
| `0x08036598` | MQTT_KeepAlive_SendPing | PINGREQ senden, Disconnect bei unbeantwortetem Ping | high | Re-Audit 2026-07-14 |
| `0x080492bc` | MQTT_Config_ExtractFields | 6 Config-Einträge iterieren (Stride 12B) | high | Re-Audit 2026-07-14 |
| `0x0804959c` | MQTT_Config_ExtractStringValue | "key=value;" Parser mit Length Limit | high | Re-Audit 2026-07-14 |
| `0x08049674` | MQTT_Config_ParseScheduleEntries | **10 Schedule-Einträge** (nm_0..nm_9): Start/End, Mode, Power | high | Re-Audit 2026-07-14 |
| `0x08049844` | MQTT_Config_ExtractU16Value | strstr+atoi → uint16 | high | Re-Audit 2026-07-14 |
| `0x08049874` | MQTT_Config_ExtractU32Value | strstr+atoi → uint32 | high | Re-Audit 2026-07-14 |
| `0x080498a4` | MQTT_Config_ExtractU8Value | strstr+atoi → uint8 | high | Re-Audit 2026-07-14 |
| `0x0804b3f0` | MQTT_ReadByte | 1 Byte lesen, Cursor++ | high | Re-Audit 2026-07-14 |
| `0x0804b3fe` | MQTT_ReadUint16 | 2 Bytes Big-Endian lesen | high | Re-Audit 2026-07-14 |
| `0x0804b418` | MQTT_ReadStringField | uint16 Länge + Pointer+Len Store | high | Re-Audit 2026-07-14 |
| `0x0804b452` | MQTT_ReceivePacket | Header + Remaining Length + Payload lesen | high | Re-Audit 2026-07-14 |
| `0x0804bcf8` | MQTT_Transport_ReceiveAll | Blocking Receive Loop, **5 Aufrufer**, Keepalive Reset | high | Re-Audit 2026-07-14 |
| `0x08050e4a` | MQTT_WaitForPacketType | Auf bestimmten MQTT-Pakettyp warten | Batch 20 | Re-Audit 2026-07-14 |
| `0x08050e7e` | MQTT_Encode_String | String in MQTT-Paket kodieren | Batch 20 | Re-Audit 2026-07-14 |
| `0x08050ea6` | MQTT_Encode_Byte | Einzelnes Byte in MQTT-Paket kodieren | Batch 20 | Re-Audit 2026-07-14 |
| `0x08050eb2` | MQTT_Encode_Uint16 | 16-Bit-Wert in MQTT-Paket kodieren | Batch 20 | Re-Audit 2026-07-14 |
| `0x08050ee2` | MQTT_Encode_Field | Generisches Feld in MQTT-Paket kodieren | Batch 20 | Re-Audit 2026-07-14 |
| `0x08025eac` | Event_Params_Pack | Packt Topic-/Payload-Zeiger in Event-Struct für MQTT_Dispatch_PublishCallback (einziger Aufrufer) | high | Re-Audit 2026-07-14 |

## Cloud-Reporting (23)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08004808` | BLE_GATT_HexByte_Send | Name korrigiert (2026-07-15, vormals Cloud_Format_And_Send_Byte): nichts mit "Cloud" zu tun — formatiert 1 Byte als 2 ASCII-Hex-Zeichen (via sprintf) und sendet beide Zeichen per UART_TransmitByte_Blocking; einziger Aufrufer BLE_GATT_HexBuffer_Send, ausschließlich aus BLE_GATT_Notify_WithData/Send genutzt (BLE-GATT-Notify-Payload-Hex-Encoding) | medium | Re-Audit 2026-07-15 |
| `0x08005494` | Cloud_Close_TCP_Connection | Baut "AT+QICLOSE=%d" via sprintf und sendet per Quectel_SendCmd_WaitResponse (wartet auf "+QISTATE"); 0 Aufrufer im aktuellen Ghidra-Stand (evtl. nur indirekt/Funktionszeiger) | high | Re-Audit 2026-07-15 |
| `0x0800b7dc` | BLE_GATT_HexBuffer_Send | Name korrigiert (2026-07-15, vormals Cloud_Format_And_Send_Buffer): Schleife über Puffer, ruft je Byte BLE_GATT_HexByte_Send auf; ausschließlich aus BLE_GATT_Notify_WithData/Send genutzt (BLE-Kontext, kein Cloud-Bezug) | medium | Re-Audit 2026-07-15 |
| `0x08014ed8` | Cloud_Report_URL_Builder | Baut Report-URL je nach param_1 (Report-Typ 1/2/4/5/6/8) und Server-Typ (EEPROM 0x441 = 0/1/2), ruft HTTPS_POST_Request(6,...) mit gebauter URL/Payload auf (6 Aufrufstellen im Funktionskörper) | high | Re-Audit 2026-07-15 |
| `0x08016764` | Cloud_Reporting_setVenusDReporting | Baut Cloud-Telemetrie-JSON (via Cloud_Telemetry_JSON_Builder=sprintf), verschlüsselt mit AES-128-ECB (eigene Impl., SRAM-Key ROT(-6)), Base64-kodiert, sendet per HTTP_POST_Request an hamedata.com/setVenusDReporting; publiziert zusätzlich per MQTT (AT+QMTPUB) je nach Cloud-Verbindungstyp (1886 Bytes, 14 Callees) | high | Re-Audit 2026-07-15 |
| `0x0801c278` | Cloud_Report_FillPvData | PV: Spannung (fp64), SOC, Power, Watt | high | Re-Audit 2026-07-15 |
| `0x0801c32c` | Cloud_Report_FillBatteryStatus | Lade-Status (0x02=Charging) + Parameter | high | Re-Audit 2026-07-15 |
| `0x0801c398` | Cloud_Report_FillDeviceInfo | "Venus_D", Serial, MAC, FW-Version | high | Re-Audit 2026-07-15 |
| `0x0801c478` | Cloud_Report_FillEnergyCounters | Mode + 4 Energy-Words + Import/Export | medium | Re-Audit 2026-07-15 |
| `0x0801c4ec` | Cloud_Report_FillGridData | AC: Zellspannung, Strom, Frequenz, Energy | high | Re-Audit 2026-07-15 |
| `0x0801c5e0` | Cloud_Report_FillOperatingMode | "Manual"/"Passive" + Energy-Counters | high | Re-Audit 2026-07-15 |
| `0x0801c748` | Cloud_Report_FillPowerFlow | Echtzeit: Batterie/Grid/PV Power + Timestamp | high | Re-Audit 2026-07-15 |
| `0x0801c88c` | Cloud_Report_FillPvStringDetails | 4 PV-Strings: V/I fp64-skaliert, Active-Flag | high | Re-Audit 2026-07-15 |
| `0x0801cafc` | Cloud_Report_FillNetworkConfig | Serial, MAC, 4 IPs, Timezone | high | Re-Audit 2026-07-15 |
| `0x08023274` | Cloud_Handle_SelfCtl_Power | Parst "selfctl_power=" aus Cloud-Befehl, schreibt PowerOffset | high | Re-Audit 2026-07-15 |
| `0x08024128` | Cloud_HTTP_Response_Parser | Parst Server-Antwort nach Telemetrie-Upload: sucht Key=Value-Paare (u.a. seq_check, meter, dchrg) per strstr/atoi_u16, schreibt diverse Config-Werte (Config_Write_*), ruft bei bestimmten Antworten Cloud_Response_Action auf (714 Bytes, 19× strstr) | high | Re-Audit 2026-07-15 |
| `0x08026aa4` | Cloud_Config_Apply | Generischer Key=Value-Parser: sucht param_2 in param_1 (strstr), extrahiert Wert danach bis ','/Ende, filtert nur druckbare Zeichen + Punkt via Ctype-Tabelle, max. 16 Byte Ausgabe in param_3; trotz "Cloud"-Namen breit genutzt (IP/Netzwerk-Config, Device-Info, BLE-Dispatcher, Quectel-UDP-State-Machine — 8 Aufrufer über mehrere Cluster) | high | Re-Audit 2026-07-15 |
| `0x08029b2c` | Cloud_Response_Action | Setzt Power-Setpoint-Flags zurück und ruft Inverter_Power_Setpoint_Calc(1,0) auf; param_1 steuert ein "War-schon-verbunden"-Flag. Aufrufer: Cloud_HTTP_Response_Parser, Cloud_EdgeDetectAndWatchdog, BLE_Recv_Cmd_Dispatcher (9 Aufrufstellen) | high | Re-Audit 2026-07-15 |
| `0x0802caf4` | Cloud_EdgeDetectAndWatchdog | 2 Edge-Detectors + 12000-Tick Connection-Watchdog | medium | Re-Audit 2026-07-15 |
| `0x0802f800` | Cloud_Telemetry_Snapshot_Build | JSON mit "VenusD" bauen, dann loggen | high | Re-Audit 2026-07-15 |
| `0x0802fa58` | UART_TransmitByte_Blocking | Generischer blockierender UART-Byte-Versand (USART_SendData + 5000-Iteration TX-Status-Poll); einziger Aufrufer Cloud_Format_And_Send_Byte (BLE-Kontext) — Name "Cloud_" irreführend, s. Namens-Verdacht bei 0x08004808 | medium | Re-Audit 2026-07-15 |
| `0x080303bc` | sprintf | Name korrigiert (2026-07-15, vormals Cloud_Telemetry_JSON_Builder): generischer sprintf/vsprintf-Wrapper (ruft printf_Format_Engine + sprintf_Output_Char), NICHT JSON- oder Cloud-spezifisch — 39 Aufrufer quer durch praktisch alle Cluster | high | Re-Audit 2026-07-15 |
| `0x0805063c` | Cloud_Telemetry_BuildTaskListJSON | Cloud-Telemetrie: Task-Liste als JSON aufbauen | Batch 20 | Re-Audit 2026-07-15 |

## Modbus / RS485 (35)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080072a0` | RS485_UART_Send | Sendet Byte-Puffer über RS485 (TX-Modus + USART-Polling, Rückschalten auf RX danach) oder alternativ über CH395-TCP-Socket, falls Netzwerkmodus aktiv (Flag an DAT_080072f8+3) | high | Doku (Re-Audit 2026-07-14) |
| `0x08007300` | RS485_Set_TX_Mode | TX-Richtung aktivieren + Settle-Wait | high | Doku |
| `0x0800731c` | RS485_Set_RX_Mode | RX-Richtung aktivieren nach Transmission | high | Doku |
| `0x08007338` | RS485_UART_SendByte | Einzelbyte über RS485 senden (TX/RX Umschaltung) | high | Doku |
| `0x0801e37c` | CRC16_Modbus_Calc | Standard CRC16: Init 0xFFFF, Poly 0xA001 | high | Doku |
| `0x0801e3c0` | CRC16_Modbus_Incremental | CRC16 inkrementell (Running-Value Update) | high | Doku |
| `0x0801e406` | CRC16_Modbus_WithSeed | CRC16 mit variablem Seed-Wert | high | Doku |
| `0x0801e43c` | Modbus_Dispatcher | Modbus-TCP-Dispatcher über CH395-Ethernet-Chip: liest Frame aus Socket-Empfangspuffer, routet nach FC (0x03/0x06/0x10) an TCP-Handler, sendet Response per CH395_SPI_Send_Data; verarbeitet zusätzlich Reboot-/Factory-Reset-Flags | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e678` | Modbus_CRC16_Calculate | Standard-CRC16 (Init 0xFFFF, Poly 0xA001), identischer Algorithmus wie CRC16_Modbus_Calc; wird nicht nur für Modbus-RTU-Frames genutzt, sondern auch für Zertifikats-Integritätsprüfung in CH395_MQTT_Init_And_CertSetup (Blockgrößen bis 0x6b4 Byte) | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e6b0` | RS485_RTU_Frame_Dispatcher | UART-Empfangsschleife (byteweise via Queue-Receive), CRC16-Check, Slave-Adress-Vergleich, FC-Routing (03→RS485_RTU_Modbus_Router, 06→RS485_FC06_WriteSingle_Handler, 10→RS485_FC10_WriteMultiple_Handler); Broadcast (Adresse 0) getrennt für FC06/FC10; verarbeitet Reboot-/Factory-Reset-Flags | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e880` | TCP_FC06_WriteSingle_Handler | FC06 Write-Single-Register für TCP/CH395-Pfad (reg muss >=40000 sein, sonst Fehlercode 2); bei Erfolg Echo-Response über CH395_SPI_Send_Data oder Quectel-Modem als Fallback | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e904` | TCP_FC06_WriteSingle_Handler_B | Zweite TCP-FC06-Instanz für parallelen zweiten Socket/Slot (eigener Kontext DAT_0801e948), identische Prüflogik wie TCP_FC06_WriteSingle_Handler, aber ohne eigenen Response-Versand | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e94c` | TCP_FC10_WriteMultiple_Handler | FC10 Write-Multiple-Registers für TCP/CH395-Pfad, reg>=40000, 1-125 Register, Byte-geswappte Werte über Byte_Swap_Copy; sendet Response über CH395_SPI_Send_Data | high | Doku (Re-Audit 2026-07-14) |
| `0x0801ea0c` | TCP_FC10_WriteMultiple_Handler_B | Zweite TCP-FC10-Instanz für parallelen zweiten Socket/Slot, identische Prüflogik wie TCP_FC10_WriteMultiple_Handler, aber ohne eigenen Response-Versand | high | Doku (Re-Audit 2026-07-14) |
| `0x0801eaa4` | FC03_Read_Handler | FC03 Read-Handler für TCP-Pfad: reg<40000 → Lookup in 246-Eintrag-Descriptor-Table (Basis 0x20000354, Stride 0xC) + Read_Serializer; reg>=40000 → Delegation an Write_Handler(param3=0) im Lese-Modus; Sonderfall reg 38000-39014 setzt Flag bei SRAM 0x20000ee5 | high | Doku (Re-Audit 2026-07-14) |
| `0x08028ee0` | Modbus_Parse_Response_Frame | FC01/02/04/18/41/61 Response-Parser, Adress-XOR-Validierung | high | Doku |
| `0x08029b88` | RS485_Modbus_RegisterMap_Init | 8 Read/Write Register-Gruppen initialisieren | high | Doku |
| `0x08029c18` | RS485_Modbus_MapReadRegister | Read-Register-Eintrag aufbauen (FC 0x52) | high | Doku |
| `0x08029c48` | RS485_Modbus_MapWriteRegister | Write-Register-Eintrag aufbauen (FC 0x53) | high | Doku |
| `0x08029df8` | RS485_FC03_ReadWrite_Handler | FC03-Handler für RS485-RTU (Pendant zu FC03_Read_Handler im TCP-Pfad), kein FC-übergreifender Router: reg<40000 liest via Descriptor-Table+Read_Serializer, reg>=40000 via Write_Handler(param3=0); sendet CRC16-gesicherte Antwort über RS485_UART_Send. Am 2026-07-14 von "RS485_RTU_Modbus_Router" umbenannt (alter Name implizierte fälschlich einen FC-übergreifenden Router) | high | Re-Audit 2026-07-14 |
| `0x08029f54` | RS485_FC06_WriteSingle_Handler | FC06 Write-Single-Register für RS485-RTU-Pfad, reg>=40000; bei Erfolg CRC16-gesicherte Echo-Response über RS485_UART_Send | high | Doku (Re-Audit 2026-07-14) |
| `0x08029fe0` | RS485_Broadcast_FC06_WriteSingle | FC06 Write-Single als RS485-Broadcast (Slave-Adresse 0x00), reg>=40000; sendet KEINE Response (Modbus-Broadcast-Konvention) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802a028` | RS485_FC10_WriteMultiple_Handler | FC10 Write-Multiple-Registers für RS485-RTU-Pfad, reg>=40000, 1-125 Register, Byte-Swap via Byte_Swap_Copy; sendet CRC16-gesicherte Response über RS485_UART_Send | high | Doku (Re-Audit 2026-07-14) |
| `0x0802a108` | RS485_Broadcast_FC10_WriteMultiple | FC10 Write-Multiple als RS485-Broadcast (Slave-Adresse 0x00), reg>=40000; sendet KEINE Response | high | Doku (Re-Audit 2026-07-14) |
| `0x0802c060` | Modbus_SendResponse | Nimmt fertigen Response-Frame aus Queue (via Queue-Receive-Funktion, Timeout 1000 Ticks) und sendet ihn über CAN (CAN_SendMessage/CAN_SetupTxMailbox) — NICHT über USART wie bisher dokumentiert; aktuell 0 direkte Caller in Ghidra | high | Doku (Re-Audit 2026-07-14, korrigiert) |
| `0x0802e94c` | Modbus_StoreRegisterSlot | FC 0x03: 8B in Slot (1-7) | medium | Doku |
| `0x0802e988` | Modbus_StoreWithHandshake | FC 0xCB: 2-Phasen Handshake | medium | Doku |
| `0x0802e9d4` | Modbus_StoreDualSlot | FC 0xCE: 4B in Slot 0/1 | medium | Doku |
| `0x0802ea04` | Modbus_StoreValue16 | FC 0xFE: 16-Bit Einzelwert | high | Doku |
| `0x0802ea18` | Modbus_StorePairSlot | FC 0xFF: 8B in Slot (1-2) | medium | Doku |
| `0x0802ea54` | Modbus_ResponseDispatch | FC-basierter Dispatcher: 0x03/0xCB/0xCE/0xFE/0xFF | high | Doku |
| `0x0802fc60` | RS485_SendIfValid | Guard-Wrapper um RS485_UART_Send: sendet nur, falls Pufferpointer != 0, gibt sonst 0 zurück; aktuell 0 direkte Caller in Ghidra (evtl. Function-Pointer-Ziel) | high | Doku (Re-Audit 2026-07-14) |
| `0x080541f8` | Queue_Receive_WithTimeout | Generische blockierende FreeRTOS-Queue-Receive-Funktion (Timeout via vTaskPlaceOnEventList/xTaskCheckForTimeOut, analog xQueueReceive); breit genutzt von RS485_RTU_Frame_Dispatcher, CAN_RxQueue_DrainAndDispatch, Quectel_SendCmd_WaitResponse, Write_Handler, CT_GridPower_Controller u.a. — keine Modbus-spezifische Funktion. Am 2026-07-14 von "Modbus_Response_Builder" umbenannt (alter Name implizierte fälschlich Modbus-Frame-Bau) | high | Re-Audit 2026-07-14 |
| `0x0804fe20` | Read_Serializer | Konvertiert SRAM-Werte per Descriptor-Tabelle typ-/skalierungsgerecht in Modbus-Read-Response (TCP FC03 + RS485 FC03) | high | Re-Audit 2026-07-14 |
| `0x08050f20` | Write_Handler | Zentraler Modbus-Register-Write-Dispatcher (FC06/FC10) für TCP und RS485, vollständige Registermap im Code-Kommentar dokumentiert | high | Re-Audit 2026-07-14 |

## CAN-Bus / Parallelbetrieb (33)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08002000` | CAN_SendMessage | CAN-Sende-Wrapper: ruft CAN_SetupTxMailbox(CAN1_BASE=0x40006400) auf; einziger Aufrufer Modbus_SendResponse (Modbus-Antwort via CAN) — **korrigiert 2026-07-14**: alte Beschreibung "USART-Wrapper" war falsch, echte CAN1-Peripherie bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08002a20` | CAN_ReadMailbox | CAN RX Mailbox lesen (ID/DLC/Daten), Release-Bit setzen | high | Doku |
| `0x08002b10` | CAN_SetupTxMailbox | CAN TX Mailbox befüllen (TME-Prüfung, TXRQ setzen) | high | Doku |
| `0x08004418` | CAN_Detect_Mismatched_Nodes | CAN-Nodes auf Adress-Mismatch scannen, Error wenn >1 | medium | Doku |
| `0x080045dc` | CAN_Update_StateMachine | 6-State-Machine für CAN-Update mit 20-Tick Timeout | high | Doku |
| `0x080049a4` | CAN_Update_Check_Retry_Limit | CAN-Update Retry-Zähler gegen Limit prüfen | medium | Doku |
| `0x08005418` | CAN_Node_Data_Reset | CAN-Node-Datenstruktur auf 0 zurücksetzen | high | Doku |
| `0x0800557c` | CAN_Parallel_Inverter_Sync | Multi-Unit SOC/Version Sync über CAN | high | Doku |
| `0x080056b4` | CAN_Select_Master_Node | Node-Validierung: erster Node mit gültigem Versions-/Kompatibilitäts-Byte (Bereich 2-4) wird aktiver Node, ruft danach CAN_Detect_Mismatched_Nodes — **korrigiert 2026-07-14**: kein SOC-Vergleich im Code (SOC-Max-Suche erfolgt tatsächlich in CAN_Parallel_Inverter_Sync) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08026f08` | CAN_Update_HandleResponse | CAN-Update Response verarbeiten | high | Doku (Name-Match) |
| `0x08027074` | CAN_Update_SendData | Firmware-Datenblöcke über CAN übertragen | high | Doku (Name-Match) |
| `0x080271a4` | CAN_Update_Success | CAN-Update erfolgreich abschließen | high | Doku (Name-Match) |
| `0x080271e4` | CAN_Update_Failed | CAN-Update Fehlerzustand behandeln | high | Doku (Name-Match) |
| `0x08027224` | CAN_Update_Init | CAN-Update Initialisierung | high | Doku (Name-Match) |
| `0x080272e0` | CAN_Update_Erase | Flash-Löschbefehl über CAN senden | high | Doku (Name-Match) |
| `0x080292d4` | CAN_RxQueue_DrainAndDispatch | Bis zu 64 Messages aus RX-Queue dispatchen  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0802c090` | CAN_Update_WriteStatus | Status-Daten an Register-Kat. 0xCE/Sub 2 schreiben | high | Doku |
| `0x0802c0c2` | CAN_Update_WriteData | Flash-Datenblock an Register-Kat. 0xCE/Sub 1 | high | Doku |
| `0x0802c0de` | CAN_Update_WriteEraseInfo | Erase-Metadaten an Register-Kat. 0xCE/Sub 0 | high | Doku |
| `0x0802c5b0` | I2C_SendWorkModeFrame | WorkMode als 2-Byte CAN-Frame (0x81\|mode<<4, Addr 0x48) | high | Doku |
| `0x0802c5d8` | I2C_SyncChangedRegisters | Delta-Sync: nur geänderte Register über CAN senden (5 Aufrufer) | high | Doku |
| `0x0802cf8c` | CAN_UpdateResultHandler | CAN Node-ID → Device-Type mappen, OTA_Set_SlotStatus | high | Doku |
| `0x0802dfd4` | CAN_RxMailbox_Handler | CAN_ReadMailbox + Forward, ISR/Callback | high | Doku |
| `0x0802e698` | CAN_FrameDispatcher | CAN-Frames nach ID-Bits dispatchen (3 Handler) | high | Doku |
| `0x0802e6e4` | CAN_ParallelInverterDataParser | CAN-Frame-ID parsen, 8-Entry Tabelle befüllen | medium | Doku |
| `0x080358ec` | CAN_Battery_Telemetry_Debug_Print | 21 CAN-PGN Felder (1801-1804, 1007) | high | Doku |
| `0x0802efac` | Protocol_AA_CommandDispatch | 0xAA-Header validieren, 17-Entry Funktionstabelle. Aufrufer ist CAN_FrameDispatcher — Name selbst korrekt | high | Re-Audit 2026-07-15 |
| `0x0802f010` | Protocol_AA_SetChannelData | Cmd 0x10: 8B in Channel-Slot (1-7) | high | Re-Audit 2026-07-15 |
| `0x0802f04c` | Protocol_AA_SetSystemParams | 8B in System-Struct kopieren | medium | Re-Audit 2026-07-15 |
| `0x0802f064` | Protocol_AA_SetDeviceParams | 6B in Device-Struct kopieren | medium | Re-Audit 2026-07-15 |
| `0x0802f07c` | Protocol_AA_EnqueueCommand | Cmd 0x13: 4B+2B in zwei FreeRTOS-Queues | high | Re-Audit 2026-07-15 |
| `0x0802f0b8` | Protocol_AA_SetExtendedParams | Cmd 0x14: 6B in Extended-Struct | medium | Re-Audit 2026-07-15 |
| `0x0802f0d0` | Protocol_AA_RS485Forward | Cmd 0xC3: RS485-Passthrough nur bei Mode 0x02 | high | Re-Audit 2026-07-15 |

## BLE / GATT (35)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08002674` | BLE_Handle_SetDischargeCutoff | Discharge-Cutoff-Relaiswert aus BLE-Payload lesen, per Config_Set_DischargeCutoff_WithRelay anwenden, WorkMode zur Bestätigung zurücksenden (Cmd 0x54) — **korrigiert 2026-07-14**: alte Beschreibung "WorkMode lesen und anwenden" war falsch, WorkMode wird nur zur Antwort ausgelesen | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080026a4` | BLE_ConnState_Timer_Control | Je nach BLE-Verbindungsstate (Offsets +0x20e/+0x210) FreeRTOS-Timer "BLE_TIMER" starten/zurücksetzen/löschen via BLE_Timer_Manage, aufgerufen aus BLE_ConnectionStateManager bei State 2/3 — **korrigiert 2026-07-14**: alte Beschreibung "Charging-Mode" war falsch, kein Lade-Bezug im Code | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08007cf4` | BLE_AdvertisingControl | AT+QBLEADVSTART/STOP mit 3 Retries | high | Doku (Re-Audit 2026-07-14) |
| `0x08007d68` | BLE_ConnectionStateManager | BLE-State-Machine: Advertising, Connect, Disconnect | medium | Doku (Re-Audit 2026-07-14) |
| `0x08007ef4` | BLE_Set_AdvParams | AT+QBLEADVPARAM mit Retry | high | Doku (Re-Audit 2026-07-14) |
| `0x08007f58` | BLE_Recv_Cmd_Dispatcher | BLE-Empfangs-Kommando-Dispatcher (~6,7 KB Code): validiert Frame-Format ([Header][Len]['#'][Cmd][Payload][XOR-Checksum]) über BLE_CRC_Calculate, dispatcht per Switch auf Cmd-Byte auf >50 Handler (Server-Typ, Work-Status, Geräteinfo, Config R/W, Factory-Reset, WLAN-Setup, Arbeitsmodus, Datum/Zeit, Develop-Mode, BMS-Daten, OTA, VID/XID-Provisioning etc.), Antwort über BLE_Send_Response | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800a740` | BLE_XOR_Checksum_Calculate | Name korrigiert (2026-07-15, vormals BLE_CRC_Calculate): berechnet XOR-Prüfsumme (kein echter CRC/Polynom) über param_2 Bytes ab param_1 — verwendet von BLE_Send_Response und BLE_Recv_Cmd_Dispatcher zur Frame-Validierung | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800a764` | BLE_Send_Response | Baut BLE-Antwortframe (Header 0x73, Länge=Payload+5, '#', Cmd-Byte, Payload, XOR-Checksum via BLE_CRC_Calculate) und sendet via BLE_GATT_Notify_Send; nur bei Payload!=0 und <0x1FC Bytes. Zentrale Antwortfunktion des BLE-Protokolls (>80 Aufrufer) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800a7c0` | BLE_Poll_Connection_State | AT+QBLESTAT pollen, 6 States, 9×500ms | high | Doku (Re-Audit 2026-07-14) |
| `0x0800a9b8` | BLE_Recv_Extract_URL | Extrahiert URL-String (ab Offset 5) aus BLE-Paket in globalen Puffer; zwei Modi: param_2=0 nur URL, param_2=1 URL inkl. Port-Feld (für Cloud-URL bzw. Cloud-URL+Port) | high | Doku (Re-Audit 2026-07-14) |
| `0x0800aa2c` | BLE_Recv_Parse_WiFi_Credentials | SSID+Passwort aus BLE parsen, `<,>` Delimiter | high | Doku (Re-Audit 2026-07-14) |
| `0x0800ab14` | BLE_Module_Init | AT+QBLEINIT mit Retry | high | Doku (Re-Audit 2026-07-14) |
| `0x0800abb8` | BLE_Set_Device_Name | AT+QBLENAME=MST_VNSD_xxxx (Seriennummer) | high | Doku (Re-Audit 2026-07-14) |
| `0x0800acc4` | BLE_GATT_Notify_Send | Wartet auf Queue-Freigabe, sendet AT+QBLEGATTSNTFY=ff02,<len> per Quectel-AT über UART ans BLE-Modul (echtes GATT-Notify, Characteristic-Handle 0xFF02) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800ad40` | BLE_GATT_Notify_WithData | GATT Notify mit Daten-Payload senden | high | Doku (Re-Audit 2026-07-14) |
| `0x0800ae5c` | BLE_Build_Settings_Response | 10 Settings-Einträge mit Byte-Swap aufbereiten | medium | Doku (Re-Audit 2026-07-14) |
| `0x0800af78` | BLE_RuntimeInfo_Builder | Baut Work-Status-Antwort (0xA4 Bytes, Cmd 0x03) aus Meter-/CT-/Telemetriedaten inkl. fp64-Leistungsberechnungen | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800b430` | BLE_Build_BMS_Data_Response | BMS-Daten (V, I, SOC, Temp, Zellen, fp64-Leistungsberechnung) in gemeinsamen Puffer aufbereiten — genutzt sowohl für BLE-Antwort (BLE_Recv_Cmd_Dispatcher) als auch für MQTT-Publish (MQTT_Publish_BMS_Full_Data) — korrigiert/ergänzt 2026-07-14 | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800b6c0` | BLE_Build_DevelopModeInfo_Response | BLE-Antwort: Entwicklermodus-Info zusammenbauen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08010518` | BLE_Build_Telemetry_Response | Inverter-Telemetrie für BLE (fp64 Power-Berechnung) | high | Doku (Re-Audit 2026-07-14) |
| `0x08010718` | BLE_Pending_Commands_Process | Deferred BLE Commands: WiFi-Setup, OTA, Socket-Ctrl (ruft WiFi_Set_Credentials, Quectel_OTA_StartUpdate_FromURL_AndReboot, BLE_ConnectionStateManager, BLE_MQTT_Command_Execute). Hinweis: 0 Aufrufer/Referenzen im aktuellen Codepfad gefunden (evtl. nur über nicht aufgelösten Funktionszeiger erreichbar) — ergänzt 2026-07-14 | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08012e04` | BLE_RuntimeInfo_ChannelDelta_Calc | BLE Laufzeit-Info: Kanal-Delta berechnen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x0801e08c` | BLE_Timer_Manage | FreeRTOS Timer: Create/Reset/Delete "BLE_TIMER" | high | Doku (Re-Audit 2026-07-14) |
| `0x08025204` | BLE_MQTT_Command_Execute | BLE-getriggerte MQTT-Aktionen: VID/XID Subscribe+Publish mit Ack-Wartezeit, Device-ID-Verschlüsselung; Aufrufer BLE_Pending_Commands_Process | high | Ghidra (Re-Audit 2026-07-14, Doku bestätigt) |
| `0x08025f94` | BLE_SendFramedNotification | Baut Antwort-Frame (Header 0x73, Länge, Cmd-Byte, Payload, XOR-Checksum via Util_XOR_Checksum_Calc) und sendet via BLE_GATT_Notify_WithData; genutzt von OTA-Cmds 0x3A/0x50/0x51/0x52 und Reboot-Cmd 0x23 | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08026bfc` | BLE_XidServerConfig_Parse | Parst XID/Server-Config-String (Delimiter `<,>`) aus BLE-Kommando 0x0C (VID/XID-Provisioning) in 6 Felder: ID (1B), Host (32B), Topic (64B), Port (2B), User (64B), Passwort (64B); Rückgabe 1=Erfolg/0=Fehler. Aufrufer: BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d0ec` | BLE_Apply_ConfigReg_Offset3 | BLE-Index 0/1 → Config Register 3/4 mappen | high | Doku (Re-Audit 2026-07-14) |
| `0x0802e78c` | BLE_Cmd_OTA_Validate | Cmd 0x52: Modell/Magic/Größe/CRC validieren | high | Doku (Re-Audit 2026-07-14) |
| `0x0802e86c` | BLE_Cmd_OTA_Init | Cmd 0x3a: OTA-Kontext (0x3C Bytes) initialisieren | high | Doku (Re-Audit 2026-07-14) |
| `0x0802e900` | BLE_Cmd_OTA_WriteSetup | Cmd 0x50: Flash-Adresse/Größe setzen, ggf. Flash löschen | high | Doku (Re-Audit 2026-07-14) |
| `0x0802eacc` | BLE_Cmd_SystemReboot | Cmd 0x23: Shutdown + Reboot, BLE-Response 0xAA01 | high | Doku (Re-Audit 2026-07-14) |
| `0x0802ed04` | BLE_OTA_WriteDataChunk | Cmd 0x51: 128B-Chunks empfangen, CRC16, Flash schreiben | high | Doku (Re-Audit 2026-07-14) |
| `0x0803216c` | BLE_Set_Mode_Persist | BLE OFF/Ready/ON → EEPROM 0x36a | very high | Doku (Re-Audit 2026-07-14) |
| `0x08004844` | Serial_Packet_Validate | Magic 's'+0x10, max 138B, Single-Byte XOR Checksum | high | Doku |
| `0x08025eb2` | Serial_Command_Dispatch | Verteilt BLE-Modul-Kommandos (OTA-Init/Write/Validate, Reboot) über serielle Schnittstelle; 0 direkte Aufrufer (vermutlich UART-RX-Callback) | medium | Re-Audit 2026-07-14 |

## CH395 — Ethernet-Controller (55)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08002c38` | CH395_SPI_Cmd_WithData | Mutex-geschützter SPI-Befehl mit Daten | high | Re-Audit 2026-07-14 |
| `0x08002e10` | CH395_SPI_ReadByte | Mutex-geschütztes Single-Byte SPI-Read | high | Re-Audit 2026-07-14 |
| `0x08002ea4` | CH395_SPI_WriteCmd | Mutex-geschütztes SPI-Write (Cmd 0x2E) | high | Re-Audit 2026-07-14 |
| `0x08002f38` | CH395_SPI_CmdWaitReady | SPI-Cmd + Busy-Poll (201×5ms, 0xFA bei Timeout) | high | Re-Audit 2026-07-14 |
| `0x08003008` | CH395_GetICVersion | CMD 0x2C: Chip-Version lesen | high | Re-Audit 2026-07-14 |
| `0x08003164` | CH395_ReadRecvBuf | CMD 0x3C: Empfangspuffer lesen (Socket+Länge→Buffer) | high | Re-Audit 2026-07-14 |
| `0x0800322c` | CH395_GetRecvLen | CMD 0x3B: Empfangspuffer-Länge abfragen (16-Bit) | high | Re-Audit 2026-07-14 |
| `0x080032d4` | CH395_GetSocketStatus | CMD 0x30: Socket-Status lesen | high | Re-Audit 2026-07-14 |
| `0x08003378` | CH395_SetProtoType | CMD 0x58: Protokolltyp setzen | high | Re-Audit 2026-07-14 |
| `0x0800340c` | CH395_SetRetranPeriod | CMD 0x56: Retransmission-Timeout (32-Bit ms) | high | Re-Audit 2026-07-14 |
| `0x080034b8` | CH395_SetRetranCount | CMD 0x57: Retransmission-Count (32-Bit) | high | Re-Audit 2026-07-14 |
| `0x08003564` | CH395_OpenSocket | CMD 0x35: Socket öffnen + Busy-Poll | high | Re-Audit 2026-07-14 |
| `0x08003644` | CH395_SPI_Send_Data | CMD 0x39: Kern-Sendefunktion, pollt Socket-Busy-Flag (max. 10×3ms), Mutex-geschützt, sendet Byte-für-Byte über SPI_WriteByte; wird von fast allen anderen CH395-Sendepfaden aufgerufen (Send_Data_Verified, Socket_SendSafe, Socket_SendData_ViaSocketPtr, DNS/Modbus/TCP-Handler) | high | Re-Audit 2026-07-14 |
| `0x08003740` | CH395_SetKeepAlive | CMD 0x59: Keep-Alive ein/aus | medium | Re-Audit 2026-07-14 |
| `0x080037dc` | CH395_SetDestIP | CMD 0x31: Ziel-IP setzen (4 Bytes) | high | Re-Audit 2026-07-14 |
| `0x08003894` | CH395_SetSocketSrcPort | CMD 0x32: Quell-Port setzen (16-Bit lo/hi) | high | Re-Audit 2026-07-14 |
| `0x08003938` | CH395_SetSocketProtocol | CMD 0x34: Socket-Protokoll (2=TCP, 3=UDP) | high | Re-Audit 2026-07-14 |
| `0x080039d4` | CH395_SetSocketDstPort | CMD 0x33: Ziel-Port setzen (16-Bit lo/hi) | high | Re-Audit 2026-07-14 |
| `0x08003a78` | CH395_TCPConnect | CMD 0x37: TCP-Verbindung initiieren + Poll | high | Re-Audit 2026-07-14 |
| `0x08003b48` | CH395_TCPDisconnect | CMD 0x38: TCP-Verbindung trennen + Poll | high | Re-Audit 2026-07-14 |
| `0x08003c18` | CH395_TCPListen | CMD 0x36: TCP-Server Listen + Poll | high | Re-Audit 2026-07-14 |
| `0x08003ce8` | CH395_ConfigAndSendSocket | Orchestrator: DestIP+SrcPort+Send für Socket | high | Re-Audit 2026-07-14 |
| `0x08003d18` | CH395_HardwareReset | GPIO-Reset-Puls (100ms low, 50ms high) | high | Re-Audit 2026-07-14 |
| `0x080066be` | CH395_MQTT_Socket_Close_And_TLS_Reset | CH395 MQTT-Socket schließen und TLS-Kontext zurücksetzen | high | Re-Audit 2026-07-14 |
| `0x080067b4` | CH395_Wait_Command_Complete | CH395 Kommando-Completion mit 5s Timeout | high | Re-Audit 2026-07-14 |
| `0x080074e4` | CH395_SendData_WaitResponse | Daten über CH395-Socket senden, Response abwarten | high | Re-Audit 2026-07-14 |
| `0x08015638` | CH395_SPI_SendData_Verified | CH395 SPI-Datenversand mit Verifikation | high | Re-Audit 2026-07-14 |
| `0x08017974` | CH395_UDP_Socket_Init | CH395 UDP-Socket initialisieren | high | Re-Audit 2026-07-14 |
| `0x08017c50` | CH395_TCP_Socket_Open_HTTPPort80 | CH395 TCP-Socket auf Port 80 öffnen (HTTP) | high | Re-Audit 2026-07-14 |
| `0x08017e64` | CH395_UDP_Socket_OpenForDNS | CH395 UDP-Socket für DNS-Anfragen öffnen | high | Re-Audit 2026-07-14 |
| `0x0801828c` | CH395_Socket_Dest_Config | Socket mit IP + Port 8883 (MQTTS) konfigurieren | high | Re-Audit 2026-07-14 |
| `0x08019560` | CH395_UDP_Socket_Config | CH395 Socket: Protokoll=UDP, Index=4 | medium | Re-Audit 2026-07-14 |
| `0x080195a4` | CH395_Recv_Buffer_Setup | Kein SPI/HW-Zugriff: setzt ein Feld im CH395-Socket-Deskriptor und initialisiert darüber eine CLI/AT-Command-Session (`CLI_InitSession`, 512B Puffer in 5 Slices, Lookup per Versionsstring "VNSD_0_v1492") — s. Abschnitt zur CLI/AT-Command-Engine (0x0804bd58-0x0804cc40). **0 Aufrufer/Xrefs gefunden (toter Code oder nur indirekt referenziert)**; Beschreibung "DMA Receive Buffer" war falsch, es gibt keine DMA-Nutzung | medium | Re-Audit 2026-07-14 |
| `0x0801ded4` | CH395_Command_SendAndWait | CH395 Cmd + Poll mit vTaskDelay(10) | high | Re-Audit 2026-07-14 |
| `0x08024d80` | CH395_MQTT_Init_And_CertSetup | Orchestriert MQTT-Init über CH395: TLS-Zertifikat-Entschlüsselung (TLS_Cert_Decrypt_All), MQTT-Session-Aufbau, CRC16 der Zertifikate in EEPROM 0x36B7-0x36BB (per vorhandenem Ghidra-Kommentar); ruft unter anderem CH395_Command_SendAndWait und CH395_MQTT_Socket_Close_And_TLS_Reset | high | Re-Audit 2026-07-14 |
| `0x08029314` | CH395_Receive_WithRetry | 6× Poll (100ms), 512B Buffer, Return 0/-1/-2 | high | Re-Audit 2026-07-14 |
| `0x08029918` | CH395_Init_Full | Mode 0x41, 4K Clear, IC-Version Poll (201×20ms) | high | Re-Audit 2026-07-14 |
| `0x08029964` | CH395_Reset_And_Reinit | FreeRTOS Queue-Sync, HW-Reset, Basic→Full Init | high | Re-Audit 2026-07-14 |
| `0x08029a24` | CH395_Init_Basic | Mode 0x27, IC-Version Poll (Soft-Init) | high | Re-Audit 2026-07-14 |
| `0x0802d12c` | CH395_Socket_SendData | 0x39 Header, Mutex-geschützt, 20000-Iteration Timeout | high | Re-Audit 2026-07-14 |
| `0x0802e004` | CH395_UDP_DataHandler | UDP-Paket parsen, IP validieren, an JSON-RPC weiterleiten | high | Re-Audit 2026-07-14 |
| `0x0802e190` | CH395_UDP_ServerTask | 3-State UDP-Server: Start→Receive→Close | high | Re-Audit 2026-07-14 |
| `0x08032634` | CH395_ConfigUDP_Defaults | UDP: RetranPeriod=10s, RetranCount=3000 | high | Re-Audit 2026-07-14 |
| `0x08032650` | CH395_PHY_StatusHandler | Link-Status: 10M/100M Full/Half, Auto-Neg | high | Re-Audit 2026-07-14 |
| `0x08032978` | CH395_Socket_WaitReady | Socket-Ready via SPI pollen | high | Re-Audit 2026-07-14 |
| `0x08032984` | CH395_Socket_ReadData | Non-Blocking Receive mit Längenlimit | high | Re-Audit 2026-07-14 |
| `0x080329b2` | CH395_Socket_SendData_ViaSocketPtr | Dünner Wrapper: dereferenziert Socket-Pointer (Byte 0 = Socket-Index) und ruft direkt CH395_SPI_Send_Data auf, kein Mutex/Polling eigenständig (Mutex steckt in Send_Data selbst); 0 Aufrufer im aktuellen Stand (s. Batch-19-Dublettenfix) | high | Re-Audit 2026-07-14 |
| `0x080329cc` | CH395_Socket_RecvBlocking | Blocking Receive, 1s Timeout | high | Re-Audit 2026-07-14 |
| `0x08032a44` | CH395_Socket_SendSafe | Guarded Send mit NULL/0-Check | high | Re-Audit 2026-07-14 |
| `0x08032c0c` | CH395_Init_TCPServer_Socket | Port 8091, Type=TCP Listen | high | Re-Audit 2026-07-14 |
| `0x08032c58` | CH395_Socket_Open_ByDescriptor | **8 Aufrufer** — Zentraler Socket-Opener (UDP/TCP Client/Server) | high | Re-Audit 2026-07-14 |
| `0x08032d78` | CH395_Debug_PrintVersion | IC-Version lesen und drucken (Debug) | high | Re-Audit 2026-07-14 |
| `0x08032dd4` | CH395_Init_BroadcastListener_Socket | Port 8090, Dest=255.255.255.255 | high | Re-Audit 2026-07-14 |
| `0x08048754` | CH395_Init_Modbus_TCP_Socket | UDP Socket Port 502, Buffer 0x80, **zwischen mbedTLS-Code** | high | Re-Audit 2026-07-14 |
| `0x08004838` | CH395_Debug_SendCmdByte | Ruft nur CH395_SPI_Cmd_WithData(param_1) auf; einziger Aufrufer CH395_Debug_PrintVersion (CH395-Chip-Versionsabfrage) | high | Re-Audit 2026-07-14 |

## Netzwerk / DNS / Sockets (allgemein) (23)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08003d40` | Network_ProtocolDispatcher | Dispatched 3 Handler (Modus 0/1/2), prüft CH395-Link, 60s Timeout | medium | Re-Audit 2026-07-15 |
| `0x0800670c` | DNS_ResourceRecord_Parse | TLV-Record dekodieren, Typ-Switch (1-16), rekursiv  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Re-Audit 2026-07-15 |
| `0x0800b5bc` | TCP_Socket_Close | AT+QICLOSE mit Socket-ID-Validierung (Quectel-AT-Pfad, 3 Retries via Quectel_TCP_SendAndVerify); einziger Aufrufer Quectel_UDP_CommStateMachine | high | Re-Audit 2026-07-15 |
| `0x08011258` | Network_ConnectionStatus_Fill | Netzwerk-Status-Struct befüllen (Typ, Signal, Mode) | medium | Re-Audit 2026-07-15 |
| `0x080130f4` | Network_BroadcastAddr_ComputeAndLog | Broadcast-Adresse berechnen und loggen | Batch 20 | Re-Audit 2026-07-15 |
| `0x080131b0` | Network_BroadcastAddr_ComputeInPlace | Broadcast-Adresse in-place berechnen | Batch 20 | Re-Audit 2026-07-15 |
| `0x080136e0` | Network_ExtractIPv4_BetweenTags | IPv4-Adresse zwischen Text-Tags extrahieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x0801379c` | Modem_ConnInfo_UpdateMeterIP | Modem-Verbindungsinfo: Meter-IP aktualisieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x080138c8` | Ethernet_ConnInfo_UpdateMeterIP | Ethernet-Verbindungsinfo: Meter-IP aktualisieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x08017dc0` | Network_LANDiscovery_SocketInit | Socket für LAN-Discovery initialisieren | Batch 20 | Re-Audit 2026-07-15 |
| `0x080195c8` | Network_Filter_Rule_Init | 16B Filter-Struct: Adresse, Maske, Typ, 0xFFFF | medium | Re-Audit 2026-07-15 |
| `0x0801d2f0` | Protocol_Set_ResponseBytes | Cmd-Byte + 2 Status-Bytes in Response | medium | Re-Audit 2026-07-15 |
| `0x0801df8c` | DNS_Query_Build | DNS Wire-Format: Label-Split auf Dots, 512B | high | Re-Audit 2026-07-15 |
| `0x08026114` | Network_HeartbeatHandler | Öffnet CH395-Socket per Descriptor (Keep-Alive/Heartbeat); erhöht Fehlerzähler (+10) bei Fehlschlag, setzt bei Erfolg State=2 und Fehlerzähler zurück. Aufrufer: Network_ProtocolDispatcher (Modus 1) | high | Re-Audit 2026-07-15 |
| `0x080267e0` | DNS_Name_Decompress | DNS-Namens-Dekompression (Label-Pointer) | high | Re-Audit 2026-07-15 |
| `0x0802c120` | DNS_Query_Send | DNS-Query aufbauen und über CH395 SPI senden | high | Re-Audit 2026-07-15 |
| `0x0802c438` | Ethernet_SendStatusTelemetry | JSON-Status via CH395 Ethernet senden | high | Re-Audit 2026-07-15 |
| `0x0802c52c` | Network_TransportDispatch | Router: 0=Quectel, 1=unknown, 2=CH395, 3=MQTT | high | Re-Audit 2026-07-15 |
| `0x08034f20` | Protocol_Reset_Counter | 16-Bit Feld bei Offset 0x100 clearen; einziger Aufrufer CH395_Init_TCPServer_Socket | medium | Re-Audit 2026-07-15 |
| `0x080491c4` | DNS_ParseResponseHeader | 12B Header + QD Skip + AN Parse, 0 Aufrufer (Fn-Pointer) | high | Re-Audit 2026-07-15 |
| `0x0804b1e6` | DNS_WriteUint16BE | 16-bit Big-Endian Write, 8× von DNS_Query_Build | high | Re-Audit 2026-07-15 |
| `0x0804d4e8` | Network_ReceiveAndDispatchData | Empfängt Bytes über CH395-Ethernet (SPI, Modus-Flag=1) oder FreeRTOS-Queue (Modus-Flag=0) und leitet sie byteweise an CLI_DispatchInputByte weiter — netzwerkbasierte CLI/Konsolen-Schnittstelle; erkennt Ctrl-C (0x03) zum Reset des Log-Levels | high | Re-Audit 2026-07-15 |
| `0x08004888` | Device_Network_Info_Init | Netzwerk-Broadcast-Info initialisieren, ASCII-Validierung (0 direkte Aufrufer laut Ghidra — vermutlich über Funktionstabelle/Init-Sequenz) | medium | Re-Audit 2026-07-14 |

## Quectel-Modem / WiFi / AT-Commands (60)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08004234` | AT_Copy_MPPT_Channel_Data | MPPT-Kanaldaten (SOC/Power/Energy) in AT-Response kopieren | high | Re-Audit 2026-07-14 |
| `0x0800736c` | Quectel_SendCmd_WaitResponse | AT-Befehl senden, Mutex, Response-Pattern matchen | high | Re-Audit 2026-07-14 |
| `0x08007968` | Quectel_AT_QISEND_HexData | Formatiert Nutzdaten als Hex-ASCII (%02X) in AT+QISEND=&lt;id&gt;,&lt;len&gt;-Kommando, sendet via Quectel_AT_SendRaw_WithMutex mit bis zu 3 Wiederholungen (genutzt von Modbus-TCP FC03/FC06-Handlern für Cellular-Response) | high | Re-Audit 2026-07-14 |
| `0x08007a18` | Quectel_AT_SendAndVerify | Core AT-Executor (19 Callers), strstr-Verify | high | Re-Audit 2026-07-14 |
| `0x08007b5c` | Quectel_AT_SendAndPollResponse | AT-Executor mit Tick-basiertem Polling-Timeout | high | Re-Audit 2026-07-14 |
| `0x0800b810` | Quectel_OTA_StartUpdate_AndReboot | Modem-OTA-Update starten und neu starten | high | Re-Audit 2026-07-14 |
| `0x0800b90c` | Quectel_OTA_StartUpdate_FromURL_AndReboot | Modem-OTA-Update von URL starten und neu starten | high | Re-Audit 2026-07-14 |
| `0x0800babc` | Quectel_AT_QVERSION_Query | AT+QVERSION Firmware-Versionsabfrage | high | Re-Audit 2026-07-14 |
| `0x0800bb30` | Quectel_Modem_HardwareReset_Handler | Hardware-Reset des Quectel-Modems durchführen | high | Re-Audit 2026-07-14 |
| `0x0800be00` | Quectel_HTTP_GET_Request | HTTP-GET-Request über Quectel-Modem senden | high | Re-Audit 2026-07-14 |
| `0x0800bfdc` | Quectel_UART_WriteCommand_Guarded | AT-Kommando abgesichert über UART senden | high | Re-Audit 2026-07-14 |
| `0x0800c060` | Quectel_HTTP_ReadResponse | HTTP-Antwort vom Quectel-Modem lesen | high | Re-Audit 2026-07-14 |
| `0x0800c184` | Quectel_HTTP_Config_SSLCtxId | SSL-Kontext-ID für Quectel-HTTP konfigurieren | high | Re-Audit 2026-07-14 |
| `0x0800df04` | Quectel_MQTT_Close_Connection | MQTT-Verbindung über Quectel-Modem schließen | high | Re-Audit 2026-07-14 |
| `0x0800e598` | Quectel_MQTT_Connect | MQTT-Verbindung über Quectel-Modem aufbauen | high | Re-Audit 2026-07-14 |
| `0x0800e684` | Quectel_MQTT_Config_DataType | MQTT-Datentyp am Quectel-Modem konfigurieren | high | Re-Audit 2026-07-14 |
| `0x0800e6f4` | Quectel_MQTT_Unsubscribe | MQTT-Topic-Abo über Quectel-Modem beenden | high | Re-Audit 2026-07-14 |
| `0x0800ebfc` | Quectel_MQTT_Publish_AndWaitAck | MQTT publish über Quectel-Modem, auf ACK warten | high | Re-Audit 2026-07-14 |
| `0x0800ed24` | Quectel_MQTT_Publish_ViaTransportDispatch | MQTT publish über Transport-Dispatch-Schicht | high | Re-Audit 2026-07-14 |
| `0x0800eea0` | Quectel_MQTT_Subscribe | MQTT-Topic über Quectel-Modem abonnieren | high | Re-Audit 2026-07-14 |
| `0x0800f040` | Quectel_MQTT_WaitForAck | Auf MQTT-ACK vom Quectel-Modem warten | high | Re-Audit 2026-07-14 |
| `0x0800f098` | Quectel_MQTT_Config_Version | MQTT-Protokollversion am Quectel-Modem konfigurieren | high | Re-Audit 2026-07-14 |
| `0x0800f108` | Quectel_UDP_OpenSocket | UDP-Socket über Quectel-Modem öffnen | high | Re-Audit 2026-07-14 |
| `0x0800fadc` | Quectel_UDP_ParseRecvURC_IPPort | IP/Port aus UDP-Empfangs-URC parsen | high | Re-Audit 2026-07-14 |
| `0x0800fc3c` | WiFi_Set_Credentials | WiFi SSID+PW via Quectel setzen, EEPROM 0x400/0x420 | high | Re-Audit 2026-07-14 |
| `0x0800fd2c` | Quectel_SSL_Certificate_Manage | AT+QSSLCERT: Upload/Delete/Query/List Zertifikate | high | Re-Audit 2026-07-14 |
| `0x0800fe6c` | Quectel_Send_CertData_WithMutex | Sendet String mit Queue-Mutex-Schutz via Quectel_AT_Send_Cmd, anschließend Delay(param_3). Generischer Sende-Wrapper; Cert-Bezug nur über Debug-String "Cert info: %d, %s" belegt, im aktuellen Disassembly kein direkter Aufrufer gefunden (0 Caller) | medium | Re-Audit 2026-07-14 |
| `0x0800fed4` | Quectel_SSL_Set_CipherSuite | AT+QSSLCFG Cipher-Suite konfigurieren | high | Re-Audit 2026-07-14 |
| `0x080106dc` | Quectel_UART_Send_Data | Thin Wrapper für HAL UART Transmit | medium | Re-Audit 2026-07-14 |
| `0x080106f4` | Quectel_AT_Send_Cmd | Generische UART-Sendefunktion (strlen-Check + UART_TransmitBytes), ohne Mutex/Response-Handling. Basis-Baustein für AT-Befehle, MQTT-Publish-Strings und BLE-GATT-Notify (16 Aufrufer, u.a. alle MQTT_Publish_*-Funktionen) | high | Re-Audit 2026-07-14 |
| `0x08010834` | Quectel_AT_SendRaw_WithMutex | Raw AT-Befehl mit Queue-Mutex senden | high | Re-Audit 2026-07-14 |
| `0x08010904` | Quectel_UART_RxByte_Parser | Byte-Parser für UART-Empfang, \r\n Terminierung | high | Re-Audit 2026-07-14 |
| `0x08010b84` | Quectel_TCP_ConnectionState_Query | AT+QISTATE=&lt;id&gt; abfragen, Antwort auf "+QISTATE: 3" prüfen (Connect-ID-basiert). Wird auch von Quectel_UDP_CommStateMachine zur Abfrage der UDP-Session (ID 3) genutzt — nicht TCP-exklusiv | high | Re-Audit 2026-07-14 |
| `0x08010c04` | Quectel_TCP_SendAndVerify | Zweiter generischer AT-Send+Verify-Kern (eigener Mutex/Buffer, notify-basiert, strstr-Verify auf 2 Muster). 4 Aufrufer bestätigt, davon einer Quectel_UDP_OpenSocket — wird für TCP- UND UDP-Socket-Aufbau verwendet | high | Re-Audit 2026-07-14 |
| `0x08010d40` | Quectel_UDP_DataReceive | UDP-Daten parsen, an MQTT JSON RPC dispatchen | high | Re-Audit 2026-07-14 |
| `0x08010eb0` | Quectel_URC_JsonFrameParser | JSON-Frame-Assembler mit Brace-Depth-Tracking | high | Re-Audit 2026-07-14 |
| `0x08011008` | Quectel_QISEND_SendData_TCP_UDP | AT+QISEND formatieren, 3 Retries | high | Re-Audit 2026-07-14 |
| `0x080110cc` | Quectel_UDP_CommStateMachine | 4-State UDP Lifecycle (Open→Verify→Recv→Close) | high | Re-Audit 2026-07-14 |
| `0x080112d4` | Quectel_URC_LineParser | Sammelt "+"-eingeleitete URC-Zeilen bis \n. Nach Erkennen von "+Q" wird bei drittem Zeichen 'I','W' oder 'G' (also +QIURC/+QWIFI.../+QGxxx) der Puffer verworfen — diese URCs werden von dedizierten Parsern behandelt; nur sonstige +Q*-URCs werden hier komplett gesammelt | high | Re-Audit 2026-07-14 |
| `0x080113b0` | Quectel_AT_SetURCConfig | Sendet "AT+QURCCFG=%d" (einzelner Integer-Parameter, keine gequotete urcport/uart-String-Syntax wie beim Standard-QURCCFG). Kein Aufrufer im Disassembly gefunden (0 Caller) — konkrete Bedeutung von param_1 nicht abschließend verifizierbar | medium | Re-Audit 2026-07-14 |
| `0x08011c94` | Quectel_UART_WriteCommand | Core UART Write: Bytes + \r\n (6 Callers) | high | Re-Audit 2026-07-14 |
| `0x08011f38` | Quectel_WiFi_SetAPConfig | AT+QSTAAPINFODEF, SSID/PW Validierung | high | Re-Audit 2026-07-14 |
| `0x08012068` | Quectel_WiFi_SetSTAInfo_NoSave | WiFi-STA-Info setzen, ohne Speichern | Batch 20 | Re-Audit 2026-07-14 |
| `0x0801219c` | Quectel_WiFi_QueryConnectionState | WiFi-Verbindungsstatus abfragen | Batch 20 | Re-Audit 2026-07-14 |
| `0x0801285c` | Inverter_PVString_ChannelValue_PeriodicCheck_Save | Name korrigiert (2026-07-15, vormals Quectel_SignalQuality_PeriodicCheck_Save) — kein AT/UART/Modem-Bezug; prüft periodisch (500ms) vier PV-String-/MPPT-Kanalwerte sowie ein Statusfeld der Inverter-Telemetrie (Struct 0x20014f40/0x20014e90) gegen einen Schwellwert und speichert bei Änderung einen Konfigurationsparameter (Config_Write_ParamPair). Einziger Aufrufer: MainLoop_Periodic_Tasks, im Umfeld reiner Energie-/Wechselrichter-Funktionen | Batch 20 | Re-Audit 2026-07-14 |
| `0x08013b18` | Quectel_AT_Recv_ByteAssembler | AT-Antwort byteweise zusammensetzen | Batch 20 | Re-Audit 2026-07-14 |
| `0x0801ce8c` | WiFi_Module_RestartStateMachine | 3-State: Trigger→Cmd→Completion (999 Tick Timeout) | medium | Re-Audit 2026-07-14 |
| `0x0801cf1c` | WiFi_HardwareResetSequence | 5-State GPIO-Toggle (Pin 0x400, 30-Tick Intervalle) | medium | Re-Audit 2026-07-14 |
| `0x0801d034` | WiFi_ModuleResetDispatcher | State-Dispatcher: GPIO Clear/HW-Reset/PowerCycle | medium | Re-Audit 2026-07-14 |
| `0x0801d168` | WiFi_ResetWithRecoveryWait | 2-Phasen GPIO-Toggle (0x400) + 300-Tick-Recovery mit Enable-Gate; triggert bei Abschluss ggf. Zustand 4 in verknüpfter State-Struktur. Hinweis: kein Caller im statischen Call-Graph gefunden | medium | Re-Audit 2026-07-14 |
| `0x0801d238` | WiFi_PowerCycleSequence | GPIO 0x400 Power-Cycle + 300 Tick Wait | medium | Re-Audit 2026-07-14 |
| `0x08022b4c` | Quectel_MQTT_OTA_Info_Parser | Parst per MQTT empfangenen "key=value"-String (strtok-Tokenizer) für bis zu 4 Device-Slots (Index über eingebettetes "d"-Feld, 1..4) mit Feldern mod/type/size/crc/url_len/url (URL bis 0xE6 Byte, ggf. über mehrere Tokens zusammengesetzt via strncat). Nach vollständigem Parse-Durchlauf (strtok liefert NULL) werden für jeden befüllten Slot die OTA-Zieldaten per Config_URLSlot_AddressSelect + Flash_EraseAddressRange + Flash_Write_Protected in den Flash geschrieben und zur Verifikation per Flash_Read_Protected zurückgelesen. Kein Caller im Disassembly gefunden (0 Caller), vermutlich Callback/Function-Pointer aus dem MQTT-JSON-RPC-Dispatch | high | Re-Audit 2026-07-14 |
| `0x08024624` | Quectel_AT_Command_Builder | Baut MQTT-Payload im "cd;p1…p7"-Format und sendet ihn wahlweise als Rohdaten (Quectel_Modem_DataSend) oder als AT+QMTPUB-Kommando (Quectel_AT_Send_Cmd) über das Quectel-Modem | high | Re-Audit 2026-07-14 |
| `0x08026b40` | Modem_Response_Dispatch | Wertet Zählertyp aus und routet zu Modem_ParseThreePhaseActivePower / Modem_ParseActivePower / AT_Response_Parser. Wird sowohl vom Modem- (Modem_SendStatusTelemetry) als auch vom Ethernet-Pfad (Ethernet_SendStatusTelemetry) genutzt — transportunabhängig | high | Re-Audit 2026-07-14 |
| `0x08027324` | Quectel_Modem_DataSend | Sendet Rohdaten über Quectel-Modem (MQTT_Client_SendAndReceive); zentrale Sendefunktion für alle 13 MQTT_Publish_*-Aufrufer | high | Re-Audit 2026-07-14 |
| `0x08027394` | Modem_QueueSendMessage | Packt 4 Parameter in eine Queue-Nachricht und sendet sie an die Modem-Sende-Queue; wird von Quectel_AT_Command_Builder per xQueueReceive konsumiert. Aufrufer: Register_WriteValue | high | Re-Audit 2026-07-14 |
| `0x0802c29c` | Modem_SendStatusTelemetry | JSON-Status via Quectel 4G Modem TCP senden | high | Re-Audit 2026-07-14 |
| `0x0802e35c` | AT_Response_Parser | Validiert Prüfsumme (XOR) einer Geräteantwort, extrahiert Geräte-ID/FW-Version/MPPT-Kanaldaten und schreibt sie in die Ausgabestruktur. Default-Zweig von Modem_Response_Dispatch (Zählertyp ≠ EM/EM1) | high | Re-Audit 2026-07-14 |
| `0x0802edfc` | Modem_ParseActivePower | "act_power" aus Modem-Response parsen (1-Phasen) | high | Re-Audit 2026-07-14 |
| `0x0802ee7c` | Modem_ParseThreePhaseActivePower | a/b/c/total_act_power parsen (3-Phasen) | high | Re-Audit 2026-07-14 |

## Inverter / Register / Energie-Logik (94)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08003e54` | SMR_TIC_SelfUse_PowerController | 6-Zustands-Regelschleife für Eigenverbrauchsoptimierung: CT-Leistung vs. Referenzwert, Schwellwert 40W (0x28), Dämpfung /2, States INIT→MEASURE→ADJUST→STABLE→CHECK→SAMPLE; ruft Inverter_Power_Setpoint_Calc. Einziger Aufrufer: CT_PowerSetpoint_Compute bei WorkMode 0x0A | high | Doku (Re-Audit 2026-07-14) |
| `0x0800434c` | Power_Direction_Change_Check | Lade/Entlade-Richtungswechsel mit 10-Tick Debounce | medium | Doku (Re-Audit 2026-07-14) |
| `0x08004490` | Battery_Charge_Power_Limiter | PV-Ertrags-/BMS-Stromlimit-basierte Ladeleistungsbegrenzung (kein SOC-Bezug im Code, fp64, Power_Limit_Clamp) — Details: Analyse §13.4 | high | Doku (Re-Audit 2026-07-14) |
| `0x080051bc` | Register_Address_Range_Check | Registeradresse gegen gültigen Bereich prüfen | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005344` | Battery_Forced_Charge_Check | Prüfung ob Zwangsladung aktiv sein sollte | high | Doku (Re-Audit 2026-07-14) |
| `0x08005860` | MQTT_Credential_Buffer_Decode | Name korrigiert (2026-07-15, vormals Inverter_Register_Buffer_Init): einziger Aufrufer ist MQTT_Connect_And_Subscribe (kein RS485/Register-Bezug). Funktion macht memset+memcpy und ruft Flash_Obfuscated_String_Decode() auf — decodiert einen obfuskierten Flash-String (vermutlich MQTT/TLS-Credential) in einen Puffer für den MQTT-Client-Aufbau | low | Ghidra (Re-Audit 2026-07-14) |
| `0x08005a7c` | Inverter_RegDirty_MarkAll | Setzt oder löscht (abhängig vom Parameter) alle 24 Dirty-Bits im Bitfield via Timeslot_Bitmap_SetClear(0,0x18,param_1) + I2C-Sync — präzisiert 2026-07-14 | high | Doku (Re-Audit 2026-07-14) |
| `0x08005a90` | Inverter_Power_Setpoint_Apply | Power-Sollwert in Register schreiben + Dirty markieren | high | Doku (Re-Audit 2026-07-14) |
| `0x08005abc` | Inverter_RegDirty_Mark_ChgVolt | Dirty-Bit für Charge-Voltage setzen oder löschen (abhängig vom Parameter) — präzisiert 2026-07-14 | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005acc` | Inverter_RegDirty_Mark_DischgVolt | Dirty-Bit für Discharge-Voltage setzen oder löschen (abhängig vom Parameter) — präzisiert 2026-07-14 | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005adc` | Inverter_Sync_Periodic | Name korrigiert (2026-07-15, vormals Inverter_Sync_Init): wird bei jedem Durchlauf aus MainLoop_Periodic_Tasks aufgerufen (kein reines Einmal-Init): bei Erstlauf MarkAll(1), danach laufend Timeslot_ApplyConfigOnSync + Inverter_Apply_BatteryParams + 3000-Tick-WorkMode-Frame + I2C-Sync | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005b7c` | Inverter_RS485_Cmd_WorkMode | RS485-Register 0x06 setzen (Arbeitsmodus) | high | Doku (Re-Audit 2026-07-14) |
| `0x08005ba0` | Inverter_RS485_Cmd_Reset | RS485-Register 0xFF setzen (Reset) | high | Doku (Re-Audit 2026-07-14) |
| `0x08005bc4` | Inverter_Set_Reg_0xFE | RS485-Register 0xFE schreiben | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005be8` | Inverter_RS485_Command_Send | Sendet RS485-Befehl an Inverter: schreibt Register Kat.2/Subindex0 (4B, On-Off) und Kat.2/Subindex1 (8B, Power+Flags) via Register_PackDescriptor/Register_WriteValue. Aufrufer: Grid_Export_Power_Limiter (4x), Write_Handler | high | Doku (Re-Audit 2026-07-14) |
| `0x08005c84` | Inverter_Set_Reg_0x04 | RS485-Register 0x04 schreiben | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005ca8` | Inverter_Set_Reg_0xFB | RS485-Register 0xFB schreiben | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005ccc` | Inverter_Set_OnOff_Reg_0x01 | Inverter Ein/Aus über RS485-Register 0x01 | high | Doku (Re-Audit 2026-07-14) |
| `0x08005d00` | Inverter_RegDirty_Mark_BatteryParams | Name korrigiert (2026-07-15, vormals Timeslot_Bitmap_Set_Slot2): setzt/löscht Bit 2/3 via Inverter_RegDirty_Bitmap_SetClear(2,2,param_1). Einziger Aufrufer Inverter_Apply_BatteryParams (Batterie-Parameter-Dirty-Flag) — kein Zeitplan-/Schedule-Bezug trotz vormaligem Namen "Timeslot" | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005d10` | Inverter_Power_Value_Scale | Leistungswert skalieren für Register-Format: zusätzlich zur Skalierung wird Inverter_PowerSetpoint_DeadbandClamp auf eine Min/Max-Tabelle angewendet, danach Fixpunkt→Float-Konvertierung (VectorSignedToFloat) und zurück — ergänzt 2026-07-14 | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005d74` | Inverter_Set_Schedule_Reg | Zeitplan-Register 0x30-0x3E schreiben | high | Doku (Re-Audit 2026-07-14) |
| `0x08005dd4` | Inverter_RegDirty_Bitmap_SetClear | Name korrigiert (2026-07-15, vormals Timeslot_Bitmap_SetClear): generischer Bitfeld-Setter/-Löscher (beliebiges Register-Dirty-Bit); 8 Aufrufer — kein Zeitplan-/Uhrzeit-Bezug trotz vormaligem Namen "Timeslot" | medium | Doku (Re-Audit 2026-07-14) |
| `0x08005e2c` | Inverter_Set_PowerLimit_Reg_0x58 | Leistungsbegrenzung über Register 0x58 | high | Doku (Re-Audit 2026-07-14) |
| `0x08005e68` | Inverter_Set_Flag_Reg_0x57 | Feature-Flag über Register 0x57 | medium | Doku (Re-Audit 2026-07-14) |
| `0x080060d6` | Inverter_Write_Reg_0x04_U32Value | 32-Bit-Wert in Register 0x04 schreiben (Register_PackDescriptor Kat.4 bestätigt) | high | Doku (Re-Audit 2026-07-14) |
| `0x08006114` | Inverter_Write_Reg_0x03_U32Value | 32-Bit-Wert in Register 0x03 schreiben (Register_PackDescriptor Kat.3 bestätigt) | high | Doku (Re-Audit 2026-07-14) |
| `0x08006152` | Inverter_Clear_Reg_0x13 | Register 0x13 löschen (Register_PackDescriptor Kat.0x13, schreibt 0 bestätigt) | high | Doku (Re-Audit 2026-07-14) |
| `0x080061a0` | Inverter_Set_WorkMode_Reg_0x60 | Arbeitsmodus-Register 0x60 setzen (Register_PackDescriptor Kat.0x60 bestätigt) | high | Doku (Re-Audit 2026-07-14) |
| `0x080061d0` | Inverter_Set_BLEMode_Reg_0x08 | BLE-Modus-Register 0x08 setzen (Register_PackDescriptor Kat.8 bestätigt, Aufrufer BLE_Set_Mode_Persist) | high | Doku (Re-Audit 2026-07-14) |
| `0x080061fc` | Inverter_Power_Setpoint_Calc | Zentrale Leistungssollwert-Berechnung (12 Aufrufer, 28 Referenzstellen). Basis Battery_Charge_Power_Limiter, optionale fp64-Summe aus 4 Struct-Feldern (Offsets 0xC/0x12/0x18/0x1E), Clamp via Power_Limit_Clamp/Inverter_Power_Setpoint_ScaleFactor_Calc, schreibt Register Kat.1 | high | Doku (Re-Audit 2026-07-14) |
| `0x08006488` | Inverter_Set_Flag_Reg_0x06 | Flag-Register 0x06 setzen (Register_PackDescriptor Kat.6 bestätigt; Aufrufer Idle_Watchdog_AutoReboot, Write_Handler, Register_SetFlag_0x06) | high | Doku (Re-Audit 2026-07-14) |
| `0x080064ba` | Inverter_Clear_Reg_0x12 | Register 0x12 löschen (Register_PackDescriptor Kat.0x12, schreibt 0 bestätigt) | high | Doku (Re-Audit 2026-07-14) |
| `0x080064dc` | Inverter_Set_Flag_Reg_0x05 | Flag-Register 0x05 setzen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08006506` | Inverter_Write_Reg_0x07_Value | Wert in Register 0x07 schreiben | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08006530` | Inverter_BatteryParams_Timeslot2_SetClear | Batterie-Parameter Zeitfenster 2 setzen/löschen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08006540` | Grid_Export_Limit_Periodic_StateMachine | Zustandsmaschine für periodisches Netzeinspeise-Limit: Flag-Byte (Offset+0x17 Bit7), 3 States (0/1/2), ruft Inverter_Power_Setpoint_Calc + Grid_Export_Power_Limiter, EventLog_Record_SystemEvent(6,600), 1000-Tick Config_Apply_SingleReg(7). Aufrufer: MainLoop_Periodic_Tasks | high | Doku (Re-Audit 2026-07-14) |
| `0x0800c0b0` | Telemetry_History_Record_Push | Telemetrie-Historieneintrag anhängen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08012f80` | Power_Limit_Clamp | Berechnet fp64-Leistungslimit aus BatteryParams-Struct (Basis SRAM 0x20014F82, Offset 0 × Offset+0x24, Vorzeichen invertiert). Aufrufer: Battery_Charge_Power_Limiter, Grid_Export_Power_Limiter, Inverter_Power_Setpoint_Calc | high | Doku (Re-Audit 2026-07-14) |
| `0x08012ff4` | Inverter_Power_Setpoint_ScaleFactor_Calc | Skalierungsfaktor für Leistungs-Sollwert berechnen (fp64-Multiplikation aus BatteryParams-Struct Offset 0 und Offset+0x28, 3 Aufrufer in Inverter_Power_Setpoint_Calc) | high | Doku (Re-Audit 2026-07-14) |
| `0x08013060` | Schedule_MinMax_PerGroup_Calc | Min/Max je Zeitplan-Gruppe berechnen | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x0801321c` | Meter_CT_GetActiveType | Aktiven CT-Messwandler-Typ ermitteln | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08013254` | Meter_CT_GetStabilizeDelay | Stabilisierungs-Verzögerung für CT-Messwandler ermitteln | Batch 20 | Ghidra (Batch 20, Re-Audit 2026-07-14) |
| `0x08013920` | WorkMode_Modbus_ResponseCache_Refresh | Modbus-Antwort-Cache für Arbeitsmodus aktualisieren (Modbus_Response_Builder, 4×4B-Cache). Einziger Aufrufer: WorkMode_ChangeHandler (am Ende jedes Zweigs) | high | Doku (Re-Audit 2026-07-14) |
| `0x08013cc8` | Inverter_PowerSetpoint_DeadbandClamp | Leistungs-Sollwert mit Totband begrenzen (fp64-Prozentwert aus BatteryParams-Struct, Vorzeichen-/Bereichslogik). Aufrufer: Remote_Power_Setpoint_Process, Inverter_Power_Value_Scale | high | Doku (Re-Audit 2026-07-14) |
| `0x0801d2a8` | Timeslot_ApplyConfigOnSync | Semaphore → Bitmap Apply → Release | high | Doku (Re-Audit 2026-07-14) |
| `0x0801d310` | Register_ToggleBit15 | 16-Bit Register XOR 0x8000 | high | Doku (Re-Audit 2026-07-14) |
| `0x0801e290` | WorkMode_Flag_Reset_And_TriggerSetpointEval | Setzt Pending-Flag zurück; bei gesetztem Broadcast-Flag ODER abgelaufenem 300ms-Timer wird TimePlan_Evaluate_Setpoint() (Sollwert-Neuberechnung) angestoßen — korrigiert 2026-07-14: alte Beschreibung "Connection-Flag löschen, Disconnect triggern" war falsch, kein Connection-/Disconnect-Bezug im Code | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x0801e5dc` | Remote_Power_Command_Execute | Mode 0-3: Zero/Discharge/Charge/SOC-Threshold | high | Doku (Re-Audit 2026-07-14) |
| `0x0801ec38` | Grid_Export_Power_Limiter | Begrenzt Netzeinspeiseleistung; 4 Modi über DAT_0801eea4 (0/1/3, inkl. Spezialfall CT-Typ 5); sendet Ergebnis über bis zu 4 Aufrufe von Inverter_RS485_Command_Send. Aufrufer: MainLoop_Periodic_Tasks, Grid_Export_Limit_Periodic_StateMachine | high | Doku (Re-Audit 2026-07-14) |
| `0x08025d74` | Power_Delta_Detect | Leistungsänderung erkennen (Schwellwert-basiert) | high | Doku (Name-Match, Re-Audit 2026-07-14) |
| `0x08026598` | Register_WriteValue | Zentraler Register-Schreibzugriff (41 Aufrufer verifiziert) | high | Doku (Name-Match, Re-Audit 2026-07-14) |
| `0x080265f0` | Register_WriteCategory0xCE | Schreibt Register-Kategorie 0xCE (Subindex param_4) über Register_PackDescriptor/Register_WriteValue; Sonderfall Subindex 3 mit inkrementellem Flag-Byte. Aufrufer: CAN_Update_WriteData/WriteStatus/WriteEraseInfo | high | Doku (Re-Audit 2026-07-14) |
| `0x08028ebc` | Inverter_Default_Init_Once | Einmalige Inverter-Initialisierung (Flag-geschützt) | high | Doku (Re-Audit 2026-07-14) |
| `0x08029394` | Inverter_Apply_BatteryParams | Batterie-Zellspannungen prüfen, Charge/Discharge Flags setzen; zusätzlich Init-Gate (I2C_SendWorkModeFrame/I2C_SyncChangedRegisters + 15-Tick-Timer), Timeslot2-Bitmap Set/Clear je nach Zellspannungs-Flag, und abschließender Aufruf von Grid_Power_Dynamic_Adjust (150ms-Regelzyklus) — ergänzt 2026-07-14 | high | Doku (Re-Audit 2026-07-14) |
| `0x08029458` | Remote_Power_Setpoint_Process | Protokoll Cmd 0x05, Register-Lookup, Float-Skalierung | high | Doku (Re-Audit 2026-07-14) |
| `0x080295a4` | Grid_Power_Dynamic_Adjust | 150ms Timer, fp64-Skalierung, Frequenz-Schwellen ±15 | high | Doku (Re-Audit 2026-07-14) |
| `0x080297cc` | Runtime_Energy_Counter_Tick | ms-Auflösung Energiemessung (999 Wrap → kWh; Einheit "kWh" im Code selbst nicht verifizierbar, aber keine Gegenbeweise gefunden) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802b9e8` | CT_StatusFlag_Test | CT-Struct Bitmask-Flag testen (Offset +8) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802b9fa` | CT_GetResultValue | CT-Struct Getter (Offset +0xC) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802ba00` | CT_SetResultValue | CT-Struct Setter (Offset +0xC) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802baa4` | CT_GridPower_Controller | Haupt-Regelschleife: CT→WorkMode→Voltage→Power→Setpoint | high | Doku (Re-Audit 2026-07-14) |
| `0x0802bce8` | CT_PowerSetpoint_Compute | Proportional-Regelung, Min/Max-Clamp, Dead-Band (11W/15W) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802bec8` | WorkMode_Register_Write | Arbeitsmodus validieren (<11), über Register_WriteValue schreiben | high | Doku (Re-Audit 2026-07-14) |
| `0x0802bf18` | PowerPercent_Register_Write | Leistungsprozent validieren (<101), über Register_WriteValue schreiben | high | Doku (Re-Audit 2026-07-14) |
| `0x0802c784` | WorkMode_State_Machine | Lade/Entlade-Steuerung: SOC-Schwellen 0x33=51%/0x32=50%, Force-Charge (Mode 5), 60s-Timer-Intervalle, ruft Inverter_Power_Setpoint_Calc 6× für unterschiedliche Zustände. Einziger Aufrufer: CT_GridPower_Controller | high | Doku (Re-Audit 2026-07-14) |
| `0x0802cf68` | Register_ClearOnWrite | Register bei Write-Zugriff auf 0 löschen | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802d484` | CT_SyncTransfer | Synchroner CT-Register-Zugriff mit 0x1000-Iteration Timeout | high | Doku (Re-Audit 2026-07-14) |
| `0x0802d53c` | Inverter_SendOnCommand | Inverter_Set_OnOff_Reg_0x01(1) 2× für Zuverlässigkeit | high | Doku (Re-Audit 2026-07-14) |
| `0x0802d6d0` | Inverter_BeginShutdown | Shutdown-State aktivieren, Inverter_StopOutput aufrufen | high | Doku (Re-Audit 2026-07-14) |
| `0x0802d714` | Inverter_StopOutput | Power=0 + Off — Kern-Shutdown-Primitiv (4 Aufrufer) | high | Doku (Re-Audit 2026-07-14) |
| `0x0802d91c` | Register_Write_PackedAsciiValue_Group0xCC | Schreibt RTC_GetDateTime()-Ergebnis + Parameterbytes in Register Kat.0xCC (Subindex 0+1); nur 1 Byte wird tatsächlich als ASCII-Ziffer kodiert (+'0'), Rest sind Rohbytes — Beschreibung "gepackter ASCII-Wert" nur teilweise zutreffend, s. Re-Audit-Bericht 2026-07-14. Keine Aufrufer im aktuellen Codepfad | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802f0ec` | Telemetry_Store_RegCB | 8B für Cmd 0xCB | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802f104` | Telemetry_Store_Reg54 | 1B für Cmd 0x54 | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802f118` | Telemetry_Store_RegC1 | 1B für Cmd 0xC1 | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802f12c` | Telemetry_Store_RegCE_ByChannel | 4B in Channel 0/2 für Cmd 0xCE | medium | Doku (Re-Audit 2026-07-14) |
| `0x0802f15c` | Telemetry_Store_EnergyCounters | Cmd 0x40-0x43: 4 Energie-Phasen | high | Doku (Re-Audit 2026-07-14) |
| `0x0802f1c0` | Telemetry_Register_Dispatcher | Zentraler Dispatcher (11 Callees), Cmd 0x10-0xCE | high | Doku (Re-Audit 2026-07-14) |
| `0x0802f2b4` | BatteryParams_PowerFlowState_Get | Umbenannt 2026-07-15 (war Telemetry_Timestamp_Get, nachweislich falsch — kein RTC-/Zeit-Zugriff). Liest Disable-Flag (BatteryParams-Struct Basis 0x20014F82, Offset+0xF) und signed short (Offset+2, /10 skaliert), liefert 4-Zustands-Code: 0=disabled, 1=~0 (<1), 2=positiv (>=1), 3=negativ (<0). Aufrufer: MQTT_Telemetry_Struct_Builder, Cloud_Report_FillPowerFlow, BLE_RuntimeInfo_Builder — jeweils als Status-Byte in Telemetrie/Report/BLE eingebettet, konsistent mit Lade-/Entlade-/Leistungsfluss-Status. Physikalische Einheit von Offset+2 nicht abschließend bewiesen. S. Control_FW_Analyse_app_1492_0702_142136.md §13.46 | medium | Deep-Dive 2026-07-15 |
| `0x0802f840` | Energy_Stats_Accumulate_And_Save | 4 Quellen akkumulieren, Datumswechsel-Reset, alle 600 Ticks Flash-Persist | high | Doku (Re-Audit 2026-07-14) |
| `0x0802fb9c` | WorkMode_ChangeHandler | 6 Modi dispatchen (CT/CH395/Remote/etc.), Heartbeat-Reset bei Wechsel | high | Doku (Re-Audit 2026-07-14) |
| `0x08032348` | Register_PackDescriptor | **36 Aufrufer** (korrigiert 2026-07-14, vorher "35 Aufrufer!")! Packt category/subindex/field/flags in 32-Bit | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08034c24` | Battery_Config_Debug_Print | SOC-Cutoffs, Max-Power, Grid-Standard (Debug-Print, 0 Aufrufer im aktuellen Codepfad — vermutlich totes Debug-Feature) | high | Doku (Re-Audit 2026-07-14) |
| `0x08035cac` | MPPT_Debug_Print | PV1-4 V/I/P, Fehler, Temp, Tag/Monat/Jahr Kapazität (Debug-Print, 0 Aufrufer im aktuellen Codepfad) | high | Doku (Re-Audit 2026-07-14) |
| `0x08035ffc` | Inverter_Telemetry_Debug_Print | Druckt 20 Felder des Inverter-Telemetrie-Blocks (Basis SRAM 0x20014E90/0x20036128, 48B) per printf: inv_state, grid_volt, grid_pf, off_grid_volt, bat_sample_power, chrg/dischrg-Energie, hard/soft/boot-Version, work_mode etc. Keine Aufrufer im aktuellen Codepfad (Debug-only) | high | Doku (Re-Audit 2026-07-14) |
| `0x08036698` | Inverter_PowerSetpoint_Apply_Wrapper | Thin Wrapper → Inverter_Power_Setpoint_Apply. 0 Aufrufer/Referenzen im gesamten Binary gefunden (weder Call noch Datenzeiger) — vermutlich toter Code oder nicht aufgelöster indirekter Aufruf — ergänzt 2026-07-14 | high | Doku (Re-Audit 2026-07-14) |
| `0x0804d204` | PowerPercent_WriteCallback | Thin Wrapper → PowerPercent_Register_Write(param_1). Keine Aufrufer im aktuellen Codepfad (vermutlich Callback-Tabelle) | high | Doku (Re-Audit 2026-07-14) |
| `0x0804d76c` | Inverter_SetWorkMode | Setzt Arbeitsmodus (Parameter <6): Inverter_RS485_Cmd_WorkMode(0) + Inverter_Set_WorkMode_Reg_0x60(param_1). Keine Aufrufer im aktuellen Codepfad (vermutlich Callback/API) | high | Doku (Re-Audit 2026-07-14) |
| `0x08050e24` | Register_SetFlag_0x06 | Thin Wrapper → Inverter_Set_Flag_Reg_0x06(1,param_1). Keine Aufrufer im aktuellen Codepfad | high | Doku (Re-Audit 2026-07-14) |
| `0x08050e32` | Register_SetValue_0x07 | Thin Wrapper → Inverter_Write_Reg_0x07_Value(1,param_1). Keine Aufrufer im aktuellen Codepfad | high | Doku (Re-Audit 2026-07-14) |
| `0x080049ec` | Voltage_Stability_Check | Prüft CT-Meterspannung auf Stabilität (Delta<31) mit Timer-Debounce, steuert Freigabe für CT_GridPower_Controller | medium | Re-Audit 2026-07-14 |
| `0x08005500` | Standby_Wakeup_Debounce | Aufwach-Entprellung aus Standby-Modus | medium | Doku |
| `0x080071c4` | Display_Cycle_DataSources | 4-State Round-Robin über 4 Fehler-/Statuswerte, meldet Nicht-Null-Werte via EventLog_Record_DisplayError | medium | Re-Audit 2026-07-14 |
| `0x0801d084` | Relay_StagedTimingControl | Relay/Contactor GPIO Bit15, 3 Timing-Stufen | medium | Doku |
| `0x0802d018` | TimePlan_Evaluate_Setpoint | 10-Slot Zeitplan: Wochentag-Bitmask, Zeitfenster, Power oder Standby | high | Doku |

## Config / EEPROM (59)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0800545c` | EEPROM_Config_Factory_Write | Factory-Reset-Routine: EEPROM-Block 0x3532 (0x22B) mit Werkseinstellungen (0xE6-Pattern) beschreiben, Flash-Region löschen (Flash_EraseAddressRange) und neu programmieren (Flash_Write_Protected); Aufrufer Factory_Reset | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08005e8a` | Config_Param51_Reset | Parameter 0x51 auf 0 zurücksetzen (Register_PackDescriptor+WriteValue); Aufrufer Write_Handler — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08005eac` | Config_WorkMode_Set | Arbeitsmodus über Param-System konfigurieren (Register_PackDescriptor(0x52)+WriteValue); Aufrufer Write_Handler (3x) — Schreibzugriff bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08005ece` | Config_PowerSetpoint_Write | Leistungs-Sollwert in Param-Store schreiben (Register_PackDescriptor(0x56)+WriteValue); Aufrufer Write_Handler (2x) — Schreibzugriff bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08005f0a` | Config_Param53_Activate | Parameter 0x53 auf 1 setzen (Register_PackDescriptor+WriteValue); Aufrufer Write_Handler — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08005f2c` | Config_Param55_Set | Parameter 0x55 setzen (param_1, Register_PackDescriptor+WriteValue); Aufrufer Write_Handler(1) — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08005f50` | Config_Counters_Reset | Zähler-Parameter 0xC1 zurücksetzen (2× Register-Schreibzugriff Subindex 3+4, je 4B=0); Aufrufer Write_Handler — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08005f94` | Config_Feature_Enable | Feature-Aktivierung über Param 0x50 (0x55EE/0x55BB); Aufrufer Write_Handler — Schreibzugriff bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006074` | Config_Conditional_Write | Bedingter Param-Write über 0xC3 (nur falls Flag DAT_080060a4 gesetzt und param_2<9); 0 Aufrufer im aktuellen Codepfad — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x080060ac` | Config_Param0A_Relay | Parameter 0x0A weiterleiten (Register_PackDescriptor(10)+WriteValue); einziger Aufrufer Config_Set_DischargeCutoff_WithRelay — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006174` | Config_Mode_Apply | EPS-Enable/Disable über Register 2 setzen (Param1=Index, Param2=Bool); Aufrufer-Kontext "BLE: Set eps_enable/disable" | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006890` | Config_Factory_Reset | EEPROM Addr 0 löschen, Stats clearen (falls param_1≠0), vor Reboot; einziger Aufrufer FactoryReset_NotifyAndReboot — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800691c` | EEPROM_Mutex_Wait | Wartefunktion nach I2C-Transfer: bei laufendem FreeRTOS-Scheduler Busy-Wait-Schleife (Iterationszahl = DAT_08006940 × param_1), sonst vTaskDelay(param_1); Aufrufer EEPROM_Read/EEPROM_Write | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006944` | Config_Get_Capacity_Factor | Batterie-Kapazitätsfaktor aus Config (Byte 30-100%, Fallback 100 falls außerhalb), als Float skaliert mit DAT_0800697c; einziger Aufrufer CT_PowerSetpoint_Compute — Lesezugriff bestätigt, kein Read/Write-Fehler | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006980` | Config_Get_WorkMode | Work-Mode = 'd'(100) - config_byte; Lesezugriff bestätigt, kein Read/Write-Fehler | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006990` | Config_Get_DeviceModelCode | Geräte-Modellcode: 0xAA-Magic-Byte → gespeicherter Wert, sonst je nach Typ-Byte hardcodierte Codes (0x3F2/0x8AE/0x8AF); Lesezugriff bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080069dc` | EEPROM_Read | Low-Level EEPROM-Lesefunktion (I2C, Mutex-/Queue-geschützt): param_1=Adresse, param_2=Zielpuffer, param_3=Größe; zentrale Primitive für alle Config_Read_*/Get_*-Funktionen (13+ Aufrufer) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006b40` | Config_Read_String_0x388 | String aus EEPROM Offset 0x388 lesen, Null-Terminierung erzwungen; Lesezugriff bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006b62` | Config_Read_ProductionDate | Produktionsdatum aus EEPROM 0x160 (8B DateTime) lesen, Jahr-Korrektur (-2000), Validierung via DateTime_Validate_NoNull; Lesezugriff bestätigt, kein Read/Write-Fehler. Keine Aufrufer im aktuellen Codepfad gefunden | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006ba8` | Config_Notify_Change | Zeitfenster-Konfig (Time-Slot, Index<10, je 10B) bzw. kompletten 100B-Block (Index≥10) nach EEPROM 0x302 persistieren | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006be0` | Config_Save_RuntimeCounters | 52B (0x34) Runtime-Statistiken nach EEPROM 0x500 persistieren; 3 Aufrufer (System_Reboot, Energy_Stats_Accumulate_And_Save, Stats_Clear_Counters) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006bf4` | EEPROM_Write | Low-Level EEPROM-Schreibfunktion (I2C, Mutex-/Queue-geschützt): param_1=Adresse, param_2=Quellpuffer, param_3=Größe; zentrale Primitive für alle Config_Write_*/Save_*-Funktionen (35+ Aufrufer) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006c9c` | Config_Write_U16_0x202 | 16-Bit-Wert (max. 0x9C4/2500) bei Änderung nach EEPROM 0x202 schreiben; Aufrufer Write_Handler, BLE_Recv_Cmd_Dispatcher (Bereichsprüfung 300-2500) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006cd0` | Config_Write_Byte_0x36b | 1-Byte-Wert nach EEPROM 0x36b schreiben, nur falls ≤ Grenzwert aus Config-Struct+8; Aufrufer Cloud_HTTP_Response_Parser, BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006d00` | Config_Write_CapacityFactor | Schreibt 1 Byte (nicht U32), Pendant zu `Config_Get_Capacity_Factor`. Am 2026-07-14 von "Config_Read_U32" umbenannt (alter Name implizierte fälschlich Lesezugriff/U32-Breite) | high | Re-Audit 2026-07-14 |
| `0x08006d2c` | Config_Write_U8 | 1-Byte-Wert (0-4) nach EEPROM 0x369 schreiben, inkl. Fehlerflag-Reset bei vorherigem Fehlerstatus | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006d68` | Config_Write_U16 | 16-Bit-Wert (max. 2500/0x9c4), bei Änderung nach EEPROM 0x204 schreiben | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006d9c` | Config_Write_DischargeCutoffSOC | Entlade-Cutoff-SOC (30-88%), als Komplement gespeichert ('d'-Wert bzw. 0x0c falls 0); Aufrufer MQTT_Config_Command_Handler, Config_Set_DischargeCutoff_WithRelay — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006dd0` | Config_Write_BoolFlag_0x375 | Bool-Flag an EEPROM 0x375 (Feature unklar); einziger Aufrufer BLE_Recv_Cmd_Dispatcher — Schreibzugriff bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006df8` | Config_Save_UserDataBlock | 36B (0x24) User-Datenblock nach EEPROM 0x4000; Aufrufer Config_SaveWithCRC, OTA_InitSlotConfig — bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08006e0c` | Config_Write_WorkingMode | Arbeitsmodus (0-7) nach EEPROM 0x374, nur bei Änderung; einziger Aufrufer Config_Set_WorkMode_Validated — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006e3c` | Config_Write_String_0x388 | String (max. 12 Zeichen + Terminator) nach EEPROM 0x388 schreiben; Aufrufer Cloud_HTTP_Response_Parser, BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006e80` | Config_Write_String | String (max. 12 Zeichen) nach EEPROM 0x376 schreiben, nur bei Längenprüfung <13 und Änderung (strcmp); Aufrufer Cloud_HTTP_Response_Parser, BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006ebc` | Config_Write_ModbusAddr | Modbus-Slave-Adresse nach EEPROM 0x901 + 0xAA-Validity-Marker nach EEPROM 0x902 (nur falls noch nicht gesetzt); einziger Aufrufer Write_Handler — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006ef0` | Config_Write_Flag_0x367 | Bool-Flag (0/1) nach EEPROM 0x367 schreiben; Aufrufer Cloud_HTTP_Response_Parser, BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006f18` | Config_Write_PowerOffset | Signed 16-Bit Leistungs-Offset/Kalibrierung (bereichsbegrenzt) nach EEPROM 899/0x383; Aufrufer Cloud_Handle_SelfCtl_Power, BLE_Recv_Cmd_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006f64` | Config_Write_ValidatedU16_0x36e | Setzt Validity-Marker 0xAA an EEPROM 0x36d und 16-Bit-Wert an EEPROM 0x36e (zwei EEPROM_Write-Aufrufe); Aufrufer Cloud_HTTP_Response_Parser, BLE_Recv_Cmd_Dispatcher | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006f98` | EEPROM_Save_RebootTimestamp | Name korrigiert (2026-07-15, vormals EEPROM_Clear_RebootState): schreibt tatsächlich das aktuelle RTC-Datum/-Uhrzeit (8B, via RTC_GetDateTime) nach EEPROM 0x160 vor System-Reboot — die lokale Null-Initialisierung wird durch den RTC_GetDateTime-Aufruf sofort überschrieben, es wird nichts gelöscht; einziger Aufrufer System_Reboot | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08006fb4` | EEPROM_ReadWrite_Test | EEPROM R/W-Test: 0xFF-Fill-Pattern + Index-Sequenz-Pattern schreiben/lesen, Hex-Dump-Ausgabe; keine Aufrufer im aktuellen Codepfad (Debug-Funktion) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800b660` | EEPROM_Clear_Range | Löscht Quectel-SSL-Zertifikate/-Keys (3× Quectel_SSL_Certificate_Manage mit 500ms-Delays: CA-Cert, User-Cert, User-Key) und ein zusätzliches Config-Byte; Aufrufer Factory_Reset, BLE_Recv_Cmd_Dispatcher. Name "EEPROM" leicht irreführend (eigentlich Quectel-Zertifikatsspeicher-Löschung, nicht EEPROM-Bereich), aber im Kontext Factory-Reset stimmig, kein Rename-Vorschlag | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0801d324` | Config_Apply_WorkModeReg | Mode-Index → Reg 8/9 mappen (via Config_Apply_SingleReg); Aufrufer Config_WorkMode_Apply_Wrapper, BLE_Recv_Cmd_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08026338` | Config_SetUpdateFlag | Update-Flag in RTC-Konfigstruktur setzen; einziger Aufrufer RTC_ConfigClockSource — Cluster-Zuordnung zu Config/EEPROM fraglich (evtl. eher Hardware/RTC-Cluster) | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08027e44` | Config_PostWriteCommit | Flag zurücksetzen + Parameter 0x54 auf 0 schreiben (Commit-Signal nach Write-Sequenz, gleiche Familie wie Config_Param51/53/55) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08028e30` | Config_Graduated_Sync_Retry | Escalating Timer (5s→30s), Config-Sync mit Retry über Config_Apply_SingleReg(10)/(4); einziger Aufrufer Status_Bitfield_Update — bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x0802bef4` | Config_Apply_SingleReg | Einzelnen Byte-Codewert (Kommando-/Status-Code, z.B. 2/4/7/8/9/0xB/0xC/0xA0) über fest vorgegebenes Register schreiben | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802bf44` | Config_Write_ParamPair | Zwei Byte-Params zu 16-Bit konkatenieren, 8B über Register_WriteValue schreiben; einziger Aufrufer Inverter_PVString_ChannelValue_PeriodicCheck_Save — bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x0802bf70` | Config_Write_ResetFlag | Konstante 1 in Register schreiben (Config-Reset-Signal); einziger Aufrufer Write_Handler — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802c034` | Config_Write_Category0xC4 | Register-Handle via 0xC4 holen und Byte schreiben; einziger Aufrufer System_ResetToDefaults — bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x0802cfc8` | Config_Set_WorkMode_Validated | WorkMode validieren (<8) → Config_Write_WorkingMode, sonst printf-Debug-Ausgabe; einziger Aufrufer Config_Set_WorkMode_Wrapper — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d108` | Config_Set_DischargeCutoff_WithRelay | Discharge-Cutoff-SOC schreiben (Config_Write_DischargeCutoffSOC), bei Erfolg Relay-Update triggern (Config_Param0A_Relay); Aufrufer MQTT_JSON_RPC_Dispatcher, BLE_Handle_SetDischargeCutoff — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802fd64` | Config_SaveWithCRC | CRC16 (Modbus) über 0x22 Bytes berechnen, dann Config_Save_UserDataBlock; einziger Aufrufer HTTP_Cloud_Reporting_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08032ed0` | Config_Set_WorkMode_Wrapper | Thin Wrapper → Config_Set_WorkMode_Validated; 0 Aufrufer im aktuellen Codepfad | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0803668c` | Config_WorkMode_Apply_Wrapper | Thin Wrapper → Config_Apply_WorkModeReg; 0 Aufrufer im aktuellen Codepfad | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0804bc68` | EEPROM_I2C_BusRecovery | I2C Bus Recovery (Clock Toggling), "IIC Restore Slave By Clock"-Logmeldung; Aufrufer EEPROM_I2C_WriteBytes, EEPROM_I2C_ReadBytes — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0804d5b0` | EEPROM_ClearSetting_0x900 | Setzt Byte auf 0 und schreibt es nach EEPROM 0x900. Keine Aufrufer im aktuellen Codepfad gefunden | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0804d6ec` | Config_SetLocalApiPort | Lokalen API-Port (16-Bit) nach EEPROM 0x372 schreiben, setzt Status-Byte auf 5 falls nicht bereits 3/4, Debug-printf. Keine Aufrufer im aktuellen Codepfad gefunden | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08050e40` | Config_Apply_SingleReg_0x01 | Einzelnes Register 0x01 aus Config anwenden (Thin Wrapper → Config_Apply_SingleReg(1)); 0 Aufrufer im aktuellen Codepfad | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x08004b24` | Status_Bitfield_Update | Setzt 3 Statusbits aus Fehler-/Zustandsflags und triggert Config_Graduated_Sync_Retry | medium | Re-Audit 2026-07-14 |
| `0x080068ac` | Stats_Clear_Counters | 0x34B Statistik-Struktur löschen (3 Modi) | high | Doku |

## OTA / Flash / SPI-Flash / QSPI (63)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08000294` | Flash_ReadWords | Flash-Controller konfigurieren, Wörter aus internem Flash lesen (Rückgabe 0x5A5A5A5A Sentinel bei Erfolg); Aufrufer Flash_ReadWithECC (1x direkt + Callee) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08000358` | Flash_ReadWithECC | Flash-Read mit ECC-Prüfung (Flash_ReadWords/Mem_CopyWords_Aligned je nach ECC-Modus) und XOR-Validierung der ECC-Wörter; 0 Aufrufer im aktuellen Codepfad | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08004918` | OTA_Is_VNSD_Model | Prüft via strstr ob Modellstring "VNSD_0" enthält; einziger Aufrufer BLE_Cmd_OTA_Validate — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08004da4` | OTA_CRC_Verify | **CRC-16** (Modbus) Prüfung eines FW-Blocks — **korrigiert 2026-07-14**: bisher fälschlich als CRC-32 dokumentiert; ruft QSPI_Flash_CalculateCRC → CRC16_Calculate (Init 0xFFFF), Vergleich maskiert mit & 0xffff | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08004e04` | OTA_Slot_Config_Validate | 4 OTA-Slots à 251B (0xfb) validieren: Modellstring (strstr "VNSD_0"), Typ 1-4, CRC/Adress-Pflichtfelder; Rückgabe 0=OK, sonst Fehlercode; einziger Aufrufer OTA_Update_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08004efc` | OTA_FW_Verify_SetStatus | OTA-Firmware-Verifikation: CRC-Check (Modbus-CRC via OTA_QSPI_ReadRegion_CalcCRC) + dev_mask-Validierung + Gerätetyp-String-Vergleich ("VNSD-0" via strstr); setzt Slot-Status 0x401=CRC-Fehler/0x402=dev_mask-Mismatch/0x403=Erfolg via OTA_Set_SlotStatus; Aufrufer OTA_Flash_Page_Writer | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0800577c` | OTA_Process_Pending_Updates | Pending-Slots (Status 0x02) verarbeiten (ProcessFirmwareUpdateCommand je Slot) und danach alle Timer stoppen (OTA_StopAllTimers); einziger Aufrufer OTA_Update_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080058cc` | Flash_Obfuscated_String_Decode | Obfuskierte Strings aus internem Flash dekodieren (Modular-LUT via DAT_080058dc, Flash_ReadWords als Sentinel-Quelle); Aufrufer sscanf_Format_Parser (12x als Getc-Callback), MQTT_Credential_Buffer_Decode | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080077f4` | Flash_ErasePage | Flash-Seite löschen (PER+STRT-Bits, 2x Flash_WaitReady mit Timeout 0xb0000); einziger Aufrufer Flash_EraseRegion — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08007848` | Flash_GetStatusFromFlags | FLASH_SR Bits (Offset+0xc) in Statuscodes 1/3/4/5/6/7 dekodieren; Aufrufer Flash_WaitReady (2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08007898` | Flash_Lock | Flash-Controller verriegeln (LOCK Bit 0x80 setzen); Aufrufer Flash_EraseRegion, Flash_WriteRegion (je 2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080078ac` | Flash_ProgramWord | 32-Bit Wort in internen Flash programmieren (4-Byte-Alignment-Check, PG-Bit, 2x Flash_WaitReady); einziger Aufrufer Flash_WriteRegion — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08007908` | Flash_Unlock | Flash-Controller entriegeln (2-Key-Sequenz in CR-Register); Aufrufer Flash_EraseRegion, Flash_WriteRegion — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08007920` | Flash_WaitReady | Flash-Status pollen (Flash_GetStatusFromFlags) mit konfigurierbarem Timeout-Zähler; Aufrufer Flash_ErasePage (2x), Flash_ProgramWord (2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08012d94` | QSPI_Flash_QuadRead_ByteLoop | Byteweise Lese-Subroutine von QSPI_Flash_QuadRead: pollt Transfer-Ready und liest Datenregister byteweise in Zielpuffer | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08012dbc` | QSPI_Flash_IsBusy | QSPI-Flash Busy-Status prüfen (Peripherie-Offset+0x28, Bit 0); einziger Aufrufer QSPI_WaitBusyDone — bestätigt | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x08012dd4` | QSPI_TransferReady_Poll | QSPI-Transfer-Bereitschaft abfragen (Peripherie-Offset+0x28, Bit 3); 4 Aufrufer (QSPI_Flash_QuadRead_ByteLoop, QSPI_TransferWords, QSPI_SendAndReceive, Retry_Until_Success_Or_Limit) — bestätigt | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x08012dec` | QSPI_WriteComplete_Check | QSPI-Schreibvorgang auf Abschluss prüfen (Peripherie-Offset+0x28, Bit 1 gelöscht); einziger Aufrufer SPI_Flash_QuadPageProgram — bestätigt | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x08012f3c` | OTA_QSPI_ReadRegion_CalcCRC | QSPI-Bereich lesen: berechnet CRC16 (QSPI_Flash_CalculateCRC) UND separate Checksumme (SPI_Flash_MutexTransaction) über denselben Bereich, beide Werte in Output-Parametern; einziger Aufrufer OTA_FW_Verify_SetStatus — bestätigt | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x08013f42` | SPI_Flash_DataChecksum_Calc | Einfache Byte-Summen-Prüfsumme (+1) über SPI-Flash-Daten berechnen; einziger Aufrufer SPI_Flash_MutexTransaction — bestätigt | Batch 20 | Ghidra (Re-Audit 2026-07-14) |
| `0x080151c8` | OTA_Update_Dispatcher | OTA-Ablauf: Pending-Updates verarbeiten, Slot validieren, Summary bauen, Firmware-Download starten, Shutdown vorbereiten, Watchdog+Retry-Handler; einziger Aufrufer App_MainLoopDispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080189f8` | OTA_Slot_Config_Summary_Build | 4 Slots Config (je 0xfb B) in kompakten Summary-Buffer (je 0x14 B) kopieren, inkl. Ziel-Adress-Lookup über 4-Eintrags-Tabelle; einziger Aufrufer OTA_Update_Dispatcher — bestätigt | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08018ad4` | OTA_Firmware_Download_Init | OTA Download: nächsten offenen/fehlerhaften Slot suchen, Runtime-Buffer initialisieren, Ziel-Flash-Adresse ermitteln, Flash_EraseAddressRange auf 0x7D000; Aufrufer OTA_Update_Dispatcher, OTA_Download_Retry_Handler (2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08019650` | Flash_EraseRegion | Flash-Pages löschen (0x800B/Page, sektorweise über Flash_ErasePage), kein Signatur-Check, nur Adressbereich>=0x8000000; einziger Aufrufer ProcessFirmwareUpdateCommand — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080196f8` | Flash_WriteRegion | Flash wortweise beschreiben via Flash_ProgramWord (Byte→Word-Zusammenbau via CONCAT), nur Adressbereich>=0x8000000; einziger Aufrufer ProcessFirmwareUpdateCommand — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08026140` | OTA_ValidateUrlSlots | Prüft 4 OTA-URL-Slots (251B) auf Gültigkeit (Pflichtfelder Offset 0/9/0xa/0xb/0xd/0x11/0x15); bei ungültigen Daten Flash-Re-Init (Read→Erase→Write). Kein Caller im Binary gefunden — Verwendung unklar | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x08026704` | OTA_WriteDataToRingBuffer | OTA-Daten in 5-Slot-Ringpuffer (je 0x800B) schreiben, teilt große Payloads über Slot-Grenzen auf, verwaltet Schreibindex/Slot-Voll-Flags; Aufrufer HTTPS_POST_ReceiveResponseData (3x) — Name bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080273b4` | SPI_Flash_PeripheralEnable | SPI/QSPI-Peripherie-Enable-Bit setzen/löschen (2 Register); Aufrufer QSPI_ConfigureMode (4x) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080273dc` | QSPI_Controller_Reset | QSPI-Controller-Reset via RCC_AHBPeriphResetCmd (Assert+Deassert); Aufrufer QSPI_ConfigureMode (4x) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080273f4` | SPI_Flash_ConfigGPIO | GPIO-Pins für SPI/QSPI-Modus konfigurieren (4 Modi 0-3: Single/Dual/Quad-Varianten), inkl. RCC-Clock-Enable und Pin-Modus (Input/AF); Aufrufer QSPI_ConfigureMode (4x) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802760c` | SPI_Flash_ClockGateControl | QSPI-Clock-Gate-Bit setzen/löschen; Aufrufer QSPI_ConfigureMode | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027630` | SPI_Flash_WriteEnableCheck | Prüft/setzt Write-Enable-Latch-Bit im Flash-Status-Register (Cmd-Sequenz via QSPI_TransferWords), pollt bis Ready via QSPI_Flash_PollStatusReady; Aufrufer SPI_Flash_QuadPageProgram | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027678` | SPI_Flash_SectorErase | Flash-Sektor löschen: Cmd 0x06 (Write-Enable) + Cmd 0x20 (Sector-Erase, 24-Bit-Adresse) via QSPI_TransferWords, Busy-Wait + Retry + Status-Poll; einziger Aufrufer Flash_EraseAddressRange (Sektor-Schleife) — Name bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080276c0` | SPI_Flash_QuadPageProgram | Quad Page Program (Cmd 0x32, max. 256B/Aufruf): Write-Enable-Check, Adresse+Daten byteweise über QSPI_WriteComplete_Check-Polling senden; einziger Aufrufer Flash_Write_Protected (9x, für Page-Aufteilung) — Name bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080277a4` | QSPI_Flash_QuadRead | Quad-Read (Cmd 0x6B) aus externer Flash: Adresse senden, 0x100 Ticks Delay, byteweises Lesen via QSPI_Flash_QuadRead_ByteLoop; einziger Aufrufer Flash_Read_Protected — Name bestätigt, kein Read/Write-Fehler | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080277e0` | QSPI_Flash_PollStatusReady | Flash Status-Register pollen bis Ready (max. 200× mit 1ms-Delay via QSPI_TransferWords); Aufrufer SPI_Flash_SectorErase, SPI_Flash_WriteEnableCheck, SPI_Flash_QuadPageProgram | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802781c` | QSPI_SendCommandIrqSafe | Sendet 1-Byte-Kommando + Datenwort per IRQ-gesperrter QSPI_SendAndReceive-Transaktion, pollt danach Busy-Status; Aufrufer SPI_Flash_SectorErase, SPI_Flash_QuadPageProgram | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027834` | QSPI_ConfigureMode | QSPI-Modus konfigurieren (Parametersatz je Modus 0-3+ für Write/Read/CRC/Quad), baut lokale Register-Konfig-Struktur und ruft QSPI_Controller_Reset, SPI_Flash_ConfigGPIO, QSPI_ApplyRegisterConfig, SPI_Flash_PeripheralEnable etc.; 6 Aufrufer (SPI_Flash_SectorErase, QSPI_Flash_CalculateCRC, SPI_Flash_MutexTransaction, Flash_Read_Protected, QSPI_Flash_QuadRead, SPI_Flash_QuadPageProgram) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027a44` | QSPI_ApplyRegisterConfig | QSPI-Register-Konfiguration anwenden: verodert Struct-Felder (Timing/Modus/Adressgröße/Datengröße) in die QSPI-Peripherieregister, Sonderpfad für erweiterte Konfig bei Wert 0x400000/0x800000; einziger Aufrufer QSPI_ConfigureMode (4x) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027b94` | QSPI_ReadDataRegister | Liest QSPI-Datenregister (Peripherie-Offset +0x60), 1-Zeilen-Funktion; 4 Aufrufer (QSPI_TransferWords, QSPI_SendAndReceive, Retry_Until_Success_Or_Limit, QSPI_Flash_QuadRead_ByteLoop) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027ba0` | QSPI_TransferWords | Schreibt param_3 Wörter ins QSPI-Datenregister, pollt Transfer-Ready (200 Iter.) + Wortzähler-Register, liest dann Antwortwörter zurück in param_2; Aufrufer SPI_Flash_WriteEnableCheck, SPI_Flash_SectorErase, QSPI_Flash_PollStatusReady | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027bfc` | QSPI_WriteDataRegister | Schreibt QSPI-Datenregister (Peripherie-Offset +0x60), 1-Zeilen-Funktion; 6 Aufrufer (QSPI_Flash_CalculateCRC, QSPI_TransferWords, QSPI_SendAndReceive, Flash_Read_Protected, QSPI_Flash_QuadRead, SPI_Flash_MutexTransaction) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027c08` | QSPI_SendAndReceive | Sendet 1 Wort über QSPI_WriteDataRegister, liest sofort Antwort; falls param_3≠0 zusätzlich Poll auf Transfer-Ready (200 Iter.) und zweite Leseantwort; Rückgabe 1=Erfolg/0=Timeout; einziger Aufrufer QSPI_SendCommandIrqSafe | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027c44` | QSPI_Flash_CalculateCRC | Mutex-geschützt: berechnet CRC-16 (Modbus, via CRC16_Calculate) über QSPI-Flash-Bereich — **korrigiert 2026-07-14**: Algorithmus ist CRC-16, nicht allgemein "CRC" | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027cf0` | SPI_Flash_MutexTransaction | Mutex-geschützte Checksummen-Transaktion über QSPI-Flash-Bereich: Queue-Lock (1000 Ticks Timeout), QSPI_ConfigureMode(3), Delay 3ms, SPI_Flash_DataChecksum_Calc, Rückschaltung auf QSPI-Modus 2 + Dummy-Write 0xFF, Unlock; einziger Aufrufer OTA_QSPI_ReadRegion_CalcCRC | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027d9c` | Flash_SelfTest | Flash-Selbsttest an fester Adresse 0x3F0000: Erase→Pattern-Write (0-0x1D)→Read→byteweiser Vergleich→abschließendes Erase; Rückgabe 0=OK/1=Fehler. Keine Aufrufer im aktuellen Codepfad gefunden | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080292b8` | OTA_Set_SlotStatus | Status pro Slot (max 4) setzen, Codes 0x400-0x404, optional zusätzliches Detail-Wort; 4 Aufrufer (Comm_Watchdog_CheckTimeout, OTA_FW_Verify_SetStatus 3x, CAN_UpdateResultHandler 2x, OTA_Firmware_Download_Init) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08029594` | OTA_FlashPageWrite_Counter_Increment | Zähler bei Offset +8 inkrementieren  — **korrigiert 2026-07-09**, s. Batch 18; einziger Aufrufer OTA_Flash_Page_Writer — Re-Audit bestätigt unverändert | medium | Ghidra (Re-Audit 2026-07-14) |
| `0x0802b6ec` | Flash_Read_Protected | Mutex-geschützter Lesevorgang aus externem QSPI-Flash (via QSPI_Flash_QuadRead, Cmd 0x6B), Timeout 1000 Ticks auf Mutex-Erwerb | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802b774` | Flash_Write_Protected | Mutex-geschützter Schreibvorgang in externen QSPI-Flash; teilt Daten automatisch an 256B-Page-Grenzen auf (Cmd 0x32 via SPI_Flash_QuadPageProgram) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802b8cc` | Flash_EraseAddressRange | Löscht Flash-Adressbereich [param_1, param_1+param_2) sektorweise (via SPI_Flash_SectorErase, 0x1000-Grenzen aus Flash_AddressToPage), Mutex-geschützt (Queue, 1000 Ticks Timeout); nur gültig für Adressen <0x400000; 9 Aufrufer u.a. EEPROM_Config_Factory_Write, OTA_Firmware_Download_Init, Flash_SelfTest | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802b984` | Flash_AddressToPage | Flash-Adresse → Page-Nummer: (addr & 0x0FFFFFFF) >> 12 (4KB-Pages); Aufrufer Flash_EraseAddressRange (2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d550` | OTA_StopAllTimers | 10 Software-Timer (xTimerStop_Internal) stoppen, dann Shutdown-Flag setzen (Shutdown_SetPendingFlag); einziger Aufrufer OTA_Process_Pending_Updates — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d5ec` | OTA_PrepareShutdown | Inverter-Shutdown einleiten (Inverter_BeginShutdown), OTA-State-Byte konfigurieren, je nach param_1 Queue-Sync (xQueueReceive/Send) oder direktes Timer-Stoppen, weitere 3 Timer stoppen; einziger Aufrufer OTA_Update_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d6a8` | OTA_InitSlotConfig | Einmalige OTA-Config-Initialisierung (0x24B memset + Config_Save_UserDataBlock, Flag-geschützt); einziger Aufrufer OTA_Firmware_Download_Init — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802d86c` | OTA_Download_Retry_Handler | 4 Slots, max 2 Retries, ruft bei Bedarf OTA_Firmware_Download_Init (2x im Code); einziger Aufrufer OTA_Update_Dispatcher — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802f730` | OTA_Flash_Prepare_ByTarget | 4 Targets: EMS(0x80000, Byte-Wert 0), MPPT(0x100000, Byte-Wert 2), BMS(0x180000, Byte-Wert 3), VNS(0x200000, Byte-Wert 4), je 512KB (0x7D000 Erase-Länge); einziger Aufrufer BLE_Cmd_OTA_WriteSetup — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802fc78` | QSPI_WaitBusyDone | 20× Poll (initial 5ms, dann je 50ms) über QSPI_Flash_IsBusy, 4 Aufrufer (SPI_Flash_WriteEnableCheck 2x, QSPI_SendCommandIrqSafe, SPI_Flash_SectorErase, QSPI_Flash_QuadRead) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0802fdec` | OTA_Flash_Page_Writer | 2KB-Pages aus RAM-Ringpuffer→externem Flash (Flash_Write_Protected), 5-Slot Circular, ruft bei vollständigem Transfer **OTA_FW_Verify_SetStatus** (Beschreibung korrigiert 2026-07-14: alter Funktionsname "OTA_FW_Verify_And_Apply" existiert nicht mehr/war veraltet); 0 Aufrufer im aktuellen Codepfad (vermutlich Timer-Callback) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08034cfc` | Flash_Address_To_PageIndex | (addr & 0x7FFFFFF) >> 11 (2KB Pages); Aufrufer Flash_EraseRegion (2x) — bestätigt | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08034d08` | Flash_ReadWriteErase_SelfTest | Flash Write→Read→Verify→Erase Selbsttest (0x1e Bytes Pattern, Hex-Dump je Schritt); 0 Aufrufer im aktuellen Codepfad (Debug-Funktion) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08001814` | ProcessFirmwareUpdateCommand | FW-Update-Kommandos (Typ 1-4): Flash-Write, Metadaten, Reboot | medium | Doku |
| `0x080054e0` | Retry_Until_Success_Or_Limit | Retry-Schleife bis Erfolg oder Limit erreicht | medium | Doku |

## Hardware / HAL (GPIO,ADC,SPI,I2C,USART,RCC,RTC,...) (84)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080001f8` | FPU_EnableCoprocessorAccess | SCB->AIRCR Priority-Grouping-Feld setzen  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x08001fb6` | RCC_BackupDomainReset_Pulse | Pin set+clear (Pulse) über Wrapper | low | Doku |
| `0x08002014` | I2C_BitBang_Delay | Busy-Wait 150 Iterationen (Timing für Bit-Bang) | high | Doku |
| `0x08002024` | I2C_BitBang_WriteByte | MSB-first Byte über GPIO senden (SDA=Pin2, SCL=Pin1) | high | Doku |
| `0x0800207c` | I2C_BitBang_Start | I2C START-Condition generieren | high | Doku |
| `0x080020b0` | I2C_BitBang_Stop | I2C STOP-Condition generieren | high | Doku |
| `0x080020d8` | I2C_BitBang_ReadBit | SDA high, SCL togglen, SDA-Bit lesen | high | Doku |
| `0x080028ec` | I2C_Init_Configure | Hardware-I2C Init (CR, CCR Register), 0 Callers | high | Doku |
| `0x0800468c` | CH395_Packet_Receive_Parse | 2KB Ringpuffer, 6 Pakettypen, XOR-Checksum, keine Auth | high | Doku |
| `0x080077e4` | Flash_SR_ClearFlags | RCC-Register Bits setzen für Peripheral-Clocks | high | Doku |
| `0x08012a04` | AFIO_PinRemapConfig | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08012c54` | GPIO_ConfigPin_ModeCNF | GPIO-Pin Modus/CNF-Bits konfigurieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08012ed0` | RTC_GetDateTime | Datum/Uhrzeit aus RTC lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08013e94` | RTC_TimeOfDay_To5MinSlotIndex | Tageszeit in 5-Minuten-Zeitfenster-Index umrechnen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080172a0` | EEPROM_I2C_CheckStatusFlags | I2C-Status-Flags für EEPROM-Zugriff prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080172ca` | EEPROM_I2C_SetAckEnable | I2C ACK-Bit aktivieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080172e4` | EEPROM_I2C_PeripheralReset | I2C-Peripherie zurücksetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0801731c` | EEPROM_I2C_SetPeripheralEnable | I2C-Peripherie aktivieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017334` | EEPROM_I2C_SetStartCondition | I2C Start-Bedingung setzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0801734c` | EEPROM_I2C_SetStopCondition | I2C Stop-Bedingung setzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017364` | EEPROM_I2C_ConfigureClockTiming | I2C-Takt-Timing konfigurieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017450` | EEPROM_I2C_ReadDataRegister | I2C-Datenregister lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017458` | EEPROM_I2C_SendSlaveAddress | I2C Slave-Adresse senden | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0801746a` | EEPROM_I2C_WriteDataRegister | I2C-Datenregister schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017470` | EEPROM_I2C_ReadBytes | Mehrere Bytes über I2C von EEPROM lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080175f0` | EEPROM_I2C_WriteBytes | Mehrere Bytes über I2C zu EEPROM schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0801771c` | EEPROM_I2C_ClockDisable_Reset | I2C-Takt deaktivieren und zurücksetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0801773c` | EEPROM_I2C_GPIO_ClockPulseRecovery | I2C-Bus-Recovery über GPIO-Taktimpulse | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017888` | SPI_Timer_GPIO_ChipSelect_Init | SPI Chip-Select GPIO/Timer initialisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080178bc` | SPI2_Peripheral_Init | ADC-Peripherie initialisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08017ed4` | EEPROM_I2C_Peripheral_Init | SPI GPIO + Timer Prescaler/Period konfigurieren | medium | Doku |
| `0x080275ec` | GPIO_ConfigPinAsInput | Wrapper um GPIO_ConfigPin_ModeCNF; konfiguriert einen Pin fix als Eingang (CNF=3, MODE=0) — **Re-Audit 2026-07-14** | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027edc` | RCC_HSEConfig | High-Speed External Oszillator konfigurieren | high | Doku (Name-Match) |
| `0x08027f28` | RCC_LSEConfig | Low-Speed External Oszillator konfigurieren | high | Doku (Name-Match) |
| `0x08027f5c` | RCC_RTCClkSourceConfig | RTC Clock-Quelle auswählen | high | Doku (Name-Match) |
| `0x08027f78` | RCC_AHBPeriphClockCmd | AHB Peripheral Clock Enable/Disable | high | Doku (Name-Match) |
| `0x08027f98` | RCC_AHBPeriphResetCmd | AHB Peripheral Reset (RCC_AHBRSTR, Bit-Set/Clear je nach param_2) — **Re-Audit 2026-07-14** | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027fb8` | RCC_APB1PeriphClockCmd | APB1 Peripheral Clock Enable/Disable | high | Doku (Name-Match) |
| `0x08027fd8` | RCC_APB1PeriphResetCmd | APB1 Peripheral Reset (RCC_APB1RSTR, Bit-Set/Clear je nach param_2) — **Re-Audit 2026-07-14** | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08027ff8` | RCC_APB2PeriphClockCmd | APB2 Peripheral Clock Enable/Disable | high | Doku (Name-Match) |
| `0x08028018` | RCC_PeriphBitControl | APB2 Peripheral Reset (RCC_APB2RSTR, Offset +0xC, Bit-Set/Clear) — funktional analog zu RCC_APB1PeriphResetCmd, u.a. für SPI1RST genutzt — **Re-Audit 2026-07-14** | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08028038` | RCC_BDCR_BDRST_Write | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08028044` | RCC_LSICmd | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x08028050` | RCC_RTCCLKCmd | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0802805c` | RCC_GetClocksFreq | System-Taktfrequenzen auslesen | high | Doku (Name-Match) |
| `0x08028168` | RCC_GetFlagStatus | Liest RCC-Statusflag (CR/BDCR/CSR je nach Flag-Kodierung), verifiziert gegen Standard-Konstanten HSERDY(0x31)/LSERDY(0x41)/LSIRDY(0x61) — **Re-Audit 2026-07-14** | high | Ghidra (Re-Audit 2026-07-14) |
| `0x080281a4` | RCC_WaitForHSEStartUp | HSE-Startup abwarten mit Timeout | high | Doku (Name-Match) |
| `0x080281dc` | RTC_BcdToByte | BCD → Binär Konvertierung | high | Doku (Name-Match) |
| `0x080281f2` | RTC_ByteToBcd | Binär → BCD Konvertierung | high | Doku (Name-Match) |
| `0x08028210` | RTC_ConfigClockSource | RTC Clock-Source konfigurieren | high | Doku (Name-Match) |
| `0x08028404` | RTC_SetTime | RTC-Datum setzen (WPR Unlock 0xCA/0x53) | high | Doku (Name-Match) |
| `0x080285c4` | RTC_EnterInitMode | RTC Init-Modus betreten | high | Doku (Name-Match) |
| `0x08028614` | RTC_ExitInitMode | RTC Init-Modus verlassen | high | Doku (Name-Match) |
| `0x08028628` | RTC_GetDate | RTC-Uhrzeit auslesen | high | Doku (Name-Match) |
| `0x08028674` | RTC_GetTime | RTC-Datum auslesen | high | Doku (Name-Match) |
| `0x080286c4` | RTC_WriteAlarmRegisters | RTC Alarm-Register schreiben | high | Doku (Name-Match) |
| `0x08028728` | RTC_InitAlarm | RTC Alarm initialisieren | high | Doku (Name-Match) |
| `0x08028750` | RTC_SetDate | RTC-Uhrzeit setzen | high | Doku (Name-Match) |
| `0x080288f0` | RTC_WaitForSynchro | RTC-Synchronisierung abwarten | high | Doku (Name-Match) |
| `0x0802b6d4` | SPI_Cmd | Const-Flag (Bit 0x40) setzen/löschen  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0802b990` | SPI_DeInit | RCC-Reset für 3 Peripherie-Basisadressen  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0802ba04` | SPI_Init | 8 Kanäle ORen, Bits 0x3040 preserven, 0x0800 clearen | medium | Doku |
| `0x0802ba40` | SPI_SSOutputCmd | Bit 2 setzen/löschen (Single/Scan-Modus) | medium | Doku |
| `0x0802ced8` | RTC_SetDateTime | Datum/Zeit validieren, HAL_RTC_Set*, Mutex-geschützt | high | Doku |
| `0x0802d9b4` | SysTick_Enable_ClockSource | NVIC SysTick Bit 2 (CLKSOURCE) setzen | high | Doku |
| `0x0802d9e0` | GPIO_TogglePin_Periodic | GPIO-Pin periodisch umschalten | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0802de9e` | UART_CheckStatusFlag | Status-Register Bitmask-Test (4 Aufrufer, Mask 0x80=TXE) | high | Doku |
| `0x0802deb8` | NVIC_GetIRQEnableStatus | IRQ-Enable-Bit aus ISER-Register lesen | high | Doku |
| `0x0802df0c` | USART_Init | CR1/CR2/CR3 + BRR-Berechnung, Standard STM32 | high | Doku |
| `0x0802dfca` | USART_SendData | 9-Bit Wert in USART_DR schreiben (4 Aufrufer) | high | Doku |
| `0x0802fa84` | UART_TransmitBytes | Byte-weise UART-Senden mit 5000-Tick TX-Poll | high | Doku |
| `0x0802facc` | SysTick_ComputeTickPeriod | Reload-Wert aus Clock-Divider berechnen | high | Doku |
| `0x0802fb04` | SysTick_WaitTicks | SysTick-Register pollen bis COUNTFLAG | high | Doku |
| `0x0802fb50` | SysTick_DelayMs | Chunked ms-Delay über SysTick_WaitTicks | high | Doku |
| `0x0802fdb8` | I2C_BitBang_WriteBytes | Vollständige I2C-Write-Transaktion (Start/WriteByte×N/ReadBit×N/Stop) über GPIOC-Bitbang; Aufrufer sind `I2C_SendWorkModeFrame` und `I2C_SyncChangedRegisters` (0x0802c5b0). **Beschreibung korrigiert 2026-07-14** (alte Aufrufer-Angabe "CAN_SendWorkModeFrame" war veraltet/falsch — Funktion heißt im aktuellen Ghidra-Stand bereits I2C_SendWorkModeFrame, kein CAN-Bezug) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x08032324` | Peripheral_SetBit15 | Bit 0x8000 auf Peripherie-Register setzen/löschen | medium | Doku |
| `0x080364a4` | GPIOD_Pin9_Write | Setzt/löscht GPIOD Pin9 (0x40011400, Bit9) via BSRR/BRR — reiner GPIO-Pin-Write, Name korrekt. **Beschreibung korrigiert 2026-07-14** (alte Beschreibung "MPU/Flash Region Protection" war falsch, kein Bezug zu MPU/Flash-Registern) | high | Ghidra (Re-Audit 2026-07-14) |
| `0x0804bc00` | RTC_CalcDayOfWeek | Arithmetische Wochentag-Berechnung (1-7, 7=So) | high | Doku |
| `0x0805452c` | SPI_ReadByte | Einzelnes Byte über SPI lesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08055120` | SPI_BeginCommand | SPI-Kommando-Übertragung starten | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805514c` | SPI_WriteByte | Einzelnes Byte über SPI schreiben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08000268` | Get_ActiveIRQn | Liest aktive Exception-/IRQ-Nummer aus IPSR, nur im privilegierten Modus (sonst 0), maskiert auf 5 Bit — einziger Aufrufer FreeRTOS-Portschicht (vPortValidateInterruptPriority) | high | Re-Audit 2026-07-14 |
| `0x08004c7c` | DateTime_Validate | Datum/Zeit-Felder auf Gültigkeit prüfen | high | Doku |
| `0x08005230` | DateTime_Validate_NoNull | DateTime-Validierung OHNE Null-Pointer-Check (Gegenstück zu DateTime_Validate) — Aufrufer garantieren gültigen Pointer; alte Beschreibung behauptete fälschlich das Gegenteil | high | Re-Audit 2026-07-14 |

## FreeRTOS-Kernel (Task/Queue/Timer/Heap) (83)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0801947c` | Task_Init_CreateAll | Erstellt 14 Tasks aus Tabelle DAT_08019518 via FreeRTOS_xTaskCreate (mit Log bei Fehlschlag), startet danach Scheduler | high | Re-Audit 2026-07-14 |
| `0x08029d84` | RTOS_ResumeSuspendedTasks | 14 Tasks prüfen, Suspended→Resume mit Logging | high | Doku |
| `0x0803313c` | FreeRTOS_eTaskGetState | Task-State: running/ready/blocked/suspended/deleted | high | Doku |
| `0x0804a46c` | prvAddCurrentTaskToDelayedList | Task → Delayed List mit Tick-Overflow Handling | high | Doku |
| `0x0804a538` | prvAddNewTaskToReadyList | Task Count++, TCB updaten, PendSV trigger | high | Doku |
| `0x0804a624` | prvCheckForValidListAndQueue | Timer-Listen + Service-Task Lazy-Init (Prio 5) | high | Doku |
| `0x0804a6d0` | prvCopyDataFromQueue | Circular Buffer Read mit Pointer Wrap | high | Doku |
| `0x0804a6fa` | prvCopyDataToQueue | Queue Back/Front Copy, Semaphore-Spezialfall | high | Doku |
| `0x0804a778` | prvDeleteTCB | Stack Storage (+0x30) + TCB freigeben | high | Doku |
| `0x0804a78a` | prvGetDisinheritPriorityAfterTimeout | Mutex Priority Disinheritance | high | Doku |
| `0x0804a7c8` | Heap_Init | heap_4 Pool: **71.680 Bytes** (0x11800), 8B-aligned | high | Doku |
| `0x0804a860` | Event_GroupInit | Event Group Felder nullen, xQueueSend Signal | high | Doku |
| `0x0804a87e` | Task_InitTcb | TCB Init: Stack-Ptr, Fn (+0x3C), Priority (+0x40) | high | Doku |
| `0x0804a8ac` | Task_InitNewTask | Stack 0xA5-Fill, Name kopieren (max 16), Prio clamp 0xF | high | Doku |
| `0x0804a990` | Timer_InitStruct | Timer CB: Period, Callback, Auto-Reload (Bit 0x04) | high | Doku |
| `0x0804aa10` | Scheduler_InitReadyLists | 16 Priority-Ready-Listen + 5 System-Listen | high | Doku |
| `0x0804aa78` | Heap_InsertFreeBlock | Free-List Insert mit Coalescing, **keine Heap Canaries** | high | Doku |
| `0x0804aae0` | FreeRTOS_Timer_InsertIntoActiveList | Timer Expiry mit Wrap-Around, 0 Aufrufer  — **korrigiert 2026-07-09**, s. Batch 18 | medium | Doku |
| `0x0804ab38` | Queue_IsEmpty | Critical-Section Check (offset 0x38) | high | Doku |
| `0x0804ab52` | Queue_IsFull | Count vs Max Length (0x38 vs 0x3C) | high | Doku |
| `0x0804ab70` | Scheduler_CopyReadyTasksToArray | 5 Kategorien × List → Flat Array | high | Doku |
| `0x0804abdc` | prvQueueSend_CopyAndNotify | FreeRTOS-intern (queue.c, Name per Error-String bestätigt): kopiert Daten in Queue und benachrichtigt wartenden Task bzw. Semaphore-Sonderfall | high | Re-Audit 2026-07-14 |
| `0x0804aee4` | prvResetNextTaskUnblockTime | Delayed-List Head → Global Timer | high | Doku |
| `0x0804af14` | prvSampleTimeNow | Tick Count, Overflow Detect → List Switch | high | Doku |
| `0x0804af40` | prvSwitchTimerLists | Expired Timer Callbacks + List Swap | high | Doku |
| `0x0804b008` | prvTaskCheckFreeStackSpace | 0xA5 Bytes zählen → Free Words (uint16) | high | Doku |
| `0x0804b094` | prvTaskIsTaskSuspended | TCB Check: Suspended-List + Event-Pending | high | Doku |
| `0x0804b12a` | prvUnlockQueue | Send/Receive Notifications drainieren, Lock reset 0xFF | high | Doku |
| `0x0804b1bc` | prvWriteNameToBuffer | Task Name → 15 Chars padded | high | Doku |
| `0x0804b1fc` | pvPortMalloc | heap_4 Allokator, First-Fit, Block-Splitting, **6 Aufrufer** | high | Doku |
| `0x0804b350` | pvTaskIncrementMutexHeldCount | Mutex Counter TCB+0x50 | high | Doku |
| `0x0804b370` | xTimerGetTimerID | Timer ID (+0x1c) mit Critical Section | high | Doku |
| `0x0804b3c4` | pxPortInitialiseStack | ARM Cortex-M Stack Frame (xPSR Thumb, EXC_RETURN) | high | Doku |
| `0x0804fc94` | ulTaskGenericNotifyTake | Generisches Notify-Take für Task | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080500e8` | uxListRemove | Element aus verketteter Liste entfernen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050110` | uxTaskGetSystemState | Systemzustand aller Tasks abfragen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080501c0` | vListInitialise | Liste initialisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080501da` | vListInitialiseItem | Listenelement initialisieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080501e0` | vListInsert | Element sortiert in Liste einfügen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050214` | vListInsertEnd | Element am Listenende einfügen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805022c` | vTaskEnterCritical | FreeRTOS Critical Section betreten, Base-Priority setzen, Counter++ | high | Doku |
| `0x080502b8` | vTaskExitCritical | FreeRTOS Critical Section verlassen, Counter--, Base-Priority restore | high | Doku |
| `0x0805032c` | vPortFree | Speicher über Port-Layer freigeben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080503e0` | vPortSetupTimerInterrupt | Timer-Interrupt für Scheduler einrichten | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050408` | vPortValidateInterruptPriority | Interrupt-Priorität gegen Kernel-Anforderungen validieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080504ac` | FreeRTOS_vQueueAddToRegistry | Trägt Queue/Mutex mit Namen in 15-Slot Queue-Registry ein (Debug/Trace) | high | Re-Audit 2026-07-14 |
| `0x080504d8` | prvQueueReceive_LockAndBlockIfEmpty | Queue-Receive: sperren und bei leerer Queue blockieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050524` | vTaskDelay | FreeRTOS vTaskDelay: Task für n Ticks blockieren via prvAddCurrentTaskToDelayedList, 90 Aufrufer im gesamten FW | high | Re-Audit 2026-07-14 |
| `0x080505a0` | vTaskGetInfo | Task-Informationen abrufen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050624` | vTaskInternalSetTimeOutState | Internen Timeout-Zustand setzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050718` | vTaskMissedYield | Verpasstes Yield markieren | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050724` | vTaskPlaceOnEventList | Task auf Event-Liste legen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050780` | vTaskPlaceOnEventListRestricted | Task mit Einschränkungen auf Event-Liste legen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050804` | vTaskPriorityDisinheritAfterTimeout | Prioritätsvererbung nach Timeout aufheben | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050934` | vTaskResume | Task fortsetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050a1c` | vTaskSetTimeOutState | Timeout-Zustand für Task setzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050a78` | vTaskStartScheduler | FreeRTOS-Scheduler starten | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050b34` | xTimerStop_Internal | Timer aus aktiver Timer-Liste entfernen, ggf. Scheduler-Yield | high | Doku |
| `0x08050c58` | vTaskSuspendAll | Scheduler anhalten (alle Tasks) | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050c68` | vTaskSwitchContext | Kontextwechsel zum nächsten Task | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053ba4` | FreeRTOS_StartScheduler | FreeRTOS Scheduler starten: HW-Checks, SysTick init, SoftReset | high | Doku |
| `0x08053d24` | FreeRTOS_SysTick_TaskUnblock | Aus ISR: Tick-basiertes Aufwecken von Tasks via PendSV | high | Doku (Name-Match) |
| `0x08053d58` | FreeRTOS_xQueueCreateMutex | Mutex-Queue erzeugen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053d7c` | FreeRTOS_xQueueGenericCreate | Generische Queue-Erzeugung | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053df8` | FreeRTOS_xQueueGenericReset | Queue in Ausgangszustand zurücksetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08053eb0` | xQueueSend | FreeRTOS xQueueSend (Basisfunktion für Send-Varianten): Daten in Queue kopieren, Timeout-Handling, Task-Notify beim Empfänger, 77 Aufrufer | high | Re-Audit 2026-07-14 |
| `0x0805408c` | FreeRTOS_xQueueGenericSend | Generisches Senden an Queue | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080541a4` | FreeRTOS_xQueueIsQueueFullFromISR | Queue-Voll-Check aus ISR-Kontext | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054370` | xQueueReceive | FreeRTOS xQueueReceive: Daten aus Queue kopieren, Mutex-Priority-Inheritance-Handling, Timeout, 61 Aufrufer | high | Re-Audit 2026-07-14 |
| `0x08054538` | FreeRTOS_xTaskCheckForTimeOut | Task-Timeout prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080545fc` | FreeRTOS_xTaskCreate | Neuen Task erzeugen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054664` | FreeRTOS_xTaskGenericNotify | Generische Task-Benachrichtigung senden | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x0805488c` | FreeRTOS_xTaskGetSchedulerState | Scheduler-Zustand abfragen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080548ac` | FreeRTOS_xTaskGetTickCount | Aktuellen Tick-Zähler auslesen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080548b8` | FreeRTOS_xTaskIncrementTick | Systick erhöhen, Delayed-Liste prüfen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054a94` | FreeRTOS_vTaskPriorityDisinherit | Mutex-Prioritätsvererbung rückgängig machen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054b9c` | FreeRTOS_vTaskPriorityDisinheritAfterTimeout | Prioritätsvererbung nach Timeout zurücksetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054c88` | FreeRTOS_xTaskRemoveFromEventList | Task aus Event-Liste entfernen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054dcc` | FreeRTOS_xTaskResumeAll | Scheduler/alle Tasks fortsetzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054f64` | FreeRTOS_xTimerCreate | Software-Timer erzeugen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08054f9c` | FreeRTOS_xTimerCreateTimerTask | Timer-Service-Task erzeugen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08055018` | FreeRTOS_xTimerGenericCommand | Generisches Timer-Kommando an Timer-Queue senden | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080550c0` | FreeRTOS_xTimerIsTimerActive | Prüfen ob Timer aktiv ist | Batch 20 | Ghidra (Batch 20, 2026-07-09) |

## CLI / AT-Command-Engine (49)

Eigenständiger Kommandozeilen-Interpreter (Token-Parser, Command-Dispatch, History, Ausgabe-Formatierung), erreichbar über den CH395/Modbus-TCP-Empfangspfad (`Network_ReceiveAndDispatchData` → `CLI_DispatchInputByte`). Ursprünglich als `BLE_GATT_*` (16 Funktionen) bzw. `ATCmd_*` (5 Funktionen) fehlbenannt — beide Male suggerierten die Namen einen Bezug zu BLE-GATT bzw. zum Quectel-AT-Modem-Interpreter, den der Code nicht hat. Korrigiert und als eigener Cluster ausgegliedert am 2026-07-14 (Re-Audit-Session), auf Nutzerentscheid hin (bewusst gegen "im BLE-Abschnitt belassen" oder "in CLI/Debug-Cluster einsortieren").

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0804bd58` | CLI_Session_Register | Service in 5-Slot Array, referenziert "VNSD_0_v1492" | medium | Doku |
| `0x0804bd90` | CLI_Entry_MatchAndInit | strcmp Match → Flag setzen | medium | Doku |
| `0x0804bdc8` | CLI_Entry_VisibilityFilter | 4 Aufrufer, Attribut-Sichtbarkeit Filter | medium | Doku |
| `0x0804c24c` | CLI_ResolveVariableRef | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c270` | CLI_InvokeCommandHandler | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c3a6` | CLI_GetEntryDisplayName | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c3d8` | CLI_GetEntryValueString | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c428` | CLI_FindActiveSession | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c45c` | CLI_ReadEntryValue | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c4b4` | CLI_DispatchInputByte | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c5a0` | CLI_HelpOrInfoDispatch | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c5cc` | CLI_HistoryNavigate | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804c68e` | CLI_HistoryPush | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804cb7e` | CLI_FindEntryByName | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804cbf8` | CLI_SelectEntry | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804cc40` | CLI_FormatEntryValue | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d018` | CLI_OutputLineTruncated | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d074` | CLI_PrintCommandInfo | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d0e0` | CLI_PrintPrompt | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d148` | CLI_PrintReturnValue | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804d1d4` | CLI_WriteString | *(keine Beschreibung — s. Hinweise oben)* | - | — |
| `0x0804bd80` | CLI_DeleteCharForward | Wrapper um CLI_DeleteChar(param,1) — Forward-Delete/Entf-Taste im Zeileneditor. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804be20` | CLI_ClearToEndOfLine | Löscht Rest der Editierzeile durch Leerzeichen-Overwrite + Cursor zurück. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804be48` | CLI_Backspace | Wrapper um CLI_DeleteChar(param,-1) — Backspace im Zeileneditor. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804be58` | CLI_DeleteChar | Kernlogik Zeichen löschen (vorwärts/rückwärts) inkl. Puffer-Verschiebung + Terminal-Echo. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804bf34` | CLI_CursorLeftRepeat | Cursor N-mal nach links (Backspace-Escape-Sequenz senden). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804bf64` | CLI_ConfirmAndExecute | Enter-Taste: verarbeitet Eingabezeile + druckt neuen Prompt. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804bf78` | CLI_ProcessInputLine | Zeilenabschluss: Entry-Match, History-Push, Tokenize, Command-Lookup + Execute. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804bfec` | CLI_DetectNumberFormat | Erkennt Zahlenformat aus Prefix (0x/0b/0-Octal/Float). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c044` | CLI_ParseEscapeChar | Wandelt Escape-Sequenz (\n,\t,\r,\b,\0) in Zeichen um. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c098` | CLI_ParseNumber | Parst Zahl (bin/oct/hex/float) aus String zu float. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c184` | CLI_ParseArgValue | Dispatcht Argument-Parsing je nach Präfix ('=Escape, Ziffer/-=Zahl, $=Variable, sonst String). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c202` | CLI_ParseString | Entfernt Anführungszeichen + löst Escapes in String auf (in-place). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c708` | CLI_InitSession | Initialisiert CLI-Session-Struktur (Puffer, History-Slots) + registriert Session + selektiert Root-Entry "VNSD_0_v1492". (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c7a8` | CLI_InsertChar | Fügt Zeichen an Cursor-Position ein (Insert/Overwrite je nach Modus-Flag) + Terminal-Echo. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c8a0` | CLI_Backspace_EchoOnly | Nur Cursor-Position--/Terminal-Echo (0x08), keine Puffer-Manipulation — anderer CLI-Kontext (Echo ohne Editier-Puffer). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c8ba` | CLI_ShowHelp | Wrapper um CLI_ListCommands. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c8c8` | CLI_ListCommands | Iteriert alle sichtbaren Command-Entries + druckt sie. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804c914` | CLI_PrintCommandEntry | Druckt eine Command-Entry-Zeile (Wert, Typ-Flags, Name). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804ca10` | CLI_InsertCharPlain | Wrapper um CLI_InsertChar mit Klartext-Echo-Flag gelöscht. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804ca2c` | CLI_TokenizeInput | Wrapper um CLI_TokenizeLine mit Session-Parametern (Trennzeichen Space, max. 8 Tokens). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804ca46` | CLI_StripQuotes | Entfernt führende/abschließende Anführungszeichen aus allen Tokens. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804caae` | CLI_CursorForward | Cursor ein Zeichen nach rechts (Zeichen erneut ausgeben). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804cacc` | CLI_ExecuteCommand | Führt Command-Entry aus je nach Typ (direkter Handler, InvokeCommandHandler mit Args, Select, FormatEntryValue). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804cd00` | CLI_TokenizeLine | Kern-Tokenizer: splittet Zeile an Trennzeichen, respektiert Anführungszeichen + Backslash-Escapes. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804ce18` | CLI_CommonPrefixLength | Berechnet gemeinsame Prefix-Länge zweier Strings (für Tab-Complete). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804ce5c` | CLI_TabComplete | Tab-Complete-Logik: findet passende Entries per Prefix-Match, zeigt Kandidaten oder ergänzt eindeutigen Treffer. (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804cffa` | CLI_MoveForward | Wrapper um CLI_HistoryNavigate(1) — History vorwärts (Pfeil runter). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |
| `0x0804d008` | CLI_PutChar | Low-Level Zeichenausgabe über Session-Output-Funktionszeiger (Offset+0x68). (2026-07-15 aus CLI/Debug-Ausgabe/Logging in CLI/AT-Command-Engine verschoben) | high | Re-Audit 2026-07-14 |

## CLI / Debug-Ausgabe / Logging (18)

> **Update (2026-07-15):** Die 28 zuvor hier fehlklassifizierten Zeileneditor-/Tokenizer-/Command-Dispatch-
> Funktionen (`CLI_DeleteCharForward` bis `CLI_PutChar`) wurden in den Cluster „CLI / AT-Command-Engine"
> verschoben (Nutzerentscheid). Verbleibend: reine Debug-Ausgabe/Logging-Funktionen.

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08005fb8` | Debug_Mode_Set | Debug-Modus aktivieren/deaktivieren über Param 0xC2 | high | Re-Audit 2026-07-14 |
| `0x08028fb0` | EventLog_Record_DisplayError | 14B Einträge, EEPROM 0x1100, 20-Slot Ringpuffer, 31s Deduplizierung | high | Re-Audit 2026-07-14 |
| `0x08029124` | EventLog_Record_SystemEvent | 9B Einträge, EEPROM 0x2000, 20 Slots, Events 0x191/0xcb/0x19b/0x259/600 | high | Re-Audit 2026-07-14 |
| `0x0802dd70` | debug_printf | Bedingter Debug-printf: gibt nur aus wenn Debug-Flag (Offset+0x38b) gesetzt ist, ruft dann putchar-basierte vararg-Ausgabe | high | Re-Audit 2026-07-14 |
| `0x0803238c` | Log_WarnCode0xE8 | Warning-Log mit Code 0xE8 | high | Re-Audit 2026-07-14 |
| `0x08034974` | Debug_PrintPowerStatistics | 6 Leistungswerte (all/monthly/daily charge/discharge) | high | Re-Audit 2026-07-14 |
| `0x08034b94` | Debug_PrintErrorCodes | err_code + warn_code als Hex | high | Re-Audit 2026-07-14 |
| `0x08035c8c` | Debug_Print_MeterMac | Meter MAC-Adresse drucken | high | Re-Audit 2026-07-14 |
| `0x0803e1b0` | log_SetEnabled | Logging ein/ausschalten (Bool-Flag) | high | Re-Audit 2026-07-14 |
| `0x0803e1c4` | log_printf | Zentrale Log-Ausgabe mit Level-/Modul-Filter (Enabled-Flag, Max-Level, Modul-Filter), Präfix [Modul][ERROR/WARN/INFO/DEBUG/UNKWN]; 386 Aufrufer projektweit | high | Re-Audit 2026-07-14 |
| `0x0803e2d0` | log_SetLevel | Log-Level 0-4 (TRACE/DEBUG/INFO/WARN/ERROR) | high | Re-Audit 2026-07-14 |
| `0x0803e2e4` | log_SetModeAndLevel | Enable + Level kombiniert setzen (ETX-Signal) | medium | Re-Audit 2026-07-14 |
| `0x0804d210` | Log_SetModeAndLevelCallback | Dünner Wrapper, ruft log_SetModeAndLevel(param) auf — 0 Aufrufer, vermutlich Function-Pointer-Callback | medium | Re-Audit 2026-07-14 |
| `0x0804d2d4` | Debug_PrintErrorAndEventLog | Debug-Dump: param=0 gibt 20 Error-Log-Slots aus, param=1 gibt 20 System-Event-Log-Slots aus (EventLog_Record_SystemEvent-Puffer) | high | Re-Audit 2026-07-14 |
| `0x0804d498` | Debug_PrintWifiStatus | Gibt WiFi-Signalstärke und Verbindungsstatus aus (2 printf) | high | Re-Audit 2026-07-14 |
| `0x0804d7e4` | Debug_PrintModbusAddress | Gibt konfigurierte Modbus-Adresse aus | high | Re-Audit 2026-07-14 |
| `0x08050dd8` | Debug_Mode_ToggleWithLog | Debug-Modus umschalten mit Log-Ausgabe | high | Re-Audit 2026-07-14 |
| `0x0802d00c` | Unused_FuncCall_Wrapper | 0 Aufrufer, 12B Passthrough-Wrapper | medium | Doku |

## System / Reset / Shutdown / Watchdog (16)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080001d0` | System_SoftReset | MSP aus VTOR zurücksetzen, IRQs re-enablen, SVC #0 Soft-Reset | high | Re-Audit 2026-07-14 |
| `0x08007946` | FactoryReset_NotifyAndReboot | Cloud-Benachrichtigung + Reboot nach Factory-Reset | high | Re-Audit 2026-07-14 |
| `0x0800b724` | Factory_Reset | Dispatcher: param=1 EEPROM-Clear+Factory-Write+Notify+Reboot, param=2 Notify ohne EEPROM-Clear, param=3 EEPROM-Clear+2s-Delay+Reboot ohne Notify | high | Re-Audit 2026-07-14 |
| `0x08013eb4` | System_IsOperationBusy_Flag | Prüfen ob Operation als 'busy' markiert ist | high | Re-Audit 2026-07-14 |
| `0x08013f68` | System_ResetRuntimeBuffers_Init | Laufzeit-Puffer beim Reset neu initialisieren | high | Re-Audit 2026-07-14 |
| `0x0801d204` | ConditionalSystemReboot | Guard-geprüfter Reboot (Counter 5-301) | high | Re-Audit 2026-07-14 |
| `0x08029900` | Comm_Status_Flags_Reset | Status-Flags Reset (4 Aufrufer: Serial, CAN, OTA) | high | Re-Audit 2026-07-14 |
| `0x08029c78` | System_Reboot | Stoppt Inverter-Output, speichert Runtime-Counter + Reboot-Timestamp, druckt "system will reboot", 50ms Delay, danach NVIC-Reset via AIRCR-Register (Endlosschleife) | high | Re-Audit 2026-07-14 |
| `0x0802d268` | MainLoop_Periodic_Tasks | Zentraler periodischer Dispatcher (13 aufgerufene Subsysteme; 1 Aufrufer: App_MainLoopDispatcher) | high | Re-Audit 2026-07-14 |
| `0x0802d2b4` | Idle_Watchdog_AutoReboot | 3600-Tick Idle → Config-Apply → Inverter-Off → Reboot | high | Re-Audit 2026-07-14 |
| `0x0802d364` | Shutdown_Sequence_Handler | 7 RTOS-Tasks suspendieren, Register dirty, 2000ms Wait, Reboot | high | Re-Audit 2026-07-14 |
| `0x0802d6fc` | Shutdown_SetPendingFlag | Pending-Flag (Offset+2) auf 1 setzen | medium | Re-Audit 2026-07-14 |
| `0x0802d728` | System_ResetToDefaults | Config schreiben, RTOS-Tasks resumieren, State clearen | medium | Re-Audit 2026-07-14 |
| `0x0802fca4` | Comm_Watchdog_CheckTimeout | 500ms Poll, 60 Fails (~30s) → OTA-Slot failed + Reset | high | Re-Audit 2026-07-14 |
| `0x08034812` | App_MainLoopDispatcher | 5 Subsysteme: Shutdown, OTA-Update, CAN-Update, Periodic-Tasks, Cloud-Watchdog | high | Re-Audit 2026-07-14 |
| `0x0804916c` | System_StopAllTimers | **7 Timer-Handles** stoppen vor Reboot | high | Re-Audit 2026-07-14 |

## libc / Standardbibliothek / Speicher-Utilities (45)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0800050a` | Mem_CopyBytes | Byte-weise Speicherkopie | high | Doku |
| `0x08000522` | Mem_CopyWords_Aligned | Word-aligned Speicherkopie (4 Wörter/Iteration, Fallback auf Byte-Kopie) | high | Doku |
| `0x08000574` | Mem_XorBytes | Zwei Byte-Buffer XOR-verknüpfen | high | Doku |
| `0x080005c8` | Mem_ZeroWords | Speicher nullen in 4-Wort-Chunks | high | Doku |
| `0x080006a0` | CompareWordArrays | Zwei Wort-Arrays vergleichen, 0=gleich, 1=verschieden | high | Doku |
| `0x08000786` | FillMemoryFromWord | Puffer mit wiederholtem 32-Bit-Wert füllen | medium | Doku |
| `0x08000820` | UInt64Div | 64-Bit unsigned Division (Shift-and-Subtract, für printf) | high | Doku |
| `0x08000884` | GetCtypeTable | Zeiger auf ctype-Klassifikationstabelle zurückgeben | high | Doku |
| `0x0800088c` | IsSpace | Whitespace-Prüfung via ctype-Tabelle | high | Doku |
| `0x0800089e` | memcpy | Standard memcpy, wortweise mit Byte-Rest; erkennt Overlap (Ziel>Quelle) und kopiert dann rückwärts (memmove-sicher) | high | Re-Audit 2026-07-14 |
| `0x080008de` | MemFill | Kern-memset-Implementierung (Fill-Loop) | high | Doku |
| `0x080008ec` | memset | Nur 2 Parameter (ptr,len), ruft MemFill(ptr,len,0) — Val fest auf 0, keine echte 3-Param-C-API (kein Rename nötig, memset ist der treffendste verfügbare Name trotz abweichender Signatur) | medium | Re-Audit 2026-07-14 |
| `0x080008f0` | MemsetStdcall | Standard-C `memset(ptr, val, len)` Wrapper | high | Doku |
| `0x08000902` | StrCat | Standard `strcat` | high | Doku |
| `0x0800091a` | strstr | Standard strstr (naive Teilstring-Suche) | high | Re-Audit 2026-07-14 |
| `0x0800093e` | strncpy | Standard strncpy mit Null-Padding bis n | high | Re-Audit 2026-07-14 |
| `0x08000956` | strchr | Name korrigiert (2026-07-15, vormals strncat): 2 Parameter (ptr,char), sucht ein Zeichen im String, entspricht strchr | - | Re-Audit 2026-07-14 |
| `0x0800096a` | strlen | Standard strlen | high | Re-Audit 2026-07-14 |
| `0x08000978` | strcmp | Standard strcmp | high | Re-Audit 2026-07-14 |
| `0x08000994` | memcmp | Byteweiser Speichervergleich bis n oder erste Abweichung (memcmp) | high | Re-Audit 2026-07-14 |
| `0x080009ae` | strcpy | Standard `strcpy` | high | Doku |
| `0x080009c0` | strncmp | Name korrigiert (2026-07-15, vormals atoi): 3 Parameter (s1,s2,n), reiner Byte-Vergleich, entspricht strncmp | - | Re-Audit 2026-07-14 |
| `0x080009e0` | strtok | Kern von strtok mit explizitem Save-Pointer (strtok_r-artig); strtok_wrapper verpackt dies als klassisches 2-Parameter strtok(str,delim) | high | Re-Audit 2026-07-14 |
| `0x08000a1c` | strtok_wrapper | Thin Wrapper um strtok | high | Doku |
| `0x08000a24` | strpbrk | Erstes Vorkommen eines Zeichens aus einem Set finden | high | Doku |
| `0x08000a44` | calloc | malloc + memset(0) | high | Doku |
| `0x08000a60` | sscanf | Variadisches sscanf (Setup + Delegation an Parser) | high | Doku |
| `0x08000a98` | sscanf_ReadInteger | Integer-Konvertierungsengine für sscanf | high | Doku |
| `0x08000be4` | strtol | String-to-Long mit Vorzeichen und Overflow-Clamping | high | Doku |
| `0x08000c54` | strtol_SaveErrno | strtol-Variante die errno sichert/wiederherstellt | high | Doku |
| `0x08000cc6` | atoi | Name korrigiert (2026-07-15, vormals atoi_u16): ruft strtol(s,NULL,10) auf und stellt errno wieder her — exaktes Standard-atoi-Verhalten, keine 16-Bit-Spezifik | - | Re-Audit 2026-07-14 |
| `0x08001020` | uint32_div | Software 32-Bit unsigned Division | high | Doku |
| `0x0800104c` | uint64_shl | 64-Bit Links-Shift (lo/hi Paar) | high | Doku |
| `0x080010d8` | sscanf_Format_Parser | Format-String-Parser für sscanf (%-Direktiven), ruft sscanf_ReadInteger für Zahl-Konvertierung | high | Re-Audit 2026-07-14 |
| `0x08001134` | strtoul_internal | Kern von strtoul (Basis-Erkennung, Akkumulation) | high | Doku |
| `0x08030368` | printf | Variadisches printf, Setup + Delegation an printf_Format_Engine | high | Re-Audit 2026-07-14 |
| `0x08030388` | snprintf | Variadisches snprintf mit Puffergrößen-Begrenzung, Delegation an printf_Format_Engine | high | Re-Audit 2026-07-14 |
| `0x080303e4` | putchar | putchar via printf_Format_Engine (einzelnes Zeichen als Format-String-Aufruf) | high | Re-Audit 2026-07-14 |
| `0x08030424` | __errno_location | Pointer auf globale errno-Variable | very high | Doku |
| `0x08031300` | malloc | Heap-Allokator mit Free-List | very high | Doku |
| `0x08031424` | printf_Float_To_Digits | Float→Dezimalziffern via Power-of-10 + UInt64Div | high | Doku |
| `0x080315a8` | printf_Format_Engine | Kern-Engine für printf/snprintf/putchar: parst Format-String, verarbeitet %d/%s/%f/...-Spezifizierer, Padding, Float-Digit-Erzeugung | high | Re-Audit 2026-07-14 |
| `0x08031c5c` | printf_Pad_Trailing_Spaces | Trailing Space-Padding (Left-Align '-') | high | Doku |
| `0x08031c80` | printf_Pad_Leading | Leading '0'/Space-Padding (Right-Align) | high | Doku |
| `0x08031cc4` | sprintf_Output_Char | Putchar-Callback: Byte schreiben, Pointer++ | high | Doku |

## Fixed-Point-Math (fp64) / dtoa / Float-Formatting (28)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x08000ce0` | fp64_add | Software-IEEE754-Addition zweier fp64-Werte (Mantissen-Alignment via Shift, Rundung) | high | Re-Audit 2026-07-14 |
| `0x08000e22` | fp64_sub | Software-fp64-Subtraktion (Tail-Call auf fp64_add mit invertiertem Vorzeichenbit von Operand B, in Assembly vor dem Sprung gesetzt) | medium | Re-Audit 2026-07-14 |
| `0x08000e28` | fp64_neg | Negiert Vorzeichenbit von Operand A, addiert Operand B (fp64_add mit XOR 0x80000000); Ghidra erkennt nur 2 von 4 Parametern | medium | Re-Audit 2026-07-14 |
| `0x08000e2e` | fp64_mul | Software-IEEE754-Multiplikation zweier fp64-Werte (Mantissen-Multiplikation + Exponentenaddition via fp64_normalize) | high | Re-Audit 2026-07-14 |
| `0x08000f12` | int_to_fp64 | Signed-Int32 nach fp64 (Betrag bilden, fp64_normalize mit Exponent-Bias 0x433) | high | Re-Audit 2026-07-14 |
| `0x08000f34` | uint_to_fp64 | Unsigned-Int32 nach fp64 (fp64_normalize mit Exponent-Bias 0x433, ohne Vorzeichenbehandlung) | high | Re-Audit 2026-07-14 |
| `0x08000f4e` | fp64_to_int | fp64 nach Signed-Int32 (Exponent-Bereichsprüfung, Shift via fp64_abs_cmp, Vorzeichen anwenden) | high | Re-Audit 2026-07-14 |
| `0x08000f8c` | fp64_to_uint | fp64 nach Unsigned-Int32 (analog fp64_to_int, ohne Vorzeichenanwendung) | high | Re-Audit 2026-07-14 |
| `0x08000fc0` | fp64_div | Software-fp64-Division; Ghidra-Dekompilierung unvollständig (nur 2 von vermutlich 4 Parametern sichtbar, Caller übergeben 4) — Name laut Aufrufkontext (Divisions-Operationen in cJSON_PrintNumber/SMR_TIC) plausibel | medium | Re-Audit 2026-07-14 |
| `0x08000ff0` | fp64_cmp_ge | fp64 Größer-Gleich-Vergleich; gleiche Dekompilierungs-Einschränkung wie fp64_div (identischer sichtbarer Code, echte Logik nicht vollständig decompiliert) — Name laut Aufrufkontext (Branch-Bedingungen) plausibel | medium | Re-Audit 2026-07-14 |
| `0x0800106a` | fp64_abs_cmp | 64-Bit-Rechts-Shift von (param1:param2) um param3 Bits; Hilfsfunktion für Mantissen-Alignment in fp64_normalize/fp64_to_int/fp64_to_uint/fp64_sqrt | high | Re-Audit 2026-07-14 |
| `0x0800108a` | fp64_ArithmeticShiftRight | 64-Bit arithmetischer Rechts-Shift mit Vorzeichenerweiterung | high | Doku |
| `0x080011f0` | fp64_normalize | Kern-Normalisierung für fp64-Ergebnisse: Leading-Zero-Count, Mantissen-Shift auf 53 Bit, Exponent-Bias-Anpassung, Rundung (round-to-nearest-even) | high | Re-Audit 2026-07-14 |
| `0x0800128c` | fp64_div_impl | Software-FP64-Division (Bit-für-Bit, IEEE 754 Rounding) | high | Doku |
| `0x0800136a` | fp64_ScaleByPowerOf2 | Exponent eines FP64-Werts anpassen | high | Doku |
| `0x08001398` | fp64_ToInteger | FP64 Richtung Null trunkieren (Fraktionsbits maskieren) | medium | Doku |
| `0x0800171c` | fp64_sqrt | Software-FP64-Quadratwurzel (53 Iterationen) | high | Doku |
| `0x080303f4` | fp64_Classify | Double-Klassifikation (zero/subnormal/inf/NaN) | high | Doku |
| `0x08030488` | fp64_Low_Word_Identity | Identity-Funktion für soft-float Low-Word | medium | Doku |
| `0x080304a0` | fp64_floor | IEEE 754 floor() Implementierung | high | Doku |
| `0x080305b8` | fp64_pow | Name korrigiert (2026-07-15, vormals dtoa_Float_To_String): implementiert x^y (2900 Bytes, Bereichsreduktion+Polynom-Auswertung, Spezialfälle sqrt/Quadrieren/Overflow), keine Float→String-Konvertierung; einziger Aufrufer cJSON_Parse_Number nutzt es als pow(10,exponent) beim JSON-Zahlen-Parsen. Entspricht Standard-C pow() | - | Re-Audit 2026-07-14 |
| `0x08031208` | fp64_Polynomial_Eval | Horner-Schema Polynom-Auswertung | very high | Doku |
| `0x08031350` | fp64_pow_OverflowInfinity | Name korrigiert (2026-07-15, vormals dtoa_Generate_Infinity): Teil des Overflow-Pfads von fp64_pow, nach fp_Set_Exception(2) aufgerufen, keine dtoa-Funktion | medium | Re-Audit 2026-07-14 |
| `0x080313b8` | fp64_pow_OverflowConst_A | Name korrigiert (2026-07-15, vormals dtoa_Square_Constant_A): quadriert feste Overflow-Konstante zur Erzeugung eines korrekt geflaggten +Inf-Ergebnisses im pow()-Overflow-Pfad, keine dtoa-Funktion | high | Re-Audit 2026-07-14 |
| `0x080313d8` | fp64_pow_OverflowConst_B | Name korrigiert (2026-07-15, vormals dtoa_Square_Constant_B): wie fp64_pow_OverflowConst_A, zweite Variante — Teil des pow()-Overflow-Pfads, keine dtoa-Funktion | high | Re-Audit 2026-07-14 |
| `0x08031418` | fp_Set_Exception | Inexact/Invalid Exception-Code speichern | high | Doku |
| `0x08034ce4` | Double_Fabs | Sign-Bit clearen (& 0x7FFFFFFFFFFFFFFF) | high | Doku |
| `0x0804d9c8` | fp64_sqrt_WithExceptionCheck | sqrt mit Exception-Flag-Setzung bei Overflow-Randfall (ruft fp64_sqrt, prüft Ergebnis-Exponent gegen Eingabe-Exponent, setzt fp_Set_Exception(1) bei Inexact) | high | Re-Audit 2026-07-14 |

## Heap-Allocator (intern) (7)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x0803042c` | heap_Free_Coalesce | Free-List mit Block-Coalescing (Kern von free()) | high | Doku |
| `0x0804b500` | heap_Realloc | Coalesce + Re-Alloc, Fallback Restore | high | Doku |
| `0x08050d18` | Heap_TrackedFree | Free mit Tracking/Zählung | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050d4c` | Heap_TrackedMalloc | Malloc mit Tracking/Zählung | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x08050d88` | Heap_TrackedRealloc | Realloc mit Tracking/Zählung | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080364c8` | Heap_AllocFromFreeList | First-Fit Allokator, Block-Splitting, von malloc aufgerufen | high | Doku |
| `0x08048f64` | Heap_Calloc | calloc: malloc + memset(0), 0 Aufrufer (Fn-Pointer) | high | Doku |

## Utility / Byte-Helpers / Timer-Helpers (46)

| Adresse | Name | Beschreibung | Conf. | Quelle |
|---|---|---|---|---|
| `0x080005f6` | ByteSwap32Array | Endian-Swap eines 32-Bit-Wort-Arrays | high | Doku |
| `0x0800068a` | ByteSwap32ArrayWrapper | Wrapper um ByteSwap32Array, gibt 0 zurück | high | Doku |
| `0x080010ae` | CharToDigitValue | ASCII → Ziffernwert für gegebene Basis | high | Doku |
| `0x080017be` | LZ77_Decompress | LZ77-artige Dekompression: Literal-Runs, Back-References UND Zero-Runs (RLE für Nullbytes, wenn Steuerbyte-Bit 0x08 nicht gesetzt) | high | Re-Audit 2026-07-14 |
| `0x08001fc8` | LookupTable_Read16 | 16-Bit Wert aus Lookup-Tabelle lesen | medium | Doku |
| `0x08004cd0` | Parse_IP_Address_String | IP-Adresse aus String parsen (dotted notation) | high | Doku |
| `0x08005644` | Version_Compare_Fields | Versionsnummern feldweise vergleichen (Range 2-4) | high | Doku |
| `0x08005758` | Byte_Swap_Copy | Kopiert param3 Bytes von param2 nach param1 in umgekehrter Byte-Reihenfolge (generischer Endian-Swap variabler Länge); u. a. für Modbus-Register in TCP/RS485-Handlern (6 Aufrufer) | medium | Re-Audit 2026-07-14 |
| `0x080066cc` | Delay_BusyWait_Ms | Blocking Busy-Wait Delay, ms-Skala | high | Doku |
| `0x080066ec` | Delay_BusyWait_Us | Blocking Busy-Wait Delay, µs-Skala | medium | Doku |
| `0x0800685a` | DNS_QuestionRecord_Skip | TLV-Record überspringen, Pointer vorrücken | high | Doku |
| `0x080068f4` | Delay_Adaptive | vTaskDelay wenn Scheduler läuft, sonst Busy-Wait | high | Doku |
| `0x08013f24` | Util_XOR_Checksum_Calc | XOR-Prüfsumme berechnen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
| `0x080195f4` | Uint32_To_DecString | uint32 → ASCII Dezimal-String Konvertierung | high | Doku |
| `0x0801df44` | HexChar_To_TimeOffsetIndex | Hex-Char → Numerisch % 5 (NTP Offset) | medium | Doku |
| `0x08025f34` | Checksum_Accumulate | Akkumuliert Byte-Summe in *param_1 über param_3 Bytes ab param_2; bei param_4≠0 wird invertiert (Einerkomplement) — genutzt für BLE-OTA-Chunk-Prüfsummen | medium | Re-Audit 2026-07-14 |
| `0x08025f60` | Timer_CheckElapsed | Timer-Ablauf prüfen (ms-basiert) | high | Doku (Name-Match) |
| `0x08029370` | Heartbeat_Timer_Reset | Flag=1, Timer-Clear, 3000ms Timer starten | medium | Doku |
| `0x08029818` | Periodic_RTC_Display_Format | Alle 5000ms: liest per RTC_GetDateTime() das Datum, formatiert ein Feld als ASCII-Ziffer, 3 weitere Bytes roh in Anzeige-Puffer kopiert (RTC-Datum, nicht generische „Sensor"-Daten) | medium | Re-Audit 2026-07-14 |
| `0x0802c174` | Timer_Defaults_Init | 13 Timer/Limit-Defaults (500-60000ms) initialisieren | high | Doku |
| `0x0802d768` | ParseIntegerWithSuffix | 0x/Dezimal + k/M Suffix (×1024/×1M), 0 Aufrufer | high | Doku |
| `0x0802d9ca` | Periodic_Tick_Handler | SysTick-ISR-Handler: prüft Scheduler-Status, ruft ggf. FreeRTOS_SysTick_TaskUnblock() auf, danach immer Runtime_Energy_Counter_Tick() | medium | Re-Audit 2026-07-14 |
| `0x0802dc24` | Tick_Timer_Check_Elapsed | Tick-basierter Elapsed-Timer (19 Aufrufer) | high | Doku |
| `0x0802dc58` | Timer_Periodic_RunCallback | Periodischer Timer mit Callback (13× von Timer_Defaults_Init) | high | Doku |
| `0x0802dc98` | Tick_Timer_Expired | Tick-basierter Elapsed-Timer, identischer Aufbau wie Tick_Timer_Check_Elapsed, eigener globaler Tick-Zähler (18 Callerfunktionen / 45 Call-Sites) | high | Re-Audit 2026-07-14 |
| `0x0802dccc` | Parse_TimeString_To_HourMinute | Parst "HH.MM" via sscanf, validiert HH<24/MM<60; Ergebnis lt. Disassembly NICHT hour<<8\|min sondern hour<<(min+8) — potenzieller Bit-Verlust bei größeren Minutenwerten (Verdacht auf FW-Bug) | high | Re-Audit 2026-07-14 |
| `0x0802dd18` | Timeout_Start_Seconds | Sekunden→ms konvertieren, dann Timeout_Start | high | Doku |
| `0x0802dd2e` | Timeout_Start | Duration speichern, Start-Tick erfassen (6 Aufrufer) | high | Doku |
| `0x0802dd3e` | Timeout_Init | 12-Byte Timeout-Struct nullen (6 Aufrufer) | high | Doku |
| `0x0802dd48` | Timeout_IsExpired | Prüfen ob Timeout abgelaufen (4 Aufrufer) | high | Doku |
| `0x0802dd5e` | Timeout_RefreshAndGetTicksRemaining | Ptr+1 verarbeiten, *ptr zurückgeben | medium | Doku |
| `0x080322fc` | Stream_ReadBytesAdvance | Bytes aus Stream-Pointer lesen + vorrücken | medium | Doku |
| `0x08035394` | Read_BigEndian_UInt16 | 2 Bytes Big-Endian → uint16 | high | Doku (Name-Match) |
| `0x08036494` | Util_CalcHalfSizeCapped | ceil(param/2), aber nur wenn param<48 — bei param≥48 Fallback auf 0 (Eingabe-Grenze mit Fallback, kein Ergebnis-Cap) | medium | Re-Audit 2026-07-14 |
| `0x0803e304` | Delay_Ms | Scheduler-aware: vTaskDelay oder BusyWait (9 Aufrufer) | high | Doku |
| `0x0803e340` | Delay_BusyWaitUs | Kalibrierter µs-BusyWait aus System-Clock | high | Doku |
| `0x0803e360` | RTOS_Delay_Ms | Scheduler-State-abhängiges Delay (Pendant zu Delay_Ms, nutzt Delay_BusyWait_Ms): BusyWait bei angehaltenem/nicht gestartetem Scheduler (xTaskGetSchedulerState), sonst vTaskDelay | high | Re-Audit 2026-07-14 |
| `0x08048f3c` | ByteSwap32 | Wrapper → ByteSwap32_Internal | high | Doku |
| `0x08048f48` | ByteSwap32_Internal | 4 Bytes Big-Endian → uint32 | high | Doku |
| `0x0804c370` | Util_HexCharToNibble | Wandelt ASCII-Hex-Zeichen (0-9, a-f, A-F) in Nibble-Wert 0-15; ungültige Zeichen ergeben 0 | high | Re-Audit 2026-07-14 |
| `0x0804ce44` | Util_StrCopy | Kopiert nullterminierten String (strcpy-Äquivalent, kein Längenlimit/Bounds-Check) | high | Re-Audit 2026-07-14 |
| `0x0804cf6c` | Util_IntToDecStr | Wandelt vorzeichenbehaftete Ganzzahl in Dezimal-ASCII (rückwärts in 12-Byte-Puffer), inkl. Vorzeichen/Null-Sonderfall; gibt Startindex zurück | high | Re-Audit 2026-07-14 |
| `0x0804cfc2` | Util_IntToHexStr | Wandelt vorzeichenlose Ganzzahl in Hex-ASCII (Kleinbuchstaben, rückwärts in 9-Byte-Puffer); gibt Startindex zurück | high | Re-Audit 2026-07-14 |
| `0x08003dd0` | CRC16_Calculate | CRC-16 mit Dual-Lookup-Tabellen, Init 0xFFFF | high | Doku |
| `0x08012d8c` | Generic_StructField_Set_0x14 | Generisches Struct-Feld an Offset 0x14 setzen (Pendant zu Generic_StructField_Set_0x10); bei GPIO-Strukturen entspricht Offset 0x14 dem BRR-Register (Pin Reset) | medium | Re-Audit 2026-07-14 |
| `0x08012d90` | Generic_StructField_Set_0x10 | Generisches Struct-Feld an Offset 0x10 setzen | Batch 20 | Ghidra (Batch 20, 2026-07-09) |
