# Bug report — Modbus FC03 returns corrupted values for signed registers with a divide scale

**Product:** Marstek Venus D (VNSD-0)
**Firmware:** Control / EMS **v150** (`VNSD-0_app_0150_0805_115146.bin`)
**Interface:** Modbus TCP, function code 03 (read holding registers)
**Affected register in this firmware:** **32101** (BMS battery current)
**Severity:** the register is unusable whenever the battery discharges

---

## Summary

The Modbus read path applies its scaling divisions as **unsigned** arithmetic to values
that were just sign-extended from a signed type. For negative values the result is not a
scaled number but an unrelated one.

In firmware v150 exactly one register combines a signed type with a divide scale, so only
register 32101 is affected today. The defect itself is in the shared serializer that every
FC03 read passes through, so any future register with that combination inherits it.

## What we observe

Register 32101 is documented as the BMS battery current, `int16`, unit 0.1 A. Reading it
while the battery discharges returns values that do not correspond to any current:

| Battery state | Actual current | Expected register value | **Value returned** |
|---|---|---|---|
| Idle, about −0.3 A | −0.3 A | `0` | **39321** (`0x9999`) |
| Discharging 600 W, −12.2 A | −12.2 A | `-12` | **39309** (`0x998D`) |
| **Charging 600 W, +10.3 A** | +10.3 A | `10` | **10** — correct |

Charging is unaffected: the same register, read while the battery charged at 600 W,
returned `10` for a pack current of `103` (0.1 A units), which is the correct result of
dividing by ten. The defect is therefore asymmetric — it corrupts discharge readings only.

The actual current was established independently: at the same moment, register **34301**
(pack 4 current, same quantity, no scale code applied) returned `-3` and `-122`
respectively, and the device's own Bluetooth interface reported battery power of −16 W and
−651 W, which matches those currents at the measured pack voltage of 53.4 V.

## Cause

In the FC03 read serializer, the value is placed in an **unsigned** local variable and the
descriptor's scale code is applied to it:

```c
uint value;

/* type 0x12 = int16 */
value = (uint) *(short *) source;   /* sign-extends: -122 becomes 0xFFFFFF86 */

switch (scale_code) {
    case 1: value = value * 10;   break;   /* correct */
    case 2: value = value * 100;  break;   /* correct */
    case 3: value = value / 10;   break;   /* INCORRECT for negative values */
    case 4: value = value / 100;  break;   /* INCORRECT for negative values */
    case 5: value = -value;       break;   /* correct */
}
```

The sign extension is right, and multiplication and negation continue to work correctly in
two's complement. Division does not: because `value` is unsigned, the compiler divides
4294967174 rather than −122. The low 16 bits of that result are then copied into the
response.

This reproduces both observed values exactly:

```python
def serialize(sram_int16):
    v = sram_int16 & 0xFFFFFFFF   # (uint)(short)x
    v = v // 10                   # unsigned division
    return v & 0xFFFF             # low 16 bits copied to the response

serialize(-3)    ->  39321
serialize(-122)  ->  39309
```

## Impact

- **Register 32101 cannot be used as a current measurement.** The value can be
  approximately inverted as `current ≈ (raw − 39321) A`, but only at 1 A resolution,
  because the division happens before the truncation to 16 bits — and the behaviour is
  asymmetric between charging and discharging.
- Any client that reads 32101 and interprets it as documented will report a large positive
  current while the battery is in fact discharging.
- The defect is latent for every other register: it lives in the shared read serializer,
  not in the descriptor entry for 32101.

## Suggested fix

Perform the scaling on a **signed** variable, or branch on the type's signedness before
dividing. For example:

```c
int32_t value;                       /* signed */
value = (int32_t) *(int16_t *) source;

switch (scale_code) {
    case 3: value = value / 10;  break;
    case 4: value = value / 100; break;
    ...
}
```

Signed division rounds toward zero in C, which matches the intent of the scale codes.

## How to reproduce

1. Connect to the device over Modbus TCP.
2. Put the battery into a discharge state — a few hundred watts is enough.
3. Read register **32101** (FC03, one register) and register **34301** in the same pass.
4. 34301 returns the pack current at 0.1 A, correctly signed. 32101 returns a large
   positive number that does not correspond to it.
5. Repeat while charging: both registers now agree.

## Notes

This was found through static analysis of the v150 firmware image together with live
Modbus scans of a six-pack Venus D in two defined load states. We have not verified
whether Venus A and Venus E v3, which share this firmware base, expose additional
registers with the same type and scale combination.

We are happy to provide the register dumps from both load states on request.
