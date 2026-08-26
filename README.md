# Bun IPMI SDR sensor support

This adds SDR repository enumeration and `Get Sensor Reading` support to the
pure Bun/TypeScript RMCP+ client.

## Files

Copy these into the existing project:

- `index.ts` — replaces the current CLI entry point.
- `src/sdr.ts` — new SDR/sensor implementation.
- Keep the existing working `src/ipmi.ts` unchanged.

## Sensor list

```bash
IPMI_DEBUG=1 bun index.ts admin@192.168.1.101 sensors
```

Normal use:

```bash
bun index.ts admin@192.168.1.101 sensors
```

JSON Lines output:

```bash
bun index.ts admin@192.168.1.101 sensors --json
```

Example output:

```text
ID    Owner     Name          Type         Value
----  --------  ------------  -----------  ------------
0x01  0x20:0    Inlet Temp    Temperature  24 degrees C
0x10  0x20:0    Fan 1         Fan          3200 RPM
```

## Existing fan command

The existing fan command is preserved:

```bash
bun index.ts admin@192.168.1.101 Fan1 92
```

`92` is interpreted as hexadecimal `0x92`.

## Current owner/LUN limitation

The current `IpmiClient.raw()` sends directly to the BMC responder at LUN 0.
Therefore `src/sdr.ts` only reads values for SDR sensors whose owner is the
local BMC (`0x20`) and LUN is 0. Other records are listed as `remote owner ...`
instead of risking a same-numbered sensor being read from the wrong controller.

If the real temperature sensors are owned by another IPMB controller or LUN,
add IPMB bridging / responder-LUN support next.

## Fail-safe direction for fan control

Do not yet use this sensor listing command as an unattended fan controller.
After the real temperature sensor names/numbers and values are verified, add a
control loop with:

- explicit sensor allow-list,
- stale/unavailable reading detection,
- high-temperature override,
- sensor/IPMI failure => fan `0xFF`,
- hysteresis / smoothing,
- minimum PWM,
- session reconnect handling.
