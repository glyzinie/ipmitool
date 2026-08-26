import { IpmiClient, IpmiCompletionError } from "./ipmi";

const NETFN_STORAGE = 0x0a;
const NETFN_SENSOR_EVENT = 0x04;

const CMD_GET_SDR_REPOSITORY_INFO = 0x20;
const CMD_RESERVE_SDR_REPOSITORY = 0x22;
const CMD_GET_SDR = 0x23;
const CMD_GET_SENSOR_READING = 0x2d;

const SDR_RECORD_TYPE_FULL_SENSOR = 0x01;
const SDR_RECORD_TYPE_COMPACT_SENSOR = 0x02;

const IPMI_CC_RESERVATION_CANCELED = 0xc5;
const IPMI_CC_CANNOT_RETURN_REQUESTED_BYTES = 0xca;

const LOCAL_BMC_OWNER_ADDRESS = 0x20;

export interface SdrRepositoryInfo {
  version: number;
  recordCount: number;
  freeSpace: number;
  mostRecentAdditionTimestamp: number;
  mostRecentEraseTimestamp: number;
  reserveSupported: boolean;
  overflow: boolean;
}

export type SdrSensorRecord = FullSensorRecord | CompactSensorRecord;

export interface SensorCommon {
  recordId: number;
  recordType: 0x01 | 0x02;
  sdrVersion: number;

  ownerId: number;
  ownerLun: number;
  ownerChannel: number;
  sensorNumber: number;

  entityId: number;
  entityInstance: number;

  sensorType: number;
  sensorTypeName: string;
  eventReadingType: number;

  analogFormat: number;
  percentage: boolean;
  unitModifierRelation: number;
  unitRate: number;
  baseUnit: number;
  modifierUnit: number;
  unit: string;

  name: string;
}

export interface FullSensorRecord extends SensorCommon {
  recordType: 0x01;
  linearization: number;
  m: number;
  b: number;
  bExp: number;
  rExp: number;
}

export interface CompactSensorRecord extends SensorCommon {
  recordType: 0x02;
  shareCount: number;
  shareModifierType: number;
  shareModifierOffset: number;
}

export type SensorReadingStatus =
  | "ok"
  | "unavailable"
  | "scanning-disabled"
  | "remote-owner"
  | "unsupported-linearization"
  | "discrete";

export interface SensorReading {
  sensor: SdrSensorRecord;
  status: SensorReadingStatus;

  raw: number | null;
  value: number | null;
  unit: string;

  readingUnavailable: boolean;
  scanningEnabled: boolean;
  eventMessagesEnabled: boolean;

  state1: number | null;
  state2: number | null;
}

interface SdrHeader {
  requestedRecordId: number;
  recordId: number;
  nextRecordId: number;
  version: number;
  type: number;
  length: number;
}

function u16le(value: number): [number, number] {
  return [value & 0xff, (value >>> 8) & 0xff];
}

function signExtend(value: number, bits: number): number {
  const sign = 1 << (bits - 1);
  const mask = (1 << bits) - 1;
  const v = value & mask;
  return (v ^ sign) - sign;
}

function decodeAnalogRaw(raw: number, format: number): number {
  switch (format) {
    case 0: // unsigned
      return raw;

    case 1: { // one's complement
      if ((raw & 0x80) === 0) {
        return raw;
      }

      // 0xff is negative zero in one's complement.
      const magnitude = (~raw) & 0x7f;
      return magnitude === 0 ? 0 : -magnitude;
    }

    case 2: // two's complement
      return raw & 0x80 ? raw - 0x100 : raw;

    default:
      throw new Error(`Sensor does not provide an analog reading (format=${format})`);
  }
}

function applyLinearization(value: number, linearization: number): number | null {
  switch (linearization & 0x7f) {
    case 0x00:
      return value;
    case 0x01:
      return Math.log(value);
    case 0x02:
      return Math.log10(value);
    case 0x03:
      return Math.log2(value);
    case 0x04:
      return Math.exp(value);
    case 0x05:
      return 10 ** value;
    case 0x06:
      return 2 ** value;
    case 0x07:
      return 1 / value;
    case 0x08:
      return value ** 2;
    case 0x09:
      return value ** 3;
    case 0x0a:
      return Math.sqrt(value);
    case 0x0b:
      return Math.cbrt(value);
    default:
      // 0x70-0x7f require Get Sensor Reading Factors; OEM/non-linear values
      // are intentionally not guessed here.
      return null;
  }
}

export function convertFullSensorReading(
  sensor: FullSensorRecord,
  raw: number,
): number | null {
  if (sensor.analogFormat === 3) {
    return null;
  }

  const x = decodeAnalogRaw(raw, sensor.analogFormat);
  const linear =
    (sensor.m * x + sensor.b * 10 ** sensor.bExp) * 10 ** sensor.rExp;

  return applyLinearization(linear, sensor.linearization);
}

const UNIT_NAMES = [
  "unspecified",
  "degrees C",
  "degrees F",
  "degrees K",
  "Volts",
  "Amps",
  "Watts",
  "Joules",
  "Coulombs",
  "VA",
  "Nits",
  "lumen",
  "lux",
  "Candela",
  "kPa",
  "PSI",
  "Newton",
  "CFM",
  "RPM",
  "Hz",
  "microsecond",
  "millisecond",
  "second",
  "minute",
  "hour",
  "day",
  "week",
  "mil",
  "inches",
  "feet",
  "cu in",
  "cu feet",
  "mm",
  "cm",
  "m",
  "cu cm",
  "cu m",
  "liters",
  "fluid ounce",
  "radians",
  "steradians",
  "revolutions",
  "cycles",
  "gravities",
  "ounce",
  "pound",
  "ft-lb",
  "oz-in",
  "gauss",
  "gilberts",
  "henry",
  "millihenry",
  "farad",
  "microfarad",
  "ohms",
  "siemens",
  "mole",
  "becquerel",
  "PPM",
  "reserved",
  "Decibels",
  "DbA",
  "DbC",
  "gray",
  "sievert",
  "color temp deg K",
  "bit",
  "kilobit",
  "megabit",
  "gigabit",
  "byte",
  "kilobyte",
  "megabyte",
  "gigabyte",
  "word",
  "dword",
  "qword",
  "line",
  "hit",
  "miss",
  "retry",
  "reset",
  "overflow",
  "underrun",
  "collision",
  "packets",
  "messages",
  "characters",
  "error",
  "correctable error",
  "uncorrectable error",
  "fatal error",
  "grams",
] as const;

const SENSOR_TYPE_NAMES = [
  "Reserved",
  "Temperature",
  "Voltage",
  "Current",
  "Fan",
  "Physical Security",
  "Platform Security",
  "Processor",
  "Power Supply",
  "Power Unit",
  "Cooling Device",
  "Other",
  "Memory",
  "Drive Slot / Bay",
  "POST Memory Resize",
  "System Firmware",
  "Event Logging Disabled",
  "Watchdog 1",
  "System Event",
  "Critical Interrupt",
  "Button",
  "Module / Board",
  "Microcontroller / Coprocessor",
  "Add-in Card",
  "Chassis",
  "Chip Set",
  "Other FRU",
  "Cable / Interconnect",
  "Terminator",
  "System Boot Initiated",
  "Boot Error",
  "OS Boot",
  "OS Critical Stop",
  "Slot / Connector",
  "System ACPI Power State",
  "Watchdog 2",
  "Platform Alert",
  "Entity Presence",
  "Monitor ASIC / IC",
  "LAN",
  "Management Subsystem Health",
  "Battery",
  "Session Audit",
  "Version Change",
  "FRU State",
] as const;

function unitName(code: number): string {
  return UNIT_NAMES[code] ?? `unit-${hexByte(code)}`;
}

function sensorTypeName(code: number): string {
  return SENSOR_TYPE_NAMES[code] ?? `SensorType ${hexByte(code)}`;
}

function formatUnit(
  percentage: boolean,
  relation: number,
  baseCode: number,
  modifierCode: number,
): string {
  const base = unitName(baseCode);
  const modifier = unitName(modifierCode);

  if (relation === 1) {
    return `${percentage ? "% " : ""}${base}/${modifier}`;
  }

  if (relation === 2) {
    return `${percentage ? "% " : ""}${base}*${modifier}`;
  }

  if (baseCode === 0 && percentage) {
    return "percent";
  }

  return `${percentage ? "% " : ""}${base}`;
}

function decodeBcdPlus(data: Buffer): string {
  const chars = "0123456789 -.:,_";
  let out = "";

  for (const byte of data) {
    out += chars[(byte >>> 4) & 0x0f] ?? "?";
    out += chars[byte & 0x0f] ?? "?";
  }

  return out.replace(/\0+$/g, "").trimEnd();
}

function decodeSixBitAscii(data: Buffer): string {
  let bitBuffer = 0;
  let bitCount = 0;
  let out = "";

  for (const byte of data) {
    bitBuffer |= byte << bitCount;
    bitCount += 8;

    while (bitCount >= 6) {
      out += String.fromCharCode((bitBuffer & 0x3f) + 0x20);
      bitBuffer >>>= 6;
      bitCount -= 6;
    }
  }

  return out.trimEnd();
}

function decodeIdString(idCode: number, bytes: Buffer): string {
  const type = (idCode >>> 6) & 0x03;
  const length = Math.min(idCode & 0x1f, bytes.length);
  const data = bytes.subarray(0, length);

  switch (type) {
    case 0:
      // "Unicode" in the SDR type/length field. UTF-16LE is the useful
      // interpretation for typical implementations; retain printable text.
      return data.length >= 2
        ? data.subarray(0, data.length & ~1).toString("utf16le").replace(/\0+$/g, "")
        : "";
    case 1:
      return decodeBcdPlus(data);
    case 2:
      return decodeSixBitAscii(data);
    case 3:
    default:
      return data.toString("latin1").replace(/\0+$/g, "").trimEnd();
  }
}

function hexByte(value: number): string {
  return `0x${value.toString(16).padStart(2, "0")}`;
}

function parseCommon(
  recordId: number,
  recordType: 0x01 | 0x02,
  sdrVersion: number,
  body: Buffer,
  idCodeOffset: number,
  idStringOffset: number,
): SensorCommon {
  if (body.length < 18) {
    throw new Error(`Sensor SDR ${recordId.toString(16)} is too short: ${body.length}`);
  }

  const ownerLunChannel = body[1];
  const units1 = body[15];

  const analogFormat = (units1 >>> 6) & 0x03;
  const percentage = (units1 & 0x01) !== 0;
  const unitModifierRelation = (units1 >>> 1) & 0x03;
  const unitRate = (units1 >>> 3) & 0x07;
  const baseUnit = body[16];
  const modifierUnit = body[17];

  const idCode = body[idCodeOffset] ?? 0;
  const idBytes = body.subarray(idStringOffset);
  const name = decodeIdString(idCode, idBytes) || `Sensor ${hexByte(body[2])}`;

  return {
    recordId,
    recordType,
    sdrVersion,

    ownerId: body[0],
    ownerLun: ownerLunChannel & 0x03,
    ownerChannel: (ownerLunChannel >>> 4) & 0x0f,
    sensorNumber: body[2],

    entityId: body[3],
    entityInstance: body[4],

    sensorType: body[7],
    sensorTypeName: sensorTypeName(body[7]),
    eventReadingType: body[8],

    analogFormat,
    percentage,
    unitModifierRelation,
    unitRate,
    baseUnit,
    modifierUnit,
    unit: formatUnit(percentage, unitModifierRelation, baseUnit, modifierUnit),

    name,
  };
}

function parseFullSensor(recordId: number, version: number, body: Buffer): FullSensorRecord {
  if (body.length < 43) {
    throw new Error(
      `Full Sensor SDR ${recordId.toString(16)} is too short: ${body.length} bytes`,
    );
  }

  const common = parseCommon(recordId, SDR_RECORD_TYPE_FULL_SENSOR, version, body, 42, 43);

  const m10 = body[19] | ((body[20] & 0xc0) << 2);
  const b10 = body[21] | ((body[22] & 0xc0) << 2);
  const exp = body[24];

  return {
    ...common,
    recordType: SDR_RECORD_TYPE_FULL_SENSOR,
    linearization: body[18],
    m: signExtend(m10, 10),
    b: signExtend(b10, 10),
    bExp: signExtend(exp & 0x0f, 4),
    rExp: signExtend((exp >>> 4) & 0x0f, 4),
  };
}

function parseCompactSensor(
  recordId: number,
  version: number,
  body: Buffer,
): CompactSensorRecord {
  if (body.length < 27) {
    throw new Error(
      `Compact Sensor SDR ${recordId.toString(16)} is too short: ${body.length} bytes`,
    );
  }

  const common = parseCommon(recordId, SDR_RECORD_TYPE_COMPACT_SENSOR, version, body, 26, 27);
  const share = body[18];

  return {
    ...common,
    recordType: SDR_RECORD_TYPE_COMPACT_SENSOR,
    shareCount: share & 0x0f,
    shareModifierType: (share >>> 4) & 0x03,
    shareModifierOffset: body[19] & 0x7f,
  };
}

export class SdrRepository {
  private reservationId = 0;
  private reserveSupported = true;

  constructor(private readonly client: IpmiClient) {}

  async getInfo(): Promise<SdrRepositoryInfo> {
    const data = await this.client.raw(NETFN_STORAGE, CMD_GET_SDR_REPOSITORY_INFO);

    if (data.length < 14) {
      throw new Error(`Get SDR Repository Info returned only ${data.length} bytes`);
    }

    const info: SdrRepositoryInfo = {
      version: data[0],
      recordCount: data.readUInt16LE(1),
      freeSpace: data.readUInt16LE(3),
      mostRecentAdditionTimestamp: data.readUInt32LE(5),
      mostRecentEraseTimestamp: data.readUInt32LE(9),
      reserveSupported: (data[13] & 0x02) !== 0,
      overflow: (data[13] & 0x80) !== 0,
    };

    this.reserveSupported = info.reserveSupported;
    return info;
  }

  async reserve(): Promise<number> {
    if (!this.reserveSupported) {
      this.reservationId = 0;
      return 0;
    }

    const data = await this.client.raw(NETFN_STORAGE, CMD_RESERVE_SDR_REPOSITORY);

    if (data.length < 2) {
      throw new Error(`Reserve SDR Repository returned only ${data.length} bytes`);
    }

    this.reservationId = data.readUInt16LE(0);
    return this.reservationId;
  }

  async listSensors(): Promise<SdrSensorRecord[]> {
    const info = await this.getInfo();

    if (info.recordCount === 0) {
      return [];
    }

    await this.reserve();

    const result: SdrSensorRecord[] = [];
    const seen = new Set<number>();

    let requestedRecordId = 0x0000;
    let iterations = 0;
    const hardLimit = Math.max(info.recordCount + 16, 64);

    while (requestedRecordId !== 0xffff) {
      if (++iterations > hardLimit) {
        throw new Error(
          `SDR iteration exceeded safety limit (${hardLimit}); repository may be changing`,
        );
      }

      const header = await this.readHeader(requestedRecordId);
      const effectiveRecordId =
        requestedRecordId === 0x0000 ? header.recordId : requestedRecordId;

      if (seen.has(effectiveRecordId)) {
        throw new Error(`SDR repository loop detected at record 0x${effectiveRecordId.toString(16)}`);
      }
      seen.add(effectiveRecordId);

      if (
        header.type === SDR_RECORD_TYPE_FULL_SENSOR ||
        header.type === SDR_RECORD_TYPE_COMPACT_SENSOR
      ) {
        const body = await this.readBody(effectiveRecordId, header.length);

        if (header.type === SDR_RECORD_TYPE_FULL_SENSOR) {
          result.push(parseFullSensor(effectiveRecordId, header.version, body));
        } else {
          result.push(parseCompactSensor(effectiveRecordId, header.version, body));
        }
      }

      requestedRecordId = header.nextRecordId;
    }

    return result;
  }

  async readSensor(sensor: SdrSensorRecord): Promise<SensorReading> {
    const localOwner = sensor.ownerId === LOCAL_BMC_OWNER_ADDRESS;

    // Existing IpmiClient.raw() sends directly to the BMC at responder LUN 0.
    // Do not accidentally read a same-numbered sensor owned by another MC/LUN.
    if (!localOwner || sensor.ownerLun !== 0) {
      return {
        sensor,
        status: "remote-owner",
        raw: null,
        value: null,
        unit: sensor.unit,
        readingUnavailable: false,
        scanningEnabled: false,
        eventMessagesEnabled: false,
        state1: null,
        state2: null,
      };
    }

    const data = await this.client.raw(NETFN_SENSOR_EVENT, CMD_GET_SENSOR_READING, [
      sensor.sensorNumber,
    ]);

    if (data.length < 2) {
      throw new Error(
        `Get Sensor Reading ${hexByte(sensor.sensorNumber)} returned only ${data.length} bytes`,
      );
    }

    const raw = data[0];
    const flags = data[1];
    const readingUnavailable = (flags & 0x20) !== 0;
    const scanningEnabled = (flags & 0x40) !== 0;
    const eventMessagesEnabled = (flags & 0x80) !== 0;
    const state1 = data.length >= 3 ? data[2] : null;
    const state2 = data.length >= 4 ? data[3] : null;

    if (!scanningEnabled) {
      return {
        sensor,
        status: "scanning-disabled",
        raw,
        value: null,
        unit: sensor.unit,
        readingUnavailable,
        scanningEnabled,
        eventMessagesEnabled,
        state1,
        state2,
      };
    }

    if (readingUnavailable) {
      return {
        sensor,
        status: "unavailable",
        raw,
        value: null,
        unit: sensor.unit,
        readingUnavailable,
        scanningEnabled,
        eventMessagesEnabled,
        state1,
        state2,
      };
    }

    if (sensor.recordType !== SDR_RECORD_TYPE_FULL_SENSOR || sensor.analogFormat === 3) {
      return {
        sensor,
        status: "discrete",
        raw,
        value: null,
        unit: sensor.unit,
        readingUnavailable,
        scanningEnabled,
        eventMessagesEnabled,
        state1,
        state2,
      };
    }

    const value = convertFullSensorReading(sensor, raw);

    return {
      sensor,
      status: value === null ? "unsupported-linearization" : "ok",
      raw,
      value,
      unit: sensor.unit,
      readingUnavailable,
      scanningEnabled,
      eventMessagesEnabled,
      state1,
      state2,
    };
  }

  private async readHeader(requestedRecordId: number): Promise<SdrHeader> {
    const response = await this.getSdr(requestedRecordId, 0, 5);

    if (response.data.length < 5) {
      throw new Error(
        `Get SDR header 0x${requestedRecordId.toString(16)} returned only ${response.data.length} bytes`,
      );
    }

    return {
      requestedRecordId,
      recordId: response.data.readUInt16LE(0),
      nextRecordId: response.nextRecordId,
      version: response.data[2],
      type: response.data[3],
      length: response.data[4],
    };
  }

  private async readBody(recordId: number, length: number): Promise<Buffer> {
    const body = Buffer.alloc(length);
    let offset = 0;
    let maxChunk = 32;

    while (offset < length) {
      let requestedLength = Math.min(maxChunk, length - offset);

      for (;;) {
        try {
          const response = await this.getSdr(recordId, offset + 5, requestedLength);

          if (response.data.length < requestedLength) {
            throw new Error(
              `Short SDR read at record 0x${recordId.toString(16)}, offset ${offset}: ` +
                `${response.data.length}/${requestedLength} bytes`,
            );
          }

          response.data.subarray(0, requestedLength).copy(body, offset);
          offset += requestedLength;
          break;
        } catch (error) {
          if (
            error instanceof IpmiCompletionError &&
            error.completionCode === IPMI_CC_CANNOT_RETURN_REQUESTED_BYTES &&
            requestedLength > 1
          ) {
            maxChunk = Math.max(1, Math.floor(requestedLength / 2));
            requestedLength = Math.min(maxChunk, length - offset);
            continue;
          }

          throw error;
        }
      }
    }

    return body;
  }

  private async getSdr(
    recordId: number,
    offset: number,
    length: number,
  ): Promise<{ nextRecordId: number; data: Buffer }> {
    for (let attempt = 1; attempt <= 5; attempt++) {
      const [reservationLo, reservationHi] = u16le(this.reservationId);
      const [recordLo, recordHi] = u16le(recordId);

      try {
        const response = await this.client.raw(NETFN_STORAGE, CMD_GET_SDR, [
          reservationLo,
          reservationHi,
          recordLo,
          recordHi,
          offset & 0xff,
          length & 0xff,
        ]);

        if (response.length < 2) {
          throw new Error(`Get SDR returned only ${response.length} bytes`);
        }

        return {
          nextRecordId: response.readUInt16LE(0),
          data: Buffer.from(response.subarray(2)),
        };
      } catch (error) {
        if (
          error instanceof IpmiCompletionError &&
          error.completionCode === IPMI_CC_RESERVATION_CANCELED &&
          attempt < 5
        ) {
          await this.reserve();
          continue;
        }

        throw error;
      }
    }

    throw new Error("Get SDR failed after reservation retries");
  }
}

export function formatSensorValue(reading: SensorReading): string {
  switch (reading.status) {
    case "ok": {
      const value = reading.value!;
      const formatted = Number.isInteger(value) ? value.toFixed(0) : value.toFixed(2);
      return `${formatted} ${reading.unit}`;
    }
    case "discrete": {
      const raw = reading.raw ?? 0;
      const states = [reading.state1, reading.state2]
        .filter((value): value is number => value !== null)
        .map(hexByte)
        .join(" ");
      return states ? `${hexByte(raw)} [${states}]` : hexByte(raw);
    }
    case "remote-owner":
      return `remote owner ${hexByte(reading.sensor.ownerId)}:${reading.sensor.ownerLun}`;
    case "unavailable":
      return "unavailable";
    case "scanning-disabled":
      return "scanning disabled";
    case "unsupported-linearization":
      return `raw ${hexByte(reading.raw ?? 0)} (non-linear)`;
  }
}

