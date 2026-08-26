import { emitKeypressEvents } from "node:readline";

import { IpmiClient } from "./src/ipmi";
import { formatSensorValue, SdrRepository, type SensorReading } from "./src/sdr";

function usage(): never {
  console.error(`Usage:
  bun index.ts <user>@<host> FanN <speed: 00~FF>
  bun index.ts <user>@<host> sensors [--json]

Examples:
  bun index.ts admin@192.168.1.101 Fan1 92
  bun index.ts admin@192.168.1.101 sensors
  bun index.ts admin@192.168.1.101 sensors --json`);
  process.exit(2);
}

function parseTarget(target: string): { username: string; host: string } {
  const at = target.lastIndexOf("@");

  if (at <= 0 || at === target.length - 1) {
    throw new Error(`Invalid target: ${target}; expected user@host`);
  }

  return {
    username: target.slice(0, at),
    host: target.slice(at + 1),
  };
}

function parseHexByte(value: string): number {
  const normalized = value.replace(/^0x/i, "");

  if (!/^[0-9a-fA-F]{1,2}$/.test(normalized)) {
    throw new Error(`Invalid hexadecimal byte: ${value}`);
  }

  return Number.parseInt(normalized, 16);
}

async function readPassword(label = "Password: "): Promise<string> {
  const stdin = process.stdin;

  if (!stdin.isTTY || !process.stdout.isTTY || typeof stdin.setRawMode !== "function") {
    throw new Error(
      "Interactive password input requires a TTY. Alternatively set IPMI_PASSWORD.",
    );
  }

  process.stdout.write(label);
  emitKeypressEvents(stdin);
  stdin.setRawMode(true);
  stdin.resume();

  return new Promise<string>((resolve, reject) => {
    let password = "";

    const cleanup = () => {
      stdin.off("keypress", onKeypress);
      stdin.setRawMode(false);
      stdin.pause();
    };

    const onKeypress = (
      str: string,
      key: { name?: string; ctrl?: boolean; meta?: boolean },
    ) => {
      if (key.ctrl && key.name === "c") {
        cleanup();
        process.stdout.write("\n");
        reject(new Error("Cancelled"));
        return;
      }

      if (key.name === "return" || key.name === "enter") {
        cleanup();
        process.stdout.write("\n");
        resolve(password);
        return;
      }

      if (key.name === "backspace") {
        password = password.slice(0, -1);
        return;
      }

      if (str && !key.ctrl && !key.meta) {
        password += str;
      }
    };

    stdin.on("keypress", onKeypress);
  });
}

function hex(value: number, width = 2): string {
  return `0x${value.toString(16).padStart(width, "0")}`;
}

function pad(value: string, width: number): string {
  return value.length >= width ? value : value + " ".repeat(width - value.length);
}

function printSensorTable(readings: SensorReading[]): void {
  const rows = readings.map((reading) => ({
    id: hex(reading.sensor.sensorNumber),
    owner: `${hex(reading.sensor.ownerId)}:${reading.sensor.ownerLun}`,
    name: reading.sensor.name,
    type: reading.sensor.sensorTypeName,
    value: formatSensorValue(reading),
  }));

  const widths = {
    id: Math.max(4, ...rows.map((row) => row.id.length)),
    owner: Math.max(7, ...rows.map((row) => row.owner.length)),
    name: Math.max(4, ...rows.map((row) => row.name.length)),
    type: Math.max(4, ...rows.map((row) => row.type.length)),
  };

  console.log(
    `${pad("ID", widths.id)}  ${pad("Owner", widths.owner)}  ${pad("Name", widths.name)}  ` +
      `${pad("Type", widths.type)}  Value`,
  );
  console.log(
    `${"-".repeat(widths.id)}  ${"-".repeat(widths.owner)}  ${"-".repeat(widths.name)}  ` +
      `${"-".repeat(widths.type)}  -----`,
  );

  for (const row of rows) {
    console.log(
      `${pad(row.id, widths.id)}  ${pad(row.owner, widths.owner)}  ${pad(row.name, widths.name)}  ` +
        `${pad(row.type, widths.type)}  ${row.value}`,
    );
  }
}

async function runSensors(client: IpmiClient, json: boolean): Promise<void> {
  const sdr = new SdrRepository(client);
  const info = await sdr.getInfo();

  if (!json) {
    console.error(
      `SDR: version=${hex(info.version)} records=${info.recordCount} ` +
        `reserve=${info.reserveSupported ? "yes" : "no"}`,
    );
  }

  // listSensors() refreshes repository info/reservation itself. Keeping that
  // behavior makes this command safe if the repository changes between calls.
  const sensors = await sdr.listSensors();
  const readings: SensorReading[] = [];

  // IpmiClient intentionally allows one request at a time, so read sequentially.
  for (const sensor of sensors) {
    try {
      readings.push(await sdr.readSensor(sensor));
    } catch (error) {
      if (json) {
        console.error(
          JSON.stringify({
            level: "error",
            sensorNumber: sensor.sensorNumber,
            sensorName: sensor.name,
            error: error instanceof Error ? error.message : String(error),
          }),
        );
      } else {
        console.error(
          `[sensor ${hex(sensor.sensorNumber)} ${sensor.name}] ` +
            (error instanceof Error ? error.message : String(error)),
        );
      }
    }
  }

  if (json) {
    for (const reading of readings) {
      console.log(
        JSON.stringify({
          sensorNumber: reading.sensor.sensorNumber,
          sensorNumberHex: hex(reading.sensor.sensorNumber),
          name: reading.sensor.name,
          type: reading.sensor.sensorTypeName,
          ownerId: reading.sensor.ownerId,
          ownerLun: reading.sensor.ownerLun,
          ownerChannel: reading.sensor.ownerChannel,
          status: reading.status,
          raw: reading.raw,
          value: reading.value,
          unit: reading.unit,
          state1: reading.state1,
          state2: reading.state2,
        }),
      );
    }
    return;
  }

  printSensorTable(readings);
}

async function runFan(client: IpmiClient, fanArgument: string, speedArgument: string): Promise<void> {
  const fanMatch = /^fan(\d+)$/i.exec(fanArgument);

  if (!fanMatch) {
    throw new Error(`Invalid fan: ${fanArgument}`);
  }

  const fan = Number.parseInt(fanMatch[1], 10);

  if (!Number.isInteger(fan) || fan < 1 || fan > 0xff) {
    throw new Error("Fan must be Fan1 ~ Fan255");
  }

  // "92" means hexadecimal 0x92, preserving the existing CLI behavior.
  const speed = parseHexByte(speedArgument);

  const response = await client.raw(0x2e, 0xf5, [
    0x80,
    0x28,
    0x00,
    0x2d,
    0x50,
    0x57,
    fan,
    speed,
  ]);

  console.log(
    `OK: Fan${fan} -> ${hex(speed)} (Cipher Suite ${client.cipherSuiteId})`,
  );

  if (response.length > 0) {
    console.log(
      "Response:",
      [...response].map((value) => value.toString(16).padStart(2, "0")).join(" "),
    );
  }
}

const args = Bun.argv.slice(2);

if (args.length < 2) {
  usage();
}

const target = args[0];
const command = args[1];
const { username, host } = parseTarget(target);

const password = process.env.IPMI_PASSWORD ?? (await readPassword());

const client = new IpmiClient({
  host,
  username,
  password,
  timeoutMs: 1500,
  retries: 3,
  debug: process.env.IPMI_DEBUG === "1",
});

try {
  await client.connect();

  if (command.toLowerCase() === "sensors") {
    const extras = args.slice(2);
    const unknown = extras.filter((arg) => arg !== "--json");

    if (unknown.length > 0) {
      throw new Error(`Unknown sensors option(s): ${unknown.join(", ")}`);
    }

    await runSensors(client, extras.includes("--json"));
  } else {
    if (args.length !== 3) {
      usage();
    }

    await runFan(client, command, args[2]);
  }
} finally {
  await client.close();
}
