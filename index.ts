import { emitKeypressEvents } from "node:readline";

import {
  IpmiClient,
} from "./src/ipmi";

function usage(): never {
  console.error(
    "Usage: bun index.ts <user>@<host> <FanN> <speed: 00~FF>",
  );

  console.error(
    "Example: bun index.ts admin@192.168.1.101 Fan1 92",
  );

  process.exit(2);
}

function parseHexByte(
  value: string,
): number {
  const normalized =
    value.replace(/^0x/i, "");

  if (
    !/^[0-9a-fA-F]{1,2}$/.test(
      normalized,
    )
  ) {
    throw new Error(
      `Invalid hexadecimal byte: ${value}`,
    );
  }

  return Number.parseInt(
    normalized,
    16,
  );
}

async function readPassword(
  label = "Password: ",
): Promise<string> {
  const stdin = process.stdin;

  if (
    !stdin.isTTY ||
    !process.stdout.isTTY ||
    typeof stdin.setRawMode !== "function"
  ) {
    throw new Error(
      "Interactive password input requires a TTY. " +
      "Alternatively set IPMI_PASSWORD.",
    );
  }

  process.stdout.write(label);

  emitKeypressEvents(stdin);

  stdin.setRawMode(true);
  stdin.resume();

  return new Promise<string>(
    (resolve, reject) => {
      let password = "";

      const cleanup = () => {
        stdin.off(
          "keypress",
          onKeypress,
        );

        stdin.setRawMode(false);
        stdin.pause();
      };

      const onKeypress = (
        str: string,
        key: {
          name?: string;
          ctrl?: boolean;
          meta?: boolean;
        },
      ) => {
        if (
          key.ctrl &&
          key.name === "c"
        ) {
          cleanup();
          process.stdout.write("\n");

          reject(
            new Error("Cancelled"),
          );

          return;
        }

        if (
          key.name === "return" ||
          key.name === "enter"
        ) {
          cleanup();
          process.stdout.write("\n");

          resolve(password);
          return;
        }

        if (key.name === "backspace") {
          password =
            password.slice(0, -1);

          return;
        }

        if (
          str &&
          !key.ctrl &&
          !key.meta
        ) {
          password += str;
        }
      };

      stdin.on(
        "keypress",
        onKeypress,
      );
    },
  );
}

const args =
  Bun.argv.slice(2);

if (args.length !== 3) {
  usage();
}

const [
  target,
  fanArgument,
  speedArgument,
] = args;

const at =
  target.lastIndexOf("@");

if (
  at <= 0 ||
  at === target.length - 1
) {
  throw new Error(
    `Invalid target: ${target}`,
  );
}

const username =
  target.slice(0, at);

const host =
  target.slice(at + 1);

const fanMatch =
  /^fan(\d+)$/i.exec(
    fanArgument,
  );

if (!fanMatch) {
  throw new Error(
    `Invalid fan: ${fanArgument}`,
  );
}

const fan =
  Number.parseInt(
    fanMatch[1],
    10,
  );

if (
  !Number.isInteger(fan) ||
  fan < 1 ||
  fan > 0xff
) {
  throw new Error(
    `Fan must be Fan1 ~ Fan255`,
  );
}

/*
 * "92" は10進92ではなく、
 * 0x92として扱う。
 */
const speed =
  parseHexByte(
    speedArgument,
  );

const password =
  process.env.IPMI_PASSWORD ??
  await readPassword();

const client =
  new IpmiClient({
    host,
    username,
    password,

    timeoutMs: 1500,
    retries: 3,

    debug:
      process.env.IPMI_DEBUG === "1",
  });

try {
  await client.connect();

  /*
   * 元の:
   *
   * raw
   *   0x2e 0xf5
   *   0x80 0x28 0x00 0x2d
   *   0x50 0x57
   *   0x01
   *   0x92
   *
   * FanN -> N
   * speed -> hex byte
   */
  const response =
    await client.raw(
      0x2e,
      0xf5,
      [
        0x80,
        0x28,
        0x00,
        0x2d,
        0x50,
        0x57,
        fan,
        speed,
      ],
    );

  console.log(
    `OK: Fan${fan} -> ` +
    `0x${speed
      .toString(16)
      .padStart(2, "0")}` +
    ` (Cipher Suite ${client.cipherSuiteId})`,
  );

  if (response.length > 0) {
    console.log(
      "Response:",
      [...response]
        .map((value) =>
          value
            .toString(16)
            .padStart(2, "0"),
        )
        .join(" "),
    );
  }
} finally {
  await client.close();
}
