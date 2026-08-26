import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

const RMCP_HEADER = Buffer.from([
  0x06, // RMCP 1.0
  0x00, // reserved
  0xff, // no ACK
  0x07, // IPMI
]);

const RMCP_PLUS_AUTH_TYPE = 0x06;

const PAYLOAD = {
  IPMI: 0x00,
  OPEN_REQUEST: 0x10,
  OPEN_RESPONSE: 0x11,
  RAKP_1: 0x12,
  RAKP_2: 0x13,
  RAKP_3: 0x14,
  RAKP_4: 0x15,
} as const;

const PRIV_ADMIN = 0x04;

const IPMI_BMC_SLAVE_ADDR = 0x20;
const IPMI_REMOTE_SWID = 0x81;

interface CipherSpec {
  id: 17 | 3;
  authAlg: number;
  integrityAlg: number;
  cryptAlg: number;
  hash: "sha1" | "sha256";
  integrityMacLength: number;
  rakp4MacLength: number;
}

const CIPHER_SUITES: CipherSpec[] = [
  {
    id: 17,
    authAlg: 0x03,        // RAKP-HMAC-SHA256
    integrityAlg: 0x04,   // HMAC-SHA256-128
    cryptAlg: 0x01,       // AES-CBC-128
    hash: "sha256",
    integrityMacLength: 16,
    rakp4MacLength: 16,
  },
  {
    id: 3,
    authAlg: 0x01,        // RAKP-HMAC-SHA1
    integrityAlg: 0x01,   // HMAC-SHA1-96
    cryptAlg: 0x01,       // AES-CBC-128
    hash: "sha1",
    integrityMacLength: 12,
    rakp4MacLength: 12,
  },
];

type ConnectedUdpSocket = {
  send(data: Uint8Array): boolean;
  close(): void;
};

interface PendingRequest {
  matcher: (packet: Buffer) => boolean;
  resolve: (packet: Buffer) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

interface ParsedRmcpPacket {
  payloadType: number;
  sessionId: number;
  sequence: number;
  payload: Buffer;
}

interface ParsedIpmiResponse {
  netfn: number;
  rqSeq: number;
  cmd: number;
  completionCode: number;
  data: Buffer;
}

export interface IpmiClientOptions {
  host: string;
  username: string;
  password: string;
  port?: number;
  timeoutMs?: number;
  retries?: number;
  debug?: boolean;
}

export class IpmiCompletionError extends Error {
  constructor(
    public readonly netfn: number,
    public readonly cmd: number,
    public readonly completionCode: number,
  ) {
    super(
      `IPMI command netfn=${hex(netfn)} cmd=${hex(cmd)} failed: ` +
      `completion code ${hex(completionCode)}`,
    );

    this.name = "IpmiCompletionError";
  }
}

class IpmiTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IpmiTimeoutError";
  }
}

class IpmiAuthenticationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IpmiAuthenticationError";
  }
}

class CipherSuiteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CipherSuiteError";
  }
}

function hex(value: number, width = 2): string {
  return `0x${value.toString(16).padStart(width, "0")}`;
}

function packetHex(data: Uint8Array): string {
  return [...data]
    .map((v) => v.toString(16).padStart(2, "0"))
    .join(" ");
}

function u32le(value: number): Buffer {
  const buffer = Buffer.allocUnsafe(4);
  buffer.writeUInt32LE(value >>> 0, 0);
  return buffer;
}

function randomU32(): number {
  for (;;) {
    const value = randomBytes(4).readUInt32LE(0);

    if (value !== 0) {
      return value;
    }
  }
}

function hmac(
  hash: "sha1" | "sha256",
  key: Uint8Array,
  data: Uint8Array,
): Buffer {
  return createHmac(hash, key)
    .update(data)
    .digest();
}

function equalConstantTime(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }

  return timingSafeEqual(a, b);
}

function checksum(data: Uint8Array): number {
  let sum = 0;

  for (const value of data) {
    sum = (sum + value) & 0xff;
  }

  return (-sum) & 0xff;
}

function checksumValid(data: Uint8Array): boolean {
  let sum = 0;

  for (const value of data) {
    sum = (sum + value) & 0xff;
  }

  return sum === 0;
}

function statusName(status: number): string {
  const names: Record<number, string> = {
    0x00: "No errors",
    0x01: "Insufficient resources",
    0x02: "Invalid session ID",
    0x03: "Invalid payload type",
    0x04: "Invalid authentication algorithm",
    0x05: "Invalid integrity algorithm",
    0x06: "No matching authentication payload",
    0x07: "No matching integrity payload",
    0x08: "Inactive session ID",
    0x09: "Invalid role",
    0x0a: "Unauthorized role/name",
    0x0b: "Insufficient resources for role",
    0x0c: "Invalid username length",
    0x0d: "Unauthorized name",
    0x0f: "Invalid integrity check value",
    0x10: "Invalid confidentiality algorithm",
    0x11: "No matching cipher suite",
    0x12: "Illegal parameter",
  };

  return names[status] ?? `Unknown status ${hex(status)}`;
}

function statusError(stage: string, status: number): Error {
  // Cipher Suiteを変えることで解決する可能性があるもの
  if (
    status === 0x04 ||
    status === 0x05 ||
    status === 0x06 ||
    status === 0x07 ||
    status === 0x10 ||
    status === 0x11
  ) {
    return new CipherSuiteError(
      `${stage}: ${statusName(status)} (${hex(status)})`,
    );
  }

  return new IpmiAuthenticationError(
    `${stage}: ${statusName(status)} (${hex(status)})`,
  );
}

export class IpmiClient {
  private readonly host: string;
  private readonly port: number;
  private readonly username: Buffer;
  private readonly passwordKey: Buffer;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly debug: boolean;

  private socket?: ConnectedUdpSocket;
  private pending?: PendingRequest;

  private cipher?: CipherSpec;

  private consoleId = 0;
  private bmcId = 0;

  private consoleRand = Buffer.alloc(0);
  private bmcRand = Buffer.alloc(0);
  private bmcGuid = Buffer.alloc(0);

  private sik = Buffer.alloc(0);
  private k1 = Buffer.alloc(0);
  private k2 = Buffer.alloc(0);

  private requestedRole = PRIV_ADMIN;

  private outSeq = 0;
  private rqSeq = 0;

  private active = false;
  private connected = false;

  constructor(options: IpmiClientOptions) {
    this.host = options.host;
    this.port = options.port ?? 623;
    this.timeoutMs = options.timeoutMs ?? 1500;
    this.retries = options.retries ?? 3;
    this.debug = options.debug ?? false;

    this.username = Buffer.from(options.username, "utf8");

    if (this.username.length > 16) {
      throw new Error(
        `IPMI username is too long: ${this.username.length} bytes (max 16)`,
      );
    }

    const password = Buffer.from(options.password, "utf8");

    if (password.length > 20) {
      throw new Error(
        `IPMI password is too long: ${password.length} bytes (max 20)`,
      );
    }

    // IPMI authcode bufferは20 bytes。
    // 短いパスワードは0x00で後ろを埋める。
    this.passwordKey = Buffer.alloc(20);
    password.copy(this.passwordKey);
  }

  get cipherSuiteId(): number | null {
    return this.cipher?.id ?? null;
  }

  async connect(): Promise<void> {
    if (this.connected) {
      return;
    }

    if (this.socket) {
      throw new Error("IPMI socket is already open");
    }

    const socket = await Bun.udpSocket({
      connect: {
        hostname: this.host,
        port: this.port,
      },

      socket: {
        data: (_socket, data) => {
          this.onDatagram(Buffer.from(data));
        },
      },
    });

    this.socket = socket;

    let lastError: Error | undefined;

    for (const suite of CIPHER_SUITES) {
      try {
        this.trace(`Trying Cipher Suite ${suite.id}`);

        await this.negotiate(suite);
        await this.setSessionPrivilege();

        this.connected = true;

        this.trace(
          `RMCP+ session active: cipher=${suite.id}, ` +
          `console=${hex(this.consoleId, 8)}, ` +
          `bmc=${hex(this.bmcId, 8)}`,
        );

        return;
      } catch (error) {
        lastError =
          error instanceof Error
            ? error
            : new Error(String(error));

        this.trace(
          `Cipher Suite ${suite.id} failed: ${lastError.message}`,
        );

        if (this.active) {
          try {
            await this.closeSession();
          } catch {
            // fallbackするので無視
          }
        }

        this.active = false;

        // 17で認証情報そのものが拒否された場合は、
        // 3にしても直らないので即終了。
        if (
          suite.id === 17 &&
          lastError instanceof IpmiAuthenticationError
        ) {
          this.closeSocket();
          throw lastError;
        }

        // Cipher 17なら次に3を試す。
        if (suite.id === 17) {
          continue;
        }

        break;
      }
    }

    this.closeSocket();

    throw lastError ?? new Error("Unable to establish RMCP+ session");
  }

  async raw(
    netfn: number,
    cmd: number,
    data: Iterable<number> = [],
  ): Promise<Buffer> {
    if (!this.connected) {
      throw new Error("IPMI session is not connected");
    }

    if (netfn < 0 || netfn > 0x3f) {
      throw new Error(`Invalid NetFn: ${netfn}`);
    }

    if (cmd < 0 || cmd > 0xff) {
      throw new Error(`Invalid command: ${cmd}`);
    }

    const response = await this.sendIpmi(
      netfn,
      cmd,
      Buffer.from(Array.from(data)),
    );

    if (response.completionCode !== 0) {
      throw new IpmiCompletionError(
        netfn,
        cmd,
        response.completionCode,
      );
    }

    return response.data;
  }

  async close(): Promise<void> {
    this.connected = false;

    if (this.active) {
      try {
        await this.closeSession();
      } catch (error) {
        this.trace(
          `Close Session failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }

    this.active = false;
    this.closeSocket();
  }

  // ------------------------------------------------------------------
  // RMCP+ handshake
  // ------------------------------------------------------------------

  private async negotiate(suite: CipherSpec): Promise<void> {
    let lastError: Error | undefined;

    /*
     * Open -> RAKP1 -> RAKP3 の途中でtimeoutした場合は
     * 個々のmessageだけをretryせず、handshake全体をやり直す。
     */
    for (let attempt = 1; attempt <= this.retries; attempt++) {
      this.resetSession(suite);

      try {
        this.trace(
          `Handshake ${attempt}/${this.retries}, cipher=${suite.id}`,
        );

        await this.openSession();
        await this.rakp1();
        await this.rakp3();

        return;
      } catch (error) {
        const err =
          error instanceof Error
            ? error
            : new Error(String(error));

        lastError = err;

        if (
          err instanceof IpmiTimeoutError &&
          attempt < this.retries
        ) {
          this.trace("Handshake timeout; restarting RMCP+ handshake");
          continue;
        }

        throw err;
      }
    }

    throw lastError ?? new Error("RMCP+ negotiation failed");
  }

  private resetSession(suite: CipherSpec): void {
    this.cipher = suite;

    this.consoleId = randomU32();
    this.bmcId = 0;

    this.consoleRand = Buffer.alloc(0);
    this.bmcRand = Buffer.alloc(0);
    this.bmcGuid = Buffer.alloc(0);

    this.sik = Buffer.alloc(0);
    this.k1 = Buffer.alloc(0);
    this.k2 = Buffer.alloc(0);

    this.requestedRole = PRIV_ADMIN;

    this.outSeq = 0;
    this.rqSeq = 0;

    this.active = false;
  }

  private async openSession(): Promise<void> {
    const suite = this.requireCipher();

    const payload = Buffer.alloc(32);

    payload[0] = 0x00; // message tag

    /*
     * ipmitoolの通常ADMIN動作と同じく0。
     * supported algorithmsで可能な最高privilegeを要求。
     */
    payload[1] = 0x00;

    payload[2] = 0x00;
    payload[3] = 0x00;

    payload.writeUInt32LE(this.consoleId, 4);

    // Authentication payload
    payload[8] = 0x00;
    payload[9] = 0x00;
    payload[10] = 0x00;
    payload[11] = 0x08;
    payload[12] = suite.authAlg;

    // Integrity payload
    payload[16] = 0x01;
    payload[17] = 0x00;
    payload[18] = 0x00;
    payload[19] = 0x08;
    payload[20] = suite.integrityAlg;

    // Confidentiality payload
    payload[24] = 0x02;
    payload[25] = 0x00;
    payload[26] = 0x00;
    payload[27] = 0x08;
    payload[28] = suite.cryptAlg;

    const frame = this.buildRmcpPacket(
      PAYLOAD.OPEN_REQUEST,
      payload,
      false,
    );

    const packet = await this.exchangeOnce(
      frame,
      (packet) =>
        this.isRmcpPayload(packet, PAYLOAD.OPEN_RESPONSE),
      "Open Session",
    );

    const response = this.parseRmcpPacket(packet, false);

    if (response.payload.length < 8) {
      throw new Error("Malformed Open Session Response");
    }

    const p = response.payload;
    const status = p[1];

    if (status !== 0) {
      throw statusError("Open Session", status);
    }

    if (p.length < 36) {
      throw new Error(
        `Open Session Response too short: ${p.length}`,
      );
    }

    const returnedConsoleId = p.readUInt32LE(4);

    if (returnedConsoleId !== this.consoleId) {
      throw new Error(
        `Open Session console ID mismatch: expected ` +
        `${hex(this.consoleId, 8)}, got ${hex(returnedConsoleId, 8)}`,
      );
    }

    this.bmcId = p.readUInt32LE(8);

    if (this.bmcId === 0) {
      throw new Error("BMC returned session ID 0");
    }

    const authAlg = p[16];
    const integrityAlg = p[24];
    const cryptAlg = p[32];

    if (
      authAlg !== suite.authAlg ||
      integrityAlg !== suite.integrityAlg ||
      cryptAlg !== suite.cryptAlg
    ) {
      throw new CipherSuiteError(
        `BMC selected unexpected algorithms: ` +
        `auth=${hex(authAlg)}, ` +
        `integrity=${hex(integrityAlg)}, ` +
        `crypt=${hex(cryptAlg)}`,
      );
    }
  }

  private async rakp1(): Promise<void> {
    const suite = this.requireCipher();

    this.consoleRand = randomBytes(16);

    const payload = Buffer.alloc(28 + this.username.length);

    payload[0] = 0x00; // message tag
    payload[1] = 0x00;
    payload[2] = 0x00;
    payload[3] = 0x00;

    payload.writeUInt32LE(this.bmcId, 4);

    this.consoleRand.copy(payload, 8);

    // Requested maximum privilege = Administrator
    payload[24] = PRIV_ADMIN;
    this.requestedRole = payload[24];

    payload[25] = 0x00;
    payload[26] = 0x00;

    payload[27] = this.username.length;
    this.username.copy(payload, 28);

    const frame = this.buildRmcpPacket(
      PAYLOAD.RAKP_1,
      payload,
      false,
    );

    const packet = await this.exchangeOnce(
      frame,
      (packet) =>
        this.isRmcpPayload(packet, PAYLOAD.RAKP_2),
      "RAKP 1",
    );

    const response = this.parseRmcpPacket(packet, false);
    const p = response.payload;

    if (p.length < 8) {
      throw new Error("Malformed RAKP 2");
    }

    const status = p[1];

    if (status !== 0) {
      throw statusError("RAKP 2", status);
    }

    const returnedConsoleId = p.readUInt32LE(4);

    if (returnedConsoleId !== this.consoleId) {
      throw new Error(
        `RAKP 2 console ID mismatch: expected ` +
        `${hex(this.consoleId, 8)}, got ${hex(returnedConsoleId, 8)}`,
      );
    }

    const digestLength =
      suite.hash === "sha256" ? 32 : 20;

    if (p.length < 40 + digestLength) {
      throw new Error(
        `RAKP 2 too short: ${p.length}`,
      );
    }

    this.bmcRand = Buffer.from(p.subarray(8, 24));
    this.bmcGuid = Buffer.from(p.subarray(24, 40));

    const receivedMac = p.subarray(
      40,
      40 + digestLength,
    );

    /*
     * RAKP2 HMAC input:
     *
     * SIDm
     * SIDc
     * Rm
     * Rc
     * GUIDc
     * ROLEm
     * ULENGTHm
     * UNAMEm
     */
    const macInput = Buffer.concat([
      u32le(this.consoleId),
      u32le(this.bmcId),
      this.consoleRand,
      this.bmcRand,
      this.bmcGuid,
      Buffer.from([
        this.requestedRole,
        this.username.length,
      ]),
      this.username,
    ]);

    const expectedMac = hmac(
      suite.hash,
      this.passwordKey,
      macInput,
    );

    if (!equalConstantTime(receivedMac, expectedMac)) {
      throw new IpmiAuthenticationError(
        "RAKP 2 HMAC verification failed",
      );
    }
  }

  private async rakp3(): Promise<void> {
    const suite = this.requireCipher();

    /*
     * RAKP3 authcode input:
     *
     * Rc
     * SIDm
     * ROLEm
     * ULENGTHm
     * UNAMEm
     */
    const rakp3Input = Buffer.concat([
      this.bmcRand,
      u32le(this.consoleId),
      Buffer.from([
        this.requestedRole,
        this.username.length,
      ]),
      this.username,
    ]);

    const rakp3Mac = hmac(
      suite.hash,
      this.passwordKey,
      rakp3Input,
    );

    /*
     * SIK:
     *
     * HMAC(Kuid,
     *      Rm || Rc || ROLEm || ULENGTHm || UNAMEm)
     */
    const sikInput = Buffer.concat([
      this.consoleRand,
      this.bmcRand,
      Buffer.from([
        this.requestedRole,
        this.username.length,
      ]),
      this.username,
    ]);

    this.sik = hmac(
      suite.hash,
      this.passwordKey,
      sikInput,
    );

    // K1 = HMAC(SIK, 0x01 × 20)
    this.k1 = hmac(
      suite.hash,
      this.sik,
      Buffer.alloc(20, 0x01),
    );

    // K2 = HMAC(SIK, 0x02 × 20)
    this.k2 = hmac(
      suite.hash,
      this.sik,
      Buffer.alloc(20, 0x02),
    );

    const payload = Buffer.alloc(
      8 + rakp3Mac.length,
    );

    payload[0] = 0x00; // message tag
    payload[1] = 0x00; // RAKP2 status
    payload[2] = 0x00;
    payload[3] = 0x00;

    payload.writeUInt32LE(this.bmcId, 4);

    rakp3Mac.copy(payload, 8);

    const frame = this.buildRmcpPacket(
      PAYLOAD.RAKP_3,
      payload,
      false,
    );

    const packet = await this.exchangeOnce(
      frame,
      (packet) =>
        this.isRmcpPayload(packet, PAYLOAD.RAKP_4),
      "RAKP 3",
    );

    const response = this.parseRmcpPacket(packet, false);
    const p = response.payload;

    if (p.length < 8) {
      throw new Error("Malformed RAKP 4");
    }

    const status = p[1];

    if (status !== 0) {
      throw statusError("RAKP 4", status);
    }

    const returnedConsoleId = p.readUInt32LE(4);

    if (returnedConsoleId !== this.consoleId) {
      throw new Error(
        `RAKP 4 console ID mismatch: expected ` +
        `${hex(this.consoleId, 8)}, got ${hex(returnedConsoleId, 8)}`,
      );
    }

    if (p.length < 8 + suite.rakp4MacLength) {
      throw new Error(
        `RAKP 4 too short: ${p.length}`,
      );
    }

    /*
     * RAKP4 integrity:
     *
     * HMAC(SIK, Rm || SIDc || GUIDc)
     */
    const rakp4Input = Buffer.concat([
      this.consoleRand,
      u32le(this.bmcId),
      this.bmcGuid,
    ]);

    const expected = hmac(
      suite.hash,
      this.sik,
      rakp4Input,
    ).subarray(0, suite.rakp4MacLength);

    const received = p.subarray(
      8,
      8 + suite.rakp4MacLength,
    );

    if (!equalConstantTime(received, expected)) {
      throw new IpmiAuthenticationError(
        "RAKP 4 integrity verification failed",
      );
    }

    this.active = true;
  }

  // ------------------------------------------------------------------
  // IPMI commands
  // ------------------------------------------------------------------

  private async setSessionPrivilege(): Promise<void> {
    const response = await this.sendIpmi(
      0x06,
      0x3b,
      Buffer.from([PRIV_ADMIN]),
    );

    if (response.completionCode !== 0) {
      throw new IpmiCompletionError(
        0x06,
        0x3b,
        response.completionCode,
      );
    }
  }

  private async closeSession(): Promise<void> {
    if (!this.active) {
      return;
    }

    const response = await this.sendIpmi(
      0x06,
      0x3c,
      u32le(this.bmcId),
      1,
    );

    if (response.completionCode !== 0) {
      throw new IpmiCompletionError(
        0x06,
        0x3c,
        response.completionCode,
      );
    }

    this.active = false;
  }

  private async sendIpmi(
    netfn: number,
    cmd: number,
    data: Buffer,
    retries = this.retries,
  ): Promise<ParsedIpmiResponse> {
    if (!this.active) {
      throw new Error("RMCP+ session is not active");
    }

    // 6-bit request sequence
    this.rqSeq = (this.rqSeq + 1) & 0x3f;

    const rqSeq = this.rqSeq;

    const payload = this.buildIpmiRequest(
      netfn,
      cmd,
      rqSeq,
      data,
    );

    /*
     * retry時にも同じIPMI rqSeq / RMCP+ sequenceを再送する。
     */
    const frame = this.buildRmcpPacket(
      PAYLOAD.IPMI,
      payload,
      true,
    );

    let lastError: Error | undefined;

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        const packet = await this.exchangeOnce(
          frame,
          (packet) =>
            this.matchesIpmiResponse(
              packet,
              netfn,
              cmd,
              rqSeq,
            ),
          `IPMI ${hex(netfn)}/${hex(cmd)}`,
        );

        const rmcp = this.parseRmcpPacket(
          packet,
          true,
        );

        const response = this.parseIpmiResponse(
          rmcp.payload,
        );

        return response;
      } catch (error) {
        const err =
          error instanceof Error
            ? error
            : new Error(String(error));

        lastError = err;

        if (
          !(err instanceof IpmiTimeoutError) ||
          attempt === retries
        ) {
          throw err;
        }

        this.trace(
          `IPMI request timeout; retry ${attempt}/${retries}`,
        );
      }
    }

    throw lastError ?? new Error("IPMI request failed");
  }

  private buildIpmiRequest(
    netfn: number,
    cmd: number,
    rqSeq: number,
    data: Buffer,
  ): Buffer {
    const first = Buffer.from([
      IPMI_BMC_SLAVE_ADDR,
      (netfn << 2) & 0xfc,
    ]);

    const csum1 = checksum(first);

    const second = Buffer.concat([
      Buffer.from([
        IPMI_REMOTE_SWID,
        (rqSeq << 2) & 0xfc,
        cmd,
      ]),
      data,
    ]);

    const csum2 = checksum(second);

    return Buffer.concat([
      first,
      Buffer.from([csum1]),
      second,
      Buffer.from([csum2]),
    ]);
  }

  private parseIpmiResponse(
    payload: Buffer,
  ): ParsedIpmiResponse {
    /*
     * RqAddr
     * NetFn/LUN
     * Checksum1
     * RsAddr
     * RqSeq/LUN
     * Cmd
     * CompletionCode
     * Data...
     * Checksum2
     */
    if (payload.length < 8) {
      throw new Error(
        `IPMI response too short: ${payload.length}`,
      );
    }

    if (!checksumValid(payload.subarray(0, 3))) {
      throw new Error("Invalid IPMI checksum #1");
    }

    if (!checksumValid(payload.subarray(3))) {
      throw new Error("Invalid IPMI checksum #2");
    }

    return {
      netfn: payload[1] >> 2,
      rqSeq: payload[4] >> 2,
      cmd: payload[5],
      completionCode: payload[6],
      data: Buffer.from(
        payload.subarray(7, payload.length - 1),
      ),
    };
  }

  private matchesIpmiResponse(
    packet: Buffer,
    requestNetfn: number,
    cmd: number,
    rqSeq: number,
  ): boolean {
    try {
      const rmcp = this.parseRmcpPacket(
        packet,
        true,
      );

      if (rmcp.payloadType !== PAYLOAD.IPMI) {
        return false;
      }

      const response = this.parseIpmiResponse(
        rmcp.payload,
      );

      const expectedNetfn =
        (requestNetfn + 1) & 0x3f;

      return (
        response.netfn === expectedNetfn &&
        response.cmd === cmd &&
        response.rqSeq === rqSeq
      );
    } catch {
      return false;
    }
  }

  // ------------------------------------------------------------------
  // RMCP+ framing
  // ------------------------------------------------------------------

  private buildRmcpPacket(
    payloadType: number,
    payload: Buffer,
    secure: boolean,
  ): Buffer {
    const suite = this.requireCipher();

    let wirePayload = payload;

    if (secure) {
      if (!this.active) {
        throw new Error(
          "Cannot build secure packet before RAKP is complete",
        );
      }

      wirePayload = this.encryptPayload(payload);
    }

    const header = Buffer.alloc(16);

    RMCP_HEADER.copy(header, 0);

    header[4] = RMCP_PLUS_AUTH_TYPE;

    header[5] = payloadType;

    if (secure) {
      // encrypted + authenticated
      header[5] |= 0x80;
      header[5] |= 0x40;

      // Client -> BMC uses managed-system session ID
      header.writeUInt32LE(this.bmcId, 6);

      header.writeUInt32LE(
        this.outSeq >>> 0,
        10,
      );
    }

    header.writeUInt16LE(
      wirePayload.length,
      14,
    );

    let packet = Buffer.concat([
      header,
      wirePayload,
    ]);

    if (secure) {
      /*
       * Integrity-covered part begins at AuthType (offset 4).
       *
       * AuthType..payload + integrity pad +
       * pad length + next header
       *
       * must be multiple of 4.
       */
      const lengthBeforeAuth =
        12 +
        wirePayload.length +
        1 +
        1;

      const padLength =
        (4 - (lengthBeforeAuth % 4)) % 4;

      const trailer = Buffer.alloc(
        padLength + 2,
      );

      trailer.fill(0xff, 0, padLength);
      trailer[padLength] = padLength;
      trailer[padLength + 1] = 0x07;

      const authInput = Buffer.concat([
        packet.subarray(4),
        trailer,
      ]);

      const authCode = hmac(
        suite.hash,
        this.k1,
        authInput,
      ).subarray(
        0,
        suite.integrityMacLength,
      );

      packet = Buffer.concat([
        packet,
        trailer,
        authCode,
      ]);
    }

    this.outSeq = (this.outSeq + 1) >>> 0;

    // RMCP+ sequence 0 is skipped after wrap.
    if (this.outSeq === 0) {
      this.outSeq = 1;
    }

    return packet;
  }

  private parseRmcpPacket(
    packet: Buffer,
    secure: boolean,
  ): ParsedRmcpPacket {
    if (packet.length < 16) {
      throw new Error(
        `RMCP+ packet too short: ${packet.length}`,
      );
    }

    if (
      packet[0] !== 0x06 ||
      packet[1] !== 0x00 ||
      packet[2] !== 0xff ||
      packet[3] !== 0x07
    ) {
      throw new Error("Invalid RMCP header");
    }

    if (packet[4] !== RMCP_PLUS_AUTH_TYPE) {
      throw new Error(
        `Unexpected auth type: ${hex(packet[4])}`,
      );
    }

    const payloadFlags = packet[5];
    const payloadType = payloadFlags & 0x3f;

    const encrypted =
      (payloadFlags & 0x80) !== 0;

    const authenticated =
      (payloadFlags & 0x40) !== 0;

    const sessionId = packet.readUInt32LE(6);
    const sequence = packet.readUInt32LE(10);
    const payloadLength = packet.readUInt16LE(14);

    const payloadEnd =
      16 + payloadLength;

    if (payloadEnd > packet.length) {
      throw new Error(
        "RMCP+ payload length exceeds packet length",
      );
    }

    const wirePayload = packet.subarray(
      16,
      payloadEnd,
    );

    if (!secure) {
      return {
        payloadType,
        sessionId,
        sequence,
        payload: Buffer.from(wirePayload),
      };
    }

    const suite = this.requireCipher();

    if (!this.active) {
      throw new Error(
        "Received secure RMCP+ packet before session is active",
      );
    }

    if (!encrypted || !authenticated) {
      throw new Error(
        "Expected encrypted/authenticated RMCP+ response",
      );
    }

    /*
     * BMC -> console uses console session ID.
     */
    if (sessionId !== this.consoleId) {
      throw new Error(
        `RMCP+ session ID mismatch: expected ` +
        `${hex(this.consoleId, 8)}, got ${hex(sessionId, 8)}`,
      );
    }

    const authLength =
      suite.integrityMacLength;

    if (
      packet.length <
      payloadEnd + 2 + authLength
    ) {
      throw new Error(
        "RMCP+ secure packet is truncated",
      );
    }

    const authStart =
      packet.length - authLength;

    const trailer = packet.subarray(
      payloadEnd,
      authStart,
    );

    if (trailer.length < 2) {
      throw new Error(
        "Missing RMCP+ integrity trailer",
      );
    }

    const padLength =
      trailer[trailer.length - 2];

    const nextHeader =
      trailer[trailer.length - 1];

    if (nextHeader !== 0x07) {
      throw new Error(
        `Unexpected RMCP+ next header: ${hex(nextHeader)}`,
      );
    }

    if (trailer.length !== padLength + 2) {
      throw new Error(
        "Invalid RMCP+ integrity padding length",
      );
    }

    for (let i = 0; i < padLength; i++) {
      if (trailer[i] !== 0xff) {
        throw new Error(
          "Invalid RMCP+ integrity padding",
        );
      }
    }

    const receivedAuth =
      packet.subarray(authStart);

    /*
     * HMAC input:
     * AuthType (offset 4) through Next Header.
     */
    const authInput =
      packet.subarray(4, authStart);

    const expectedAuth = hmac(
      suite.hash,
      this.k1,
      authInput,
    ).subarray(
      0,
      suite.integrityMacLength,
    );

    if (
      !equalConstantTime(
        receivedAuth,
        expectedAuth,
      )
    ) {
      throw new Error(
        "RMCP+ integrity HMAC verification failed",
      );
    }

    return {
      payloadType,
      sessionId,
      sequence,
      payload: this.decryptPayload(
        wirePayload,
      ),
    };
  }

  // ------------------------------------------------------------------
  // AES-CBC confidentiality
  // ------------------------------------------------------------------

  private encryptPayload(
    payload: Buffer,
  ): Buffer {
    /*
     * Plaintext:
     *
     * payload
     * 01 02 03 ... confidentiality-pad
     * pad-length
     *
     * whole plaintext => multiple of 16.
     */
    const mod =
      (payload.length + 1) % 16;

    const padLength =
      mod === 0 ? 0 : 16 - mod;

    const plaintext = Buffer.alloc(
      payload.length + padLength + 1,
    );

    payload.copy(plaintext);

    for (let i = 0; i < padLength; i++) {
      plaintext[payload.length + i] =
        i + 1;
    }

    plaintext[plaintext.length - 1] =
      padLength;

    const iv = randomBytes(16);

    const cipher = createCipheriv(
      "aes-128-cbc",
      this.k2.subarray(0, 16),
      iv,
    );

    cipher.setAutoPadding(false);

    const ciphertext = Buffer.concat([
      cipher.update(plaintext),
      cipher.final(),
    ]);

    // RMCP+ confidentiality header = IV
    return Buffer.concat([
      iv,
      ciphertext,
    ]);
  }

  private decryptPayload(
    wirePayload: Buffer,
  ): Buffer {
    if (
      wirePayload.length < 32 ||
      (wirePayload.length - 16) % 16 !== 0
    ) {
      throw new Error(
        `Malformed AES RMCP+ payload length: ${wirePayload.length}`,
      );
    }

    const iv =
      wirePayload.subarray(0, 16);

    const ciphertext =
      wirePayload.subarray(16);

    const decipher = createDecipheriv(
      "aes-128-cbc",
      this.k2.subarray(0, 16),
      iv,
    );

    decipher.setAutoPadding(false);

    const plaintext = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    if (plaintext.length === 0) {
      throw new Error(
        "Empty decrypted RMCP+ payload",
      );
    }

    const padLength =
      plaintext[plaintext.length - 1];

    if (padLength > 15) {
      throw new Error(
        `Invalid confidentiality pad length: ${padLength}`,
      );
    }

    const payloadLength =
      plaintext.length -
      padLength -
      1;

    if (payloadLength < 0) {
      throw new Error(
        "Malformed confidentiality padding",
      );
    }

    for (let i = 0; i < padLength; i++) {
      if (
        plaintext[payloadLength + i] !==
        i + 1
      ) {
        throw new Error(
          "Malformed confidentiality padding",
        );
      }
    }

    return Buffer.from(
      plaintext.subarray(
        0,
        payloadLength,
      ),
    );
  }

  // ------------------------------------------------------------------
  // UDP request / response
  // ------------------------------------------------------------------

  private async exchangeOnce(
    frame: Buffer,
    matcher: (packet: Buffer) => boolean,
    description: string,
  ): Promise<Buffer> {
    if (!this.socket) {
      throw new Error("UDP socket is not open");
    }

    if (this.pending) {
      throw new Error(
        "Concurrent IPMI requests are not supported",
      );
    }

    this.tracePacket("TX", frame);

    return new Promise<Buffer>(
      (resolve, reject) => {
        let entry!: PendingRequest;

        const timer = setTimeout(() => {
          if (this.pending === entry) {
            this.pending = undefined;
          }

          reject(
            new IpmiTimeoutError(
              `${description} timed out after ${this.timeoutMs} ms`,
            ),
          );
        }, this.timeoutMs);

        entry = {
          matcher,
          resolve,
          reject,
          timer,
        };

        this.pending = entry;

        const sent =
          this.socket!.send(frame);

        if (!sent) {
          if (this.pending === entry) {
            this.pending = undefined;
          }

          clearTimeout(timer);

          reject(
            new Error(
              `UDP send failed for ${description}`,
            ),
          );
        }
      },
    );
  }

  private onDatagram(packet: Buffer): void {
    this.tracePacket("RX", packet);

    const pending = this.pending;

    if (!pending) {
      return;
    }

    let matched = false;

    try {
      matched =
        pending.matcher(packet);
    } catch {
      matched = false;
    }

    if (!matched) {
      return;
    }

    this.pending = undefined;
    clearTimeout(pending.timer);

    pending.resolve(packet);
  }

  private isRmcpPayload(
    packet: Buffer,
    payloadType: number,
  ): boolean {
    try {
      const parsed =
        this.parseRmcpPacket(
          packet,
          false,
        );

      return (
        parsed.payloadType === payloadType
      );
    } catch {
      return false;
    }
  }

  private closeSocket(): void {
    if (this.pending) {
      const pending = this.pending;

      this.pending = undefined;
      clearTimeout(pending.timer);

      pending.reject(
        new Error("UDP socket closed"),
      );
    }

    if (this.socket) {
      this.socket.close();
      this.socket = undefined;
    }
  }

  private requireCipher(): CipherSpec {
    if (!this.cipher) {
      throw new Error(
        "Cipher Suite has not been selected",
      );
    }

    return this.cipher;
  }

  private trace(message: string): void {
    if (this.debug) {
      console.error(`[ipmi] ${message}`);
    }
  }

  private tracePacket(
    direction: "TX" | "RX",
    packet: Buffer,
  ): void {
    if (this.debug) {
      console.error(
        `[ipmi] ${direction} ${packetHex(packet)}`,
      );
    }
  }
}
