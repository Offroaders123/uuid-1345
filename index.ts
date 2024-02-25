/* jshint node: true */

import crypto = require("crypto");

// error codes
var invalidNamespace =
  "options.namespace must be a string or a Buffer " +
  "containing a valid UUID, or a UUID object";

var invalidName =
  "options.name must be either a string or a Buffer";

var invalidMacAddress =
  "invalid options.mac - must either not be set, the value `false`, " +
  "a Buffer of length 6, or a MAC address as a string";

var moreThan10000 =
  "can not generate more than 10000 UUIDs per second";

// Node ID according to rfc4122#section-4.5
var randomHost = crypto.randomBytes(16);
randomHost[0] = randomHost[0]! | 0x01;

// randomize clockSeq initially, as per rfc4122#section-4.1.5
var seed = crypto.randomBytes(2);
var clockSeq = (seed[0]! | (seed[1]! << 8)) & 0x3fff;

// clock values
var lastMTime = 0;
var lastNTime = 0;

// lookup table hex to byte
var hex2byte: Record<string, number> = {};

// lookup table byte to hex
var byte2hex: string[] = [];

// populate lookup tables
for (var i = 0; i < 256; i++) {
    var hex = (i + 0x100).toString(16).substr(1);
    hex2byte[hex] = i;
    byte2hex[i] = hex;
}

var newBufferFromSize: (size: number) => Buffer;
var newBufferFromBuffer: (buf: Buffer) => Buffer;
if (Buffer.allocUnsafe) {
    // both `Buffer.allocUnsafe` and `Buffer.from` are added in
    // Node.js v5.10.0
    /* istanbul ignore next */
    newBufferFromSize = function newBufferFromSize(size) {
        return Buffer.allocUnsafe(size);
    };
    /* istanbul ignore next */
    newBufferFromBuffer = function newBufferFromBuffer(buf) {
        return Buffer.from(buf);
    };
} else {
    /* istanbul ignore next */
    newBufferFromSize = function(size) {
        return new Buffer(size);
    };
    /* istanbul ignore next */
    newBufferFromBuffer = function(buf) {
        return new Buffer(buf);
    };
}

function parseMacAddress(address: string): Buffer {
    var buffer = newBufferFromSize(6);
    buffer[0] = hex2byte[address[0]! + address[1]!]!;
    buffer[1] = hex2byte[address[3]! + address[4]!]!;
    buffer[2] = hex2byte[address[6]! + address[7]!]!;
    buffer[3] = hex2byte[address[9]! + address[10]!]!;
    buffer[4] = hex2byte[address[12]! + address[13]!]!;
    buffer[5] = hex2byte[address[15]! + address[16]!]!;
    return buffer;
}

// MAC address for v1 uuids
var macAddress = randomHost;
var macAddressLoaded = false;

function loadMacAddress(): void {
  (require("macaddress") as typeof import("macaddress")).one(function (err, result) {
      if (!err) {
          macAddress = parseMacAddress(result);
      }
      macAddressLoaded = true;
  });
}

type UUIDOptions = { clockSeq?: number; encoding?: "ascii" | "binary" | "object"; namespace?: string; name?: string; mac?: string | false; };

type UUIDLike = string | Buffer | UUID;

type UUIDCallback = (err: string | null, result: UUIDLike | null) => void;

// UUID class
class UUID {
version?: number;
variant: Check["variant"];
ascii?: string;
binary?: Buffer;

constructor(uuid: string | Buffer) {

    var check = UUID.check(uuid);
    if (!check) {
        throw "not a UUID";
    }

    this.version = check.version;
    this.variant = check.variant;

    this[check.format] = uuid as string & Buffer;
}

toString(): string {
    if (!this.ascii) {
        var ascii = UUID.stringify(this.binary!);
        this.ascii = ascii;
    }
    return this.ascii;
}

toBuffer(): Buffer {
    if (!this.binary) {
        this.binary = UUID.parse(this.ascii!);
    }
    return newBufferFromBuffer(this.binary);
}

inspect(): string {
    return "UUID v" + this.version + " " + this.toString();
}

static stringify = stringify;

static parse = parse;

static check = check;

// according to rfc4122#section-4.1.7
static nil = new UUID("00000000-0000-0000-0000-000000000000");

// from rfc4122#appendix-C
static namespace = {
    dns:  new UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8"),
    url:  new UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8"),
    oid:  new UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8"),
    x500: new UUID("6ba7b814-9dad-11d1-80b4-00c04fd430c8")
} as const;

static v1(arg1: UUIDOptions): UUIDLike;
static v1(arg1: UUIDOptions, arg2?: UUIDCallback): void;
static v1(arg1: UUIDOptions, arg2?: UUIDCallback): UUIDLike | void {

    var options: UUIDOptions = arg1 || {};
    var callback = typeof arg1 === "function" ? arg1 : arg2;

    var nodeId = options.mac;

    if (nodeId === undefined) {
        if(!macAddressLoaded) {
            loadMacAddress();
        }
        if (!macAddressLoaded && callback) {
            setImmediate(function () {
                UUID.v1(options, callback);
            });
            return;
        }
        return uuidTimeBased(macAddress, options, callback);
    }
    if (nodeId === false) {
        return uuidTimeBased(randomHost, options, callback);
    }
    return uuidTimeBased(parseMacAddress(nodeId), options, callback);
}

static v4 = uuidRandom;

static v4fast = uuidRandomFast;

static v3(options: UUIDOptions): UUIDLike;
static v3(options: UUIDOptions, callback?: UUIDCallback): void;
static v3(options: UUIDOptions, callback?: UUIDCallback): void | UUIDLike {
    return uuidNamed("md5", 0x30, options, callback);
}

static v5(options: UUIDOptions): UUIDLike;
static v5(options: UUIDOptions, callback?: UUIDCallback): void;
static v5(options: UUIDOptions, callback?: UUIDCallback): void | UUIDLike {
    return uuidNamed("sha1", 0x50, options, callback);
}
}

function error(message: string, callback?: UUIDCallback): void {
    if (callback) {
        callback(message, null);
    } else {
        throw new Error(message);
    }
}

// read stringified uuid into a Buffer
function parse(string: string): Buffer {

    var buffer = newBufferFromSize(16);
    var j = 0;
    for (var i = 0; i < 16; i++) {
        buffer[i]! = hex2byte[string[j++]! + string[j++]!]!;
        if (i === 3 || i === 5 || i === 7 || i === 9) {
            j += 1;
        }
    }

    return buffer;
}

// according to rfc4122#section-4.1.1
function getVariant(bits: number): "ncs" | "rfc4122" | "microsoft" | "future" {
    switch (bits) {
        case 0: case 1: case 3:
            return "ncs";
        case 4: case 5:
            return "rfc4122";
        case 6:
            return "microsoft";
        default:
            return "future";
    }
}

type Check = { version?: number; variant: "nil" | "ncs" | "rfc4122" | "microsoft" | "future"; format: "ascii" | "binary"; };

function check(uuid: string | Buffer, offset?: number): false | Check {

    if (typeof uuid === "string") {
        uuid = uuid.toLowerCase();

        if (!/^[a-f0-9]{8}(\-[a-f0-9]{4}){3}\-([a-f0-9]{12})$/.test(uuid)) {
            return false;
        }

        if (uuid === "00000000-0000-0000-0000-000000000000") {
            return { version: undefined, variant: "nil", format: "ascii" };
        }

        return {
            version: (hex2byte[uuid[14]! + uuid[15]!]! & 0xf0) >> 4,
            variant: getVariant((hex2byte[uuid[19]! + uuid[20]!]! & 0xe0) >> 5),
            format: "ascii"
        };
    }

        offset = offset || 0;

        if (uuid.length < offset + 16) {
            return false;
        }

        for (var i = 0; i < 16; i++) {
            if (uuid[offset + i] !== 0) {
                break;
            }
        }
        if (i === 16) {
            return { version: undefined, variant: "nil", format: "binary" };
        }

        return {
            version: (uuid[offset + 6]! & 0xf0) >> 4,
            variant: getVariant((uuid[offset + 8]! & 0xe0) >> 5),
            format: "binary"
        };
}

// v1
function uuidTimeBased(nodeId: Buffer, options: UUIDOptions, callback?: UUIDCallback): UUIDLike {

    var mTime = Date.now();
    var nTime = lastNTime + 1;
    var delta = (mTime - lastMTime) + (nTime - lastNTime) / 10000;

    if (delta < 0) {
        clockSeq = (clockSeq + 1) & 0x3fff;
        nTime = 0;
    } else if (mTime > lastMTime) {
        nTime = 0;
    } else if (nTime >= 10000) {
        return moreThan10000;
    }

    lastMTime = mTime;
    lastNTime = nTime;

    // unix timestamp to gregorian epoch as per rfc4122#section-4.5
    mTime += 12219292800000;

    var buffer = newBufferFromSize(16);
    var myClockSeq = options.clockSeq === undefined ?
            clockSeq : (options.clockSeq & 0x3fff);
    var timeLow = ((mTime & 0xfffffff) * 10000 + nTime) % 0x100000000;
    var timeHigh = (mTime / 0x100000000 * 10000) & 0xfffffff;

    buffer[0] = timeLow >>> 24 & 0xff;
    buffer[1] = timeLow >>> 16 & 0xff;
    buffer[2] = timeLow >>> 8 & 0xff;
    buffer[3] = timeLow & 0xff;

    buffer[4] = timeHigh >>> 8 & 0xff;
    buffer[5] = timeHigh & 0xff;

    buffer[6] = (timeHigh >>> 24 & 0x0f) | 0x10;
    buffer[7] = (timeHigh >>> 16 & 0x3f) | 0x80;

    buffer[8] = myClockSeq >>> 8;
    buffer[9] = myClockSeq & 0xff;

    var result: UUIDLike;
    switch (options.encoding && options.encoding[0]) {
        case "b":
        case "B":
            buffer[10]! = nodeId[0]!;
            buffer[11]! = nodeId[1]!;
            buffer[12]! = nodeId[2]!;
            buffer[13]! = nodeId[3]!;
            buffer[14]! = nodeId[4]!;
            buffer[15]! = nodeId[5]!;
            result = buffer;
            break;
        case "o":
        case "U":
            buffer[10]! = nodeId[0]!;
            buffer[11]! = nodeId[1]!;
            buffer[12]! = nodeId[2]!;
            buffer[13]! = nodeId[3]!;
            buffer[14]! = nodeId[4]!;
            buffer[15]! = nodeId[5]!;
            result = new UUID(buffer);
            break;
        default:
            result = byte2hex[buffer[0]!]! + byte2hex[buffer[1]!]! +
                     byte2hex[buffer[2]!]! + byte2hex[buffer[3]!]! + "-" +
                     byte2hex[buffer[4]!]! + byte2hex[buffer[5]!]! + "-" +
                     byte2hex[buffer[6]!]! + byte2hex[buffer[7]!]! + "-" +
                     byte2hex[buffer[8]!]! + byte2hex[buffer[9]!]! + "-" +
                     byte2hex[nodeId[0]!]! + byte2hex[nodeId[1]!]! +
                     byte2hex[nodeId[2]!]! + byte2hex[nodeId[3]!]! +
                     byte2hex[nodeId[4]!]! + byte2hex[nodeId[5]!]!;
            break;
    }
    if (callback) {
        setImmediate(function () {
            callback(null, result);
        });
    }
    return result;
}

// v3 + v5
function uuidNamed(hashFunc: string, version: number, arg1: UUIDOptions): UUIDLike;
function uuidNamed(hashFunc: string, version: number, arg1: UUIDOptions, arg2?: UUIDCallback): void;
function uuidNamed(hashFunc: string, version: number, arg1: UUIDOptions, arg2?: UUIDCallback): void | UUIDLike {

    var options: UUIDOptions = arg1 || {};
    var callback = typeof arg1 === "function" ? arg1 : arg2;

    var namespace: string | Buffer = options.namespace;
    var name = options.name;

    var hash = crypto.createHash(hashFunc);

    if (typeof namespace === "string") {
        if (!check(namespace)) {
            return error(invalidNamespace, callback);
        }
        namespace = parse(namespace);
    } else if (namespace instanceof UUID) {
        namespace = namespace.toBuffer();
    } else if (!(namespace instanceof Buffer) || namespace.length !== 16) {
        return error(invalidNamespace, callback);
    }

    var nameIsNotAString = typeof name !== "string";
    if (nameIsNotAString && !(name instanceof Buffer)) {
        return error(invalidName, callback);
    }

    hash.update(namespace);
    hash.update(options.name, nameIsNotAString ? "binary" : "utf8");

    var buffer = hash.digest();

    var result: UUIDLike;
    switch (options.encoding && options.encoding[0]) {
        case "b":
        case "B":
            buffer[6] = (buffer[6]! & 0x0f) | version;
            buffer[8] = (buffer[8]! & 0x3f) | 0x80;
            result = buffer;
            break;
        case "o":
        case "U":
            buffer[6] = (buffer[6]! & 0x0f) | version;
            buffer[8] = (buffer[8]! & 0x3f) | 0x80;
            result = new UUID(buffer);
            break;
        default:
            result = byte2hex[buffer[0]!]! + byte2hex[buffer[1]!]! +
                     byte2hex[buffer[2]!]! + byte2hex[buffer[3]!]! + "-" +
                     byte2hex[buffer[4]!]! + byte2hex[buffer[5]!]! + "-" +
                     byte2hex[(buffer[6]! & 0x0f) | version]! +
                     byte2hex[buffer[7]!]! + "-" +
                     byte2hex[(buffer[8]! & 0x3f) | 0x80]! +
                     byte2hex[buffer[9]!]! + "-" +
                     byte2hex[buffer[10]!]! + byte2hex[buffer[11]!]! +
                     byte2hex[buffer[12]!]! + byte2hex[buffer[13]!]! +
                     byte2hex[buffer[14]!]! + byte2hex[buffer[15]!]!;
            break;
    }
    if (callback) {
        setImmediate(function () {
            callback!(null, result);
        });
    } else {
        return result;
    }
}

// v4
function uuidRandom(arg1: UUIDOptions): UUIDLike;
function uuidRandom(arg1: UUIDOptions, arg2?: UUIDCallback): void;
function uuidRandom(arg1: UUIDOptions, arg2?: UUIDCallback): UUIDLike | void {

    var options: UUIDOptions = arg1 || {};
    var callback = typeof arg1 === "function" ? arg1 : arg2;

    var buffer = crypto.randomBytes(16);

    buffer[6] = (buffer[6]! & 0x0f) | 0x40;
    buffer[8] = (buffer[8]! & 0x3f) | 0x80;

    var result: UUIDLike;
    switch (options.encoding && options.encoding[0]) {
        case "b":
        case "B":
            result = buffer;
            break;
        case "o":
        case "U":
            result = new UUID(buffer);
            break;
        default:
            result = byte2hex[buffer[0]!]! + byte2hex[buffer[1]!]! +
                     byte2hex[buffer[2]!]! + byte2hex[buffer[3]!]! + "-" +
                     byte2hex[buffer[4]!]! + byte2hex[buffer[5]!]! + "-" +
                     byte2hex[(buffer[6]! & 0x0f) | 0x40]! +
                     byte2hex[buffer[7]!]! + "-" +
                     byte2hex[(buffer[8]! & 0x3f) | 0x80]! +
                     byte2hex[buffer[9]!]! + "-" +
                     byte2hex[buffer[10]!]! + byte2hex[buffer[11]!]! +
                     byte2hex[buffer[12]!]! + byte2hex[buffer[13]!]! +
                     byte2hex[buffer[14]!]! + byte2hex[buffer[15]!]!;
            break;
    }
    if (callback) {
        setImmediate(function () {
            callback!(null, result);
        });
    } else {
        return result;
    }
}

// v4 fast
function uuidRandomFast(): string {

    var r1 = Math.random() * 0x100000000;
    var r2 = Math.random() * 0x100000000;
    var r3 = Math.random() * 0x100000000;
    var r4 = Math.random() * 0x100000000;

    return byte2hex[ r1        & 0xff]! +
           byte2hex[ r1 >>>  8 & 0xff]! +
           byte2hex[ r1 >>> 16 & 0xff]! +
           byte2hex[ r1 >>> 24 & 0xff]! + "-" +
           byte2hex[ r2 & 0xff]! +
           byte2hex[ r2 >>>  8 & 0xff]! + "-" +
           byte2hex[(r2 >>> 16 & 0x0f) | 0x40]! +
           byte2hex[ r2 >>> 24 & 0xff]! + "-" +
           byte2hex[(r3 & 0x3f) | 0x80]! +
           byte2hex[ r3 >>>  8 & 0xff]! + "-" +
           byte2hex[ r3 >>> 16 & 0xff]! +
           byte2hex[ r3 >>> 24 & 0xff]! +
           byte2hex[ r4        & 0xff]! +
           byte2hex[ r4 >>>  8 & 0xff]! +
           byte2hex[ r4 >>> 16 & 0xff]! +
           byte2hex[ r4 >>> 24 & 0xff]!;
}

function stringify(buffer: Buffer): string {
    return byte2hex[buffer[0]!]!  + byte2hex[buffer[1]!]!  +
           byte2hex[buffer[2]!]!  + byte2hex[buffer[3]!]!  + "-" +
           byte2hex[buffer[4]!]!  + byte2hex[buffer[5]!]!  + "-" +
           byte2hex[buffer[6]!]!  + byte2hex[buffer[7]!]!  + "-" +
           byte2hex[buffer[8]!]!  + byte2hex[buffer[9]!]!  + "-" +
           byte2hex[buffer[10]!]! + byte2hex[buffer[11]!]! +
           byte2hex[buffer[12]!]! + byte2hex[buffer[13]!]! +
           byte2hex[buffer[14]!]! + byte2hex[buffer[15]!]!;
}

export = UUID;
