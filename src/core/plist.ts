import { TraceForgeError } from "./errors.js";

/**
 * Property list reader for bundle manifests.
 *
 * Apple writes property lists in three encodings that appear in real bundles:
 * XML, binary (`bplist00`) and, rarely, JSON. Everything here is bounded: a
 * malformed or oversized manifest becomes a `TraceForgeError` or an explicit
 * limitation, never unbounded work. Old-style NeXT ASCII property lists are
 * reported as unsupported instead of being guessed.
 */

export type PlistValue =
  | string
  | number
  | boolean
  | null
  | readonly PlistValue[]
  | { readonly [key: string]: PlistValue };

export type PlistEncoding = "xml" | "binary" | "json";

export interface PlistDocument {
  readonly encoding: PlistEncoding;
  readonly root: PlistValue;
  readonly limitations: readonly string[];
}

export const MAX_PLIST_BYTES = 4 * 1024 * 1024;
const MAX_DEPTH = 32;
const MAX_NODES = 200_000;
const MAX_TEXT_CHARS = 8_192;
const BINARY_MAGIC = "bplist00";
const UNIX_2001_MS = 978_307_200_000;

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
};

export const plistEncoding = (buffer: Buffer): PlistEncoding | "unknown" => {
  if (buffer.length >= BINARY_MAGIC.length && buffer.subarray(0, BINARY_MAGIC.length).toString("latin1") === BINARY_MAGIC)
    return "binary";
  const head = buffer.subarray(0, Math.min(buffer.length, 512)).toString("utf8").replace(/^\uFEFF/u, "").trimStart();
  if (head.startsWith("<?xml") || head.startsWith("<plist") || head.startsWith("<!--")) return "xml";
  if (head.startsWith("{")) return "json";
  return "unknown";
};

export const parsePlist = (buffer: Buffer): PlistDocument => {
  if (buffer.length > MAX_PLIST_BYTES)
    throw new TraceForgeError(
      "file_too_large",
      `Property list is larger than the ${MAX_PLIST_BYTES} byte manifest limit`,
    );
  const limitations: string[] = [];
  const encoding = plistEncoding(buffer);
  if (encoding === "unknown")
    throw new TraceForgeError(
      "parse_error",
      "Property list encoding was not recognized; only XML, binary and JSON plists are read",
    );
  if (encoding === "binary")
    return { encoding, root: parseBinaryPlist(buffer, limitations), limitations };
  if (encoding === "json") {
    let text: string;
    try {
      text = buffer.toString("utf8");
    } catch (cause) {
      throw new TraceForgeError("parse_error", "JSON property list is not valid UTF-8", { cause });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (cause) {
      throw new TraceForgeError(
        "parse_error",
        "property list is not JSON; old-style ASCII property lists are not supported",
        { cause },
      );
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      throw new TraceForgeError("parse_error", "JSON property list root is not an object");
    limitations.push("A JSON property list was accepted; Apple tooling normally writes XML or binary.");
    return { encoding, root: toPlistValue(parsed, limitations), limitations };
  }
  return { encoding, root: parseXmlPlist(buffer.toString("utf8"), limitations), limitations };
};

const toPlistValue = (value: unknown, limitations: string[]): PlistValue => {
  if (value === null || typeof value === "string" || typeof value === "boolean")
    return value;
  if (typeof value === "number")
    return Number.isFinite(value) ? value : null;
  if (Array.isArray(value)) {
    if (value.length > MAX_NODES) {
      limitations.push("A JSON property list array exceeded the element limit.");
      return [];
    }
    return value.map((item) => toPlistValue(item, limitations));
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length > MAX_NODES) {
      limitations.push("A JSON property list object exceeded the key limit.");
      return {};
    }
    const out: Record<string, PlistValue> = {};
    for (const [key, item] of entries) out[key] = toPlistValue(item, limitations);
    return out;
  }
  limitations.push("A JSON property list value had an unsupported type and was recorded as null.");
  return null;
};

/** Flattens a scalar claim into the text recorded in Evidence; containers return null. */
export const scalarClaim = (value: PlistValue): string | null => {
  if (value === null) return null;
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const items = value.map((item) => scalarClaim(item));
    if (items.some((item) => item === null)) return null;
    return items.join(",");
  }
  return null;
};

interface Cursor {
  readonly text: string;
  pos: number;
  nodes: number;
  readonly limitations: string[];
}

const isSpace = (value: string): boolean => /^[ \t\r\n\u000b\u000c]$/u.test(value);

const skipSpace = (cursor: Cursor): void => {
  while (cursor.pos < cursor.text.length && isSpace(cursor.text[cursor.pos] ?? ""))
    cursor.pos += 1;
};

const startsWith = (cursor: Cursor, token: string): boolean =>
  cursor.text.startsWith(token, cursor.pos);

const decodeEntities = (value: string, limitations: string[]): string => {
  let text = value;
  if (text.includes("&")) {
    text = text.replace(/&(#x?[0-9a-fA-F]+|[A-Za-z][A-Za-z0-9]*);/gu, (whole, body: string) => {
      if (body.startsWith("#")) {
        const hex = body.startsWith("#x") || body.startsWith("#X");
        const code = Number.parseInt(hex ? body.slice(2) : body.slice(1), hex ? 16 : 10);
        if (!Number.isFinite(code) || code < 0 || code > 0x10_ff_ff) {
          limitations.push("An XML character reference was out of range and was kept as text.");
          return whole;
        }
        try {
          return String.fromCodePoint(code);
        } catch {
          limitations.push("An XML character reference was not a scalar value and was kept as text.");
          return whole;
        }
      }
      const named = NAMED_ENTITIES[body];
      if (named === undefined) {
        limitations.push("An unknown XML entity was kept as text.");
        return whole;
      }
      return named;
    });
  }
  if (text.length > MAX_TEXT_CHARS) {
    limitations.push(`A property list string was truncated at ${MAX_TEXT_CHARS} characters.`);
    return text.slice(0, MAX_TEXT_CHARS);
  }
  return text;
};

/** Skips prolog, comments and processing instructions between values. */
const skipMiscellaneous = (cursor: Cursor): void => {
  for (;;) {
    skipSpace(cursor);
    if (startsWith(cursor, "<!--")) {
      const end = cursor.text.indexOf("-->", cursor.pos);
      if (end < 0)
        throw new TraceForgeError("parse_error", "XML comment is not closed");
      cursor.pos = end + 3;
      continue;
    }
    if (startsWith(cursor, "<?")) {
      const end = cursor.text.indexOf("?>", cursor.pos);
      if (end < 0)
        throw new TraceForgeError("parse_error", "XML processing instruction is not closed");
      cursor.pos = end + 2;
      continue;
    }
    if (startsWith(cursor, "<!")) {
      const end = findDoctypeEnd(cursor);
      cursor.pos = end + 1;
      continue;
    }
    return;
  }
};

const findDoctypeEnd = (cursor: Cursor): number => {
  let insideSubset = false;
  for (let index = cursor.pos; index < cursor.text.length; index += 1) {
    const char = cursor.text[index];
    if (char === "[") insideSubset = true;
    else if (char === "]") insideSubset = false;
    else if (char === ">" && !insideSubset) return index;
  }
  throw new TraceForgeError("parse_error", "XML declaration is not closed");
};

interface Tag {
  readonly name: string;
  readonly closing: boolean;
  readonly selfClosing: boolean;
}

const readTag = (cursor: Cursor): Tag => {
  if (cursor.text[cursor.pos] !== "<")
    throw new TraceForgeError("parse_error", "Property list value is missing");
  const closing = startsWith(cursor, "</");
  let index = cursor.pos + (closing ? 2 : 1);
  const nameStart = index;
  while (index < cursor.text.length && /[^\s/>]/u.test(cursor.text[index] ?? "")) index += 1;
  const name = cursor.text.slice(nameStart, index);
  if (name.length === 0)
    throw new TraceForgeError("parse_error", "Property list element name is empty");
  const limit = Math.min(cursor.text.length, index + 4_096);
  let selfClosing = false;
  while (index < limit) {
    const char = cursor.text[index];
    if (char === ">" && (cursor.text[index - 1] !== "?" || index === nameStart + name.length)) {
      cursor.pos = index + 1;
      return { name, closing, selfClosing };
    }
    if (char === "/" && cursor.text[index + 1] === ">") {
      cursor.pos = index + 2;
      return { name, closing, selfClosing: true };
    }
    index += 1;
  }
  throw new TraceForgeError("parse_error", "Property list element is not closed");
};

const readTextUntil = (cursor: Cursor, closeName: string): string => {
  const end = cursor.text.indexOf(`</${closeName}>`, cursor.pos);
  if (end < 0)
    throw new TraceForgeError("parse_error", `Property list ${closeName} value is not closed`);
  const raw = cursor.text.slice(cursor.pos, end);
  cursor.pos = end + closeName.length + 3;
  return raw;
};

const parseNumber = (raw: string, kind: "integer" | "real", limitations: string[]): PlistValue => {
  const text = raw.trim();
  if (text.length === 0) return null;
  if (kind === "real") {
    const value = Number(text);
    if (!Number.isFinite(value)) {
      limitations.push("A property list real value was not a finite number.");
      return null;
    }
    return value;
  }
  if (!/^[+-]?\d+$/u.test(text)) {
    limitations.push("A property list integer value was not an integer.");
    return null;
  }
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : text;
};

const dataLength = (raw: string): number => {
  const compact = raw.replace(/[^A-Za-z0-9+/=]/gu, "");
  const padding = compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0;
  return Math.max(0, Math.floor((compact.length * 3) / 4) - padding);
};

const parseXmlValue = (cursor: Cursor, depth: number): PlistValue => {
  skipMiscellaneous(cursor);
  cursor.nodes += 1;
  if (cursor.nodes > MAX_NODES) {
    cursor.limitations.push(`The property list node limit of ${MAX_NODES} was reached.`);
    return null;
  }
  if (depth > MAX_DEPTH) {
    cursor.limitations.push(`The property list nesting limit of ${MAX_DEPTH} was reached.`);
    return null;
  }
  const tag = readTag(cursor);
  if (tag.closing)
    throw new TraceForgeError("parse_error", "Property list has an unexpected closing element");
  if (tag.selfClosing) {
    switch (tag.name) {
      case "true":
        return true;
      case "false":
        return false;
      case "string":
      case "data":
        return "";
      case "array":
        return [];
      case "dict":
        return {};
      default:
        cursor.limitations.push(`An empty <${tag.name}> element was recorded as null.`);
        return null;
    }
  }
  switch (tag.name) {
    case "dict": {
      const out: Record<string, PlistValue> = {};
      for (;;) {
        skipMiscellaneous(cursor);
        if (startsWith(cursor, "</")) {
          const close = readTag(cursor);
          if (close.name !== "dict")
            throw new TraceForgeError("parse_error", "Property list dict is not closed correctly");
          return out;
        }
        const keyTag = readTag(cursor);
        if (keyTag.name !== "key")
          throw new TraceForgeError("parse_error", "Property list dict expects a key element");
        const key = keyTag.selfClosing
          ? ""
          : decodeEntities(readTextUntil(cursor, "key"), cursor.limitations);
        out[key] = parseXmlValue(cursor, depth + 1);
      }
    }
    case "array": {
      const out: PlistValue[] = [];
      for (;;) {
        skipMiscellaneous(cursor);
        if (startsWith(cursor, "</")) {
          const close = readTag(cursor);
          if (close.name !== "array")
            throw new TraceForgeError("parse_error", "Property list array is not closed correctly");
          return out;
        }
        out.push(parseXmlValue(cursor, depth + 1));
      }
    }
    case "string":
      return decodeEntities(readTextUntil(cursor, "string"), cursor.limitations);
    case "data": {
      const bytes = dataLength(readTextUntil(cursor, "data"));
      cursor.limitations.push(`A <data> value of ${bytes} bytes was recorded by length only.`);
      return `<data ${bytes} bytes>`;
    }
    case "date":
      return readTextUntil(cursor, "date").trim();
    case "integer":
      return parseNumber(readTextUntil(cursor, "integer"), "integer", cursor.limitations);
    case "real":
      return parseNumber(readTextUntil(cursor, "real"), "real", cursor.limitations);
    case "true":
      readTag(cursor);
      return true;
    case "false":
      readTag(cursor);
      return false;
    default:
      throw new TraceForgeError("parse_error", `Unsupported property list element <${tag.name}>`);
  }
};

const parseXmlPlist = (text: string, limitations: string[]): PlistValue => {
  const cursor: Cursor = { text, pos: 0, nodes: 0, limitations };
  skipMiscellaneous(cursor);
  if (startsWith(cursor, "<plist")) {
    const tag = readTag(cursor);
    const value = parseXmlValue(cursor, 1);
    skipMiscellaneous(cursor);
    if (startsWith(cursor, "</")) {
      const close = readTag(cursor);
      if (close.name !== "plist")
        throw new TraceForgeError("parse_error", "Property list plist element is not closed");
    }
    void tag;
    return value;
  }
  return parseXmlValue(cursor, 1);
};

const beInteger = (buffer: Buffer, offset: number, size: number): number => {
  if (size > 6) {
    const value = buffer.readBigUInt64BE(offset);
    if (value > BigInt(Number.MAX_SAFE_INTEGER))
      throw new TraceForgeError("parse_error", "Binary property list index exceeds the safe range");
    return Number(value);
  }
  let result = 0;
  for (let index = 0; index < size; index += 1)
    result = result * 256 + (buffer[offset + index] ?? 0);
  return result;
};

const readCountAndLength = (
  buffer: Buffer,
  offset: number,
  low: number,
): { readonly count: number; readonly next: number } => {
  if (low !== 0xf) return { count: low, next: offset };
  const marker = buffer[offset] ?? 0xff;
  if ((marker & 0xf0) !== 0x10)
    throw new TraceForgeError("parse_error", "Binary property list length marker is invalid");
  const size = 1 << (marker & 0x0f);
  if (offset + 1 + size > buffer.length)
    throw new TraceForgeError("parse_error", "Binary property list length is truncated");
  return { count: beInteger(buffer, offset + 1, size), next: offset + 1 + size };
};

const decodeUtf16Be = (buffer: Buffer, start: number, units: number): string => {
  const out: string[] = [];
  for (let index = 0; index < units; index += 1) {
    const at = start + index * 2;
    if (at + 2 > buffer.length) break;
    out.push(String.fromCharCode(buffer.readUInt16BE(at)));
  }
  return out.join("");
};

const binaryDate = (seconds: number): string => {
  if (!Number.isFinite(seconds)) return "<date unavailable>";
  const ms = UNIX_2001_MS + seconds * 1000;
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? "<date unavailable>" : date.toISOString();
};

interface BinaryTable {
  readonly buffer: Buffer;
  readonly offsets: readonly number[];
  readonly referenceSize: number;
}

const parseBinaryObject = (
  table: BinaryTable,
  index: number,
  depth: number,
  reading: Set<number>,
  limitations: string[],
): PlistValue => {
  const { buffer, offsets, referenceSize } = table;
  if (index < 0 || index >= offsets.length)
    throw new TraceForgeError("parse_error", "Binary property list reference is out of range");
  const start = offsets[index];
  if (start === undefined || start < 0 || start >= buffer.length)
    throw new TraceForgeError("parse_error", "Binary property list offset is out of range");
  if (reading.has(index)) {
    limitations.push("A binary property list object referenced itself and was recorded as null.");
    return null;
  }
  if (depth > MAX_DEPTH) {
    limitations.push(`The binary property list nesting limit of ${MAX_DEPTH} was reached.`);
    return null;
  }
  const header = buffer[start] ?? 0;
  const top = header & 0xf0;
  const low = header & 0x0f;
  const body = start + 1;
  if (top === 0x00) {
    if (low === 0x08) return false;
    if (low === 0x09) return true;
    if (low === 0x00 || low === 0x0f) return null;
    limitations.push(`An unknown binary property list singleton 0x${header.toString(16)} was recorded as null.`);
    return null;
  }
  if (top === 0x10 || top === 0x80) {
    const size = 1 << low;
    if (body + size > buffer.length || size > 8)
      throw new TraceForgeError("parse_error", "Binary property list integer is truncated");
    if (size === 8) {
      const value = buffer.readBigInt64BE(body);
      if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER))
        return value.toString();
      return Number(value);
    }
    return beInteger(buffer, body, size);
  }
  if (top === 0x20) {
    const size = 1 << low;
    if (body + size > buffer.length)
      throw new TraceForgeError("parse_error", "Binary property list real is truncated");
    if (size === 4) return buffer.readFloatBE(body);
    if (size === 8) return buffer.readDoubleBE(body);
    limitations.push("A binary property list real had an unsupported width.");
    return null;
  }
  if (top === 0x30) {
    const size = 1 << low;
    if (body + size > buffer.length || size !== 8) {
      limitations.push("A binary property list date had an unsupported width.");
      return null;
    }
    return binaryDate(buffer.readDoubleBE(body));
  }
  if (top === 0x40 || top === 0x50 || top === 0x60) {
    const { count, next } = readCountAndLength(buffer, body, low);
    if (top === 0x40) {
      if (next + count > buffer.length)
        throw new TraceForgeError("parse_error", "Binary property list data exceeds the file");
      return `<data ${count} bytes>`;
    }
    const width = top === 0x50 ? 1 : 2;
    if (next + count * width > buffer.length)
      throw new TraceForgeError("parse_error", "Binary property list string exceeds the file");
    let text =
      width === 1
        ? buffer.subarray(next, next + count).toString("utf8")
        : decodeUtf16Be(buffer, next, count);
    if (text.length > MAX_TEXT_CHARS) {
      limitations.push(`A binary property list string was truncated at ${MAX_TEXT_CHARS} characters.`);
      text = text.slice(0, MAX_TEXT_CHARS);
    }
    return text;
  }
  if (top === 0xa0) {
    const { count, next } = readCountAndLength(buffer, body, low);
    if (count > MAX_NODES)
      throw new TraceForgeError("parse_error", "Binary property list array is unreasonably large");
    if (next + count * referenceSize > buffer.length)
      throw new TraceForgeError("parse_error", "Binary property list array exceeds the file");
    const out: PlistValue[] = [];
    reading.add(index);
    for (let position = 0; position < count; position += 1) {
      const child = beInteger(buffer, next + position * referenceSize, referenceSize);
      out.push(parseBinaryObject(table, child, depth + 1, reading, limitations));
    }
    reading.delete(index);
    return out;
  }
  if (top === 0xc0 || top === 0xd0) {
    const { count, next } = readCountAndLength(buffer, body, low);
    if (count > MAX_NODES)
      throw new TraceForgeError("parse_error", "Binary property list dict is unreasonably large");
    if (next + count * 2 * referenceSize > buffer.length)
      throw new TraceForgeError("parse_error", "Binary property list dict exceeds the file");
    const out: Record<string, PlistValue> = {};
    reading.add(index);
    for (let position = 0; position < count; position += 1) {
      const keyIndex = beInteger(buffer, next + position * referenceSize, referenceSize);
      const valueIndex = beInteger(
        buffer,
        next + (count + position) * referenceSize,
        referenceSize,
      );
      const key = parseBinaryObject(table, keyIndex, depth + 1, reading, limitations);
      out[typeof key === "string" ? key : String(key)] = parseBinaryObject(
        table,
        valueIndex,
        depth + 1,
        reading,
        limitations,
      );
    }
    reading.delete(index);
    return out;
  }
  limitations.push(
    `Binary property list object type 0x${top.toString(16)} was not parsed and was recorded as null.`,
  );
  return null;
};

const parseBinaryPlist = (buffer: Buffer, limitations: string[]): PlistValue => {
  if (buffer.length < 40)
    throw new TraceForgeError("parse_error", "Binary property list trailer is truncated");
  const trailer = buffer.length - 32;
  const offsetSize = buffer[trailer + 6] ?? 0;
  const referenceSize = buffer[trailer + 7] ?? 0;
  if (offsetSize < 1 || offsetSize > 8 || referenceSize < 1 || referenceSize > 8)
    throw new TraceForgeError("parse_error", "Binary property list trailer sizes are invalid");
  const objectCount = Number(buffer.readBigUInt64BE(trailer + 8));
  const topObject = Number(buffer.readBigUInt64BE(trailer + 16));
  const tableOffset = Number(buffer.readBigUInt64BE(trailer + 24));
  if (objectCount > MAX_NODES || objectCount <= 0)
    throw new TraceForgeError("parse_error", "Binary property list object count is unreasonable");
  const tableEnd = tableOffset + objectCount * offsetSize;
  if (tableOffset < 0 || tableOffset >= buffer.length || tableEnd > trailer)
    throw new TraceForgeError("parse_error", "Binary property list offset table is out of range");
  if (topObject >= objectCount)
    throw new TraceForgeError("parse_error", "Binary property list top object is out of range");
  const offsets: number[] = [];
  for (let index = 0; index < objectCount; index += 1)
    offsets.push(beInteger(buffer, tableOffset + index * offsetSize, offsetSize));
  return parseBinaryObject(
    { buffer, offsets, referenceSize },
    topObject,
    1,
    new Set<number>(),
    limitations,
  );
};
