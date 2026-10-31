import { sectionHash } from "./binary.js";
import type { ParsedContainer } from "./binary.js";
import { TraceForgeError } from "./errors.js";
import type { SectionInfo, SliceInventory } from "./types.js";

const SECTION_NAMES: Record<number, string> = {
  1: "type",
  2: "import",
  3: "function",
  4: "table",
  5: "memory",
  6: "global",
  7: "export",
  8: "start",
  9: "element",
  10: "code",
  11: "data",
  12: "data-count",
  13: "tag",
};

interface Reader {
  offset: number;
}

const readU32 = (buffer: Buffer, reader: Reader): number => {
  let result = 0;
  let shift = 0;
  for (let index = 0; index < 5; index += 1) {
    if (reader.offset >= buffer.length)
      throw new TraceForgeError("parse_error", "WASM LEB128 is truncated");
    const byte = buffer[reader.offset] ?? 0;
    reader.offset += 1;
    result |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result >>> 0;
    shift += 7;
  }
  throw new TraceForgeError("parse_error", "WASM LEB128 is too long");
};

const readString = (buffer: Buffer, reader: Reader): string => {
  const length = readU32(buffer, reader);
  if (reader.offset + length > buffer.length)
    throw new TraceForgeError("parse_error", "WASM string exceeds the section");
  const value = buffer.toString("utf8", reader.offset, reader.offset + length);
  reader.offset += length;
  return value;
};

const skipImportDescriptor = (buffer: Buffer, reader: Reader, kind: number): void => {
  if (kind === 0) {
    readU32(buffer, reader);
    return;
  }
  if (kind === 1) {
    readU32(buffer, reader);
    const flags = readU32(buffer, reader);
    readU32(buffer, reader);
    if ((flags & 1) !== 0) readU32(buffer, reader);
    return;
  }
  if (kind === 2) {
    const flags = readU32(buffer, reader);
    readU32(buffer, reader);
    if ((flags & 1) !== 0) readU32(buffer, reader);
    return;
  }
  if (kind === 3) {
    readU32(buffer, reader);
    readU32(buffer, reader);
  }
};

export const parseWasm = (buffer: Buffer, _path: string): ParsedContainer => {
  if (buffer.length < 8)
    throw new TraceForgeError("parse_error", "WASM header is truncated");
  const version = buffer.readUInt32LE(4);
  if (version !== 1)
    throw new TraceForgeError("parse_error", `Unsupported WASM version ${version}`);
  const limitations: string[] = [];
  const sections: SectionInfo[] = [];
  const imports = new Set<string>();
  const exports = new Set<string>();
  let offset = 8;
  while (offset < buffer.length) {
    const id = buffer[offset] ?? 0;
    offset += 1;
    const header: Reader = { offset };
    const size = readU32(buffer, header);
    if (header.offset + size > buffer.length)
      throw new TraceForgeError("parse_error", "WASM section exceeds the file");
    const start = header.offset;
    const end = start + size;
    let name = SECTION_NAMES[id] ?? `section-${id}`;
    if (id === 0) {
      const payload: Reader = { offset: start };
      const customName = size > 0 ? readString(buffer, payload) : "";
      name = customName.length > 0 ? `custom:${customName}` : "custom";
    } else if (id === 2) {
      const payload: Reader = { offset: start };
      const count = readU32(buffer, payload);
      for (let index = 0; index < Math.min(count, 20_000); index += 1) {
        const moduleName = readString(buffer, payload);
        const importName = readString(buffer, payload);
        const kind = readU32(buffer, payload);
        imports.add(`${moduleName}.${importName}`);
        skipImportDescriptor(buffer, payload, kind);
      }
      if (count > 20_000) limitations.push("WASM imports were capped at 20,000 entries.");
    } else if (id === 7) {
      const payload: Reader = { offset: start };
      const count = readU32(buffer, payload);
      for (let index = 0; index < Math.min(count, 20_000); index += 1) {
        exports.add(readString(buffer, payload));
        readU32(buffer, payload);
        readU32(buffer, payload);
      }
      if (count > 20_000) limitations.push("WASM exports were capped at 20,000 entries.");
    }
    sections.push({
      name,
      segment: null,
      address: null,
      offset: start,
      size,
      sha256: sectionHash(buffer, start, size, limitations),
      flags: null,
    });
    offset = end;
  }
  const slice: SliceInventory = {
    architecture: "wasm32",
    bits: 32,
    endian: "little",
    fileType: "module",
    entrypoint: null,
    entrypointKind: null,
    buildId: null,
    sections,
    imports: [...imports].sort(),
    exports: [...exports].sort(),
    libraries: [],
    limitations: [...new Set(limitations)].sort(),
  };
  return { format: "wasm", slices: [slice], limitations: [...new Set(limitations)].sort() };
};
