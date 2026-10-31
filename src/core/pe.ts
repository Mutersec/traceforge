import { hex, readCString, sectionHash } from "./binary.js";
import type { ParsedContainer } from "./binary.js";
import { TraceForgeError } from "./errors.js";
import type { SectionInfo, SliceInventory } from "./types.js";

const MAX_SECTIONS = 96;
const MAX_IMPORTS = 20_000;
const MAX_EXPORTS = 20_000;

const machineName = (machine: number): string => {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x86_64";
    case 0x01c0:
      return "arm";
    case 0x01c4:
      return "armv7";
    case 0xaa64:
      return "arm64";
    case 0x0200:
      return "ia64";
    default:
      return `machine_0x${machine.toString(16)}`;
  }
};

interface PeSection {
  readonly name: string;
  readonly virtualAddress: number;
  readonly virtualSize: number;
  readonly rawOffset: number;
  readonly rawSize: number;
  readonly characteristics: number;
}

export const parsePe = (buffer: Buffer, _path: string): ParsedContainer => {
  if (buffer.length < 64 || buffer[0] !== 0x4d || buffer[1] !== 0x5a)
    throw new TraceForgeError("parse_error", "PE DOS header is missing");
  const peOffset = buffer.readUInt32LE(0x3c);
  if (peOffset + 24 > buffer.length)
    throw new TraceForgeError("parse_error", "PE header is truncated");
  if (
    buffer[peOffset] !== 0x50 ||
    buffer[peOffset + 1] !== 0x45 ||
    buffer[peOffset + 2] !== 0 ||
    buffer[peOffset + 3] !== 0
  )
    throw new TraceForgeError("parse_error", "PE signature is missing");
  const coff = peOffset + 4;
  const machine = buffer.readUInt16LE(coff);
  const sectionCount = buffer.readUInt16LE(coff + 2);
  const timestamp = buffer.readUInt32LE(coff + 4);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  const characteristics = buffer.readUInt16LE(coff + 18);
  if (sectionCount > MAX_SECTIONS)
    throw new TraceForgeError("parse_error", "PE section count is unreasonable");
  const optional = coff + 20;
  if (optional + optionalSize > buffer.length || optionalSize < 2)
    throw new TraceForgeError("parse_error", "PE optional header is truncated");
  const magic = buffer.readUInt16LE(optional);
  if (magic !== 0x10b && magic !== 0x20b)
    throw new TraceForgeError("parse_error", "PE optional header magic is invalid");
  const bits: 32 | 64 = magic === 0x20b ? 64 : 32;
  const entryRva = buffer.readUInt32LE(optional + 16);
  const imageBase = bits === 64
    ? Number(buffer.readBigUInt64LE(optional + 24))
    : buffer.readUInt32LE(optional + 28);
  const directoryCount = buffer.readUInt32LE(optional + (bits === 64 ? 108 : 92));
  const directoryOffset = optional + (bits === 64 ? 112 : 96);
  const sectionTable = optional + optionalSize;
  if (sectionTable + sectionCount * 40 > buffer.length)
    throw new TraceForgeError("parse_error", "PE section table is truncated");
  const sections: PeSection[] = [];
  const limitations: string[] = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const base = sectionTable + index * 40;
    const name = buffer.toString("utf8", base, base + 8).replace(/\0.*$/u, "");
    sections.push({
      name,
      virtualSize: buffer.readUInt32LE(base + 8),
      virtualAddress: buffer.readUInt32LE(base + 12),
      rawSize: buffer.readUInt32LE(base + 16),
      rawOffset: buffer.readUInt32LE(base + 20),
      characteristics: buffer.readUInt32LE(base + 36),
    });
  }
  const rvaToOffset = (rva: number): number | null => {
    for (const section of sections) {
      const span = Math.max(section.virtualSize, section.rawSize);
      if (rva >= section.virtualAddress && rva < section.virtualAddress + span)
        return section.rawOffset + (rva - section.virtualAddress);
    }
    return rva < sectionTable ? rva : null;
  };
  const directory = (index: number): { rva: number; size: number } | null =>
    index >= directoryCount || directoryOffset + (index + 1) * 8 > buffer.length
      ? null
      : {
          rva: buffer.readUInt32LE(directoryOffset + index * 8),
          size: buffer.readUInt32LE(directoryOffset + index * 8 + 4),
        };
  const imports = new Set<string>();
  const libraries = new Set<string>();
  const importDirectory = directory(1);
  if (importDirectory !== null && importDirectory.rva !== 0) {
    let descriptorRva = importDirectory.rva;
    for (let descriptor = 0; descriptor < 4096; descriptor += 1) {
      const offset = rvaToOffset(descriptorRva);
      if (offset === null || offset + 20 > buffer.length) break;
      const originalThunk = buffer.readUInt32LE(offset);
      const nameRva = buffer.readUInt32LE(offset + 12);
      const firstThunk = buffer.readUInt32LE(offset + 16);
      if (originalThunk === 0 && nameRva === 0 && firstThunk === 0) break;
      const nameOffset = rvaToOffset(nameRva);
      const dll = nameOffset === null ? null : readCString(buffer, nameOffset, 4096);
      if (dll !== null && dll.length > 0) libraries.add(dll);
      const thunkRva = originalThunk !== 0 ? originalThunk : firstThunk;
      for (let thunkIndex = 0; thunkIndex < MAX_IMPORTS; thunkIndex += 1) {
        const entryOffset = rvaToOffset(thunkRva + thunkIndex * (bits === 64 ? 8 : 4));
        if (entryOffset === null || entryOffset + (bits === 64 ? 8 : 4) > buffer.length) break;
        const value = bits === 64
          ? buffer.readBigUInt64LE(entryOffset)
          : BigInt(buffer.readUInt32LE(entryOffset));
        if (value === 0n) break;
        const ordinalMask = bits === 64 ? 0x8000000000000000n : 0x80000000n;
        if ((value & ordinalMask) !== 0n) {
          const ordinal = Number(value & 0xffffn);
          if (dll !== null) imports.add(`${dll}!#${ordinal}`);
          continue;
        }
        const hintName = rvaToOffset(Number(value));
        if (hintName === null) continue;
        const symbol = readCString(buffer, hintName + 2, 4096);
        if (symbol !== null && symbol.length > 0 && dll !== null)
          imports.add(`${dll}!${symbol}`);
      }
      descriptorRva += 20;
    }
    if (imports.size >= MAX_IMPORTS)
      limitations.push("PE imports were capped at the safety limit.");
  } else {
    limitations.push("PE import directory was absent or empty.");
  }

  const exports = new Set<string>();
  const exportDirectory = directory(0);
  if (exportDirectory !== null && exportDirectory.rva !== 0) {
    const offset = rvaToOffset(exportDirectory.rva);
    if (offset !== null && offset + 40 <= buffer.length) {
      const nameCount = buffer.readUInt32LE(offset + 24);
      const namesRva = buffer.readUInt32LE(offset + 32);
      const count = Math.min(nameCount, MAX_EXPORTS);
      if (nameCount > MAX_EXPORTS)
        limitations.push("PE exports were capped at the safety limit.");
      for (let index = 0; index < count; index += 1) {
        const namePointerOffset = rvaToOffset(namesRva + index * 4);
        if (namePointerOffset === null) break;
        const nameRva = buffer.readUInt32LE(namePointerOffset);
        const nameOffset = rvaToOffset(nameRva);
        if (nameOffset === null) continue;
        const name = readCString(buffer, nameOffset, 4096);
        if (name !== null && name.length > 0) exports.add(name);
      }
    }
  } else {
    limitations.push("PE export directory was absent or empty.");
  }

  const sectionRows: SectionInfo[] = sections.map((section) => ({
    name: section.name,
    segment: null,
    address: hex(BigInt(imageBase) + BigInt(section.virtualAddress)),
    offset: section.rawOffset,
    size: section.rawSize,
    sha256: sectionHash(buffer, section.rawOffset, section.rawSize, limitations),
    flags: hex(section.characteristics),
  }));
  const slice: SliceInventory = {
    architecture: machineName(machine),
    bits,
    endian: "little",
    fileType: (characteristics & 0x2000) !== 0 ? "dll" : "executable",
    entrypoint: hex(entryRva),
    entrypointKind: "rva",
    buildId: hex(timestamp),
    sections: sectionRows,
    imports: [...imports].sort(),
    exports: [...exports].sort(),
    libraries: [...libraries].sort(),
    limitations: [...new Set(limitations)].sort(),
  };
  return { format: "pe", slices: [slice], limitations: [...new Set(limitations)].sort() };
};
