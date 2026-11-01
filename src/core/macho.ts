import { hex, readCString, sectionHash, securitySummary } from "./binary.js";
import { TraceForgeError } from "./errors.js";
import type { ParsedContainer } from "./binary.js";
import type { SectionInfo, SliceInventory } from "./types.js";

const MH_MAGIC = 0xfeedface;
const MH_MAGIC_64 = 0xfeedfacf;
const FAT_MAGIC = 0xcafebabe;
const FAT_MAGIC_64 = 0xcafebabf;

const LC_SEGMENT = 0x1;
const LC_SYMTAB = 0x2;
const LC_LOAD_DYLIB = 0xc;
const LC_ID_DYLIB = 0xd;
const LC_CODE_SIGNATURE = 0x1d;
const LC_DYLD_INFO = 0x22;
const LC_SEGMENT_64 = 0x19;
const LC_UUID = 0x1b;
const LC_VERSION_MIN_MACOSX = 0x24;
const LC_VERSION_MIN_IPHONEOS = 0x25;
const LC_FUNCTION_STARTS = 0x26;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_VERSION_MIN_TVOS = 0x2f;
const LC_VERSION_MIN_WATCHOS = 0x30;
const LC_BUILD_VERSION = 0x32;
const LC_DYLD_CHAINED_FIXUPS = 0x80000034;
const LC_LOAD_WEAK_DYLIB = 0x80000018;
const LC_DYLD_INFO_ONLY = 0x80000022;
const LC_REEXPORT_DYLIB = 0x8000001f;
const LC_LOAD_UPWARD_DYLIB = 0x80000023;
const LC_MAIN = 0x80000028;

const MH_DYLDLINK = 0x4;
const MH_PIC = 0x200;
const MH_ALLOW_STACK_EXECUTION = 0x20000;
const VM_PROT_WRITE = 0x2;
const VM_PROT_EXECUTE = 0x4;

const PLATFORM_NAMES: Record<number, string> = {
  1: "macos",
  2: "ios",
  3: "tvos",
  4: "watchos",
  5: "bridgeos",
  6: "maccatalyst",
  7: "ios-simulator",
  8: "tvos-simulator",
  9: "watchos-simulator",
  10: "driverkit",
};

const MAX_COMMANDS = 100_000;
const MAX_SECTIONS = 100_000;
const MAX_SYMBOLS = 200_000;

const u32 = (buffer: Buffer, offset: number, little: boolean): number =>
  little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
const i32 = (buffer: Buffer, offset: number, little: boolean): number =>
  little ? buffer.readInt32LE(offset) : buffer.readInt32BE(offset);
const u64 = (buffer: Buffer, offset: number, little: boolean): number => {
  const value = little
    ? buffer.readBigUInt64LE(offset)
    : buffer.readBigUInt64BE(offset);
  if (value > BigInt(Number.MAX_SAFE_INTEGER))
    throw new TraceForgeError("parse_error", "Mach-O offset exceeds the safe integer range");
  return Number(value);
};

const fixedString = (buffer: Buffer, offset: number, length: number): string =>
  buffer.toString("utf8", offset, offset + length).replace(/\0.*$/u, "");

const architectureName = (cpuType: number, cpuSubtype: number): string => {
  const subtype = cpuSubtype & 0x00ffffff;
  switch (cpuType) {
    case 7:
      return "x86";
    case 0x01000007:
      if (subtype === 8) return "x86_64h";
      return subtype <= 3 ? "x86_64" : `x86_64_subtype_${subtype}`;
    case 12:
      return "arm";
    case 0x0100000c:
      if (subtype === 1) return "arm64v8";
      if (subtype === 2) return "arm64e";
      return subtype === 0 ? "arm64" : `arm64_subtype_${subtype}`;
    case 18:
      return "ppc";
    case 0x01000012:
      return "ppc64";
    default:
      return `cpu_${cpuType}`;
  }
};

const fileTypeName = (type: number): string => {
  switch (type) {
    case 1:
      return "object";
    case 2:
      return "executable";
    case 3:
      return "fixed-vm-library";
    case 4:
      return "core";
    case 5:
      return "preload";
    case 6:
      return "dylib";
    case 7:
      return "dylinker";
    case 8:
      return "bundle";
    case 9:
      return "dylib-stub";
    case 10:
      return "dsym";
    case 11:
      return "kext-bundle";
    default:
      return `filetype_${type}`;
  }
};

const uuid = (buffer: Buffer, offset: number): string => {
  const bytes = buffer.subarray(offset, offset + 16);
  if (bytes.length !== 16) return "";
  const text = bytes.toString("hex").toUpperCase();
  return `${text.slice(0, 8)}-${text.slice(8, 12)}-${text.slice(12, 16)}-${text.slice(16, 20)}-${text.slice(20)}`;
};

const packedVersion = (value: number): string =>
  `${(value >>> 16) & 0xffff}.${(value >>> 8) & 0xff}.${value & 0xff}`;

const parseThin = (
  buffer: Buffer,
  start: number,
  end: number,
  limitations: string[],
): SliceInventory => {
  if (start + 28 > end)
    throw new TraceForgeError("parse_error", "Mach-O header is truncated");
  const little =
    buffer.readUInt32LE(start) === MH_MAGIC ||
    buffer.readUInt32LE(start) === MH_MAGIC_64;
  const magic = u32(buffer, start, little);
  if (magic !== MH_MAGIC && magic !== MH_MAGIC_64)
    throw new TraceForgeError("parse_error", "Mach-O magic is invalid");
  const bits: 32 | 64 = magic === MH_MAGIC_64 ? 64 : 32;
  const cpuType = i32(buffer, start + 4, little);
  const cpuSubtype = i32(buffer, start + 8, little);
  const fileType = u32(buffer, start + 12, little);
  const ncmds = u32(buffer, start + 16, little);
  const sizeofcmds = u32(buffer, start + 20, little);
  const headerFlags = u32(buffer, start + 24, little);
  const headerSize = bits === 64 ? 32 : 28;
  if (ncmds > MAX_COMMANDS)
    throw new TraceForgeError("parse_error", "Mach-O command count is unreasonable");
  const commandEnd = start + headerSize + sizeofcmds;
  if (commandEnd > end)
    throw new TraceForgeError("parse_error", "Mach-O load commands exceed the file");

  const sections: SectionInfo[] = [];
  const imports = new Set<string>();
  const exports = new Set<string>();
  const libraries = new Set<string>();
  let entrypoint: string | null = null;
  let entrypointKind: SliceInventory["entrypointKind"] = null;
  let buildId: string | null = null;
  let writableExecute = false;
  let chainedFixups = false;
  let dyldFixups = false;
  let signatureDeclared = false;
  let platform: string | null = null;
  let minOs: string | null = null;
  let sdk: string | null = null;
  let linkerVersion: string | null = null;

  let offset = start + headerSize;
  for (let index = 0; index < ncmds; index += 1) {
    if (offset + 8 > commandEnd)
      throw new TraceForgeError("parse_error", "Mach-O command is truncated");
    const command = u32(buffer, offset, little);
    const commandSize = u32(buffer, offset + 4, little);
    if (commandSize < 8 || offset + commandSize > commandEnd)
      throw new TraceForgeError("parse_error", "Mach-O command size is invalid");

    if (command === LC_SEGMENT_64 || command === LC_SEGMENT) {
      const is64 = command === LC_SEGMENT_64;
      const segmentName = fixedString(buffer, offset + 8, 16);
      const protectionOffset = is64 ? 56 : 40;
      if (commandSize >= protectionOffset + 4) {
        const maxProt = u32(buffer, offset + protectionOffset, little);
        if ((maxProt & VM_PROT_WRITE) !== 0 && (maxProt & VM_PROT_EXECUTE) !== 0)
          writableExecute = true;
      }
      const sectionCount = u32(buffer, offset + (is64 ? 64 : 48), little);
      if (sectionCount > MAX_SECTIONS)
        throw new TraceForgeError("parse_error", "Mach-O section count is unreasonable");
      const sectionSize = is64 ? 80 : 68;
      let sectionOffset = offset + (is64 ? 72 : 56);
      for (let sectionIndex = 0; sectionIndex < sectionCount; sectionIndex += 1) {
        if (sectionOffset + sectionSize > offset + commandSize) break;
        const name = fixedString(buffer, sectionOffset, 16);
        const sectionSegment = fixedString(buffer, sectionOffset + 16, 16);
        const address = is64
          ? u64(buffer, sectionOffset + 32, little)
          : u32(buffer, sectionOffset + 32, little);
        const size = is64
          ? u64(buffer, sectionOffset + 40, little)
          : u32(buffer, sectionOffset + 36, little);
        const fileOffset = is64
          ? u32(buffer, sectionOffset + 48, little)
          : u32(buffer, sectionOffset + 40, little);
        const flags = is64
          ? u32(buffer, sectionOffset + 64, little)
          : u32(buffer, sectionOffset + 56, little);
        if (name.length > 0)
          sections.push({
            name,
            segment: sectionSegment.length > 0 ? sectionSegment : segmentName,
            address: hex(address),
            offset: start + fileOffset,
            size,
            sha256: sectionHash(buffer, start + fileOffset, size, limitations),
            flags: hex(flags),
          });
        sectionOffset += sectionSize;
      }
    } else if (command === LC_SYMTAB) {
      const symoff = u32(buffer, offset + 8, little);
      const nsyms = u32(buffer, offset + 12, little);
      const stroff = u32(buffer, offset + 16, little);
      const strsize = u32(buffer, offset + 20, little);
      const entrySize = bits === 64 ? 16 : 12;
      const count = Math.min(nsyms, MAX_SYMBOLS);
      if (nsyms > MAX_SYMBOLS)
        limitations.push("Symbol list was capped at 200,000 entries.");
      for (let symbol = 0; symbol < count; symbol += 1) {
        const symbolOffset = start + symoff + symbol * entrySize;
        if (symbolOffset + entrySize > end) break;
        const stringIndex = u32(buffer, symbolOffset, little);
        const type = buffer[symbolOffset + 4] ?? 0;
        if ((type & 0xe0) !== 0) continue;
        const name = readCString(buffer, start + stroff + stringIndex, 4096);
        if (name === null || name.length === 0) continue;
        const typeBits = type & 0x0e;
        const external = (type & 0x01) !== 0;
        if (!external) continue;
        if (typeBits === 0x0 || typeBits === 0x0c) imports.add(name);
        else if (typeBits === 0x02 || typeBits === 0x0a || typeBits === 0x0e)
          exports.add(name);
      }
      if (stroff + strsize > buffer.length)
        limitations.push("Mach-O string table is truncated.");
    } else if (
      command === LC_LOAD_DYLIB ||
      command === LC_LOAD_WEAK_DYLIB ||
      command === LC_REEXPORT_DYLIB ||
      command === LC_LOAD_UPWARD_DYLIB ||
      command === LC_ID_DYLIB
    ) {
      const nameOffset = u32(buffer, offset + 8, little);
      if (nameOffset < commandSize) {
        const name = readCString(buffer, offset + nameOffset, 4096);
        if (name !== null && name.length > 0 && command !== LC_ID_DYLIB)
          libraries.add(name);
      }
    } else if (command === LC_UUID && commandSize >= 24) {
      buildId = uuid(buffer, offset + 8);
    } else if (command === LC_BUILD_VERSION && commandSize >= 24) {
      const rawPlatform = u32(buffer, offset + 8, little);
      platform = PLATFORM_NAMES[rawPlatform] ?? `platform_${rawPlatform}`;
      minOs = packedVersion(u32(buffer, offset + 12, little));
      sdk = packedVersion(u32(buffer, offset + 16, little));
      const toolCount = u32(buffer, offset + 20, little);
      for (let tool = 0; tool < Math.min(toolCount, 32); tool += 1) {
        const entry = offset + 24 + tool * 8;
        if (entry + 8 > commandEnd) break;
        if (u32(buffer, entry, little) === 1)
          linkerVersion = packedVersion(u32(buffer, entry + 4, little));
      }
    } else if (
      command === LC_VERSION_MIN_MACOSX ||
      command === LC_VERSION_MIN_IPHONEOS ||
      command === LC_VERSION_MIN_TVOS ||
      command === LC_VERSION_MIN_WATCHOS
    ) {
      if (commandSize >= 16) {
        platform =
          command === LC_VERSION_MIN_MACOSX
            ? "macos"
            : command === LC_VERSION_MIN_IPHONEOS
              ? "ios"
              : command === LC_VERSION_MIN_TVOS
                ? "tvos"
                : "watchos";
        minOs = packedVersion(u32(buffer, offset + 8, little));
        sdk = packedVersion(u32(buffer, offset + 12, little));
      }
    } else if (command === LC_DYLD_CHAINED_FIXUPS && commandSize >= 16) {
      chainedFixups = true;
      dyldFixups = true;
    } else if (
      (command === LC_DYLD_INFO || command === LC_DYLD_INFO_ONLY) &&
      commandSize >= 48
    ) {
      dyldFixups = true;
    } else if (command === LC_CODE_SIGNATURE && commandSize >= 16) {
      signatureDeclared = true;
    } else if (command === LC_ENCRYPTION_INFO_64 && commandSize >= 16) {
      if (u32(buffer, offset + 12, little) !== 0)
        limitations.push(
          "An encrypted Mach-O region was declared; bytes in that region were not parsed.",
        );
    } else if (command === LC_MAIN && commandSize >= 24) {
      entrypoint = hex(u64(buffer, offset + 8, little));
      entrypointKind = "file-offset";
    }
    offset += commandSize;
  }

  limitations.push(
    "Mach-O symbols come from LC_SYMTAB; stripped binaries may omit imports or exports.",
  );
  limitations.push(
    "Mitigation names are structural claims from Mach-O headers, not observed runtime enforcement.",
  );
  limitations.push(
    "Mach-O does not set MH_PIC for dyld-linked executables, so PIE stays undetermined unless MH_PIC is present.",
  );
  if (signatureDeclared)
    limitations.push(
      "A code signature blob was recorded as present; its contents and validity were not checked.",
    );
  if (entrypointKind === "file-offset")
    limitations.push("LC_MAIN exposes a file offset, not a linked virtual address.");

  const isObject = fileType === 1;
  const security = securitySummary([
    [
      "pie",
      (headerFlags & MH_PIC) !== 0
        ? "present"
        : isObject || dyldFixups || (headerFlags & MH_DYLDLINK) !== 0
          ? "undetermined"
          : "absent",
    ],
    [
      "nx",
      isObject
        ? "undetermined"
        : (headerFlags & MH_ALLOW_STACK_EXECUTION) !== 0 || writableExecute
          ? "absent"
          : "present",
    ],
    ["chained-fixups", chainedFixups ? "present" : "absent"],
  ]);

  return {
    architecture: architectureName(cpuType, cpuSubtype),
    bits,
    endian: little ? "little" : "big",
    fileType: fileTypeName(fileType),
    entrypoint,
    entrypointKind,
    buildId,
    security,
    provenance: {
      ...(platform === null ? {} : { platform }),
      ...(minOs === null ? {} : { min_os: minOs }),
      ...(sdk === null ? {} : { sdk }),
      ...(linkerVersion === null ? {} : { linker_version: linkerVersion }),
      ...(signatureDeclared ? { code_signature: "declared" } : {}),
    },
    sections,
    imports: [...imports].sort(),
    exports: [...exports].sort(),
    libraries: [...libraries].sort(),
    limitations: [...new Set(limitations)].sort(),
  };
};

export const parseMachO = (buffer: Buffer, _path: string): ParsedContainer => {
  if (buffer.length < 4)
    throw new TraceForgeError("parse_error", "Mach-O header is truncated");
  const beMagic = buffer.readUInt32BE(0);
  if (beMagic === FAT_MAGIC || beMagic === FAT_MAGIC_64) {
    const is64 = beMagic === FAT_MAGIC_64;
    const count = buffer.readUInt32BE(4);
    if (count > 64)
      throw new TraceForgeError("parse_error", "Mach-O fat slice count is unreasonable");
    const entrySize = is64 ? 32 : 20;
    const slices: SliceInventory[] = [];
    const limitations: string[] = [];
    for (let index = 0; index < count; index += 1) {
      const entry = 8 + index * entrySize;
      if (entry + entrySize > buffer.length)
        throw new TraceForgeError("parse_error", "Mach-O fat header is truncated");
      const sliceOffset = is64
        ? Number(buffer.readBigUInt64BE(entry + 8))
        : buffer.readUInt32BE(entry + 8);
      const sliceSize = is64
        ? Number(buffer.readBigUInt64BE(entry + 16))
        : buffer.readUInt32BE(entry + 12);
      if (
        sliceOffset < 0 ||
        sliceSize < 0 ||
        sliceOffset + sliceSize > buffer.length
      ) {
        limitations.push(`Fat slice ${index} is outside the file and was skipped.`);
        continue;
      }
      slices.push(parseThin(buffer, sliceOffset, sliceOffset + sliceSize, limitations));
    }
    if (count > 1)
      limitations.push("Each universal slice is inspected independently.");
    return {
      format: "mach-o",
      slices,
      limitations: [...new Set(limitations)].sort(),
    };
  }
  const limitations: string[] = [];
  return {
    format: "mach-o",
    slices: [parseThin(buffer, 0, buffer.length, limitations)],
    limitations: [...new Set(limitations)].sort(),
  };
};
