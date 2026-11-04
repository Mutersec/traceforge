import { readCString, sectionHash, hex, securitySummary } from "./binary.js";
import type { ParsedContainer } from "./binary.js";
import { TraceForgeError } from "./errors.js";
import type { SectionInfo, SliceIdentity, SliceInventory } from "./types.js";

const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_DYNAMIC = 6;
const SHT_NOTE = 7;
const SHT_NOBITS = 8;
const SHT_PROGBITS = 1;
const SHT_DYNSYM = 11;
const DT_NEEDED = 1;
const DT_SONAME = 14;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;
const DF_BIND_NOW = 0x2;
const DF_1_NOW = 0x1;
const PT_NULL = 0;
const PT_LOAD = 1;
const PT_INTERP = 3;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;
const PF_X = 1;
const PF_W = 2;
const MAX_SECTIONS = 100_000;
const MAX_SYMBOLS = 200_000;
const MAX_PROGRAM_HEADERS = 65_536;
const OS_ABI_NAMES: Record<number, string> = {
  0: "sysv",
  1: "hpux",
  3: "linux",
  6: "solaris",
  7: "aix",
  9: "freebsd",
  10: "tru64",
  12: "openbsd",
  13: "openvms",
  14: "nonstop_kernel",
  15: "cygwin",
  17: "gnu_hurd",
  45: "fips-pspabi2",
  64: "arm-abi",
  97: "openrisc",
  247: "bpf",
  252: "cuda",
  253: "coreboot",
  255: "reserved",
};

interface ElfSection {
  readonly index: number;
  readonly name: string;
  readonly type: number;
  readonly flags: bigint;
  readonly address: bigint;
  readonly offset: number;
  readonly size: number;
  readonly link: number;
  readonly entrySize: number;
}

const machineName = (machine: number): string => {
  switch (machine) {
    case 3:
      return "x86";
    case 8:
      return "mips";
    case 20:
      return "ppc";
    case 21:
      return "ppc64";
    case 40:
      return "arm";
    case 62:
      return "x86_64";
    case 183:
      return "arm64";
    case 243:
      return "riscv";
    case 247:
      return "bpf";
    case 258:
      return "loongarch";
    default:
      return `machine_${machine}`;
  }
};

const fileTypeName = (type: number): string => {
  switch (type) {
    case 1:
      return "relocatable";
    case 2:
      return "executable";
    case 3:
      return "shared";
    case 4:
      return "core";
    default:
      return `etype_${type}`;
  }
};

const noteBuildId = (
  buffer: Buffer,
  section: ElfSection,
  little: boolean,
): string | null => {
  let offset = section.offset;
  const end = Math.min(buffer.length, section.offset + section.size);
  while (offset + 12 <= end) {
    const nameSize = little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
    const descSize = little
      ? buffer.readUInt32LE(offset + 4)
      : buffer.readUInt32BE(offset + 4);
    const type = little ? buffer.readUInt32LE(offset + 8) : buffer.readUInt32BE(offset + 8);
    const nameStart = offset + 12;
    const nameEnd = nameStart + nameSize;
    if (nameEnd + descSize > end) break;
    const name = buffer.toString("utf8", nameStart, nameEnd).replace(/\0.*$/u, "");
    const descStart = (nameEnd + 3) & ~3;
    if (name === "GNU" && type === 3 && descStart + descSize <= end)
      return buffer.subarray(descStart, descStart + descSize).toString("hex");
    const next = (descStart + descSize + 3) & ~3;
    if (next <= offset) break;
    offset = next;
  }
  return null;
};

export const parseElf = (buffer: Buffer, _path: string): ParsedContainer => {
  if (buffer.length < 52)
    throw new TraceForgeError("parse_error", "ELF header is truncated");
  const classValue = buffer[4];
  if (classValue !== 1 && classValue !== 2)
    throw new TraceForgeError("parse_error", "ELF class is invalid");
  const bits: 32 | 64 = classValue === 2 ? 64 : 32;
  const little = buffer[5] === 1;
  if (!little && buffer[5] !== 2)
    throw new TraceForgeError("parse_error", "ELF endianness is invalid");
  const u16 = (offset: number) =>
    little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  const u32 = (offset: number) =>
    little ? buffer.readUInt32LE(offset) : buffer.readUInt32BE(offset);
  const u64 = (offset: number): bigint =>
    little ? buffer.readBigUInt64LE(offset) : buffer.readBigUInt64BE(offset);
  const type = u16(16);
  const machine = u16(18);
  const entry = bits === 64 ? u64(24) : BigInt(u32(24));
  const sectionOffset = bits === 64 ? Number(u64(40)) : u32(32);
  const sectionEntrySize = u16(bits === 64 ? 58 : 46);
  const sectionCount = u16(bits === 64 ? 60 : 48);
  const stringTableIndex = u16(bits === 64 ? 62 : 50);
  if (sectionCount > MAX_SECTIONS)
    throw new TraceForgeError("parse_error", "ELF section count is unreasonable");
  if (
    sectionCount > 0 &&
    (sectionEntrySize < (bits === 64 ? 64 : 40) ||
      sectionOffset + sectionCount * sectionEntrySize > buffer.length)
  )
    throw new TraceForgeError("parse_error", "ELF section headers exceed the file");
  const readSection = (index: number): ElfSection | null => {
    const base = sectionOffset + index * sectionEntrySize;
    if (base + sectionEntrySize > buffer.length) return null;
    return {
      index,
      name: "",
      type: u32(base + 4),
      flags: bits === 64 ? u64(base + 8) : BigInt(u32(base + 8)),
      address: bits === 64 ? u64(base + 16) : BigInt(u32(base + 12)),
      offset: bits === 64 ? Number(u64(base + 24)) : u32(base + 16),
      size: bits === 64 ? Number(u64(base + 32)) : u32(base + 20),
      link: u32(bits === 64 ? base + 40 : base + 24),
      entrySize: bits === 64 ? Number(u64(base + 56)) : u32(base + 36),
    };
  };
  const rawSections: ElfSection[] = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const section = readSection(index);
    if (section !== null) rawSections.push(section);
  }
  const stringSection =
    stringTableIndex < rawSections.length
      ? rawSections[stringTableIndex] ?? null
      : null;
  const namedSections = rawSections.map((section) => {
    if (stringSection === null || section.index === 0) return section;
    const name = readCString(buffer, stringSection.offset + u32(sectionOffset + section.index * sectionEntrySize), 4096);
    return { ...section, name: name ?? "" };
  });
  const limitations: string[] = [];
  const sections: SectionInfo[] = [];
  for (const section of namedSections) {
    if (section.index === 0 || section.name.length === 0) continue;
    sections.push({
      name: section.name,
      segment: null,
      address: hex(section.address),
      offset: section.offset,
      size: section.size,
      sha256:
        section.type === SHT_NOBITS
          ? null
          : sectionHash(buffer, section.offset, section.size, limitations),
      flags: hex(section.flags),
    });
  }
  if (stringTableIndex === 0xffff || sectionCount === 0)
    limitations.push("ELF extended section indices or missing section headers limit section names.");

  const programHeaderOffset = bits === 64 ? Number(u64(32)) : u32(28);
  const programEntrySize = u16(bits === 64 ? 54 : 42);
  const minimumEntry = bits === 64 ? 56 : 32;
  let programCount = u16(bits === 64 ? 56 : 44);
  if (programCount === 0xffff) {
    programCount =
      sectionCount > 0 && sectionEntrySize >= minimumEntry
        ? bits === 64
          ? u32(sectionOffset + 44)
          : u32(sectionOffset + 28)
        : 0;
    limitations.push("ELF program header count was taken from the PN_XNUM section header.");
  }
  const segments = {
    load: 0,
    writableExecute: false,
    interp: null as string | null,
    gnuStack: null as number | null,
    gnuRelro: false,
  };
  if (
    programCount > MAX_PROGRAM_HEADERS ||
    (programCount > 0 &&
      (programEntrySize < minimumEntry ||
        programHeaderOffset + programCount * programEntrySize > buffer.length))
  ) {
    limitations.push("ELF program headers were out of bounds and were not inspected.");
  } else {
    for (let index = 0; index < programCount; index += 1) {
      const base = programHeaderOffset + index * programEntrySize;
      const type = u32(base);
      const flags = bits === 64 ? u32(base + 4) : u32(base + 24);
      const fileOffset = bits === 64 ? Number(u64(base + 8)) : u32(base + 4);
      const fileSize = bits === 64 ? Number(u64(base + 32)) : u32(base + 16);
      if (type === PT_NULL) continue;
      if (type === PT_LOAD) segments.load += 1;
      if ((flags & PF_W) !== 0 && (flags & PF_X) !== 0) segments.writableExecute = true;
      if (type === PT_GNU_STACK) segments.gnuStack = flags;
      if (type === PT_GNU_RELRO) segments.gnuRelro = true;
      if (type === PT_INTERP && segments.interp === null)
        segments.interp = readCString(buffer, fileOffset, 4096);
    }
  }

  const imports = new Set<string>();
  const exports = new Set<string>();
  let symbolCount = 0;
  for (const section of namedSections) {
    if (section.type !== SHT_SYMTAB && section.type !== SHT_DYNSYM) continue;
    const strings = namedSections[section.link];
    if (strings === undefined || (strings.type !== SHT_STRTAB && strings.size === 0))
      continue;
    const entrySize = section.entrySize > 0 ? section.entrySize : bits === 64 ? 24 : 16;
    const count = Math.min(Math.floor(section.size / entrySize), MAX_SYMBOLS);
    if (section.size / entrySize > MAX_SYMBOLS)
      limitations.push("ELF symbol list was capped at 200,000 entries.");
    for (let index = 0; index < count; index += 1) {
      const base = section.offset + index * entrySize;
      if (base + entrySize > buffer.length) break;
      const nameOffset = u32(base);
      const info = buffer[bits === 64 ? base + 4 : base + 12] ?? 0;
      const sectionIndex = u16(bits === 64 ? base + 6 : base + 14);
      const name = readCString(buffer, strings.offset + nameOffset, 4096);
      if (name === null || name.length === 0) continue;
      symbolCount += 1;
      const binding = info >> 4;
      const symbolType = info & 0x0f;
      if (binding !== 1 && binding !== 2) continue;
      if (sectionIndex === 0) {
        imports.add(name);
        continue;
      }
      if (symbolType === 0 || symbolType === 1 || symbolType === 2 || symbolType === 10)
        exports.add(name);
    }
  }
  if (symbolCount >= MAX_SYMBOLS)
    limitations.push("ELF symbol processing stopped at the safety cap.");

  const libraries = new Set<string>();
  let soname: string | null = null;
  let bindNow: boolean | null = null;
  const dynamic = namedSections.find((section) => section.type === SHT_DYNAMIC);
  if (dynamic !== undefined) {
    const strings = namedSections[dynamic.link];
    const entrySize = dynamic.entrySize > 0 ? dynamic.entrySize : bits === 64 ? 16 : 8;
    const count = Math.min(Math.floor(dynamic.size / entrySize), 100_000);
    for (let index = 0; index < count; index += 1) {
      const base = dynamic.offset + index * entrySize;
      if (base + entrySize > buffer.length) break;
      const tag = bits === 64 ? Number(u64(base)) : u32(base);
      const value = bits === 64 ? Number(u64(base + 8)) : u32(base + 4);
      if (tag === 0) break;
      if (tag === DT_FLAGS) bindNow = (value & DF_BIND_NOW) !== 0;
      if (tag === DT_FLAGS_1) bindNow = (value & DF_1_NOW) !== 0 || bindNow === true;
      if ((tag === DT_NEEDED || tag === DT_SONAME) && strings !== undefined) {
        const name = readCString(buffer, strings.offset + value, 4096);
        if (name !== null && name.length > 0) {
          if (tag === DT_NEEDED) libraries.add(name);
          else soname = name;
        }
      }
    }
  } else {
    limitations.push("ELF DT_NEEDED libraries were unavailable without a dynamic section.");
  }
  if (bindNow === null)
    limitations.push("ELF BIND_NOW could not be decided without DT_FLAGS or DT_FLAGS_1.");

  const commentSection = namedSections.find(
    (section) => section.type === SHT_PROGBITS && section.name === ".comment",
  );
  const producer =
    commentSection === undefined
      ? null
      : (readCString(buffer, commentSection.offset, 160) ?? "").trim() || null;
  if (producer !== null)
    limitations.push("The ELF .comment producer string is a self-reported claim.");


  const buildSection = namedSections.find(
    (section) => section.type === SHT_NOTE && section.name === ".note.gnu.build-id",
  );
  const buildId = buildSection === undefined ? null : noteBuildId(buffer, buildSection, little);
  const relocatable = type === 3;
  limitations.push(
    "Mitigation names are structural claims from ELF headers, not observed runtime enforcement.",
  );
  limitations.push(
    "ASLR depends on the operating system and loader; only image relocatability was inspected.",
  );
  const security = securitySummary([
    ["pie", relocatable ? "present" : type === 2 ? "absent" : "undetermined"],
    ["aslr", relocatable ? "present" : type === 2 ? "absent" : "undetermined"],
    [
      "nx",
      segments.gnuStack === null
        ? segments.writableExecute
          ? "absent"
          : "undetermined"
        : (segments.gnuStack & PF_X) === 0
          ? "present"
          : "absent",
    ],
    ["relro", segments.gnuRelro ? "present" : "absent"],
    ["bind-now", bindNow === null ? "undetermined" : bindNow ? "present" : "absent"],
    [
      "full-relro",
      !segments.gnuRelro
        ? "absent"
        : bindNow === null
          ? "undetermined"
          : bindNow
            ? "present"
            : "absent",
    ],
  ]);
  const slice: SliceInventory = {
    architecture: machineName(machine),
    bits,
    endian: little ? "little" : "big",
    fileType: fileTypeName(type),
    entrypoint: hex(entry),
    entrypointKind: "virtual-address",
    buildId,
    security,
    provenance: {
      os_abi: OS_ABI_NAMES[buffer[7] ?? 0] ?? `abi_${buffer[7] ?? 0}`,
      abi_version: String(buffer[8] ?? 0),
      ...(segments.load === 0 ? {} : { load_segments: String(segments.load) }),
      ...(segments.interp === null ? {} : { interpreter: segments.interp }),
      ...(soname === null ? {} : { soname }),
      ...(producer === null ? {} : { producer }),
    },
    sections,
    imports: [...imports].sort(),
    exports: [...exports].sort(),
    libraries: [...libraries].sort(),
    limitations: [...new Set(limitations)].sort(),
  };
  return {
    format: "elf",
    slices: [slice],
    limitations: [...new Set(limitations)].sort(),
  };
};

/**
 * Reads only the ELF identity fields (class, endianness, type, machine).
 *
 * Package members are labelled from the first 20 header bytes; no section table
 * is touched, so a scan stays cheap on a bundle with thousands of members.
 */
export const readElfIdentities = (
  buffer: Buffer,
  _limitations: string[],
): readonly SliceIdentity[] => {
  if (buffer.length < 20)
    throw new TraceForgeError("parse_error", "ELF header is truncated");
  const classValue = buffer[4];
  if (classValue !== 1 && classValue !== 2)
    throw new TraceForgeError("parse_error", "ELF class is invalid");
  const little = buffer[5] === 1;
  if (!little && buffer[5] !== 2)
    throw new TraceForgeError("parse_error", "ELF endianness is invalid");
  const u16 = (offset: number): number =>
    little ? buffer.readUInt16LE(offset) : buffer.readUInt16BE(offset);
  return [
    {
      architecture: machineName(u16(18)),
      file_type: fileTypeName(u16(16)),
    },
  ];
};
