import { readCString, sectionHash, hex } from "./binary.js";
import type { ParsedContainer } from "./binary.js";
import { TraceForgeError } from "./errors.js";
import type { SectionInfo, SliceInventory } from "./types.js";

const SHT_SYMTAB = 2;
const SHT_STRTAB = 3;
const SHT_DYNAMIC = 6;
const SHT_NOTE = 7;
const SHT_NOBITS = 8;
const SHT_DYNSYM = 11;
const DT_NEEDED = 1;
const MAX_SECTIONS = 100_000;
const MAX_SYMBOLS = 200_000;

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
      if (tag !== DT_NEEDED || strings === undefined) continue;
      const name = readCString(buffer, strings.offset + value, 4096);
      if (name !== null && name.length > 0) libraries.add(name);
    }
  } else {
    limitations.push("ELF DT_NEEDED libraries were unavailable without a dynamic section.");
  }

  const buildSection = namedSections.find(
    (section) => section.type === SHT_NOTE && section.name === ".note.gnu.build-id",
  );
  const buildId = buildSection === undefined ? null : noteBuildId(buffer, buildSection, little);
  const slice: SliceInventory = {
    architecture: machineName(machine),
    bits,
    endian: little ? "little" : "big",
    fileType: fileTypeName(type),
    entrypoint: hex(entry),
    entrypointKind: "virtual-address",
    buildId,
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
