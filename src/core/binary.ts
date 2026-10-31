import { createHash } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { resolve } from "node:path";

import { sha256Hex } from "./canonical.js";
import { TraceForgeError } from "./errors.js";
import { parseElf } from "./elf.js";
import { parseMachO } from "./macho.js";
import { parsePe } from "./pe.js";
import { parseWasm } from "./wasm.js";
import type { BinaryFormat, BinaryInventory, ComparisonResult, SliceInventory } from "./types.js";

export const MAX_BINARY_BYTES = 512 * 1024 * 1024;
const MAX_SECTION_HASH_BYTES = 64 * 1024 * 1024;

export interface ParsedContainer {
  readonly format: BinaryFormat;
  readonly slices: readonly SliceInventory[];
  readonly limitations: readonly string[];
}

export const detectFormat = (buffer: Uint8Array): BinaryFormat => {
  if (buffer.length >= 4) {
    const magic = Buffer.from(buffer.subarray(0, 4)).toString("hex");
    if (["feedface", "cefaedfe", "feedfacf", "cffaedfe", "cafebabe", "bebafeca", "cafebabf", "bfbafeca"].includes(magic))
      return "mach-o";
    if (magic === "7f454c46") return "elf";
    if (magic === "0061736d") return "wasm";
  }
  if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) return "pe";
  return "unknown";
};

export const readCString = (
  buffer: Buffer,
  offset: number,
  limit = 4096,
): string | null => {
  if (offset < 0 || offset >= buffer.length) return null;
  const end = Math.min(buffer.length, offset + limit);
  const zero = buffer.indexOf(0, offset);
  if (zero < 0 || zero > end) return null;
  return buffer.toString("utf8", offset, zero);
};

export const hex = (value: bigint | number): string =>
  `0x${typeof value === "bigint" ? value.toString(16) : value.toString(16)}`;

export const sectionHash = (
  buffer: Buffer,
  offset: number,
  size: number,
  limitations: string[],
): string | null => {
  if (size === 0) return null;
  if (
    offset < 0 ||
    size < 0 ||
    offset + size > buffer.length ||
    size > MAX_SECTION_HASH_BYTES
  ) {
    if (size > MAX_SECTION_HASH_BYTES)
      limitations.push("A section hash was omitted for a section larger than 64 MiB.");
    return null;
  }
  return createHash("sha256")
    .update(buffer.subarray(offset, offset + size))
    .digest("hex");
};

export const parseContainer = (
  buffer: Buffer,
  path: string,
): ParsedContainer => {
  const format = detectFormat(buffer);
  switch (format) {
    case "mach-o":
      return parseMachO(buffer, path);
    case "elf":
      return parseElf(buffer, path);
    case "pe":
      return parsePe(buffer, path);
    case "wasm":
      return parseWasm(buffer, path);
    default:
      return {
        format,
        slices: [],
        limitations: ["The binary format was not recognized; only file identity was recorded."],
      };
  }
};

export const inspectBinary = async (
  inputPath: string,
): Promise<BinaryInventory> => {
  const path = resolve(inputPath);
  const info = await stat(path).catch((cause: unknown) => {
    throw new TraceForgeError("invalid_path", `Cannot read ${inputPath}`, { cause });
  });
  if (!info.isFile())
    throw new TraceForgeError("not_a_file", `${inputPath} is not a regular file`);
  if (info.size > MAX_BINARY_BYTES)
    throw new TraceForgeError(
      "file_too_large",
      `${inputPath} is larger than the 512 MiB inspection limit`,
    );
  const buffer = await readFile(path).catch((cause: unknown) => {
    throw new TraceForgeError("invalid_path", `Cannot read ${inputPath}`, { cause });
  });
  const sha256 = sha256Hex(buffer);
  const parsed = parseContainer(buffer, path);
  return {
    schema: "traceforge.inventory.v1",
    path,
    sha256,
    size: buffer.length,
    format: parsed.format,
    slices: parsed.slices,
    limitations: parsed.limitations,
  };
};

const sectionKey = (slice: SliceInventory, section: SliceInventory["sections"][number]): string =>
  `${slice.architecture}:${section.segment ?? ""}:${section.name}`;

const uniqueSorted = (values: Iterable<string>): string[] =>
  [...new Set(values)].sort((left, right) => left.localeCompare(right));

const setDiff = (left: readonly string[], right: readonly string[]): {
  readonly added: string[];
  readonly removed: string[];
} => {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return {
    added: uniqueSorted([...rightSet].filter((item) => !leftSet.has(item))),
    removed: uniqueSorted([...leftSet].filter((item) => !rightSet.has(item))),
  };
};

export const compareInventories = (
  left: BinaryInventory,
  right: BinaryInventory,
): ComparisonResult => {
  const changes = {
    format: left.format !== right.format,
    size: left.size !== right.size,
    slices_added: setDiff(
      left.slices.map((slice) => slice.architecture),
      right.slices.map((slice) => slice.architecture),
    ).added,
    slices_removed: setDiff(
      left.slices.map((slice) => slice.architecture),
      right.slices.map((slice) => slice.architecture),
    ).removed,
    sections_added: [] as string[],
    sections_removed: [] as string[],
    sections_changed: [] as string[],
    imports_added: [] as string[],
    imports_removed: [] as string[],
    exports_added: [] as string[],
    exports_removed: [] as string[],
  };
  const limitations = uniqueSorted([
    ...left.limitations,
    ...right.limitations,
    ...(left.format === right.format
      ? []
      : ["Formats differ; structural differences are limited to slice identity."]),
  ]);
  const leftSlices = new Map(left.slices.map((slice) => [slice.architecture, slice]));
  const rightSlices = new Map(right.slices.map((slice) => [slice.architecture, slice]));
  for (const [architecture, leftSlice] of leftSlices) {
    const rightSlice = rightSlices.get(architecture);
    if (rightSlice === undefined) continue;
    const leftSections = new Map(
      leftSlice.sections.map((section) => [sectionKey(leftSlice, section), section]),
    );
    const rightSections = new Map(
      rightSlice.sections.map((section) => [sectionKey(rightSlice, section), section]),
    );
    for (const [key, leftSection] of leftSections) {
      const rightSection = rightSections.get(key);
      if (rightSection === undefined) {
        changes.sections_removed.push(key);
        continue;
      }
      if (
        leftSection.sha256 !== null &&
        rightSection.sha256 !== null &&
        leftSection.sha256 !== rightSection.sha256
      )
        changes.sections_changed.push(key);
    }
    for (const key of rightSections.keys())
      if (!leftSections.has(key)) changes.sections_added.push(key);
    const imports = setDiff(leftSlice.imports, rightSlice.imports);
    const exports = setDiff(leftSlice.exports, rightSlice.exports);
    changes.imports_added.push(...imports.added);
    changes.imports_removed.push(...imports.removed);
    changes.exports_added.push(...exports.added);
    changes.exports_removed.push(...exports.removed);
  }
  for (const key of [
    "slices_added",
    "slices_removed",
    "sections_added",
    "sections_removed",
    "sections_changed",
    "imports_added",
    "imports_removed",
    "exports_added",
    "exports_removed",
  ] as const)
    changes[key] = uniqueSorted(changes[key]);
  return {
    schema: "traceforge.comparison.v1",
    changed:
      changes.format ||
      changes.size ||
      changes.slices_added.length > 0 ||
      changes.slices_removed.length > 0 ||
      changes.sections_added.length > 0 ||
      changes.sections_removed.length > 0 ||
      changes.sections_changed.length > 0 ||
      changes.imports_added.length > 0 ||
      changes.imports_removed.length > 0 ||
      changes.exports_added.length > 0 ||
      changes.exports_removed.length > 0,
    left,
    right,
    changes,
    limitations,
  };
};

export const summarizeInventory = (inventory: BinaryInventory) => ({
  schema: "traceforge.scan.v1",
  path: inventory.path,
  sha256: inventory.sha256,
  size: inventory.size,
  format: inventory.format,
  slices: inventory.slices.map((slice) => ({
    architecture: slice.architecture,
    bits: slice.bits,
    endian: slice.endian,
    file_type: slice.fileType,
    entrypoint: slice.entrypoint,
    sections: slice.sections.length,
    imports: slice.imports.length,
    exports: slice.exports.length,
    libraries: slice.libraries.length,
  })),
  limitations: [...inventory.limitations],
});
