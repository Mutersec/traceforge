#!/usr/bin/env node
// elf-crosscheck.mjs - CI-only comparison of TraceForge's own ELF inventory
// against `readelf -h -d -S` run over the SAME file. Owned by the ci.yml
// "ELF cross-check against readelf" step (ubuntu leg); it exists because no
// macOS developer machine can run GNU readelf, so until now the ELF output had
// no independent second reader anywhere.
//
// Input: two files produced from one binary (in CI: the runner's /bin/ls):
//   --traceforge <f>  `node dist/cli.js inspect <path> --json --no-save` output
//   --readelf <f>     text from `readelf -h -d -S <path>` (the same <path>)
//
// GATING RULE: a field is gated only when both tools read the same header
// field under ONE shared counting convention. Candidates whose conventions
// differ (entrypoint display, program header count, section names, ET_DYN
// label) are printed side by side and never asserted. The three gated fields:
//
//   1. machine          - `Machine: <name>` vs slice.architecture. The readelf
//      string comes from libbinutils's machine table and the TraceForge token
//      from src/core/elf.ts machineName() (same e_machine number, two tables).
//      An unmapped readelf string FAILS instead of guessing.
//   2. section headers  - the header count vs slice.sections.length. readelf
//      counts every section header including the required index-0 SHT_NULL
//      entry; src/core/elf.ts:194-195 builds its section list with
//      `if (section.index === 0 || section.name.length === 0) continue`, so
//      the TraceForge list excludes index 0 and any empty-name section. The
//      gated tolerance is therefore exactly N_readelf - 1, which additionally
//      assumes no empty-name section beyond index 0 (true of GNU-toolchain
//      executables; if this fails on a real binary, the raw numbers printed
//      below show which side of the convention moved).
//   3. dynamic + DT_NEEDED - presence is decided from the readelf -d wording
//      ("Dynamic section at offset ... contains M entries" vs "no dynamic
//      section"), and on the TraceForge side from the single limitation
//      src/core/elf.ts:315-317 pushes exactly when no SHT_DYNAMIC section
//      exists. When dynamic is present, the (NEEDED) "Shared library: [x]"
//      names are compared as sorted unique sets: elf.ts collects DT_NEEDED
//      into a Set (line 291) and sorts on output (line 389), so set equality -
//      not DT order - is the shared convention. The English wording assumes
//      the runner's C/en locale (GitHub-hosted Ubuntu default).
//
// Every gate failure prints the RAW value of both sides (in the table and in
// the FAIL lines), then the script exits 1 at the end; gated rows never stop
// the reported rows from also being printed.
//
// Exit codes: 0 every gated field matched · 1 a gate failed, or readelf text
// was unrecognisable (a changed format is NOT silently passed) · 2 usage
// error or input that is not a TraceForge inspect JSON of an ELF binary.

import { readFileSync } from "node:fs";

const USAGE = [
  "usage: node scripts/elf-crosscheck.mjs --traceforge <inspect.json> --readelf <readelf.txt>",
  "",
  "  --traceforge <f>  JSON from `node dist/cli.js inspect <path> --json --no-save`",
  "  --readelf <f>     text from `readelf -d -h -S <path>` (the same <path>)",
  "  -h, --help        show this help",
  "",
  "Gates machine, section header count (SHT_NULL tolerance per",
  "src/core/elf.ts:194-195) and dynamic/DT_NEEDED presence + library set.",
  "Entrypoint, program header count, ET_DYN label and section names are",
  "reported side by side, not gated.",
  "Exit 0 matched · 1 gate failure or unrecognized readelf text · 2 usage.",
].join("\n");

// e_machine display strings GNU binutils prints in `readelf -h`, mapped to the
// token src/core/elf.ts machineName() produces for the same number. Only
// strings the maintainer is confident binutils prints verbatim are listed;
// anything else fails as unmapped rather than guessed. The ubuntu leg only
// needs the first entry today (x86_64 runners).
const MACHINE_BY_READELF = new Map([
  ["Advanced Micro Devices X86-64", "x86_64"], // EM_X86_64=62, elf.ts:76
  ["Intel 80386", "x86"],                      // EM_386=3,    elf.ts:66
  ["AArch64", "arm64"],                        // EM_AARCH64=183, elf.ts:78
  ["RISC-V", "riscv"],                         // EM_RISCV=243, elf.ts:80
  ["PowerPC64", "ppc64"],                      // EM_PPC64=21, elf.ts:72
  ["PowerPC", "ppc"],                          // EM_PPC=20,   elf.ts:70
  ["MIPS R3000", "mips"],                      // EM_MIPS=8,   elf.ts:68
]);

// The exact string src/core/elf.ts:316 pushes iff no SHT_DYNAMIC section was
// found. Its presence on the TraceForge side means "no dynamic section".
const NO_DYNAMIC_LIMITATION =
  "ELF DT_NEEDED libraries were unavailable without a dynamic section.";

const problems = []; // gated-field mismatches, reported with raw values
const notes = [];    // informational parse notes

const fail = (code, message) => {
  process.stderr.write(`${message}\n`);
  process.exit(code);
};

const argv = process.argv.slice(2);
const options = { traceforge: null, readelf: null };
for (let index = 0; index < argv.length; index += 1) {
  const token = argv[index];
  if (token === "-h" || token === "--help") {
    process.stdout.write(`${USAGE}\n`);
    process.exit(0);
  } else if (token === "--traceforge") {
    const value = argv[++index];
    if (value === undefined) fail(2, "elf-crosscheck: --traceforge needs a file");
    options.traceforge = value;
  } else if (token === "--readelf") {
    const value = argv[++index];
    if (value === undefined) fail(2, "elf-crosscheck: --readelf needs a file");
    options.readelf = value;
  } else fail(2, `elf-crosscheck: unknown argument "${token}".\n\n${USAGE}`);
}
if (options.traceforge === null || options.readelf === null)
  fail(2, `elf-crosscheck: both --traceforge and --readelf are required.\n\n${USAGE}`);

const readText = (path) => {
  try {
    return readFileSync(path, "utf8");
  } catch {
    fail(2, `elf-crosscheck: cannot read ${path}`);
  }
};

let tf;
try {
  tf = JSON.parse(readText(options.traceforge));
} catch (cause) {
  fail(2, `elf-crosscheck: --traceforge file is not valid JSON: ${cause.message}`);
}
const inventory = tf?.result;
const slices = Array.isArray(inventory?.slices) ? inventory.slices : null;
if (
  tf?.schema !== "traceforge.evidence.v1" ||
  inventory?.schema !== "traceforge.inventory.v2" ||
  slices === null
)
  fail(2, "elf-crosscheck: --traceforge file is not a full `inspect --json` record (expected schema traceforge.evidence.v1 with result.slices).");
if (inventory.format !== "elf")
  fail(2, `elf-crosscheck: inventory format is "${inventory.format}", not elf - wrong subject for this step.`);
if (slices.length !== 1)
  fail(2, `elf-crosscheck: expected a single ELF slice, got ${slices.length}; refusing to pick one.`);
const slice = slices[0];
for (const key of ["sections", "libraries", "limitations"])
  if (!Array.isArray(slice[key])) fail(2, `elf-crosscheck: inspect JSON slice.${key} is not an array (record shape changed?).`);
if (tf.input?.path !== undefined && inventory.path !== undefined && tf.input.path !== inventory.path)
  notes.push(`record.input.path=${tf.input.path} differs from result.path=${inventory.path} (both printed from the same record)`);

const text = readText(options.readelf);

// --- required readelf lines -------------------------------------------------
// Each gated field must be locatable in the readelf text; an absent line means
// readelf's format moved (or the file is not readelf output) and no gate can
// claim anything, so the whole script fails loudly (exit 1) with an excerpt.
const grab = (pattern, label) => {
  const match = pattern.exec(text);
  if (match === null)
    fail(1, `elf-crosscheck: could not locate "${label}" in the readelf output; refusing to guess.\n--- readelf first 40 lines ---\n${text.split("\n").slice(0, 40).join("\n")}`);
  return match[1];
};

const machineRaw = grab(/^\s*Machine:\s+(.+?)\s*$/mu, "Machine: in -h");
const nFromH = Number(grab(/^\s*Number of section headers:\s+(\d+)/mu, "Number of section headers: in -h"));

// -S repeats the same count; when both lines are present they must agree,
// otherwise this script's parse (or the readelf output) is broken.
const sCountMatch = /There are (\d+) section headers,/u.exec(text);
if (sCountMatch !== null && Number(sCountMatch[1]) !== nFromH)
  fail(1, `elf-crosscheck: readelf -h says ${nFromH} section headers, readelf -S says ${sCountMatch[1]}; refusing to arbitrate.`);

// dynamic presence, decided from the readelf text; unrecognized means fail.
const dynamicPresentRe = /Dynamic section at offset .* contains \d+ entries/u;
const dynamicAbsentRe = /no dynamic section/iu;
const readelfDynamicPresent = dynamicPresentRe.test(text);
const readelfDynamicAbsent = dynamicAbsentRe.test(text);
if (readelfDynamicPresent === readelfDynamicAbsent)
  fail(1, `elf-crosscheck: readelf -d output is unrecognized (dynamic-present=${readelfDynamicPresent}, no-dynamic-line=${readelfDynamicAbsent}); refusing to decide.\n--- readelf first 40 lines ---\n${text.split("\n").slice(0, 40).join("\n")}`);

// --- gated field 1: machine -------------------------------------------------
const mappedMachine = MACHINE_BY_READELF.get(machineRaw);
if (mappedMachine === undefined) {
  problems.push(`machine: unmapped readelf Machine string "${machineRaw}" vs TraceForge architecture "${slice.architecture}"; extend MACHINE_BY_READELF only after checking binutils.`);
} else if (mappedMachine !== slice.architecture) {
  problems.push(`machine: readelf Machine="${machineRaw}" maps to "${mappedMachine}", TraceForge architecture="${slice.architecture}".`);
}
const machineOk = mappedMachine !== undefined && mappedMachine === slice.architecture;

// --- gated field 2: section header count ------------------------------------
const tfSectionCount = slice.sections.length;
const countOk = tfSectionCount === nFromH - 1;
if (!countOk)
  problems.push(`section headers: readelf reports ${nFromH} headers (SHT_NULL index 0 included), TraceForge lists ${tfSectionCount} sections; gated expectation is sections == headers - 1 per src/core/elf.ts:194-195 (index 0 always skipped; empty-name sections also skipped, which would widen the gap).`);

// --- gated field 3: dynamic presence + DT_NEEDED set -------------------------
const tfDynamicPresent = !slice.limitations.includes(NO_DYNAMIC_LIMITATION);
const needed = [...new Set([...text.matchAll(/\(\s*NEEDED\s*\)\s+Shared library:\s+\[(.*?)\]/gu)].map((m) => m[1]))].sort();
const tfLibraries = [...new Set(slice.libraries)].sort();
let dynamicOk = true;
if (readelfDynamicPresent !== tfDynamicPresent) {
  dynamicOk = false;
  problems.push(`dynamic section: readelf -d says ${readelfDynamicPresent ? "present" : "absent"}, TraceForge limitations say ${tfDynamicPresent ? "present (no limitation)" : `absent (contains "${NO_DYNAMIC_LIMITATION}")`}.`);
} else if (readelfDynamicPresent && JSON.stringify(needed) !== JSON.stringify(tfLibraries)) {
  dynamicOk = false;
  problems.push(`DT_NEEDED set: readelf (NEEDED)=[${needed.join(", ")}] vs TraceForge libraries=[${tfLibraries.join(", ")}] (elf.ts:291 Set, :389 sort).`);
}

// --- reported, never gated --------------------------------------------------
const grabFirst = (pattern, label) => {
  const match = pattern.exec(text);
  if (match === null) {
    notes.push(`${label}: not found in the readelf text (reported-only field, not gated)`);
    return "(not found)";
  }
  return match[1];
};
const entryRaw = grabFirst(/^\s*Entry point address:\s+(\S+)/mu, "Entry point address");
const phnumRaw = grabFirst(/^\s*Number of program headers:\s+(\d+)/mu, "Number of program headers");
const typeRaw = grabFirst(/^\s*Type:\s+(.+?)\s*$/mu, "Type");

const namesShown = slice.sections.length > 60
  ? `${slice.sections.map((s) => s.name).slice(0, 60).join(" ")} ... (${slice.sections.length} total)`
  : slice.sections.map((s) => s.name).join(" ");

// --- output -----------------------------------------------------------------
const cell = (value) => `\`${String(value)}\``;
const mark = (ok) => (ok ? "ok" : "**FAIL**");
const lines = [
  "Subject: `/bin/ls` leg input · readelf text vs TraceForge inspect JSON (single slice).",
  "",
  "Gated fields (raw values of both sides, always shown):",
  "",
  "| # | field | readelf raw | TraceForge raw | expectation | result |",
  "| - | ----- | ----------- | -------------- | ----------- | ------ |",
  `| 1 | machine | ${cell(machineRaw)} | ${cell(slice.architecture)} | binutils string maps to the elf.ts token | ${mark(machineOk)} |`,
  `| 2 | section headers | ${cell(nFromH)} (SHT_NULL included${sCountMatch !== null ? ", -S agrees" : ", -S count line absent"}) | ${cell(tfSectionCount)} | TraceForge == readelf - 1 (elf.ts:194-195) | ${mark(countOk)} |`,
  `| 3 | dynamic/DT_NEEDED | ${cell(readelfDynamicPresent ? `present, NEEDED=[${needed.join(", ")}]` : "absent")} | ${cell(tfDynamicPresent ? `libraries=[${tfLibraries.join(", ")}]` : "absent (no-dynamic limitation)")} | same presence; NEEDED set == libraries set | ${mark(dynamicOk)} |`,
  "",
  "Reported side by side, deliberately NOT gated:",
  "",
  "| field | readelf | TraceForge | why not gated |",
  "| ----- | ------- | ---------- | ------------- |",
  `| entrypoint | ${cell(entryRaw)} | ${cell(`${slice.entrypoint} (kind: ${slice.entrypointKind})`)} | PIE display convention differs between the tools; asserting it would add no independent signal |`,
  `| program headers | ${cell(phnumRaw)} | ${cell(slice.provenance?.load_segments === undefined ? "load_segments absent (0 PT_LOAD)" : `load_segments=${slice.provenance.load_segments}`)} | elf.ts:246-247 counts only PT_LOAD and skips PT_NULL, so this is not readelf's phnum |`,
  `| Type | ${cell(typeRaw)} | ${cell(slice.fileType)} | elf.ts:100 labels ET_DYN "shared", readelf labels the same number "DYN (...)" |`,
  "",
  `TraceForge section names (${slice.sections.length}): ${cell(namesShown)}`,
];
if (notes.length > 0) lines.push("", "Parse notes (informational):", ...notes.map((n) => `  - ${n}`));
if (problems.length > 0) lines.push("", "Gate failures (raw values of both sides):", ...problems.map((p) => `  x ${p}`));

process.stdout.write(`${lines.join("\n")}\n`);

if (problems.length > 0) {
  const message = `elf-crosscheck: ${problems.length} gated field(s) disagreed between readelf and TraceForge - see the lines above.`;
  process.stderr.write(`${message}\n`);
  for (const p of problems) process.stderr.write(`elf-crosscheck: x ${p}\n`);
  process.exit(1);
}
process.stdout.write("elf-crosscheck: all gated ELF fields agree with readelf · non-gated fields are reported above for review\n");
