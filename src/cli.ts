#!/usr/bin/env node
import { stat } from "node:fs/promises";
import { parseArgs } from "node:util";

import { summarizePackage } from "./core/app.js";
import { compare, inspect, scanBinary, scanPackage } from "./core/operations.js";
import { EvidenceStore } from "./core/evidence.js";
import { writeEvidenceReport } from "./core/report.js";
import { TraceForgeError } from "./core/errors.js";
import type { AppInventory, ComparisonResult, EvidenceRecord } from "./core/types.js";
import { runMcpServer } from "./mcp/server.js";

export const VERSION = "0.2.0";

const HELP = `TraceForge ${VERSION} — local-first binary evidence.

Usage:
  tforge scan <path> [--json] [--store <dir>] [--no-save]
  tforge inspect <path> [--arch <name>] [--json] [--store <dir>] [--no-save]
  tforge app <package> [--json] [--store <dir>] [--no-save]
  tforge diff <left> <right> [--json] [--store <dir>] [--no-save]
  tforge evidence list
  tforge evidence show <evidence_id>
  tforge evidence verify <evidence_id>
  tforge evidence verify-all
  tforge evidence export <bundle.json>
  tforge evidence import <bundle.json>
  tforge report <path|package|evidence_id> [--out <file>]
  tforge mcp
  tforge version

Packages:
  tforge app walks an .app, .framework or directory recursively: one member
  per file with size, SHA-256 and format, plus the identity the bundle
  manifest declares. The walk stops at 5,000 members or depth 32 and records
  that as a limitation instead of failing. Nothing is executed, and symbolic
  links are recorded but never followed.

Evidence:
  Every scan, inspect, app and diff writes a deterministic content-addressed
  record to .traceforge/evidence unless --no-save is used.

Exit codes:
  0 success, 1 user/input error, 2 internal error.
`;

const color = (enabled: boolean, code: string, value: string): string =>
  enabled ? `\u001b[${code}m${value}\u001b[0m` : value;

const ttyColor = (): boolean =>
  process.stdout.isTTY === true && process.env.NO_COLOR === undefined;

const print = (value: unknown, json: boolean): void => {
  if (json) process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
};

const evidenceLine = (record: EvidenceRecord, enabled: boolean): void => {
  process.stderr.write(
    `${color(enabled, "2", "Evidence")} ${record.evidence_id} ${color(enabled, "2", `(${record.operation})`)}\n`,
  );
};

const simpleHeader = (title: string, enabled: boolean): void => {
  process.stdout.write(`${color(enabled, "1;36", "TraceForge")} ${color(enabled, "2", `· ${title}`)}\n\n`);
};

const scanHuman = (
  result: Awaited<ReturnType<typeof scanBinary>>["result"],
  enabled: boolean,
): void => {
  simpleHeader("scan", enabled);
  process.stdout.write(`${color(enabled, "2", "path")}     ${result.path}\n`);
  process.stdout.write(`${color(enabled, "2", "sha256")}   ${result.sha256}\n`);
  process.stdout.write(`${color(enabled, "2", "size")}     ${result.size.toLocaleString()} bytes\n`);
  process.stdout.write(`${color(enabled, "2", "format")}   ${result.format}\n`);
  if (result.slices.length === 0) {
    process.stdout.write(`${color(enabled, "33", "No recognized slices.")}\n`);
    return;
  }
  process.stdout.write(`\n${color(enabled, "1", "Slices")}\n`);
  for (const slice of result.slices) {
    process.stdout.write(
      `  ${color(enabled, "36", slice.architecture)}  ${slice.bits}-bit ${slice.endian}  ${slice.file_type}\n`,
    );
    process.stdout.write(
      `    ${slice.sections} sections · ${slice.imports} imports · ${slice.exports} exports · ${slice.libraries} libraries\n`,
    );
    if (slice.mitigations.length > 0 || slice.undetermined_mitigations.length > 0)
      process.stdout.write(
        `    ${color(enabled, "32", slice.mitigations.join(", ") || "none observed")}` +
          (slice.undetermined_mitigations.length > 0
            ? ` ${color(enabled, "2", `· undetermined: ${slice.undetermined_mitigations.join(", ")}`)}`
            : "") +
          "\n",
      );
  }
};

const inspectHuman = (
  result: Awaited<ReturnType<typeof inspect>>["result"],
  enabled: boolean,
): void => {
  simpleHeader("inspect", enabled);
  process.stdout.write(`${color(enabled, "2", "path")}     ${result.path}\n`);
  process.stdout.write(`${color(enabled, "2", "sha256")}   ${result.sha256}\n`);
  process.stdout.write(`${color(enabled, "2", "format")}   ${result.format}\n`);
  for (const slice of result.slices) {
    process.stdout.write(
      `\n${color(enabled, "1", "Slice")} ${color(enabled, "36", slice.architecture)}  ${slice.bits}-bit ${slice.endian}  ${slice.fileType}\n`,
    );
    if (slice.entrypoint !== null)
      process.stdout.write(
        `  entrypoint ${slice.entrypoint} (${slice.entrypointKind ?? "unknown"})\n`,
      );
    if (slice.buildId !== null) process.stdout.write(`  build      ${slice.buildId}\n`);
    process.stdout.write(
      `  security   ${slice.security.present.join(", ") || "none observed"}\n`,
    );
    if (slice.security.absent.length > 0)
      process.stdout.write(`  disabled   ${slice.security.absent.join(", ")}\n`);
    if (slice.security.undetermined.length > 0)
      process.stdout.write(`  unclear    ${slice.security.undetermined.join(", ")}\n`);
    const facts = Object.entries(slice.provenance);
    if (facts.length > 0) {
      process.stdout.write(`  provenance\n`);
      for (const [key, value] of facts)
        process.stdout.write(`    ${key.padEnd(17)} ${value}\n`);
    }
    process.stdout.write(`  sections   ${slice.sections.length}\n`);
    for (const section of slice.sections.slice(0, 12))
      process.stdout.write(
        `    ${section.name.padEnd(24)} ${section.size.toString().padStart(8)} bytes  ${section.sha256?.slice(0, 12) ?? "-"}\n`,
      );
    if (slice.sections.length > 12)
      process.stdout.write(`    … ${slice.sections.length - 12} more (use --json)\n`);
    process.stdout.write(`  imports    ${slice.imports.length}\n`);
    for (const item of slice.imports.slice(0, 8)) process.stdout.write(`    ${item}\n`);
    if (slice.imports.length > 8)
      process.stdout.write(`    … ${slice.imports.length - 8} more (use --json)\n`);
    process.stdout.write(`  exports    ${slice.exports.length}\n`);
    process.stdout.write(`  libraries  ${slice.libraries.length}\n`);
  }
  if (result.limitations.length > 0) {
    process.stdout.write(`\n${color(enabled, "33", "Limitations")}\n`);
    for (const limitation of result.limitations)
      process.stdout.write(`  - ${limitation}\n`);
  }
};

const bytesHuman = (value: number): string => {
  if (value < 1024) return `${value} B`;
  if (value < 1024 ** 2) return `${(value / 1024).toFixed(1)} KiB`;
  if (value < 1024 ** 3) return `${(value / 1024 ** 2).toFixed(1)} MiB`;
  return `${(value / 1024 ** 3).toFixed(2)} GiB`;
};

const appHuman = (inventory: AppInventory, enabled: boolean): void => {
  simpleHeader(`app · ${inventory.kind}`, enabled);
  process.stdout.write(`${color(enabled, "2", "path")}       ${inventory.path}\n`);
  process.stdout.write(`${color(enabled, "2", "layout")}     ${inventory.layout}\n`);
  process.stdout.write(
    `${color(enabled, "2", "members")}    ${inventory.counts.files.toLocaleString("en-US")} files · ${inventory.counts.directories.toLocaleString("en-US")} dirs · ${inventory.counts.links} links · ${bytesHuman(inventory.total_bytes)}\n`,
  );
  process.stdout.write(
    `${color(enabled, "2", "tree")}       ${inventory.tree_sha256}\n`,
  );
  const kinds = Object.entries(inventory.counts.by_kind);
  if (kinds.length > 0)
    process.stdout.write(
      `${color(enabled, "2", "kinds")}      ${kinds.map(([kind, count]) => `${kind} ${count}`).join(" · ")}\n`,
    );
  const architectures = Object.entries(inventory.counts.architectures);
  if (architectures.length > 0)
    process.stdout.write(
      `${color(enabled, "2", "architectures")} ${architectures.map(([name, count]) => `${name} ${count}`).join(" · ")}\n`,
    );

  if (inventory.manifest === null) {
    process.stdout.write(`\n${color(enabled, "33", "No bundle manifest was found.")}\n`);
  } else {
    const manifest = inventory.manifest;
    process.stdout.write(
      `\n${color(enabled, "1", "Manifest")} ${color(enabled, "2", `${manifest.path} · ${manifest.encoding ?? "unparsed"} · ${manifest.keys} keys`)}`,
    );
    process.stdout.write("\n");
    if (manifest.sha256 !== null)
      process.stdout.write(`  sha256     ${manifest.sha256}\n`);
    const claims = Object.entries(manifest.claims).slice(0, 14);
    for (const [key, value] of claims)
      process.stdout.write(`  ${key.padEnd(29)} ${value}\n`);
    if (Object.keys(manifest.claims).length > claims.length)
      process.stdout.write(
        `  … ${Object.keys(manifest.claims).length - claims.length} more claims (use --json)\n`,
      );
    const pkgInfo = Object.entries(inventory.pkg_info);
    if (pkgInfo.length > 0)
      process.stdout.write(
        `  PkgInfo                      ${pkgInfo.map(([key, value]) => `${key}=${value}`).join(" ")}\n`,
      );
  }

  const declared = inventory.declared_executable;
  if (declared.name !== null)
    process.stdout.write(
      `\n${color(enabled, "1", "Declared executable")} ${color(
        enabled,
        declared.present ? "32" : "33",
        declared.present ? `${declared.path} present` : `${declared.name} not found`,
      )}\n`,
    );

  const code = summarizePackage(inventory).code;
  if (code.length > 0) {
    process.stdout.write(
      `\n${color(enabled, "1", "Largest code members")} ${color(enabled, "2", `${inventory.counts.by_format["mach-o"] ?? 0} mach-o · ${inventory.counts.by_format["wasm"] ?? 0} wasm · ${inventory.counts.by_format["elf"] ?? 0} elf · ${inventory.counts.by_format["pe"] ?? 0} pe`)}\n`,
    );
    for (const file of code.slice(0, 10))
      process.stdout.write(
        `  ${file.path.padEnd(58)} ${bytesHuman(file.size).padStart(9)}  ${[file.format, file.architectures.join("/")].filter((part) => part.length > 0 && part !== "unknown").join(" ")}\n`,
      );
    if (code.length > 10)
      process.stdout.write(`  … ${code.length - 10} more (use --json)\n`);
  }

  if (inventory.nested.length > 0) {
    process.stdout.write(
      `\n${color(enabled, "1", "Nested packages")} ${color(enabled, "2", String(inventory.nested.length))}\n`,
    );
    for (const nested of inventory.nested.slice(0, 8))
      process.stdout.write(
        `  ${nested.path}\n    ${nested.kind}  ${nested.declared.CFBundleIdentifier ?? "no declared identifier"}\n`,
      );
    if (inventory.nested.length > 8)
      process.stdout.write(
        `  … ${inventory.nested.length - 8} more (use --json)\n`,
      );
  }

  if (inventory.limitations.length > 0) {
    process.stdout.write(`\n${color(enabled, "33", "Limitations")}\n`);
    for (const limitation of inventory.limitations)
      process.stdout.write(`  - ${limitation}\n`);
  }
};

const diffHuman = (result: ComparisonResult, enabled: boolean): void => {
  simpleHeader("diff", enabled);
  process.stdout.write(`${color(enabled, "2", "left")}   ${result.left.path}\n`);
  process.stdout.write(`${color(enabled, "2", "right")}  ${result.right.path}\n`);
  process.stdout.write(
    `${color(enabled, result.changed ? "33" : "32", result.changed ? "changed" : "identical")}\n`,
  );
  const groups: Array<[string, readonly string[]]> = [
    ["slices added", result.changes.slices_added],
    ["slices removed", result.changes.slices_removed],
    ["sections added", result.changes.sections_added],
    ["sections removed", result.changes.sections_removed],
    ["sections changed", result.changes.sections_changed],
    ["imports added", result.changes.imports_added],
    ["imports removed", result.changes.imports_removed],
    ["exports added", result.changes.exports_added],
    ["exports removed", result.changes.exports_removed],
    ["mitigations added", result.changes.mitigations_added],
    ["mitigations removed", result.changes.mitigations_removed],
    ["provenance changed", result.changes.provenance_changed],
  ];
  for (const [label, values] of groups) {
    if (values.length === 0) continue;
    process.stdout.write(`\n${color(enabled, "1", label)} (${values.length})\n`);
    for (const value of values.slice(0, 12)) process.stdout.write(`  ${value}\n`);
    if (values.length > 12)
      process.stdout.write(`  … ${values.length - 12} more (use --json)\n`);
  }
  if (result.limitations.length > 0) {
    process.stdout.write(`\n${color(enabled, "33", "Limitations")}\n`);
    for (const limitation of result.limitations)
      process.stdout.write(`  - ${limitation}\n`);
  }
};

const main = async (): Promise<number> => {
  const parsed = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      store: { type: "string" },
      arch: { type: "string" },
      out: { type: "string" },
      "no-save": { type: "boolean", default: false },
      debug: { type: "boolean", default: false },
      help: { type: "boolean", short: "h", default: false },
      version: { type: "boolean", short: "v", default: false },
    },
  });
  const [command, ...args] = parsed.positionals;
  if (parsed.values.help || command === "help" || command === undefined) {
    process.stdout.write(HELP);
    return 0;
  }
  if (parsed.values.version || command === "version") {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const store =
    parsed.values["no-save"] === true
      ? undefined
      : new EvidenceStore(parsed.values.store);
  const useColor = ttyColor();

  if (command === "scan" || command === "inspect") {
    const path = args[0];
    if (path === undefined) throw new TraceForgeError("invalid_input", `${command} needs a path`);
    if (command === "scan") {
      const outcome = await scanBinary(path, store, VERSION);
      if (parsed.values.json) print(outcome.record, true);
      else {
        scanHuman(outcome.result, useColor);
        evidenceLine(outcome.record, useColor);
      }
    } else {
      const outcome = await inspect(path, store, VERSION, parsed.values.arch);
      if (parsed.values.json) print(outcome.record, true);
      else {
        inspectHuman(outcome.result, useColor);
        evidenceLine(outcome.record, useColor);
      }
    }
    return 0;
  }
  if (command === "app") {
    const path = args[0];
    if (path === undefined)
      throw new TraceForgeError("invalid_input", "app needs a package directory");
    const outcome = await scanPackage(path, store, VERSION);
    if (parsed.values.json) print(outcome.record, true);
    else {
      appHuman(outcome.inventory, useColor);
      evidenceLine(outcome.record, useColor);
    }
    return 0;
  }
  if (command === "report") {
    const subject = args[0];
    if (subject === undefined)
      throw new TraceForgeError("invalid_input", "report needs a path or evidence ID");
    const reportStore = new EvidenceStore(parsed.values.store);
    let record: EvidenceRecord;
    if (subject.startsWith("ev_")) record = await reportStore.get(subject);
    else {
      const info = await stat(subject).catch(() => null);
      record =
        info !== null && info.isDirectory()
          ? (await scanPackage(subject, store, VERSION)).record
          : (await inspect(subject, store, VERSION)).record;
    }
    const out = await writeEvidenceReport(
      record,
      parsed.values.out ?? "traceforge-report.html",
    );
    if (parsed.values.json) print({ path: out, evidence_id: record.evidence_id }, true);
    else
      process.stdout.write(
        `${color(useColor, "1;36", "TraceForge")} report → ${out}\n${color(useColor, "2", "Evidence")} ${record.evidence_id}\n`,
      );
    return 0;
  }
  if (command === "diff") {
    const [left, right] = args;
    if (left === undefined || right === undefined)
      throw new TraceForgeError("invalid_input", "diff needs left and right paths");
    const outcome = await compare(left, right, store, VERSION);
    if (parsed.values.json) print(outcome.record, true);
    else {
      diffHuman(outcome.result, useColor);
      evidenceLine(outcome.record, useColor);
    }
    return 0;
  }
  if (command === "evidence") {
    const subcommand = args[0];
    const evidenceStore = new EvidenceStore(parsed.values.store);
    if (subcommand === "verify-all") {
      const verified = await evidenceStore.verifyAll();
      if (parsed.values.json) print(verified, true);
      else
        process.stdout.write(
          `${verified.valid} valid · ${verified.invalid.length} invalid\n` +
            verified.invalid.map((id) => `  ${id}\n`).join(""),
        );
      return verified.invalid.length === 0 ? 0 : 1;
    }
    if (subcommand === "export" || subcommand === "import") {
      const path = args[1];
      if (path === undefined)
        throw new TraceForgeError("invalid_input", `evidence ${subcommand} needs a path`);
      const outcome =
        subcommand === "export"
          ? await evidenceStore.exportBundle(path)
          : await evidenceStore.importBundle(path);
      if (parsed.values.json) print(outcome, true);
      else process.stdout.write(`${JSON.stringify(outcome)}\n`);
      return 0;
    }
    if (subcommand === "list") {
      const summaries = await evidenceStore.list();
      if (parsed.values.json) print(summaries, true);
      else {
        simpleHeader("evidence", useColor);
        if (summaries.length === 0) process.stdout.write("No evidence records.\n");
        for (const summary of summaries)
          process.stdout.write(
            `${summary.evidence_id}  ${summary.operation.padEnd(8)}  ${summary.path}\n`,
          );
      }
      return 0;
    }
    const id = args[1];
    if (id === undefined)
      throw new TraceForgeError("invalid_input", "evidence needs show or verify and an ID");
    if (subcommand === "show") {
      print(await evidenceStore.get(id), true);
      return 0;
    }
    if (subcommand === "verify") {
      const valid = await evidenceStore.verify(id);
      process.stdout.write(valid ? "valid\n" : "invalid or missing\n");
      return valid ? 0 : 1;
    }
    throw new TraceForgeError("invalid_input", "Unknown evidence subcommand");
  }
  if (command === "mcp") {
    await runMcpServer({ store: new EvidenceStore(parsed.values.store), version: VERSION });
    return 0;
  }
  throw new TraceForgeError("invalid_input", `Unknown command: ${command}`);
};

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error: unknown) => {
    const debug = process.argv.includes("--debug");
    if (error instanceof TraceForgeError) {
      process.stderr.write(`error [${error.code}]: ${error.message}\n`);
      if (debug) process.stderr.write(`${error.stack ?? ""}\n`);
      process.exitCode = 1;
      return;
    }
    process.stderr.write(`error [internal]: ${error instanceof Error ? error.message : String(error)}\n`);
    if (debug) process.stderr.write(`${error instanceof Error ? error.stack ?? "" : ""}\n`);
    process.exitCode = 2;
  });
