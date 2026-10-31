#!/usr/bin/env node
import { parseArgs } from "node:util";

import { compare, inspect, scanBinary } from "./core/operations.js";
import { EvidenceStore } from "./core/evidence.js";
import { TraceForgeError } from "./core/errors.js";
import type { ComparisonResult, EvidenceRecord } from "./core/types.js";
import { runMcpServer } from "./mcp/server.js";

export const VERSION = "0.1.0";

const HELP = `TraceForge ${VERSION} — local-first binary evidence.

Usage:
  tforge scan <path> [--json] [--store <dir>] [--no-save]
  tforge inspect <path> [--json] [--store <dir>] [--no-save]
  tforge diff <left> <right> [--json] [--store <dir>] [--no-save]
  tforge evidence list
  tforge evidence show <evidence_id>
  tforge evidence verify <evidence_id>
  tforge mcp
  tforge version

Evidence:
  Every scan, inspect and diff writes a deterministic content-addressed
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
      const outcome = await inspect(path, store, VERSION);
      if (parsed.values.json) print(outcome.record, true);
      else {
        inspectHuman(outcome.result, useColor);
        evidenceLine(outcome.record, useColor);
      }
    }
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
