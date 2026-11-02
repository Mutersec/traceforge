#!/usr/bin/env node
import { readFile, stat } from "node:fs/promises";
import { parseArgs } from "node:util";
import { resolve } from "node:path";

import { summarizePackage } from "./core/app.js";
import { compare, inspect, scanBinary, scanPackage } from "./core/operations.js";
import { EvidenceStore } from "./core/evidence.js";
import {
  INSPECT_FIELDS,
  MAX_PAGE_ITEMS,
  PACKAGE_FIELDS,
  omittedFields,
  pageBinaryLists,
  pageNamedList,
  pageOffset,
  parseOnly,
  selectInspectFields,
  selectPackageFields,
  validatedLimit,
} from "./core/paging.js";
import type { PageRequest } from "./core/paging.js";
import { writeEvidenceReport } from "./core/report.js";
import type { EvidenceSignatureReport } from "./core/report.js";
import {
  SignatureStore,
  generateSigningKeyPair,
  readSignatureFields,
  signEvidenceRecord,
} from "./core/signature.js";
import type { SignatureVerifyOptions } from "./core/signature.js";
import { TraceForgeError } from "./core/errors.js";
import type { AppInventory, ComparisonResult, EvidenceRecord } from "./core/types.js";
import { runMcpServer } from "./mcp/server.js";

export const VERSION = "0.2.0";

const HELP = `TraceForge ${VERSION} — local-first binary evidence.

Usage:
  tforge scan <path> [--json] [--store <dir>] [--no-save]
  tforge inspect <path> [--arch <name>] [--only <fields>] [--limit <n>] [--cursor <offset>] [--json] [--store <dir>] [--no-save]
  tforge app <package> [--only <fields>] [--limit <n>] [--cursor <offset>] [--json] [--store <dir>] [--no-save]
  tforge diff <left> <right> [--json] [--store <dir>] [--no-save]
  tforge evidence list
  tforge evidence show <evidence_id>
  tforge evidence verify <evidence_id> [--public-key <path>] [--signature <path>]
  tforge evidence verify-all
  tforge evidence keygen [--name <label>]
  tforge evidence sign <evidence_id> [--private-key <path>]
  tforge evidence export <bundle.json>
  tforge evidence import <bundle.json>
  tforge report <path|package|evidence_id> [--out <file>] [--signature <path>] [--public-key <path>]
  tforge mcp
  tforge version

Packages:
  tforge app walks an .app, .framework or directory recursively: one member
  per file with size, SHA-256 and format, plus the identity the bundle
  manifest declares. The walk stops at 5,000 members or depth 32 and records
  that as a limitation instead of failing. Nothing is executed, and symbolic
  links are recorded but never followed.

Agent ergonomics:
  --only <fields>   Keep only these fields. inspect accepts sections,
                    imports, exports, libraries, provenance, security;
                    app accepts files, manifest, nested, limitations.
                    Dropped fields are named in the omitted list of --json.
  --limit <n>       Page size for long lists in --json answers (1-500).
  --cursor <n>      Offset cursor from a previous next_cursor.
  Paging and --only shape one answer; the stored Evidence record always
  stays complete.

Evidence:
  Every scan, inspect, app and diff writes a deterministic content-addressed
  record to .traceforge/evidence unless --no-save is used.

Signing:
  tforge evidence keygen writes an Ed25519 key pair to .traceforge/keys.
  tforge evidence sign writes a detached signature sidecar per record to
  .traceforge/signatures. verify checks that the record bytes have not
  changed since that key signed them. A signature proves who signed and
  that the content is unchanged — never where a file came from, and never
  when it was signed. Keys and signatures live under .traceforge/, which
  git ignores.

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

const cliPageRequest = (
  limit: string | undefined,
  cursor: string | undefined,
): PageRequest | null => {
  if (limit === undefined && cursor === undefined) return null;
  const request: { cursor?: string; limit?: number } = {};
  if (cursor !== undefined) request.cursor = cursor;
  if (limit !== undefined) {
    if (!/^\d+$/u.test(limit.trim()))
      throw new TraceForgeError(
        "invalid_input",
        `--limit must be an integer between 1 and ${MAX_PAGE_ITEMS}, got "${limit}"`,
      );
    request.limit = Number(limit);
  }
  const page = request as PageRequest;
  validatedLimit(page);
  pageOffset(page);
  return page;
};

const inspectHuman = (
  result: Awaited<ReturnType<typeof inspect>>["result"],
  enabled: boolean,
  omitted: readonly string[] = [],
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
    if (!omitted.includes("security")) {
      process.stdout.write(
        `  security   ${slice.security.present.join(", ") || "none observed"}\n`,
      );
      if (slice.security.absent.length > 0)
        process.stdout.write(`  disabled   ${slice.security.absent.join(", ")}\n`);
      if (slice.security.undetermined.length > 0)
        process.stdout.write(`  unclear    ${slice.security.undetermined.join(", ")}\n`);
    }
    const facts = Object.entries(slice.provenance);
    if (!omitted.includes("provenance") && facts.length > 0) {
      process.stdout.write(`  provenance\n`);
      for (const [key, value] of facts)
        process.stdout.write(`    ${key.padEnd(17)} ${value}\n`);
    }
    if (!omitted.includes("sections")) {
      process.stdout.write(`  sections   ${slice.sections.length}\n`);
      for (const section of slice.sections.slice(0, 12))
        process.stdout.write(
          `    ${section.name.padEnd(24)} ${section.size.toString().padStart(8)} bytes  ${section.sha256?.slice(0, 12) ?? "-"}\n`,
        );
      if (slice.sections.length > 12)
        process.stdout.write(`    … ${slice.sections.length - 12} more (use --json)\n`);
    }
    if (!omitted.includes("imports")) {
      process.stdout.write(`  imports    ${slice.imports.length}\n`);
      for (const item of slice.imports.slice(0, 8)) process.stdout.write(`    ${item}\n`);
      if (slice.imports.length > 8)
        process.stdout.write(`    … ${slice.imports.length - 8} more (use --json)\n`);
    }
    if (!omitted.includes("exports"))
      process.stdout.write(`  exports    ${slice.exports.length}\n`);
    if (!omitted.includes("libraries"))
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

const appHuman = (
  inventory: AppInventory,
  enabled: boolean,
  omitted: readonly string[] = [],
): void => {
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

  if (omitted.includes("manifest")) {
    // --only dropped the manifest view; the member and tree identity lines above still stand.
  } else if (inventory.manifest === null) {
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
  if (!omitted.includes("manifest") && declared.name !== null)
    process.stdout.write(
      `\n${color(enabled, "1", "Declared executable")} ${color(
        enabled,
        declared.present ? "32" : "33",
        declared.present ? `${declared.path} present` : `${declared.name} not found`,
      )}\n`,
    );

  const code = summarizePackage(inventory).code;
  if (!omitted.includes("files") && code.length > 0) {
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

  if (!omitted.includes("nested") && inventory.nested.length > 0) {
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

  if (!omitted.includes("limitations") && inventory.limitations.length > 0) {
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

const readKeyFile = async (path: string, kind: "private" | "public"): Promise<string> => {
  try {
    return await readFile(resolve(path), "utf8");
  } catch (cause) {
    throw new TraceForgeError(
      "invalid_input",
      `Cannot read the ${kind} key file ${path}. Run \`tforge evidence keygen\` or pass an existing ${kind} key.`,
      { cause },
    );
  }
};

const signatureReportFor = async (
  store: EvidenceStore,
  record: EvidenceRecord,
  signaturePath: string | undefined,
  publicKeyPath: string | undefined,
): Promise<EvidenceSignatureReport | undefined> => {
  if (signaturePath === undefined && publicKeyPath === undefined) return undefined;
  const signatures = new SignatureStore(store);
  const options: SignatureVerifyOptions = {};
  if (signaturePath !== undefined) options.path = resolve(signaturePath);
  if (publicKeyPath !== undefined)
    options.publicKeyPem = await readKeyFile(publicKeyPath, "public");
  const sidecarPath = options.path ?? signatures.pathFor(record.evidence_id);
  try {
    const result = await signatures.verify(record.evidence_id, options);
    return {
      status: "verified",
      message: result.external_key
        ? "Verified against the public key supplied on the command line."
        : "Verified against the public key embedded in the signature file.",
      algorithm: result.signature.algorithm,
      key_fingerprint: result.fingerprint,
      record_sha256: result.signature.record_sha256,
      self_reported: !result.external_key,
    };
  } catch (error) {
    const fields = await readSignatureFields(sidecarPath);
    return {
      status: "failed",
      message:
        error instanceof TraceForgeError
          ? error.message
          : "The signature could not be checked.",
      algorithm: fields === null || fields.algorithm === null ? "—" : fields.algorithm,
      key_fingerprint:
        fields === null || fields.key_fingerprint === null ? "—" : fields.key_fingerprint,
      record_sha256:
        fields === null || fields.record_sha256 === null ? "—" : fields.record_sha256,
      self_reported: publicKeyPath === undefined,
    };
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
      only: { type: "string" },
      limit: { type: "string" },
      cursor: { type: "string" },
      "private-key": { type: "string" },
      "public-key": { type: "string" },
      signature: { type: "string" },
      name: { type: "string" },
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
      const keep =
        parsed.values.only === undefined
          ? null
          : parseOnly(parsed.values.only, INSPECT_FIELDS);
      const request = cliPageRequest(parsed.values.limit, parsed.values.cursor);
      const outcome = await inspect(path, store, VERSION, parsed.values.arch);
      if (parsed.values.json) {
        if (keep === null && request === null) print(outcome.record, true);
        else {
          const selection = keep === null ? null : selectInspectFields(outcome.result, keep);
          let value: object = selection === null ? outcome.result : selection.value;
          const paged = request === null ? null : pageBinaryLists(value, request);
          if (paged !== null) value = paged.value;
          print(
            {
              evidence_id: outcome.record.evidence_id,
              detail: "complete",
              ...(paged === null ? {} : { page: paged.page }),
              inventory: value,
              ...(selection === null ? {} : { omitted: selection.omitted }),
            },
            true,
          );
        }
      } else {
        inspectHuman(outcome.result, useColor, omittedFields(keep, INSPECT_FIELDS));
        evidenceLine(outcome.record, useColor);
      }
    }
    return 0;
  }
  if (command === "app") {
    const path = args[0];
    if (path === undefined)
      throw new TraceForgeError("invalid_input", "app needs a package directory");
    const keep =
      parsed.values.only === undefined
        ? null
        : parseOnly(parsed.values.only, PACKAGE_FIELDS);
    const request = cliPageRequest(parsed.values.limit, parsed.values.cursor);
    const outcome = await scanPackage(path, store, VERSION);
    if (parsed.values.json) {
      if (keep === null && request === null) print(outcome.record, true);
      else {
        const selection = keep === null ? null : selectPackageFields(outcome.inventory, keep);
        let value: object = selection === null ? outcome.inventory : selection.value;
        const paged = request === null ? null : pageNamedList(value, "files", request);
        if (paged !== null) value = paged.value;
        print(
          {
            evidence_id: outcome.record.evidence_id,
            detail: "complete",
            ...(paged === null ? {} : { page: paged.page }),
            inventory: value,
            ...(selection === null ? {} : { omitted: selection.omitted }),
          },
          true,
        );
      }
    } else {
      appHuman(outcome.inventory, useColor, omittedFields(keep, PACKAGE_FIELDS));
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
    const signatureReport = await signatureReportFor(
      reportStore,
      record,
      parsed.values.signature,
      parsed.values["public-key"],
    );
    const out = await writeEvidenceReport(
      record,
      parsed.values.out ?? "traceforge-report.html",
      signatureReport,
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
    const signatures = new SignatureStore(evidenceStore);
    if (subcommand === "keygen") {
      const pair = generateSigningKeyPair();
      const paths = await signatures.putKeyPair(pair, parsed.values.name);
      if (parsed.values.json)
        print(
          {
            fingerprint: pair.fingerprint,
            algorithm: "ed25519",
            private_key: paths.private_path,
            public_key: paths.public_path,
          },
          true,
        );
      else {
        simpleHeader("Ed25519 key", useColor);
        process.stdout.write(`${color(useColor, "2", "fingerprint")} ${pair.fingerprint}\n`);
        process.stdout.write(`${color(useColor, "2", "private key")} ${paths.private_path}\n`);
        process.stdout.write(`${color(useColor, "2", "public key")}  ${paths.public_path}\n`);
        process.stdout.write(
          `\n${color(useColor, "33", "Keep the private key offline.")} Anyone who holds it can sign records as you; share only the public key.\n`,
        );
      }
      return 0;
    }
    if (subcommand === "sign") {
      const signId = args[1];
      if (signId === undefined)
        throw new TraceForgeError("invalid_input", "evidence sign needs an Evidence ID");
      const record = await evidenceStore.get(signId);
      const privateKeyPath =
        parsed.values["private-key"] ?? (await signatures.defaultPrivateKeyPath());
      const privateKeyPem = await readKeyFile(privateKeyPath, "private");
      const signature = signEvidenceRecord(record, privateKeyPem, VERSION);
      const sidecar = await signatures.put(signature);
      if (parsed.values.json) print(signature, true);
      else {
        process.stdout.write(`${color(useColor, "2", "evidence")}  ${signature.evidence_id}\n`);
        process.stdout.write(`${color(useColor, "2", "key")}       ${signature.key_fingerprint}\n`);
        process.stdout.write(`${color(useColor, "2", "signature")} ${sidecar}\n`);
      }
      return 0;
    }
    if (subcommand === "verify-all") {
      const verified = await evidenceStore.verifyAll();
      const records = await evidenceStore.list();
      let signed = 0;
      const signatureErrors: { evidence_id: string; error: string }[] = [];
      for (const summary of records) {
        try {
          await signatures.verify(summary.evidence_id);
          signed += 1;
        } catch (error) {
          if (error instanceof TraceForgeError && error.code === "signature_not_found")
            continue;
          signatureErrors.push({
            evidence_id: summary.evidence_id,
            error: error instanceof TraceForgeError ? error.message : "The signature could not be checked.",
          });
        }
      }
      const unsigned = records.length - signed;
      if (parsed.values.json)
        print(
          {
            valid: verified.valid,
            invalid: verified.invalid,
            signed,
            unsigned,
            signature_errors: signatureErrors,
          },
          true,
        );
      else
        process.stdout.write(
          `${verified.valid} valid · ${verified.invalid.length} invalid\n` +
            verified.invalid.map((id) => `  ${id}\n`).join("") +
            `${signed} signed · ${unsigned} unsigned\n` +
            signatureErrors.map((item) => `  ${item.evidence_id} ${item.error}\n`).join(""),
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
      const publicKeyPath = parsed.values["public-key"];
      const signaturePath = parsed.values.signature;
      if (publicKeyPath === undefined && signaturePath === undefined) {
        const valid = await evidenceStore.verify(id);
        process.stdout.write(valid ? "valid\n" : "invalid or missing\n");
        return valid ? 0 : 1;
      }
      const options: SignatureVerifyOptions = {};
      if (signaturePath !== undefined) options.path = resolve(signaturePath);
      if (publicKeyPath !== undefined)
        options.publicKeyPem = await readKeyFile(publicKeyPath, "public");
      const result = await signatures.verify(id, options);
      if (parsed.values.json)
        print(
          {
            evidence_id: id,
            verified: true,
            key_fingerprint: result.fingerprint,
            record_sha256: result.signature.record_sha256,
            self_reported: !result.external_key,
          },
          true,
        );
      else {
        process.stdout.write(`signed · verified by ${result.fingerprint}\n`);
        if (!result.external_key)
          process.stdout.write(
            `${color(useColor, "33", "self-reported key")} · the public key was read from the signature file itself, so this is not third-party confirmation; pass --public-key to check against a key you hold.\n`,
          );
      }
      return 0;
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
