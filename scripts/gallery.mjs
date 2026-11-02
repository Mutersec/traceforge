#!/usr/bin/env node
// Reproducible regeneration of the TraceForge evidence gallery.
//
// The gallery is a set of standalone HTML Evidence reports produced by the real
// CLI (`node dist/cli.js report <package>`) against applications installed on
// this machine. Nothing here renders HTML: the script calls the CLI, measures
// what came back, and enforces the size and safety budget.
//
//   node scripts/gallery.mjs                  # regenerate every target
//   node scripts/gallery.mjs --only obsidian  # one target (comma list ok)
//   node scripts/gallery.mjs --check          # temp dir only, compare bytes, write nothing
//   node scripts/gallery.mjs --audit f.html   # audit any HTML for executable/remote markup
//
// Budget (fixed for the gallery):
//   * one report     <= 700 KiB  (716800 bytes)
//   * gallery total  <= 2 MiB    (2097152 bytes, each report counted once)
// If a report would break the per-report cap its HTML is NOT published: the
// script removes it, keeps the plain-text `tforge app <package> --no-save`
// transcript for that target instead, and says so in the summary.
//
// Outputs are mirrored to examples/gallery (canonical) and site/gallery, because
// the pages workflow publishes only site/** and the links must resolve there.
// Both copies are byte-identical and written 0644 (the CLI writes 0600).
//
// The script makes no network request, executes no target, and writes only under
// examples/, site/ and .cache/. Exit codes: 0 ok · 1 cap/audit violation or
// drift under --check · 2 usage or environment problem.

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const repo = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(repo, "dist", "cli.js");

const REPORT_CAP_BYTES = 700 * 1024;
const TOTAL_CAP_BYTES = 2 * 1024 * 1024;
const CANONICAL_DIR = "examples/gallery";
const MIRROR_DIRS = ["examples/gallery", "site/gallery"];

// Every target is a real application on this machine and proves one specific
// capability. The Riot path is a symlinked bundle root with a non-ASCII name on
// purpose; that is part of what its report demonstrates.
const TARGETS = [
  {
    slug: "airstats",
    path: "/Applications/AirStats.app",
    proves: "nested packages: Sparkle.framework, an inner Updater.app, two .xpc services",
  },
  {
    slug: "obsidian",
    path: "/Applications/Obsidian.app",
    proves: "a large real payload (378.9 MiB member) and the archive limitation",
  },
  {
    slug: "qoder",
    path: "/Applications/Qoder.app",
    proves: "the 5,000 member walk cap firing on a real package, written as a limitation",
  },
  {
    slug: "riot-client",
    path: "/Applications/Riot İstemcisi.app",
    proves: "a symlinked bundle root resolved, and a non-ASCII path carried through",
  },
];

const USAGE = [
  "usage: node scripts/gallery.mjs [--check] [--strict] [--only <slug>[,<slug>]]",
  "                                [--report-cap <bytes>] [--total-cap <bytes>]",
  "       node scripts/gallery.mjs --audit <file.html> [...]",
  "",
  "Regenerates the evidence gallery with `node dist/cli.js report <package>`.",
  "Caps: one report <= 700 KiB, gallery total <= 2 MiB. A report over its cap",
  "is replaced by the text output of `tforge app <package> --no-save`.",
  "Mirrors examples/gallery and site/gallery byte for byte.",
  "Exits 0 clean · 1 cap/audit violation or --check drift · 2 usage or environment.",
].join("\n");

const fail = (code, message) => {
  process.stderr.write(`${message}\n`);
  process.exit(code);
};

const sizeLabel = (value) => `${value.toLocaleString("en-US")} B`;

const positiveInt = (raw, flag) => {
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) fail(2, `gallery: ${flag} needs a positive integer`);
  return value;
};

const parseFlags = (argv) => {
  const options = {
    check: false,
    strict: false,
    audit: [],
    only: [],
    reportCap: REPORT_CAP_BYTES,
    totalCap: TOTAL_CAP_BYTES,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === "-h" || flag === "--help") {
      process.stdout.write(`${USAGE}\n`);
      process.exit(0);
    } else if (flag === "--check") options.check = true;
    else if (flag === "--strict") options.strict = true;
    else if (flag === "--audit") {
      while (index + 1 < argv.length && !argv[index + 1].startsWith("--"))
        options.audit.push(argv[++index]);
      if (options.audit.length === 0) fail(2, "gallery: --audit needs at least one file");
    } else if (flag === "--only") {
      const value = argv[++index];
      if (value === undefined) fail(2, "gallery: --only needs a slug");
      options.only.push(...value.split(",").map((part) => part.trim()).filter(Boolean));
    } else if (flag === "--report-cap")
      options.reportCap = positiveInt(argv[++index], "--report-cap");
    else if (flag === "--total-cap")
      options.totalCap = positiveInt(argv[++index], "--total-cap");
    else fail(2, `gallery: unknown argument "${flag}"\n\n${USAGE}`);
  }
  return options;
};

// A report is only safe to hand to a browser when it carries no executable or
// remote markup. Every byte that comes from the inspected target is escaped by
// the renderer, so a literal "<" can only belong to a tag the renderer itself
// wrote — which makes the tag and attribute names a sound check.
// Scope: this audits generated reports. A landing page legitimately links out
// with <a href>, so do not run --audit against site/index.html.
const ALLOWED_TAGS = new Set([
  "a", "article", "aside", "b", "body", "br", "code", "div", "em", "figcaption",
  "footer", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header", "html", "i",
  "li", "main", "meta", "nav", "ol", "p", "path", "pre", "rect", "s", "section",
  "small", "span", "strong", "style", "svg", "table", "tbody", "td", "tfoot",
  "th", "thead", "title", "tr", "ul", "wbr",
]);
const REMOTE_ATTRS = ["src", "srcset", "href", "xlink:href", "data", "poster", "background"];

const auditHtml = (name, html) => {
  const findings = [];
  for (const match of html.matchAll(/<\s*([a-zA-Z][a-zA-Z0-9]*)\b([^>]*)>/g)) {
    const tag = match[1].toLowerCase();
    const attrs = match[2] ?? "";
    if (!ALLOWED_TAGS.has(tag)) findings.push(`${name}: disallowed tag <${tag}>`);
    for (const attr of REMOTE_ATTRS)
      if (new RegExp(`(^|\\s)${attr}\\s*=`, "iu").test(attrs))
        findings.push(`${name}: <${tag}> carries remote attribute "${attr}="`);
    if (/\son[a-z]+\s*=/iu.test(attrs)) findings.push(`${name}: <${tag}> carries an event handler`);
  }
  for (const needle of ["@import", "javascript:"])
    if (html.toLowerCase().includes(needle)) findings.push(`${name}: contains "${needle}"`);
  return findings;
};

const evidenceIdOf = (stdout) => {
  const match = /Evidence\s+(ev_[0-9a-f]{64})/u.exec(stdout);
  return match === null ? null : match[1];
};

const cliEnv = { ...process.env, NO_COLOR: "1" };

const runCli = async (args) =>
  run(process.execPath, [cli, ...args], {
    cwd: repo,
    env: cliEnv,
    maxBuffer: 64 * 1024 * 1024,
  });

const isInstalled = async (path) => {
  try {
    await stat(path);
    return true;
  } catch {
    return false;
  }
};

const captureText = async (path, out) => {
  const { stdout } = await runCli(["app", path, "--no-save"]);
  await writeFile(out, `TraceForge · tforge app ${path} --no-save\n\n${stdout}`, {
    mode: 0o644,
  });
  await chmod(out, 0o644);
};

const generateOne = async (target, outDir, reportCap) => {
  const htmlPath = join(outDir, `${target.slug}.html`);
  const { stdout } = await runCli(["report", target.path, "--out", htmlPath]);
  const evidenceId = evidenceIdOf(stdout);
  const htmlBytes = (await stat(htmlPath)).size;
  if (htmlBytes > reportCap) {
    // Fixed gallery decision: an oversized report is never published as HTML.
    // The stopping point itself is the evidence, so keep the CLI transcript.
    await rm(htmlPath, { force: true });
    const textPath = join(outDir, `${target.slug}.txt`);
    await captureText(target.path, textPath);
    return {
      ...target,
      kind: "text",
      bytes: (await stat(textPath)).size,
      htmlBytes,
      evidenceId,
    };
  }
  const findings = auditHtml(`${target.slug}.html`, await readFile(htmlPath, "utf8"));
  if (findings.length > 0) {
    await rm(htmlPath, { force: true });
    fail(
      1,
      `gallery: ${target.slug} report is not self-contained\n${findings
        .map((finding) => `  x ${finding}`)
        .join("\n")}`,
    );
  }
  // The CLI writes reports owner-only (0600); gallery artifacts are meant to be
  // read by anyone who clones the repository.
  await chmod(htmlPath, 0o644);
  return { ...target, kind: "html", bytes: htmlBytes, htmlBytes, evidenceId };
};

const options = parseFlags(process.argv.slice(2));

if (options.audit.length > 0) {
  const findings = [];
  for (const file of options.audit) {
    if (!existsSync(file)) fail(2, `gallery: --audit file not found: ${file}`);
    findings.push(...auditHtml(file.replace(`${repo}/`, ""), readFileSync(file, "utf8")));
  }
  if (findings.length > 0) fail(1, findings.map((finding) => `  x ${finding}`).join("\n"));
  process.stdout.write(
    `gallery: audit ok · ${options.audit.length} file(s) · no executable or remote markup\n`,
  );
  process.exit(0);
}

if (!existsSync(cli)) fail(2, "gallery: dist/cli.js is missing. Run `npm run build` first.");

const selected =
  options.only.length === 0
    ? TARGETS
    : TARGETS.filter((target) => options.only.includes(target.slug));
if (selected.length === 0)
  fail(2, `gallery: no target matches --only ${options.only.join(",")}`);

let workDir = null;
if (options.check) {
  await mkdir(join(repo, ".cache"), { recursive: true, mode: 0o755 });
  workDir = await mkdtemp(join(repo, ".cache", "gallery-check-"));
}
const dirs = MIRROR_DIRS.map((dir) =>
  workDir === null ? resolve(repo, dir) : join(workDir, dir),
);
for (const dir of dirs) await mkdir(dir, { recursive: true, mode: 0o755 });

const rows = [];
const notes = [];
for (const target of selected) {
  if (!(await isInstalled(target.path))) {
    notes.push(`  - ${target.slug}: skipped, ${target.path} is not installed here`);
    if (options.strict) rows.push({ ...target, kind: "missing", bytes: 0, evidenceId: null });
    continue;
  }
  const row = await generateOne(target, dirs[0], options.reportCap);
  const produced = `${row.slug}.${row.kind === "text" ? "txt" : "html"}`;
  for (const mirror of dirs.slice(1))
    await copyFile(join(dirs[0], produced), join(mirror, produced));
  rows.push(row);
}

const published = rows.filter((row) => row.kind !== "missing");
if (published.length === 0) fail(2, "gallery: nothing was generated (no target installed?)");
const total = published.reduce((sum, row) => sum + row.bytes, 0);

const summary = [
  "TraceForge · evidence gallery",
  ...rows.map((row) => {
    const mark = row.kind === "html" ? "ok  " : row.kind === "text" ? "cap " : "skip";
    const fallback =
      row.kind === "text"
        ? ` (html was ${sizeLabel(row.htmlBytes)}, over the ${sizeLabel(options.reportCap)} cap → transcript kept)`
        : "";
    return [
      `  ${mark} ${row.slug.padEnd(12)} ${sizeLabel(row.bytes).padStart(15)}  ${row.evidenceId ?? "no evidence id"}${fallback}`,
      `       proves: ${row.proves}`,
    ].join("\n");
  }),
  `  ${published.length} artifact(s) · ${sizeLabel(total)} counted once · total cap ${sizeLabel(options.totalCap)} · per-report cap ${sizeLabel(options.reportCap)}`,
  `  mirrored to ${dirs.map((dir) => dir.replace(`${repo}/`, "")).join(" + ")}`,
];

if (options.check) {
  const drift = [];
  for (const row of published) {
    const produced = `${row.slug}.${row.kind === "text" ? "txt" : "html"}`;
    const committed = join(repo, CANONICAL_DIR, produced);
    if (!existsSync(committed)) {
      drift.push(`  + ${CANONICAL_DIR}/${produced} is missing from the repository`);
      continue;
    }
    const [fresh, onDisk] = await Promise.all([
      readFile(join(dirs[0], produced)),
      readFile(committed),
    ]);
    if (!onDisk.equals(fresh))
      drift.push(
        `  ~ ${CANONICAL_DIR}/${produced} differs from a fresh run (${sizeLabel(onDisk.size)} committed vs ${sizeLabel(fresh.size)} fresh)`,
      );
  }
  await rm(workDir, { recursive: true, force: true });
  process.stdout.write(`${summary.join("\n")}\n`);
  if (drift.length > 0)
    fail(
      1,
      `gallery: --check found drift (the installed apps changed since the committed reports, or a report is stale)\n${drift.join("\n")}`,
    );
  process.stdout.write("gallery: check ok · committed reports match a fresh run\n");
  process.exit(0);
}

const overCap = published.filter((row) => row.bytes > options.reportCap);
if (overCap.length > 0)
  fail(
    1,
    `gallery: per-report cap exceeded\n${overCap
      .map((row) => `  x ${row.slug} ${sizeLabel(row.bytes)} > ${sizeLabel(options.reportCap)}`)
      .join("\n")}`,
  );
if (total > options.totalCap)
  fail(1, `gallery: total cap exceeded · ${sizeLabel(total)} > ${sizeLabel(options.totalCap)}`);

process.stdout.write(`${summary.join("\n")}\n`);
if (notes.length > 0) process.stdout.write(`${notes.join("\n")}\n`);
process.stdout.write(
  "gallery: ok · every evidence id is in your local store, verify with `node dist/cli.js evidence verify <id>`\n",
);
