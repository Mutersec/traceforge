#!/usr/bin/env node
// Reproducible regeneration of the TraceForge evidence gallery.
//
// The gallery is a set of standalone HTML Evidence reports produced by the real
// CLI (`node dist/cli.js report <package>`) against four synthetic demo packages
// that this script builds itself under one fixed absolute path outside the
// repository (`/tmp/traceforge-gallery`). Nothing here renders HTML: the script
// builds the fixtures, calls the CLI, measures what came back, and enforces the
// size and safety budget. Because the targets are generated from fixed bytes and
// live at a fixed path that carries no username, every machine regenerates the
// same reports — the committed HTML and its Evidence IDs are reproducible on any
// host, which is exactly what the old installed-application gallery could not do.
//
//   node scripts/gallery.mjs                  # rebuild fixtures, regenerate every target
//   node scripts/gallery.mjs --only demo-app  # one target (comma list ok)
//   node scripts/gallery.mjs --check          # temp dir only, compare bytes, keep repo clean
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
// examples/, site/, .cache/ and the fixture directory /tmp/traceforge-gallery
// (owned by the script: it replaces that tree only when its own marker file is
// present, and refuses a foreign directory there). Exit codes: 0 ok · 1
// cap/audit violation or drift under --check · 2 usage or environment problem.

import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  stat,
  symlink,
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

// Fixed absolute fixture root. It carries no username, so the reports never
// embed a personal path, and it is never random (no mkdtemp): a changing path
// would change the Evidence IDs on every run. path.resolve() in the CLI is
// lexical (no realpath), so the strings below are what the HTML shows.
const FIXTURE_ROOT = "/tmp/traceforge-gallery";
const FIXTURE_MARKER = ".traceforge-gallery-fixture.json";
const FIXTURE_MARKER_JSON = '{"tool":"traceforge","schema":"traceforge.gallery-fixture.v1"}\n';

// Every target is a synthetic demo package this script builds, and proves one
// specific capability the gallery claims for it. The last target's root is a
// relative symlink with a non-ASCII name on purpose; resolving it from the path
// the CLI was given is part of what its report demonstrates.
const TARGETS = [
  {
    slug: "demo-app",
    path: `${FIXTURE_ROOT}/DemoApp.app`,
    proves: "nested packages: a framework version tree with its Current alias recorded (never followed), an inner Updater.app and two .xpc services, each with its own declared identifier",
  },
  {
    slug: "heavy-kit",
    path: `${FIXTURE_ROOT}/HeavyKit.app`,
    proves: "archive members (.asar, .car, .zip) counted and hashed but not opened, and one 8,388,608-byte member hashed in a single pass",
  },
  {
    slug: "wide-app",
    path: `${FIXTURE_ROOT}/WideApp.app`,
    proves: "the walk firing its 5,000-member cap on a 5,007-file tree and writing the stop into limitations",
  },
  {
    slug: "linked-client",
    path: `${FIXTURE_ROOT}/Demo İstemci.app`,
    proves: "a symlinked bundle root resolved from the path given, non-ASCII (İ, ç, ğ) names carried through, and two bundles declaring the same identifier",
  },
];

const USAGE = [
  "usage: node scripts/gallery.mjs [--check] [--strict] [--only <slug>[,<slug>]]",
  "                                [--report-cap <bytes>] [--total-cap <bytes>]",
  "       node scripts/gallery.mjs --audit <file.html> [...]",
  "",
  "Builds the four synthetic demo targets under /tmp/traceforge-gallery (never",
  "inside the repository), then regenerates the evidence gallery with",
  "`node dist/cli.js report <package>`. The fixture path is fixed and carries no",
  "username, so the reports and Evidence IDs reproduce byte for byte on any host.",
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

// ---------------------------------------------------------------------------
// Synthetic fixture builders. Every byte below is a fixed constant or derived
// from one by a pure function, so two runs of buildFixtures() produce the same
// tree. No file is copied from a real application, nothing is executed, and no
// tool outside Node is called.

// The same thin arm64 Mach-O pattern the test suite uses (machoFixture in
// test/fixtures.ts), re-expressed here with fixed bytes. Copying /bin/ls would
// make the gallery drift whenever macOS updates that binary; these constants
// cannot change. The magic at offset 0 is what makes the CLI label the member
// "mach-o · arm64".
const machoBytes = () => {
  const buffer = Buffer.alloc(136);
  buffer.writeUInt32LE(0xfeedfacf, 0);
  buffer.writeInt32LE(0x0100000c, 4);
  buffer.writeInt32LE(0, 8);
  buffer.writeUInt32LE(2, 12);
  buffer.writeUInt32LE(2, 16);
  buffer.writeUInt32LE(104, 20);
  buffer.writeUInt32LE(0x201, 24);
  const segment = 32;
  buffer.writeUInt32LE(0x19, segment);
  buffer.writeUInt32LE(72, segment + 4);
  buffer.write("__TEXT", segment + 8, "ascii");
  buffer.writeBigUInt64LE(0x1000n, segment + 24);
  buffer.writeBigUInt64LE(0x1000n, segment + 32);
  buffer.writeUInt32LE(0x1000, segment + 40);
  buffer.writeUInt32LE(0x1000, segment + 48);
  buffer.writeUInt32LE(5, segment + 56);
  buffer.writeUInt32LE(5, segment + 60);
  buffer.writeUInt32LE(0, segment + 64);
  const build = 104;
  buffer.writeUInt32LE(0x32, build);
  buffer.writeUInt32LE(32, build + 4);
  buffer.writeUInt32LE(1, build + 8);
  buffer.writeUInt32LE((13 << 16) | (2 << 8) | 1, build + 12);
  buffer.writeUInt32LE(14 << 16, build + 16);
  buffer.writeUInt32LE(1, build + 20);
  buffer.writeUInt32LE(1, build + 24);
  buffer.writeUInt32LE(902 << 16, build + 28);
  return buffer;
};

// XML property list with the claims a macOS bundle manifest declares — same
// fixed template the test fixtures use, values supplied per bundle so the
// nested-package table shows distinct declared identifiers.
const plistBytes = (
  entries,
) => {
  const escape = (value) =>
    value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
  const body = entries
    .map(([key, value]) => `\t\t<key>${escape(key)}</key>\n\t\t<string>${escape(value)}</string>`)
    .join("\n");
  return Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
	<dict>
${body}
	</dict>
</plist>
`,
    "utf8",
  );
};

const pkgInfoBytes = () => Buffer.from("APPL????", "ascii");

// Deterministic filler for archive members: one ASCII line repeated to an exact
// byte length. Nothing here is a real archive format — the point is that the
// walk counts the extension, hashes the bytes, and states it did not open them.
const fillerBytes = (label, size) => {
  const base = Buffer.from(`TraceForge synthetic archive member ${label}\n`, "utf8");
  const out = Buffer.alloc(size);
  for (let at = 0; at < size; at += base.length)
    base.copy(out, at, 0, Math.min(base.length, size - at));
  return out;
};

// One Mach-O header padded with zeros to an exact large size: a member the
// report must hash in full, so the "hashed in one pass" claim is measurable.
const paddedMachoBytes = (size) =>
  Buffer.concat([machoBytes(), Buffer.alloc(size - 136)]);

const writeMember = async (path, bytes, mode = 0o644) => {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await writeFile(path, bytes, { mode });
  await chmod(path, mode);
};

const makeLink = async (target, path) => {
  await mkdir(dirname(path), { recursive: true, mode: 0o755 });
  await symlink(target, path);
};

const bundleManifest = (identifier, name, executable, shortVersion, buildVersion) =>
  plistBytes([
    ["CFBundleIdentifier", identifier],
    ["CFBundleName", name],
    ["CFBundleExecutable", executable],
    ["CFBundleShortVersionString", shortVersion],
    ["CFBundleVersion", buildVersion],
    ["LSMinimumSystemVersion", "12.0"],
    ["CFBundlePackageType", "APPL"],
    ["NSHumanReadableCopyright", "Copyright 2026 Example Labs. Synthetic demo data."],
  ]);

// A classic macOS framework layout: the real bytes live under Versions/A, and
// the root is aliases. The walk must record those aliases and not follow them.
const frameworkTree = (root, frameworkName, identifier, version) => [
  writeMember(join(root, "Versions/A", frameworkName), machoBytes(), 0o755),
  writeMember(join(root, "Versions/A/Info.plist"), plistBytes([
    ["CFBundleIdentifier", identifier],
    ["CFBundleName", frameworkName],
    ["CFBundleExecutable", frameworkName],
    ["CFBundleShortVersionString", version],
    ["CFBundleVersion", version],
  ])),
  writeMember(join(root, "Versions/A/Resources/Info.strings"), plistBytes([
    ["CFBundleName", frameworkName],
  ])),
  makeLink("Versions/Current", join(root, "Current")),
  makeLink("A", join(root, "Versions/Current")),
  makeLink("Versions/Current/" + frameworkName, join(root, frameworkName)),
  makeLink("Versions/A/Info.plist", join(root, "Info.plist")),
  makeLink("Versions/A/Resources", join(root, "Resources")),
];

const appTree = (root, executableName, manifest) => [
  writeMember(join(root, "Contents/Info.plist"), manifest),
  writeMember(join(root, "Contents/PkgInfo"), pkgInfoBytes()),
  writeMember(join(root, "Contents/MacOS", executableName), machoBytes(), 0o755),
];

// 1. DemoApp.app — an app that contains other apps.
const buildDemoApp = async () => {
  const root = join(FIXTURE_ROOT, "DemoApp.app");
  const framework = join(root, "Contents/Frameworks/DemoFramework.framework");
  await Promise.all([
    ...appTree(
      root,
      "DemoApp",
      bundleManifest("com.example.demo.app", "DemoApp", "DemoApp", "2.0.0", "200"),
    ),
    ...frameworkTree(framework, "DemoFramework", "com.example.demo.framework", "1.4.0"),
    ...appTree(join(framework, "Versions/A/Updater.app"), "Updater", bundleManifest(
      "com.example.demo.updater", "Demo Updater", "Updater", "1.1.0", "110",
    )),
    ...appTree(join(framework, "Versions/A/XPCServices/Downloader.xpc"), "Downloader", bundleManifest(
      "com.example.demo.downloader", "Demo Downloader Service", "Downloader", "1.1.0", "110",
    )),
    ...appTree(join(framework, "Versions/A/XPCServices/Installer.xpc"), "Installer", bundleManifest(
      "com.example.demo.installer", "Demo Installer Service", "Installer", "1.1.0", "110",
    )),
    ...appTree(join(root, "Contents/Resources/DemoUI.bundle"), "DemoUI", bundleManifest(
      "com.example.demo.ui", "Demo UI Bundle", "DemoUI", "2.0.0", "200",
    )),
  ]);
};

// 2. HeavyKit.app — archive members counted but not opened, one big hashed member.
const buildHeavyKit = async () => {
  const root = join(FIXTURE_ROOT, "HeavyKit.app");
  await Promise.all([
    ...appTree(
      root,
      "HeavyKit",
      bundleManifest("com.example.heavykit", "HeavyKit", "HeavyKit", "3.2.1", "321"),
    ),
    writeMember(join(root, "Contents/Frameworks/HeavyEngine"), paddedMachoBytes(8388608)),
    writeMember(join(root, "Contents/Resources/app.asar"), fillerBytes("app.asar", 1048576)),
    writeMember(join(root, "Contents/Resources/cache.car"), fillerBytes("cache.car", 65536)),
    writeMember(join(root, "Contents/Resources/assets.zip"), fillerBytes("assets.zip", 65536)),
    writeMember(join(root, "Contents/Resources/config.json"), Buffer.from(
      '{\n  "synthetic": true,\n  "purpose": "resource-kind member"\n}\n',
      "utf8",
    )),
  ]);
};

// 3. WideApp.app — more members than the walk budget, so the cap fires and the
// limitation line is real: 3 root members + 5,004 member files = 5,007, which
// stops the walk mid-directory at the 5,000-member limit.
const buildWideApp = async () => {
  const root = join(FIXTURE_ROOT, "WideApp.app");
  const membersDir = join(root, "Contents/Resources/members");
  await mkdir(membersDir, { recursive: true, mode: 0o755 });
  await Promise.all(
    appTree(root, "WideApp", bundleManifest("com.example.wideapp", "WideApp", "WideApp", "0.9.0", "90")),
  );
  // Written in batches of 250 so the build stays quick; the names are zero-padded
  // and the bodies fixed-length, so sorted order and every hash are stable.
  for (let start = 0; start < 5004; start += 250) {
    const batch = [];
    for (let index = start; index < Math.min(start + 250, 5004); index += 1) {
      const label = String(index).padStart(6, "0");
      batch.push(
        writeFile(join(membersDir, `part-${label}.bin`), Buffer.from(`traceforge wide member ${label}`, "utf8"), {
          mode: 0o644,
        }),
      );
    }
    await Promise.all(batch);
  }
};

// 4. Demo İstemci.app — a symlinked bundle root with non-ASCII names; the real
// tree lives under Paketler/, and the outer bundle plus a nested bundle declare
// the same identifier (two bundles, one name — visible only in a recursive walk).
const buildLinkedClient = async () => {
  const payload = join(FIXTURE_ROOT, "Paketler/Demo İstemci.app");
  const inner = join(payload, "Contents/Frameworks/Demo İstemci.app");
  const library = join(payload, "Contents/Frameworks/DemoLib.framework");
  await Promise.all([
    ...appTree(
      payload,
      "Demo İstemci",
      bundleManifest("com.example.demo.istemci", "Demo İstemci", "Demo İstemci", "0.3.0", "30"),
    ),
    ...appTree(
      inner,
      "Demo İstemci",
      bundleManifest("com.example.demo.istemci", "Demo İstemci", "Demo İstemci", "0.3.0", "30"),
    ),
    ...frameworkTree(library, "DemoLib", "com.example.demolib", "0.2.0"),
    writeMember(join(payload, "Contents/Resources/İçeriler/çalışma-günlüğü.txt"), Buffer.from(
      "İstemci çalışma günlüğü — sentetik demo verisi.\n",
      "utf8",
    )),
    makeLink(join("Paketler", "Demo İstemci.app"), join(FIXTURE_ROOT, "Demo İstemci.app")),
  ]);
};

const buildFixtures = async () => {
  let info = null;
  try {
    info = await lstat(FIXTURE_ROOT);
  } catch {
    info = null;
  }
  if (info !== null) {
    const marker = await readFile(join(FIXTURE_ROOT, FIXTURE_MARKER), "utf8").catch(() => null);
    if (!info.isDirectory() || marker !== FIXTURE_MARKER_JSON)
      fail(
        2,
        `gallery: ${FIXTURE_ROOT} exists but is not a directory this script created; move it away yourself — the script will not touch foreign files`,
      );
    await rm(FIXTURE_ROOT, { recursive: true, force: true });
  }
  await mkdir(FIXTURE_ROOT, { recursive: true, mode: 0o755 });
  await writeFile(join(FIXTURE_ROOT, FIXTURE_MARKER), FIXTURE_MARKER_JSON, { mode: 0o644 });
  await buildDemoApp();
  await buildHeavyKit();
  await buildWideApp();
  await buildLinkedClient();
};

// ---------------------------------------------------------------------------

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

const isPresent = async (path) => {
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

await buildFixtures();

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
  if (!(await isPresent(target.path))) {
    notes.push(`  - ${target.slug}: skipped, ${target.path} does not exist after the fixture build`);
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
if (published.length === 0) fail(2, "gallery: nothing was generated (fixture build failed?)");
const total = published.reduce((sum, row) => sum + row.bytes, 0);

const summary = [
  "TraceForge · evidence gallery",
  `  fixtures: ${TARGETS.length} synthetic demo packages built under ${FIXTURE_ROOT} (outside the repository)`,
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
      `gallery: --check found drift (the committed reports do not match a fresh regeneration of the fixtures)\n${drift.join("\n")}`,
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
