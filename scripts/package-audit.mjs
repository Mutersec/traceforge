#!/usr/bin/env node
// Dependency-free audit of `npm pack --dry-run --json` output read on stdin.
//
// Fails (exit 1) when the published tarball would miss required content or
// would carry content that must never be published. It packs nothing itself
// and never touches a registry; run the pack step with the same pipe:
//
//   npm pack --dry-run --json | node scripts/package-audit.mjs
//
// Required at the package top level: dist/ (runtime output), README.md,
// LICENSE, assets/. Forbidden anywhere in the tarball: the local evidence
// store (.traceforge), signing key directories (keys/), any *.pem file,
// SABAH.md, and the test/ tree.

import { readFileSync } from "node:fs";

const USAGE = [
  "usage: npm pack --dry-run --json | node scripts/package-audit.mjs",
  "",
  "Parses the npm pack listing and asserts required package content",
  "(dist/, README.md, LICENSE, assets/) and rejects content that must",
  "never ship (.traceforge, keys/, *.pem, SABAH.md, test/).",
  "Exits 0 on a clean package, 1 on any violation, 2 on unreadable input.",
].join("\n");

const fail = (code, message) => {
  process.stderr.write(`${message}\n`);
  process.exit(code);
};

if (process.argv.includes("-h") || process.argv.includes("--help")) {
  process.stdout.write(`${USAGE}\n`);
  process.exit(0);
}

const raw = readFileSync(0, "utf8");
let listing;
try {
  const parsed = JSON.parse(raw);
  listing = Array.isArray(parsed) ? parsed[0] : parsed;
} catch {
  const preview = raw.replace(/\s+/gu, " ").slice(0, 200);
  fail(2, `package-audit: stdin is not \`npm pack --dry-run --json\` output (parse failed). First 200 chars: "${preview}"`);
}
const files = listing?.files;
if (!Array.isArray(files) || files.length === 0)
  fail(2, `package-audit: pack listing has no "files" array: ${JSON.stringify(Object.keys(listing ?? {}))}`);

const paths = files.map((entry) => String(entry?.path ?? ""));
const topLevel = (path) => path.split("/")[0];

const REQUIRED_DIRS = ["dist", "assets"];
const REQUIRED_FILES = ["README.md", "LICENSE"];
const FORBIDDEN = [
  { label: ".traceforge evidence store", test: (p) => p === ".traceforge" || p.startsWith(".traceforge/") || p.includes("/.traceforge/") },
  { label: "keys/ directory", test: (p) => p === "keys" || p.startsWith("keys/") || p.includes("/keys/") },
  { label: "*.pem key file", test: (p) => p.toLowerCase().endsWith(".pem") },
  { label: "SABAH.md", test: (p) => p === "SABAH.md" || p.endsWith("/SABAH.md") },
  { label: "test/ tree", test: (p) => p === "test" || p.startsWith("test/") || p.includes("/test/") },
];

const problems = [];

for (const dir of REQUIRED_DIRS) {
  const count = paths.filter((p) => topLevel(p) === dir).length;
  if (count === 0) problems.push(`required content missing: no files under ${dir}/`);
}
for (const file of REQUIRED_FILES) {
  if (!paths.includes(file)) problems.push(`required content missing: ${file}`);
}
for (const path of paths) {
  for (const rule of FORBIDDEN)
    if (rule.test(path))
      problems.push(`forbidden content present: ${path} (rule: ${rule.label})`);
}

const summary = [
  `package-audit: ${listing.name ?? "?"}@${listing.version ?? "?"} · ${paths.length} file(s) · ${(Number(listing.unpackedSize ?? 0) / 1024).toFixed(1)} KiB unpacked`,
  ...REQUIRED_DIRS.map((dir) => `  ${dir}/ ${paths.filter((p) => topLevel(p) === dir).length} file(s)`),
  ...REQUIRED_FILES.map((file) => `  ${file} ${paths.includes(file) ? "present" : "MISSING"}`),
];

if (problems.length > 0) {
  fail(1, [`package-audit: package content is wrong.`, ...summary, ...problems.map((p) => `  ✗ ${p}`)].join("\n"));
}
process.stdout.write(`${summary.join("\n")}\npackage-audit: ok · required content present, nothing forbidden in the tarball\n`);
