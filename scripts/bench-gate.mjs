#!/usr/bin/env node
// Dependency-free CI gate for bench/benchmark.mjs.
//
// Reads one benchmark JSON report from stdin (generate it with
// `npm run bench --silent`) and compares wall times against absolute
// ceilings. This is a SMOKE CEILING, not a cross-run regression gate: CI
// runners differ per boot and shared runners are noisy, so the thresholds
// are deliberately wide, and no baseline artifact is stored or compared.
// Real regression tracking would need a retained baseline per host class.
//
// Exits 0 when inside the ceiling, 1 when a ceiling is exceeded (the error
// names the expected and the measured number), 2 when the input is not a
// benchmark report or an argument is invalid.

import { readFileSync } from "node:fs";

const DEFAULT_MAX_MEDIAN_MS = 10;
const DEFAULT_MAX_P95_MS = 25;

const USAGE = [
  "usage: npm run bench --silent | node scripts/bench-gate.mjs [options]",
  "",
  "  --max-median-ms <n>  wall-time median ceiling in ms",
  `                       (env TFORGE_BENCH_MAX_MEDIAN_MS, default ${DEFAULT_MAX_MEDIAN_MS})`,
  "  --max-p95-ms <n>     wall-time p95 ceiling in ms",
  `                       (env TFORGE_BENCH_MAX_P95_MS, default ${DEFAULT_MAX_P95_MS})`,
  "  -h, --help           show this help",
  "",
  "Smoke ceiling only: it never compares this run against an earlier run,",
  "because no benchmark baseline artifact exists yet.",
].join("\n");

const fail = (code, message) => {
  process.stderr.write(`${message}\n`);
  process.exit(code);
};

const parsePositive = (flag, raw, source) => {
  const value = Number(raw);
  if (
    raw === undefined ||
    raw === "" ||
    !Number.isFinite(value) ||
    value <= 0
  )
    fail(2, `bench-gate: ${flag} needs a positive number from ${source}, got "${raw ?? ""}".`);
  return value;
};

const readValue = (argv, index, flag) => {
  const eq = argv[index].indexOf("=");
  if (eq !== -1) return [argv[index].slice(eq + 1), index];
  const next = argv[index + 1];
  if (next === undefined || next.startsWith("-"))
    fail(2, `bench-gate: ${flag} needs a number argument.`);
  return [next, index + 1];
};

const limits = {
  median: { value: DEFAULT_MAX_MEDIAN_MS, source: "default" },
  p95: { value: DEFAULT_MAX_P95_MS, source: "default" },
};
if (process.env.TFORGE_BENCH_MAX_MEDIAN_MS !== undefined)
  limits.median = {
    value: parsePositive("--max-median-ms", process.env.TFORGE_BENCH_MAX_MEDIAN_MS, "TFORGE_BENCH_MAX_MEDIAN_MS"),
    source: "TFORGE_BENCH_MAX_MEDIAN_MS",
  };
if (process.env.TFORGE_BENCH_MAX_P95_MS !== undefined)
  limits.p95 = {
    value: parsePositive("--max-p95-ms", process.env.TFORGE_BENCH_MAX_P95_MS, "TFORGE_BENCH_MAX_P95_MS"),
    source: "TFORGE_BENCH_MAX_P95_MS",
  };
const argv = process.argv.slice(2);
for (let index = 0; index < argv.length; index += 1) {
  const token = argv[index];
  if (token === "-h" || token === "--help") {
    process.stdout.write(`${USAGE}\n`);
    process.exit(0);
  }
  if (token === "--max-median-ms" || token.startsWith("--max-median-ms=")) {
    const [raw, consumed] = readValue(argv, index, "--max-median-ms");
    limits.median = {
      value: parsePositive("--max-median-ms", raw, "the command line"),
      source: "command line",
    };
    index = consumed;
    continue;
  }
  if (token === "--max-p95-ms" || token.startsWith("--max-p95-ms=")) {
    const [raw, consumed] = readValue(argv, index, "--max-p95-ms");
    limits.p95 = {
      value: parsePositive("--max-p95-ms", raw, "the command line"),
      source: "command line",
    };
    index = consumed;
    continue;
  }
  fail(2, `bench-gate: unknown argument "${token}".\n\n${USAGE}`);
}

const raw = readFileSync(0, "utf8");
let report;
try {
  report = JSON.parse(raw);
} catch {
  const preview = raw.replace(/\s+/gu, " ").slice(0, 200);
  fail(
    2,
    `bench-gate: stdin is not a bench/benchmark.mjs JSON report (parse failed). First 200 chars: "${preview}"`,
  );
}
const median = report?.elapsed_ms?.median;
const p95 = report?.elapsed_ms?.p95;
if (!Number.isFinite(median) || !Number.isFinite(p95)) {
  fail(
    2,
    `bench-gate: benchmark report is missing finite elapsed_ms.median/p95 (got ${JSON.stringify(report?.elapsed_ms)}).`,
  );
}

const violations = [];
if (median > limits.median.value)
  violations.push(
    `  median: measured ${median} ms, expected <= ${limits.median.value} ms (limit from ${limits.median.source})`,
  );
if (p95 > limits.p95.value)
  violations.push(
    `  p95:    measured ${p95} ms, expected <= ${limits.p95.value} ms (limit from ${limits.p95.source})`,
  );

const context = `${report.target ?? "unknown"} · ${report.iterations ?? "?"} iterations · node ${report.node ?? "?"} ${report.platform ?? "?"}/${report.arch ?? "?"}`;
if (violations.length > 0) {
  fail(
    1,
    [
      `bench-gate: benchmark smoke ceiling exceeded for ${context}.`,
      ...violations,
      "Note: this ceiling is a smoke bound, not a measured regression baseline.",
    ].join("\n"),
  );
}
process.stdout.write(
  `bench-gate: ok · ${context} · median ${median} ms <= ${limits.median.value} ms (${limits.median.source}) · p95 ${p95} ms <= ${limits.p95.value} ms (${limits.p95.source}) · smoke ceiling, not a cross-run regression gate\n`,
);
