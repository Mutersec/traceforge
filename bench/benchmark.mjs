import { performance } from "node:perf_hooks";

import { inspectBinary, summarizeInventory } from "../dist/index.js";

const target = process.argv[2] ?? "/bin/ls";
const iterations = Number(process.env.BENCH_ITERATIONS ?? "25");
if (!Number.isInteger(iterations) || iterations < 5)
  throw new Error("BENCH_ITERATIONS must be an integer >= 5");

await inspectBinary(target);
const samples = [];
for (let index = 0; index < iterations; index += 1) {
  const cpu = process.cpuUsage();
  const started = performance.now();
  const inventory = await inspectBinary(target);
  const elapsed = performance.now() - started;
  const used = process.cpuUsage(cpu);
  summarizeInventory(inventory);
  samples.push({ elapsed, cpuMs: (used.user + used.system) / 1000, size: inventory.size });
}
const sorted = [...samples].sort((left, right) => left.elapsed - right.elapsed);
const percentile = (value) => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * value))];
const median = percentile(0.5);
const report = {
  target,
  bytes: samples[0]?.size ?? 0,
  iterations,
  elapsed_ms: {
    min: Number(sorted[0]?.elapsed.toFixed(3)),
    median: Number(median?.elapsed.toFixed(3)),
    p95: Number(percentile(0.95)?.elapsed.toFixed(3)),
    max: Number(sorted.at(-1)?.elapsed.toFixed(3)),
  },
  cpu_ms_median: Number(median?.cpuMs.toFixed(3)),
  node: process.version,
  platform: process.platform,
  arch: process.arch,
};
console.log(JSON.stringify(report, null, 2));
