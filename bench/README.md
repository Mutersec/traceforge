# Benchmark

The benchmark builds the runtime, then repeatedly inspects one local binary.
It measures the parser plus inventory construction; it does not execute the
target and does not include process startup or Evidence writes.

```sh
npm run bench -- /bin/ls
```

The report includes median, p95, min/max wall time and median process CPU time.
Results depend on the host, filesystem and binary size; do not treat a single
run as a cross-tool comparison.

## CI gate

CI pipes the report through an absolute ceiling check:

```sh
BENCH_ITERATIONS=25 npm run bench --silent | node scripts/bench-gate.mjs
```

The gate fails (exit 1) when `elapsed_ms.median` exceeds `--max-median-ms`
(env `TFORGE_BENCH_MAX_MEDIAN_MS`, default 10 ms) or `elapsed_ms.p95` exceeds
`--max-p95-ms` (env `TFORGE_BENCH_MAX_P95_MS`, default 25 ms), and prints the
measured value next to the expected one. CI pins `BENCH_ITERATIONS=25`.

This is a **smoke ceiling, not a cross-run regression gate.** The numbers are
deliberately wide because shared runners differ between boots and hosts, and a
single CI measurement cannot distinguish a code regression from a noisy
neighbor. Real regression tracking needs a retained baseline per host class to
compare against; no such baseline artifact exists yet, so nothing here
compares one run to another.
