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
