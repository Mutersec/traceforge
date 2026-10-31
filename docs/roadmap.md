# Roadmap

TraceForge 0.1 is deliberately small: identify, inventory, diff, and preserve
Evidence. The next increments should deepen usefulness without weakening the
read-only boundary.

## 0.2 — deeper inspection

- Mach-O code-signature and entitlement summary (without trusting the claim).
- ELF program headers and dynamic tags beyond `DT_NEEDED`.
- PE delay imports and richer resource metadata.
- Per-slice symbol filters and deterministic symbol pages.
- Evidence manifest indexes for larger stores.

## 0.3 — agent workflows

- MCP resources for paged inventories and retained Evidence.
- Evidence-aware task summaries with explicit coverage and limitations.
- Reference examples for Claude Code, Cursor, OpenCode and LM Studio.
- Stable JSON Schemas for every tool result.

## Later

- Cross-format structural fingerprinting with explicit uncertainty.
- Signed Evidence bundles with detached signatures.
- Optional lightweight disassembly, only if it can preserve byte-level
  provenance and bounded resource use.

## Non-goals

- Executing, injecting into, or modifying the target.
- Cloud accounts, telemetry, or a hosted analysis service.
- Guessing behavior from names, strings, or similarity alone.
- Treating a partial parser result as complete.
