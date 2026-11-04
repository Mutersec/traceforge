# Roadmap

TraceForge has stayed deliberately small: identify, inventory, diff, sign and
preserve Evidence. The increments below deepen usefulness without weakening the
read-only boundary.

## 0.2 — deeper inspection

- Mach-O code-signature and entitlement summary (without trusting the claim).
  — Signature *presence* is recorded as a provenance claim; the blob is not yet
  parsed, so issuer and entitlements remain open.
- ELF program headers and dynamic tags beyond `DT_NEEDED`. — Done: `PT_LOAD`,
  `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_RELRO`, `DT_SONAME`, `DT_FLAGS`,
  `DT_FLAGS_1`.
- PE delay imports and richer resource metadata. — Open; `DllCharacteristics`
  and optional-header claims were delivered first.
- Mitigation and provenance vocabulary across Mach-O, ELF and PE. — Done, with
  the decision rules documented in [parsers.md](parsers.md).
- Per-slice symbol filters and deterministic symbol pages.
- Evidence manifest indexes for larger stores.

## 0.3 — agent workflows

Delivered in 0.3.0:

- Recursive package (`.app`, `.framework`, directory) inventory with a bundle
  manifest recorded as declared identity. — Done: `tforge app`, per-member
  hashes, tree fingerprint, nested packages with their own declared identity,
  bounded caps written as limitations.
- Signed Evidence: Ed25519 keygen / sign / detached sidecar / verify, with the
  full failure taxonomy and honest non-claims. — Done: `evidence
  keygen|sign|verify|verify-all`, `report --signature`, documented in
  [signing.md](signing.md). (This was listed under "Later" before; it landed
  early as a sidecar, not as a signed bundle.)
- Paged inventories and agent-sized answers: `--only` selectors,
  `--limit`/`--cursor` offset paging (1-500), and a 256 KiB ceiling per MCP
  tool answer with degrade-to-summary instead of a blob. — Done.
- MCP resources for paged inventories and retained Evidence. — Done:
  `traceforge://evidence`, `traceforge://evidence/{evidence_id}`,
  `traceforge://store`; `initialize` advertises `{ tools: {}, resources: {} }`.
- Evidence gallery of four real reports plus a regeneration script with a size
  budget, a markup audit and drift check. — Done: `examples/gallery`,
  `site/gallery`, `scripts/gallery.mjs`, notes in
  [`examples/README.md`](../examples/README.md).
- Hardened CI: ubuntu-latest + macos-latest × Node 22/24 with live CLI/MCP/
  signing smokes, a benchmark smoke ceiling and package-content gates
  (`npm pack --dry-run` audit, `npm publish --dry-run`). — Done.
- Reference examples for Claude Code, Cursor, OpenCode and LM Studio. —
  Partial: one client-agnostic `examples/mcp.json`; per-client screenshots and
  snippets remain open.

Open, left on purpose:

- Archive contents (`.asar`, `.car`, `.zip`) are counted and hashed but not
  enumerated — opening them safely (bombs, path traversal, huge member lists)
  needs its own bounded reader before any listing is honest.
- Code-signature blob and entitlements parsing — only the *presence* of
  `LC_CODE_SIGNATURE` is recorded today; decoding a blob invites treating a
  self-reported structure as identity.
- Cross-run benchmark baseline — the CI gate is a smoke ceiling because shared
  runners add too much noise for regression math; a retained baseline artifact
  is the prerequisite.
- Key revocation and a time-stamp authority — a sidecar proves non-change, not
  when or still-valid; both need an external trust source this tool refuses to
  fake.
- `get_evidence` deliberately answers above the 256 KiB tool cap — an
  authenticated record must be retrievable whole or the ceiling would silently
  break the evidence contract.
- The offset cursor can shift if the underlying package changes between pages
  of repeated live scans — paging is transport over one fixed record, and a
  consistent-snapshot token is not built yet.
- Stable JSON Schemas for every tool result — consumers today infer shape from
  the documented examples.

## Later

- Cross-format structural fingerprinting with explicit uncertainty.
- Optional lightweight disassembly, only if it can preserve byte-level
  provenance and bounded resource use.

## Non-goals

- Executing, injecting into, or modifying the target.
- Cloud accounts, telemetry, or a hosted analysis service.
- Guessing behavior from names, strings, or similarity alone.
- Treating a partial parser result as complete.
