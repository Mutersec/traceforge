# Changelog

## Unreleased (0.3.0 work)

- Signed Evidence: `tforge evidence keygen`, `sign` and `verify --public-key`
  use Ed25519 from Node's own `crypto` — no new dependencies. Keys are PKCS#8
  and SPKI PEMs under `.traceforge/keys`, sidecars under
  `.traceforge/signatures`, every file atomic and owner-only (0600).
- A signature covers the ASCII message `traceforge.signature.v1\n` plus the
  SHA-256 of the record's canonical JSON, so it cannot be replayed against a
  bare hash or another schema. Ed25519 is deterministic: the same key and
  record always produce the same signature. Timestamps are deliberately not
  hashed — hashed content must stay deterministic.
- Verification distinguishes every failure: missing sidecar, malformed
  sidecar, record bytes changed since signing, record identity broken, wrong
  public key, and a signature that does not verify. `evidence verify` without
  signature flags and the `N valid · M invalid` line of `verify-all` are
  unchanged; `verify-all` adds a `X signed · Y unsigned` line and unsigned is
  never an error.
- `tforge report` gains an optional Signature section when `--signature` or
  `--public-key` is given: verified/failed badge, key fingerprint,
  `record_sha256`, and the honest line that a signature proves who signed and
  non-change, not origin. An embedded key is rendered as self-reported.
- A signature proves no time, no revocation and no OS keyring protection: the
  0600 file mode is the only guard on a private key. See
  [docs/signing.md](docs/signing.md).
- `tforge app <package>`: recursive inventory of an `.app`, `.framework` or
  directory. Every member keeps its own path, size, streaming SHA-256, kind,
  detected format and architecture labels read from a 64 KiB header window.
- Bundle manifests are recorded as **declared** identity: a new
  `src/core/plist.ts` reads XML, binary (`bplist00`) and JSON property lists,
  and the record states that the values are self-reported and were not checked
  against a signature, notarization ticket or entitlements.
- `traceforge.app.inventory.v1` results carry a `tree_sha256` — a fingerprint
  over relative member paths, sizes and hashes — so a directory gets an input
  identity even though it is not one file. `app` Evidence records bind the
  manifest and the declared executable as `related` identities.
- Nested packages (`Helper.app`, frameworks, bundles, XPC services, `.dSYM`,
  app extensions) are listed with the identity their own manifest declares.
- Hard read-only limits: symbolic links recorded and never followed, pipes and
  sockets skipped rather than read, archives counted and hashed but not opened,
  and a walk capped at 5,000 members / depth 32 / 64 nested packages, each stop
  written into `limitations` instead of failing the scan.
- New `inspect_package` MCP tool with `summary` and `complete` detail levels.
- `tforge report` accepts a package directory and renders manifest claims,
  largest members and nested packages in the standalone HTML report.
- Existing schemas are untouched: stored Evidence records keep authenticating
  and single-file Evidence IDs are unchanged.

## 0.2.0

- Per-slice `security` summary with one cross-format mitigation vocabulary
  (`present` / `absent` / `undetermined`) decoded from Mach-O header flags and
  segment protections, ELF program headers and dynamic tags, and PE
  `DllCharacteristics`.
- Per-slice `provenance` claims: Mach-O build version and code-signature
  presence, ELF OS/ABI, interpreter, soname and `.comment` producer, PE linker
  version, subsystem and declared image facts.
- ELF program header table is now read, including `PT_INTERP`, `PT_GNU_STACK`
  and `PT_GNU_RELRO`, with `PN_XNUM` extended counts.
- Mach-O load commands added: `LC_BUILD_VERSION`, `LC_VERSION_MIN_*`,
  `LC_DYLD_INFO(_ONLY)`, `LC_DYLD_CHAINED_FIXUPS`, `LC_CODE_SIGNATURE` and
  `LC_ENCRYPTION_INFO_64`.
- `diff` reports `mitigations_added`, `mitigations_removed` and
  `provenance_changed`; `scan` lists observed mitigation names.
- Arm64/x86_64 subtype labels are exact or explicitly unknown
  (`arm64_subtype_N`); an unrecognized subtype is no longer folded into `arm64`.
- Evidence report renders mitigation groups and a provenance claim table.
- Inventory schema bumped to `traceforge.inventory.v2`. Existing stored Evidence
  records keep their own schema and still authenticate.
- Documented mitigation decision rules in `docs/parsers.md`.

## 0.1.0

- Initial Mach-O, ELF, PE and WebAssembly inventory.
- Content-addressed, atomic Evidence store with verification.
- `scan`, `inspect`, `diff`, `evidence` CLI commands.
- Dependency-free MCP stdio server with five tools.
- Architecture selection with `inspect --arch`.
- Deterministic Evidence bundle export/import and verify-all.
- Standalone HTML Evidence report and one-command `npm run demo`.
- Parser benchmark and GitHub Pages landing site.
- Synthetic parser fixtures, real Mach-O smoke test, CI, CodeQL and release
  workflow.
