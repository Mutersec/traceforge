# Changelog

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
