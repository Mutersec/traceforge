# Parser support and limits

TraceForge reads local files once, computes their identity, and asks one format
parser to interpret the bytes. A parser returns facts plus explicit limitations;
it never infers behavior from names alone.

## Mitigation vocabulary and decision rules

`security.present`, `security.absent` and `security.undetermined` share one
vocabulary across formats. A name appears in exactly one list. Every rule below
is a statement about header bytes only: TraceForge never runs the target, never
loads it, and never claims the operating system enforced anything.

| Name | Mach-O | ELF | PE |
|---|---|---|---|
| `pie` | `present` when `MH_PIC` is set; `undetermined` for objects and for dyld-linked images that carry fixup structures; else `absent` | `present` for `ET_DYN`, `absent` for `ET_EXEC`, `undetermined` otherwise | not reported (see `aslr`) |
| `aslr` | not reported | `present` for `ET_DYN`, `absent` for `ET_EXEC`, `undetermined` otherwise | `present` when `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` is set |
| `high-entropy-aslr` | not reported | not reported | `present` with `DYNAMIC_BASE` and `HIGH_ENTROPY_VA`; `absent` without `DYNAMIC_BASE` |
| `nx` | `absent` when `MH_ALLOW_STACK_EXECUTION` is set or a segment has writable-and-executable `maxprot` | `absent` when `PT_GNU_STACK` is executable or a segment is RWX; `undetermined` without `PT_GNU_STACK` | `present` with `NX_COMPAT` |
| `relro` | not reported | `present` with `PT_GNU_RELRO` | not reported |
| `bind-now` | not reported | `present` with `DT_FLAGS`/`DF_BIND_NOW` or `DT_FLAGS_1`/`DF_1_NOW`; `undetermined` without a dynamic section | not reported |
| `full-relro` | not reported | `present` with `PT_GNU_RELRO` and BIND_NOW; `undetermined` when BIND_NOW cannot be decided | not reported |
| `chained-fixups` | `present` with `LC_DYLD_CHAINED_FIXUPS` | not reported | not reported |
| `guard-cf` | not reported | not reported | `present` with `GUARD_CF` |
| `code-integrity` | not reported | not reported | `present` with `FORCE_INTEGRITY` |
| `image-isolation` | not reported | not reported | `absent` when `NO_ISOLATION` is set, `present` otherwise (documented OS default) |

## Provenance claims

`provenance` holds what the container says about its own build. These are
claims, not verified facts, and each parser records that as a limitation.

- Mach-O: `platform`, `min_os`, `sdk`, `linker_version` from
  `LC_BUILD_VERSION` or a `LC_VERSION_MIN_*` command, and `code_signature`
  when an `LC_CODE_SIGNATURE` blob is present. The blob is not parsed and its
  validity is never checked.
- ELF: `os_abi`, `abi_version`, `load_segments`, `interpreter` from `PT_INTERP`,
  `soname` from `DT_SONAME`, and `producer` from the first `.comment` string.
- PE: `linker_version`, `subsystem`, `os_version`, `image_version`,
  `size_of_image` and `declared_checksum`. A checksum field is a header claim;
  the file digest is the `sha256` identity instead.
- WebAssembly: `module_version`.

## Architecture labels

Arm64 and x86_64 subtypes are decoded only where a name is known:
`arm64`, `arm64v8`, `arm64e`, `x86_64`, `x86_64h`. An unknown subtype is
reported as `arm64_subtype_N` rather than being folded into the closest known
name, because a wrong label would enter every diff and Evidence record built
from it.

## Mach-O

- Thin 32/64-bit and universal/fat containers.
- CPU architecture including `x86_64`, `arm64`, `arm64e`, and common legacy
  architectures.
- Segments and sections with virtual address, file offset, size, flags and a
  SHA-256 of the section bytes.
- `LC_SYMTAB` imports and exports, dylib dependencies, UUID, entrypoint
  (`LC_MAIN`), and build metadata.
- Header `flags`, segment `maxprot`, `LC_BUILD_VERSION` / `LC_VERSION_MIN_*`,
  `LC_DYLD_INFO(_ONLY)`, `LC_DYLD_CHAINED_FIXUPS`, `LC_CODE_SIGNATURE` presence
  and `LC_ENCRYPTION_INFO_64`.
- Limitations: stripped binaries may omit symbols; `LC_MAIN` reports a file
  offset, not a linked virtual address; a declared encrypted region is not
  parsed.

## ELF

- ELF32/ELF64, little- or big-endian.
- Section names, addresses, sizes, flags and hashes.
- `SHT_SYMTAB` and `SHT_DYNSYM` symbols; undefined external symbols become
  imports, defined external functions/objects become exports.
- `DT_NEEDED` libraries and GNU build-id from a note section.
- Program headers (`PT_LOAD`, `PT_INTERP`, `PT_GNU_STACK`, `PT_GNU_RELRO`),
  `DT_SONAME`, `DT_FLAGS`, `DT_FLAGS_1` and the `.comment` producer string.
- Limitations: missing section headers or extended section indices reduce
  coverage; symbols are capped at 200,000; out-of-bounds program headers are
  reported as a limitation instead of guessed.

## PE

- PE32 and PE32+, x86 and x64/ARM64 machine fields.
- Sections with virtual address, raw offset, hash and flags.
- Import descriptors and names/ordinals, DLL dependencies, export names.
- RVA entrypoint and timestamp as build identity.
- `DllCharacteristics`, subsystem, linker version and the declared image size
  and checksum from the optional header.
- Limitations: directory RVAs that cannot be mapped through a section are
  skipped; malformed directories stay visible as limitations.

## WebAssembly

- Module version and all section headers.
- Custom section names, import module/name pairs and export names.
- Limitations: this is an inventory, not a validator or compiler.

## Unknown formats

An unrecognized format still receives a SHA-256 identity, size and a limitation.
TraceForge does not claim to understand bytes it cannot parse.

## Safety limits

| Limit | Value |
|---|---:|
| Maximum input file | 512 MiB |
| Maximum hashed section | 64 MiB |
| Maximum Mach-O commands/sections | 100,000 |
| Maximum ELF program headers | 65,536 |
| Maximum Mach-O build-version tools | 32 |
| Maximum `.comment` producer string | 160 bytes |
| Maximum symbols | 200,000 |
| Maximum PE imports/exports | 20,000 |

Every parser validates offsets and sizes before reading. Counts and string
lengths are bounded; malformed inputs become typed errors, not unbounded work.
