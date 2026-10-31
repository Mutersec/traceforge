# Parser support and limits

TraceForge reads local files once, computes their identity, and asks one format
parser to interpret the bytes. A parser returns facts plus explicit limitations;
it never infers behavior from names alone.

## Mach-O

- Thin 32/64-bit and universal/fat containers.
- CPU architecture including `x86_64`, `arm64`, `arm64e`, and common legacy
  architectures.
- Segments and sections with virtual address, file offset, size, flags and a
  SHA-256 of the section bytes.
- `LC_SYMTAB` imports and exports, dylib dependencies, UUID, entrypoint
  (`LC_MAIN`), and build metadata.
- Limitations: stripped binaries may omit symbols; `LC_MAIN` reports a file
  offset, not a linked virtual address.

## ELF

- ELF32/ELF64, little- or big-endian.
- Section names, addresses, sizes, flags and hashes.
- `SHT_SYMTAB` and `SHT_DYNSYM` symbols; undefined external symbols become
  imports, defined external functions/objects become exports.
- `DT_NEEDED` libraries and GNU build-id from a note section.
- Limitations: missing section headers or extended section indices reduce
  coverage; symbols are capped at 200,000.

## PE

- PE32 and PE32+, x86 and x64/ARM64 machine fields.
- Sections with virtual address, raw offset, hash and flags.
- Import descriptors and names/ordinals, DLL dependencies, export names.
- RVA entrypoint and timestamp as build identity.
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
| Maximum symbols | 200,000 |
| Maximum PE imports/exports | 20,000 |

Every parser validates offsets and sizes before reading. Counts and string
lengths are bounded; malformed inputs become typed errors, not unbounded work.
