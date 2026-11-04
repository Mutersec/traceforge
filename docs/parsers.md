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

## Packages (`.app`, `.framework`, directories)

`src/core/app.ts` walks a directory tree in sorted name order and inventories
each member: relative path, size, streaming SHA-256, mode executability, kind,
detected format, and the architecture/file-type labels read from a 64 KiB header
window (see *Member identity* below). A member that cannot be `stat`-ed or read
is still listed — with size 0, a null hash and a counted limitation — because a
file the tool could not open is evidence of itself. A directory has no single
file digest, so the tree gets a `tree_sha256`: the SHA-256 of the canonical
`traceforge.app.tree.v1` document built from relative paths, sizes and member
hashes. That fingerprint deliberately ignores where the package is mounted, and
it only covers inventoried members — when the walk stops at a cap, the members
it never reached are absent from the fingerprint, and the record says so.

Rules that are stated rather than guessed:

- **Kinds.** `manifest` (Info.plist, any `.plist`, PkgInfo, CodeResources), then
  `code` (recognized container magic, else a native extension such as `.dylib`,
  `.so`, `.dll`, `.node`), then `archive`, `script`, `resource`, `link`, `other`.
  A kind is a triage label drawn from a name and a magic number; it is never a
  claim about what the file does.
- **Symbolic links** are recorded with their target text and never followed,
  opened or hashed. A link entry carries size 0 and a null hash, so the tree
  fingerprint sees the link without double-counting the file it points at.
  Versioned frameworks are mostly aliases of one real tree, so following links
  would multiply the inventory without adding evidence. The consequence is
  stated in the record: a `.framework` whose only `Info.plist` is reachable
  through `Versions/Current` is reported as layout `unknown`.
- **Nested packages** (`.app`, `.framework`, `.bundle`, `.xpc`, `.plugin`,
  `.component`, `.kext`, `.dSYM`, `.appex`, `.prefPane`) are listed with the
  identity their own manifest declares, up to a cap of 64.
- **Declared executable.** `CFBundleExecutable` is resolved as
  `Contents/MacOS/<name>` (macOS layout) or `<name>` (flat layout). A value
  containing a path separator is not resolved. Absence is recorded as a
  limitation, not as a silently empty field.
- **Nothing is opened deeper**: archives are counted and hashed but not
  enumerated; code signature blobs are not parsed; entitlements are not read.

### Member identity

`readContainerIdentities` reads only the header window, because a package scan
touches thousands of files and must not load a 379 MiB framework to learn its
architecture. Mach-O reports thin headers fully (architecture plus file type)
and each fat entry as `universal-member`, since a slice's file type lives past
the window. ELF reports `e_machine` and `e_type`; PE reports the COFF machine
and `dll` versus `executable` from `IMAGE_FILE_DLL`; WebAssembly reports
`wasm32`/`module` and states that this is all a header can honestly say. A
member whose magic matches but whose header does not decode keeps its format,
loses its architecture, and is counted in a limitation.

## Property lists

Bundle manifests arrive in three encodings, all three are read
(`src/core/plist.ts`): XML plists (prolog, comments, DOCTYPE, CDATA-free text,
named and numeric entities), binary `bplist00` (offset table, trailer, extended
length markers, ASCII and UTF-16BE strings, ints, reals, dates, data by length,
arrays, dicts, self-reference guard) and JSON plists (accepted, with a
limitation noting they are not Apple's canonical encoding). Old-style NeXT ASCII
plists are reported as unsupported rather than half-parsed.

Manifest values are **claims**, recorded under `manifest.claims` and marked as
self-reported in `limitations`. Keys are taken in a documented preferred order,
then any other top-level scalar, up to 64 keys and 256 characters per value. A
`<data>` value is recorded by byte length only. A manifest that cannot be parsed
still keeps its path, size and hash: "this package shipped an unreadable
Info.plist" is itself evidence, and the parse error text is preserved verbatim
in the limitation.

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
| Maximum package members inventoried | 5,000 |
| Maximum package directory depth | 32 |
| Maximum nested packages described | 64 |
| Package member header window | 64 KiB |
| Maximum package member hashed | 512 MiB |
| Maximum manifest parsed | 4 MiB |
| Maximum manifest claims recorded | 64 keys |
| Maximum manifest claim length | 256 characters |
| Maximum property list nodes | 200,000 |
| Maximum property list nesting | 32 |
| Maximum property list string | 8,192 characters |
| Maximum symlink target recorded | 4,096 characters |

Every parser validates offsets and sizes before reading. Counts and string
lengths are bounded; malformed inputs become typed errors, not unbounded work.
A package scan degrades differently on purpose: an unreadable member, a broken
manifest or a cap that stopped the walk is recorded as a limitation and the scan
continues, because a partial inventory of a suspicious package is more useful
than no inventory at all.
