import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { open, readdir, readFile, readlink, stat } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

import { readContainerIdentities } from "./binary.js";
import { canonicalJson, sha256Hex } from "./canonical.js";
import { TraceForgeError } from "./errors.js";
import { MAX_PLIST_BYTES, parsePlist, plistEncoding, scalarClaim } from "./plist.js";
import type {
  AppCounts,
  AppDeclaredExecutable,
  AppFileEntry,
  AppFileKind,
  AppInventory,
  AppLayout,
  AppManifest,
  AppNestedPackage,
  BinaryFormat,
} from "./types.js";

/**
 * Package inventory for `.app`, `.framework` and plain directory trees.
 *
 * A package is a directory, so it has no single input SHA-256 the way a file
 * does. Every member therefore keeps its own identity, the tree gets a
 * fingerprint computed over those member identities, and the bundle manifest is
 * recorded as what it is: claims the target makes about itself. Nothing here is
 * executed, opened for writing, followed through a symlink, or trusted. Caps
 * stop the walk and say so in `limitations` instead of failing the scan.
 */

export const MAX_APP_FILES = 5000;
export const MAX_APP_DEPTH = 32;
export const MAX_APP_NESTED = 64;
export const APP_HEADER_WINDOW_BYTES = 64 * 1024;
export const MAX_APP_HASH_BYTES = 512 * 1024 * 1024;
export const MAX_MANIFEST_CLAIMS = 64;
export const MAX_MANIFEST_CLAIM_CHARS = 256;
const MAX_LINK_TARGET_CHARS = 4_096;
const MAX_REPORTED_PATHS = 5;

/** Directory suffixes that mark a nested package, with the kind reported. */
const PACKAGE_SUFFIXES: readonly (readonly [string, string])[] = [
  [".app", "app"],
  [".framework", "framework"],
  [".bundle", "bundle"],
  [".xpc", "xpc-service"],
  [".plugin", "plugin"],
  [".component", "component"],
  [".kext", "kernel-extension"],
  [".dsym", "debug-symbols"],
  [".appex", "app-extension"],
  [".prefpane", "preference-pane"],
];

const NESTED_CLAIM_KEYS = [
  "CFBundleIdentifier",
  "CFBundleName",
  "CFBundleExecutable",
  "CFBundleShortVersionString",
  "CFBundleVersion",
] as const;

/** Ordered, because the claims an analyst reads first must win a place under the cap. */
const MANIFEST_CLAIM_KEYS = [
  "CFBundleIdentifier",
  "CFBundleName",
  "CFBundleDisplayName",
  "CFBundleExecutable",
  "CFBundleShortVersionString",
  "CFBundleVersion",
  "CFBundlePackageType",
  "CFBundleSignature",
  "CFBundleInfoDictionaryVersion",
  "LSMinimumSystemVersion",
  "LSApplicationCategoryType",
  "CFBundleIconFile",
  "CFBundleSupportedPlatforms",
  "DTPlatformName",
  "DTPlatformVersion",
  "DTSDKName",
  "DTSDKBuild",
  "DTCompiler",
  "BuildMachineOSBuild",
  "NSHumanReadableCopyright",
  "LSUIElement",
  "LSBackgroundOnly",
] as const;

const NATIVE_EXTENSIONS = new Set([
  "dylib", "so", "dll", "exe", "node", "o", "a", "lib", "obj", "sys", "efi",
]);

const SCRIPT_EXTENSIONS = new Set([
  "js", "mjs", "cjs", "jsx", "ts", "tsx", "lua", "py", "sh", "bash", "zsh", "pl", "rb",
]);

const ARCHIVE_EXTENSIONS = new Set([
  "asar", "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "jar", "war", "car", "dmg",
  "pkg", "ipk", "deb", "rpm", "skp", "tzb",
]);

const RESOURCE_EXTENSIONS = new Set([
  "png", "jpg", "jpeg", "gif", "tif", "tiff", "bmp", "webp", "svg", "icns", "ico",
  "pdf", "nib", "xib", "storyboard", "storyboardc", "strings", "stringsdict",
  "ttf", "otf", "ttc", "woff", "woff2", "eot", "wav", "aiff", "mp3", "mp4", "m4a",
  "m4v", "mov", "html", "htm", "css", "json", "md", "txt", "xml", "yaml", "yml",
  "toml", "pak",
]);

const byteOrder = (left: string, right: string): number =>
  left < right ? -1 : left > right ? 1 : 0;

const extensionOf = (name: string): string => {
  const lower = name.toLowerCase();
  const dot = lower.lastIndexOf(".");
  return dot < 0 ? "" : lower.slice(dot + 1);
};

const packageKindOf = (name: string): string | null => {
  const lower = name.toLowerCase();
  for (const [suffix, kind] of PACKAGE_SUFFIXES) if (lower.endsWith(suffix)) return kind;
  return null;
};

/**
 * One rule per kind, applied in this order: manifest name, then machine code
 * (magic first, native extension second), then archive, script, resource, other.
 * A classification is a label for triage, never a claim about what the file does.
 */
const classify = (name: string, format: BinaryFormat): AppFileKind => {
  const lower = name.toLowerCase();
  if (
    lower === "info.plist" ||
    lower.endsWith(".plist") ||
    lower === "pkginfo" ||
    lower === "coderesources"
  )
    return "manifest";
  const extension = extensionOf(lower);
  if (format !== "unknown" || NATIVE_EXTENSIONS.has(extension)) return "code";
  if (ARCHIVE_EXTENSIONS.has(extension)) return "archive";
  if (SCRIPT_EXTENSIONS.has(extension)) return "script";
  if (RESOURCE_EXTENSIONS.has(extension)) return "resource";
  return "other";
};

const countBy = (values: readonly string[]): Record<string, number> => {
  const tally = new Map<string, number>();
  for (const value of values) tally.set(value, (tally.get(value) ?? 0) + 1);
  return Object.fromEntries([...tally.entries()].sort(([a], [b]) => byteOrder(a, b)));
};

/** A count phrase that stays readable at one and at thousands. */
const counted = (count: number, noun: string): string =>
  `${count.toLocaleString("en-US")} ${noun}${count === 1 ? "" : "s"}`;

const wasWere = (count: number): string => (count === 1 ? "was" : "were");

const truncatedText = (value: string, limit: number): string =>
  value.length <= limit ? value : `${value.slice(0, limit)}...`;

/** Streams one member into SHA-256, so a 400 MiB framework never sits in memory. */
const hashMember = (path: string): Promise<string | null> =>
  new Promise((resolveHash) => {
    const hash = createHash("sha256");
    let failed = false;
    let settled = false;
    const finish = (value: string | null): void => {
      if (settled) return;
      settled = true;
      resolveHash(value);
    };
    const stream = createReadStream(path);
    stream.on("data", (chunk: Buffer) => hash.update(chunk));
    stream.on("error", () => {
      failed = true;
      finish(null);
    });
    stream.on("close", () => finish(failed ? null : hash.digest("hex")));
  });

/** Reads only the first bytes of a member; a package scan must not load bodies. */
const readHeaderWindow = async (path: string, size: number): Promise<Buffer | null> => {
  let handle;
  try {
    handle = await open(path, "r");
    const info = await handle.stat();
    const length = Math.min(size, info.size);
    if (length <= 0) return Buffer.alloc(0);
    const buffer = Buffer.alloc(length);
    const { bytesRead } = await handle.read(buffer, 0, length, 0);
    return buffer.subarray(0, Math.max(0, bytesRead));
  } catch {
    return null;
  } finally {
    await handle?.close().catch(() => undefined);
  }
};

interface ManifestRead {
  readonly encoding: "xml" | "binary" | "json" | null;
  readonly claims: Record<string, string>;
  readonly keys: number;
  readonly parsed: boolean;
  readonly limitations: readonly string[];
};

const claimText = (value: unknown): string | null => {
  const text = scalarClaim(value as never);
  if (text === null || text.trim().length === 0) return null;
  return truncatedText(text.replace(/\s+/gu, " ").trim(), MAX_MANIFEST_CLAIM_CHARS);
};

/**
 * Reads declared manifest identity.
 *
 * A manifest that cannot be parsed still keeps its path, size and hash, because
 * "this package shipped an unreadable Info.plist" is itself evidence. Parsing
 * limits become limitations; they never become guesses.
 */
const readManifestClaims = async (
  path: string,
  preferred: readonly string[],
  allowOtherKeys: boolean,
): Promise<ManifestRead> => {
  const limitations: string[] = [];
  let buffer: Buffer;
  try {
    buffer = await readFile(path);
  } catch {
    return {
      encoding: null,
      claims: {},
      keys: 0,
      parsed: false,
      limitations: ["The bundle manifest could not be read."],
    };
  }
  if (buffer.length > MAX_PLIST_BYTES)
    return {
      encoding: null,
      claims: {},
      keys: 0,
      parsed: false,
      limitations: [
        `The bundle manifest is larger than the ${MAX_PLIST_BYTES / 1024 / 1024} MiB property list limit, so it was hashed but not parsed.`,
      ],
    };
  let document;
  try {
    document = parsePlist(buffer);
  } catch (cause) {
    const detected = plistEncoding(buffer);
    return {
      encoding: detected === "unknown" ? null : detected,
      claims: {},
      keys: 0,
      parsed: false,
      limitations: [
        `The bundle manifest could not be parsed: ${cause instanceof Error ? cause.message : String(cause)}`,
      ],
    };
  }
  limitations.push(...document.limitations);
  const root = document.root;
  if (root === null || typeof root !== "object" || Array.isArray(root)) {
    limitations.push(
      "The bundle manifest root is not a dictionary, so no identity claims were recorded.",
    );
    return { encoding: document.encoding, claims: {}, keys: 0, parsed: false, limitations };
  }
  const source = root as Record<string, unknown>;
  const claims: Record<string, string> = {};
  for (const key of preferred) {
    const text = claimText(source[key]);
    if (text !== null) claims[key] = text;
  }
  if (allowOtherKeys) {
    for (const key of Object.keys(source).sort(byteOrder)) {
      if (key in claims) continue;
      if (Object.keys(claims).length >= MAX_MANIFEST_CLAIMS) {
        limitations.push(
          `The manifest claim cap of ${MAX_MANIFEST_CLAIMS} keys was reached; the remaining keys are counted but not recorded.`,
        );
        break;
      }
      const text = claimText(source[key]);
      if (text !== null) claims[key] = text;
    }
  }
  return {
    encoding: document.encoding,
    claims,
    keys: Object.keys(source).length,
    parsed: true,
    limitations,
  };
};

interface WalkState {
  readonly maxFiles: number;
  readonly maxDepth: number;
  readonly maxNested: number;
  readonly files: AppFileEntry[];
  readonly nested: AppNestedPackage[];
  readonly limitations: string[];
  readonly unreadableNames: string[];
  readonly deepPaths: string[];
  directories: number;
  specials: number;
  headerFailures: number;
  oversized: number;
  unreadable: number;
  hashedBytes: number;
  totalBytes: number;
  capReached: boolean;
  nestedCapReached: boolean;
  depthCapReached: boolean;
}

const relativePath = (parent: string, name: string): string =>
  parent.length === 0 ? name : `${parent}/${name}`;

const noteUnreadable = (state: WalkState, relative: string): void => {
  state.unreadable += 1;
  if (state.unreadableNames.length < MAX_REPORTED_PATHS) state.unreadableNames.push(relative);
};

const recordLink = async (state: WalkState, absolute: string, relative: string): Promise<void> => {
  let target: string | null;
  try {
    target = truncatedText(await readlink(absolute), MAX_LINK_TARGET_CHARS);
  } catch {
    target = null;
  }
  state.files.push({
    path: relative,
    size: 0,
    sha256: null,
    kind: "link",
    format: "unknown",
    executable: false,
    architectures: [],
    file_types: [],
    link_target: target,
  });
};

const recordMember = async (
  state: WalkState,
  absolute: string,
  relative: string,
): Promise<void> => {
  let size = 0;
  let executable = false;
  let sizeKnown = false;
  try {
    const info = await stat(absolute);
    size = info.size;
    executable = (info.mode & 0o111) !== 0;
    sizeKnown = true;
  } catch {
    sizeKnown = false;
  }
  const window = await readHeaderWindow(absolute, APP_HEADER_WINDOW_BYTES);
  let format: BinaryFormat = "unknown";
  const architectures = new Set<string>();
  const fileTypes = new Set<string>();
  if (window !== null && window.length >= 2) {
    try {
      const localLimitations: string[] = [];
      const detected = readContainerIdentities(window, localLimitations);
      format = detected.format;
      for (const identity of detected.identities) {
        architectures.add(identity.architecture);
        fileTypes.add(identity.file_type);
      }
      state.limitations.push(...localLimitations);
    } catch {
      state.headerFailures += 1;
    }
  }
  let sha256: string | null = null;
  if (!sizeKnown) noteUnreadable(state, relative);
  else if (size > MAX_APP_HASH_BYTES) state.oversized += 1;
  else {
    sha256 = await hashMember(absolute);
    if (sha256 === null) noteUnreadable(state, relative);
    else state.hashedBytes += size;
  }
  if (sizeKnown) state.totalBytes += size;
  state.files.push({
    path: relative,
    size,
    sha256,
    kind: classify(basename(relative), format),
    format,
    executable,
    architectures: [...architectures].sort(byteOrder),
    file_types: [...fileTypes].sort(byteOrder),
    link_target: null,
  });
};

/** Records one nested package and the identity its own manifest declares. */
const recordNested = async (
  state: WalkState,
  absolute: string,
  relative: string,
  kind: string,
): Promise<void> => {
  const candidates: readonly (readonly [string, AppLayout])[] = [
    ["Contents/Info.plist", "macos"],
    ["Info.plist", "flat"],
  ];
  let manifestPath: string | null = null;
  let layout: AppLayout = "unknown";
  let declared: Record<string, string> = {};
  for (const [candidate, candidateLayout] of candidates) {
    const info = await stat(join(absolute, candidate)).catch(() => null);
    if (info === null || !info.isFile()) continue;
    manifestPath = relativePath(relative, candidate);
    layout = candidateLayout;
    const read = await readManifestClaims(join(absolute, candidate), NESTED_CLAIM_KEYS, false);
    declared = read.claims;
    for (const limitation of read.limitations)
      state.limitations.push(`Nested package ${relative}: ${limitation}`);
    break;
  }
  state.nested.push({ path: relative, kind, layout, manifest_path: manifestPath, declared });
};

/**
 * Depth-first walk in sorted name order.
 *
 * Sorting per directory makes the entry order — and therefore the fingerprint and
 * the Evidence ID — reproducible across runs and machines. Symlinks are recorded
 * and never followed: a `.framework` root is usually five aliases of one real
 * tree, and following them would multiply the inventory without adding evidence.
 */
const walkPackage = async (
  state: WalkState,
  absolute: string,
  relative: string,
  depth: number,
): Promise<void> => {
  let entries;
  try {
    entries = await readdir(absolute, { withFileTypes: true });
  } catch {
    state.limitations.push(
      relative.length === 0
        ? "The package root could not be listed, so nothing was inventoried."
        : `The directory ${relative} could not be listed; its contents are not inventoried.`,
    );
    return;
  }
  entries.sort((left, right) => byteOrder(left.name, right.name));
  for (const entry of entries) {
    if (state.files.length >= state.maxFiles) {
      state.capReached = true;
      return;
    }
    const childRelative = relativePath(relative, entry.name);
    const childAbsolute = join(absolute, entry.name);
    if (entry.isSymbolicLink()) {
      await recordLink(state, childAbsolute, childRelative);
      continue;
    }
    if (entry.isDirectory()) {
      state.directories += 1;
      const kind = packageKindOf(entry.name);
      if (kind !== null) {
        if (state.nested.length < state.maxNested)
          await recordNested(state, childAbsolute, childRelative, kind);
        else state.nestedCapReached = true;
      }
      if (depth + 1 >= state.maxDepth) {
        state.depthCapReached = true;
        if (state.deepPaths.length < MAX_REPORTED_PATHS) state.deepPaths.push(childRelative);
        continue;
      }
      await walkPackage(state, childAbsolute, childRelative, depth + 1);
      continue;
    }
    if (entry.isFile()) {
      await recordMember(state, childAbsolute, childRelative);
      continue;
    }
    state.specials += 1;
  }
};

const resolveDeclaredExecutable = async (
  root: string,
  layout: AppLayout,
  manifest: AppManifest | null,
  byPath: ReadonlyMap<string, AppFileEntry>,
  state: WalkState,
): Promise<AppDeclaredExecutable> => {
  const name = manifest?.claims.CFBundleExecutable ?? null;
  if (name === null || name.length === 0)
    return { name, path: null, present: false, sha256: null };
  if (name.includes("/") || name.includes("\\") || name === "." || name === "..") {
    state.limitations.push(
      "CFBundleExecutable declared a path rather than a member name, so it was not resolved.",
    );
    return { name, path: null, present: false, sha256: null };
  }
  const relative = layout === "macos" ? `Contents/MacOS/${name}` : name;
  const info = await stat(join(root, relative)).catch(() => null);
  if (info === null || !info.isFile()) {
    state.limitations.push(
      `The manifest declares ${name} as its executable at ${relative}, but no regular file was found there.`,
    );
    return { name, path: null, present: false, sha256: null };
  }
  return { name, path: relative, present: true, sha256: byPath.get(relative)?.sha256 ?? null };
};

/** Reads the eight printable bytes that name a package's type and OS. */
const readPkgInfo = async (
  root: string,
  layout: AppLayout,
  byPath: ReadonlyMap<string, AppFileEntry>,
  state: WalkState,
): Promise<Record<string, string>> => {
  const relative = layout === "macos" ? "Contents/PkgInfo" : "PkgInfo";
  if (!byPath.has(relative)) return {};
  const window = await readHeaderWindow(join(root, relative), 32);
  const text = window === null ? "" : window.toString("latin1");
  if (!/^[\x20-\x7e]{8}/u.test(text)) {
    state.limitations.push(
      `The PkgInfo file at ${relative} was present but did not decode as a four-character type and OS code.`,
    );
    return {};
  }
  return { signature: text.slice(0, 4), os_type: text.slice(4, 8) };
};

const treeFingerprint = (kind: string, files: readonly AppFileEntry[]): string =>
  sha256Hex(
    canonicalJson({
      schema: "traceforge.app.tree.v1",
      kind,
      entries: files.map((file) => ({
        path: file.path,
        size: file.size,
        sha256: file.sha256,
        kind: file.kind,
        link_target: file.link_target,
      })),
    }),
  );

export const packageKind = (path: string): string =>
  packageKindOf(basename(resolve(path))) ?? "directory";

export interface PackageOptions {
  readonly maxFiles?: number;
  readonly maxDepth?: number;
  readonly maxNested?: number;
}

/**
 * Inventories a package directory recursively.
 *
 * Every member keeps its own path, size, content hash and format label; the
 * manifest becomes declared identity claims. Caps stop the walk rather than
 * failing it, and every stopped walk states what is missing.
 */
export const inspectPackage = async (
  inputPath: string,
  options: PackageOptions = {},
): Promise<AppInventory> => {
  const root = resolve(inputPath);
  const rootInfo = await stat(root).catch((cause: unknown) => {
    throw new TraceForgeError("invalid_path", `Cannot read ${inputPath}`, { cause });
  });
  if (!rootInfo.isDirectory())
    throw new TraceForgeError(
      "not_a_directory",
      `${inputPath} is not a package directory; use inspect for a single file`,
    );
  const maxFiles = options.maxFiles ?? MAX_APP_FILES;
  const maxDepth = options.maxDepth ?? MAX_APP_DEPTH;
  const maxNested = options.maxNested ?? MAX_APP_NESTED;
  if (!Number.isInteger(maxFiles) || maxFiles <= 0)
    throw new TraceForgeError("invalid_input", "The package member limit must be a positive integer");
  if (!Number.isInteger(maxDepth) || maxDepth <= 0)
    throw new TraceForgeError("invalid_input", "The package depth limit must be a positive integer");
  if (!Number.isInteger(maxNested) || maxNested <= 0)
    throw new TraceForgeError("invalid_input", "The nested package limit must be a positive integer");

  const state: WalkState = {
    maxFiles,
    maxDepth,
    maxNested,
    files: [],
    nested: [],
    limitations: [],
    unreadableNames: [],
    deepPaths: [],
    directories: 0,
    specials: 0,
    headerFailures: 0,
    oversized: 0,
    unreadable: 0,
    hashedBytes: 0,
    totalBytes: 0,
    capReached: false,
    nestedCapReached: false,
    depthCapReached: false,
  };
  await walkPackage(state, root, "", 0);

  const kind = packageKind(root);
  const byPath = new Map(state.files.map((file) => [file.path, file]));
  const contentsDir = await stat(join(root, "Contents")).catch(() => null);
  const macosLayout = contentsDir !== null && contentsDir.isDirectory();
  const manifestRelative = macosLayout ? "Contents/Info.plist" : "Info.plist";
  const manifestInfo = await stat(join(root, manifestRelative)).catch(() => null);
  const layout: AppLayout =
    manifestInfo !== null && manifestInfo.isFile() ? (macosLayout ? "macos" : "flat") : "unknown";
  if (layout === "unknown")
    state.limitations.push(
      "No bundle manifest was found at Contents/Info.plist or Info.plist, so this is a directory inventory rather than a package identity.",
    );

  let manifest: AppManifest | null = null;
  if (manifestInfo !== null && manifestInfo.isFile()) {
    const read = await readManifestClaims(
      join(root, manifestRelative),
      MANIFEST_CLAIM_KEYS,
      true,
    );
    state.limitations.push(...read.limitations);
    if (read.parsed)
      state.limitations.push(
        "Manifest values are self-reported by the target; none were checked against a signature, notarization ticket or entitlements.",
      );
    const entry = byPath.get(manifestRelative);
    manifest = {
      path: manifestRelative,
      size: entry?.size ?? manifestInfo.size,
      sha256: entry?.sha256 ?? (await hashMember(join(root, manifestRelative))),
      encoding: read.encoding,
      keys: read.keys,
      claims: read.claims,
    };
  }

  const declaredExecutable = await resolveDeclaredExecutable(
    root,
    layout,
    manifest,
    byPath,
    state,
  );
  const pkgInfo = await readPkgInfo(root, layout, byPath, state);

  if (state.capReached)
    state.limitations.push(
      `The walk stopped at the ${maxFiles.toLocaleString("en-US")} member limit; later members are absent from the inventory and from the tree fingerprint.`,
    );
  if (state.depthCapReached)
    state.limitations.push(
      `The directory depth limit of ${maxDepth} was reached${
        state.deepPaths.length === 0
          ? ""
          : ` (for example ${state.deepPaths.map((path) => `${path}/`).join(", ")})`
      }; deeper contents are not inventoried.`,
    );
  if (state.nestedCapReached)
    state.limitations.push(
      `Only the first ${maxNested} nested packages were described; the rest are still counted as directories.`,
    );
  const linkCount = state.files.filter((file) => file.kind === "link").length;
  if (linkCount > 0)
    state.limitations.push(
      "Symbolic links were recorded with their target text but were never followed, opened or hashed.",
    );
  const archives = state.files.filter((file) => file.kind === "archive");
  if (archives.length > 0)
    state.limitations.push(
      `${counted(archives.length, "archive member")} ${wasWere(archives.length)} counted and hashed but not opened (for example ${archives
        .slice(0, MAX_REPORTED_PATHS)
        .map((archive) => basename(archive.path))
        .join(", ")}).`,
    );
  if (state.unreadable > 0)
    state.limitations.push(
      `${counted(state.unreadable, "member")} could not be read${
        state.unreadableNames.length === 0
          ? ""
          : ` (for example ${state.unreadableNames.join(", ")})`
      } and ${wasWere(state.unreadable)} recorded without a content hash.`,
    );
  if (state.oversized > 0)
    state.limitations.push(
      `${counted(state.oversized, "member")} ${wasWere(state.oversized)} exceed the ${MAX_APP_HASH_BYTES / 1024 / 1024} MiB content limit and ${wasWere(state.oversized)} recorded without a hash.`,
    );
  if (state.headerFailures > 0)
    state.limitations.push(
      `${counted(state.headerFailures, "member")} could not be labelled from the ${APP_HEADER_WINDOW_BYTES / 1024} KiB header window, so no architecture was recorded for ${state.headerFailures === 1 ? "it" : "them"}.`,
    );
  if (state.specials > 0)
    state.limitations.push(
      `${counted(state.specials, "special file")} (sockets, pipes or devices) ${wasWere(state.specials)} skipped because reading them could block.`,
    );
  state.limitations.push(
    "A package inventory hashes each inventoried member; it does not open archives, parse code signatures, or establish where any member came from.",
  );
  state.limitations.push(
    "The tree fingerprint is computed over relative member paths, sizes and hashes, so it does not depend on where the package is mounted.",
  );

  const counts: AppCounts = {
    files: state.files.filter((file) => file.kind !== "link").length,
    directories: state.directories,
    links: linkCount,
    special: state.specials,
    unreadable: state.unreadable,
    executable: state.files.filter((file) => file.executable).length,
    total_bytes: state.totalBytes,
    hashed_bytes: state.hashedBytes,
    by_kind: countBy(state.files.map((file) => file.kind)),
    by_format: countBy(state.files.map((file) => file.format)),
    architectures: countBy(state.files.flatMap((file) => file.architectures)),
  };

  return {
    schema: "traceforge.app.inventory.v1",
    path: root,
    kind,
    layout,
    tree_sha256: treeFingerprint(kind, state.files),
    total_bytes: state.totalBytes,
    manifest,
    pkg_info: pkgInfo,
    declared_executable: declaredExecutable,
    nested: state.nested,
    counts,
    files: state.files,
    limitations: [...new Set(state.limitations)].sort(byteOrder),
  };
};

export interface PackageSummary {
  readonly schema: "traceforge.app.summary.v1";
  readonly path: string;
  readonly kind: string;
  readonly layout: AppLayout;
  readonly tree_sha256: string;
  readonly total_bytes: number;
  readonly manifest: AppManifest | null;
  readonly pkg_info: Readonly<Record<string, string>>;
  readonly declared_executable: AppDeclaredExecutable;
  readonly counts: AppCounts;
  readonly nested: readonly AppNestedPackage[];
  readonly code: readonly AppFileEntry[];
  readonly members: number;
  readonly limitations: readonly string[];
}

/** The bounded view an agent reads first: no member list, largest code first. */
export const summarizePackage = (inventory: AppInventory): PackageSummary => {
  const code = inventory.files
    .filter((file) => file.kind === "code")
    .sort(
      (left, right) =>
        right.size - left.size || byteOrder(left.path, right.path),
    )
    .slice(0, 40);
  return {
    schema: "traceforge.app.summary.v1",
    path: inventory.path,
    kind: inventory.kind,
    layout: inventory.layout,
    tree_sha256: inventory.tree_sha256,
    total_bytes: inventory.total_bytes,
    manifest: inventory.manifest,
    pkg_info: inventory.pkg_info,
    declared_executable: inventory.declared_executable,
    counts: inventory.counts,
    nested: inventory.nested,
    code,
    members: inventory.files.length,
    limitations: inventory.limitations,
  };
};

