import {
  chmod,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

import { afterEach, expect, it } from "vitest";

import {
  inspectPackage,
  packageKind,
  summarizePackage,
} from "../src/core/app.js";
import { sha256Hex } from "../src/core/canonical.js";
import { EvidenceStore } from "../src/core/evidence.js";
import { TraceForgeError } from "../src/core/errors.js";
import { scanPackage } from "../src/core/operations.js";
import { renderEvidenceReport } from "../src/core/report.js";
import { handleMcpMessage } from "../src/mcp/server.js";
import type { AppFileEntry } from "../src/core/types.js";
import {
  binaryPlistFixture,
  elfFixture,
  machoFixture,
  wasmFixture,
  xmlPlistFixture,
} from "./fixtures.js";

const roots: string[] = [];
const temporaryRoot = async (prefix: string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const entryAt = (files: readonly AppFileEntry[], path: string): AppFileEntry => {
  const found = files.find((file) => file.path === path);
  if (found === undefined) throw new Error(`missing inventory entry ${path}`);
  return found;
};

/**
 * A package shaped like a real macOS app: an XML manifest, a PkgInfo file, a
 * Mach-O executable, a WASM module, an archive, a script and resources, one
 * versioned framework whose real tree is only reachable through symlinks, and a
 * nested helper app whose manifest is a binary property list.
 */
const buildPackage = async (root: string, manifest: Buffer): Promise<string> => {
  const bundle = join(root, "Example.app");
  const contents = join(bundle, "Contents");
  const framework = join(
    contents,
    "Frameworks",
    "Example Framework.framework",
    "Versions",
    "A",
  );
  const helper = join(contents, "Frameworks", "Helper.app");
  await Promise.all([
    mkdir(join(contents, "MacOS"), { recursive: true }),
    mkdir(join(contents, "Resources", "en.lproj"), { recursive: true }),
    mkdir(join(framework, "Resources"), { recursive: true }),
    mkdir(join(helper, "Contents", "MacOS"), { recursive: true }),
  ]);
  await Promise.all([
    writeFile(join(contents, "Info.plist"), manifest),
    writeFile(join(contents, "PkgInfo"), "APPL????"),
    writeFile(join(contents, "MacOS", "example"), machoFixture()),
    writeFile(join(contents, "Resources", "app.wasm"), wasmFixture()),
    writeFile(join(contents, "Resources", "icon.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47])),
    writeFile(join(contents, "Resources", "payload.asar"), Buffer.from("ARK0", "ascii")),
    writeFile(join(contents, "Resources", "main.js"), Buffer.from("console.log(1);", "ascii")),
    writeFile(
      join(contents, "Resources", "en.lproj", "Localizable.strings"),
      Buffer.from('"key" = "value";', "ascii"),
    ),
    writeFile(join(framework, "Example Framework"), machoFixture()),
    writeFile(join(helper, "Contents", "Info.plist"), binaryPlistFixture()),
    writeFile(join(helper, "Contents", "MacOS", "helper"), elfFixture()),
  ]);
  await Promise.all([
    chmod(join(contents, "MacOS", "example"), 0o755),
    chmod(join(framework, "Example Framework"), 0o755),
    chmod(join(helper, "Contents", "MacOS", "helper"), 0o755),
  ]);
  await symlink("A", join(contents, "Frameworks", "Example Framework.framework", "Versions", "Current"));
  await symlink("example", join(contents, "MacOS", "example-alias"));
  return bundle;
};

it("inventories a package tree and records the identity it declares", async () => {
  const root = await temporaryRoot("traceforge-package-");
  const bundle = await buildPackage(root, xmlPlistFixture());
  const store = new EvidenceStore(join(root, "evidence"));
  const outcome = await scanPackage(bundle, store, "0.2.0");
  const inventory = outcome.inventory;

  expect(inventory.schema).toBe("traceforge.app.inventory.v1");
  expect(inventory.kind).toBe("app");
  expect(inventory.layout).toBe("macos");
  expect(inventory.path).toBe(bundle);
  expect(inventory.counts.files).toBe(11);
  expect(inventory.counts.links).toBe(2);
  expect(inventory.counts.executable).toBe(3);
  expect(inventory.counts.directories).toBeGreaterThan(8);
  expect(inventory.counts.by_kind).toEqual({
    archive: 1,
    code: 4,
    link: 2,
    manifest: 3,
    resource: 2,
    script: 1,
  });
  expect(inventory.counts.by_format).toMatchObject({ "elf": 1, "mach-o": 2, "wasm": 1 });
  expect(inventory.counts.architectures).toEqual({ arm64: 2, wasm32: 1, x86_64: 1 });
  expect(inventory.pkg_info).toEqual({ signature: "APPL", os_type: "????" });

  const manifest = inventory.manifest;
  expect(manifest).not.toBeNull();
  expect(manifest?.path).toBe("Contents/Info.plist");
  expect(manifest?.encoding).toBe("xml");
  expect(manifest?.keys).toBe(9);
  expect(manifest?.sha256).toBe(sha256Hex(xmlPlistFixture()));
  expect(manifest?.claims).toMatchObject({
    CFBundleIdentifier: "com.acme.example",
    CFBundleExecutable: "example",
    CFBundleShortVersionString: "1.4.2",
    LSMinimumSystemVersion: "12.0",
    NSHumanReadableCopyright: "Copyright © Acme & Co",
  });

  expect(inventory.declared_executable).toEqual({
    name: "example",
    path: "Contents/MacOS/example",
    present: true,
    sha256: sha256Hex(machoFixture()),
  });

  const wasm = entryAt(inventory.files, "Contents/Resources/app.wasm");
  expect(wasm.format).toBe("wasm");
  expect(wasm.kind).toBe("code");
  expect(wasm.architectures).toEqual(["wasm32"]);
  expect(wasm.file_types).toEqual(["module"]);
  const executable = entryAt(inventory.files, "Contents/MacOS/example");
  expect(executable.architectures).toEqual(["arm64"]);
  expect(executable.file_types).toEqual(["executable"]);
  expect(executable.executable).toBe(true);
  const helper = entryAt(
    inventory.files,
    "Contents/Frameworks/Helper.app/Contents/MacOS/helper",
  );
  expect(helper.format).toBe("elf");
  expect(helper.architectures).toEqual(["x86_64"]);
  expect(helper.file_types).toEqual(["shared"]);
  expect(entryAt(inventory.files, "Contents/Resources/payload.asar").kind).toBe("archive");
  expect(entryAt(inventory.files, "Contents/Resources/main.js").kind).toBe("script");
  expect(entryAt(inventory.files, "Contents/Resources/icon.png").kind).toBe("resource");
  expect(entryAt(inventory.files, "Contents/PkgInfo").kind).toBe("manifest");

  const alias = entryAt(inventory.files, "Contents/MacOS/example-alias");
  expect(alias.kind).toBe("link");
  expect(alias.link_target).toBe("example");
  expect(alias.sha256).toBeNull();
  expect(
    inventory.files.some((file) => file.path.includes("Versions/Current/")),
  ).toBe(false);

  expect(inventory.nested).toHaveLength(2);
  const helperBundle = inventory.nested.find((item) => item.path.endsWith("Helper.app"));
  expect(helperBundle?.kind).toBe("app");
  expect(helperBundle?.layout).toBe("macos");
  expect(helperBundle?.declared.CFBundleIdentifier).toBe("com.acme.helper");
  expect(helperBundle?.declared.CFBundleName).toBe("Helper");
  const frameworkBundle = inventory.nested.find((item) => item.path.endsWith(".framework"));
  expect(frameworkBundle?.kind).toBe("framework");
  expect(frameworkBundle?.manifest_path).toBeNull();

  expect(inventory.limitations).toEqual(
    expect.arrayContaining([
      expect.stringMatching(/1 archive member was counted and hashed but not opened/u),
      expect.stringMatching(/Symbolic links were recorded/u),
      expect.stringMatching(/Manifest values are self-reported/u),
      expect.stringMatching(/does not depend on where the package is mounted/u),
      expect.stringMatching(/WebAssembly members are labelled by module version only/u),
    ]),
  );
  expect(
    inventory.files.every(
      (file) => file.sha256 === null || /^[a-f0-9]{64}$/u.test(file.sha256),
    ),
  ).toBe(true);

  expect(outcome.record.operation).toBe("app");
  expect(outcome.record.input.sha256).toBe(inventory.tree_sha256);
  expect(outcome.record.input.size).toBe(inventory.total_bytes);
  expect(outcome.record.input.related).toEqual([
    {
      path: join(bundle, "Contents", "Info.plist"),
      sha256: sha256Hex(xmlPlistFixture()),
      size: xmlPlistFixture().length,
    },
    {
      path: join(bundle, "Contents", "MacOS", "example"),
      sha256: sha256Hex(machoFixture()),
      size: machoFixture().length,
    },
  ]);
  expect(await store.get(outcome.record.evidence_id)).toEqual(outcome.record);

  const again = await scanPackage(bundle, undefined, "0.2.0");
  expect(again.inventory.tree_sha256).toBe(inventory.tree_sha256);
  expect(again.record.evidence_id).toBe(outcome.record.evidence_id);
}, 30_000);

it("binds the tree fingerprint to member bytes", async () => {
  const root = await temporaryRoot("traceforge-tree-");
  const bundle = await buildPackage(root, xmlPlistFixture());
  const before = await inspectPackage(bundle);
  await writeFile(join(bundle, "Contents", "Resources", "icon.png"), Buffer.from([0x00, 0x01]));
  const after = await inspectPackage(bundle);
  expect(after.tree_sha256).not.toBe(before.tree_sha256);
  expect(after.counts.files).toBe(before.counts.files);
});

it("decodes a binary property list manifest and reports a missing executable", async () => {
  const root = await temporaryRoot("traceforge-bplist-");
  const bundle = await buildPackage(root, binaryPlistFixture());
  const inventory = await inspectPackage(bundle);
  expect(inventory.manifest?.encoding).toBe("binary");
  expect(inventory.manifest?.keys).toBe(3);
  expect(inventory.manifest?.claims).toEqual({
    CFBundleIdentifier: "com.acme.helper",
    CFBundleName: "Helper",
    LSUIElement: "false",
  });
  expect(inventory.declared_executable).toEqual({
    name: null,
    path: null,
    present: false,
    sha256: null,
  });

  const ghost = await buildPackage(join(root, "ghost"), xmlPlistFixture({ CFBundleExecutable: "ghost" }));
  const ghostInventory = await inspectPackage(ghost);
  expect(ghostInventory.declared_executable.present).toBe(false);
  expect(
    ghostInventory.limitations.some((item) =>
      /declares ghost as its executable at Contents\/MacOS\/ghost, but no regular file was found/u.test(
        item,
      ),
    ),
  ).toBe(true);
});

it("reads a real system binary manifest when one is available", async () => {
  const candidates = [
    "/System/Library/PrivateFrameworks/AMPLibrary.framework/Versions/A/Resources/Info.plist",
    "/System/Library/PrivateFrameworks/ACDEClient.framework/Versions/A/Resources/Info.plist",
    "/System/Library/PrivateFrameworks/DataAccess.framework/Frameworks/AccountInfo.plist",
  ];
  const bodies = await Promise.all(
    candidates
      .filter((path) => existsSync(path))
      .map(async (path) => ({ path, body: await readFile(path).catch(() => null) })),
  );
  const real = bodies.find(
    (item) => item.body !== null && item.body.subarray(0, 8).toString("latin1") === "bplist00",
  );
  if (process.platform !== "darwin" || real === undefined || real.body === null) return;
  const inventory = await inspectPackage(dirname(real.path));
  expect(inventory.layout).toBe("flat");
  expect(inventory.manifest?.encoding).toBe("binary");
  expect(inventory.manifest?.sha256).toBe(sha256Hex(real.body));
  // Apple ships these manifests as binary plists with a reverse-DNS identifier;
  // this is the same file the system's own tools read.
  expect(inventory.manifest?.claims.CFBundleIdentifier ?? "").toMatch(/^com\./u);
}, 30_000);

it("keeps scanning when a manifest cannot be parsed", async () => {
  const root = await temporaryRoot("traceforge-broken-manifest-");
  const bundle = await buildPackage(
    root,
    Buffer.from("<plist><dict><key>a</key>", "ascii"),
  );
  const inventory = await inspectPackage(bundle);
  expect(inventory.manifest).not.toBeNull();
  expect(inventory.manifest?.claims).toEqual({});
  expect(inventory.manifest?.encoding).toBe("xml");
  expect(inventory.manifest?.sha256).toMatch(/^[a-f0-9]{64}$/u);
  expect(inventory.limitations.some((item) => /could not be parsed/u.test(item))).toBe(true);

  const old = await buildPackage(
    join(root, "old"),
    Buffer.from("{ CFBundleName = Old; };", "ascii"),
  );
  const oldInventory = await inspectPackage(old);
  expect(oldInventory.manifest?.claims).toEqual({});
  expect(
    oldInventory.limitations.some((item) =>
      /old-style ASCII property lists are not supported/u.test(item),
    ),
  ).toBe(true);

  const unknown = await buildPackage(
    join(root, "binary"),
    Buffer.from([0x00, 0x01, 0x02, 0x03, 0xff]),
  );
  const unknownInventory = await inspectPackage(unknown);
  expect(unknownInventory.manifest?.encoding).toBeNull();
  expect(
    unknownInventory.limitations.some((item) =>
      /encoding was not recognized; only XML, binary and JSON plists are read/u.test(item),
    ),
  ).toBe(true);
});

it("stops at member, depth and nested limits and says what is missing", async () => {
  const root = await temporaryRoot("traceforge-limits-");
  const bundle = await buildPackage(root, xmlPlistFixture());

  const capped = await inspectPackage(bundle, { maxFiles: 3 });
  expect(capped.files).toHaveLength(3);
  expect(
    capped.limitations.some((item) => /stopped at the 3 member limit/u.test(item)),
  ).toBe(true);

  const shallow = await inspectPackage(bundle, { maxDepth: 2 });
  expect(shallow.files.some((file) => file.path === "Contents/MacOS/example")).toBe(false);
  expect(shallow.files.some((file) => file.path === "Contents/Info.plist")).toBe(true);
  expect(
    shallow.limitations.some((item) => /depth limit of 2 was reached/u.test(item)),
  ).toBe(true);

  const nested = await inspectPackage(bundle, { maxNested: 1 });
  expect(nested.nested).toHaveLength(1);
  expect(
    nested.limitations.some((item) => /first 1 nested packages were described/u.test(item)),
  ).toBe(true);
});

it("rejects a file, a missing path and an invalid limit", async () => {
  const root = await temporaryRoot("traceforge-reject-");
  const file = join(root, "plain.txt");
  await writeFile(file, "not a package");
  await expect(inspectPackage(file)).rejects.toThrow(/not a package directory/u);
  await expect(inspectPackage(join(root, "nope.app"))).rejects.toThrow(/Cannot read/u);
  await expect(inspectPackage(root, { maxFiles: 0 })).rejects.toThrow(/positive integer/u);
  const error = await inspectPackage(file).catch((cause: unknown) => cause);
  expect(error).toBeInstanceOf(TraceForgeError);
  expect((error as TraceForgeError).code).toBe("not_a_directory");
  expect(packageKind(join(root, "Whatever.app"))).toBe("app");
  expect(packageKind(join(root, "Plain.bundle"))).toBe("bundle");
  expect(packageKind(root)).toBe("directory");
});

it("records a member it cannot read instead of failing the scan", async () => {
  const root = await temporaryRoot("traceforge-permission-");
  const bundle = await buildPackage(root, xmlPlistFixture());
  const locked = join(bundle, "Contents", "Resources", "main.js");
  await chmod(locked, 0o000);
  const blocked = await open(locked, "r")
    .then((handle) => handle.close().then(() => false))
    .catch(() => true);
  if (!blocked) {
    await chmod(locked, 0o644);
    return;
  }
  const inventory = await inspectPackage(bundle);
  await chmod(locked, 0o644);
  const entry = entryAt(inventory.files, "Contents/Resources/main.js");
  expect(entry.sha256).toBeNull();
  expect(entry.size).toBe(15);
  expect(inventory.counts.unreadable).toBe(1);
  expect(
    inventory.limitations.some((item) =>
      /1 member could not be read \(for example Contents\/Resources\/main\.js\)/u.test(item),
    ),
  ).toBe(true);
  expect(inventory.tree_sha256).toMatch(/^[a-f0-9]{64}$/u);
});

it("summarizes a package without listing every member", async () => {
  const root = await temporaryRoot("traceforge-summary-");
  const inventory = await inspectPackage(await buildPackage(root, xmlPlistFixture()));
  const summary = summarizePackage(inventory);
  expect(summary.schema).toBe("traceforge.app.summary.v1");
  expect(summary.members).toBe(inventory.files.length);
  expect(summary.code.length).toBeLessThanOrEqual(40);
  expect(summary.code.every((file) => file.kind === "code")).toBe(true);
  const sizes = summary.code.map((file) => file.size);
  expect(sizes).toEqual([...sizes].sort((left, right) => right - left));
  expect(JSON.stringify(summary)).not.toContain("icon.png");
});

it("escapes untrusted manifest claims in the package report", async () => {
  const root = await temporaryRoot("traceforge-package-report-");
  const bundle = await buildPackage(
    root,
    xmlPlistFixture({ CFBundleName: "<script>alert(1)</script>" }),
  );
  const store = new EvidenceStore(join(root, "evidence"));
  const outcome = await scanPackage(bundle, store, "0.2.0");
  const html = renderEvidenceReport(outcome.record);
  expect(html).toContain("Manifest claims");
  expect(html).toContain("Largest members");
  expect(html).toContain("Declared executable");
  expect(html).toContain("identity verified");
  expect(html).not.toContain("<script>alert(1)</script>");
  expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
});

it("serves inspect_package over MCP with a bounded summary", async () => {
  const root = await temporaryRoot("traceforge-mcp-package-");
  const bundle = await buildPackage(root, xmlPlistFixture());
  const store = new EvidenceStore(join(root, "evidence"));
  const options = { store, version: "0.2.0" };
  const listed = await handleMcpMessage(
    { jsonrpc: "2.0", id: 1, method: "tools/list" },
    options,
  );
  expect(
    (listed?.result as { tools: { name: string }[] }).tools.map((tool) => tool.name),
  ).toContain("inspect_package");
  const called = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "inspect_package", arguments: { path: bundle } },
    },
    options,
  );
  const content = (
    called?.result as {
      structuredContent: {
        evidence_id: string;
        detail: string;
        inventory: { schema: string; members: number };
      };
    }
  ).structuredContent;
  expect(content.detail).toBe("summary");
  expect(content.inventory.schema).toBe("traceforge.app.summary.v1");
  expect(content.inventory.members).toBe(13);
  expect(await store.verify(content.evidence_id)).toBe(true);
  const complete = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "inspect_package",
        arguments: { path: bundle, detail: "complete" },
      },
    },
    options,
  );
  const inventory = (
    complete?.result as { structuredContent: { inventory: { schema: string } } }
  ).structuredContent.inventory;
  expect(inventory.schema).toBe("traceforge.app.inventory.v1");
  const missing = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "tools/call",
      params: { name: "inspect_package", arguments: { path: join(root, "absent.app") } },
    },
    options,
  );
  expect(
    (
      missing?.result as {
        isError?: boolean;
        structuredContent: { error: string };
      }
    ).structuredContent.error,
  ).toMatch(/Cannot read/u);
});

it("scans a real installed bundle and stays deterministic", async () => {
  if (process.platform !== "darwin") return;
  const candidates = [
    "/System/Applications/Calculator.app",
    "/System/Applications/TextEdit.app",
    "/System/Applications/Dictionary.app",
  ];
  const target = candidates.find((path) => existsSync(path));
  if (target === undefined) return;
  const root = await temporaryRoot("traceforge-real-package-");
  const store = new EvidenceStore(root);
  const first = await scanPackage(target, store, "0.2.0");
  const second = await scanPackage(target, undefined, "0.2.0");
  expect(first.inventory.kind).toBe("app");
  expect(first.inventory.layout).toBe("macos");
  expect(first.inventory.counts.files).toBeGreaterThan(4);
  expect(first.inventory.manifest?.claims.CFBundleExecutable ?? "").not.toBe("");
  expect(first.inventory.declared_executable.present).toBe(true);
  expect(
    first.inventory.files
      .filter((file) => file.format === "mach-o")
      .every((file) => file.architectures.length > 0),
  ).toBe(true);
  expect(second.inventory.tree_sha256).toBe(first.inventory.tree_sha256);
  expect(second.record.evidence_id).toBe(first.record.evidence_id);
  expect(await store.verify(first.record.evidence_id)).toBe(true);
}, 60_000);
