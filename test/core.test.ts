import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it } from "vitest";

import { inspectBinary } from "../src/core/binary.js";
import { canonicalJson, evidenceId } from "../src/core/canonical.js";
import { EvidenceStore, createEvidenceRecord } from "../src/core/evidence.js";
import { compare, scanBinary } from "../src/core/operations.js";
import { handleMcpMessage } from "../src/mcp/server.js";
import { elfFixture, peFixture, wasmFixture } from "./fixtures.js";

const roots: string[] = [];
const temporaryRoot = async (prefix: string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

it("canonical JSON and Evidence IDs are deterministic", () => {
  expect(canonicalJson({ b: 1, a: { d: 2, c: null } })).toBe(
    '{"a":{"c":null,"d":2},"b":1}',
  );
  expect(evidenceId({ b: 1, a: 2 })).toBe(evidenceId({ a: 2, b: 1 }));
  expect(evidenceId({ a: 1 })).toMatch(/^ev_[a-f0-9]{64}$/u);
});

it("stores, lists and authenticates Evidence records", async () => {
  const root = await temporaryRoot("traceforge-evidence-");
  const store = new EvidenceStore(root);
  const record = createEvidenceRecord(
    "scan",
    { path: "/tmp/example", sha256: "a".repeat(64), size: 4 },
    { format: "unknown" },
    ["test"],
    "0.1.0",
  );
  await store.put(record);
  expect(await store.get(record.evidence_id)).toEqual(record);
  expect(await store.verify(record.evidence_id)).toBe(true);
  expect(await store.list()).toEqual([
    {
      evidence_id: record.evidence_id,
      operation: "scan",
      path: "/tmp/example",
      sha256: "a".repeat(64),
      size: 4,
    },
  ]);
  const path = join(root, `${record.evidence_id}.json`);
  await writeFile(path, JSON.stringify({ ...record, result: { tampered: true } }));
  expect(await store.verify(record.evidence_id)).toBe(false);
  await expect(store.get(record.evidence_id)).rejects.toThrow(/does not match/u);
});

it("parses synthetic ELF, PE and WASM fixtures", async () => {
  const root = await temporaryRoot("traceforge-fixtures-");
  const elfPath = join(root, "fixture.elf");
  const pePath = join(root, "fixture.exe");
  const wasmPath = join(root, "fixture.wasm");
  await Promise.all([
    writeFile(elfPath, elfFixture()),
    writeFile(pePath, peFixture()),
    writeFile(wasmPath, wasmFixture()),
  ]);
  const elf = await inspectBinary(elfPath);
  expect(elf.format).toBe("elf");
  expect(elf.slices[0]?.architecture).toBe("x86_64");
  expect(elf.slices[0]?.entrypoint).toBe("0x401000");
  expect(elf.slices[0]?.sections.map((section) => section.name)).toEqual(
    expect.arrayContaining([".shstrtab", ".text"]),
  );
  const pe = await inspectBinary(pePath);
  expect(pe.format).toBe("pe");
  expect(pe.slices[0]?.architecture).toBe("x86_64");
  expect(pe.slices[0]?.entrypoint).toBe("0x1000");
  expect(pe.slices[0]?.imports).toContain("KERNEL32.dll!CreateFileA");
  expect(pe.slices[0]?.libraries).toContain("KERNEL32.dll");
  const wasm = await inspectBinary(wasmPath);
  expect(wasm.format).toBe("wasm");
  expect(wasm.slices[0]?.sections[0]?.name).toBe("custom:meta");
});

it("scans and diffs a real macOS Mach-O on arm64", async () => {
  if (process.platform !== "darwin") return;
  const root = await temporaryRoot("traceforge-macho-");
  const store = new EvidenceStore(root);
  const scanned = await scanBinary("/bin/ls", store, "0.1.0");
  expect(scanned.result.format).toBe("mach-o");
  expect(scanned.result.slices.length).toBeGreaterThan(0);
  expect(scanned.result.slices.some((slice) => slice.architecture.startsWith("arm64"))).toBe(true);
  expect(await store.verify(scanned.record.evidence_id)).toBe(true);
  const compared = await compare("/bin/ls", "/usr/bin/true", store, "0.1.0");
  expect(compared.result.changed).toBe(true);
  expect(compared.result.changes.slices_added.length + compared.result.changes.slices_removed.length +
    compared.result.changes.sections_changed.length).toBeGreaterThan(0);
}, 30_000);

it("handles an MCP initialize, tools/list and scan call", async () => {
  const root = await temporaryRoot("traceforge-mcp-");
  const store = new EvidenceStore(root);
  const options = { store, version: "0.1.0" };
  const initialized = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18" },
    },
    options,
  );
  expect(initialized).toMatchObject({
    jsonrpc: "2.0",
    id: 1,
    result: { serverInfo: { name: "traceforge" }, capabilities: { tools: {} } },
  });
  const listed = await handleMcpMessage(
    { jsonrpc: "2.0", id: 2, method: "tools/list" },
    options,
  );
  expect(
    (listed?.result as { tools: { name: string }[] }).tools.map((tool) => tool.name),
  ).toEqual([
    "scan_binary",
    "inspect_binary",
    "compare_binaries",
    "get_evidence",
    "list_evidence",
  ]);
  if (process.platform !== "darwin") return;
  const scanned = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: { name: "scan_binary", arguments: { path: "/bin/ls" } },
    },
    options,
  );
  const result = scanned?.result as {
    structuredContent: { evidence_id: string; result: { format: string } };
  };
  expect(result.structuredContent.result.format).toBe("mach-o");
  expect(await store.verify(result.structuredContent.evidence_id)).toBe(true);
}, 30_000);
