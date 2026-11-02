import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, expect, it } from "vitest";

import { inspectBinary } from "../src/core/binary.js";
import { createEvidenceRecord, EvidenceStore } from "../src/core/evidence.js";
import { TraceForgeError } from "../src/core/errors.js";
import {
  INSPECT_FIELDS,
  MAX_PAGE_ITEMS,
  MAX_TOOL_TEXT_BYTES,
  parseOnly,
  pageItems,
} from "../src/core/paging.js";
import {
  SignatureStore,
  generateSigningKeyPair,
  signEvidenceRecord,
} from "../src/core/signature.js";
import { handleMcpMessage } from "../src/mcp/server.js";
import type { McpServerOptions } from "../src/mcp/server.js";
import { machoFixture, xmlPlistFixture } from "./fixtures.js";

const roots: string[] = [];
const temporaryRoot = async (prefix: string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

interface ToolCallResult {
  isError?: boolean;
  content: { type: string; text: string }[];
  structuredContent: Record<string, unknown>;
}

const toolCall = async (
  options: McpServerOptions,
  name: string,
  args: Record<string, unknown>,
): Promise<ToolCallResult> => {
  const response = await handleMcpMessage(
    { jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } },
    options,
  );
  return response?.result as ToolCallResult;
};

const errorOf = (run: () => unknown): TraceForgeError => {
  try {
    run();
  } catch (error) {
    if (error instanceof TraceForgeError) return error;
    throw error;
  }
  throw new Error("expected a TraceForgeError, none was thrown");
};

it("pageItems is deterministic and a cursor walk visits every item exactly once in order", () => {
  const items = Array.from({ length: 237 }, (_, index) => index);
  expect(pageItems(items, { limit: 50 })).toEqual(pageItems(items, { limit: 50 }));
  const first = pageItems(items, { limit: 50 });
  expect(first.items).toEqual(items.slice(0, 50));
  expect(first.next_cursor).toBe("50");
  expect(first.total).toBe(237);
  expect(first.limit).toBe(50);
  const visited: number[] = [];
  let cursor: string | undefined;
  for (;;) {
    const page = pageItems(items, { ...(cursor === undefined ? {} : { cursor }), limit: 50 });
    visited.push(...page.items);
    if (page.next_cursor === null) break;
    cursor = page.next_cursor;
    expect(visited.length).toBeLessThanOrEqual(items.length);
  }
  expect(visited).toEqual(items);
  const empty = pageItems(items, { cursor: "500", limit: 10 });
  expect(empty.items).toEqual([]);
  expect(empty.next_cursor).toBeNull();
});

it("rejects out-of-range limits and corrupt cursors with readable invalid_input errors", () => {
  const items = [1, 2, 3];
  let error = errorOf(() => pageItems(items, { limit: 0 }));
  expect(error.code).toBe("invalid_input");
  expect(error.message).toMatch(/between 1 and 500/u);
  error = errorOf(() => pageItems(items, { limit: MAX_PAGE_ITEMS + 1 }));
  expect(error.code).toBe("invalid_input");
  error = errorOf(() => pageItems(items, { limit: 1.5 }));
  expect(error.code).toBe("invalid_input");
  error = errorOf(() => pageItems(items, { cursor: "abc123" }));
  expect(error.code).toBe("invalid_input");
  expect(error.message).toMatch(/next_cursor/u);
  error = errorOf(() => pageItems(items, { cursor: "-1" }));
  expect(error.code).toBe("invalid_input");
});

it("only= drops unselected fields, names them in omitted, and keeps the no-parameter answer byte-identical", async () => {
  const root = await temporaryRoot("traceforge-paging-only-");
  const target = join(root, "sample.macho");
  await writeFile(target, machoFixture());
  const store = new EvidenceStore(join(root, "evidence"));
  const options = { store, version: "0.2.0" };
  const raw = await inspectBinary(target);
  const baseline = await toolCall(options, "inspect_binary", { path: target, detail: "complete" });
  expect(Object.keys(baseline.structuredContent)).toEqual(["evidence_id", "detail", "inventory"]);
  expect(baseline.content[0]?.text).toBe(
    JSON.stringify(
      { evidence_id: baseline.structuredContent.evidence_id, detail: "complete", inventory: raw },
      null,
      2,
    ),
  );
  const filtered = await toolCall(options, "inspect_binary", {
    path: target,
    detail: "complete",
    only: "sections,imports",
  });
  expect(Object.keys(filtered.structuredContent)).toEqual([
    "evidence_id",
    "detail",
    "inventory",
    "omitted",
  ]);
  expect(filtered.structuredContent.omitted).toEqual([
    "exports",
    "libraries",
    "provenance",
    "security",
  ]);
  const slice = (
    filtered.structuredContent.inventory as { slices: Record<string, unknown>[] }
  ).slices[0];
  expect(slice).toBeDefined();
  expect(Object.keys(slice ?? {})).toEqual(
    expect.arrayContaining(["sections", "imports"]),
  );
  for (const dropped of ["exports", "libraries", "provenance", "security"])
    expect(Object.keys(slice ?? {})).not.toContain(dropped);
  expect(filtered.structuredContent.evidence_id).toBe(baseline.structuredContent.evidence_id);
});

it("an unknown only field fails and the error states the allowed fields", async () => {
  const root = await temporaryRoot("traceforge-paging-unknown-");
  const target = join(root, "sample.macho");
  await writeFile(target, machoFixture());
  const options = { store: new EvidenceStore(join(root, "evidence")), version: "0.2.0" };
  const failed = await toolCall(options, "inspect_binary", { path: target, only: "sections,glitches" });
  expect(failed.isError).toBe(true);
  expect(failed.structuredContent.error).toMatch(
    /allowed fields are: sections, imports, exports, libraries, provenance, security/u,
  );
  expect(() => parseOnly("", INSPECT_FIELDS)).toThrow(/at least one field/u);
  expect(() => parseOnly("files", INSPECT_FIELDS)).toThrow(/Unknown --only field files/u);
  expect(() => parseOnly("bogus", ["files", "manifest", "nested", "limitations"])).toThrow(
    /allowed fields are: files, manifest, nested, limitations/u,
  );
});

it("caps one oversized tool answer below MAX_TOOL_TEXT_BYTES by degrading to summary", async () => {
  const root = await temporaryRoot("traceforge-paging-cap-");
  const bundle = join(root, "Big.app");
  const contents = join(bundle, "Contents", "MacOS");
  await mkdir(contents, { recursive: true });
  await writeFile(join(bundle, "Contents", "Info.plist"), xmlPlistFixture());
  const count = 2200;
  await Promise.all(
    Array.from({ length: count }, (_, index) =>
      writeFile(join(contents, `prog-${String(index).padStart(5, "0")}`), Buffer.from([index % 256])),
    ),
  );
  const options = { store: new EvidenceStore(join(root, "evidence")), version: "0.2.0" };
  const big = await toolCall(options, "inspect_package", { path: bundle, detail: "complete" });
  const text = big.content[0]?.text ?? "";
  expect(Buffer.byteLength(text, "utf8")).toBeLessThanOrEqual(MAX_TOOL_TEXT_BYTES);
  expect(big.structuredContent.truncated).toBe(true);
  expect(big.structuredContent.detail).toBe("summary");
  expect(big.structuredContent.hint).toBe("use detail=summary with cursor/limit");
  expect((big.structuredContent.inventory as { schema: string }).schema).toBe(
    "traceforge.app.summary.v1",
  );
  const oddDetail = await toolCall(options, "inspect_package", { path: bundle, detail: "full" });
  expect(oddDetail.structuredContent.detail).toBe("full");
  expect(oddDetail.structuredContent.truncated).toBeUndefined();
  const paged = await toolCall(options, "inspect_package", {
    path: bundle,
    detail: "complete",
    limit: 20,
  });
  expect(paged.structuredContent.truncated).toBeUndefined();
  expect((paged.structuredContent.inventory as { files: unknown[] }).files).toHaveLength(20);
  expect(paged.structuredContent.page).toMatchObject({ limit: 20, returned: 20, next_cursor: "20" });
  const again = await toolCall(options, "inspect_package", {
    path: bundle,
    detail: "complete",
    cursor: "20",
    limit: 20,
  });
  const once = await toolCall(options, "inspect_package", {
    path: bundle,
    detail: "complete",
    cursor: "20",
    limit: 20,
  });
  expect(once.content[0]?.text).toBe(again.content[0]?.text);
  expect((again.structuredContent.inventory as { files: { path: string }[] }).files[0]?.path).not.toBe(
    (paged.structuredContent.inventory as { files: { path: string }[] }).files[0]?.path,
  );
}, 60_000);

it("lists resources and reads a stored record back as the same JSON", async () => {
  const root = await temporaryRoot("traceforge-paging-resources-");
  const store = new EvidenceStore(join(root, "evidence"));
  const options = { store, version: "0.2.0" };
  const record = createEvidenceRecord(
    "scan",
    { path: "/tmp/example", sha256: "a".repeat(64), size: 3 },
    { format: "unknown" },
    [],
    "0.2.0",
  );
  await store.put(record);
  const listed = await handleMcpMessage({ jsonrpc: "2.0", id: 1, method: "resources/list" }, options);
  const uris = ((listed?.result as { resources: { uri: string }[] }).resources).map(
    (resource) => resource.uri,
  );
  expect(uris).toEqual(["traceforge://evidence", "traceforge://store"]);
  const templates = await handleMcpMessage(
    { jsonrpc: "2.0", id: 2, method: "resources/templates/list" },
    options,
  );
  expect(
    ((templates?.result as { resourceTemplates: { uriTemplate: string }[] }).resourceTemplates[0]
      ?.uriTemplate),
  ).toBe("traceforge://evidence/{evidence_id}");
  const read = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 3,
      method: "resources/read",
      params: { uri: `traceforge://evidence/${record.evidence_id}` },
    },
    options,
  );
  const contents = (read?.result as { contents: { text: string }[] }).contents;
  expect(JSON.parse(contents[0]?.text ?? "null")).toEqual(record);
  const missing = await handleMcpMessage(
    {
      jsonrpc: "2.0",
      id: 4,
      method: "resources/read",
      params: { uri: `traceforge://evidence/ev_${"0".repeat(64)}` },
    },
    options,
  );
  expect(missing?.error?.code).toBe(-32001);
  expect(missing?.error?.message).toMatch(/evidence_not_found/u);
  const unknown = await handleMcpMessage(
    { jsonrpc: "2.0", id: 5, method: "resources/read", params: { uri: "traceforge://keys" } },
    options,
  );
  expect(unknown?.error?.code).toBe(-32602);
  expect(unknown?.error?.message).toMatch(/Unknown resource/u);
});

it("summarizes the store resource without ever surfacing a private key", async () => {
  const root = await temporaryRoot("traceforge-paging-store-");
  const store = new EvidenceStore(join(root, "evidence"));
  const options = { store, version: "0.2.0" };
  const signatures = new SignatureStore(store);
  const pair = generateSigningKeyPair();
  await signatures.putKeyPair(pair);
  const record = createEvidenceRecord(
    "scan",
    { path: "/tmp/example", sha256: "b".repeat(64), size: 1 },
    {},
    [],
    "0.2.0",
  );
  await store.put(record);
  await signatures.put(signEvidenceRecord(record, pair.privateKeyPem, "0.2.0"));
  const read = await handleMcpMessage(
    { jsonrpc: "2.0", id: 1, method: "resources/read", params: { uri: "traceforge://store" } },
    options,
  );
  const text = ((read?.result as { contents: { text: string }[] }).contents[0] ?? { text: "" }).text;
  expect(text).not.toContain("BEGIN PRIVATE KEY");
  expect(text).not.toContain("PRIVATE KEY");
  expect(text).not.toContain(pair.privateKeyPem.trim());
  expect(JSON.parse(text)).toMatchObject({
    schema: "traceforge.store.summary.v1",
    records: 1,
    valid: 1,
    signed: 1,
    unsigned: 0,
    signatures_directory_present: true,
  });
});

it("keeps the six tool names in order and advertises resources in initialize", async () => {
  const root = await temporaryRoot("traceforge-paging-tools-");
  const options = { store: new EvidenceStore(join(root, "evidence")), version: "0.2.0" };
  const listed = await handleMcpMessage({ jsonrpc: "2.0", id: 1, method: "tools/list" }, options);
  expect(
    ((listed?.result as { tools: { name: string }[] }).tools).map((tool) => tool.name),
  ).toEqual([
    "scan_binary",
    "inspect_binary",
    "inspect_package",
    "compare_binaries",
    "get_evidence",
    "list_evidence",
  ]);
  const initialized = await handleMcpMessage(
    { jsonrpc: "2.0", id: 2, method: "initialize", params: {} },
    options,
  );
  expect((initialized?.result as { capabilities: unknown }).capabilities).toMatchObject({
    tools: {},
    resources: {},
  });
});

it("shrinks a real /bin/ls answer with only and page parameters", async () => {
  if (process.platform !== "darwin") return;
  const root = await temporaryRoot("traceforge-paging-live-");
  const options = { store: new EvidenceStore(join(root, "evidence")), version: "0.2.0" };
  const full = await toolCall(options, "inspect_binary", { path: "/bin/ls", detail: "complete" });
  const fullBytes = Buffer.byteLength(full.content[0]?.text ?? "", "utf8");
  expect(fullBytes).toBeLessThanOrEqual(MAX_TOOL_TEXT_BYTES);
  expect(full.structuredContent.truncated).toBeUndefined();
  const selected = await toolCall(options, "inspect_binary", {
    path: "/bin/ls",
    detail: "complete",
    only: "sections",
  });
  const selectedBytes = Buffer.byteLength(selected.content[0]?.text ?? "", "utf8");
  expect(selectedBytes).toBeLessThan(fullBytes);
  const paged = await toolCall(options, "inspect_binary", {
    path: "/bin/ls",
    detail: "complete",
    limit: 5,
  });
  expect(Buffer.byteLength(paged.content[0]?.text ?? "", "utf8")).toBeLessThan(selectedBytes);
  expect(paged.structuredContent.page).toMatchObject({ limit: 5, next_cursor: "5" });
  let cursor: string | undefined;
  let pages = 0;
  for (;;) {
    const step = await toolCall(options, "inspect_binary", {
      path: "/bin/ls",
      detail: "complete",
      limit: 5,
      ...(cursor === undefined ? {} : { cursor }),
    });
    const page = step.structuredContent.page as { next_cursor: string | null };
    pages += 1;
    expect(Buffer.byteLength(step.content[0]?.text ?? "", "utf8")).toBeLessThanOrEqual(
      MAX_TOOL_TEXT_BYTES,
    );
    if (page.next_cursor === null) break;
    cursor = page.next_cursor;
    expect(pages).toBeLessThan(80);
  }
  expect(pages).toBeGreaterThan(5);
}, 30_000);
