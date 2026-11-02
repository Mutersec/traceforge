import { createInterface } from "node:readline";
import { readdir } from "node:fs/promises";

import { summarizePackage } from "../core/app.js";
import { summarizeInventory } from "../core/binary.js";
import { compare, inspect, scanBinary, scanPackage } from "../core/operations.js";
import { EvidenceStore } from "../core/evidence.js";
import { TraceForgeError } from "../core/errors.js";
import {
  INSPECT_FIELDS,
  MAX_PAGE_ITEMS,
  MAX_TOOL_TEXT_BYTES,
  PACKAGE_FIELDS,
  pageBinaryLists,
  pageNamedList,
  parseOnly,
  selectInspectFields,
  selectPackageFields,
} from "../core/paging.js";
import type { PageRequest } from "../core/paging.js";
import { SignatureStore } from "../core/signature.js";
import type { AppInventory, BinaryInventory } from "../core/types.js";

export interface McpServerOptions {
  readonly store: EvidenceStore;
  readonly version: string;
  readonly input?: NodeJS.ReadableStream;
  readonly output?: NodeJS.WritableStream;
}

interface JsonRpcRequest {
  readonly jsonrpc?: string;
  readonly id?: string | number | null;
  readonly method?: string;
  readonly params?: unknown;
}

interface JsonRpcResponse {
  readonly jsonrpc: "2.0";
  readonly id: string | number | null;
  readonly result?: unknown;
  readonly error?: { readonly code: number; readonly message: string };
}

interface ToolDefinition {
  readonly name: string;
  readonly description: string;
  readonly inputSchema: Record<string, unknown>;
}

type InspectMode = "complete" | "summary" | "minimal";

const stringArgument = (args: unknown, name: string): string => {
  if (args === null || typeof args !== "object")
    throw new TraceForgeError("invalid_input", "Tool arguments must be an object");
  const value = (args as Record<string, unknown>)[name];
  if (typeof value !== "string" || value.length === 0)
    throw new TraceForgeError("invalid_input", `Argument ${name} must be a non-empty string`);
  return value;
};

const optionalStringArgument = (args: unknown, name: string): string | undefined => {
  if (args === null || typeof args !== "object") return undefined;
  const value = (args as Record<string, unknown>)[name];
  return typeof value === "string" ? value : undefined;
};

const rawArgument = (args: unknown, name: string): unknown =>
  args !== null && typeof args === "object"
    ? (args as Record<string, unknown>)[name]
    : undefined;

const onlyArgument = (args: unknown, allowed: readonly string[]): readonly string[] | null => {
  const raw = optionalStringArgument(args, "only");
  return raw === undefined ? null : parseOnly(raw, allowed);
};

const pageArgument = (args: unknown): PageRequest | null => {
  const cursor = optionalStringArgument(args, "cursor");
  const limit = rawArgument(args, "limit");
  if (cursor === undefined && limit === undefined) return null;
  if (limit !== undefined && typeof limit !== "number")
    throw new TraceForgeError(
      "invalid_input",
      `The page limit must be a number between 1 and ${MAX_PAGE_ITEMS}`,
    );
  return {
    ...(cursor === undefined ? {} : { cursor }),
    ...(limit === undefined ? {} : { limit }),
  };
};

const toolText = (payload: unknown): string => JSON.stringify(payload, null, 2);

const textBytes = (payload: unknown): number => Buffer.byteLength(toolText(payload), "utf8");

const toolResult = (payload: unknown, isError = false) => ({
  content: [
    {
      type: "text",
      text: toolText(payload),
    },
  ],
  structuredContent: payload,
  ...(isError ? { isError: true } : {}),
});

const SIZE_HINT = "use detail=summary with cursor/limit";

const bounded = (
  build: (mode: InspectMode) => Record<string, unknown>,
  mode: InspectMode,
): Record<string, unknown> => {
  const direct = build(mode);
  if (textBytes(direct) <= MAX_TOOL_TEXT_BYTES) return direct;
  if (mode === "complete") {
    const fallback = build("summary");
    if (textBytes(fallback) <= MAX_TOOL_TEXT_BYTES)
      return { ...fallback, truncated: true, hint: SIZE_HINT };
  }
  return { ...build("minimal"), truncated: true, hint: SIZE_HINT };
};

const minimalBinaryIdentity = (inventory: BinaryInventory): object => ({
  schema: "traceforge.scan.minimal.v1",
  path: inventory.path,
  sha256: inventory.sha256,
  size: inventory.size,
  format: inventory.format,
  slices: inventory.slices.length,
});

const minimalPackageIdentity = (inventory: AppInventory): object => ({
  schema: "traceforge.app.minimal.v1",
  path: inventory.path,
  kind: inventory.kind,
  layout: inventory.layout,
  tree_sha256: inventory.tree_sha256,
  total_bytes: inventory.total_bytes,
  counts: inventory.counts,
  members: inventory.files.length,
});

const PAGING_SCHEMA = {
  only: {
    type: "string",
    description:
      "Comma-separated fields to keep; every other selectable field is removed from the answer and named in omitted.",
  },
  cursor: {
    type: "string",
    description: "Offset cursor from a previous next_cursor.",
  },
  limit: {
    type: "integer",
    minimum: 1,
    maximum: MAX_PAGE_ITEMS,
    description: `Items per page (1-${MAX_PAGE_ITEMS}, default 100).`,
  },
} as const;

const TOOLS: readonly ToolDefinition[] = [
  {
    name: "scan_binary",
    description:
      "Identify a local binary, hash it, and summarize its slices with observed mitigation names.",
    inputSchema: {
      type: "object",
      properties: { path: { type: "string", minLength: 1 } },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_binary",
    description:
      "Return sections, imports, exports, libraries, build identity, structural mitigations, and self-reported provenance claims for a local binary. Read-only; nothing is executed or validated. only/cursor/limit keep one answer bounded; oversized answers degrade to summary detail with truncated=true. The stored Evidence record always stays complete.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", minLength: 1 },
        detail: { type: "string", enum: ["summary", "complete"] },
        architecture: { type: "string", minLength: 1 },
        ...PAGING_SCHEMA,
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "inspect_package",
    description:
      "Recursively inventory a local .app, .framework or directory: one entry per member with size, SHA-256 and format, plus the identity claims its bundle manifest makes. Read-only; archives are not opened and symbolic links are never followed. detail=summary returns counts and the largest code members, detail=complete returns every member. only/cursor/limit keep one answer bounded; oversized answers degrade to summary detail with truncated=true. The stored Evidence record always stays complete.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", minLength: 1 },
        detail: { type: "string", enum: ["summary", "complete"] },
        ...PAGING_SCHEMA,
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "compare_binaries",
    description:
      "Compare two local binaries by metadata, sections, imports, exports, and mitigation changes.",
    inputSchema: {
      type: "object",
      properties: {
        left_path: { type: "string", minLength: 1 },
        right_path: { type: "string", minLength: 1 },
      },
      required: ["left_path", "right_path"],
      additionalProperties: false,
    },
  },
  {
    name: "get_evidence",
    description: "Read one content-addressed Evidence record from the local store.",
    inputSchema: {
      type: "object",
      properties: { evidence_id: { type: "string", minLength: 1 } },
      required: ["evidence_id"],
      additionalProperties: false,
    },
  },
  {
    name: "list_evidence",
    description: "List local Evidence summaries without copying full records.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
  },
];

const callTool = async (
  name: string,
  args: unknown,
  options: McpServerOptions,
): Promise<unknown> => {
  switch (name) {
    case "scan_binary": {
      const outcome = await scanBinary(
        stringArgument(args, "path"),
        options.store,
        options.version,
      );
      return toolResult(outcome.record);
    }
    case "inspect_binary": {
      const outcome = await inspect(
        stringArgument(args, "path"),
        options.store,
        options.version,
        optionalStringArgument(args, "architecture"),
      );
      const detail = optionalStringArgument(args, "detail") ?? "complete";
      const keep = onlyArgument(args, INSPECT_FIELDS);
      const request = pageArgument(args);
      const requested: InspectMode = detail === "summary" ? "summary" : "complete";
      const build = (mode: InspectMode): Record<string, unknown> => {
        const base: object =
          mode === "minimal"
            ? minimalBinaryIdentity(outcome.result)
            : mode === "summary"
              ? summarizeInventory(outcome.result)
              : outcome.result;
        const selection = keep === null ? null : selectInspectFields(base, keep);
        let value: object = selection === null ? base : selection.value;
        const paged = request === null ? null : pageBinaryLists(value, request);
        if (paged !== null) value = paged.value;
        return {
          evidence_id: outcome.record.evidence_id,
          detail: mode === requested ? detail : "summary",
          ...(paged === null ? {} : { page: paged.page }),
          inventory: value,
          ...(selection === null ? {} : { omitted: selection.omitted }),
        };
      };
      return toolResult(bounded(build, requested));
    }
    case "inspect_package": {
      const outcome = await scanPackage(
        stringArgument(args, "path"),
        options.store,
        options.version,
      );
      const detail = optionalStringArgument(args, "detail") ?? "summary";
      const keep = onlyArgument(args, PACKAGE_FIELDS);
      const request = pageArgument(args);
      const requested: InspectMode = detail === "complete" ? "complete" : "summary";
      const build = (mode: InspectMode): Record<string, unknown> => {
        const base: object =
          mode === "minimal"
            ? minimalPackageIdentity(outcome.inventory)
            : mode === "complete"
              ? outcome.inventory
              : summarizePackage(outcome.inventory);
        const selection = keep === null ? null : selectPackageFields(base, keep);
        let value: object = selection === null ? base : selection.value;
        const paged =
          request === null
            ? null
            : pageNamedList(value, mode === "complete" ? "files" : "code", request);
        if (paged !== null) value = paged.value;
        return {
          evidence_id: outcome.record.evidence_id,
          detail: mode === requested ? detail : "summary",
          ...(paged === null ? {} : { page: paged.page }),
          inventory: value,
          ...(selection === null ? {} : { omitted: selection.omitted }),
        };
      };
      return toolResult(bounded(build, requested));
    }
    case "compare_binaries": {
      const outcome = await compare(
        stringArgument(args, "left_path"),
        stringArgument(args, "right_path"),
        options.store,
        options.version,
      );
      return toolResult(outcome.record);
    }
    case "get_evidence":
      return toolResult(await options.store.get(stringArgument(args, "evidence_id")));
    case "list_evidence":
      return toolResult({ evidence: await options.store.list() });
    default:
      throw new TraceForgeError("invalid_input", `Unknown tool: ${name}`);
  }
};

const EVIDENCE_INDEX_URI = "traceforge://evidence";
const STORE_URI = "traceforge://store";
const EVIDENCE_RECORD_URI = /^traceforge:\/\/evidence\/(ev_[a-f0-9]{64})$/u;

const RESOURCES: readonly Record<string, string>[] = [
  {
    uri: EVIDENCE_INDEX_URI,
    name: "evidence_index",
    title: "Evidence summaries",
    description:
      "One summary per authenticated record in the local store; the same list the list_evidence tool returns.",
    mimeType: "application/json",
  },
  {
    uri: STORE_URI,
    name: "store_summary",
    title: "Evidence store summary",
    description:
      "Record count, integrity result and signature state of the local store. Key files under the keys directory are never read or returned.",
    mimeType: "application/json",
  },
];

const RESOURCE_TEMPLATES: readonly Record<string, string>[] = [
  {
    uriTemplate: "traceforge://evidence/{evidence_id}",
    name: "evidence_record",
    title: "One full Evidence record",
    description:
      "The complete JSON of a single authenticated record, read-only. Paging is a transport convenience, not an evidence boundary.",
    mimeType: "application/json",
  },
];

const resourceContents = (uri: string, value: unknown): unknown => ({
  contents: [{ uri, mimeType: "application/json", text: JSON.stringify(value, null, 2) }],
});

const directoryPresent = (path: string): Promise<boolean> =>
  readdir(path).then(
    () => true,
    () => false,
  );

const storeSummary = async (options: McpServerOptions): Promise<unknown> => {
  const verified = await options.store.verifyAll();
  const summaries = await options.store.list();
  const signatures = new SignatureStore(options.store);
  let signed = 0;
  const signatureErrors: { evidence_id: string; error: string }[] = [];
  for (const summary of summaries) {
    try {
      await signatures.verify(summary.evidence_id);
      signed += 1;
    } catch (error) {
      if (error instanceof TraceForgeError && error.code === "signature_not_found") continue;
      signatureErrors.push({
        evidence_id: summary.evidence_id,
        error:
          error instanceof TraceForgeError
            ? error.message
            : "The signature could not be checked.",
      });
    }
  }
  return {
    schema: "traceforge.store.summary.v1",
    records: summaries.length,
    valid: verified.valid,
    invalid: verified.invalid,
    signed,
    unsigned: summaries.length - signed,
    signature_errors: signatureErrors,
    signatures_directory_present: await directoryPresent(signatures.root),
    note: "Key files are never read or returned by this resource; only counts and state are.",
  };
};

export const handleMcpMessage = async (
  message: unknown,
  options: McpServerOptions,
): Promise<JsonRpcResponse | undefined> => {
  if (message === null || typeof message !== "object")
    return {
      jsonrpc: "2.0",
      id: null,
      error: { code: -32600, message: "Invalid Request" },
    };
  const request = message as JsonRpcRequest;
  const id = request.id ?? null;
  if (request.jsonrpc !== "2.0" || typeof request.method !== "string")
    return { jsonrpc: "2.0", id, error: { code: -32600, message: "Invalid Request" } };
  if (request.id === undefined) return undefined;
  switch (request.method) {
    case "initialize": {
      const params = request.params as { protocolVersion?: unknown } | undefined;
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion:
            typeof params?.protocolVersion === "string"
              ? params.protocolVersion
              : "2025-06-18",
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: "traceforge", version: options.version },
        },
      };
    }
    case "ping":
      return { jsonrpc: "2.0", id, result: {} };
    case "tools/list":
      return { jsonrpc: "2.0", id, result: { tools: TOOLS } };
    case "tools/call": {
      const params = request.params as { name?: unknown; arguments?: unknown } | undefined;
      if (typeof params?.name !== "string")
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "tools/call requires a tool name" },
        };
      try {
        const result = await callTool(params.name, params.arguments, options);
        return { jsonrpc: "2.0", id, result };
      } catch (error) {
        const messageText =
          error instanceof TraceForgeError
            ? `[${error.code}] ${error.message}`
            : error instanceof Error
              ? error.message
              : String(error);
        return {
          jsonrpc: "2.0",
          id,
          result: toolResult({ error: messageText }, true),
        };
      }
    }
    case "resources/list":
      return { jsonrpc: "2.0", id, result: { resources: RESOURCES } };
    case "resources/templates/list":
      return { jsonrpc: "2.0", id, result: { resourceTemplates: RESOURCE_TEMPLATES } };
    case "resources/read": {
      const params = request.params as { uri?: unknown } | undefined;
      if (typeof params?.uri !== "string" || params.uri.length === 0)
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: "resources/read requires a uri" },
        };
      const uri = params.uri;
      if (uri === EVIDENCE_INDEX_URI)
        return {
          jsonrpc: "2.0",
          id,
          result: resourceContents(uri, { evidence: await options.store.list() }),
        };
      if (uri === STORE_URI)
        return {
          jsonrpc: "2.0",
          id,
          result: resourceContents(uri, await storeSummary(options)),
        };
      const match = EVIDENCE_RECORD_URI.exec(uri);
      const evidenceId = match?.[1];
      if (evidenceId === undefined)
        return {
          jsonrpc: "2.0",
          id,
          error: { code: -32602, message: `Unknown resource: ${uri}` },
        };
      try {
        return {
          jsonrpc: "2.0",
          id,
          result: resourceContents(uri, await options.store.get(evidenceId)),
        };
      } catch (error) {
        return {
          jsonrpc: "2.0",
          id,
          error: {
            code: -32001,
            message:
              error instanceof TraceForgeError
                ? `[${error.code}] ${error.message}`
                : "Evidence resource could not be read",
          },
        };
      }
    }
    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${request.method}` },
      };
  }
};

/** Dependency-free MCP stdio server using one JSON-RPC message per line. */
export const runMcpServer = async (options: McpServerOptions): Promise<void> => {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const readline = createInterface({ input, crlfDelay: Infinity });
  for await (const line of readline) {
    if (line.trim().length === 0) continue;
    let message: unknown;
    try {
      message = JSON.parse(line);
    } catch {
      output.write(
        `${JSON.stringify({
          jsonrpc: "2.0",
          id: null,
          error: { code: -32700, message: "Parse error" },
        })}\n`,
      );
      continue;
    }
    const response = await handleMcpMessage(message, options);
    if (response !== undefined) output.write(`${JSON.stringify(response)}\n`);
  }
};
