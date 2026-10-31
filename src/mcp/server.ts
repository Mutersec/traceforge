import { createInterface } from "node:readline";

import { summarizeInventory } from "../core/binary.js";
import { compare, inspect, scanBinary } from "../core/operations.js";
import { EvidenceStore } from "../core/evidence.js";
import { TraceForgeError } from "../core/errors.js";

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

const toolResult = (payload: unknown, isError = false) => ({
  content: [
    {
      type: "text",
      text: JSON.stringify(payload, null, 2),
    },
  ],
  structuredContent: payload,
  ...(isError ? { isError: true } : {}),
});

const TOOLS: readonly ToolDefinition[] = [
  {
    name: "scan_binary",
    description: "Identify a local binary, hash it, and summarize its slices.",
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
      "Return sections, imports, exports, libraries, and build identity for a local binary. Read-only.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", minLength: 1 },
        detail: { type: "string", enum: ["summary", "complete"] },
      },
      required: ["path"],
      additionalProperties: false,
    },
  },
  {
    name: "compare_binaries",
    description: "Compare two local binaries by metadata, sections, imports, and exports.",
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
      );
      const detail = optionalStringArgument(args, "detail") ?? "complete";
      return toolResult({
        evidence_id: outcome.record.evidence_id,
        detail,
        inventory:
          detail === "summary" ? summarizeInventory(outcome.result) : outcome.result,
      });
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
          capabilities: { tools: {} },
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
