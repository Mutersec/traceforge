# MCP server

TraceForge uses newline-delimited JSON-RPC 2.0 over stdio. It has no runtime
MCP SDK dependency and starts only when `tforge mcp` is invoked.

## Client configuration

```json
{
  "mcpServers": {
    "traceforge": {
      "command": "node",
      "args": ["/absolute/path/to/traceforge/dist/cli.js", "mcp"]
    }
  }
}
```

Set `--store /absolute/path` after `mcp` to use a non-default Evidence store.

## Tools

### `scan_binary`

```json
{ "path": "/bin/ls" }
```

Returns a complete Evidence record whose result is a compact slice summary.

### `inspect_binary`

```json
{ "path": "/bin/ls", "detail": "summary", "architecture": "arm64" }
```

`summary` returns slice collection counts; `complete` (default) returns the
complete inventory. `architecture` optionally selects one universal slice. The complete Evidence record is retained in both cases.

Optional agent ergonomics:

- `only`: comma-separated fields to keep, from `sections, imports, exports,
  libraries, provenance, security`. Every other selectable field is removed
  from the answer and named in the response's `omitted` list. Unknown fields
  fail with `invalid_input` and the allowed list. Identity fields (path,
  sha256, architecture, entrypoint, counts) are never selectable.
- `cursor` + `limit`: pages the per-slice `sections`, `imports`, `exports`
  and `libraries` lists with one fixed offset window (`limit` 1-500, default
  100). The response gains a `page` object (`limit`, `returned`, `total`,
  `next_cursor`); pass `next_cursor` back as `cursor` for the next page, or
  omit it to start again. A list shorter than the window returns empty in
  later pages, so a full cursor walk visits every entry exactly once.

### `inspect_package`

```json
{ "path": "/Applications/Obsidian.app", "detail": "summary" }
```

Recursively inventories a package directory: one entry per member with size,
SHA-256, kind and detected format, plus the identity the bundle manifest
declares. `summary` (default) returns counts, the manifest and the largest code
members; `complete` returns every inventoried member. Archives are not opened
and symbolic links are never followed. The full `app` Evidence record is
retained in both cases.

Same optional parameters, different selector namespace: `only` accepts
`files, manifest, nested, limitations` (`files` also covers the summary's
`code` list; `manifest` also covers `pkg_info` and `declared_executable`),
and `cursor`/`limit` page the `files` list (or `code` in summary detail).

Paging is a transport convenience, not an evidence boundary — the stored
record stays complete.

### `compare_binaries`

```json
{ "left_path": "/bin/ls", "right_path": "/usr/bin/true" }
```

Returns one comparison Evidence record with format, size, slice, section,
import and export changes.

### `get_evidence`

```json
{ "evidence_id": "ev_..." }
```

Reads and authenticates a local record.

### `list_evidence`

Returns summaries only; full records are fetched with `get_evidence`.

## Response size ceiling

One tool answer's serialized text is capped at 262,144 bytes (256 KiB). If a
`detail=complete` answer would exceed the cap, the tool automatically degrades
to `detail=summary` and adds `"truncated": true` plus
`"hint": "use detail=summary with cursor/limit"` to the wrapper. If even the
summary would overflow, the inventory is reduced to a minimal identity stub.
An answer is never silently cut mid-record; `get_evidence` and the Evidence
resource below deliberately return the complete stored record.

## Resources

The server also exposes read-only MCP resources (`resources/list`,
`resources/templates/list`, `resources/read`). `initialize` advertises
`capabilities: { tools: {}, resources: {} }`.

| URI | Content |
|---|---|
| `traceforge://evidence` | The same summaries as `list_evidence`. |
| `traceforge://evidence/{evidence_id}` | The complete JSON of one authenticated record. A missing record returns a JSON-RPC error object (`-32001`), never an exception. |
| `traceforge://store` | Store summary: record count, valid/invalid, signed/unsigned, signature errors, whether the `signatures` directory exists. Key files are never read or returned by any path. |

An unknown resource URI answers `-32602`. Unknown JSON-RPC methods keep
answering `-32601`.

## Errors

Tool failures are returned as `isError: true` with a text error object. Invalid
JSON-RPC requests use standard JSON-RPC error codes. The server never writes
non-protocol data to stdout; diagnostics belong on stderr.
