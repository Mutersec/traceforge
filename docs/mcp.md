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

## Errors

Tool failures are returned as `isError: true` with a text error object. Invalid
JSON-RPC requests use standard JSON-RPC error codes. The server never writes
non-protocol data to stdout; diagnostics belong on stderr.
