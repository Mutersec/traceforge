# Demo script

This is a three-minute demo for two different audiences. Do not script praise;
show the artifact and ask for honest feedback.

## For a non-technical guest (3 minutes)

1. Open the live site: <https://mutersec.github.io/traceforge/>
   Say: “This is a local tool for inspecting software without running it.”
2. In a terminal:

   ```sh
   cd /path/to/traceforge
   npm run demo
   ```

3. Open `.cache/demo/traceforge-report.html` in a browser.
   Point out:
   - the green **identity verified** badge;
   - the file SHA-256 and Evidence ID;
   - sections, imports and exports in plain language;
   - the footer: *no target was executed*.
4. Show tamper evidence:

   ```sh
   tforge evidence verify <evidence_id>   # valid
   # edit a field in the JSON under .cache/demo/evidence
   tforge evidence verify <evidence_id>   # invalid or missing
   ```

   Message: “The record is not a screenshot; changing it makes verification
   fail.”

5. Ask: “Would this help you review a release or explain a binary to someone
   else? What would you want on the report?”

## For a technical guest (5 minutes)

1. `tforge inspect /bin/ls --arch arm64` — one universal slice.
2. `tforge diff /bin/ls /usr/bin/true` — deterministic structural changes.
3. `tforge evidence export bundle.json` and `tforge evidence import bundle.json`
   — portable, authenticated records.
4. Start MCP:

   ```sh
   node dist/cli.js mcp
   ```

   Show `scan_binary`, `inspect_binary`, `compare_binaries` and
   `get_evidence` from a JSON-RPC client.
5. `npm run bench -- /bin/ls` — parser-only number, clearly separated from CLI
   startup time.
6. Open the GitHub Actions page: CI, CodeQL and release workflow.

## Honest feedback questions

- Which task would you use this for, if any?
- What is missing before you would replace your current command?
- Is the report understandable without reading the code?
- Would you trust the Evidence ID and bundle in a release process?

Record actual answers; do not invent testimonials.
