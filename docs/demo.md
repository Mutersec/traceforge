# Demo script

This is a three-minute live demo for two different audiences. Do not script
praise; show the artifact and ask for honest feedback. Every command below is
the real 0.3 surface — run it, do not describe it.

## The three-minute live flow (any audience)

Open a terminal in the repository (built with `npm run build`) and run, in
order:

```sh
# 1. What is actually inside an installed app? (nothing is executed)
node dist/cli.js app /Applications/AirStats.app

# 2. Turn that inventory into one standalone HTML report and open it
node dist/cli.js report /Applications/AirStats.app --out report.html
open report.html

# 3. Prove the record is tamper-evident: sign it, then verify it
node dist/cli.js evidence keygen            # once; prints the pk_ fingerprint
node dist/cli.js evidence sign <evidence_id printed above>
node dist/cli.js evidence verify <evidence_id> --public-key .traceforge/keys/<pk>.pub.pem

# 4. Audit the whole local store
node dist/cli.js evidence verify-all
```

Point at, in this order:

- the member list, nested packages and **manifest claims** in step 1 — say:
  "this is what is inside the app; it never ran the app; the identifiers are
  what the bundle *claims*, and the record says so";
- the green **identity verified** badge and the Evidence ID in the report;
- step 3's failure path if you have 30 spare seconds: edit one byte of the
  saved record JSON and re-run `verify` — it stops with
  `error [signature_mismatch]: The record changed after it was signed (record
  hash differs).`;
- `verify-all`: `N valid · 0 invalid` plus the `X signed · Y unsigned` line —
  unsigned is not an error.

End with: "Every number you saw came off this machine's disk. Nothing phoned
home. Re-run any command and the Evidence ID is identical."

For a non-technical guest, add the live site
(<https://mutersec.github.io/traceforge/>) first and the gallery
("four reports from one real machine") instead of steps 3–4.

## For a technical guest (5 minutes)

1. `tforge inspect /bin/ls --arch arm64` — one universal slice.
2. `tforge diff /bin/ls /usr/bin/true` — deterministic structural changes; the
   diff itself is an Evidence record.
3. `tforge app <App> --json --only files --limit 2` and follow
   `page.next_cursor` — paging and field selectors shape the *answer*, never
   the stored record.
4. `tforge evidence export bundle.json` and `tforge evidence import bundle.json`
   — portable, authenticated records.
5. Start MCP:

   ```sh
   node dist/cli.js mcp
   ```

   Show `tools/list` (six tools, fixed order), one `inspect_package` call, a
   `detail=complete` answer degrading under the 256 KiB ceiling, and
   `resources/read` on `traceforge://store`.
6. `npm run bench -- /bin/ls` — parser-only number, clearly separated from CLI
   startup time; CI's gate is a smoke ceiling, not a regression baseline.
7. Raise the version dependency on purpose: the same `/bin/ls` scanned under
   0.2.0 and 0.3.0 yields different Evidence IDs, because `tool.version` is
   part of the hashed content (see README "Determinism").
8. Open the GitHub Actions page: CI matrix (ubuntu + macos × Node 22/24),
   CodeQL and release workflow.

## Honest feedback questions

- Which task would you use this for, if any?
- What is missing before you would replace your current command?
- Is the report understandable without reading the code?
- Would you trust the Evidence ID and bundle in a release process?

Record actual answers; do not invent testimonials.
