# Contributing

Thanks for helping make binary inspections easier to verify.

## Development

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run check
```

Use Node.js 22 or newer. The project has no runtime dependencies; keep it that
way unless a dependency removes a demonstrated risk or a meaningful amount of
code.

## Pull requests

- Keep each pull request focused and explain the observable outcome.
- Add or update tests for parser boundaries, Evidence integrity, CLI behavior,
  or MCP protocol changes.
- Include a malformed-input case when changing a parser.
- Preserve deterministic Evidence identities; do not add timestamps, random
  values, or host-specific paths to hashed content.
- Do not claim equivalence or completeness that the input cannot establish.
- Run `npm run check` before requesting review.

## Parser rules

- Validate offsets and sizes before reading.
- Bound counts, string lengths, and allocations.
- Prefer explicit limitations over guesses.
- Do not execute or attach to a target.
- Keep format interpretation in the parser that owns it; adapters should consume
  the parsed result rather than re-reading bytes.

## Commit style

Use Conventional Commit subjects, for example:

```text
feat: add PE delay-import inventory
fix: reject ELF section tables beyond the file
docs: document evidence verification
```

## License

By contributing, you agree that your contribution is licensed under the MIT
license in [LICENSE](LICENSE).
