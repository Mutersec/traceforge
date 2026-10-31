# Security policy

## Supported versions

Security fixes are applied to the latest published release.

## Reporting

Please use **GitHub private vulnerability reporting** on this repository:
Security → Report a vulnerability.

Do not open a public issue for a suspected vulnerability. Include:

- the affected version and platform,
- the input format and a minimal reproducer when safe,
- whether the target was executed (TraceForge should never execute it),
- the observed impact and any evidence record IDs.

## Security model

TraceForge is a read-only inspector:

- it does not launch, attach to, or modify analyzed binaries;
- it reads local files only and makes no network requests;
- it rejects files larger than 512 MiB before parsing;
- section hashing is capped at 64 MiB per section;
- parser counts and string lengths are bounded;
- Evidence is stored atomically with owner-only permissions.

Malformed binaries can still exercise parser bugs. Treat untrusted inputs as
untrusted and run TraceForge in the environment appropriate for that risk.
