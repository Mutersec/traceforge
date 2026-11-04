# Signing Evidence

TraceForge can attach a detached Ed25519 signature to one Evidence record. The
signature answers exactly one question: **this record was produced under this
private key, and not one byte of it has changed since.** Nothing more.

Keys come from Node's own `crypto` module. TraceForge still has zero runtime
dependencies.

## The model

- A key pair is Ed25519. The private half is a PKCS#8 PEM, the public half an
  SPKI PEM. The key fingerprint is `pk_` plus the SHA-256 (hex) of the public
  key's DER encoding.
- A signature covers the ASCII message

  ```
  traceforge.signature.v1\n<record_sha256>
  ```

  where `record_sha256` is the SHA-256 of the record's canonical JSON as it
  sits on disk. The prefix is domain separation: the signature is valid for
  this exact purpose and schema and cannot be replayed against a bare hash, a
  future schema version, or any other system that happens to sign hashes.
- Ed25519 is deterministic. The same key signing the same record always
  produces the same signature bytes, so a signature can be reproduced and
  compared, not just re-verified.
- The sidecar content is hashed content-free: it carries no timestamp and no
  random value. `canonicalJson` keeps its byte layout stable.

## Files

```
.traceforge/evidence/<ev_id>.json      the record (authenticated by its ID)
.traceforge/signatures/<ev_id>.sig.json  the detached signature (sidecar)
.traceforge/keys/<pk_fingerprint>.pem  private key, PKCS#8, 0600
.traceforge/keys/<pk_fingerprint>.pub.pem public key, SPKI, 0600
```

`signatures/` and `keys/` sit beside `evidence/`, derived from the store root
(`<store>/../signatures`), so `--store` moves all three together. Everything
under `.traceforge/` is git-ignored; nothing here is ever meant to be
committed. Sidecars and keys are written atomically (temp file plus rename)
with owner-only mode.

## Sidecar format

```json
{
  "algorithm": "ed25519",
  "evidence_id": "ev_72e61605858e30e40a66f858b0ca1d3e74c934cb39f6acced07abf9226dd6b0e",
  "key_fingerprint": "pk_786bbd87c43f5f088dafb5f9ab7ed0b6765b5a11bf60fbaea819da88714205a4",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAet2L1pSkAMdwrU5U3ECB1vBSuXEWl0Ra9YcHc4Uwc8w=\n-----END PUBLIC KEY-----\n",
  "record_sha256": "8c0034a71b2b96dbdc708d65c54db6535f77329778c64276769e7e4dded4d672",
  "schema": "traceforge.signature.v1",
  "signature": "66564a307a70c19b1875cf15bcc50ea3b2177212289aa18ee69988145ef27a35198250fdb36ddc0fa0dc3574eb6ceeb38a712d989fbdcdb3ffe81b31e75c9703",
  "tool": {
    "name": "traceforge",
    "version": "0.3.0"
  }
}
```

*(The file above is the real sidecar for `tforge scan /bin/ls` on version
0.3.0, pretty-printed here; on disk it is one canonical JSON line.)*

## Workflow

```sh
tforge evidence keygen [--name <label>]   # one-time; prints the fingerprint
tforge evidence sign <ev_id> [--private-key <path>]
tforge evidence verify <ev_id> [--public-key <path>]
tforge evidence verify-all                # N valid · M invalid, then X signed · Y unsigned
tforge report <ev_id> [--signature <path>] [--public-key <path>]
```

`tforge evidence verify <ev_id>` **without** signature flags behaves exactly
as before: it authenticates the record itself and prints `valid` or
`invalid or missing`. Unsigned records are not errors; `verify-all` exit codes
did not change. When a sidecar exists, `verify-all` counts it as signed only
if the whole verification chain below passes.

## Verification order

Each failure has its own readable message and error code:

| Order | Code | Meaning |
|---|---|---|
| 1 | `signature_not_found` | No sidecar for this record; sign it first. |
| 2 | `signature_format` | The sidecar is not valid JSON, does not match `traceforge.signature.v1`, or embeds a key that contradicts its own fingerprint. |
| 3 | `signature_mismatch` | `record_sha256` differs from the hash of the record on disk: the record changed after it was signed. |
| 4 | `evidence_integrity` | The record does not authenticate against its own `evidence_id` — the pre-existing check runs before any crypto. |
| 5 | `key_mismatch` | The `--public-key` supplied has a different fingerprint than the sidecar's signer. |
| 6 | `signature_invalid` | Ed25519 verification returned false for this key and message. |

## What a signature proves

- Which key produced the record (by fingerprint, once you hold the key).
- That the record bytes have not changed since that key signed them.
- That the sidecar itself belongs to exactly one `evidence_id`.

## What a signature does not prove

- **No time.** There is no timestamp and no timestamping authority. A
  signature cannot say when the record was signed, only that it was signed
  before now and nothing changed since.
- **No origin.** A signature says nothing about where the binary came from.
  It is not a code signature and has no relationship to Apple codesign,
  notarization, Authenticode or package repositories.
- **No revocation.** There is no key revocation list. A compromised key keeps
  producing signatures an old public key will happily accept.
- **No secure storage.** There is no OS keyring or hardware protection. The
  0600 file mode is the only guard on a private key; anyone who reads that
  file can sign records as you.
- **No third-party trust by default.** When `--public-key` is not given,
  verification uses the key embedded in the sidecar. That key is a
  self-reported claim: anyone can write any public key into a sidecar, so the
  embedded-key path proves only that the sidecar's bytes are internally
  consistent. Reports and CLI output label this case as self-reported. Only
  `--public-key` with a key you hold turns the result into an identity claim.

## Hashed-content rule

`CONTRIBUTING.md` forbids timestamps, random values and host-specific data
inside hashed content. The sidecar follows the same rule: its content is
record hash, key, signature and tool version, so a re-sign of an unchanged
record with an unchanged key reproduces the identical file byte for byte.
