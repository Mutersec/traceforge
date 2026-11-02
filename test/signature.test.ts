import { spawnSync } from "node:child_process";
import { createPublicKey, verify as rawVerify } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, expect, it } from "vitest";

import { canonicalJson, sha256Hex } from "../src/core/canonical.js";
import { EvidenceStore, createEvidenceRecord } from "../src/core/evidence.js";
import { TraceForgeError } from "../src/core/errors.js";
import { renderEvidenceReport } from "../src/core/report.js";
import {
  SignatureStore,
  generateSigningKeyPair,
  keyFingerprint,
  recordSha256,
  signEvidenceRecord,
  signatureMessage,
} from "../src/core/signature.js";
import type { EvidenceSignature } from "../src/core/signature.js";
import type { EvidenceRecord } from "../src/core/types.js";

const projectRoot = resolve(fileURLToPath(new URL(".", import.meta.url)), "..");

const roots: string[] = [];
const temporaryRoot = async (prefix: string): Promise<string> => {
  const root = await mkdtemp(join(tmpdir(), prefix));
  roots.push(root);
  return root;
};
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

const runCli = (
  ...argv: string[]
): { status: number | null; stdout: string; stderr: string } =>
  spawnSync(process.execPath, ["--import", "tsx", "src/cli.ts", ...argv], {
    cwd: projectRoot,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });

const sampleRecord = (): EvidenceRecord =>
  createEvidenceRecord(
    "scan",
    { path: "/tmp/example", sha256: "a".repeat(64), size: 4 },
    { format: "unknown" },
    ["test"],
    "0.2.0",
  );

interface SignedFixture {
  readonly root: string;
  readonly store: EvidenceStore;
  readonly signatures: SignatureStore;
  readonly record: EvidenceRecord;
  readonly pair: ReturnType<typeof generateSigningKeyPair>;
  readonly paths: { private_path: string; public_path: string };
  readonly signature: EvidenceSignature;
  readonly sidecarPath: string;
}

const signedFixture = async (prefix: string): Promise<SignedFixture> => {
  const root = await temporaryRoot(prefix);
  const store = new EvidenceStore(join(root, "evidence"));
  const signatures = new SignatureStore(store);
  const record = await store.put(sampleRecord());
  const pair = generateSigningKeyPair();
  const paths = await signatures.putKeyPair(pair);
  const signature = signEvidenceRecord(record, pair.privateKeyPem, "0.2.0");
  const sidecarPath = await signatures.put(signature);
  return { root, store, signatures, record, pair, paths, signature, sidecarPath };
};

const errorCode = async (action: Promise<unknown>): Promise<TraceForgeError> => {
  const error = await action.catch((cause: unknown) => cause);
  expect(error).toBeInstanceOf(TraceForgeError);
  return error as TraceForgeError;
};

it("generates an Ed25519 key pair and stores both halves owner-only", async () => {
  const root = await temporaryRoot("traceforge-keygen-");
  const signatures = new SignatureStore(new EvidenceStore(join(root, "evidence")));
  const first = generateSigningKeyPair();
  const paths = await signatures.putKeyPair(first);
  expect(first.fingerprint).toMatch(/^pk_[a-f0-9]{64}$/u);
  expect(first.privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
  expect(first.publicKeyPem).toContain("-----BEGIN PUBLIC KEY-----");
  expect(keyFingerprint(first.publicKeyPem)).toBe(first.fingerprint);
  for (const path of [paths.private_path, paths.public_path]) {
    const info = await stat(path);
    expect(info.mode & 0o077).toBe(0);
  }
  const second = generateSigningKeyPair();
  expect(second.privateKeyPem).not.toBe(first.privateKeyPem);
  expect(second.fingerprint).not.toBe(first.fingerprint);
  const labeled = await signatures.putKeyPair(second, "release team");
  expect(labeled.private_path).toContain("release-team");
  expect(existsSync(labeled.private_path)).toBe(true);
});

it("signs a record into a sidecar bound to its canonical on-disk bytes", async () => {
  const fixture = await signedFixture("traceforge-sign-");
  expect(fixture.signature.schema).toBe("traceforge.signature.v1");
  expect(fixture.signature.algorithm).toBe("ed25519");
  expect(fixture.signature.evidence_id).toBe(fixture.record.evidence_id);
  expect(fixture.signature.key_fingerprint).toBe(fixture.pair.fingerprint);
  expect(fixture.signature.signature).toMatch(/^[a-f0-9]{128}$/u);
  expect(fixture.signature.tool).toEqual({ name: "traceforge", version: "0.2.0" });
  const disk = await readFile(
    join(fixture.store.root, `${fixture.record.evidence_id}.json`),
    "utf8",
  );
  const canonical = disk.endsWith("\n") ? disk.slice(0, -1) : disk;
  expect(fixture.signature.record_sha256).toBe(sha256Hex(canonical));
  expect(fixture.signature.record_sha256).toBe(recordSha256(fixture.record));
  expect(fixture.sidecarPath).toBe(
    join(fixture.root, "signatures", `${fixture.record.evidence_id}.sig.json`),
  );
  expect(await readFile(fixture.sidecarPath, "utf8")).toBe(
    `${canonicalJson(fixture.signature)}\n`,
  );
  const info = await stat(fixture.sidecarPath);
  expect(info.mode & 0o077).toBe(0);
  expect(await fixture.signatures.get(fixture.record.evidence_id)).toEqual(fixture.signature);
});

it("is deterministic: the same key and record produce the same signature", async () => {
  const fixture = await signedFixture("traceforge-determinism-");
  const before = await readFile(fixture.sidecarPath, "utf8");
  const again = signEvidenceRecord(fixture.record, fixture.pair.privateKeyPem, "0.2.0");
  expect(again.signature).toBe(fixture.signature.signature);
  expect(again.record_sha256).toBe(fixture.signature.record_sha256);
  await fixture.signatures.put(again);
  expect(await readFile(fixture.sidecarPath, "utf8")).toBe(before);
});

it("verifies with the embedded key and with the same key supplied separately", async () => {
  const fixture = await signedFixture("traceforge-verify-");
  const embedded = await fixture.signatures.verify(fixture.record.evidence_id);
  expect(embedded.external_key).toBe(false);
  expect(embedded.fingerprint).toBe(fixture.pair.fingerprint);
  expect(embedded.record.evidence_id).toBe(fixture.record.evidence_id);
  const supplied = await fixture.signatures.verify(fixture.record.evidence_id, {
    publicKeyPem: fixture.pair.publicKeyPem,
  });
  expect(supplied.external_key).toBe(true);
  expect(supplied.fingerprint).toBe(embedded.fingerprint);
  const message = Buffer.from(signatureMessage(fixture.signature.record_sha256), "ascii");
  expect(
    rawVerify(
      null,
      message,
      createPublicKey({ key: fixture.pair.publicKeyPem, format: "pem" }),
      Buffer.from(fixture.signature.signature, "hex"),
    ),
  ).toBe(true);
  expect(
    rawVerify(
      null,
      Buffer.from(fixture.signature.record_sha256, "ascii"),
      createPublicKey({ key: fixture.pair.publicKeyPem, format: "pem" }),
      Buffer.from(fixture.signature.signature, "hex"),
    ),
  ).toBe(false);
});

it("fails each tamper case with its own readable error", async () => {
  const tampered = await signedFixture("traceforge-tamper-record-");
  await writeFile(
    join(tampered.store.root, `${tampered.record.evidence_id}.json`),
    `${canonicalJson({ ...tampered.record, result: { tampered: true } })}\n`,
  );
  const mismatch = await errorCode(tampered.signatures.verify(tampered.record.evidence_id));
  expect(mismatch.code).toBe("signature_mismatch");
  expect(mismatch.message).toMatch(/changed after it was signed \(record hash differs\)/u);

  const wrongKey = await signedFixture("traceforge-wrong-key-");
  const stranger = generateSigningKeyPair();
  const keyError = await errorCode(
    wrongKey.signatures.verify(wrongKey.record.evidence_id, {
      publicKeyPem: stranger.publicKeyPem,
    }),
  );
  expect(keyError.code).toBe("key_mismatch");
  expect(keyError.message).toMatch(/does not match the key that signed/u);

  const corrupt = await signedFixture("traceforge-bad-sidecar-");
  await writeFile(corrupt.sidecarPath, "not json at all");
  const formatError = await errorCode(corrupt.signatures.verify(corrupt.record.evidence_id));
  expect(formatError.code).toBe("signature_format");

  const absent = await signedFixture("traceforge-no-sidecar-");
  await rm(absent.sidecarPath);
  const notFound = await errorCode(absent.signatures.verify(absent.record.evidence_id));
  expect(notFound.code).toBe("signature_not_found");
  expect(notFound.message).toMatch(/sign it with `tforge evidence sign/u);

  const flipped = await signedFixture("traceforge-flipped-sig-");
  const raw = await readFile(flipped.sidecarPath, "utf8");
  const broken = raw.replace(
    /("signature":")([a-f0-9])/u,
    (_match: string, prefix: string, hex: string) => `${prefix}${hex === "0" ? "1" : "0"}`,
  );
  expect(broken).not.toBe(raw);
  await writeFile(flipped.sidecarPath, broken);
  const invalid = await errorCode(flipped.signatures.verify(flipped.record.evidence_id));
  expect(invalid.code).toBe("signature_invalid");
  expect(invalid.message).toMatch(/not valid for this key and record/u);

  const missingKey = await signedFixture("traceforge-missing-key-");
  await rm(missingKey.paths.private_path);
  const cli = runCli(
    "--store",
    join(missingKey.root, "evidence"),
    "evidence",
    "sign",
    missingKey.record.evidence_id,
    "--private-key",
    missingKey.paths.private_path,
  );
  expect(cli.status).toBe(1);
  expect(cli.stderr).toMatch(/cannot read the private key file/iu);

  const publicAsPrivate = await signedFixture("traceforge-public-as-private-");
  const wrongKind = await errorCode(
    Promise.resolve().then(() =>
      signEvidenceRecord(publicAsPrivate.record, publicAsPrivate.pair.publicKeyPem, "0.2.0"),
    ),
  );
  expect(wrongKind.code).toBe("invalid_input");
  expect(wrongKind.message).toMatch(/that file is a public key/iu);
});

it("keeps plain evidence verify at its original behavior", async () => {
  const fixture = await signedFixture("traceforge-legacy-verify-");
  const result = runCli(
    "--store",
    join(fixture.root, "evidence"),
    "evidence",
    "verify",
    fixture.record.evidence_id,
  );
  expect(result.status).toBe(0);
  expect(result.stdout).toBe("valid\n");
  const missing = runCli(
    "--store",
    join(fixture.root, "evidence"),
    "evidence",
    "verify",
    `ev_${"0".repeat(64)}`,
  );
  expect(missing.status).toBe(1);
  expect(missing.stdout).toBe("invalid or missing\n");
});

it("keeps the verify-all line and adds signed and unsigned counts", async () => {
  const fixture = await signedFixture("traceforge-verify-all-");
  const storeArgs = ["--store", join(fixture.root, "evidence")];
  await rm(fixture.sidecarPath);
  const unsigned = runCli(...storeArgs, "evidence", "verify-all");
  expect(unsigned.status).toBe(0);
  expect(unsigned.stdout).toBe("1 valid · 0 invalid\n0 signed · 1 unsigned\n");
  const signed = runCli(
    ...storeArgs,
    "evidence",
    "sign",
    fixture.record.evidence_id,
    "--private-key",
    fixture.paths.private_path,
  );
  expect(signed.status).toBe(0);
  const both = runCli(...storeArgs, "evidence", "verify-all");
  expect(both.status).toBe(0);
  expect(both.stdout).toBe("1 valid · 0 invalid\n1 signed · 0 unsigned\n");
  await writeFile(fixture.sidecarPath, "broken sidecar");
  const broken = runCli(...storeArgs, "evidence", "verify-all");
  expect(broken.status).toBe(0);
  expect(broken.stdout).toContain("1 valid · 0 invalid\n");
  expect(broken.stdout).toContain("0 signed · 1 unsigned\n");
  expect(broken.stdout).toContain(fixture.record.evidence_id);
});

it("escapes hostile signature fields in the HTML report", async () => {
  const fixture = await signedFixture("traceforge-report-xss-");
  const raw = await readFile(fixture.sidecarPath, "utf8");
  const forgedPath = join(fixture.root, "forged.sig.json");
  await writeFile(forgedPath, raw.replace(/pk_[a-f0-9]{64}/u, "<script>alert(1)</script>"));
  const outPath = join(fixture.root, "report.html");
  const result = runCli(
    "--store",
    join(fixture.root, "evidence"),
    "report",
    fixture.record.evidence_id,
    "--signature",
    forgedPath,
    "--out",
    outPath,
  );
  expect(result.status).toBe(0);
  const html = await readFile(outPath, "utf8");
  expect(html).toContain("identity verified");
  expect(html).toContain("Signature");
  expect(html).toContain("signature failed");
  expect(html).toContain("&lt;script&gt;alert(1)&lt;/script&gt;");
  expect(html).not.toContain("<script>alert(1)</script>");
  const verifiedHtml = renderEvidenceReport(fixture.record, {
    status: "verified",
    message: "Verified against the public key supplied on the command line.",
    algorithm: fixture.signature.algorithm,
    key_fingerprint: fixture.signature.key_fingerprint,
    record_sha256: fixture.signature.record_sha256,
    self_reported: false,
  });
  expect(verifiedHtml).toContain("signed · verified");
  expect(verifiedHtml).toContain(fixture.signature.key_fingerprint);
  expect(verifiedHtml).toContain("does not prove where the file came from");
});

it("runs the full keygen, sign and verify flow through the CLI", async () => {
  if (process.platform !== "darwin") return;
  const root = await temporaryRoot("traceforge-cli-live-");
  const storePath = join(root, "evidence");
  const storeArgs = ["--store", storePath];
  const scanned = runCli(...storeArgs, "scan", "/bin/ls", "--json");
  expect(scanned.status).toBe(0);
  const record = JSON.parse(scanned.stdout) as EvidenceRecord;
  expect(record.evidence_id).toBe(
    "ev_4881c15a0c4ae521f75e89d77d9abaca2cb5b6f68f32ce74cd005e58beb15e2a",
  );
  const keys = runCli(...storeArgs, "evidence", "keygen", "--json");
  expect(keys.status).toBe(0);
  const keyInfo = JSON.parse(keys.stdout) as {
    fingerprint: string;
    private_key: string;
    public_key: string;
  };
  expect(keyInfo.fingerprint).toMatch(/^pk_[a-f0-9]{64}$/u);
  expect(keyInfo.private_key.startsWith(root)).toBe(true);
  const signed = runCli(...storeArgs, "evidence", "sign", record.evidence_id, "--json");
  expect(signed.status).toBe(0);
  const signature = JSON.parse(signed.stdout) as EvidenceSignature;
  expect(signature.key_fingerprint).toBe(keyInfo.fingerprint);
  const verified = runCli(
    ...storeArgs,
    "evidence",
    "verify",
    record.evidence_id,
    "--public-key",
    keyInfo.public_key,
  );
  expect(verified.status).toBe(0);
  expect(verified.stdout).toContain(`signed · verified by ${keyInfo.fingerprint}`);
  expect(verified.stdout).not.toContain("self-reported");
  const embedded = runCli(...storeArgs, "evidence", "verify", record.evidence_id, "--signature",
    join(root, "signatures", `${record.evidence_id}.sig.json`));
  expect(embedded.status).toBe(0);
  expect(embedded.stdout).toContain("self-reported");
  const legacy = runCli(...storeArgs, "evidence", "verify", record.evidence_id);
  expect(legacy.stdout).toBe("valid\n");
  const all = runCli(...storeArgs, "evidence", "verify-all");
  expect(all.status).toBe(0);
  expect(all.stdout).toContain("1 valid · 0 invalid");
  expect(all.stdout).toContain("1 signed · 0 unsigned");
  const forged = runCli(
    ...storeArgs,
    "evidence",
    "verify",
    record.evidence_id,
    "--public-key",
    join(root, "keys", "absent.pub.pem"),
  );
  expect(forged.status).toBe(1);
  expect(forged.stderr).toMatch(/cannot read the public key file/iu);
}, 120_000);

it("writes keys and signatures only under the store it was given, and git ignores them", async () => {
  const root = await temporaryRoot("traceforge-hygiene-");
  const storePath = join(root, "evidence");
  const keys = runCli("--store", storePath, "evidence", "keygen", "--json");
  expect(keys.status).toBe(0);
  const info = JSON.parse(keys.stdout) as { private_key: string; public_key: string };
  expect(info.private_key.startsWith(root)).toBe(true);
  expect(info.public_key.startsWith(root)).toBe(true);
  const fixture = await signedFixture("traceforge-hygiene-sidecar-");
  expect(fixture.sidecarPath.startsWith(fixture.root)).toBe(true);
  expect(fixture.paths.private_path.startsWith(fixture.root)).toBe(true);
  for (const path of [".traceforge/keys/demo.pem", ".traceforge/signatures/demo.sig.json"]) {
    const ignored = spawnSync("git", ["check-ignore", "-q", path], {
      cwd: projectRoot,
      encoding: "utf8",
    });
    expect(ignored.status).toBe(0);
  }
}, 60_000);
