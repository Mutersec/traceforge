import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";

import { canonicalJson, evidenceId, sha256Hex } from "./canonical.js";
import { EVIDENCE_ID, isEvidenceRecord, recordContent } from "./evidence.js";
import type { EvidenceStore } from "./evidence.js";
import { TraceForgeError } from "./errors.js";
import type { EvidenceRecord } from "./types.js";

/**
 * Domain separation for the signed message: an Ed25519 signature covers
 * `traceforge.signature.v1\n<record hash>`, never the bare hash, so a
 * signature can never be replayed against another schema or purpose.
 */
export const SIGNATURE_PREFIX = "traceforge.signature.v1\n";

const KEY_FINGERPRINT = /^pk_[a-f0-9]{64}$/u;
const SHA256_HEX = /^[a-f0-9]{64}$/u;
const ED25519_SIGNATURE_HEX = /^[a-f0-9]{128}$/u;

export interface EvidenceSignature {
  readonly schema: "traceforge.signature.v1";
  readonly algorithm: "ed25519";
  readonly evidence_id: string;
  readonly record_sha256: string;
  /** A self-reported identity claim from the signer, never a trust anchor. */
  readonly public_key: string;
  readonly key_fingerprint: string;
  readonly signature: string;
  /** Timestamps are excluded on purpose: hashed content must stay deterministic. */
  readonly tool: { readonly name: "traceforge"; readonly version: string };
}

export interface GeneratedKeyPair {
  readonly privateKeyPem: string;
  readonly publicKeyPem: string;
  readonly fingerprint: string;
}

export interface KeyPairPaths {
  readonly private_path: string;
  readonly public_path: string;
}

export interface SignatureFields {
  readonly evidence_id: string | null;
  readonly algorithm: string | null;
  readonly key_fingerprint: string | null;
  readonly record_sha256: string | null;
}

export interface SignatureVerification {
  readonly signature: EvidenceSignature;
  readonly record: EvidenceRecord;
  readonly fingerprint: string;
  readonly external_key: boolean;
}

export interface SignatureVerifyOptions {
  path?: string;
  publicKeyPem?: string;
}

/** The identity of one stored record, over its canonical on-disk bytes. */
export const recordSha256 = (record: unknown): string => sha256Hex(canonicalJson(record));

export const signatureMessage = (digest: string): string =>
  `${SIGNATURE_PREFIX}${digest}`;

export const keyFingerprint = (publicKeyPem: string): string =>
  `pk_${sha256Hex(
    createPublicKey({ key: publicKeyPem, format: "pem" }).export({
      type: "spki",
      format: "der",
    }),
  )}`;

export const generateSigningKeyPair = (): GeneratedKeyPair => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return {
    privateKeyPem: privateKey,
    publicKeyPem: publicKey,
    fingerprint: keyFingerprint(publicKey),
  };
};

export const signEvidenceRecord = (
  record: EvidenceRecord,
  privateKeyPem: string,
  version: string,
): EvidenceSignature => {
  let key: ReturnType<typeof createPrivateKey>;
  try {
    key = createPrivateKey({ key: privateKeyPem, format: "pem" });
  } catch (cause) {
    if (privateKeyPem.includes("BEGIN PUBLIC KEY"))
      throw new TraceForgeError(
        "invalid_input",
        "That file is a public key. Signing needs the private key PEM written by tforge evidence keygen.",
        { cause },
      );
    throw new TraceForgeError(
      "invalid_input",
      "Cannot read the private key. Expected a PKCS#8 PEM key (-----BEGIN PRIVATE KEY-----).",
      { cause },
    );
  }
  if (key.asymmetricKeyType !== "ed25519")
    throw new TraceForgeError(
      "invalid_input",
      `Signing supports Ed25519 keys only, got ${key.asymmetricKeyType ?? "unknown"}.`,
    );
  const digest = recordSha256(record);
  const publicKeyPem = createPublicKey(key)
    .export({ type: "spki", format: "pem" })
    .toString();
  return {
    schema: "traceforge.signature.v1",
    algorithm: "ed25519",
    evidence_id: record.evidence_id,
    record_sha256: digest,
    public_key: publicKeyPem,
    key_fingerprint: keyFingerprint(publicKeyPem),
    signature: cryptoSign(
      null,
      Buffer.from(signatureMessage(digest), "ascii"),
      key,
    ).toString("hex"),
    tool: { name: "traceforge", version },
  };
};

const isEvidenceSignature = (value: unknown): value is EvidenceSignature => {
  if (value === null || typeof value !== "object") return false;
  const signature = value as Record<string, unknown>;
  const tool = signature["tool"];
  return (
    signature["schema"] === "traceforge.signature.v1" &&
    signature["algorithm"] === "ed25519" &&
    typeof signature["evidence_id"] === "string" &&
    EVIDENCE_ID.test(signature["evidence_id"]) &&
    typeof signature["record_sha256"] === "string" &&
    SHA256_HEX.test(signature["record_sha256"]) &&
    typeof signature["signature"] === "string" &&
    ED25519_SIGNATURE_HEX.test(signature["signature"]) &&
    typeof signature["public_key"] === "string" &&
    signature["public_key"].startsWith("-----BEGIN PUBLIC KEY-----") &&
    typeof signature["key_fingerprint"] === "string" &&
    KEY_FINGERPRINT.test(signature["key_fingerprint"]) &&
    tool !== null &&
    typeof tool === "object" &&
    (tool as { name?: unknown }).name === "traceforge" &&
    typeof (tool as { version?: unknown }).version === "string"
  );
};

export const loadSignatureFile = async (
  path: string,
  evidenceIdValue: string,
): Promise<EvidenceSignature> => {
  let contents: string;
  try {
    contents = await readFile(path, "utf8");
  } catch (cause) {
    throw new TraceForgeError(
      "signature_not_found",
      `No signature file for ${evidenceIdValue}; sign it with \`tforge evidence sign ${evidenceIdValue}\`.`,
      { cause },
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch (cause) {
    throw new TraceForgeError(
      "signature_format",
      `The signature file ${path} is not valid JSON.`,
      { cause },
    );
  }
  if (!isEvidenceSignature(parsed))
    throw new TraceForgeError(
      "signature_format",
      `The signature file ${path} does not match the traceforge.signature.v1 schema.`,
    );
  if (parsed.evidence_id !== evidenceIdValue)
    throw new TraceForgeError(
      "signature_mismatch",
      "The signature file was made for a different Evidence record.",
    );
  let fingerprint: string;
  try {
    fingerprint = keyFingerprint(parsed.public_key);
  } catch (cause) {
    throw new TraceForgeError(
      "signature_format",
      `The public key embedded in ${path} cannot be read.`,
      { cause },
    );
  }
  if (fingerprint !== parsed.key_fingerprint)
    throw new TraceForgeError(
      "signature_format",
      "The embedded public key does not match the fingerprint recorded beside it.",
    );
  return parsed;
};

/**
 * Best-effort field read for the report. The signature file is untrusted
 * input, so values are shown even when strict validation failed; callers must
 * escape them before rendering.
 */
export const readSignatureFields = async (
  path: string,
): Promise<SignatureFields | null> => {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== "object") return null;
  const signature = parsed as Record<string, unknown>;
  const field = (name: string): string | null =>
    typeof signature[name] === "string" ? (signature[name] as string) : null;
  return {
    evidence_id: field("evidence_id"),
    algorithm: field("algorithm"),
    key_fingerprint: field("key_fingerprint"),
    record_sha256: field("record_sha256"),
  };
};

const labelSlug = (label: string): string => {
  const slug = label
    .trim()
    .replace(/[^A-Za-z0-9._-]+/gu, "-")
    .replace(/^[.-]+/gu, "");
  if (slug.length === 0)
    throw new TraceForgeError(
      "invalid_input",
      "The key name has no filename-safe characters.",
    );
  if (slug.length > 64)
    throw new TraceForgeError("invalid_input", "The key name is longer than 64 characters.");
  return slug;
};

/**
 * Detached Ed25519 signatures for Evidence records. Sidecars live beside the
 * record tree in `<store root>/../signatures` and keys in `<store root>/../keys`,
 * which keeps them out of bundles and out of the authenticated record bytes.
 */
export class SignatureStore {
  readonly store: EvidenceStore;
  readonly root: string;
  readonly keyRoot: string;

  constructor(store: EvidenceStore) {
    this.store = store;
    this.root = resolve(store.root, "..", "signatures");
    this.keyRoot = resolve(store.root, "..", "keys");
  }

  pathFor(evidenceIdValue: string): string {
    if (!EVIDENCE_ID.test(evidenceIdValue))
      throw new TraceForgeError("invalid_input", "Evidence ID is invalid");
    return join(this.root, `${evidenceIdValue}.sig.json`);
  }

  keyPathFor(fingerprint: string, label?: string): KeyPairPaths {
    if (!KEY_FINGERPRINT.test(fingerprint))
      throw new TraceForgeError("invalid_input", "Key fingerprint is invalid");
    const stem = label === undefined ? fingerprint : `${labelSlug(label)}.${fingerprint}`;
    return {
      private_path: join(this.keyRoot, `${stem}.pem`),
      public_path: join(this.keyRoot, `${stem}.pub.pem`),
    };
  }

  async putKeyPair(pair: GeneratedKeyPair, label?: string): Promise<KeyPairPaths> {
    await mkdir(this.keyRoot, { recursive: true, mode: 0o700 });
    const paths = this.keyPathFor(pair.fingerprint, label);
    await this.writeAtomic(pair.privateKeyPem, paths.private_path);
    await this.writeAtomic(pair.publicKeyPem, paths.public_path);
    return paths;
  }

  async put(signature: EvidenceSignature): Promise<string> {
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const path = this.pathFor(signature.evidence_id);
    await this.writeAtomic(`${canonicalJson(signature)}\n`, path);
    return path;
  }

  async get(evidenceIdValue: string): Promise<EvidenceSignature> {
    return loadSignatureFile(this.pathFor(evidenceIdValue), evidenceIdValue);
  }

  async verify(
    evidenceIdValue: string,
    options: SignatureVerifyOptions = {},
  ): Promise<SignatureVerification> {
    const sidecarPath = options.path ?? this.pathFor(evidenceIdValue);
    const signature = await loadSignatureFile(sidecarPath, evidenceIdValue);
    const record = await this.readDiskRecord(evidenceIdValue);
    if (recordSha256(record) !== signature.record_sha256)
      throw new TraceForgeError(
        "signature_mismatch",
        "The record changed after it was signed (record hash differs).",
      );
    if (
      record.evidence_id !== evidenceIdValue ||
      evidenceId(recordContent(record)) !== record.evidence_id
    )
      throw new TraceForgeError(
        "evidence_integrity",
        "Evidence content does not match its ID",
      );
    let publicKeyPem: string;
    let externalKey: boolean;
    if (options.publicKeyPem !== undefined) {
      externalKey = true;
      try {
        const key = createPublicKey({ key: options.publicKeyPem, format: "pem" });
        if (!options.publicKeyPem.includes("BEGIN PUBLIC KEY") || key.asymmetricKeyType !== "ed25519")
          throw new TraceForgeError(
            "invalid_input",
            "The supplied public key is not an Ed25519 SPKI PEM (-----BEGIN PUBLIC KEY-----).",
          );
      } catch (cause) {
        if (cause instanceof TraceForgeError) throw cause;
        throw new TraceForgeError(
          "invalid_input",
          "The supplied public key cannot be read. Expected a PEM written by tforge evidence keygen.",
          { cause },
        );
      }
      if (keyFingerprint(options.publicKeyPem) !== signature.key_fingerprint)
        throw new TraceForgeError(
          "key_mismatch",
          "That public key does not match the key that signed this record.",
        );
      publicKeyPem = options.publicKeyPem;
    } else {
      externalKey = false;
      publicKeyPem = signature.public_key;
    }
    let valid: boolean;
    try {
      valid = cryptoVerify(
        null,
        Buffer.from(signatureMessage(signature.record_sha256), "ascii"),
        publicKeyPem,
        Buffer.from(signature.signature, "hex"),
      );
    } catch (cause) {
      throw new TraceForgeError(
        "signature_invalid",
        "The signature is not valid for this key and record.",
        { cause },
      );
    }
    if (!valid)
      throw new TraceForgeError(
        "signature_invalid",
        "The signature is not valid for this key and record.",
      );
    return {
      signature,
      record,
      fingerprint: signature.key_fingerprint,
      external_key: externalKey,
    };
  }

  async defaultPrivateKeyPath(): Promise<string> {
    let candidates: string[];
    try {
      const entries = await readdir(this.keyRoot, { withFileTypes: true });
      candidates = entries
        .filter((entry) => entry.isFile())
        .map((entry) => entry.name)
        .filter((name) => name.endsWith(".pem") && !name.endsWith(".pub.pem"))
        .filter((name) => /pk_[a-f0-9]{64}\.pem$/u.test(name))
        .sort();
    } catch {
      candidates = [];
    }
    const [first] = candidates;
    if (candidates.length === 0 || first === undefined)
      throw new TraceForgeError(
        "invalid_input",
        `No signing key in ${this.keyRoot} yet. Run \`tforge evidence keygen\` first.`,
      );
    if (candidates.length > 1)
      throw new TraceForgeError(
        "invalid_input",
        `Multiple signing keys in ${this.keyRoot} (${candidates.join(", ")}); pass --private-key <path> to pick one.`,
      );
    return join(this.keyRoot, first);
  }

  private async readDiskRecord(evidenceIdValue: string): Promise<EvidenceRecord> {
    let contents: string;
    try {
      contents = await readFile(this.store.pathFor(evidenceIdValue), "utf8");
    } catch (cause) {
      throw new TraceForgeError(
        "evidence_not_found",
        `Evidence ${evidenceIdValue} was not found`,
        { cause },
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch (cause) {
      throw new TraceForgeError("evidence_integrity", "Evidence file is not valid JSON", {
        cause,
      });
    }
    if (!isEvidenceRecord(parsed))
      throw new TraceForgeError("evidence_integrity", "Evidence record is malformed");
    return parsed;
  }

  private async writeAtomic(contents: string, target: string): Promise<void> {
    const directory = dirname(target);
    const temporary = join(
      directory,
      `.${basename(target)}.${process.pid}.${randomUUID()}.tmp`,
    );
    try {
      await writeFile(temporary, contents, { mode: 0o600 });
      await rename(temporary, target);
    } catch (cause) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw new TraceForgeError("signature_write_failed", `Could not write ${target}`, {
        cause,
      });
    }
  }
}
