import { randomUUID } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { canonicalJson, evidenceId } from "./canonical.js";
import { TraceForgeError } from "./errors.js";
import type {
  BinaryInventory,
  EvidenceRecord,
  EvidenceSummary,
} from "./types.js";

const EVIDENCE_ID = /^ev_[a-f0-9]{64}$/u;

const recordContent = (record: EvidenceRecord): unknown => {
  const { evidence_id: _ignored, ...content } = record;
  return content;
};

const basicInput = (inventory: BinaryInventory) => ({
  path: inventory.path,
  sha256: inventory.sha256,
  size: inventory.size,
});

export const createEvidenceRecord = <Result>(
  operation: EvidenceRecord["operation"],
  input: EvidenceRecord["input"],
  result: Result,
  limitations: readonly string[],
  version: string,
): EvidenceRecord<Result> => {
  const body = {
    schema: "traceforge.evidence.v1" as const,
    operation,
    tool: { name: "traceforge" as const, version },
    input,
    result,
    limitations: [...new Set(limitations)].sort(),
  };
  return {
    ...body,
    evidence_id: evidenceId(body),
  };
};

export const inventoryInput = (inventory: BinaryInventory): EvidenceRecord["input"] =>
  basicInput(inventory);

export class EvidenceStore {
  readonly root: string;

  constructor(root = join(process.cwd(), ".traceforge", "evidence")) {
    this.root = resolve(root);
  }

  private pathFor(evidenceIdValue: string): string {
    if (!EVIDENCE_ID.test(evidenceIdValue))
      throw new TraceForgeError("invalid_input", "Evidence ID is invalid");
    return join(this.root, `${evidenceIdValue}.json`);
  }

  async put<Result>(record: EvidenceRecord<Result>): Promise<EvidenceRecord<Result>> {
    const expected = evidenceId(recordContent(record));
    if (record.evidence_id !== expected)
      throw new TraceForgeError("evidence_integrity", "Evidence ID does not match its content");
    await mkdir(this.root, { recursive: true, mode: 0o700 });
    const path = this.pathFor(record.evidence_id);
    const temporary = join(
      this.root,
      `.${record.evidence_id}.${process.pid}.${randomUUID()}.tmp`,
    );
    try {
      await writeFile(temporary, `${canonicalJson(record)}\n`, { mode: 0o600 });
      await rename(temporary, path);
    } catch (cause) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw new TraceForgeError("evidence_integrity", "Evidence could not be written", {
        cause,
      });
    }
    return record;
  }

  async get(evidenceIdValue: string): Promise<EvidenceRecord> {
    const path = this.pathFor(evidenceIdValue);
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(path, "utf8"));
    } catch (cause) {
      throw new TraceForgeError("evidence_not_found", `Evidence ${evidenceIdValue} was not found`, {
        cause,
      });
    }
    if (!isEvidenceRecord(parsed))
      throw new TraceForgeError("evidence_integrity", "Evidence record is malformed");
    if (parsed.evidence_id !== evidenceIdValue)
      throw new TraceForgeError("evidence_integrity", "Evidence file identity does not match its name");
    if (evidenceId(recordContent(parsed)) !== parsed.evidence_id)
      throw new TraceForgeError("evidence_integrity", "Evidence content does not match its ID");
    return parsed;
  }

  async verify(evidenceIdValue: string): Promise<boolean> {
    try {
      await this.get(evidenceIdValue);
      return true;
    } catch {
      return false;
    }
  }

  async verifyAll(): Promise<{
    readonly valid: number;
    readonly invalid: readonly string[];
  }> {
    const names = await readdir(this.root).catch(() => [] as string[]);
    let valid = 0;
    const invalid: string[] = [];
    for (const name of names.sort()) {
      if (!name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (!EVIDENCE_ID.test(id)) continue;
      if (await this.verify(id)) valid += 1;
      else invalid.push(id);
    }
    return { valid, invalid };
  }

  async exportBundle(path: string): Promise<{
    readonly path: string;
    readonly records: number;
  }> {
    const names = await readdir(this.root).catch(() => [] as string[]);
    const records: EvidenceRecord[] = [];
    for (const name of names.sort()) {
      if (!name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (!EVIDENCE_ID.test(id)) continue;
      try {
        records.push(await this.get(id));
      } catch {
        // A corrupt record is not silently exported.
      }
    }
    const operations: Record<string, number> = {};
    for (const record of records)
      operations[record.operation] = (operations[record.operation] ?? 0) + 1;
    const bundle = {
      schema: "traceforge.bundle.v1" as const,
      records,
      manifest: { records: records.length, operations },
    };
    const target = resolve(path);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    const temporary = `${target}.${process.pid}.${randomUUID()}.tmp`;
    try {
      await writeFile(temporary, `${canonicalJson(bundle)}\n`, { mode: 0o600 });
      await rename(temporary, target);
    } catch (cause) {
      await rm(temporary, { force: true }).catch(() => undefined);
      throw new TraceForgeError("evidence_integrity", "Evidence bundle could not be written", {
        cause,
      });
    }
    return { path: target, records: records.length };
  }

  async importBundle(path: string): Promise<{ readonly imported: number }> {
    let parsed: unknown;
    try {
      parsed = JSON.parse(await readFile(resolve(path), "utf8"));
    } catch (cause) {
      throw new TraceForgeError("invalid_input", `Cannot read Evidence bundle ${path}`, {
        cause,
      });
    }
    if (parsed === null || typeof parsed !== "object")
      throw new TraceForgeError("evidence_integrity", "Evidence bundle is malformed");
    const bundle = parsed as { schema?: unknown; records?: unknown };
    if (bundle.schema !== "traceforge.bundle.v1" || !Array.isArray(bundle.records))
      throw new TraceForgeError("evidence_integrity", "Evidence bundle schema is invalid");
    const records: EvidenceRecord[] = [];
    for (const item of bundle.records) {
      if (!isEvidenceRecord(item))
        throw new TraceForgeError("evidence_integrity", "Evidence bundle record is malformed");
      if (evidenceId(recordContent(item)) !== item.evidence_id)
        throw new TraceForgeError("evidence_integrity", "Evidence bundle record failed authentication");
      records.push(item);
    }
    for (const record of records) await this.put(record);
    return { imported: records.length };
  }

  async list(): Promise<readonly EvidenceSummary[]> {
    let names: string[];
    try {
      names = await readdir(this.root);
    } catch {
      return [];
    }
    const summaries: EvidenceSummary[] = [];
    for (const name of names.sort()) {
      if (!name.endsWith(".json")) continue;
      const id = name.slice(0, -".json".length);
      if (!EVIDENCE_ID.test(id)) continue;
      try {
        const record = await this.get(id);
        summaries.push({
          evidence_id: record.evidence_id,
          operation: record.operation,
          path: record.input.path,
          sha256: record.input.sha256,
          size: record.input.size,
        });
      } catch {
        // A corrupt record is surfaced by `evidence verify`, not by list.
      }
    }
    return summaries;
  }
}

const isEvidenceRecord = (value: unknown): value is EvidenceRecord => {
  if (value === null || typeof value !== "object") return false;
  const record = value as Record<string, unknown>;
  return (
    record.schema === "traceforge.evidence.v1" &&
    typeof record.evidence_id === "string" &&
    (record.operation === "scan" ||
      record.operation === "inspect" ||
      record.operation === "compare") &&
    record.tool !== null &&
    typeof record.tool === "object" &&
    record.input !== null &&
    typeof record.input === "object" &&
    Array.isArray(record.limitations)
  );
};
