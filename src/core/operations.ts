import { compareInventories, inspectBinary, summarizeInventory } from "./binary.js";
import { inspectPackage, type PackageOptions } from "./app.js";
import { createEvidenceRecord, inventoryInput, type EvidenceStore } from "./evidence.js";
import type {
  AppInventory,
  BinaryInventory,
  ComparisonResult,
  EvidenceRecord,
} from "./types.js";

export interface OperationResult<Result> {
  readonly inventory: BinaryInventory;
  readonly result: Result;
  readonly record: EvidenceRecord<Result>;
}

export interface PackageOperationResult {
  readonly inventory: AppInventory;
  readonly record: EvidenceRecord<AppInventory>;
}

const record = async <Result>(
  operation: EvidenceRecord["operation"],
  inventory: BinaryInventory,
  result: Result,
  limitations: readonly string[],
  store: EvidenceStore | undefined,
  version: string,
): Promise<EvidenceRecord<Result>> => {
  const created = createEvidenceRecord(
    operation,
    inventoryInput(inventory),
    result,
    limitations,
    version,
  );
  return store === undefined ? created : store.put(created);
};

export const scanBinary = async (
  path: string,
  store: EvidenceStore | undefined,
  version: string,
): Promise<OperationResult<ReturnType<typeof summarizeInventory>>> => {
  const inventory = await inspectBinary(path);
  const result = summarizeInventory(inventory);
  return {
    inventory,
    result,
    record: await record("scan", inventory, result, inventory.limitations, store, version),
  };
};

export const inspect = async (
  path: string,
  store: EvidenceStore | undefined,
  version: string,
  architecture?: string,
): Promise<OperationResult<BinaryInventory>> => {
  const inventory = await inspectBinary(path, {
    ...(architecture === undefined ? {} : { architecture }),
  });
  const input = {
    ...inventoryInput(inventory),
    ...(architecture === undefined ? {} : { architecture }),
  };
  const created = createEvidenceRecord(
    "inspect",
    input,
    inventory,
    inventory.limitations,
    version,
  );
  return {
    inventory,
    result: inventory,
    record: store === undefined ? created : await store.put(created),
  };
};

export const compare = async (
  leftPath: string,
  rightPath: string,
  store: EvidenceStore | undefined,
  version: string,
): Promise<OperationResult<ComparisonResult>> => {
  const [left, right] = await Promise.all([inspectBinary(leftPath), inspectBinary(rightPath)]);
  const result = compareInventories(left, right);
  const input = {
    ...inventoryInput(left),
    related: [inventoryInput(right)],
  };
  const created = createEvidenceRecord(
    "compare",
    input,
    result,
    result.limitations,
    version,
  );
  return {
    inventory: left,
    result,
    record: store === undefined ? created : await store.put(created),
  };
};

/**
 * Scans a package directory and records the result as one Evidence record.
 *
 * The record input is the package root, and its `sha256` is the tree fingerprint
 * rather than a file digest — a directory has no single file hash. The manifest
 * and the declared executable are attached as `related` identities so a reader
 * can tie the record to those exact bytes.
 */
export const scanPackage = async (
  path: string,
  store: EvidenceStore | undefined,
  version: string,
  options: PackageOptions = {},
): Promise<PackageOperationResult> => {
  const inventory = await inspectPackage(path, options);
  const members: readonly {
    readonly relative: string;
    readonly sha256: string | null;
    readonly size: number;
  }[] = [
    ...(inventory.manifest === null
      ? []
      : [
          {
            relative: inventory.manifest.path,
            sha256: inventory.manifest.sha256,
            size: inventory.manifest.size,
          },
        ]),
    ...(inventory.declared_executable.path === null
      ? []
      : [
          {
            relative: inventory.declared_executable.path,
            sha256: inventory.declared_executable.sha256,
            size:
              inventory.files.find(
                (file) => file.path === inventory.declared_executable.path,
              )?.size ?? 0,
          },
        ]),
  ];
  const related = members
    .filter(
      (member): member is { relative: string; sha256: string; size: number } =>
        member.sha256 !== null,
    )
    .map((member) => ({
      path: `${inventory.path}/${member.relative}`,
      sha256: member.sha256,
      size: member.size,
    }));
  const created = createEvidenceRecord(
    "app",
    {
      path: inventory.path,
      sha256: inventory.tree_sha256,
      size: inventory.total_bytes,
      ...(related.length === 0 ? {} : { related }),
    },
    inventory,
    inventory.limitations,
    version,
  );
  return {
    inventory,
    record: store === undefined ? created : await store.put(created),
  };
};
