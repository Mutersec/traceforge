import { compareInventories, inspectBinary, summarizeInventory } from "./binary.js";
import { createEvidenceRecord, inventoryInput, type EvidenceStore } from "./evidence.js";
import type { BinaryInventory, ComparisonResult, EvidenceRecord } from "./types.js";

export interface OperationResult<Result> {
  readonly inventory: BinaryInventory;
  readonly result: Result;
  readonly record: EvidenceRecord<Result>;
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
