export { canonicalJson, evidenceId, sha256Hex } from "./core/canonical.js";
export { compareInventories, inspectBinary, summarizeInventory } from "./core/binary.js";
export { EvidenceStore, createEvidenceRecord } from "./core/evidence.js";
export { TraceForgeError } from "./core/errors.js";
export { compare, inspect, scanBinary } from "./core/operations.js";
export { renderEvidenceReport, writeEvidenceReport } from "./core/report.js";
export type {
  BinaryFormat,
  BinaryInventory,
  ComparisonResult,
  EvidenceRecord,
  EvidenceSummary,
  SectionInfo,
  SliceInventory,
} from "./core/types.js";
export { handleMcpMessage, runMcpServer } from "./mcp/server.js";
