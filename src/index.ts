export { canonicalJson, evidenceId, sha256Hex } from "./core/canonical.js";
export {
  inspectPackage,
  packageKind,
  summarizePackage,
  MAX_APP_DEPTH,
  MAX_APP_FILES,
  MAX_APP_NESTED,
} from "./core/app.js";
export { compareInventories, inspectBinary, summarizeInventory } from "./core/binary.js";
export { EvidenceStore, createEvidenceRecord } from "./core/evidence.js";
export { TraceForgeError } from "./core/errors.js";
export { parsePlist, plistEncoding, scalarClaim } from "./core/plist.js";
export {
  SignatureStore,
  SIGNATURE_PREFIX,
  generateSigningKeyPair,
  keyFingerprint,
  loadSignatureFile,
  readSignatureFields,
  recordSha256,
  signEvidenceRecord,
  signatureMessage,
} from "./core/signature.js";
export {
  compare,
  inspect,
  scanBinary,
  scanPackage,
} from "./core/operations.js";
export {
  DEFAULT_PAGE_ITEMS,
  INSPECT_FIELDS,
  MAX_PAGE_ITEMS,
  MAX_TOOL_TEXT_BYTES,
  PACKAGE_FIELDS,
  omittedFields,
  pageBinaryLists,
  pageItems,
  pageNamedList,
  pageOffset,
  parseOnly,
  selectInspectFields,
  selectPackageFields,
  validatedLimit,
} from "./core/paging.js";
export type {
  FieldSelection,
  ListPage,
  Page,
  PageRequest,
} from "./core/paging.js";
export { renderEvidenceReport, writeEvidenceReport } from "./core/report.js";
export type {
  AppCounts,
  AppDeclaredExecutable,
  AppFileEntry,
  AppInventory,
  AppLayout,
  AppManifest,
  AppNestedPackage,
  BinaryFormat,
  BinaryInventory,
  ComparisonResult,
  EvidenceRecord,
  EvidenceSummary,
  SectionInfo,
  SliceIdentity,
  SliceInventory,
} from "./core/types.js";
export type { PackageOptions, PackageSummary } from "./core/app.js";
export type { PlistDocument, PlistEncoding, PlistValue } from "./core/plist.js";
export type {
  EvidenceSignature,
  GeneratedKeyPair,
  KeyPairPaths,
  SignatureFields,
  SignatureVerification,
  SignatureVerifyOptions,
} from "./core/signature.js";
export type { EvidenceSignatureReport } from "./core/report.js";
export { handleMcpMessage, runMcpServer } from "./mcp/server.js";
