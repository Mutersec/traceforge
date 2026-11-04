export type BinaryFormat = "mach-o" | "elf" | "pe" | "wasm" | "unknown";

export interface SectionInfo {
  readonly name: string;
  readonly segment: string | null;
  readonly address: string | null;
  readonly offset: number;
  readonly size: number;
  readonly sha256: string | null;
  readonly flags: string | null;
}

/** Structural protection decisions. Each name has one documented decision rule per format. */
export type MitigationName =
  | "aslr"
  | "pie"
  | "nx"
  | "relro"
  | "full-relro"
  | "bind-now"
  | "chained-fixups"
  | "guard-cf"
  | "high-entropy-aslr"
  | "code-integrity"
  | "image-isolation";

export interface SecuritySummary {
  readonly present: readonly MitigationName[];
  readonly absent: readonly MitigationName[];
  readonly undetermined: readonly MitigationName[];
}

/** Self-reported build facts. Recorded as claims, never as verified provenance. */
export type ProvenanceFacts = Readonly<Record<string, string>>;

export interface SliceInventory {
  readonly architecture: string;
  readonly bits: 32 | 64;
  readonly endian: "little" | "big";
  readonly fileType: string;
  readonly entrypoint: string | null;
  readonly entrypointKind: "file-offset" | "virtual-address" | "rva" | null;
  readonly buildId: string | null;
  readonly security: SecuritySummary;
  readonly provenance: ProvenanceFacts;
  readonly sections: readonly SectionInfo[];
  readonly imports: readonly string[];
  readonly exports: readonly string[];
  readonly libraries: readonly string[];
  readonly limitations: readonly string[];
}

/** A member's header-level identity, read from a bounded window without a full parse. */
export interface SliceIdentity {
  readonly architecture: string;
  readonly file_type: string;
}

export interface BinaryInventory {
  readonly schema: "traceforge.inventory.v2";
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
  readonly format: BinaryFormat;
  readonly slices: readonly SliceInventory[];
  readonly limitations: readonly string[];
}

/** How a package member was classified from its name, mode bits and header magic. */
export type AppFileKind =
  | "manifest"
  | "code"
  | "archive"
  | "script"
  | "resource"
  | "link"
  | "other";

export interface AppFileEntry {
  readonly path: string;
  readonly size: number;
  readonly sha256: string | null;
  readonly kind: AppFileKind;
  readonly format: BinaryFormat;
  readonly executable: boolean;
  readonly architectures: readonly string[];
  readonly file_types: readonly string[];
  /** Target text of a symbolic link, recorded but never followed. Null for other entries. */
  readonly link_target: string | null;
}

/** Aggregated totals over the inventoried subtree, not over the whole package. */
export interface AppCounts {
  readonly files: number;
  readonly directories: number;
  readonly links: number;
  readonly special: number;
  readonly unreadable: number;
  readonly executable: number;
  readonly total_bytes: number;
  readonly hashed_bytes: number;
  readonly by_kind: Readonly<Record<string, number>>;
  readonly by_format: Readonly<Record<string, number>>;
  readonly architectures: Readonly<Record<string, number>>;
}

/** One package member declared as the launch target. */
export interface AppDeclaredExecutable {
  readonly name: string | null;
  readonly path: string | null;
  readonly present: boolean;
  readonly sha256: string | null;
}

export interface AppManifest {
  readonly path: string;
  readonly size: number;
  readonly sha256: string | null;
  readonly encoding: "xml" | "binary" | "json" | null;
  readonly keys: number;
  readonly claims: Readonly<Record<string, string>>;
}

/** A bundle found inside the scanned root, with its own declared identity. */
export interface AppNestedPackage {
  readonly path: string;
  readonly kind: string;
  readonly layout: AppLayout;
  readonly manifest_path: string | null;
  readonly declared: Readonly<Record<string, string>>;
}

export type AppLayout = "macos" | "flat" | "unknown";

export interface AppInventory {
  readonly schema: "traceforge.app.inventory.v1";
  readonly path: string;
  readonly kind: string;
  readonly layout: AppLayout;
  /** SHA-256 of the canonical file tree below; a directory identity, not a file hash. */
  readonly tree_sha256: string;
  readonly total_bytes: number;
  readonly manifest: AppManifest | null;
  readonly pkg_info: Readonly<Record<string, string>>;
  readonly declared_executable: AppDeclaredExecutable;
  readonly nested: readonly AppNestedPackage[];
  readonly counts: AppCounts;
  readonly files: readonly AppFileEntry[];
  readonly limitations: readonly string[];
}

export interface EvidenceRecord<Result = unknown> {
  readonly schema: "traceforge.evidence.v1";
  readonly evidence_id: string;
  readonly operation: "scan" | "inspect" | "compare" | "app";
  readonly tool: { readonly name: "traceforge"; readonly version: string };
  readonly input: {
    readonly path: string;
    readonly sha256: string;
    readonly size: number;
    readonly architecture?: string;
    readonly related?: readonly {
      readonly path: string;
      readonly sha256: string;
      readonly size: number;
    }[];
  };
  readonly result: Result;
  readonly limitations: readonly string[];
}

export interface EvidenceSummary {
  readonly evidence_id: string;
  readonly operation: EvidenceRecord["operation"];
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
}

export interface EvidenceBundle {
  readonly schema: "traceforge.bundle.v1";
  readonly records: readonly EvidenceRecord[];
  readonly manifest: {
    readonly records: number;
    readonly operations: Readonly<Record<string, number>>;
  };
}

export interface ComparisonResult {
  readonly schema: "traceforge.comparison.v1";
  readonly changed: boolean;
  readonly left: BinaryInventory;
  readonly right: BinaryInventory;
  readonly changes: {
    readonly format: boolean;
    readonly size: boolean;
    readonly slices_added: readonly string[];
    readonly slices_removed: readonly string[];
    readonly sections_added: readonly string[];
    readonly sections_removed: readonly string[];
    readonly sections_changed: readonly string[];
    readonly imports_added: readonly string[];
    readonly imports_removed: readonly string[];
    readonly exports_added: readonly string[];
    readonly exports_removed: readonly string[];
    readonly mitigations_added: readonly string[];
    readonly mitigations_removed: readonly string[];
    readonly provenance_changed: readonly string[];
  };
  readonly limitations: readonly string[];
}
