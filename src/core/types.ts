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

export interface SliceInventory {
  readonly architecture: string;
  readonly bits: 32 | 64;
  readonly endian: "little" | "big";
  readonly fileType: string;
  readonly entrypoint: string | null;
  readonly entrypointKind: "file-offset" | "virtual-address" | "rva" | null;
  readonly buildId: string | null;
  readonly sections: readonly SectionInfo[];
  readonly imports: readonly string[];
  readonly exports: readonly string[];
  readonly libraries: readonly string[];
  readonly limitations: readonly string[];
}

export interface BinaryInventory {
  readonly schema: "traceforge.inventory.v1";
  readonly path: string;
  readonly sha256: string;
  readonly size: number;
  readonly format: BinaryFormat;
  readonly slices: readonly SliceInventory[];
  readonly limitations: readonly string[];
}

export interface EvidenceRecord<Result = unknown> {
  readonly schema: "traceforge.evidence.v1";
  readonly evidence_id: string;
  readonly operation: "scan" | "inspect" | "compare";
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
  };
  readonly limitations: readonly string[];
}
