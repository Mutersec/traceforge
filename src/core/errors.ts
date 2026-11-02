export class TraceForgeError extends Error {
  constructor(
    readonly code:
      | "invalid_path"
      | "not_a_file"
      | "not_a_directory"
      | "file_too_large"
      | "parse_error"
      | "unsupported_format"
      | "evidence_not_found"
      | "evidence_integrity"
      | "signature_not_found"
      | "signature_format"
      | "signature_write_failed"
      | "signature_mismatch"
      | "key_mismatch"
      | "signature_invalid"
      | "invalid_input",
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options);
    this.name = "TraceForgeError";
  }
}
