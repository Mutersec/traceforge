export class TraceForgeError extends Error {
  constructor(
    readonly code:
      | "invalid_path"
      | "not_a_file"
      | "file_too_large"
      | "parse_error"
      | "unsupported_format"
      | "evidence_not_found"
      | "evidence_integrity"
      | "invalid_input",
    message: string,
    options?: { readonly cause?: unknown },
  ) {
    super(message, options);
    this.name = "TraceForgeError";
  }
}
