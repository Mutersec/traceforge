import { TraceForgeError } from "./errors.js";

/**
 * Transport ergonomics for agents: cursors, page limits, field selectors and
 * the per-response size ceiling. Nothing in this module touches stored
 * Evidence. Paging is a transport convenience, not an evidence boundary; the
 * record in the store always stays complete.
 */

export const MAX_PAGE_ITEMS = 500;
export const DEFAULT_PAGE_ITEMS = 100;
export const MAX_TOOL_TEXT_BYTES = 262_144;

export interface PageRequest {
  readonly cursor?: string;
  readonly limit?: number;
}

export interface Page<T> {
  readonly items: readonly T[];
  readonly next_cursor: string | null;
  readonly total: number;
  readonly limit: number;
}

export interface ListPage {
  readonly limit: number;
  readonly returned: number;
  readonly next_cursor: string | null;
  readonly total: number;
}

export interface FieldSelection<Value> {
  readonly value: Value;
  readonly omitted: readonly string[];
}

/** Cursors are plain decimal offsets; inventories are sorted, so an offset cursor is stable. */
const OFFSET_CURSOR = /^(?:0|[1-9][0-9]{0,14})$/u;

export const validatedLimit = (request: PageRequest): number => {
  const limit = request.limit ?? DEFAULT_PAGE_ITEMS;
  if (!Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_ITEMS)
    throw new TraceForgeError(
      "invalid_input",
      `The page limit must be an integer between 1 and ${MAX_PAGE_ITEMS}, got ${String(request.limit ?? "default-requested")} — pass limit as a number from 1 to ${MAX_PAGE_ITEMS}`,
    );
  return limit;
};

export const pageOffset = (request: PageRequest): number => {
  const cursor = request.cursor;
  if (cursor === undefined) return 0;
  if (!OFFSET_CURSOR.test(cursor))
    throw new TraceForgeError(
      "invalid_input",
      `The page cursor "${cursor}" is not an offset this tool produced; pass back the next_cursor from a previous page, or omit cursor to start at the beginning`,
    );
  const offset = Number(cursor);
  if (!Number.isSafeInteger(offset))
    throw new TraceForgeError("invalid_input", `The page cursor "${cursor}" is out of range`);
  return offset;
};

export const pageItems = <T>(items: readonly T[], request: PageRequest): Page<T> => {
  const limit = validatedLimit(request);
  const offset = pageOffset(request);
  const window = items.slice(offset, offset + limit);
  const end = offset + window.length;
  return {
    items: window,
    next_cursor: end < items.length ? String(end) : null,
    total: items.length,
    limit,
  };
};

export const INSPECT_FIELDS = [
  "sections",
  "imports",
  "exports",
  "libraries",
  "provenance",
  "security",
] as const;

export const PACKAGE_FIELDS = ["files", "manifest", "nested", "limitations"] as const;

/** Field name -> payload keys it controls, covering both the complete and the summary shape. */
const INSPECT_DROP_KEYS: Readonly<Record<(typeof INSPECT_FIELDS)[number], readonly string[]>> = {
  sections: ["sections"],
  imports: ["imports"],
  exports: ["exports"],
  libraries: ["libraries"],
  provenance: ["provenance"],
  security: ["security", "mitigations", "undetermined_mitigations"],
};

const PACKAGE_DROP_KEYS: Readonly<Record<(typeof PACKAGE_FIELDS)[number], readonly string[]>> = {
  files: ["files", "code"],
  manifest: ["manifest", "pkg_info", "declared_executable"],
  nested: ["nested"],
  limitations: ["limitations"],
};

export const parseOnly = (raw: string, allowed: readonly string[]): string[] => {
  const parts = raw
    .split(",")
    .map((part) => part.trim())
    .filter((part) => part.length > 0);
  if (parts.length === 0)
    throw new TraceForgeError(
      "invalid_input",
      `--only needs at least one field; allowed: ${allowed.join(", ")}`,
    );
  const unknown = parts.filter((part) => !allowed.includes(part));
  if (unknown.length > 0)
    throw new TraceForgeError(
      "invalid_input",
      `Unknown --only field ${unknown.join(", ")}; allowed fields are: ${allowed.join(", ")}`,
    );
  return [...new Set(parts)];
};

export const omittedFields = (
  keep: readonly string[] | null,
  allowed: readonly string[],
): readonly string[] =>
  keep === null ? [] : allowed.filter((field) => !keep.includes(field));

const dropKeys = (
  target: Record<string, unknown>,
  keys: readonly string[],
): Record<string, unknown> => {
  const copy: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(target))
    if (!keys.includes(name)) copy[name] = value;
  return copy;
};

const droppedKeys = (
  allowed: readonly string[],
  keep: readonly string[],
  map: Readonly<Record<string, readonly string[]>>,
): string[] =>
  allowed.flatMap((field) => (keep.includes(field) ? [] : map[field] ?? []));

/**
 * Keeps the listed inventory fields inside each slice and removes the others
 * from the returned payload. Identity fields (path, sha256, architecture,
 * entrypoint, counts) are never selectable; they always stay. The value is
 * returned uncloned when nothing is dropped, so unfiltered responses stay
 * byte-identical to the old ones.
 */
export const selectInspectFields = <Value extends object>(
  inventory: Value,
  keep: readonly string[],
): FieldSelection<Value> => {
  const omitted = omittedFields(keep, INSPECT_FIELDS);
  if (omitted.length === 0) return { value: inventory, omitted: [] };
  const keys = droppedKeys(INSPECT_FIELDS, keep, INSPECT_DROP_KEYS);
  const record = inventory as unknown as Record<string, unknown>;
  const slices = record.slices;
  const value = Array.isArray(slices)
    ? {
        ...record,
        slices: slices.map((slice) =>
          slice !== null && typeof slice === "object"
            ? dropKeys(slice as Record<string, unknown>, keys)
            : slice,
        ),
      }
    : record;
  return { value: value as Value, omitted };
};

/** Same contract as selectInspectFields for package inventories and summaries. */
export const selectPackageFields = <Value extends object>(
  inventory: Value,
  keep: readonly string[],
): FieldSelection<Value> => {
  const omitted = omittedFields(keep, PACKAGE_FIELDS);
  if (omitted.length === 0) return { value: inventory, omitted: [] };
  const keys = droppedKeys(PACKAGE_FIELDS, keep, PACKAGE_DROP_KEYS);
  return {
    value: dropKeys(inventory as unknown as Record<string, unknown>, keys) as Value,
    omitted,
  };
};

/** Pages one named top-level list (package members or summary code entries). */
export const pageNamedList = <Value extends object>(
  inventory: Value,
  key: string,
  request: PageRequest,
): { value: Value; page: ListPage } => {
  const record = inventory as unknown as Record<string, unknown>;
  const limit = validatedLimit(request);
  const offset = pageOffset(request);
  const list = record[key];
  if (!Array.isArray(list))
    return { value: inventory, page: { limit, returned: 0, next_cursor: null, total: 0 } };
  const page = pageItems(list as readonly unknown[], request);
  return {
    value: { ...record, [key]: page.items } as Value,
    page: {
      limit: page.limit,
      returned: page.items.length,
      next_cursor: page.next_cursor,
      total: page.total,
    },
  };
};

const BINARY_LIST_FIELDS = ["sections", "imports", "exports", "libraries"] as const;

/**
 * Applies one shared offset window to the list fields of every slice.
 * A fixed stride means each entry is visited exactly once across a cursor
 * walk; a list shorter than the window simply returns empty in later pages.
 */
export const pageBinaryLists = <Value extends object>(
  inventory: Value,
  request: PageRequest,
): { value: Value; page: ListPage } => {
  const limit = validatedLimit(request);
  const offset = pageOffset(request);
  const record = inventory as unknown as Record<string, unknown>;
  const slices = record.slices;
  if (!Array.isArray(slices)) {
    return { value: inventory, page: { limit, returned: 0, next_cursor: null, total: 0 } };
  }
  let returned = 0;
  let total = 0;
  let hasMore = false;
  const pagedSlices = slices.map((entry) => {
    if (entry === null || typeof entry !== "object") return entry;
    const slice = entry as Record<string, unknown>;
    const next: Record<string, unknown> = { ...slice };
    for (const field of BINARY_LIST_FIELDS) {
      const list = slice[field];
      if (!Array.isArray(list)) continue;
      total += list.length;
      const window = list.slice(offset, offset + limit);
      returned += window.length;
      if (list.length > offset + limit) hasMore = true;
      next[field] = window;
    }
    return next;
  });
  return {
    value: { ...record, slices: pagedSlices } as Value,
    page: {
      limit,
      returned,
      next_cursor: hasMore ? String(offset + limit) : null,
      total,
    },
  };
};
