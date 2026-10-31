import { mkdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

import { evidenceId } from "./canonical.js";
import type {
  BinaryInventory,
  ComparisonResult,
  EvidenceRecord,
  SectionInfo,
  SliceInventory,
} from "./types.js";

const escapeHtml = (value: unknown): string =>
  String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

const formatBytes = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MiB`;
};

const short = (value: string | null, length = 16): string =>
  value === null ? "—" : `${value.slice(0, length)}${value.length > length ? "…" : ""}`;

const sectionRows = (sections: readonly SectionInfo[]): string =>
  sections
    .slice(0, 250)
    .map(
      (section) => `<tr>
        <td><code>${escapeHtml(section.name)}</code></td>
        <td>${escapeHtml(section.segment ?? "—")}</td>
        <td>${escapeHtml(section.address ?? "—")}</td>
        <td>${escapeHtml(section.offset)}</td>
        <td>${escapeHtml(formatBytes(section.size))}</td>
        <td><code>${escapeHtml(short(section.sha256))}</code></td>
      </tr>`,
    )
    .join("\n");

const symbolList = (title: string, values: readonly string[]): string => {
  const shown = values.slice(0, 120);
  return `<div class="symbol-block">
    <h4>${escapeHtml(title)} <span>${escapeHtml(values.length)}</span></h4>
    ${shown.length === 0 ? '<p class="muted">None observed.</p>' : `<ul>${shown.map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("")}</ul>`}
    ${values.length > shown.length ? `<p class="muted">${escapeHtml(values.length - shown.length)} more not shown in this report.</p>` : ""}
  </div>`;
};

const sliceBlock = (slice: SliceInventory): string => `
  <section class="slice">
    <div class="slice-head">
      <h3>${escapeHtml(slice.architecture)}</h3>
      <span class="pill">${escapeHtml(slice.bits)}-bit ${escapeHtml(slice.endian)}</span>
      <span class="pill">${escapeHtml(slice.fileType)}</span>
      ${slice.buildId === null ? "" : `<span class="pill muted">build ${escapeHtml(short(slice.buildId, 24))}</span>`}
    </div>
    <div class="stats">
      <div><strong>${escapeHtml(slice.sections.length)}</strong><span>sections</span></div>
      <div><strong>${escapeHtml(slice.imports.length)}</strong><span>imports</span></div>
      <div><strong>${escapeHtml(slice.exports.length)}</strong><span>exports</span></div>
      <div><strong>${escapeHtml(slice.libraries.length)}</strong><span>libraries</span></div>
    </div>
    ${slice.entrypoint === null ? "" : `<p class="muted">Entrypoint <code>${escapeHtml(slice.entrypoint)}</code> · ${escapeHtml(slice.entrypointKind ?? "unknown")}</p>`}
    <table>
      <thead><tr><th>Section</th><th>Segment</th><th>Address</th><th>Offset</th><th>Size</th><th>SHA-256</th></tr></thead>
      <tbody>${sectionRows(slice.sections)}</tbody>
    </table>
    <div class="symbol-grid">
      ${symbolList("Imports", slice.imports)}
      ${symbolList("Exports", slice.exports)}
      ${symbolList("Libraries", slice.libraries)}
    </div>
  </section>`;

const inventoryBlock = (inventory: BinaryInventory): string => `
  <section class="summary">
    <div><span>Format</span><strong>${escapeHtml(inventory.format)}</strong></div>
    <div><span>Size</span><strong>${escapeHtml(formatBytes(inventory.size))}</strong></div>
    <div><span>Slices</span><strong>${escapeHtml(inventory.slices.length)}</strong></div>
    <div><span>SHA-256</span><strong class="mono">${escapeHtml(short(inventory.sha256, 24))}</strong></div>
  </section>
  ${inventory.slices.map(sliceBlock).join("\n")}
  ${inventory.limitations.length === 0 ? "" : `<section class="limitations"><h3>Limitations</h3><ul>${inventory.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>`}`;

const changeList = (label: string, values: readonly string[]): string =>
  values.length === 0
    ? ""
    : `<div class="change"><h4>${escapeHtml(label)} <span>${escapeHtml(values.length)}</span></h4><ul>${values.slice(0, 80).map((value) => `<li><code>${escapeHtml(value)}</code></li>`).join("")}</ul>${values.length > 80 ? `<p class="muted">More changes not shown.</p>` : ""}</div>`;

const comparisonBlock = (result: ComparisonResult): string => `
  <section class="summary">
    <div><span>Result</span><strong class="${result.changed ? "warn" : "ok"}">${result.changed ? "changed" : "identical"}</strong></div>
    <div><span>Left</span><strong class="mono">${escapeHtml(short(result.left.sha256, 24))}</strong></div>
    <div><span>Right</span><strong class="mono">${escapeHtml(short(result.right.sha256, 24))}</strong></div>
    <div><span>Size delta</span><strong>${escapeHtml(result.right.size - result.left.size)} B</strong></div>
  </section>
  <div class="change-grid">
    ${changeList("Slices added", result.changes.slices_added)}
    ${changeList("Slices removed", result.changes.slices_removed)}
    ${changeList("Sections added", result.changes.sections_added)}
    ${changeList("Sections removed", result.changes.sections_removed)}
    ${changeList("Sections changed", result.changes.sections_changed)}
    ${changeList("Imports added", result.changes.imports_added)}
    ${changeList("Imports removed", result.changes.imports_removed)}
    ${changeList("Exports added", result.changes.exports_added)}
    ${changeList("Exports removed", result.changes.exports_removed)}
  </div>
  ${result.limitations.length === 0 ? "" : `<section class="limitations"><h3>Limitations</h3><ul>${result.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul></section>`}`;

const resultBlock = (result: unknown): string => {
  if (result !== null && typeof result === "object") {
    const value = result as Record<string, unknown>;
    if (value.schema === "traceforge.inventory.v1")
      return inventoryBlock(result as BinaryInventory);
    if (value.schema === "traceforge.comparison.v1")
      return comparisonBlock(result as ComparisonResult);
  }
  return `<pre>${escapeHtml(JSON.stringify(result, null, 2))}</pre>`;
};

const logo = `<svg width="42" height="42" viewBox="0 0 512 512" aria-hidden="true"><rect width="512" height="512" rx="112" fill="#0b0f14"/><path d="M144 336 256 144l112 192-112 48z" fill="none" stroke="#5eead4" stroke-width="22" stroke-linejoin="round"/><path d="M176 320h160M208 256h96" stroke="#fbbf24" stroke-width="22" stroke-linecap="round"/></svg>`;

export const renderEvidenceReport = (record: EvidenceRecord): string => {
  const { evidence_id: id, ...content } = record;
  const verified = evidenceId(content) === id;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>TraceForge Evidence ${escapeHtml(id.slice(0, 16))}</title>
<style>
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #070b10; color: #dbe7f3; font: 14px/1.6 Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif; }
.wrap { max-width: 1180px; margin: 0 auto; padding: 36px 24px 64px; }
header { display: flex; align-items: center; justify-content: space-between; gap: 20px; border-bottom: 1px solid #203041; padding-bottom: 22px; }
.brand { display: flex; align-items: center; gap: 14px; }
.brand h1 { margin: 0; font-size: 24px; letter-spacing: -.03em; }
.brand p { margin: 2px 0 0; color: #7f93a8; }
.badge { border: 1px solid #2b4a5e; color: #5eead4; border-radius: 999px; padding: 5px 10px; font-size: 12px; font-weight: 700; }
.badge.ok { border-color: #1f6f5c; background: #0c2c25; }
.badge.warn { border-color: #7a5a1d; background: #2a220c; color: #fbbf24; }
h2 { font-size: 13px; letter-spacing: .14em; text-transform: uppercase; color: #7f93a8; margin: 34px 0 12px; }
h3 { margin: 0 0 8px; }
h4 { margin: 0 0 8px; font-size: 13px; }
h4 span { color: #5eead4; margin-left: 6px; }
.summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; }
.summary div { background: #0d151e; border: 1px solid #203041; border-radius: 10px; padding: 14px; }
.summary span { display: block; color: #7f93a8; font-size: 11px; text-transform: uppercase; letter-spacing: .1em; margin-bottom: 6px; }
.summary strong { font-size: 15px; }
.slice { border: 1px solid #203041; border-radius: 12px; padding: 20px; margin: 16px 0; background: #0a1118; }
.slice-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.slice-head h3 { margin: 0; font-size: 20px; color: #c4b5fd; }
.pill { border: 1px solid #2b3e52; border-radius: 999px; color: #a9bad0; padding: 2px 8px; font-size: 11px; }
.stats { display: flex; gap: 26px; margin: 16px 0; }
.stats div { display: flex; flex-direction: column; }
.stats strong { font-size: 22px; }
.stats span { color: #7f93a8; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; }
table { width: 100%; border-collapse: collapse; margin: 14px 0; }
th { text-align: left; color: #7f93a8; font-size: 11px; text-transform: uppercase; letter-spacing: .08em; border-bottom: 1px solid #203041; padding: 8px 6px; }
td { border-bottom: 1px solid #16212c; padding: 7px 6px; color: #b7c6d8; }
code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
code { background: #12202d; color: #b8f7ea; padding: 1px 5px; border-radius: 4px; font-size: .92em; }
.symbol-grid, .change-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-top: 18px; }
.symbol-block, .change { background: #0d151e; border: 1px solid #203041; border-radius: 10px; padding: 14px; min-width: 0; }
ul { margin: 0; padding-left: 18px; color: #b7c6d8; }
li { margin: 3px 0; overflow-wrap: anywhere; }
.muted { color: #7f93a8 !important; }
.limitations { border: 1px solid #3b3020; background: #19150c; border-radius: 10px; padding: 16px; margin-top: 18px; }
.limitations h3 { color: #fbbf24; }
.ok { color: #5eead4; } .warn { color: #fbbf24; }
pre { overflow: auto; background: #0d151e; border: 1px solid #203041; border-radius: 10px; padding: 16px; }
footer { color: #56697d; font-size: 12px; border-top: 1px solid #16212c; margin-top: 40px; padding-top: 18px; }
@media (max-width: 800px) { .summary, .symbol-grid, .change-grid { grid-template-columns: 1fr 1fr; } }
@media (max-width: 520px) { .summary, .symbol-grid, .change-grid { grid-template-columns: 1fr; } }
</style>
</head>
<body>
<div class="wrap">
<header>
  <div class="brand">${logo}<div><h1>TraceForge Evidence</h1><p>${escapeHtml(record.operation)} · ${escapeHtml(record.tool.name)} ${escapeHtml(record.tool.version)}</p></div></div>
  <span class="badge ${verified ? "ok" : "warn"}">${verified ? "identity verified" : "verification failed"}</span>
</header>
<h2>Record</h2>
<div class="summary">
  <div><span>Evidence ID</span><strong class="mono">${escapeHtml(short(id, 22))}</strong></div>
  <div><span>Input SHA-256</span><strong class="mono">${escapeHtml(short(record.input.sha256, 22))}</strong></div>
  <div><span>Input size</span><strong>${escapeHtml(formatBytes(record.input.size))}</strong></div>
  <div><span>Limitations</span><strong>${escapeHtml(record.limitations.length)}</strong></div>
</div>
<p class="muted">${escapeHtml(record.input.path)}${record.input.related === undefined ? "" : ` · related: ${record.input.related.map((item) => escapeHtml(item.path)).join(", ")}`}</p>
<h2>Result</h2>
${resultBlock(record.result)}
<footer>Generated by TraceForge. Evidence is content-addressed and locally authenticated. Verify with <code>tforge evidence verify ${escapeHtml(id)}</code>.</footer>
</div>
</body>
</html>`;
};

export const writeEvidenceReport = async (
  record: EvidenceRecord,
  path: string,
): Promise<string> => {
  const target = resolve(path);
  await mkdir(dirname(target), { recursive: true, mode: 0o700 });
  const temporary = `${target}.${process.pid}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, renderEvidenceReport(record), { mode: 0o600 });
    await rename(temporary, target);
  } catch (cause) {
    await rm(temporary, { force: true }).catch(() => undefined);
    throw cause;
  }
  return target;
};
