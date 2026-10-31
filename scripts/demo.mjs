#!/usr/bin/env node
import { mkdir, rm } from "node:fs/promises";
import { join } from "node:path";

import { compare, inspect, scanBinary, EvidenceStore } from "../dist/index.js";
import { writeEvidenceReport } from "../dist/core/report.js";

const root = join(process.cwd(), ".cache", "demo");
const store = new EvidenceStore(join(root, "evidence"));
const reportPath = join(root, "traceforge-report.html");
const target = "/bin/ls";
const other = "/usr/bin/true";

await rm(root, { recursive: true, force: true });
await mkdir(root, { recursive: true });

const log = (message) => process.stdout.write(`${message}\n`);
log("TraceForge demo · read-only binary evidence");
log("----------------------------------------");

const scan = await scanBinary(target, store, "0.1.0");
log(`✓ scan       ${scan.result.format} · ${scan.result.slices.length} slice(s) · ${scan.record.evidence_id}`);

const detail = await inspect(target, store, "0.1.0");
log(`✓ inspect    ${detail.result.slices.reduce((sum, slice) => sum + slice.sections.length, 0)} sections · ${detail.record.evidence_id}`);

const diff = await compare(target, other, store, "0.1.0");
log(`✓ diff       changed=${diff.result.changed} · ${diff.record.evidence_id}`);

const verified = await store.verifyAll();
log(`✓ verify-all ${verified.valid} valid · ${verified.invalid.length} invalid`);

await writeEvidenceReport(detail.record, reportPath);
log(`✓ report     ${reportPath}`);
log("");
log(`Evidence store: ${store.root}`);
log("Open the report in a browser. No target was executed.");
