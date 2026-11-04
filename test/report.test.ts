import { expect, it } from "vitest";

import { createEvidenceRecord } from "../src/core/evidence.js";
import { renderEvidenceReport } from "../src/core/report.js";
import type { AppInventory, BinaryInventory, SliceInventory } from "../src/core/types.js";

// The F4 gallery measured a real overflow: at a 390 px viewport the member
// tables laid out 1,348 px wide and the footer's 64-hex Evidence ID spilled
// out of its box. The fix is CSS-only: wide tables scroll inside a
// `.table-wrap` and long tokens break anywhere (`td code`, `footer *`).
// HTML bytes never enter the hashed record, so these layout classes must not
// change any Evidence ID — the last assertion pins that down.

const longSection = "__very_long_section_name_that_keeps_going_and_going".repeat(4); // 212 chars
const longMemberPath =
  "Contents/Resources/app.asar.unpacked/node_modules/aoq-electron-sdk/prebuilds/darwin-universal/AoqClientSdk.framework/Versions/A/Frameworks/openhevc.framework/Versions/A/openhevc"; // 177 chars
const longValue = `https://example.invalid/${"a-very-long-producer-claim-string".repeat(4)}`;

const binaryRecord = () =>
  createEvidenceRecord(
    "inspect",
    { path: "/tmp/overflow-demo", sha256: "a".repeat(64), size: 4 },
    {
      schema: "traceforge.inventory.v2",
      path: "/tmp/overflow-demo",
      sha256: "a".repeat(64),
      size: 4,
      format: "mach-o",
      slices: [
        {
          architecture: "arm64",
          bits: 64,
          endian: "little",
          fileType: "executable",
          entrypoint: "0x100003f00",
          entrypointKind: "virtual-address",
          buildId: null,
          security: { present: ["nx"], absent: [], undetermined: [] },
          provenance: { producer: longValue },
          sections: [
            {
              name: longSection,
              segment: "__TEXT",
              address: "0x100008000",
              offset: 32768,
              size: 4096,
              sha256: "b".repeat(64),
              flags: "0x80000400",
            },
          ],
          imports: [],
          exports: [],
          libraries: [],
          limitations: [],
        } satisfies SliceInventory,
      ],
      limitations: [],
    } satisfies BinaryInventory,
    [],
    "0.3.0",
  );

const appRecord = () =>
  createEvidenceRecord(
    "app",
    { path: "/Applications/Overflow.app", sha256: "f".repeat(64), size: 10 },
    {
      schema: "traceforge.app.inventory.v1",
      path: "/Applications/Overflow.app",
      kind: "app",
      layout: "macos",
      tree_sha256: "c".repeat(64),
      total_bytes: 10,
      manifest: {
        path: "Contents/Info.plist",
        size: 10,
        sha256: "d".repeat(64),
        encoding: "xml",
        keys: 2,
        claims: { CFBundleIdentifier: longValue, CFBundleName: "Overflow" },
      },
      pkg_info: {},
      declared_executable: { name: null, path: null, present: false, sha256: null },
      nested: [
        {
          path: longMemberPath,
          kind: "framework",
          layout: "macos",
          manifest_path: null,
          declared: { CFBundleIdentifier: longValue },
        },
      ],
      counts: {
        files: 1,
        directories: 2,
        links: 0,
        special: 0,
        unreadable: 0,
        executable: 0,
        total_bytes: 10,
        hashed_bytes: 10,
        by_kind: { resource: 1 },
        by_format: { unknown: 1 },
        architectures: {},
      },
      files: [
        {
          path: longMemberPath,
          size: 10,
          sha256: "e".repeat(64),
          kind: "resource",
          format: "unknown",
          executable: false,
          architectures: [],
          file_types: [],
          link_target: null,
        },
      ],
      limitations: [],
    } satisfies AppInventory,
    [],
    "0.3.0",
  );

it("report CSS wraps long tokens in table cells and the footer", () => {
  const html = renderEvidenceReport(binaryRecord());
  expect(html).toContain("identity verified");
  expect(html).toContain("overflow-wrap: anywhere");
  expect(html).toContain("td code, footer *");
});

it("wide binary tables scroll inside a table-wrap and keep long names", () => {
  const record = binaryRecord();
  const html = renderEvidenceReport(record);
  const wraps = html.match(/<div class="table-wrap">/g) ?? [];
  // one for the provenance claim table, one for the section table
  expect(wraps.length).toBeGreaterThanOrEqual(2);
  expect(html).toContain(longSection);
  expect(html).toContain(longValue);
  // the section row sits inside the wrapper, not loose in the slice
  const wrapIndex = html.lastIndexOf('<div class="table-wrap">');
  const sectionIndex = html.indexOf(longSection);
  expect(sectionIndex).toBeGreaterThan(wrapIndex);
});

it("package reports wrap member, nested and manifest tables", () => {
  const html = renderEvidenceReport(appRecord());
  const wraps = html.match(/<div class="table-wrap">/g) ?? [];
  // manifest claims + nested packages + largest members
  expect(wraps.length).toBeGreaterThanOrEqual(3);
  expect(html).toContain(longMemberPath);
});

it("layout-only HTML changes never move the Evidence ID", () => {
  const record = appRecord();
  const html = renderEvidenceReport(record);
  expect(html).toContain(record.evidence_id);
  // re-rendering an identical record is byte-identical (determinism guard)
  expect(renderEvidenceReport(record)).toBe(html);
});
