# Evidence gallery

Four HTML reports made by TraceForge. The four targets are **synthetic demo
packages that `scripts/gallery.mjs` builds itself** under one fixed absolute
path (`/tmp/traceforge-gallery`) before calling the real CLI on them. Nothing
renders HTML by hand: each report is the output of a single
`node dist/cli.js report <package>` run, and every number below was read back
out of the report itself. Because the targets are generated from fixed bytes at
a username-free path, the reports and their Evidence IDs reproduce byte for
byte on any machine — you do not need any particular application installed.

Open any file in this folder in a browser. It is one standalone page — no
scripts, no stylesheets, no fonts fetched from anywhere, no internet needed.
Nothing on the page can run.

| Report | The demo target | What it shows |
|---|---|---|
| [`demo-app.html`](gallery/demo-app.html) | DemoApp 2.0.0 (200) | an app that contains other apps |
| [`heavy-kit.html`](gallery/heavy-kit.html) | HeavyKit 3.2.1 (321) | one 8,388,608-byte member inside a bundle, and archives left closed |
| [`wide-app.html`](gallery/wide-app.html) | WideApp 0.9.0 (90) | the walk hitting its 5,000-member limit and saying so |
| [`linked-client.html`](gallery/linked-client.html) | Demo İstemci 0.3.0 (30) | a path that is only an alias, and a Turkish folder name |

Every report carries an Evidence ID. Those four, and the exact byte sizes, are
the whole point of this folder: they are reproducible with
`node scripts/gallery.mjs` (see [Regenerating](#regenerating)).

```console
ev_4ad427e3ed0d1029153bd4d19e8d4407f283aacbede5a533e00f0f5221224e9a   demo-app.html       15,206 B
ev_8f4518f0e088c4fea7b42a9b3e64b5fa9f544aa41dbbada4a35dea6f0eaea7ef   heavy-kit.html       9,997 B
ev_b204eb46a39655c8927ee52cff2b2a0349500584746f8e902b43bee9b9f26b91   wide-app.html       64,092 B
ev_761ff4508e786ca378b9e2fed921f8b2291ade9895abef32dfcb174d300b8cf3   linked-client.html  12,280 B
```

## 1. `demo-app.html` — an app that contains other apps

DemoApp is a small demo bundle: **18 files, 21 directories, 5 symbolic
links, 5.1 KiB**. The report lists its **5 nested packages**, and each one is
labelled with the identifier its own manifest declares:

- `Contents/Frameworks/DemoFramework.framework` — `com.example.demo.framework`
- `…/DemoFramework.framework/Versions/A/Updater.app` — `com.example.demo.updater`
- `…/Versions/A/XPCServices/Downloader.xpc` — `com.example.demo.downloader`
- `…/Versions/A/XPCServices/Installer.xpc` — `com.example.demo.installer`
- `Contents/Resources/DemoUI.bundle` — `com.example.demo.ui`

An updater that ships its own nested app and two XPC services is exactly the
kind of structure a flat file listing misses. The framework uses the classic
macOS version layout — the real bytes live under `Versions/A`, while names like
`Current`, the framework binary, `Info.plist` and `Resources` are aliases (five
of them in this tree, `Versions/Current` included). The report records every
alias with its target text and never follows it, so the inventory names each
file once.

**Why it matters:** you can see what is inside a bundle, not just that it exists.

## 2. `heavy-kit.html` — a big workload, and an honest boundary

HeavyKit is **8 files, 4 directories, 9.13 MiB**. The largest member is
`Contents/Frameworks/HeavyEngine` at **8,388,608 bytes** — 8.00 MiB, hashed in
one pass, and it is one row in a report that is only 9,997 bytes.

The report's Limitations box states that **3 archive members were counted and
hashed but not opened** (`app.asar`, `assets.zip`, `cache.car`; the first is
1,048,576 bytes). TraceForge does not pretend to have looked inside them.

**Why it matters:** the walk handles multi-megabyte members without loading them
into memory twice, and it draws its boundary in words you can read instead of
failing silently.

## 3. `wide-app.html` — the limit fired, and that is the evidence

WideApp carries 5,007 members — more than the inventory budget. The report shows
**5,000 files, 4 directories, 142.4 KiB**, and its Limitations box says:

> The walk stopped at the 5,000 member limit; later members are absent from the
> inventory and from the tree fingerprint.

Exactly **5,000 members were recorded** — by format: 1 Mach-O (the declared
executable) and 4,999 unknown; by kind: code 1, manifest 2, other 4,997. The 7
members beyond the cap stay unrecorded on purpose, and the report says so.

**Why it matters:** a tool that never stops is a tool that will one day stop
without telling you. Here the stop is written into the record, and the tree
fingerprint is computed over what was actually inventoried.

## 4. `linked-client.html` — an alias, and a name that is not ASCII

`/tmp/traceforge-gallery/Demo İstemci.app` is not a folder. It is a symlink
pointing at `Paketler/Demo İstemci.app`, and its name contains a dotted capital
**İ**; inside, the tree reaches through `Contents/Resources/İçeriler/` to a file
named `çalışma-günlüğü.txt`. TraceForge inventoried what the alias points to —
**10 files, 12 directories, 5 symbolic links, 2.6 KiB** — recorded the path you
actually asked for, and hashed every regular member without following the links
(each link is written down with its target text, never opened).

The report also shows something worth a second look: the outer bundle and the
nested `Contents/Frameworks/Demo İstemci.app` **declare the same identifier**,
`com.example.demo.istemci`. Two bundles, one name. That is a fact you can only
see once the inventory is recursive.

**Why it matters:** real filesystems have aliases, non-English names and
duplicated identities. The record handles all three and keeps its promise that
the tree fingerprint does not depend on where the package is mounted.

## Reading a report

Top to bottom, every report has the same shape:

1. **Identity badge** — `identity verified` means the page recomputed its own
  Evidence ID from the record content and it matched.
2. **Record** — Evidence ID, input SHA-256, input size, limitation count.
3. **Result** — package kind, member counts, tree SHA-256, the declared
   executable, the manifest claims, nested packages, largest members.
4. **Limitations** — what was not looked at, in plain sentences.
5. **Footer** — the command to re-verify the record yourself.

**On a phone, and on a narrow window:** the summary cards at the top fit any
screen, and the member tables no longer break the page. F4 measured the old
behaviour in headless Chrome at a 390 px viewport before the gallery was
switched to synthetic targets — a real report laid out 1,348 px wide and the
footer's Evidence ID overflowed its own box — and 0.3.0 closed it in the report
renderer (`src/core/report.ts`): every wide table now sits in a horizontally
scrollable `.table-wrap`, and `td code` and `footer *` get
`overflow-wrap: anywhere`, so a member path like
`Contents/Frameworks/DemoFramework.framework/Versions/A/XPCServices/Downloader.xpc/Contents/MacOS/Downloader`
(107 characters in this gallery) stays inside its cell and the footer ID inside
the page. The table test is locked in `test/report.test.ts`. A wide table is
still a wide table — it scrolls sideways — but nothing overflows a box any more,
and the record content is identical: the fix changed rendered HTML bytes only,
never a hashed record.

Confirm any of them locally:

```sh
node dist/cli.js evidence verify ev_b204eb46a39655c8927ee52cff2b2a0349500584746f8e902b43bee9b9f26b91
node dist/cli.js evidence verify-all
```

## What these reports do not prove

Saying this out loud is part of the product:

- **No origin.** Nothing here checks an Apple code signature or a notarization
  ticket. The manifest values (`CFBundleIdentifier`, versions, copyright) are
  **self-reported by the target** and labelled as claims. In these four reports
  every claim is a known-false-by-construction demo value — which is exactly
  how the tool treats a stranger's bundle: record what it says, not what it is.
- **No contents.** Archives are hashed, not opened. A bundle could hide anything
  inside `app.asar` and this report would say so rather than guess.
- **No behaviour.** No target was executed, launched or attached to — the demo
  targets are deliberately not runnable binaries. A report describes bytes, not
  what the software does when it runs.
- **Not complete**, in the one case where a limit applied — and the WideApp
  report is the case where it did.

## Regenerating

```sh
npm run build
node scripts/gallery.mjs              # builds the demo targets, writes examples/gallery + site/gallery
node scripts/gallery.mjs --check      # fresh run in a temp dir, byte-compared, keeps the repository clean
node scripts/gallery.mjs --only wide-app # one target
node scripts/gallery.mjs --audit site/gallery/demo-app.html
```

The script builds the four synthetic demo packages under
`/tmp/traceforge-gallery` from fixed bytes (it never copies a file out of an
installed application), then only calls
`node dist/cli.js report <package>`; it renders no HTML of its own. It enforces
the gallery budget — **one report ≤ 700 KiB, gallery total ≤ 2 MiB** (the four
reports here are 101,575 bytes counted once) — and if a report ever came back
over its cap it would be dropped and replaced by the plain-text
`tforge app <package> --no-save` transcript instead, because the stopping point
is the evidence in that case.

Each generated file is also audited before it is kept: the auditor parses every
tag in the HTML and fails the run on a disallowed tag, a `src=`/`href=` style
remote attribute, or an event-handler attribute. That gate was tested with
payloads, not assumed — a fixture bundle whose file and manifest names contain
`<script>alert(1)`, `<img src=x onerror=alert(1)>` and `</td>`-style break-outs
was scanned, and the report escaped all of it (`grep -c "<script"` → `0`, and
the strings appear on the page as visible text). The injected copy that adds a
real `<script>`/`<img onerror>`/`<link href>` is rejected with exit 1.

Reports are byte-stable for the same input: `--check` rebuilds the fixtures,
regenerates all four and compares them to the committed files, which is how
this folder stays trustworthy after any change — rerun it and drift is reported
instead of hidden.
