# Evidence gallery

Four HTML reports, made by TraceForge on one Apple Silicon MacBook, about four
applications that are really installed on it. Nothing was staged: each report is
the output of a single command, and every number below was read back out of the
report itself.

Open any file in this folder in a browser. It is one standalone page — no
scripts, no stylesheets, no fonts fetched from anywhere, no internet needed.
Nothing on the page can run.

| Report | The application | What it shows |
|---|---|---|
| [`airstats.html`](gallery/airstats.html) | AirStats 1.3.2 (8) | an app that contains other apps |
| [`obsidian.html`](gallery/obsidian.html) | Obsidian | one 378.9 MiB file inside a bundle |
| [`qoder.html`](gallery/qoder.html) | Qoder 0.4.11 | the walk hitting its 5,000-member limit and saying so |
| [`riot-client.html`](gallery/riot-client.html) | Riot Client | a path that is only an alias, and a Turkish folder name |

Every report carries an Evidence ID. Those four, and the exact byte sizes, are
the whole point of this folder: they are reproducible with
`node scripts/gallery.mjs` (see [Regenerating](#regenerating)).

```console
ev_19f2674909d4a320a2a389a4a22b986bbdead0c9361ca154db1aacdad135b227   airstats.html    37,363 B
ev_2060636de94207c12cdf6bd4b898183aba495319120f1dea9f7db126bb032c87   obsidian.html    81,373 B
ev_0b58f8187a470543e4e9d8b48662ceac4e61b3540afc584b8e25d46d7b44669c   qoder.html       83,700 B
ev_10acf3ad89b337409fb93091fc9f04a1dfa943bad98cfe63aadf91555e65aa56   riot-client.html 79,420 B
```

## 1. `airstats.html` — an app that contains other apps

AirStats is a small menu-bar app: **95 files, 65 directories, 8.78 MiB**. The
report lists its **5 nested packages**, and each one is labelled with the
identifier its own manifest declares:

- `Contents/Frameworks/Sparkle.framework` — the update library
- `…/Sparkle.framework/Versions/B/Updater.app` — `org.sparkle-project.Sparkle.Updater`
- `…/XPCServices/Downloader.xpc` — `org.sparkle-project.DownloaderService`
- `…/XPCServices/Installer.xpc` — `org.sparkle-project.InstallerLauncher`
- `Contents/Resources/AirStats_AirStatUI.bundle`

An updater that ships its own nested app and two XPC services is exactly the
kind of structure a flat file listing misses. The report also shows the
`SUFeedURL` claim (`https://airstats.app/appcast.xml`) straight from the
framework's own metadata — the address the app would phone home to for updates,
recorded as a claim, not as an observation.

**Why it matters:** you can see what is inside a bundle, not just that it exists.

## 2. `obsidian.html` — a real workload, and an honest boundary

Obsidian is **278 files, 322 directories, 513.63 MiB**. The largest member is
`Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework`
at **397,316,032 bytes** — 378.9 MiB, hashed in one pass, and it is one row in a
report that is only 81 KB.

The report's Limitations box states that **2 archive members were counted and
hashed but not opened** (`app.asar`, `obsidian.asar`, the second one 25,787,463
bytes). TraceForge does not pretend to have looked inside them.

**Why it matters:** the tool is useful on real software at real sizes, and it
draws its boundary in words you can read instead of failing silently.

## 3. `qoder.html` — the limit fired, and that is the evidence

Qoder is bigger than the inventory budget. The report shows
**4,975 files, 1,241 directories, 705.59 MiB**, and its Limitations box says:

> The walk stopped at the 5,000 member limit; later members are absent from the
> inventory and from the tree fingerprint.

Exactly **5,000 members carry a format label**: 4,907 unknown, 57 Mach-O, 20
ELF, 12 PE, 4 WebAssembly. Inside one macOS `.app`, the report finds Windows
binaries (`…/vendor/wintun/bin/amd64/wintun.dll`) and Linux/Android ones
(`…/appium-ios-tuntap/prebuilds/linux-x64/appium-ios-tuntap.node`).

**Why it matters:** a tool that never stops is a tool that will one day stop
without telling you. Here the stop is written into the record, and the tree
fingerprint is computed over what was actually inventoried.

## 4. `riot-client.html` — an alias, and a name that is not ASCII

`/Applications/Riot İstemcisi.app` is not a folder. It is an alias pointing at
`/Users/Shared/Riot Games/Riot Client.app`, and its name contains a dotted
capital **İ**. TraceForge inventoried what the alias points to —
**256 files, 118 directories, 1,261.55 MiB** — recorded the path you actually
asked for, and hashed 1.2 GiB of members without following the 14 symbolic
links inside the bundle (each link is written down with its target text, never
opened).

The report also shows something worth a second look: the outer bundle and the
nested `Contents/Frameworks/Riot Client.app` **declare the same identifier**,
`com.riotgames.RiotGames.RiotClient`. Two bundles, one name. That is a fact you
can only see once the inventory is recursive.

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
screen, but the member tables are wider than a phone. Measured in headless
Chrome at a 390 px viewport, `airstats.html` lays out 1,348 px wide and
`qoder.html` 1,195 px, so the tables need a sideways scroll; the footer's
Evidence ID overflows its own 342 px box (454 px of content). The cause is in
the report renderer's CSS (`src/core/report.ts`): `td code` and `footer` have no
`overflow-wrap`, and a member path like
`Contents/Resources/app.asar.unpacked/node_modules/aoq-electron-sdk/prebuilds/darwin-universal/AoqClientSdk.framework/Versions/A/Frameworks/openhevc.framework/Versions/A/openhevc`
is 177 characters with nowhere to break. This is a known limitation of the
generated report, not of the record — nothing is missing, it just scrolls. The
same content on a desktop at 1,280 px also overflows (1,398 px), so this is not
only a mobile issue.

Confirm any of them locally:

```sh
node dist/cli.js evidence verify ev_0b58f8187a470543e4e9d8b48662ceac4e61b3540afc584b8e25d46d7b44669c
node dist/cli.js evidence verify-all
```

## What these reports do not prove

Saying this out loud is part of the product:

- **No origin.** Nothing here checks an Apple code signature or a notarization
  ticket. The manifest values (`CFBundleIdentifier`, versions, `SUFeedURL`) are
  **self-reported by the target** and labelled as claims.
- **No contents.** Archives are hashed, not opened. A bundle could hide anything
  inside `app.asar` and this report would say so rather than guess.
- **No behaviour.** No target was executed, launched or attached to. A report
  describes bytes, not what the software does when it runs.
- **Not complete**, in the one case where a limit applied — and the Qoder report
  is the case where it did.

## Regenerating

```sh
npm run build
node scripts/gallery.mjs              # writes examples/gallery + site/gallery
node scripts/gallery.mjs --check      # fresh run in a temp dir, byte-compared, writes nothing
node scripts/gallery.mjs --only qoder # one target
node scripts/gallery.mjs --audit site/gallery/airstats.html
```

The script only calls `node dist/cli.js report <package>`; it renders no HTML of
its own. It enforces the gallery budget — **one report ≤ 700 KiB, gallery total
≤ 2 MiB** (the four reports here are 281,856 bytes counted once) — and if a
report ever came back over its cap it would be dropped and replaced by the
plain-text `tforge app <package> --no-save` transcript instead, because the
stopping point is the evidence in that case.

Each generated file is also audited before it is kept: the auditor parses every
tag in the HTML and fails the run on a disallowed tag, a `src=`/`href=` style
remote attribute, or an event-handler attribute. That gate was tested with
payloads, not assumed — a fixture bundle whose file and manifest names contain
`<script>alert(1)`, `<img src=x onerror=alert(1)>` and `</td>`-style break-outs
was scanned, and the report escaped all of it (`grep -c "<script"` → `0`, and
the strings appear on the page as visible text). The injected copy that adds a
real `<script>`/`<img onerror>`/`<link href>` is rejected with exit 1.

Reports are byte-stable for the same input: `--check` regenerates all four and
compares them to the committed files, which is how this folder can be trusted
after an app updates — rerun it and drift is reported instead of hidden.
