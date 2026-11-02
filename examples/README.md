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
ev_8e6ff9bf617a35853592297b528301e9908549ef212861c4bed9bfc22ecb378e   airstats.html    37,577 B
ev_eb9eb2ef46957214978eba85c1278b5b34ef2b32c869dd28dc1522aaa6e2b271   obsidian.html    81,587 B
ev_0b118594dcb68fb100202ac6d5b3a23af53a134defe83d175566e2fe07f0239b   qoder.html       83,914 B
ev_0ccd1730f2396f46aed6b8f0d96892ccd0d6ca57dc7fd0f4fc76838c23ee5096   riot-client.html 79,604 B
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
screen, and the member tables no longer break the page. F4 measured the old
behaviour in headless Chrome at a 390 px viewport — `airstats.html` laid out
1,348 px wide and the footer's Evidence ID overflowed its own box — and 0.3.0
closed it in the report renderer (`src/core/report.ts`): every wide table now
sits in a horizontally scrollable `.table-wrap`, and `td code` and `footer *`
get `overflow-wrap: anywhere`, so a member path like
`Contents/Resources/app.asar.unpacked/node_modules/aoq-electron-sdk/prebuilds/darwin-universal/AoqClientSdk.framework/Versions/A/Frameworks/openhevc.framework/Versions/A/openhevc`
(177 characters) stays inside its cell and the footer ID inside the page. The
table test is locked in `test/report.test.ts`. A wide table is still a wide
table — it scrolls sideways — but nothing overflows a box any more, and the
record content is identical: the fix changed rendered HTML bytes only, never a
hashed record.

Confirm any of them locally:

```sh
node dist/cli.js evidence verify ev_0b118594dcb68fb100202ac6d5b3a23af53a134defe83d175566e2fe07f0239b
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
≤ 2 MiB** (the four reports here are 282,682 bytes counted once) — and if a
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
