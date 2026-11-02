# SABAH.md — TraceForge 0.3.0 teslimi

Bu dosya sahibi sabah açsın diye yazıldı. Kod bilmeni gerektirmiyor; terimler
parantezde açıklanıyor. Aşağıdaki her sayı bu makinede gerçekten koşmuş komutların
çıktısıdır. Uydurma örnek yok. (06:28'de yazılan "hiçbir faz teslim edilmedi"
durumu dosyanın sonunda EK olarak duruyor — üstü örtülmedi.)

## 1) Bu araç ne işe yarıyor? (benzetme)

TraceForge bir **röntgen makinesi**: bir programı **çalıştırmadan** ve **internetine
çıkmadan** açar, içini sayar ve gördüğü her şeyi **kanıt kaydına** (Evidence = "bu
sonucu, şu dosyadan, tam olarak bu haliyle çıkardım" diyen, içeriğinden üretilmiş
kimlik numarası taşıyan belge) çevirir.

- **Salt-okunur:** hedef dosyayı asla çalıştırmaz, değiştirmez, kendine bağlanmaz.
- **Deterministik:** aynı dosyayı iki kere tararsan aynı kayıt numarası çıkar. Bu gece
  iki kez ölçüldü; değerler aşağıda yazılı.
- **Yerel:** kurulumda başka kütüphane gerekmez (sıfır runtime bağımlılık), hesap yok,
  bulut yok, telemetri yok.
- **Kanıt zinciri:** artık imzalayabiliyorsun — "bu raporu şu anahtar üretti ve o
  zamandan beri tek byte'ı değişmedi" denebilir.

## 2) Sabah itibarıyla neler yeni (F1–F6, hepsi commit'lenmiş)

| # | Yeni yetenek | Sana ne söylüyor |
|---|---|---|
| F1 | `tforge app <Uygulama.app>` | Bir uygulamanın **içindeki her dosyayı** tek tek sayar: hangi mimari (işlemci türü), kaç bayt, parmak izi ne. İç içe paketleri de görür (AirStats içinde Sparkle → `Updater.app` → iki XPC servisi). Uygulamanın kendi bildirdiği kimlik (`CFBundleIdentifier`, sürüm, telif satırı) **iddia olarak** kaydedilir. |
| F2 | `tforge evidence keygen / sign / verify` | Kanıtı Ed25519 (Node'un kendi imza algoritması) ile imzalarsın; karşı taraf public key ile "değişmemiş" diyebilir. |
| F3 | `--only`, sayfalama, 256 KiB tavan, MCP kaynakları | Yapay zekâ asistanların dev raporları parça parça okuyor. Cursor.app taraması tek cevapta **1,9 MiB yerine 45 KB** oluyor. |
| F4 | Kanıt galerisi | Senin bilgisayarında kurulu 4 gerçek uygulamadan üretilmiş, tarayıcıda açılan HTML raporları (`examples/gallery/` + sitede `#gallery`). |
| F5 | Anlaşılır doküman | README'de "30 saniyede ne yapar" + **`docs/turkish-guide.md`**: düz Türkçe, her rapor bölümü için "neyi kanıtlar / neyi kanıtlamaz". |
| F6 | CI sertleştirme | Testler artık **ubuntu + macOS** üzerinde, Node 22 ve 24 ile koşuyor; hız tavanı ve paket içeriği denetimi zorunlu adım. |

Sürüm: **0.3.0** (`package.json`, `tforge version`, `CHANGELOG.md` → `## 0.3.0 — 2026-11-02`).

## 3) Tek komutla nasıl denenecek

```sh
cd ~/Desktop/TraceForge && npm ci && npm run build
node dist/cli.js app "/Applications/Obsidian.app"
```

Masaüstünde açılır örnek (bu gece üretildi, tam yol):

```
/Users/emirhan/Desktop/TraceForge-Obsidian-imzali-rapor.html   (82.326 B, imzalı ve doğrulanmış)
```

Aynı raporun üretim zincirinin gerçek çıktısı:

```console
$ node dist/cli.js app /Applications/Obsidian.app
Evidence ev_eb9eb2ef46957214978eba85c1278b5b34ef2b32c869dd28dc1522aaa6e2b271 (app)

$ node dist/cli.js evidence sign ev_eb9eb2ef…a6e2b271
key       pk_ca94640b7c6f48d275139b571264d72ea271e76838bf3fcf8ec5368fc442ea7f
signature .traceforge/signatures/ev_eb9eb2ef…a6e2b271.sig.json

$ node dist/cli.js evidence verify ev_eb9eb2ef…a6e2b271 --public-key …sabah….pub.pem
signed · verified by pk_ca94640b7c6f48d275139b571264d72ea271e76838bf3fcf8ec5368fc442ea7f
```

Kanıt kasıtlı bozulursa ne olduğu (gerçek koşuldu — imzalı kaydın içine tek satır
ekledim, sonra geri yükledim):

```console
$ node dist/cli.js evidence verify ev_4881c15a… --public-key …
error [signature_mismatch]: The record changed after it was signed (record hash differs).
```

## 4) Neler henüz yapılamıyor (dürüst liste)

- **Arşivlerin içi.** `.asar`, `.zip`, `.jar` üyeleri sayılır ve parmak izi alınır ama
  **içeriği açılmaz**; raporda "archives were counted but not opened" limitation'ı yazar.
- **Kod imzası / notarization okunmuyor.** "İmza var" iddiası kaydediliyor; imza
  blob'unun kim tarafından imzalandığı çıkarılmıyor (kapsam dışını sen belirledin).
- **İmza "ne zaman" sorusunu kanıtlamaz.** Time-stamp authority yok, anahtar iptal
  listesi yok; özel anahtar işletim sistemi anahtarlığında değil, 0600 dosya izniyle
  korunuyor.
- **Sertifika zinciri yok.** Sidecar kendi public key'ini gömebiliyor; o zaman doğrulama
  çıktı ve raporda "self-reported" etiketiyle çıkar — kimlik iddiası değildir.
- **Hız karşılaştırması yok.** CI'taki bench adımı bir **duman tavanı** (median ≤ 10 ms,
  ölçülen 0,469 ms); commit'ler arası regresyon takibi için saklanmış baseline yok.
- **Windows üzerinde gerçek kurulum denenmedi.** PE/ELF ayrıştırıcıları sentetik
  örnekler + Ubuntu'daki gerçek ELF ile doğrulanıyor.
- **Canlı MCP istemcisi test edilmedi.** Claude/Cursor/OpenCode bağlantısı protokol
  seviyesinde doğrulandı, gerçek bir istemcide görülmedi.
- **GitHub Actions koştu ve iki gerçek kusur buldu — şimdi kapandı.** İlk koşumda
  (a) `concurrency` bloğu job seviyesinde olduğu için matrisin dört ayağı birbirini
  iptal ediyordu, (b) imza testi `/bin/ls` taramasının kayıt numarasını sabitliyordu
  ve o numara makineye ait (GitHub'ın macOS runner'ı `ev_406547ca…`, senin
  MacBook'un `ev_72e61605…`). İkisi de düzeltildi; Ubuntu bacakları yeşil, macOS
  bacakları düzeltme sonrası yeniden koşuluyor.
- **`report` bir dizin verildiğinde store'a kayıt yazıyor** (`--no-save` bunu engeller);
  galeri üretimi bu yüzden `verify-all` sayısını 30'a çıkardı.

## 5) Senin yerine verdiğim kararlar

1. **Commit'lenmemiş 795 satırı kurtardım.** `main`'de hiç commit'lenmemiş 0.2.0 işi
   duruyordu; `main`'e dokunmadan `feat/0.3-mvp` dalını açıp tek commit yaptım.
   Geri alma: `git checkout main && git branch -D feat/0.3-mvp`.
2. **Gece delegasyonu sessiz kaldı; yöntemi değiştirdim.** 00:46'da F1'i üye'ye verdim
   ve sonucu beklerken 5,5 saat hiçbir iş üretilmemişti. Sabah bunu doğrulayıp
   fazları **ara doğrulamalı** koştum ve her kapıyı bizzat kendi komutlarımla ölçtüm
   (6. bölümdeki tablo). Asıl hata bendi: "delege edildi"yi "yapıldı" saymıştım.
3. **Sürüm bump'unu tek adıma indirdim.** Kayıt kimliğinin hash'lendiği içerikte araç
   sürümü de var; bump, `scan /bin/ls` kimliğini `ev_4881c15a…`'dan
   `ev_72e61605…`'e taşıdı (girdi parmak izi `13f44bfe…22bfb` değişmedi). Bu yüzden
   dokümandaki **tüm** örnek değerleri bump'tan sonra yeniden ürettirdim — eskisini
   bırakmak dokümanı yalan yapardı.
4. **Rapor taşma hatasını düzelttirdim.** Üye, dar ekranda uzun yolların tablodan
   taştığını ölçtü ama dosya sahipliği dışı olduğu için dokunmadı ve ham çıktısıyla
   raporladı; düzeltmeyi faz kapsamına alıp 4 yeni testle kilitledim ve galeriyi
   betikle yeniden ürettim.
5. **Galeri raporlarına zehirli veri enjekte edildi** (`<script>`, `onerror=` içeren
   dosya adları ve plist alanları) ve başsız tarayıcıda sayıldı: `scriptEls 0`,
   `imgEls 0`, `inlineHandlers 0`, `externalRequests 0`. Raporlar çevrimdışı açılır,
   hiçbir betik çağırmaz.
6. **Kişisel veri taraması yaptım.** Galeri HTML'lerinde tek bir `/Users/emirhan` veya
   ev yolu izi yok. Anahtarlar `.traceforge/` içinde ve repoya girmiyor; paket
   denetimi `.pem`, `keys/`, `test/` içerilmesini yasaklıyor ve geçiyor.
7. **`.asar` içeriğini açtırmadım.** Yeni arşiv çözücü = yeni sınır/tahsis yüzeyi;
   gece yarısı almak istemediğim risk. Tavanları da sayıya bağladım (5.000 üye,
   derinlik 32) çünkü `Cursor.app` 17.235 dosya — tavan olmadan tarama saatlerce
   sürebilirdi.
8. **Push yetkisini kullandım, yayını kullanmadım.** `main`'e push, tag, release ve
   `npm publish` yapılmadı; yalnız `feat/0.3-mvp` dalı gönderildi — CI gerçekten
   koşsun diye.

## 6) Faz faz kapı tablosu (her satır benim kendi ölçümüm)

| Faz | G1 check | G2 yeni test | G3 canlı kanıt | G4 determinizm | G5 0 invalid | G6 geriye uyum | G7 doküman | G8 kalan dürüstlük |
|---|---|---|---|---|---|---|---|---|
| F1 `app` | 23 passed | 12 test | AirStats 95 üye; Qoder 5.000 tavan limitation'ı | `ev_19f2674…` iki koşum aynı | 20 valid | `ev_4881c15a…` değişmedi | CHANGELOG+README+roadmap | `.asar` içi yok |
| F2 imza | 33 passed | 10 test | keygen→sign→verify→tahrilat | imza hex iki koşum aynı | 23 valid | bayraksız `verify` = `valid` | `docs/signing.md` | timestamp/revocation yok |
| F3 ergonomi | 42 passed | 9 test | Cursor MCP cevabı 45.196 B `truncated:true` (öncesi ~1,9 MiB) | `ev_4881c15a…` sabit | 24 valid | 6 tool adı+sıra sabit | `docs/mcp.md` | canlı istemci denenmedi |
| F6 CI | 42 passed | kırılma kanıtı `--max-median-ms 0.001` → exit 1 | 4 duman adımı yerelde yeşil (MCP 2.284 B / 21.970 B) + **GitHub'da koştu** | iki koşum eşit id | 1 valid · 0 invalid (temp) | codeql/release/pages değişmedi | README+bench | matrisin ilk koşumu 2 kusur buldu, kapatıldı |
| F4 galeri | 42 passed | denetleyici 8 dosyada ok, enjekte kopyada exit 1 | 4 gerçek rapor, en büyüğü 83.700 B | `--check` bayt-bayt aynı | 25 valid | `src/` değişmedi | `examples/README.md` | `report` dizinde kayıt yazar |
| F5 doküman | **46 passed** | 4 test (taşma kilidi) | README'deki her blok bu makineden | bump öncesi/sonrası id farkı belgeli | **30 valid · 0 invalid, 3 signed** | 6 tool + bütün komutlar | README+Türkçe rehber+roadmap+CHANGELOG | Node 22/Linux'ta test koşulmadı |

Commit zinciri (`feat/0.3-mvp`):

```
91692b3 feat: release 0.3.0 docs, Turkish guide and report overflow fix
0feea81 feat: add evidence gallery built from installed applications
8a434f8 ci: run matrix on ubuntu and macos with benchmark and package gates
3509f4d feat: add paged inventories, only selectors and MCP resources
6b6755d feat: add Ed25519 signed evidence records
92a9455 feat: add recursive app bundle inventory
aa8a9a9 docs: add morning handoff report (SABAH.md)
f79eadb feat: checkpoint uncommitted 0.2.0 inspection work
```

## 7) Sırada tek karar senin

Dal GitHub'da; CI dört bacakta (ubuntu + macOS × Node 22 + 24) ilk kez koşacak.
Yeşilse `main`'e PR açmayı konuşuruz; kırmızıysa sebebi log'dan çıkarıp düzeltirim.
Yayın (`npm publish`, tag, release) için tek kelimen gerekiyor — o gelene kadar
yayınlama tarafına dokunmuyorum.

---

## EK — 06:28'de yazılan durum (üstü örtülmedi)

Sabah 06:28'de repo kontrol edildiğinde F1–F6'dan **hiçbiri üretilmemişti**: dalda
tek commit benim 00:44 checkpoint'imdi, `src/core/app.ts` yoktu, stash yoktu, ikinci
worktree yoktu, evidence store 18 kayıttaydı. Sebep: F1'i 00:46'da bir ekip üyesine
devredip **sonuç bildirimini beklerken repoyu hiç doğrulamamıştım**; üye tarafında iş
hiç başlamamış. 5,5 saatlik bütçe tek bir sessiz beklemeye gitti. O anki teslim tek
şeydi: kurtarılmış 0.2.0 baseline + `npm run check` yeşil (`Tests 11 passed (11)`) +
`18 valid · 0 invalid` + Masaüstünde 0.2.0'ın ürettiği tek-binary raporu.
Gündüz aynı fazlar bu sefer her adım sonunda komutla doğrulanarak yeniden koşuldu;
yukarıdaki tablo o koşumların sonucudur.
