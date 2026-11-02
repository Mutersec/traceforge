# SABAH.md — TraceForge gece mesaisi çıktısı

Bu dosya sahibi sabah 06.30'da açsın diye yazıldı. Kod bilmeni gerektirmez.
Terimleri parantez içinde açıkladım.

## 1) Bu araç ne işe yarıyor? (benzetme)

TraceForge bir **röntgen cihazı** gibi: şüpheli bir programı **çalıştırmadan** ve
**internetine çıkmadan** açar, içindekileri sayar ve gördüğü her şeyi bir **kanıt
kaydına** dönüştürür.

- **Evidence (kanıt kaydı):** "bu sonucu, şu dosyadan, tam olarak bu haliyle
  çıkardım" diyen, dosyanın parmak izine (SHA-256 = içeriğin tek-anahtarı hash'i)
  bağlanmış doküman. Sonuç değişirse kaydın kimliği de değişir; yani sonradan
  kıpırdatılamaz.
- **Deterministik:** aynı dosyayı iki kere tararsan aynı kayıt numarası çıkar. Aşağıda
  bu gerçekten iki kere koşuldu, iki değer de yazılı.
- **Sıfır runtime bağımlılık:** kurması gereken başka bir kütüphane yok; sadece Node 22+
  gerekiyor. Çalıştırdığın şeyde ağ izi, hesap, bulut servisi yok.

## 2) Sabah itibarıyla neler yeni — dürüst durum

**Bu gece vaat edilen 6 fazdan (F1–F6) hiçbiri teslim edilmedi.** Repoda tek yeni
şey, senin yokken bulduğum ve kurtardığım commit'lenmemiş 0.2.0 işi.

| Vaat | Durum | Kanıt |
|---|---|---|
| — Baseline kurtarma (0.2.0 işi commit'lenmemişti) | **YAPILDI** | commit `f79eadb`, 16 dosya / +795 satır |
| F1 `tforge app <Bundle.app>` paket taraması | YAPILMADI | `src/core/app.ts` yok, ya `app` komutu yok |
| F2 Ed25519 imza (`evidence keygen/sign/verify`) | YAPILMADI | kod yok |
| F3 Agent ergonomisi (MCP kaynakları, sayfalama, `--only`) | YAPILMADI | `src/mcp/server.ts` değişmedi |
| F4 Kanıt galerisi | YAPILMADI | F1 olmadığı için üretilemezdi |
| F5 Anlaşılır doküman (README 30 saniye, Türkçe rehber) | KISMEN | bu dosya var; README/docs/CHANGELOG'a faz işlenmedi |
| F6 CI sertleştirme (ubuntu+macos, bench kapısı, publish dry-run) | YAPILMADI | `.github/workflows/ci.yml` hâlâ tek OS |

Sürüm hâlâ **0.2.0** (0.3.0'a çıkarılmadı), çünkü üzerine özellik eklenmedi.

## 3) Tek komutla nasıl denenecek (bu sabah çalışan şey)

```sh
cd ~/Desktop/TraceForge && npm ci && npm run check
node dist/cli.js scan /bin/ls
```

`npm run check` = tip kontrolü + testler + derleme; bu gece son durumu **yeşil**:
`Tests 11 passed (11)`.

Açılır örnek rapor (senin Masaüstünde, gerçek çıktı — uydurma değil):

```
/Users/emirhan/Desktop/TraceForge-ornek-rapor.html
```

Komut ve gerçek çıktısı:

```console
$ node dist/cli.js report /bin/ls --out "$HOME/Desktop/TraceForge-ornek-rapor.html"
TraceForge report → /Users/emirhan/Desktop/TraceForge-ornek-rapor.html
Evidence ev_5f9cabcae910ec6203b35a141aea0c61dbc1f02fbc10cdd916645b71217bbc4e
```

Determinizm kanalı (aynı komut, iki koşum, aynı kayıt numarası):

```console
$ node dist/cli.js scan /bin/ls --no-save --json | grep -m1 evidence_id   # 1. koşum
  "evidence_id": "ev_4881c15a0c4ae521f75e89d77d9abaca2cb5b6f68f32ce74cd005e58beb15e2a"
$ node dist/cli.js scan /bin/ls --no-save --json | grep -m1 evidence_id   # 2. koşum
  "evidence_id": "ev_4881c15a0c4ae521f75e89d77d9abaca2cb5b6f68f32ce74cd005e58beb15e2a"
```

Eski kayıtlar sağlam: `node dist/cli.js evidence verify-all` → `18 valid · 0 invalid`.

## 4) Henüz yapılamayanlar (dürüst liste)

- Bir uygulamanın **içini** (`.app` paketi: Frameworks, Resources, `.dylib`, `.wasm`)
  tek komutla tarama — F1'in vereceği buydu, yok. Bugün yalnız **tek tek dosya**
  verebilirsin: `tforge inspect "/Applications/Obsidian.app/Contents/MacOS/Obsidian"`.
- Kanıtları **imzalama**: "bu raporu şu anahtar üretti ve değişmedi" diyemiyorsun.
  Kayıtlar parmak izine bağlı ama senin anahtarınla imzalı değil (F2).
- Büyük bir binary'nin MCP (yapay zekâ asistanı bağlantısı) cevabı hâlâ **tek seferde
  megabyte'larca** olabiliyor; sayfalama yok (F3).
- Kurulmuş uygulamalardan üretilmiş **hazır galeri raporları** yok (F4).
- `.asar` arşivlerinin içi sayılmıyor; `.app` taraması bile olmadığı için henüz hiç
  görülmüyor.
- Kod imzası (code signature) blob'unun içeriği ve entitlements okunmuyor; sadece
  "imza var" iddiası kaydediliyor. 0.2.0'dan beri böyle.
- CI yalnız **ubuntu** üzerinde koşuyor (node 22 + 24); macOS matrisi ve benchmark
  regresyon kapısı yok. Benchmark bu makinede ölçüldü (median 0.458 ms) ama bir
  eşikle kimse kıyaslamıyor.

## 5) Senin yerine verdiğim kararlar (ve nedeni)

1. **Commit'lenmemiş 795 satırı kurtardım.** `main` üzerinde hiç commit'lenmemiş 16
   dosyalık 0.2.0 işi duruyordu; bir sonraki adım bunu silebilirdi. `main`'e
   dokunmadan `feat/0.3-mvp` dalını açıp tek commit yaptım. Geri alma:
   `git checkout main && git branch -D feat/0.3-mvp`.
2. **Fazları sıraya koydum, paralel vermedim.** `src/cli.ts`, `src/core/types.ts`,
   `test/core.test.ts` altı fazın ortak dosyası; paralelde aynı dosyada çakışır ve
   `dist/` yeniden derlemesi sahte kırmızı test üretirdi.
3. **Sürüm bump'unu sona bıraktım.** Kayıt kimliğinin hash'lenen içeriğinde araç
   sürümü de var; faz ortasında 0.3.0'a çıkmak kayıtların numaralarını sebepsiz
   değiştirirdi.
4. **`.asar` içeriğini bu gece açtırmama kararı verdim.** Yeni arşiv çözücü = yeni
   sınır/tahsis yüzeyi; gece yarısı almak istemediğim bir risk.
5. **Tavanları sayıya bağladım:** dosya 5000, derinlik 32, aşım hata değil "limitation"
   (eksikliği kayda geçen dürüstlük notu) olacak. Gerekçe: `Cursor.app` 17.235 dosya;
   tavan yoktu tarama saatlerce sürebilirdi.
6. **GitHub'a push yapmadım.** İzni yeni dal içindi; kapılar yeşil olmadığı için
   dalı local bıraktım. `main`'e push, tag, release ve `npm publish` yapılmadı.
7. **SABAH.md'yi gecikmeli olarak repo köküne şimdi yazdım.** Gerekçe: üye commit
   atarken taslağım onun commit'ine sızmasın istedim; bu korunma kararı bana 1 dosyalık
   bir teslim kaybına mal oldu — hatayı gördüğüm anda düzelttim.

## 6) Nerede durdum ve sebebi

- Saat 00:46'da F1'i **Full-stack Geliştirici**'ye verdim ve sonuç bildirimini
  beklerken repoyu hiç kontrol etmedim. 06:28'te kontrol ettiğimde: ya `app.ts` yok,
  commit yok, stash yok, başka worktree/branch yok, test süreci çalışmıyor. Yani F1
  **hiç başlamamış**.
- Sebebi (dürüst): koordinasyon hatası bende. Üye çıktısını "gönderildi" diye kabul
  edip ara checkpoint'te repo durumunu doğrulamam gerekiyordu; kuralım ("iddia edilen
  ile kanıtlananı ayır") tam da bu senaryo içindi ve ben uygulamadım. 5,5 saatlik
  bütçe tek bir beklemeyle harcandı.
- Düzeltme, tek cümle: fazları artık **ara kontrollü** koşacağım — her ~15 dakikada bir
  `git status` + dosya varlığı kontrolü, üye sessizse işi kendim alt fazlara bölüp
  yürütürüm.
- Repo şu an **bozuk değil**: `feat/0.3-mvp` @ `f79eadb`, working tree temiz,
  `npm run check` yeşil, `evidence verify-all` `0 invalid`.

## 7) Sıradaki tek karar (senin)

Tercihini tek kelimeyle söyle, kaldığım yerden devam edeyim:

- **"devam"** → F1'i bugün gözüne ara kontrol ederek yeniden koştururum (tahmini
  60–90 dk), sonra sırayla F2 → F3 → F6 → F4 → F5.
- **"önce sabitle"** → 0.2.0 baseline'ı temiz bir PR/dal haline getirip dokümanı ve
  CI'ı (F5+F6) önce bitiririm; yeni özellik gelmez ama repo güvenli ve tanıtılabilir olur.
- **"bırak"** → bu haliyle bırakırım; Masaüstündeki örnek rapor ve bu dosya kalır.
