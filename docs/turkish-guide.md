# TraceForge Türkçe Rehber (anlaşılır anlatım)

Bu belge jargonsuz yazıldı; teknik terimler parantezde veriliyor. Komutların
kendisi İngilizce kalır çünkü aynen yazılacakları şekil odur. Tüm örnek çıktılar
2026-11-02'de, bu MacBook'ta (darwin/arm64, Node v24.20.0) ve sürüm 0.3.0 ile
gerçekten koşularak alınmıştır.

## Bu araç ne işe yarıyor?

TraceForge bir **röntgen makinesidir**. Bir uygulamayı ya da dosyayı
**çalıştırmadan** içini çeker: hangi parçalar var, hangisi kaç bayt, hangisinin
karma değeri (SHA-256) ne. Sonra bu bulguları tek bir HTML raporu olarak
diske yazar. Raporu tarayıcıda açarsın; internet gerekmez, hiçbir şey
çalışmaz, hiçbir yer sunucuya gönderilmez.

Neden gerekli? Bir yazılımı indirip kurmadan önce "içinde gerçekten ne var?"
diye sormak istersin. Klasik çözümler ya virüs taraması gibi "temiz/şüpheli"
der (kanıt vermez) ya da programı çalıştırıp izler (riskli). TraceForge üçüncü
yolu seçer: **sadece okur, kanıt biriktirir**. Her bulgu, içeriğinden ürelenen
bir kimlik numarası (Evidence ID) taşır; raporun bir harfini değiştirsen
kimlik tutmaz ve doğrulama patlar.

Üç kelimeyle: yerel (local-first), salt-okunur (read-only), tekrar
üretilebilir (deterministic).

## Bir raporu açtığında neye bakmalısın

Rapor tepeden aşağı sabit sıradadır. Her bölüm için: hangi satır ne demek,
neyi **kanıtlar**, neyi **kanıtlamaz**.

### 1. Kanıt Kimliği (Evidence ID)

- **Hangi satır:** başlık altındaki kartlardan ilki; `ev_` ile başlayan 67
  karakterlik değer (`ev_` + 64 onaltılık rakam). Raporun alt bilgisinde (footer)
  tam hali bir kez daha yazar.
- **Ne kanıtlar:** kimlik, kaydın (JSON) içeriğinden üretilir;
  `tforge evidence verify <id>` o içeriği yeniden hesaplar. **Kanıt kaydının**
  bir karakteri bile değişse doğrulama düşer. Bunu bu gece ölçtüm: kayda tek
  satır ekleyince `signature_mismatch`, geri yükleyince `signed · verified` aldım.
- **Ne kanıtlamaz:** tek başına "bu dosya iyidir/kötüdür" demez. Sadece "bu
  kayıt şudur ve değişmemiştir" der. Bir de şu önemli sınır: **HTML raporunun
  kendisi tahrilata karşı korumalı değildir.** Raporun içinde betik yok ve
  kanonik kaydın tamamı gömülü değil; o yüzden HTML dosyasını biri ellersen
  bunu ancak kaydı veya imzayı yanında götürerek yakalayabilirsin
  (`evidence export` / `evidence sign`). Bu gece deneyim: galeri HTML'inde bir
  etiketi değiştirdim, `evidence verify` yine `valid` dedi — çünkü doğrulanan
  şey HTML değil kayıttı.

### 2. Girdi SHA-256'sı (input SHA-256)

- **Hangi satır:** "Input SHA-256" kartı ve altındaki yol satırı.
- **Ne kanıtlar:** incelenen dosyanın **parmak izi**. Aynı parmak izi, aynı
  dosya demektir; iki farklı dosyanın aynı parmak izine sahip olması pratikte
  imkânsızdır. Bir sürüm yükseltmesinde `/bin/ls` için parmak izi
  (`13f44bfe…22bfb`) hiç değişmedi — dosya aynıydı.
- **Ne kanıtlamaz:** dosyanın nereden geldiğini, kimin imzaladığını, iyi ya da
  kötü olduğunu kanıtlamaz. Sadece "hangi dosyaya baktığımızı" sabitler.

### 3. Dilimler (slices)

- **Hangi satır:** Mach-O dosyalardaki "Slices" bölümü; her dilim bir
  işlemci mimarisi taşır (ör. `arm64`, `x86_64`).
- **Ne kanıtlar:** tek dosyanın içinde hangi mimariler için makine kodu var,
  her dilimde kaç bölüm (section) ve dışarıdan çağrı (import) geçtiği.
- **Ne kanıtlamaz:** kodun ne işe yaradığını kanıtlamaz. TraceForge bir
  çözümleyici (disassembler) değildir; makine kodunu insan diline çevirmez.

### 4. Korumalar (mitigations)

- **Hangi satır:** her dilimin altındaki yeşil "Enabled", sarı "Disabled",
  gri "Undetermined" etiketleri (`aslr`, `nx`, `pie`, `chained-fixups` gibi).
- **Ne kanıtlar:** dosya başlıklarında (header) hangi koruma bayraklarının
  **yapısal olarak öne sürüldüğünü**. Yani derleyici dosyaya "ben şunları
  açtım" yazmış.
- **Ne kanıtlamaz:** korumaların çalışırken gerçekten zorunlu (enforce)
  olduğunu kanıtlamaz. Çalıştırmadığımız için işletim sisteminin onları
  uygulayıp uygulamadığını göremeyiz.

### 5. Kaynak iddiaları (provenance claims)

- **Hangi satır:** "Provenance claims" tablosu; `.app` paketlerinde ayrıca
  "Manifest claims" (Info.plist) tablosu (`CFBundleIdentifier`, sürüm,
  `LSMinimumSystemVersion`, `SUFeedURL` gibi).
- **Ne kanıtlar:** dosyanın kendisi hakkında **kendi kendine beyan ettiği**
  etiketleri olduğu gibi kaydeder. "Bu paket adının com.airstat.AirStats
  olduğunu söylüyor" satırı, gerçek bir kimlik denetimi değil, bir **iddia**
  satırıdır.
- **Ne kanıtlamaz:** Apple kod imzasını (code signature) ya da noter onayını
  (notarization) kontrol etmeyiz. Bir paket kimliğini başkasınınkiyle
  yazmış olabilir — rapor bunu "iddia" etiketiyle taşıdığı için okuyan
  yanılmaz. Galerideki Riot raporu iki ayrı pakette aynı kimlik
  iddiasını gösterir; bunu ancak oynan (declared) demeyi kabul edersen
  görürsün.

### 6. Sınırlar (Limitations)

- **Hangi satır:** raporun alt kısmındaki sarı çerçeveli kutu.
- **Ne kanıtlar:** aracın dürüstlüğü. Arşivler (`.asar`, `.zip`) sayılıp
  parmak izi alındı ama **içleri açılmadı**; 5.000 üye sınırına dayanıldıysa
  "gerisi sayıma girmedi" diye yazar; simgesel bağlar (symlink) hedefiyle
  kaydedilir ama **peşlerine düşülmez**.
- **Ne kanıtlamaz:** bu kutu bir kusur listesi değil, bir kapsama sınır
  ilanıdır. Yine de "kutu boşsa her şeyi gördük" deme: kutu yalnızca
  sınıra çarpılan işlerde dolar.

### 7. İmza (Signature)

- **Hangi satır:** rapora `--signature` ya da `--public-key` ile bakıldıysa
  çıkan "Signature" bölümü: `signed · verified` ya da `signature failed`.
- **Ne kanıtlar:** bu kaydın belirli bir Ed25519 anahtarıyla imzalandığını ve
  o günden beri **tek bir bayt bile** değişmediğini.
- **Ne kanıtlamaz:** **ne zaman** imzalandığını (zaman damgası yok), anahtarın
  hâlâ geçerli olduğunu (iptal listesi yok), dosyanın nereden geldiğini
  (kod imzası değil), ve --public-key verilmemişse anahtarın sana ait birine
  ait olduğunu (gömülü anahtar kendi kendini bildirir).

## İki uygulamayı karşılaştırma

Aynı programın iki sürümünü yan yana koyup "neyi değiştirmişler?" demek
için:

```sh
node dist/cli.js diff /bin/ls /usr/bin/true
```

Çıktının tepesinde `changed` ya da `identical` yazar. Altında gruplar hâlinde
eklenen/çıkarılan dilimler, bölümler, dış çağrılar ve **korumalar** listelenir
(mitigations added/removed). Bir güncellemede `pie` ya da `chained-fixups`
gibi bir koruma **çıkarıldıysa** bu satırda görünür — sessizce düşen bir
güvenlik ayarını ancak böyle yakalarsın. Karşılaştırmanın kendisi de bir
kanıt kaydıdır; kimliği vardır, imzalanabilir.

Paket paket karşılaştırma (`.app` → `.app`) henüz `diff` yüzeyinde değil;
bugün için iki `app` raporu açıp "kinds / architectures / nested" kartlarını
elle karşılaştırıyorsun. (Yol haritasında açık kenar olarak yazılı.)

## İmzalama ve doğrulama adımları

Komut komut, bugün koşulmuş haliyle:

```sh
# 1) Bir imza anahtarı üret (bir kez). Parmak izi pk_ ile başlar.
node dist/cli.js evidence keygen
# fingerprint pk_786bbd87c43f5f088dafb5f9ab7ed0b6765b5a11bf60fbaea819da88714205a4

# 2) Bir kaydı imzala; yan dosya (sidecar) .traceforge/signatures/ altına yazar.
node dist/cli.js evidence sign ev_72e61605858e30e40a66f858b0ca1d3e74c934cb39f6acced07abf9226dd6b0e
# evidence  ev_72e61605858e30e40a66f858b0ca1d3e74c934cb39f6acced07abf9226dd6b0e
# key       pk_786bbd87c43f5f088dafb5f9ab7ed0b6765b5a11bf60fbaea819da88714205a4
# signature /Users/emirhan/Desktop/TraceForge/.traceforge/signatures/ev_72e61605858e30e40a66f858b0ca1d3e74c934cb39f6acced07abf9226dd6b0e.sig.json

# 3) Karşı taraf, SAKLADIĞI açık anahtarla doğrulasın:
node dist/cli.js evidence verify ev_72e61605858e30e40a66f858b0ca1d3e74c934cb39f6acced07abf9226dd6b0e --public-key .traceforge/keys/pk_786bbd87c43f5f088dafb5f9ab7ed0b6765b5a11bf60fbaea819da88714205a4.pub.pem
# signed · verified by pk_786bbd87c43f5f088dafb5f9ab7ed0b6765b5a11bf60fbaea819da88714205a4

# 4) Tüm kasayı denetle:
node dist/cli.js evidence verify-all
# 30 valid · 0 invalid
# 2 signed · 28 unsigned
```

Tahrilat kanıtı — imzalı kaydın JSON'unda tek bir alan (input.size)
elle değiştirildikten sonra aynı doğrulama:

```text
error [signature_mismatch]: The record changed after it was signed (record hash differs).
```

(Tamper demo, gönderilen kasa bozulmasın diye geçici bir `--store` kopyasında
koşuldu; çıktı birebir budur.) Bayraksız `evidence verify` eski davranışını
korur: sadece `valid` ya da `invalid or missing` yazar.

Dikkat: `.traceforge/` altına yazılan anahtarlar 0600 izinlidir ve git
tarafından yoksayılır — kaybolursa imzalar yeniden üretilemez, çünkü gizli
anahtar sunucuda değil, sadece senin diskindedir.

## Galerideki dört rapor neyi gösteriyor

`examples/gallery/` (site için aynıları `site/gallery/` altında):

| Rapor | Uygulama | Tek cümlelik anlamı |
|---|---|---|
| `airstats.html` | AirStats 1.3.2 | İçinde başka uygulamalar taşıyan uygulama: Sparkle.framework, onun iç `Updater.app`'ı ve iki `.xpc` hizmeti; 95 dosya, 8.8 MiB. |
| `obsidian.html` | Obsidian | Gerçek hacim: tek bir üye 397.316.032 bayt (378.9 MiB) tek geçişte parmak izlendi; `app.asar` ve `obsidian.asar` sayıldı ama **içi açılmadı** — sınır kutuda yazılı. |
| `qoder.html` | Qoder | Yürüyüş 5.000 üye sınırına çarptı ve bunu Limitations kutusuna yazdı; "durduk" demeyi bilen araç güvenilir araçtır. |
| `riot-client.html` | Riot Client | `/Applications/Riot İstemcisi.app` aslında bir bağ (alias); Türkçe büyük "İ" içeren yol ve içinden çıkan 1.261.55 MiB hedef paket sorunsuz taşındı. |

Her raporun kanıt kimliği (0.3.0 ile üretildiler, `--check` ile tekrar
üretilebilirler):

```text
ev_8e6ff9bf617a35853592297b528301e9908549ef212861c4bed9bfc22ecb378e  airstats.html   37,577 B
ev_eb9eb2ef46957214978eba85c1278b5b34ef2b32c869dd28dc1522aaa6e2b271  obsidian.html   81,587 B
ev_0b118594dcb68fb100202ac6d5b3a23af53a134defe83d175566e2fe07f0239b  qoder.html      83,914 B
ev_0ccd1730f2396f46aed6b8f0d96892ccd0d6ca57dc7fd0f4fc76838c23ee5096  riot-client.html 79,604 B
```

## Sık sorulanlar

**Bu araç incelediği programı çalıştırıyor mu?**
Hayır. Hiçbir hedefi açmaz, çağırmaz, belleğine dokunmaz. Sadece dosya
baytlarını okur. Bir Mach-O'un başlığını okumak, onu çalıştırmaktan tamamen
farklıdır — röntgen hastayı uyutmaz.

**Rapor ya da araç internete çıkıyor mu?**
Hayır. Motorun hiçbir ağ çağrısı yok (sıfır runtime bağımlılık, Node'un
kendi modülleri). Rapor tek dosyalık bağımsız HTML'dir; içinde script, dış
stil, yazı tipi yüklemesi yok. Uçak modunda bile doğrulayabilirsin.

**Bir dosyayı gizlice değiştirebilir mi?**
Hayır. Hedefler salt-okunur açılır; araç yalnızca kendi `.traceforge/`
kasasına ve `--out` ile senin gösterdiğin rapor dosyasına yazar. Kanıt
kasasındaki dosyalar atomik yazım ve 0600 izinle korunur.

**Rapor sahte olabilir mi?**
İmzasız bir rapor tek başına "buna ben sahtekârca ürettim" demeni
engellemez — isteyen kendi kasasında isteyeni üretir. İki şey seni korur:
(1) kayıt içeriğine kenetlenmiştir (content-addressed); imzalı bir kaydın tek
baytı bile değişirse `verify` şu hatayla düşer: `signature_mismatch`. (2) kimlik,
dosyanın parmak izinle baştan hesaplanır; "şu tarihte, şu dosyaya
bakıldı" zincirini imzalıysan kırabilirsin, imzasızsa kıramazsın. Yani
cevap: imzasızsa evet, kuşkulu; imzalıysa değişmişse `signature_mismatch`
görürsün.

**Bir raporun ne zaman üretildiğini kanıtlar mı?**
Hayır. Kayıtlarda ve imzalarda zaman damgası yok — içerik karmasının
değişmemesi için bilinçli çıkarıldı. "Şu ana kadar değişmedi" diyebilirsin,
"şu tarihte üretildi" diyemezsin. Noter gibi davranan bir zaman damgası
makamı (timestamp authority) yol haritasında açık kenar olarak duruyor.

**Neden dosya değişmediği hâlde yeni sürümde kimlik değişti?**
Çünkü kanıt kimliği hesaplanırken araç sürümü de hash'e girer (`tool.version`
kenetlenmiştir). 0.2.0 → 0.3.0 bump'ında `/bin/ls` aynı baytlarla kaldı
(parmak izi `13f44bfe…`), ama `ev_4881c15a…` yerine `ev_72e61605…` üretildi.
Bu bir hata değil, şeffaflık: hangi sürümün ürettiği kaydın kim olduğunu
kimlikten okuyabilirsin.

**Hangi durumlarda bu aracı kullanmamalıyım?**
"Bu uygulama güvenli mi?" sorusuna cevap arıyorsan — bu araç cevap vermez.
Kod imzası analizi, davranış izleme (sandbox), ağ gözlemi ve arşiv içi
inceleme burada değil. Bunlar Yol Haritası'nda açık kenar olarak yazılı;
araç kendine "gördüm" demediği yeri Limitations kutusunda dürüstçe sayar.
