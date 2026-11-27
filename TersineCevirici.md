# TersineCevirici.md — VMProtect Tersine Mühendislik Bilgi Temeli (TAM KAPSAM)

**Sürüm:** 3.0 (V336, 2026-11-27) · **Kapsam:** V301–V336 tur zincirinin öğrettiği HER ŞEY —
118 mesajlık tam sohbet dökümü (sohbet_arşivi/) madde madde taranarak hazırlanmıştır.
**Amaç:** Bu doküman, TersineCevirici projesinin (github.com/0xByteDeveloper/TersineCevirici)
bilgi tabanıdır — hangi yöntem hangi korumayı nasıl çözer, hangi tuzaklar var, neyi
YAPMAMALI, her bulgunun kanıtı nerede. Yeni bir tur bu dokümandan başlamalıdır.

**v3.0'da yeni:** §14 VMProtect ÜRETİM MEKANİZMASI (kaynak dosya-satırı seviyesinde),
§15 KOMUT KORPUSU + talimat seti detayları, §16 ARAÇ KURULUM REÇETELERİ (wine/X/Ghidra),
§17 ÖLÇÜM YÖNTEMLERİ BÜTÜNÜ, §18 VARYANT BOYUT VERİTABANI (tam sayı tablolar).

---

## 0) Proje kimliği ve envanter

**Hedef koruma:** VMProtect 3.5.1 (kaynağı elimizde) ve 3.9.4 (resmî ikili, wine'da çalışır)
**Test korpusu:** Test_64.exe (12.800 B, pac-man tarzı oyun, MovePlayer @RVA 0x14C0,
WrapPos @0x1470, semboller: dx 0x140003230 / dy 0x140003240 / g_px 0x140004008 /
g_py 0x14000400C / g_maze 0x140004010 / g_score 0x140004140 / g_dots 0x140004144)
**Varyant ailesi:** mutation / virtualization (+complexity 100) / ultra (+c100) / ALL (Pack)
/ Pack_Output / import_protection / Memory_Protection / debugger_user(+kernel) / strip_* / bos
**Araç zinciri:** Python (capstone + unicorn 2.1.3 referans) → C++ (g++ 14.2, capstone +
unicorn C kütüphaneleri, statik) → TersineCevirici 7 alt komut: `girisler mutasyon vmtrace
oracle etiket avtuzak unpack`
**Kanıt disiplini:** her iddia ya gerçek koşu çıktısıyla ya orijinal dosyayla bayt-birebir
doğrulanır; "çalıştı" değil "değer-değer aynı" aranır; yapılamayan şey "çözülemedi" değil
"çalışma-anı gerektirir" olarak işaretlenir.

### 0.1) Köken ve kaynak repolar (sohbet kaydından — V335-g export)
- **MovePlayer'ın 42-satırlık referans disassembly'si KULLANICININ VERDİĞİ listedir**
  (chat 86. mesaj, x64dbg formatında: `push rsi; push rdi; sub rsp,28; mov eax,ecx;
  dec eax; xor ecx,ecx; mov edi,0; cmp eax,3; ja +2C; lea rcx,[GameTick+1BB0] ...` —
  GameTick+1BB0/+1BC0 = dx/dy tabloları). Tüm 42/42 birebir doğrulamalar BU listeye
  karşı yapıldı.
- Kullanıcının işaret ettiği yöntem kaynakları: `ilyida/vmp3-demo-devirt`,
  `whoamicrashh/VMProtectDumper`, `whowould/VMProtect-Unpacker` (GitHub) +
  MyRepo/MVPReverseV3.
- Kullanıcının verdiği kritik girdiler: localdekendimdenedim.rar (3.9.4 üretimleri —
  V334 kurtarma kaynağı), universalObfusPublicSrc_kaynak_kod.zip (3.5.1 kaynağı),
  universalAllver.rar (500MB sigorta kopyası; içindeki VMProtect.exe MD5'si YEAHMAN
  arşivindekiyle birebir: 24576e5e…), Yandex Disk 11-sürüm arşivi (captcha'ya rağmen
  V306'da inmiş kopya + eski analizci JSON'u kullanıldı).
- **GhostStep'in yapay zekâsı çözüldü (V323):** LCG (lineer-kongrüans) rand — oyun
  mantığı devirt'in yan ürünü olarak ayrıca çözüldü.
- **rea v6.10.1 + Ghidra 12.2 + JDK25 (V321):** Test_64 analizi çalıştı; resmî 3.9.4
  korumalı fonksiyonda Ghidra "Failed to create function" hatası aldı — resmî korumanın
  analiz direncinin bizzat kanıtı (kanıt: v321_kanit/v321_rea_394.log, 136KB).
- **111. yama noktası (V321):** kayıtlı yolda VM yazmaç seçimi rastgeleleştirildi —
  10 kopyanın her biri kendi pcode/stack/jmp yazmaçlarını seçer (sabit-yazmaç lifter
  saldırısına karşı). Instances'ın üç bileşeni: konum (V321) + yön (rand&1) + gövde (V320 junk).

---

## 1) KORUMA TİPLERİ TEŞHİSİ — ilk bakışta yol seçimi

Varyantı ayırt etmenin en hızlı yolu **0x14C0'daki ilk baytlar** (hedef fonksiyon giriş RVA'sı):

| 0x14C0'da ne var | Koruma | Strateji |
|---|---|---|
| `E9 rel32` → gövde-içi (~0x1400062EB) | **Mutasyon** — gövde YERİNDE + junk | Statik devirt (§2) |
| `E9` → uzak VM (0x14007xxxx) | **Sanallaştırma** — gövde boşaltılmış | Emülasyon + oracle (§3) |
| `E9` → gövde-içi köprü + `pushfq/anahtar-türetme` | ultra / c100 | Köprü reçetesi (§5) |
| `00 00 ...` (hepsi sıfır) | **ALL / Pack** | Statik unpack (§6) — bölümler sanal, kod .cqM paketinde |

**Ders (V324):** giriş çözümü tek satırlık bilgi ama strateji seçici. Yanlış strateji
haftalarca kaybettirir (V329-V332'de 3 başarısız koşu, 43-64 dk emülasyon — çünkü kızak
koşuyordu, unpack değil).

---

## 2) MUTASYON DEVIRT — gövde yerinde, junk ayıklanır

**Teze dayanan yöntem (doğrulandı):** VMProtect mutasyonu orijinal talimat baytlarını
**taşımaz**; arasına junk gömer. Sonuç: orijinal dizinin tamamı gövdenin içinde mevcuttur.

### 2.1 İmza = opkod + RIP-göreli hedefin ÇÖZÜLMÜŞ ADRESİ
```
imza(talimat) = (opkod-baytları, RIP-göreli hedefin VA'sı)
```
disp baytları değil **hedef adres** karşılaştırılır — mutasyon talimatları yer değiştirse
veya uzasa bile hedef sembol aynı kalır. Örnek: `48 8D 0D` + hedef 0x140003230 = `lea rcx,[dx]`.

### 2.2 Her-hiza çözümleme
Junk talimat hizasını bozar → doğrusal disasm yetersiz. Gövde boyunca **her bayt
ofsetinden 1 talimat** çözülür (capstone), başarılı hizalar haritaya alınır. Bu, junk
arasına gömülü gerçek talimatları kaçırmaz. Maliyeti önemsiz (1376 B gövde).

### 2.3 Derleyici eşdeğerleri (bayt-birebir değil semantik-birebir)
Motor `add rcx,rdx` yerine `lea rcx,[rcx+rdx]` (`48 8D 0C 11`) yazar. Eşdeğer aile:
`48 01 D1` / `48 8D 0C 11` / `48 8D 0C 91` / `48 8D 0C 13`. Eşleşme tablosuna "eşdeğer
form" notuyla girilir.

### 2.4 Dal hedefi doğrulaması
Orijinal listedeki göreli dallar (+2C, +92) → mutasyon gövdesinde hedef VA çözülür →
karşılık gelen gerçek talimatla eşleştirilir: `ja → 0x14000636C` = `add ecx,[g_px]`.

### 2.5 Junk sınıflandırma (güven ölçüsü — yalancı-pozitif riskini ölçer)
- **ölü-yazmaç:** yazdığı yazmaç sonraki gerçek talimatla eziliyor (`dil`/`dx`/`r12w`/
  `r14b`/`r15w`/`r13b`/`r10b` zincirleri)
- **ölü-bayrak:** `clc stc cmc cdq setl sahf` — hiçbir dal tarafından tüketilmez
- **akış-jmp:** `e9 00000000` tipi sıfır-etkili sıçramalar
- **diğer:** anlamlı ama eşleşmeyen (genel tablo junk'u)

**Sonuç (kanıt: birebir_sonuc.txt):** 42/42 talimat + 3/3 dal + 11/11 RIP-hedef.
Junk yoğunluğu ~%55 (~35 ölü blok), tamamı kanıtlanmış sonuç-etkisiz.

---

## 3) SANALLAŞTIRILMIŞ DOĞRULAMA — Unicorn + doğal oracle

Statik çıkarma mümkün değil (gövde boş) → semantiğin ÇALIŞTIĞI kanıtlanır:

### 3.1 Doğru girişi bulmak (en kritik adım — 2 kez yanılındı!)
- **Yanlış #1:** desen başlangıcı +6 (`0x1400014C6`) — hizalı görünüyor, değil.
- **Yanlış #2:** gövde-içi kripto köprüsü (`0x1400CD444`) — yanlış yığın/anahtar bağlamı
  üretir → akış TUTARLI GÖRÜNÜR ama konuk hiç çalışmaz (0 bellek olayı). Köprüdeki
  `adc rdi,-0x762fd` (0x140231567) carry-bağımlı anahtar türetir = **anti-emülasyon tuzağı**:
  yanlış CF ile emülatör sonsuza dek "anlamlı" döngüde dolaşır.
- **Doğru:** `0x14C0`'daki jmp'nin gösterdiği klasik vmenter: `push r11; pushfq;
  movabs r11,<anahtar>; test r11,r11; jge`. **Giriş kendi-kendine-yeterli olmalı.**

### 3.2 Emülatör kurulumu (kanıtlanmış reçete)
- PE görüntüsü base'e serilir; yığın `0x7FFF00000000+0x200000`; **dönüş adresi yığına
  yazılır** (`emu_start(giriş, dönüş)` değil — vmenter kayıt çerçevesi dönüşü oradan çeker)
- **TÜM GP yazmaçlarına geçerli işaretçiler** (giriş obfuscasyonu canlı kayıtları okur;
  çöp değer → yanlış dal)
- `RCX = yön` (konuk parametre), `RDX = 0x11`
- Düşük bellek (0..0x40000) önceden eşlenir (VM-yığını RBP=0 çevresini kullanabilir)
- Eşlenmemiş erişim kancası sayfa açıp devam eder (motor self-decrypting bölge yazar)

### 3.3 Olay kanalları (komut-atfının omurgası)
- `jmp rbp` (`FF E5`) / `jmp rbx` (`FF E3`) = **dispatch** → komut sayacı (sürüm-duyarlı:
  3.8.4'te `jmp rsi`, 3.9.4'te `jmp rbx`)
- `.data/.rdata` okuma-yazma → RVA+değer yakalanır
- `.text`'e giriş = WrapPos gerçek kodunun koşusu
- **Her olay hangi komut aralığında olduğunu taşır** → olay→talimat atfı

### 3.4 Doğal oracle
Orijinal exe'de aynı fonksiyon aynı girdiyle koşturulur, aynı kanallar kaydedilir.
**Değer-değer birebirlik = semantik korunduğunun kanıtı.** 0 olay = aldatmaca yoldasın;
≥12 olay = doğru yol.

### 3.5 Sonuç + derin işleyici füzyonu (3.9.4'e özgü)
111.170 adım, 51 dispatch, temiz dönüş, 12/12 olay birebir. Komut↔talimat **çoka-tek**:
komut#14 = dx+dy İKİ tablo okuması, #24 = 2×WrapPos, #37 = g_score oku+yaz, #38 =
maze-yaz + g_dots oku+yaz ÜÇ işlem. 51 komut ↔ 42 talimat = **superoperator füzyonu**
(3.8.1'de yok — 3.9.4'ün pcode derleyicisinin işleyici-birleştirme geçişi).

---

## 4) KOMUT→TİP SEMANTİK ETİKETLEME (%100)

941/941 komut (4 varyant: 51/8/859/23) dispatch-arası **yazmaç-deltası + bellek olayı +
WrapPos giriş/çıkış** kanıtlarıyla etiketlendi:
- VARSAYILAN 51: VM-İÇ 2, ARITH/FUSE 17, PROLOG/EPILOG 24, LOAD 3, CALL 1, STORE 2, RMW 2
- c100 8: LOAD(pos)→CALL(WrapPos)×2→STORE(pos)→RMW(g_dots,g_score) — 42 satır → 8 komut
  (en derin füzyon; complexity parametresinin işleyici-birleştirmeyi SIKILAŞTIRDIĞININ kanıtı)
- ultra 859: ARITH/FUSE 836 (obfuscasyon katmanı = VARSAYILAN'ın ~49 katı)
- ultra_c100 23: dengeli karışım
- VM-İÇ toplam 5/941 — tüm komutlar kullanıcı talimat uzayına bağlandı

**Ders (V328, 3 hata düzeltmesi):** (1) `jmp rbp` fazladan dispatch sayılıyordu — dispatch
YALNIZ `jmp rbx` `FF E3` (Python referansıyla parite); (2) RSP-delta=0'da GPR-dalına
düşülmeli (PROLOG sanma); (3) ECX/EDX 32-bit okunmalı (yazmaç-deltası yanlış hesaplanıyordu).

---

## 5) İÇ-KÖPRÜ GİRİŞLERİ (c100 / ultra / ultra_c100) — çözüm reçetesi

Bu varyantlarda `0x14C0` jmp'si gerçek vmenter DEĞİL, gövde içine gömülü şifreli köprüye gider:

| Varyant | Köprü | Desen |
|---|---|---|
| c100 | 0x140001530 | `push <anahtar>; pushfq; shr/sub/mov [rsp+8]` + `jae` **junk-tuzaklı** (yanlış dal → HLT) |
| ultra | 0x140001520 → 0x1400094DF | `pushfq; push r9; mov r9,[rsp+0x18]` — **anahtar-göreli yığın erişimleri** `[rsp+r9-0x2d0e2d89]`, istatistiksel çözümlemez |
| ultra_c100 | 0x140094163 | `push r9; pushfq; movabs r9,0x8923...; sub r9w; call` — ultra+c100 birleşimi |

**Reçete (5 adım):** (1) emülatörü tuzak-bağışık kur (tüm bayrak yazmaçları geçerli,
`hlt`/`int3` yakalanır), (2) `jae`-tipi tuzaklarda HER İKİ CF senaryosunu dene,
(3) köprü çıkışında `pushfq+movabs anahtar` deseni (gerçek vmenter) ara, (4) bulunan
girişten §3 zincirini koş, (5) oracle doğrulaması (0 olay = aldatmaca).

---

## 6) ALL (PACK) STATİK UNPACK — 5 adımlı yöntem (SERİNİN TAÇI)

**Teşhis (V327, 6 emülatör sürümü + 9'luk giriş matrisi — kesin):**
- ALL'un emülatörde çözülemediği şey antidebug/antivm DEĞİL: TEB/PEB/Ldr/KUSER_SHARED_DATA
  + sahte ntdll/kernel32 kuruldu → yazmaçlar/kızak BİREBİR AYNI; 9/9 giriş kombinasyonu
  aynı 343892 talimat; SYSCALL kullanmıyor (UC_HOOK_INSN ile doğrulandı); API çağrısı 0.
- **Gerçek mekanizma: istisna-tabanlı unpacker.** `movzx r9d,[rdx+r9*2-0xf187d1a]` —
  sabit `r9*2` → EA=rdx=8 → BİLİNÇLİ NULL-page okuması → gerçek Windows'ta
  ACCESS_VIOLATION → VEH değer üretir → yığın-LUT indeksi → `jmp r8` gerçek kızak.
  Emülatörde AV üretilemediği için (unicorn 2.1: hook içi mem_map → UC_ERR_MAP)
  LUT yanlış okunur → akış 0x1000'e düşer.
- **AV-tuzak kaba kuvvet (226/256 K):** 58 K değeri kızaksız farklı yola sapıyor —
  TAMAMI **bit-3 SET** (0x06/0x07/0xE0/0xE1): tuzak baytının bit-3'ü akışı dallayan gerçek
  bileşen. K=0xE0 → 7.479.511 talimat (normalin 21 katı) — tek bayt yetmiyor, VEH
  çok-baytlı değer üretiyor.

**Ders (V331/V332 — KOŞU YAKLAŞIMINI KAPATAN PİVOT):** 3 başarısız uzun koşu
(43 dk → RIP=0x4E8F9002'ye 1.3 GB doğrusal yürüyüş, .text'e yazma 0; 64 dk sürüm de öyle)
= yürüyüş unpack değil KIZAK. **ASKERİ KURAL: aynı yaklaşım 3 kez başarısızsa değiştir.**
Pivot: **kaynağı oku** (3.5.1 kaynağı elimizde) → çözümü statik bul.

### 6.1 Beş adım (her ikisi sürümde de birebir çalışır — V332/V333/V334)

```
Adım 1  Bölüm tablosu: .text/.rdata/.data/.pdata RSZ=0 (SANAL) + paket bölümü
        (.vmp00 3.5.1 / .cqM 3.9.4) + küçük tablo bölümü (.#:V vb.)
Adım 2  props imzası: 5D 00 00 00 01 (LZMA level 9, endMark, dict=1<<24)
        → dosyada TEK aday çıkar (3.5.1 @0x2EC0, 3.9.4 @0x118A909)
Adım 3  PACKER_INFO: [props_RVA][00000005] desenini ara → tablo:
        girişler [Src_RVA][Dst=bölüm_RVA] çiftleri (Faces.PACKER_INFO=0xFACE0100)
Adım 4  LZMA akışları: python lzma FORMAT_RAW, filters={LZMA1, dict 1<<24, lc3, lp0, pb2}
        (akışta boyut alanı YOK — end-marker'lı; başlıksız format, S1-S4 taramalarının
        boş çıkma sebebi buydu)
Adım 5  import şifresi (known-plaintext) + IAT + OEP (aşağıda)
```

### 6.2 Import şifresi — known-plaintext saldırısı

**Mekanizma (kaynaktan, intel.cc:22386 EncryptString):**
```
enc[i] = pt[i] XOR uint8( rotl32(key, i) + i )    — key = rand32() dosya-başına
```
**Saldırı:** 37 baytlık bilinen DLL adının (api-ms-win-crt-environment-l1-1-0.dll)
i=0,8,16,24 baytları key'in 4 dilimini tek geçişte verir (rotl kaydırmaları sayesinde):
```
b0=enc[0]^pt[0];  b8=(enc[8]^pt[8])-8;  b16=(enc[16]^pt[16])-16;  b24=(enc[24]^pt[24])-24
key = b0 | b24<<8 | b16<<16 | b8<<24
```
Doğrulama: tüm 37 bayt aynı key ile çözülüyorsa bulundu — dosyada TEK konum eşleşir
(3.5.1: key=0xADF33A3C @0x10D80B; 3.9.4: key=0x7114E936 @0x11BD4C2 — dosya-başına
rastgeleliğin kanıtı).

**Çözülenler:** 3.5.1 → 200+ string (11 DLL + 134 API); 3.9.4 → 5617 string (13 DLL).
DLL seti: KERNEL32, USER32, ntdll, sbiedll (Sandboxie tespiti!), api-ms-win-crt-×7.
**Anti-debug sürücü adları: sice.sys, ntice.sys, siwvid.sys, iceext.sys, syser.sys**
(SoftICE ailesi + Syser — iki sürümde de birebir aynı). Loader API'leri: Nt* syscall seti
+ `wine_get_version` (wine tespiti).

### 6.3 Import tablosu formatı (dosyadaki hali)

- Konum: DLL başına tablo blokları (3.5.1 @0xE3D7D bölgesi; 3.9.4 @0x484800/0x16FB4FC+ —
  konum sürümden sürüme değişir, FORMAT sabittir)
- Kayıt: **[Name_RVA][V1][V2] 12 bayt**; DLL başlığı: `[DLL_RVA][IAT_başlangıcı][0]`
- V2=0 (Key=0) kayıtları **IAT RVA'yı doğrudan** taşır: `__acrt_iob_func`=0x38E0,
  `_fpreset`=0x3960 — orijinal IAT ile birebir eşleşir (biçim kanıtı)
- Loader koşu-anında `*(dst+Address) = GPA(h,api) - Key` yazar → IAT gizleme
- **Tarama dersi (V334):** key doğrulanmış olsa bile her konumda tekil string-çözümü
  false-positive üretir (0xB7'de sahte 'EnumResourceLanguagesW'). Çözüm: **zincir-filtre
  — ≥3 ardışık geçerli kayıt = tablo bloğu**; ayrıca minimum çözülen uzunluk 6.

### 6.4 OEP

VMP dosyanın EP'si VM girişini gösterir (3.5.1: EP=0x29E196). Ama decoded .text'te
**orijinal EP RVA'sındaki baytlar sapasağlam durur**: 3.5.1 de 3.9.4 de OEP=0x13B0,
EP kodu `48 8b 05 61 1c 00 00 c7 ...` 32/32 birebir. VMProtect EP'yi taşır, özgün kodu
silmez — statik dekompres onu geri getirir.

### 6.5 .text farklarının sınıflandırması (bilinçli koruma, hata değil)

Decoded .text ile orijinal arasındaki farkların TAMAMI üç kategoride:
1. `ff25/ff15` (jmp/call [IAT]) → `e8` (call VM-thunk) — import koruması (~24 thunk,
   3.9.4'te ayrıca erken-bölge 0x105A/0x1332)
2. Korunan fonksiyon gövdesi → `e9` VM jmp (MovePlayer 0x14C0-0x1561)
3. .rdata 0x400-0xE00 import bölgesi şifreli (iki sürümde aynı desen)

**.pdata sürüm farkı:** 3.5.1 kısmen düz (loader koşu-anında yeniden yazar), 3.9.4
TAMAMEN şifreli (`0xd6ca7585...` rastgele görünümlü).

### 6.6 Sonuç sayıları
- 3.5.1: .data %100, .text korunan kod birebir, OEP 32/32, unpack_saf.bin .text 6144/6144
- 3.9.4: .text %88.1 (66 fark bloğu/353 B, tamamı bilinçli), .data %90.6, OEP 32/32,
  .FYP 7.712.242 bayt decode
- Pack_The_Output_File varyantı: tablo @0x4374F3, .text %93.8 + OEP 32/32

---

## 7) 3.5.1 ↔ 3.9.4 YAPISAL FARK CEDVELİ (kanıtlı)

| Özellik | 3.5.1 | 3.9.4 |
|---|---|---|
| Paket bölümü | .vmp00 (1.83 MB, loader-verisi ŞİFRELİ) | .cqM (31.5 MB) |
| VM+loader bölümü | .vmp00 içinde | **.FYP 19.5 MB — loader kodu AÇIK düz x86-64** (`48 8d 64 24 10 e8..` + `cc` dolgu) |
| PACKER_INFO konumu | @0x10DF93 | @0x1164D4C (konum serbest — imzayla bulunur) |
| import key | 0xADF33A3C | 0x7114E936 (dosya-başına rand32) |
| Dispatch | jmp rbx (FF E3) | jmp rbx (3.8.4'te jmp rsi) |
| VIP | geriye-yürür, 1-13 bayt değişken | aynı |
| Füzyon | yok | superoperator (51/8/859/23 dosya-başına parametre) |
| .pdata | kısmen düz | TAMAMEN şifreli |
| İstisna-unpacker | VEH tuzağı 3.5.1-motor üretiminde yok (V329 bulgusu) | AV-tuzak + yığın-LUT (V327) |
| Anti-debug seti | sice/ntice/siwvid/iceext/syser .sys | AYNI |
| OEP davranışı | EP taşınır, özgün .text'te kalır | AYNI |

---

## 8) TAŞINMA VE EMÜLASYON TUZAKLARI (C++/Unicorn dersleri)

1. **VA sabitleri uint64_t olmalı:** `constexpr uint32_t VM_DATA0 = 0x140004000` → 33 bit,
   sessizce `0x40004000`'e kesilir → filtre hiçbir VA'yı yakalamaz (sessiz körelme!).
2. **Unicorn C API callback'i `void*` bekler** → C++ lambda KAPMASIZ olmalı + `(void*)` cast.
3. **`uc_mem_map` C API'de izin parametresi ister** (`UC_PROT_ALL`).
4. **Hook aralığı `begin > end`** Python bağında "global" demektir; C API'de hata döner.
5. **Kod kancasında her adım disasm = 10-50× yavaşlama.** Kanca içinde yalnız ham-bayt
   eşle (`FF E3`), disasm'i yalnız olay anlarında yap.
6. **Bellek kancaları aralıklı kaydedin** (begin/end); her erişimde callback maliyeti
   tam koşuyu dakikalara çıkarır.
7. **Unicorn 2.1 emülatör-sınırı:** hook içi `mem_map` → `UC_ERR_MAP`; unmapped okuma
   False döndürür ama AV istisnasına dönüşmez → VEH-tabanlı unpacker emüle edilemez
   (gerçek Windows dökümü reçetesi).
8. **img/ham uzay ayrımı (V335 dersi):** pe.img RVA-uzayı görüntüsüdür (bölümler VA'ya
   serilir); LZMA akışları ve import tabloları HAM dosya ofsetlerindedir → PE.ham alanı.
   Karıştırılırsa akışlar sıfırdan okunur ve hata SESSİZDIR (boş decode ≠ çökme).
9. **32-bit PE bu sandbox'ta koşmaz** (seccomp 32-bit syscall ABI'sini engelliyor:
   WOW64 xtajit yok, Kron4ek multi-lib SIGSYS, Debian chroot SIGSYS). 64-bit PE'ler
   Debian wine64 + Kron4ek wow64 ile koşar.

---

## 9) HANGİ YAKLAŞIM NEDEN BAŞARISIZ (negatif bilgi — en değerlisi)

| Denenmiş | Sonuç | Ders |
|---|---|---|
| ALL'u emülatörde uzun koşuyla açmak (3 kez: 43+64+dk) | kızak yürüyüşü, .text=0 | Koşu-yaklaşımı ölü; statik + kaynak-okuma doğru |
| LZMA-ALONE başlık taraması (S1-S4: tam başlık/props+dict/XOR/zlib-xz-lz4) | 0 aday | Format BAŞLIKSIZ (props 5 bayt AYRI + end-marker, boyut alanı yok) |
| TEB/PEB/anti-debug taklidi (KozDbg değerleri) | yazmaçlar zaten aynı | ALL antidebug DEĞİL — istisna-tabanlı; yanlış teşhis 1 tur yaktı |
| Yanlış VM girişinden emülasyon (0x1400014C6, 0x1400CD444) | akış tutarlı ama 0 olay | Aldatmaca akış = anti-emülasyon tuzağı; giriş kendi-kendine-yeterli olmalı |
| Tek-tuzak-bayt kaba kuvveti (K=0xE0 7.5M talimat) | kızak yine yok | VEH çok-baytlı değer üretiyor; tek bayt yetmez |
| 3.9.4'ü yeniden üretmek (V333) | dosyalar recycle'da kayıp | Önce arşivleri tara — kullanıcı arşivindeydi (V334) |
| unrar joker çıkarımı | boş dizin | Python rarfile ile çözüldü |
| GitHub anonim API | rate-limit | clone/git ile çalış |

---

## 10) TERSİNEÇEVİRİCİ KAYNAK MİMARİSİ

```
tc_kurulum.hpp   — bağımlılık kontrolü + kütüphane yol yardımcıları
tc_pe.{hpp,cpp}  — PE yükleyici (bölümler, RVA↔offset, isim çözümü)
tc_disasm        — capstone sarmalayıcı + her-hiza çözümleme
tc_mutasyon      — imza eşleme + akış takibi + junk sınıflandırma (§2)
tc_vm            — unicorn yürütme + olay kanalları (§3)
tc_oracle        — doğal referans koşusu + değer-değer karşılaştırma (§3.4)
tc_etiket        — komut→tip semantik etiketleme (§4)
tc_unpack        — 5 adımlı statik unpack (§6): props→PACKER_INFO→LZMA→key→kayıtlar
tc_lzma          — liblzma raw LZMA1 sarmalayıcı (props 5D 00 00 00 01 sabit) — V335
tersinecevirici.cpp — CLI: girisler mutasyon vmtrace oracle etiket avtuzak unpack unpack-tam
                    (unpack-tam = tablo + 5 akış decode + orijinal karşılaştırma + OEP
                     32/32 OTOMATİK doğrulama + dosya çıktısı — kapalı döngü:
                     yamalı motorumuzun pack çıktısını da çözer, kanıt V335)
```
**Derleme:** `make` (g++ 14.2, capstone + unicorn statik; libcapstone.so.5 kopyası gerekir)
**Doğrulanmış regresyon seti (her değişiklikten sonra koşulmalı):**
- `mutasyon` Test_64_mutation.vmp.exe → 42/42 + 3/3 dal + 11/11 RIP-hedef
- `vmtrace` → 111.170 adım, 51 dispatch, 12/12 olay
- `girisler` → 5 varyant doğru sınıflama
- `etiket` → 4/4 varyant dağılım birebir (51/8/859/23)
- `unpack` 3.5.1 → 127 kayıt + KEY 0xADF33A3C; 3.9.4 → 128 kayıt + KEY 0x7114E936

---

## 11) KANIT VE DOSYA HARİTASI

| Konu | Kanıt |
|---|---|
| Mutasyon birebir | download/vmp_yukseltme_3.9.4/birebir_sonuc.txt + yontem_scriptleri/ |
| Etiketleme 4/4 | download/v327_kanit/etiket_*.txt + etiket_ozet.json |
| AV-tuzağı/bit-3 | download/v328_kanit/av_kaba.log + vtablo_rapor.txt |
| 3.5.1 unpack | download/v332_kanit/ (PACKER_INFO_ANALIZ.txt + cozulen_*.bin) |
| import+OEP | download/v333_kanit/ (IMPORT_OEP_KANIT.txt + unpack_saf.bin 6144/6144) |
| 3.9.4 unpack | download/v334_kanit/ (KURTARMA_VE_COZUM_KANITI.txt + fark_351_vs_394.json) |
| Yöntem zinciri | TersineCevirici repo YONTEM.md (742b975) + bu doküman |
| Tur tarihi | WORKLOG2.md §33-§56 (V312-V334) |

---

## 12) SÜREÇ DERSLERİ (tam sohbet kaydından — SOHBET_DERSLERI.md özeti)

1. **Token'ı elle yeniden yazma** — payload'da 1 bayt "düzeltme" JWT imzasını öldürür
   (V335: 401'in asıl nedeni buydu; ham dosyadan okununca 200). Token işi bitince yok et.
2. **Kullanıcı deposuna force-push YASAK; push öncesi origin/main..main farkı** (V313:
   add -A + force 83 commit'i silmiş götürdü; reflog ile tamamı kurtarıldı).
3. **Ölçmeden "tamamlandı" yazma** — V313'ün "yeni komutlar tamam"ı V314 ölçümünde
   çürüdü ve AÇIKÇA geri çekildi; iddia-geriçekme disiplini güveni korur.
4. **Aynı yaklaşım 3 kez başarısızsa değiştir** (V329-V332: 3 uzun koşu = kızak;
   pivot kaynak-okumaya → statik çözüm 1 saatte geldi).
5. **Yanlış teşhis bir tur yaktı** (V327 öncesi "antidebug" sanısı): deney matrisi
   (9 kombinasyon, deterministik sonuç) olmadan neden iddia edilmez.
6. **Sıkıştırma/şifre formatını tahminle değil KAYNAKTAN oku** — LZMA formatı 5 dakikada
   loader.cc'den çıktı; S1-S4 imza taramaları saatlerce boşa koşmuştu.
7. **Ghidra'nın "Failed to create function" hatası** resmî korumanın analiz direnci
   anlamına gelir — araç hatası değil, hedef başarısı olarak okunur.
8. **Recycle sigortası:** kritik çıktı anında download/ + upload/YEDEK/ + repo üç kopyası;
   kur betikleri idempotent (v314_yeniden_kur.sh tek komutla her şeyi getirdi).

## 13) SONRAKİ YÖNLER (öncelik sırasıyla)

1. **.FYP açık loader devirt** — 3.9.4'ün loader rutinleri düz x86-64; V327 AV-tuzak
   desenleri burada STATİK aranabilir (avtuzak komutu .FYP-decode çıktısıyla beslenmeli)
2. **.pdata koşu-anı şifresi** — 3.9.4 exception tablosunun loader'daki çözücü rutini
3. **debugger_user varyantları** — VEH/LoaderAlloc anti-debug akış analizi
4. **VEH değerini gerçek Windows'ta dökmek** — ALL koşu-anı kızlağının son parçası
5. **Zincir otomasyonu** — unpack çıktısından otomatik devirt girişi (e8/e9 hedeflerini
   vmtrace'e verme)

---

# BÖLÜM B — V336 DERİNLEVİ EKLER (118 mesajlık tam döküm taramasından)

## 14) VMPROTECT ÜRETİM MEKANİZMASI — kaynak dosya-satırı seviyesinde (3.5.1 ağacından)

**Kaynak ağaçlar:** `universalObfusPublicSrc` (3.5.1, zip'te `_YAMALAR/` ile) + Allver
rar'ında `VMProtect 3.5.1 [Source Code]` tam ağacı (1197 dosya). Motor ~117.000 satır;
Linux-native konsol ikilisi `VMProtectCon` 19,9 MB (g++ 14.2).

### 14.1 Proje (.vmp) XML formatı
```xml
<Document Version="2">                              ← Version="2" ŞART (V335 pack dersi)
  <Protection InputFileName="..." OutputFileName="..." Options="<bitmask>">
    <Procedure MapAddress="MovePlayer" Options="0" Complexity="60"
               IncludedInCompilation="true"/>       ← MapAddress = EXPORT ADI (hex adres DEĞİL!)
    <Messages/>
  </Protection>
</Document>
```
- `OutputFileName` eksikse pack SESSİZ çalışmaz (V335); `MapAddress`'te hex yazarsan
  aynı-MD5 klonlar üretirsin (V329 hatası); `<Document>` Version'suz olamaz.

### 14.2 CompilationType + ProjectOption bitleri (core/core.cc, runtime/common.h)
```
CompilationType: 0=Virtualization  1=Mutation  2=Ultra (mutation+virtualization)
ProjectOption:   cpImportProtection=0x200  cpMemoryProtection=0x1000
                 cpStripFixups=32768  ShadowStack=0x80000 (Options="524288")
ALL konfigürasyonu: Options=0x513C8
```

### 14.3 Determinizm hatası (V312'nin en kritik keşfi)
`Core::Compile` içinde `rand_seed` Lua betiği ÇALIŞMADAN ÖNCE yakalanıyordu →
`setRandomSeed(7)` etkisiz, saat tohumu → aynı betik 3 kez = 3 farklı çıktı. Düzeltme:
betik SONRASI yeniden tohumlama. Sonuç: 3/3 bayt-özdeş (SHA-256 aynı).
**Gizli tuzak:** `saveProject` Lua betiğini XML'e GÖMER (`<Script>`) → yeniden derlemede
gömülü betik tekrar koşar → "yeniden yükleme" testleri kirli kanıttı. Temiz kanıt:
betiksiz MapAddress deneyi (1.642.496 ≠ 1.651.712 B).

### 14.4 Sanallaştırma motoru (kaynak mimari)
- Komutlar `CompileOperand` + `AddVMCommand` ile derlenir; operandlar VM yığına
  `PrepareValues`/`ReturnValues` ile itilir/geri yazılır; değerler `ValueCryptor` ile
  şifrelenir.
- **95 komut tipi sanallaşabilir; hiçbiri SSE/AVX değil.** Bilinmeyen tipler
  `IntelFunction::CompileToVM` beyaz listesinde (intel.cc:18263–18316) `default →
  ltNative` (yerel geçit). Bu yüzden MOVD/MOVQ ve XMM'li komutlar VM'e girmez (V315
  ölçümü: yerel=1, yani geçit). VEX.vvvv gerçek operand DEĞİLDİR — `vex_operand_` içinde
  bekler; BMI2 3-operand sanallaştırması için ayrı yol yazıldı.
- **Instances = aynı VM'in N kopyası** (i1=75.264 B → i10=589.312 B); **VM Version
  "VMProtect 2.X" = daha küçük bytecode** (156–159 KB vs 589 KB).
- **Complexity = birleşik işleyici OLASILIĞI** (resmî Help/en.qch: "probability of
  creating complex handlers") — 3.5.1'de mekanizma VAR (`IntelCommand::Merge`
  intel.cc:12703–12762 + füzyon döngüsü `CommandBlock::Compile` processors.cc:1141)
  ama olasılık kapısı YOKTU → yama: `rand() % 100 < etkin_complexity` kapısı.
- **VM yazmaç modeli: yalnız GPR + bayraklar** (XMM yok) — 111. yama noktasına kadar
  kayıtsız dalda SABİT VM yazmaçları (ESI/EBP/EDI/R11) kullanılıyordu = devirt kaldıracı;
  yama sonrası her kopya kendi pcode/stack/jmp yazmaçlarını seçer (2 tohum = tamamen
  farklı .vmp akışı).
- **Mutasyon deseni:** `jmp xxxx → push xxxx; ret` dönüşümü (intel.cc ~16324) — CET
  gölge yığınıyla ÇAKIŞIR; Shadow Stack açıkken bu dönüşüm kapatılır (7/11/13 ölçüm:
  push;ret 1 → 0).

### 14.5 Yamalı konsol anahtarları + Lua API
```
-vm <0|1>  VM 2.X       -vi <1-10> instances      -vc <0-100> complexity
-rs <seed> tohum         -ss <0|1>  Shadow Stack   (geçersiz değerler reddedilir)
Lua: vmprotect.core(), setVMComplexity, setVMInstances (11 reddi), setRandomSeed,
     setShadowStackCompatible, fonksiyon.complexity (101 reddi), saveProject
     — listeler 1-TABANLI indeksli (item(0) sınır dışı!)
```

### 14.6 Derleme zinciri (Linux-native)
`lin_common.mak`: `-DNDEBUG -fno-stack-protector -fno-builtin -fPIC`, C++ `-std=c++11`,
link `-no-pie`; invar `-DSCI_LEXER -DSCI_NAMESPACE`. Tek g++ uyumluluk düzeltmesi:
pe.h'deki `COMIMAGE_FLAGS_NATIVE_ENTRYPOINT`'in dotnet.h enumuyla çakışması. Runtime
modülleri (win_runtime*.dll.inc, lin_runtime*.so.inc) kaynakta gömülü. -j8 bellek
limiti → -j2. Başlık-duyarsız önbellek hatası: başlık değişince 10 eski nesne
derlenmedi → önbellek en-yeni-başlık-zamanına bağlandı.

## 15) KOMUT KORPUSU — talimat seti detayları (V314/V315)

**Doğru harita (GNU as/objdump ile doğrulanmış — ilk yamada 2 hata vardı):**
```
SHLX = 0F38.F7/66   SHRX = 0F38.F7/F2   SARX = 0F38.F7/F3   (pp 10=F3=SARX, 11=F2=SHRX!)
RORX = 0F3A.F0      VPMASKMOV-store = 0F38.8E   VPBLENDD = 0F3A.02 (0F38.02'den TAŞINDI)
```
- **case 0x02 çakışması:** 0F38.02'de PHADDD vardı; 3.5.1 VEX'li 0F38.02'yi PHADDD
  sanıyordu — resmî 3.7.3 changelog "VPBLENDD disassembling" kaydının GERÇEK NEDENİ.
- **V314'ün en kritiği — test PE şablonu hatası:** `movabs r11,body; jmp r11` dolaylı
  atlaması sınanan komutu FONKSİYON DIŞINDA bıraktı → çözümleyici 6 komut gördü →
  **185/185 "TAMAM" yanlış kanıttı** (komutlara hiç dokunulmamıştı!). Düzeltme: doğrusal
  şablon + "ret'e ulaşıyor mu" denetimi. DERS: testin kendisi test edilmeden ölçüm yok.
- **El yazımı baytlar neden yanlıştı:** VEX harita baytları, BMI2 vvvv, RORX vvvv,
  roundsd 2.5-bayt düzeni; INSERTPS/EXTRACTPS immediate bitleri (EXTRACTPS seçici
  imm8[1:0]; INSERTPS kaynak imm8[7:6], hedef imm8[5:4], zmask imm8[1:0]); VPMASKMOV
  yüklemede maskeli şeritler SIFIRLANIR (korunmaz) — hepsi yerel CPU'da ölçülerek düzeltildi.
- Komut tipi numaraları (yamalı çözümleyici): SHLX=579, SHRX=578, SARX=577, RORX=580,
  VPBLENDD=585, VPMASKMOVD/Q=583/584, MOVD t=178.
- Komut başına TEK test PE (GNU as+ld; `func` yalnız komut DOĞRU hesaplarsa 42 döndürür):
  37 test (1 düz denetim + 8 MOVD/MOVQ + 28 yeni). Metrikler: rc=42 (semantik) +
  **yerel sayısı** (0 = sanallaştırıldı, >0 = yerel geçit). Evrim: taban 9/37 →
  V314b 37/37 derlendi → V315 BMI2 10/10 yerel=0 (GERÇEK VM).

## 16) ARAÇ KURULUM REÇETELERİ (kanıtlanmış kombinasyonlar)

### 16.1 wine (GUI'yi debugger-detection'sız açan TEK güvenilir build)
- **Kron4ek wine-10.0-amd64-wow64.tar.xz** (65 MB) — VMProtect GUI sorunsuz.
- wine-11.22-amd64: wineboot core dump; wine-11.22-wow64: açılışta "debugger found";
  wine-9.0-amd64: koşum OK ama uzun koşuda page fault.
- Debian wine64 debs + `dpkg -x` (root'suz): builtin user32/kernel32 c0000135 yüklenemedi
  (3 konfigürasyonda çözülemedi) → terk; nls sorunu `l_intl.nls` sabit yol araması
  LD_PRELOAD kök-çeviriciyle (v312_wine_kok_shim.c) aşıldı.
- Wine Mono sihirbazı: registry `[Software\\Wine\\DllOverrides]` mscoree/mshtml/winedbg="".
- zlib1.dll 32-bit tuzağı: kurulum i686 kopyalamış (c000007b) → 64-bit mingw zlib
  prefix system32'ye (builtin dizini reddeder: "not a builtin, ignoring").

### 16.2 GUI otomasyonu (Xvfb zinciri)
```
Xvfb :99 1280x1024x24 → wm.py (ctypes mini-WM: WM'siz Xvfb'de wine pencereleri
map OLMAZ!) → xkey (XTEST klavye; otomatik Shift katmanı: "colon" → Shift+;)
→ xdotool (libXtst6 deb'i ŞART — eksikse xdotool SESSİZCE hiç çalışmaz, F9 gitmez!)
→ tesseract OCR + python-xlib ekran görüntüsü
```
- F5=Execute (oyun başlar!), F9=Compile — mainwindow.cc kısayol setinden doğrulandı.
- wineconsole odağı çalar → oyun penceresi `windowunmap` edilince derleme tetiklendi.
- Confirmation diyaloğuna **Escape** (Return oyunu başlatır).
- XSetInputFocus BadMatch → hata yok-sayan handler; kök odaklı yazım gitmez → BackSpace×60.

### 16.3 Analiz araçları
- **rea 6.10.1** (npm): inspect-binary-hardening/compare-artifacts/audit-release-exposure
  çalışır; decompiler native motor ister. **Ghidra 12.2** (570MB) + **JDK 25** (Temurin).
- **unrar-nonfree 7.3.2** (Debian pool/non-free; unrar-free RAR5 ÇÖZEMEZ); Python rarfile.
- **innoextract** + libboost-program-options (VMProtectDemo.exe 177MB açılımı).
- **pefile (pip)**: RVA→dosya-ofset dönüşümü el yapısı parser'da eksikti (+24/+28/+36
  yanlış alarmları).
- Qt Help .qch = SQLite → `v312_qch_cek.py` FileDataTable'dan HTML (resmî dokümantasyon!).
- vmpsoft.com sertifika zinciri: Let's Encrypt kökleri CA paketine eklenerek (TLS
  denetimi KAPATILMADAN) çözüldü.
- **32-bit PE bu sandbox'ta KOŞMAZ** (seccomp; WOW64 xtajit yok, Kron4ek multi-lib
  SIGSYS, Debian chroot SIGSYS) — 3.3.1 x86 bu yüzden 0/15.

## 17) ÖLÇÜM YÖNTEMLERİ BÜTÜNÜ

1. **E2E parite:** FIFO'dan hamle dizisi (d,d,d,s,w,q) → skor/can/yem/RC karşılaştırma
   (V301: Skor 40 / Can 3 / Yem 78 / RC=0, skor geçişleri 20→30→40 dahil birebir).
2. **Canlı RAM analizi:** umvpqt --pid + CE-tarzı /proc/PID/mem UTF-8+UTF-16 tarama
   (vsyscall taşma filtresiyle). Self-protect farkının kanıtı: menü metinleri RAM'de
   (File×698) ama Qt meta 0 (QMainWindow sıfır; tek sınıf kaydı metaobject=0x0).
3. **Crash-pencere yakalama:** self-protected exe'ler wine'da unpack'te page fault →
   0,5 sn döngüyle winedbg askısında QObject sayımı (3.9.6: 292; normal koşumda 3–36).
4. **Determinizm:** aynı tohum 3 koşu SHA-256; HANG tespiti: 320×60 "Saving... %"
   diyaloğu + 50 sn erken tespit + yeniden başlatma.
5. **Dedektör doğrulaması:** MVP_GOD_SSS_TIER_PACKER_FINDER v4, 407/407 kör test;
   K1 bayrak deseni 0x68000020 / K2 PURE sarmalayıcı 2048/2032 B (3.5.1'de 216) /
   K4 408-profil. Dedektör çıktısı GÖSTERGE'dir, kanıt değil.
6. **en.lng anahtar-diff:** sürüm eşiği tespiti (3.6+ Assemblies/LockToHWID,
   3.8.1+ Complexity/Instances −Taggant, 3.8.4+ ShadowStack, 3.8.7+ StackTraceDecoder;
   3.0.9–3.6.0'da Complexity anahtarı HİÇ yok — 3.5.1 GUI kodunda "complexity" 0 kez).

## 18) VARYANT BOYUT VERİTABANI (tam sayılar — Test_64.exe 12.800 B girdi)

| Konfig | Boyut |
|---|---|
| Taban fn1-virt (i10 default) | 589.312 B |
| Instances i1→i10 | 75.264 → 592.384 B |
| VM Complexity c0→c100 | 585–590 KB → 1.623.552 B (%50=1.150.464) |
| VM 2.X | 156.160 / 158.720 / 159.232 B |
| Fonksiyon Complexity %50/%100 | 611.840 / 612.352 B (zayıf!) |
| Füzyon fc0/fc50/fc100 | 586.240 / 603.136 / 614.400 B |
| Konsol -vc100 -rs7 | 1.651.712 B (3/3 SHA-256 aynı) |
| Lua betik yolu | 1.645.056 B; betiksiz MapAddress-60: 1.642.496 B |
| Tüm seçenekler açık | 18,55 MB (wine'da koşmadı) |
| Resmî 3.9.6 GUI (V301, 6 prosedür) | 2,74 MB, .dne entropi 7,07 |
| fn-virt / fn-mutation / fn0-pack (V309) | 2.539.008 / 14.848 / 4.088.165 B |
| ALL 3.9.4 orijinal | 51 MB (.cqM 31,5 MB + .FYP 19,5 MB) |
| ALL 3.5.1-motor | 1.245.184 B |
| vi1 c100 | 196 KB → 1,93 MB (18×) |
| vi10 (10 kopya) | 18,86 MB; tam-ayar vi10+c50: 15,8 MB rc=0 |

**V309 matrisi (15 varyant × 11 sürüm, 140/165):** 3.0.9/3.2.0 15/15 kusursuz;
3.4.0/3.6.0 10/15 (5 HANG: fn-virt, fn-virt-all, fn0-import, fn0-stripreloc, fn0-vmtools
— wine'a özgü); 3.3.1 0/15 (x86); 3.8.1/3.8.4 12/15; 3.9.6 7/15; 3.9.4 6/15 (3.9.x
wine'da dengesiz — Windows'ta farklı olabilir).

## 19) RESMÎ SÜRÜM ENVANTERİ (universalAllver.rar: MD5 f98140bb208579efae4709ab395f1c96, 500 MB)

- 12 VMProtect.exe (gerçek 11 benzersiz; 3.9.4 iki klasör = aynı MD5 24576e5e…):
  Lite 3.10.4/3.8.7, Pro 3.8.1/3.9.6, Ultimate 3.0.9/3.2.0/3.3.1(x86)/3.4.0/3.6.0/
  3.8.4/3.9.4. 3.9.4 paketinde konsol ikilisi YOK (yalnız GUI) + Help/en.qch.
- **Paketleme evrimi (en çarpıcı bulgu):** 3.0.9→3.4.0 `.UPX0/.UPX1` taşır (entropi ~7,9)
  ama `upx -d` "not packed by UPX" der → **kamuflaj** (paketleyici VMProtect'ın kendisi);
  3.6.0+ UPX bırakıldı → ~30 MB rastgele adlı VM bölümleri; 3.6.0+ sürekli: `.qtmetad`
  VAR (Qt statik) ama orijinal bölümler diskten silinmiş (rawsize=0).
- VM bölüm adları sürüm DEĞİL proje-seçeneği farkı: Ultimate 3.9.4 çıktısı düz `.vmp0`
  (Metin2 kanıtı), Pro 3.9.6 çıktısı rastgele `.dne` (entropi 7,07).
- 3.11 demo: VMProtect.exe 47,4–49,7 MB + VMProtect_Con.exe + SDK'lar (Rust/Go/Lazarus)
  + 5 dil (de/en/fr/ru/zh); 3.9.6→3.11 +6 UI anahtarı (Theme/Dark/Light).
- QObject canlı sayımlar: 3.0.9=317, 3.8.1=293, 3.8.4=40, 3.9.6=36, 3.8.7=32,
  3.9.4=30, 3.4.0=27, 3.2.0=4, 3.10.4=3, 3.6.0=3.

## 20) SÜRÜM TEŞHİS ARACI REÇETESİ (Packer Finder profilleri)

K1: bölüm bayrak deseni 0x68000020 (resmî K1 birebir) · K2: PURE sarmalayıcı boyutu
2048/2032 B (3.5.1 tabanı 216 B → V319 yamasıyla parite) · K4: 408-profil.
Yamalı motor 3.5.1 olarak ALGILANMAYI bıraktı (3.6.0–3.8.7 bandına düştü) — amaç
"3.9.4" etiketi değil, resmî profil eşleşmesi.
