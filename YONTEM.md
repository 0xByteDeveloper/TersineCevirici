# YÖNTEM — VMProtect 3.9.4 Devirtualization Bilgi Zinciri (V320–V329)

Bu belge, `TersineCevirici` projesinin arkasındaki **kanıtlanmış yöntem zincirini** ve
**3.5.1 → 3.9.4 kaynak yükseltmesi için 6 kanıtlı fark maddesini** içerir. Her madde
deneylerle doğrulanmıştır; kanıt dosyaları MyRepo `download/v32x_kanit/` klasörlerindedir.

---

## Bölüm A — Yöntem zinciri (V320 → V329)

### A.1 Çoklu-koşu determinizmi (V320–V321)
Aynı konfigürasyon N kez üretilir; talimat dizileri karşılaştırılır.
**Bulgu:** 2 farklı tohum tamamen farklı .vmp bayt akışları üretir (tohum-kanıt);
koşu-içi akış dosya-başına deterministiktir.

### A.2 Unicorn kaldırıcı zinciri (V322)
Korumalı gövdeden `vm_entry` bulunur; Unicorn'da talimat talimat yürütülür.
**Bulgu:** 422 komut, 263 işleyici, VIP=RSI, VM-yığını=RDI (3.5.1 motor).

### A.3 Birebir oracle doğrulaması (V323)
Emülatör koşusu, doğal (wine'da çalışan) orijinalin .data olay dizisiyle
değer-değer karşılaştırılır. **Bulgu:** resmî 3.9.4 sanallaştırılmış MovePlayer
111.170 adım, 51 dispatch, 12/12 olay birebir — sahte iç-köprüler (0x1400CD444)
ayıklanmalı, gerçek vmenter = `push r11; pushfq; movabs <anahtar>; test/jge`.

### A.4 Mutasyon gövdesinden birebir çıkarma (V324)
Her-hiza Capstone decode + (opkod, RIP-göreli hedef) imza eşleme + derleyici
eşdeğeri tanıma (`add rcx,rdx` ≡ `lea rcx,[rcx+rdx]`). **Sonuç:** 42/42 talimat,
3 dal, 9 RIP-hedef birebir; junk sınıflandırması: ölü-yazmaç/ölü-bayrak/akış-jmp.

### A.5 C++ taşıma (V325 + V328)
Zincirin tamamı C++'a taşındı (bu repo). `etiket` komutu V327 Python etiketleyiciyle
**4/4 varyant birebir** doğrulandı: VARSAYILAN 51, c100 8, ultra 859, ultra_c100 23
komut — dağılımlar dahil.

### A.6 Negatif kanıt yöntemi (V326)
Bir iddianın çürütülmesi de kanıttır: TEB/PEB/Ldr/KUSER değerleri gerçek Windows
değerleriyle kuruldu (BeingDebugged=0, NtGlobalFlag=0, NtQIP(DebugPort)→0) —
**fark yok** → PEB-tabanlı anti-debug YOK. 9'luk giriş matrisi (EFLAGS × RCX × [RSP])
9/9 aynı → akış dosya-içi deterministik. SYSCALL kancası → 0 çağrı.

### A.7 İstisna-tabanlı unpacker teşhisi (V327)
ALL varyantı emülatörde düşük belleğe kayar. Kök neden: **bilinçli null-okuma tuzağı**
(`movzx r9d,[rdx+r9*2-0xf187d1a]`, sabit=idx·scale → EA=rdx=8). Gerçek Windows'ta
ACCESS_VIOLATION → unpacker'ın VEH'i istisna bağlamından değer üretir → bu değer
yığın-LUT'a (`mov r9d,[rcx+r9*4]`) indeks. Emülatörde AV yok → yanlış LUT → `jmp r8`.
**Kaba kuvvet doğrulaması (V328):** sayfa-0'ı K baytıyla doldur, 256 koşu —
58 kızaksız K'nın TAMAMI bit-3 set; K=0xE0/E8 7.5M talimat (normalin 21 katı).
textY=0 → VEH çok-baytlı değer üretiyor.

### A.8 LZMA formatı (V328, 3.5.1 kaynağından)
- Packer: LZMA level=9, dictSize=1<<24, writeEndMark → **props 0x5D ayrı 5 bayt**
- Loader: **PACKER_INFO tablosu** — 8 baytlık `{uint32 Src, uint32 Dst}` girdileri;
  ilk girdi props'u gösterir; `LzmaDecode(..., -1, ...)` → **akışta boyut alanı YOK**
  (end-marker'lı). Faces magic: `PACKER_INFO = 0xFACE0100`.
- ALL'da `.#:V` bölümü bu tablodur (25 girdi; Src'ler .cqM-içi göreli ofset;
  Dst'ler koşu-anında çözülür).
- **Statik taramada S1/S2'nin boş çıkma nedeni:** 13-baytlık ALONE başlığı arıyorduk —
  format başlıksız (props ayrı + boyutsuz).

### A.9 Kaynak kurtarma + Linux derleme (V329)
`work/` sandbox recycle'ında silinince: universalAllver.rar içinden 3.5.1 tam kaynak
(1338 dosya, VMProtectCon dahil) `rarfile` ile çıkarıldı; lang_enum/lang_def/lang_info
(version.bat/lang.bat'ın Python karşılığı) + liblzma(-D_7ZIP_ST) + libtinyxml +
libdemangle(-D_DEBUG -DBOOL=int) + liblua yeniden üretildi; **vmprotect_con
Linux-native derlendi (CON_OK)** ve 4+2 varyant yeniden üretildi (V324 deseni:
.text RSZ=0 sanal + Options=0x513C8).

### A.10 reu (rancy777/reu) karşılaştırması (V328)
reu bir devirt aracı değil — 3.8.4 tek-vaka Triton trace-replay kanıt zinciri.
Kanıtlı VM detayları: VIP=r8 geriye-yürür, rolling-key=rbp, dispatch=jmp rsi,
handler tablosu=[r11+rcx*8-0x40], %78 junk. **Füzyon hakkında ipucu yok** —
51/8/859/23 gözlemimiz benzersiz. Metodolojik katkı: concrete-sync'li sembolik
replay şablonu.

---

## Bölüm B — 3.5.1 → 3.9.4 yükseltme: 6 KANITLI FARK MADDESİ

Her madde: gözlem → kanıt → yükseltmede yapılacak şey.

### B.1 Superoperator füzyonu — dosya-başına parametre
**Gözlem:** Aynı 42 satırlık MovePlayer, 4 farklı komut sayısına derleniyor:
VARSAYILAN 51, c100 8, ultra 859, ultra_c100 23 (c100: LOAD→CALL×2→PROLOG×3→STORE→RMW
okunuşu). ultra'da 836/859 ARITH/FUSE = obfuscasyon katmanı (~49× VARSAYILAN).
**Kanıt:** V325/V326 (20/20 koşu × 42/42 satır) + V327 (941/941 komut etiketleme) +
V328 C++ 4/4 birebir.
**Yükseltme:** motor derleyicisinde işleyici-birleştirme (superoperator) aşaması
dosya-başına rastgele füzyon parametresiyle çalışır; çözücü bu parametreyi
girdi dosyadan türetmelidir (deterministik tohumdan).

### B.2 Derin işleyici füzyonu
**Gözlem:** VARSAYILAN #14: dx+dy çift tablo okuması TEK komutta; #24: 2×WrapPos
TEK komutta; #38: maze-yaz + g_dots TEK komutta.
**Kanıt:** V327 etiket tabloları (download/v327_kanit/).
**Yükseltme:** işleyici-graf çözümleyici, çoklu-etki işleyicileri bölebilmeli
(etki-etkilenen analiziyle).

### B.3 Dispatch talimatı ve VIP yönü
**Gözlem:** 3.8.4: dispatch=`jmp rsi`, VIP=r8 geriye-yürür, rolling-key=rbp,
handler=[r11+rcx*8-0x40]. 3.9.4 (bizim izler): dispatch=`jmp rbx (FF E3)`,
VIP geriye-yürür, rolling adc-carry türevi.
**Kanıt:** reu trace analizi + bizim vmtrace (V322–V324).
**Yükseltme:** dispatch desenini yapılandırma-dan türet (jmp reg tablosu),
sabit kodlama; VIP yönü her iki sürümde aynı (geriye).

### B.4 Packer LZMA formatı
**Gözlem:** 3.5.1'de PACKER_INFO {Src,Dst} + props-ayrı + end-marker'lı akış;
3.9.4 ALL'da aynı yapı (.#:V tablosu) ama Dst'ler koşu-anında çözülür, akışlar
koşu-anı anahtarlı (statik decode 'Corrupt input').
**Kanıt:** vmpsrc loader.cc + Loader.cs okuması + ALL .#:V dökümü (V328).
**Yükseltme:** statik unpacker, PACKER_INFO çözümünü koşu-anına taşımalı veya
VEH değerini önce çıkarmalı.

### B.5 İstisna-tabanlı unpacker (3.9.4'e özgü davranış)
**Gözlem:** 3.9.4 ALL'da bilinçli NULL-page AV-tuzağı + yığın-LUT (A.7). 3.5.1
kaynağında bu mekanizma yok (loader.cc doğrudan LzmaDecode çağırır).
**Kanıt:** V327 kok_neden.txt + V328 kaba kuvvet (bit-3 keşfi).
**Yükseltme:** 3.5.1 loader'ına VEH-dispatch emülasyonu eklenmeli ya da çözücü
AV'yi yakalayıp VEH'i kendisi çağırmalı.

### B.6 Sürüm duyarlılığı uyarısı (reu)
**Gözlem:** reu'nun kendi workflow dosyası: "Version/config changes may invalidate
all prior handler descriptions".
**Kanıt:** reu repo + bizim 3.5.1↔3.9.4 dispatch farkı (B.3).
**Yükseltme:** her sürüm için işleyici tablosunu yeniden türet; sabit tablo ASLA
sürümler-arası taşıma.

---

## Bölüm C — ALL unpack playbook'u (uygulanabilir reçete)

1. **Kurulum:** TEB/PEB/Ldr/KUSER gerçek değerlerle (A.6) — antidebug kaynaklı
   engel yok, geç.
2. **Koşu:** unpacker'ın LZMA döngüsü Milyonlarca talimat sürer (34M+ yazma,
   probs bölgesi 0x200000-0x2FFFFF). Uzun koşu (900s+) gerekli.
3. **AV-tuzağı:** null-AV yakalanırsa (V324-orijinal ALL: 345K'de) → VEH-değer
   gerekli. İz: kaba kuvvet bit-3 ailesi (0xE0/0xE8) veya Windows'ta x64dbg ile
   ilk ACCESS_VIOLATION'da VEH'in LUT'a yazdığı değeri oku.
4. **LZMA bitişi:** dekompres tamamlanınca PACKER_INFO'daki {Src,Dst} çiftleriyle
   .text/.rdata/.data/.pdata bölümleri dolar (sanal RSZ=0 bölümler).
5. **OEP + impçözüm:** fixup + IAT kopyaları (loader.cc `__movsb` IAT_INFO döngüsü)
   sonra OEP'e atlar — .text doluluğu + jmp kontrolü.

---

## Sürüm geçmişi
- V328: etiket (4/4 birebir) + avtuzak komutları eklendi (b437c0e)
- V329: bu belge (YÖNTEM.md) — bilgi zinciri + 6 madde + playbook
