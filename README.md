# TersineCevirici — VMProtect 3.9.4 Mutasyon + Sanallaştırma Devirtualizer (C++)

V324 araştırma zincirinin C++ uygulaması: VMProtect 3.9.4 ile korunmuş bir PE'de
**mutasyona uğramış fonksiyon gövdesinden orijinal talimat dizisini birebir çıkar**
ve **sanallaştırılmış fonksiyonu Unicorn emülasyonu ile doğal yürütmeyle (oracle)
değer-değer doğrula**.

Doğrulanmış hedef: `Test_64_mutation.vmp.exe` → MovePlayer (42/42 talimat, 3 dal
hedefi, 9 RIP-göreli sembol adresi birebir) + `Test_64_moveplayer_virtualization.vmp.exe`
→ 111.170 adımlık VM yürütmesi, 51 komut-dispatch, 12/12 konuk olayı oracle ile eşleşti.

## V327/V328 — Yeni yetenekler

- **`etiket` komutu** — komut→tip semantik etiketleme: her VM komutu dispatch-arası yazmaç
  deltaları + bellek olayları + WrapPos giriş/çıkış kanıtlarıyla kullanıcı 42-tip sınıfına
  bağlanır (LOAD/STORE/RMW/CALL/PROLOG/EPILOG/ARITH-FUSE/VM-İÇ). **4/4 varyant C++ ↔ Python
  birebir doğrulandı**: VARSAYILAN 51, c100 8, ultra 859, ultra_c100 23 komut — dağılımlar
  dahil tam eşleşme (kanıt: work/v327/etiket_*.txt + etiket_ozet.json)
- **`avtuzak` komutu** — AV-tuzak aday tarayıcı: `[base + idx*scale - K]` desenli talimatları
  bulur (V327 ALL teşhisi: `movzx r9d,[rdx+r9*2-0xf187d1a]` → sabit=idx*scale → EA=base →
  bilinçli NULL-page okuması → gerçek Windows'ta ACCESS_VIOLATION → VEH değer üretir →
  yığın-LUT indeksi). ALL'da 0x142998C82-0x142998D11 bölgesinde 3 aday bulundu
- **AV-tuzak kaba kuvvet** (Python tarafı, scripts/v328_av_kaba.py): sayfa-0'ı K baytıyla
  doldurup 256 koşu — bit-3 set olan 58 K değeri kızaksız farklı yola sapıyor (VEH değerinin
  akışı dallayan gerçek bileşeni); K=0xE0 1.23M talimata kadar koşuyor (normal ~345K)

## ALL (Pack) teşhisi — özet (V327, kanıtlı)

ALL'un emülatörde çözülemediği şey **antidebug/antivm DEĞİL** (TEB/PEB/Ldr/KUSER kuruldu —
fark yok; 9'luk giriş matrisi deterministik; syscall kullanmıyor; API çağrısı 0). Gerçek
neden: **istisna-tabanlı unpacker** — bilinçli null-okuma → AV → VEH'in ürettiği değer
yığın-LUT'a indeks. LZMA formatı da çözüldü (3.5.1 kaynağından): PACKER_INFO {Src,Dst}
tablosu + props 5 bayt AYRI + akışta boyut alanı YOK (end-marker'lı, dict 1<<24, level 9).
ALL'da .#:V bölümü bu tablodur (25 girdi; Src'ler .cqM-içi göreli ofset; Dst'ler koşu-anında
çözülür). Statik LZMA 0 aday = akışlar koşu-anı anahtarlı.

## Ne yapıyor?

1. **PE yükleyici** — bölüm tablosunu belleğe serer (RVA→VA eşlemesi, image base 0x140000000)
2. **Giriş çözücü** — MovePlayer RVA 0x14C0'daki `E9 rel32` jmp'sini çözerek her varyantın
   koruma girişini bulur (MUTATION → 0x1400062EB, VARSAYILAN → 0x14007602F, ...)
3. **Her-hizadan talimat çözümü** — Capstone ile tüm olası hizalarda decode edilir;
   her talimat için imza = (opkod baytları, RIP-göreli hedef adresi)
4. **İmza eşleme** — bilinen orijinal fonksiyonun talimat listesi (opkod + sembol adresi)
   mutasyon gövdesinde aranır; `add rcx,rdx` gibi derleyici eşdeğerleri (`lea rcx,[rcx+rdx]`)
   de tanınır
5. **Akış takibi + junk sınıflandırma** — opak-koşul sıçramaları ve `jmp +N` blokları
   takip edilir; ölü-yazmaç (`dil`, `dx`, `r12w`...), ölü-bayrak (`clc`/`stc`/`setl`),
   akış-junk'ları sınıflandırılıp raporlanır
6. **Sanallaştırma doğrulayıcı (Unicorn)** — doğru girişten yürütme: dispatch sayacı
   (`jmp rbp`), .data olay kanalları, WrapPos'in gerçek .text koşusu, komut-atıf
   (olay → VM komut numarası) ve doğal oracle ile değer karşılaştırması

## Derleme

```bash
make                        # libtersinecevirici.a + tersinecevirici üretir
make test                   # sandbox testi (örnek dosyalarla, varsa)
```

Bağımlılıklar: Capstone (libcapstone), Unicorn (libunicorn). `Makefile` içindeki
`CAPSTONE_DIR` / `UNICORN_DIR` yollarını kendi kurulumunuza göre düzenleyin
(test ortamında Python wheel'leri içindeki paylaşılan kütüphaneler kullanıldı).

## Kullanım

```bash
# 1) Mutasyon devirtualization — birebir tablo + junk raporu
./tersinecevirici mutasyon  <korunmus.exe> [giris-hex]

# 2) Varyant giriş envanteri — tüm dosyaların 0x14C0 jmp hedefleri
./tersinecevirici girisler  <orijinal.exe> <dosya1.exe> [dosya2.exe ...]

# 3) Sanallaştırılmış doğrulama — Unicorn iz + olay → oracle karşılaştırması
./tersinecevirici vmtrace   <korunmus.exe> <orijinal.exe> [yon]

# 4) Doğal oracle — orijinal exe'de referans olay dizisi
./tersinecevirici oracle    <orijinal.exe> [yon]

# 5) Komut→tip semantik etiketleme (V327 — 4/4 varyant Python ile birebir)
./tersinecevirici etiket    <korumali.exe> <giris-va> [yon=2]
#   ornek: etiket Test_64_moveplayer_virtualization_complexity_100.vmp.exe 0x140001530 2
#   c100 → 8 komut: LOAD(pos)→CALL(WrapPos)×2→PROLOG×3→STORE(pos)→RMW(g_score,g_dots)

# 6) AV-tuzak aday taraması (V327 ALL teşhisi — istisna-tabanlı unpacker)
./tersinecevirici avtuzak   <korumali.exe> <bas-va> <son-va>
#   ornek: avtuzak Test_64_ALL.vmp.exe 0x142998C82 0x142998D11 → 3 aday (0x142998CC2 dahil)
```

## Çıktı örneği (mutasyon, Test_64_mutation.vmp.exe)

```
[EŞLEŞME 42/42] push rsi ← 0x1400062EB
[EŞLEŞME 42/42] ja → 0x14000636C (= +2C karşılığı: add ecx,[g_px])
...
[SONUÇ] 42/42 talimat birebir | 3/3 dal hedefi | 9/9 RIP-hedef sembol adresi
[JUNK] ~35 blok (%55): ölü-yazmaç 12, ölü-bayrak 5, akış-jmp 8, ...
```

## Mimari

```
tersinecevirici.cpp     — main: komut satırı yönlendirme (4 alt komut)
tc_pe.hpp / tc_pe.cpp   — PE64 yükleyici (bölümler, image base, bölüm envanteri)
tc_disasm.hpp / .cpp    — Capstone sarmalayıcı: her-hiza decode + RIP-hedef çözümü
tc_mutasyon.hpp / .cpp  — imza eşleme + akış + junk sınıflandırma (devirt çekirdeği)
tc_vm.hpp / .cpp        — Unicorn yürütme: dispatch/olay kanalları + komut-atıf
tc_oracle.hpp / .cpp    — orijinal exe'de doğal referans koşusu
tc_kurulum.hpp          — test ortamı yardımcıları (kütüphane yolları)
```

## Kanıt zinciri

- Python referans zinciri: `scripts/v322_lifter.py`, `v323_tamiz.py`, `v323_natif.py`,
  `v324_birebir.py`, `v324_sonuc.py` (MyRepo / MVP_REVERSE, WORKLOG2 §44–§46)
- Doğrulama verisi: `download/v324_kanit/birebir_sonuc.txt` (42 satırın tamamı)
- Yöntem dökümanı: MyRepo `download/vmp_yukseltme_3.9.4/YONTEM.md`
