# TersineCevirici — VMProtect 3.9.4 Mutasyon + Sanallaştırma Devirtualizer (C++)

V324 araştırma zincirinin C++ uygulaması: VMProtect 3.9.4 ile korunmuş bir PE'de
**mutasyona uğramış fonksiyon gövdesinden orijinal talimat dizisini birebir çıkar**
ve **sanallaştırılmış fonksiyonu Unicorn emülasyonu ile doğal yürütmeyle (oracle)
değer-değer doğrula**.

Doğrulanmış hedef: `Test_64_mutation.vmp.exe` → MovePlayer (42/42 talimat, 3 dal
hedefi, 9 RIP-göreli sembol adresi birebir) + `Test_64_moveplayer_virtualization.vmp.exe`
→ 111.170 adımlık VM yürütmesi, 51 komut-dispatch, 12/12 konuk olayı oracle ile eşleşti.

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
