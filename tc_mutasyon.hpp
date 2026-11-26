// tc_mutasyon.hpp — devirt çekirdeği: imza eşleme + akış + junk sınıflandırma
// (V324 v324_birebir.py + v324_sonuc.py TABLO listesinin C++ karşılığı)
#pragma once
#include "tc_disasm.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace tc {

// Bilinen orijinal fonksiyon talimatı: etiket + ham desen (opsiyonel) + RIP-hedef VA
// (0 = eşleşmede kullanılmaz). V324 sonuc TABLO'su ile birebir aynı veri.
struct TalimatImza {
    const char* etiket;
    const char* desen_hex;  // "" → desen yok (dal hedefleri akışla çözülür)
    uint64_t    hedef_va;   // 0 = önemsiz; 'D' = dal (akış çözümü); 'L' = lea-eşdeğer ailesi
};

// V324 birebir tablosu — MovePlayer (Test_64, resmî 3.9.4 MUTATION ile doğrulandı)
const TalimatImza MOVEPLAYER_IMZALARI[] = {
    {"push rsi",                    "56", 0},
    {"push rdi",                    "57", 0},
    {"sub rsp,28",                  "4883ec28", 0},
    {"mov eax,ecx",                 "89c8", 0},
    {"dec eax",                     "ffc8", 0},
    {"xor ecx,ecx",                 "31c9", 0},
    {"mov edi,0",                   "bf00000000", 0},
    {"cmp eax,3",                   "83f803", 0},
    {"ja +2C",                      "0f87", 'D'},
    {"mov eax,eax",                 "89c0", 0},
    {"lea rcx,[dx_tablo]",          "488d0d", 0x140003230},
    {"mov ecx,[rcx+rax*4]",         "8b0c81", 0},
    {"lea rdx,[dy_tablo]",          "488d15", 0x140003240},
    {"mov edi,[rdx+rax*4]",         "8b3c82", 0},
    {"add ecx,[g_px]",              "030d", 0x140004008},
    {"add edi,[g_py]",              "033d", 0x14000400C},
    {"mov edx,0F",                  "ba0f000000", 0},
    {"call WrapPos",                "e8", 0x140001470},
    {"mov esi,eax",                 "89c6", 0},
    {"mov ecx,edi",                 "89f9", 0},
    {"mov edx,0B",                  "ba0b000000", 0},
    {"call WrapPos(2)",             "e8", 0x140001470},
    {"movsxd rdx,eax",              "4863d0", 0},
    {"shl rdx,4",                   "48c1e204", 0},
    {"lea rcx,[g_maze]",            "488d0d", 0x140004010},
    {"add rcx,rdx (=lea [rcx+rdx])","",  'L'},
    {"movsxd rdx,esi",              "4863d6", 0},
    {"movzx r8d,[rdx+rcx]",         "440fb6040a", 0},
    {"cmp r8l,23",                  "4180f823", 0},
    {"je +92",                      "0f84", 'D'},
    {"mov [g_px],esi",              "8935", 0x140004008},
    {"mov [g_py],eax",              "8905", 0x14000400C},
    {"cmp r8l,2E",                  "4180f82e", 0},
    {"jne +92",                     "0f85", 'D'},
    {"add [g_score],0A",            "8305", 0x140004140},
    {"mov byte [rcx+rdx],20",       "c6041120", 0},
    {"dec [g_dots]",                "ff0d", 0x140004144},
    {"xor eax,eax",                 "31c0", 0},
    {"add rsp,28",                  "4883c428", 0},
    {"pop rdi",                     "5f", 0},
    {"pop rsi",                     "5e", 0},
    {"ret",                         "c3", 0},
};
constexpr size_t MOVEPLAYER_IMZA_SAYI = sizeof(MOVEPLAYER_IMZALARI) / sizeof(MOVEPLAYER_IMZALARI[0]);

// +2C / +92 dal hedeflerinin mutasyon gövdesindeki bilinen karşılıkları (doğrulanmış)
constexpr uint64_t DAL_HD_JA   = 0x14000636C;  // = add ecx,[g_px]
constexpr uint64_t DAL_HD_JENE = 0x14000642B;  // = xor eax,eax

// lea-eşdeğer ailesi: add rcx,rdx için derleyici/motor formları
const char* const LEA_ESDEGER[] = {"4801d1", "488d0c11", "488d0c91", "488d0c13", nullptr};

struct Eslesme {
    std::string etiket;
    uint64_t    adres = 0;   // bulunamadıysa 0
    std::string notlar;
};

struct JunkBlok {
    uint64_t    adres;
    std::string tur;        // "olu-yazmac" | "olu-bayrak" | "akis-jmp" | "diger"
    std::string metin;
};

struct MutasyonSonuc {
    std::vector<Eslesme> eslesmeler;
    std::vector<JunkBlok> junklar;
    uint32_t govde_rva0 = 0, govde_rva1 = 0;
    size_t bulunan = 0, toplam = 0;
    size_t dal_dogru = 0, rip_dogru = 0;
    bool birebir() const { return toplam > 0 && bulunan == toplam; }
};

// Korumalı dosyada mutasyon gövdesini (giris_va'dan ileriye) çözümle ve
// MOVEPLAYER_IMZALARI listesiyle birebir eşleştir. govde_uzunluk = tarama penceresi.
MutasyonSonuc mutasyon_coz(const PE& pe, Cozucu& c, uint64_t giris_va,
                           uint32_t govde_uzunluk = 0x560);

// Opak-koşul/jmp akışını takip ederek gerçek talimat dizisini üretir (junk dahil).
struct AkisSatiri { uint64_t adres; std::string mnemonik, op_str; uint8_t bayt[16]; uint8_t boy; bool gercekmis; };
std::vector<AkisSatiri> akis_izle(const PE& pe, Cozucu& c, uint64_t giris_va,
                                  uint32_t govde_uzunluk, size_t adim_siniri);

} // namespace tc
