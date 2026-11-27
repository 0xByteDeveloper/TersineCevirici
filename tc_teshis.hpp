// tc_teshis.hpp — V336: otomatik koruma-tipi teşhisi (TersineCevirici.md §1'in kodu).
// 0x14C0 ilk-bayt + bölüm-RSZ kalıbı + props imzası → koruma tipi + önerilen komut zinciri.
#pragma once
#include "tc_pe.hpp"
#include "tc_unpack.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace tc {

struct TeshisBulgusu {
    std::string koruma;        // "Mutasyon" / "Sanallaştırma" / "ultra/c100" / "ALL (Pack)" / ...
    std::string kanit;         // neden (ilk bayt, RSZ kalıbı, props adedi)
    std::string oneri;         // önerilen alt komut zinciri
};

struct TeshisRaporu {
    bool                        tamam = false;
    uint64_t                    giris_va = 0;   // taranan fonksiyon girişi (default 0x14C0)
    uint8_t                     ilk_bayt = 0;
    uint64_t                    jmp_hedefi = 0; // E9 ise çözülmüş hedef
    bool                        rsz0_kalibi = false;  // sanal bölüm kalıbı (pack)
    bool                        props_var = false;    // 5D 00 00 00 01 imzası
    std::vector<TeshisBulgusu>  bulgular;
};

// fonksiyon_va: korunan fonksiyonun RVA'sı (Test_64 ailesi için 0x14C0)
TeshisRaporu teshis_yap(const PE& pe, uint64_t fonksiyon_va);

// avtuzak için loader-akışı taraması (YÖN 1): unpack-tam'ın decode ettiği .FYP/vmp00
// loader bölgesini disasm edip [base+idx*scale-K] adaylarını arar.
// loader_veri: decode edilmiş bölüm içeriği (dosyadan değil bellek-uzayı VA'sı)
std::vector<std::string> av_tuzak_loader_tara(const std::vector<uint8_t>& loader_veri,
                                              uint64_t bolum_va);

} // namespace tc
