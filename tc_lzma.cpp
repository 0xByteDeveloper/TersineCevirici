// tc_lzma.cpp — LZMA1 FORMAT_RAW decoder (liblzma raw API) — V335
#include "tc_lzma.hpp"
#include <lzma.h>
#include <cstring>

namespace tc {

std::vector<uint8_t> lzma1_coz(const uint8_t* giris, size_t giris_boyut,
                               size_t hedef_boyut) {
    // props 5D 00 00 00 01 → lc=3 lp=0 pb=2, dict 1<<24 (packer.cc:86)
    lzma_options_lzma opt;
    memset(&opt, 0, sizeof(opt));
    opt.dict_size = 1u << 24;
    opt.lc = 3; opt.lp = 0; opt.pb = 2;
    lzma_filter filtre[2];
    filtre[0].id = LZMA_FILTER_LZMA1;
    filtre[0].options = &opt;
    filtre[1].id = LZMA_VLI_UNKNOWN;
    filtre[1].options = nullptr;

    std::vector<uint8_t> cikis;
    size_t kapasite = hedef_boyut ? hedef_boyut + 4096 : giris_boyut * 20 + (1 << 16);
    cikis.resize(kapasite);

    size_t giris_pos = 0, cikis_pos = 0;
    lzma_ret r = lzma_raw_buffer_decode(
        filtre, nullptr,
        giris, &giris_pos, giris_boyut,
        cikis.data(), &cikis_pos, cikis.size());
    // LZMA_OK (0) veya LZMA_BUF_ERROR (küçük çıktı tamponu) kabul:
    // end-marker'lı akışta hedef_boyut dolunca BUF_ERROR normaldir.
    if (r != LZMA_OK && r != LZMA_BUF_ERROR && r != LZMA_NO_CHECK)
        return {};
    cikis.resize(cikis_pos);
    if (hedef_boyut && cikis_pos < hedef_boyut)
        return {}; // beklenen boyuta ulaşmadı — bozuk akış
    return cikis;
}

} // namespace tc
