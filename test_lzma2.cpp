#include "tc_pe.hpp"
#include "tc_unpack.hpp"
#include "tc_lzma.hpp"
#include <cstdio>
#include <fstream>
using namespace tc;
int main() {
    PE pe; std::string h;
    if (!pe_yukle("/home/z/my-project/work/v330/variants/Test_64_v324_ALL.vmp.exe", pe, h)) { printf("yukleme: %s\n", h.c_str()); return 1; }
    printf("bolum sayisi=%zu img=%zu\n", pe.bolumler.size(), pe.img.size());
    for (auto& b : pe.bolumler) printf("  %-8s VA=0x%X VSZ=0x%X RA=0x%X RSZ=0x%X\n", b.ad.c_str(), b.va, b.vsz, b.ra, b.rsz);
    UnpackTablo T = unpack_tablo_bul(pe);
    printf("tablo_off=0x%X props=0x%X giris=%zu\n", T.tablo_off, T.props_rva, T.girisler.size());
    for (auto& g : T.girisler) {
        uint32_t off = 0;
        for (const auto& b : pe.bolumler)
            if (g.src >= b.va && g.src < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz) && b.rsz)
                { off = b.ra + (g.src - b.va); break; }
        printf("  Src=0x%X → off=0x%X\n", g.src, off);
        if (!off) continue;
        uint32_t vsz = 0;
        for (const auto& b : pe.bolumler) if (g.dst == b.va) { vsz = b.vsz; break; }
        auto v = lzma1_coz(pe.img.data() + off, pe.img.size() - off, vsz);
        printf("    vsz=0x%X decode=%zu\n", vsz, v.size());
    }
    return 0;
}
