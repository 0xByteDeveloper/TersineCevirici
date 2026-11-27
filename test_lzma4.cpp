#include "tc_pe.hpp"
#include "tc_lzma.hpp"
#include <cstdio>
#include <fstream>
using namespace tc;
int main() {
    PE pe; std::string h;
    pe_yukle("/home/z/my-project/work/v330/variants/Test_64_v324_ALL.vmp.exe", pe, h);
    printf("img boyut=%zu, img[0x10EB2D..+8]=", pe.img.size());
    for (int i = 0; i < 8; i++) printf("%02x ", pe.img[0x10EB2D + i]);
    printf("\n");
    auto v = lzma1_coz(pe.img.data() + 0x10EB2D, pe.img.size() - 0x10EB2D, 0x1686);
    printf("lzma1_coz: %zu\n", v.size());
    // şimdi aynı veriyi ham dosyadan al
    std::ifstream f("/home/z/my-project/work/v330/variants/Test_64_v324_ALL.vmp.exe", std::ios::binary);
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    printf("dosya[0x10EB2D..+8]=");
    for (int i = 0; i < 8; i++) printf("%02x ", d[0x10EB2D + i]);
    printf("\n");
    auto v2 = lzma1_coz(d.data() + 0x10EB2D, d.size() - 0x10EB2D, 0x1686);
    printf("lzma1_coz (dosya): %zu\n", v2.size());
    return 0;
}
