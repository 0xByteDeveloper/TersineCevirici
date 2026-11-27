#include "tc_lzma.hpp"
#include <cstdio>
#include <vector>
#include <fstream>
int main() {
    std::ifstream f("/home/z/my-project/work/v330/variants/Test_64_v324_ALL.vmp.exe", std::ios::binary);
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t off = 0x10EB2D;
    auto v = tc::lzma1_coz(d.data() + off, d.size() - off, 0x1686);
    printf("decode: %zu bayt\n", v.size());
    if (!v.empty()) printf("ilk 16: %s\n", [&]{ std::string s; char b[4]; for (int i=0;i<16;i++){snprintf(b,4,"%02x ",v[i]); s+=b;} return s; }().c_str());
    return 0;
}
