#include <lzma.h>
#include <cstdio>
#include <fstream>
#include <vector>
#include <cstring>
int main() {
    std::ifstream f("/home/z/my-project/work/v330/variants/Test_64_v324_ALL.vmp.exe", std::ios::binary);
    std::vector<uint8_t> d((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t off = 0x10EB2D;
    lzma_options_lzma opt; memset(&opt, 0, sizeof(opt));
    opt.dict_size = 1u << 24; opt.lc = 3; opt.lp = 0; opt.pb = 2;
    lzma_filter fil[2]; fil[0].id = LZMA_FILTER_LZMA1; fil[0].options = &opt;
    fil[1].id = LZMA_VLI_UNKNOWN; fil[1].options = nullptr;
    std::vector<uint8_t> out(0x2000);
    size_t ip = 0, op = 0;
    lzma_ret r = lzma_raw_buffer_decode(fil, nullptr, d.data()+off, &ip, d.size()-off, out.data(), &op, out.size());
    printf("ret=%d ip=%zu op=%zu\n", (int)r, ip, op);
    if (op) printf("ilk8: %02x %02x %02x %02x\n", out[0],out[1],out[2],out[3]);
    return 0;
}
