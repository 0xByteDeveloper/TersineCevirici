// tc_pe.cpp — PE64 yükleyici uygulaması (V322 pe_yukle birebir karşılığı)
#include "tc_pe.hpp"
#include <cstdio>
#include <cstring>

namespace tc {

static uint16_t rd16(const uint8_t* p) { uint16_t v; memcpy(&v, p, 2); return v; }
static uint32_t rd32(const uint8_t* p) { uint32_t v; memcpy(&v, p, 4); return v; }
static uint64_t rd64(const uint8_t* p) { uint64_t v; memcpy(&v, p, 8); return v; }

bool pe_yukle(const std::string& yol, PE& pe, std::string& hata) {
    FILE* f = fopen(yol.c_str(), "rb");
    if (!f) { hata = "dosya acilamadi: " + yol; return false; }
    std::vector<uint8_t> d;
    uint8_t buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + n);
    fclose(f);
    if (d.size() < 0x40 || rd16(d.data()) != 0x5A4D) { hata = "MZ imzasi yok"; return false; }
    uint32_t e = rd32(d.data() + 0x3C);
    if (e + 4 > d.size() || rd32(d.data() + e) != 0x4550) { hata = "PE imzasi yok"; return false; }
    if (e + 24 + 88 > d.size()) { hata = "PE basligi eksik"; return false; }
    uint32_t opt = e + 24;
    uint16_t makine = rd16(d.data() + e + 4);
    if (makine != 0x8664) { hata = "PE32+ (x64) degil"; return false; }
    pe.base = rd64(d.data() + opt + 24);
    uint16_t nsec = rd16(d.data() + e + 6);
    uint16_t optsz = rd16(d.data() + e + 20);
    uint32_t sec0 = opt + optsz;
    pe.boyut = rd32(d.data() + opt + 56);
    pe.img.assign(pe.boyut, 0);
    memcpy(pe.img.data(), d.data(), d.size() < 0x1000 ? d.size() : 0x1000);
    pe.bolumler.clear();
    for (uint16_t i = 0; i < nsec; ++i) {
        uint32_t s = sec0 + i * 40;
        if (s + 40 > d.size()) break;
        Bolum b;
        b.ad.assign(reinterpret_cast<const char*>(d.data() + s),
                    strnlen(reinterpret_cast<const char*>(d.data() + s), 8));
        b.vsz = rd32(d.data() + s + 8);
        b.va  = rd32(d.data() + s + 12);
        b.rsz = rd32(d.data() + s + 16);
        b.ra  = rd32(d.data() + s + 20);
        uint32_t kopya = b.rsz;
        if (b.ra + kopya > d.size()) kopya = uint32_t(d.size() > b.ra ? d.size() - b.ra : 0);
        if (b.va + kopya > pe.img.size()) kopya = uint32_t(pe.img.size() - b.va);
        if (kopya) memcpy(pe.img.data() + b.va, d.data() + b.ra, kopya);
        pe.bolumler.push_back(b);
    }
    return true;
}

} // namespace tc
