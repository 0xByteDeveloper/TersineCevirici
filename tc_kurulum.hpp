// tc_kurulum.hpp — test ortamı yardımcıları
#pragma once
#include <cstdio>
#include <cstdlib>
#include <string>

namespace tc {

// Komut satırından hex/dec adresi ayrıştırır ("0x..." ya da dec)
inline uint64_t adres_oku(const char* s, uint64_t varsayilan = 0) {
    if (!s || !*s) return varsayilan;
    return strtoull(s, nullptr, 0);
}

// Basit tablo çizgisi
inline void cizgi(char ch = '-', int n = 78) {
    for (int k = 0; k < n; ++k) putchar(ch);
    putchar('\n');
}

} // namespace tc
