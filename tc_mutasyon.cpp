// tc_mutasyon.cpp — devirt çekirdeği uygulaması (V324 birebir eşleme mantığının C++ karşılığı)
#include "tc_mutasyon.hpp"
#include <cstdio>
#include <cstring>
#include <set>

namespace tc {

static bool hex2bayt(const char* hex, uint8_t* cikti, size_t kapasite, size_t& boy) {
    boy = 0;
    size_t L = strlen(hex);
    if (L == 0 || L / 2 > kapasite) return false;
    for (size_t k = 0; k + 1 < L; k += 2) {
        auto h = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        int hi = h(hex[k]), lo = h(hex[k + 1]);
        if (hi < 0 || lo < 0) return false;
        cikti[boy++] = uint8_t((hi << 4) | lo);
    }
    return true;
}

std::vector<AkisSatiri> akis_izle(const PE& pe, Cozucu& c, uint64_t giris_va,
                                  uint32_t govde_uzunluk, size_t adim_siniri) {
    std::vector<AkisSatiri> akis;
    std::set<uint64_t> ziyaret;
    uint64_t a = giris_va;
    uint32_t son_rva = pe.va2rva(giris_va) + govde_uzunluk;
    while (akis.size() < adim_siniri) {
        uint32_t r = pe.va2rva(a);
        if (!r || r >= son_rva || pe.va2rva(a) >= pe.img.size()) break;
        if (ziyaret.count(a)) break;
        Insn i;
        if (!c.coz(a, pe.img.data() + r, i)) break;
        ziyaret.insert(a);
        AkisSatiri s;
        s.adres = i.adres; s.mnemonik = i.mnemonik; s.op_str = i.op_str;
        s.boy = i.boy; memcpy(s.bayt, i.bayt, i.boy); s.gercekmis = false;
        akis.push_back(std::move(s));
        if (i.mnemonik == "jmp" && i.rip_var) { a = i.rip_hedef; continue; }
        a += i.boy;
    }
    return akis;
}

MutasyonSonuc mutasyon_coz(const PE& pe, Cozucu& c, uint64_t giris_va,
                           uint32_t govde_uzunluk) {
    MutasyonSonuc S;
    uint32_t rva0 = pe.va2rva(giris_va);
    if (!rva0) return S;
    S.govde_rva0 = rva0;
    S.govde_rva1 = rva0 + govde_uzunluk;

    // 1) her hizadan çözümle (imza eşlemesi için)
    std::map<uint64_t, Insn> at;
    c.tum_hizalar(pe, rva0, S.govde_rva1, at);

    // 2) gerçek akış (junk sınıflandırması için)
    auto akis = akis_izle(pe, c, giris_va, govde_uzunluk, 300);

    S.toplam = MOVEPLAYER_IMZA_SAYI;
    std::set<uint64_t> kullanilan;   // aynı talimatın tekrar eşleşmesini engelle

    for (size_t k = 0; k < MOVEPLAYER_IMZA_SAYI; ++k) {
        const TalimatImza& t = MOVEPLAYER_IMZALARI[k];
        Eslesme e;
        e.etiket = t.etiket;
        if (t.hedef_va == 'D') {
            // dal: akışta jcc ara, hedefi bilinen karşılıklarla doğrula;
            // aynı dal talimatının (je/jne aynı hedef) tekrar eşleşmemesi için
            // kullanılmayan İLK jcc seçilir
            for (auto& s : akis) {
                if (s.mnemonik.size() > 0 && s.mnemonik[0] == 'j' && s.mnemonik != "jmp") {
                    if (kullanilan.count(s.adres)) continue;
                    // akış satırında hedef: yeniden çöz
                    Insn i2;
                    if (c.coz(s.adres, s.bayt, i2) && i2.rip_var) {
                        if ((strstr(t.etiket, "ja ") == t.etiket && i2.rip_hedef == DAL_HD_JA) ||
                            ((strstr(t.etiket, "je ") == t.etiket || strstr(t.etiket, "jne ") == t.etiket)
                             && i2.rip_hedef == DAL_HD_JENE)) {
                            e.adres = s.adres;
                            char buf[96];
                            snprintf(buf, sizeof buf, "-> 0x%llX", (unsigned long long)i2.rip_hedef);
                            e.notlar = buf;
                            S.dal_dogru++;
                            break;
                        }
                    }
                }
            }
        } else if (t.hedef_va == 'L') {
            // lea-eşdeğer ailesi
            for (int m = 0; LEA_ESDEGER[m]; ++m) {
                uint8_t d[8]; size_t db = 0;
                if (hex2bayt(LEA_ESDEGER[m], d, sizeof d, db)) {
                    uint32_t yer = c.ara(pe, rva0, S.govde_rva1, d, db);
                    if (yer && !kullanilan.count(pe.va(yer))) {
                        e.adres = pe.va(yer);
                        e.notlar = std::string("esdeger form: ") + LEA_ESDEGER[m];
                        break;
                    }
                }
            }
        } else {
            uint8_t d[16]; size_t db = 0;
            if (t.desen_hex[0] && hex2bayt(t.desen_hex, d, sizeof d, db)) {
                // gövdede tüm buluntuları tara; RIP-hedefi eşleşen (veya hedef önemsizse
                // önceki eşleşmeden İLERİDEki ilk kullanılmamış) yerini bul.
                // Artan sıra kuralı: orijinal listedeki talimatlar gövdede sıralıdır;
                // aday adresi önceki eşleşmenin adresinden küçükse atlanır.
                uint32_t aranan_rva = rva0;
                bool ileri_sira = S.eslesmeler.size() > 0 &&
                                  S.eslesmeler.back().adres > pe.base;
                uint64_t onceki = ileri_sira ? S.eslesmeler.back().adres : 0;
                while (true) {
                    uint32_t yer = c.ara(pe, aranan_rva, S.govde_rva1, d, db);
                    if (!yer) break;
                    aranan_rva = yer + 1;
                    uint64_t va = pe.va(yer);
                    if (kullanilan.count(va) || (onceki && va <= onceki)) continue;
                    bool uygun = true;
                    if (t.hedef_va != 0) {
                        uygun = false;
                        auto it = at.find(va);
                        if (it != at.end() && it->second.rip_var && it->second.rip_hedef == t.hedef_va)
                            uygun = true;
                    }
                    if (uygun) {
                        e.adres = va;
                        if (t.hedef_va) {
                            char buf[96];
                            snprintf(buf, sizeof buf, "RIP-hedef 0x%llX dogru",
                                     (unsigned long long)t.hedef_va);
                            e.notlar = buf;
                            S.rip_dogru++;
                        }
                        break;
                    }
                }
            }
        }
        if (e.adres) {
            kullanilan.insert(e.adres);
            S.bulunan++;
        }
        S.eslesmeler.push_back(std::move(e));
    }

    // 3) junk sınıflandırması: akışta eşleşmeyenler
    for (auto& s : akis) {
        if (kullanilan.count(s.adres)) continue;
        JunkBlok j;
        j.adres = s.adres;
        j.metin = s.mnemonik + " " + s.op_str;
        const char* o = s.op_str.c_str();
        bool olu_yazmac =
            strstr(o, "dil") || strstr(o, ", di") || strstr(o, "di,") ||
            strstr(o, "dx") || strstr(o, "r12w") || strstr(o, "r14b") ||
            strstr(o, "r15w") || strstr(o, "r13b") || strstr(o, "r10b") ||
            strstr(o, "bx")  || strstr(o, "sil");
        bool olu_bayrak = s.mnemonik == "clc" || s.mnemonik == "stc" ||
                          s.mnemonik == "cmc" || s.mnemonik == "cdq" ||
                          s.mnemonik.rfind("set", 0) == 0 ||
                          s.mnemonik == "sahf" || s.mnemonik == "lahf";
        bool akis_jmp = s.mnemonik == "jmp";
        if (akis_jmp) j.tur = "akis-jmp";
        else if (olu_yazmac) j.tur = "olu-yazmac";
        else if (olu_bayrak) j.tur = "olu-bayrak";
        else j.tur = "diger";
        S.junklar.push_back(std::move(j));
    }
    return S;
}

} // namespace tc
