// tc_unpack.cpp — VMProtect ALL (3.5.1-motor) STATİK unpack — V333 (WORKLOG2 §55)
//
// Yöntem (V332'de kanıtlandı, V333'te import+OEP eklendi):
//   1) PE bölümleri okunur (sanal bölümler RSZ=0 = paketli işaretçisi)
//   2) Dosyada LZMA props imzası (5D 00 00 00 01 = lc3/lp0/pb2, dict 1<<24) bulunur
//   3) [props_RVA][00000005] deseni aranır → PACKER_INFO tablosu
//   4) Tablodaki her [Src][Dst] çifti → LZMA akışı → bölüm geri yazılır
//   5) Import tablosu (cmDD zinciri) known-plaintext key ile çözülür (V333-b)
//
// LZMA decode harici yapılır (python-lzma / 7z); bu modül tabloyu çıkarır ve
// bölümleri geri inşa eder. Key araması: en uzun DLL adı biliniyorsa otomatik.
#include "tc_pe.hpp"
#include "tc_unpack.hpp"
#include <cstdio>
#include <cstring>

namespace tc {

static uint32_t r16(const uint8_t* p) { return p[0] | (p[1] << 8); }
static uint32_t r32(const uint8_t* p) { return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24); }

// RVA → dosya ofseti (bölüm tablosundan)
static uint32_t rva2off(const std::vector<Bolum>& b, uint32_t rva) {
    for (const auto& s : b)
        if (rva >= s.va && rva < s.va + (s.vsz > s.rsz ? s.vsz : s.rsz) && s.rsz)
            return s.ra + (rva - s.va);
    return 0;
}

// ---------- Adım 2: props imzası ----------
// VMProtect packer.cc: props her zaman level 9 + endMark + dict 1<<24 → 5D 00 00 00 01
std::vector<uint32_t> unpack_props_adaylari(const PE& pe) {
    std::vector<uint32_t> sonuc;
    const uint8_t imza[5] = { 0x5D, 0x00, 0x00, 0x00, 0x01 };
    const auto& img = pe.img;
    for (size_t i = 0; i + 5 <= img.size(); i++)
        if (!memcmp(img.data() + i, imza, 5))
            sonuc.push_back(uint32_t(i));
    return sonuc;
}

// ---------- Adım 3: PACKER_INFO tablosu ----------
// Tablo = cmDD komut zinciri: [props_RVA][5] [akis1_RVA][Dst1] ...
// (intel.cc:23123; V332'de 0x10DF93'te bulundu)
UnpackTablo unpack_tablo_bul(const PE& pe) {
    UnpackTablo t;
    auto adaylar = unpack_props_adaylari(pe);
    // pe.img zaten RVA-uzayı: props_off = props RVA'sı doğrudan
    for (uint32_t props_rva : adaylar) {
        uint8_t desen[8];
        memcpy(desen, &props_rva, 4);
        uint32_t bes = 5;
        memcpy(desen + 4, &bes, 4);
        for (size_t i = 0; i + 8 <= pe.img.size(); i++) {
            if (!memcmp(pe.img.data() + i, desen, 8)) {
                t.props_rva = props_rva;
                t.tablo_off = uint32_t(i);
                size_t q = i + 8;
                while (q + 8 <= pe.img.size()) {
                    uint32_t src = r32(pe.img.data() + q);
                    uint32_t dst = r32(pe.img.data() + q + 4);
                    if (src == 0 || dst == 0) break;
                    bool bilinen = false;
                    for (const auto& b : pe.bolumler)
                        if (dst == b.va && b.rsz == 0) { bilinen = true; break; }
                    if (!bilinen) break;
                    t.girisler.push_back({ src, dst });
                    q += 8;
                }
                if (t.girisler.size() >= 1)
                    return t;
                t.girisler.clear();
            }
        }
    }
    return t;
}

// ---------- Adım 5: import string şifresi (known-plaintext) ----------
// EncryptString (intel.cc:22386): enc[i] = pt[i] ^ uint8(rotl32(key,i) + i)
// key = rand32() dosya başına sabit. En uzun DLL adı üzerinden türetilir.
static uint32_t rotl32(uint32_t v, int n) { n &= 31; return (v << n) | (v >> (32 - n)); }

static bool string_coz(const std::vector<uint8_t>& img, uint32_t off, uint32_t key,
                       std::string& cikti) {
    cikti.clear();
    for (size_t i = 0; i < 260 && off + i < img.size(); i++) {
        uint8_t c = img[off + i] ^ uint8_t(rotl32(key, int(i)) + uint32_t(i));
        if (!c) return cikti.size() >= 3;
        if (c < 32 || c >= 127) return false;
        cikti.push_back(char(c));
    }
    return false;
}

// Known-plaintext: i=0,8,16,24 baytları key'in 4 dilimini verir (rotl kaydırmaları):
//   k&0xFF, k>>24, k>>16&0xFF, k>>8&0xFF (her biri +i carry'siz düşük bayt)
uint32_t unpack_key_bul(const PE& pe, const std::string& bilinen_dll_adi,
                        uint32_t& konum) {
    const auto& img = pe.img;
    const std::string& pt = bilinen_dll_adi;
    if (pt.size() < 25) return 0;   // en az 25 bayt: 4 stratejik konum + doğrulama
    for (size_t k = 0; k + pt.size() <= img.size(); k++) {
        uint32_t b0  = img[k]        ^ uint8_t(pt[0]);
        uint32_t b8  = (img[k + 8]  ^ uint8_t(pt[8]))  - 8;
        uint32_t b16 = (img[k + 16] ^ uint8_t(pt[16])) - 16;
        uint32_t b24 = (img[k + 24] ^ uint8_t(pt[24])) - 24;
        uint32_t key = (b0 & 0xFF) | ((b24 & 0xFF) << 8) | ((b16 & 0xFF) << 16) | ((b8 & 0xFF) << 24);
        std::string test;
        if (string_coz(img, uint32_t(k), key, test) && test == pt) {
            konum = uint32_t(k);
            return key;
        }
    }
    return 0;
}

// Import tablosu taraması: [Name_RVA][V1][V2] 12-bayt kayıtlar (V333-b: 148 kayıt, 0xE3D7D)
std::vector<ImportKayit> unpack_import_tara(const PE& pe, uint32_t key) {
    std::vector<ImportKayit> sonuc;
    const auto& img = pe.img;
    size_t q = 0;
    while (q + 12 <= img.size()) {
        uint32_t nm = r32(img.data() + q);
        if (nm && nm < img.size()) {
            std::string ad;
            if (string_coz(img, nm, key, ad)) {
                ImportKayit k;
                k.konum = uint32_t(q);
                k.ad = ad;
                k.v1 = r32(img.data() + q + 4);
                k.v2 = r32(img.data() + q + 8);
                sonuc.push_back(k);
                q += 12;
                continue;
            }
        }
        q++;
    }
    return sonuc;
}

} // namespace tc
