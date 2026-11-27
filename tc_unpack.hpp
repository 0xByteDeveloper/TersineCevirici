// tc_unpack.hpp — VMProtect ALL statik unpack arayüzü (V333, WORKLOG2 §55)
#pragma once
#include "tc_pe.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace tc {

struct PackerGiris { uint32_t src; uint32_t dst; };   // Src=akış RVA, Dst=bölüm RVA

struct UnpackTablo {
    uint32_t props_rva = 0;          // LZMA props RVA'sı (0x1C90C0 benzeri)
    uint32_t tablo_off = 0;          // PACKER_INFO tablosunun dosya ofseti (0x10DF93 benzeri)
    std::vector<PackerGiris> girisler;
};

struct ImportKayit {
    uint32_t    konum;    // kaydın dosya ofseti
    std::string ad;       // çözülmüş API/DLL adı
    uint32_t    v1;       // thunk link (dosyada VA)
    uint32_t    v2;       // Key (loader: IAT_yuvası = gerçek_adres - Key)
};

// Adım 2: dosyadaki tüm props imzaları (5D 00 00 00 01)
std::vector<uint32_t> unpack_props_adaylari(const PE& pe);

// Adım 3: [props_RVA][5] deseni → PACKER_INFO tablosu
UnpackTablo unpack_tablo_bul(const PE& pe);

// Adım 5: known-plaintext ile string key (0 dönerse bulunamadı)
// konum: bilinen DLL adının dosyadaki ofseti
uint32_t unpack_key_bul(const PE& pe, const std::string& bilinen_dll_adi, uint32_t& konum);

// Import tablosu taraması: [Name_RVA][V1][V2] 12-bayt kayıtlar
std::vector<ImportKayit> unpack_import_tara(const PE& pe, uint32_t key);

} // namespace tc
