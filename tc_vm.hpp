// tc_vm.hpp — Unicorn yürütme: dispatch/olay kanalları + komut-atıf (V323/V324 karşılığı)
#pragma once
#include "tc_pe.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace tc {

// V323 sabitlerinin birebir karşılığı (VA'lar 33 bit — uint64_t şart, uint32_t'e kesilir!)
constexpr uint64_t VM_GIRIS   = 0x1400014C0;  // MovePlayer mutasyona uğramış giriş
constexpr uint64_t VM_DONUS   = 0x140001689;  // çağıranın dönüş adresi (tick)
constexpr uint64_t VM_DATA0   = 0x140004000, VM_DATA1 = 0x1400041D0;
constexpr uint64_t VM_RDATA0  = 0x140003000, VM_RDATA1 = 0x140003E8C;
constexpr uint64_t VM_TEXT0   = 0x140001000, VM_TEXT1 = 0x140002686;
constexpr uint64_t K_STAK     = 0x00007FFF00000000ull;
constexpr uint64_t K_STAK_BOY = 0x200000;

struct VmOlay {
    char        tur = '?';    // 'R' oku | 'W' yaz | 'T' .text koşusu | 'D' dispatch
    uint64_t    adim = 0;
    uint64_t    adres = 0;    // erişim VA'si (olay için talimat VA'si)
    uint32_t    boy = 0;
    uint64_t    deger = 0;
    uint64_t    rva = 0;      // DATA olayları için RVA
    int         komut = 0;    // dispatch-atıf (0 = giriş öncesi)
};

struct VmSonuc {
    uint64_t toplam_adim = 0;
    uint32_t dispatch = 0;
    std::vector<VmOlay> olaylar;
    bool temiz_donus = false; // DONUS adresinde durdu mu
    uint64_t durma_rip = 0;
    std::string hata;
    uint64_t sonuc_eax = 0;   // MovePlayer dönüş değeri
};

// Sanallaştırılmış MovePlayer'ı yürütür (yon=1..5). Kancalar: her kod adımı sayılır,
// jmp rbp = dispatch, DATA/RDATA okuma + DATA yazma olayları, .text koşusu WrapPos.
VmSonuc vm_kos(const PE& pe, uint64_t yon, uint64_t adim_siniri = 400000);

// 0x14C0'daki jmp rel32 → koruma girişi VA (E9 değilse 0)
uint64_t giris_coz(const PE& pe, uint32_t rva = 0x14C0);

} // namespace tc
