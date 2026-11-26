// tc_oracle.hpp — doğal referans: orijinal exe'de MovePlayer yürütmesi
#pragma once
#include "tc_pe.hpp"
#include "tc_vm.hpp"   // VmSonuc/VmOlay ortak yapısı
#include <string>

namespace tc {

constexpr uint64_t ORIJ_MOVEPLAYER = 0x1400014C0;

// Orijinal (korumasız) exe'de MovePlayer'ı yürütür: olay dizisi = doğal oracle.
// (v323_natif.py karşılığı: aynı kancalar, GIRIS yerine ORIJ_MOVEPLAYER,
//  durma adresi güvenli .text başlangıcı)
VmSonuc oracle_kos(const PE& pe, uint64_t yon, uint64_t adim_siniri = 400000);

// İki olay dizisini karşılaştırır (tur, rva, sıra, değer): birebir oran döner.
struct Karsilastirma {
    size_t vm_olay = 0, oracle_olay = 0;
    size_t eslesen = 0;
    bool birebir() const { return vm_olay > 0 && vm_olay == oracle_olay && eslesen == vm_olay; }
};
Karsilastirma olay_karsilastir(const VmSonuc& vm, const VmSonuc& oracle);

} // namespace tc
