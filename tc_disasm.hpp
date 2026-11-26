// tc_disasm.hpp — Capstone sarmalayıcı: her-hiza decode + RIP-hedef çözümü
// (V324 v324_birebir.py talimatlar()/rip_hedef() karşılığı)
#pragma once
#include "tc_pe.hpp"
#include <capstone/capstone.h>
#include <map>
#include <memory>
#include <string>

namespace tc {

struct Insn {
    uint64_t    adres = 0;
    uint8_t     boy = 0;
    uint8_t     bayt[16] = {0};
    std::string mnemonik;
    std::string op_str;
    uint64_t    rip_hedef = 0;   // RIP-göreli hedef / jmp-call imm (yoksa 0)
    bool        rip_var = false; // rip_hedef geçerli mi
};

class Cozucu {
public:
    Cozucu();
    ~Cozucu();
    Cozucu(const Cozucu&) = delete;
    Cozucu& operator=(const Cozucu&) = delete;

    // tek talimat çöz; başarısızsa false (Insn.kod boyu 0)
    bool coz(uint64_t adres, const uint8_t* kod, Insn& i);

    // PE görüntüsünde [rva0, rva1) aralığını tüm olası hizalarda çözer;
    // adres → Insn (başarılı hizalar). V324 "her hizadan çözümle" birebir karşılığı.
    void tum_hizalar(const PE& pe, uint32_t rva0, uint32_t rva1,
                     std::map<uint64_t, Insn>& cikti);

    // bayt deseni arama: pe.img içinde rva0'dan itibaren ilk buluntu (yoksa 0)
    uint32_t ara(const PE& pe, uint32_t rva0, uint32_t rva1,
                 const uint8_t* desen, size_t desen_boy);

    csh tutamac() const { return h_; }

private:
    csh h_ = 0;
};

} // namespace tc
