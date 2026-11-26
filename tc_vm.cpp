// tc_vm.cpp — Unicorn yürütme uygulaması (v322_lifter + v323_tamiz kancalarının karşılığı)
#include "tc_vm.hpp"
#include <unicorn/unicorn.h>
#include <unicorn/x86.h>
#include <cstdio>
#include <cstring>

namespace tc {

uint64_t giris_coz(const PE& pe, uint32_t rva) {
    if (rva + 5 > pe.img.size()) return 0;
    if (pe.img[rva] != 0xE9) return 0;
    int32_t rel;
    memcpy(&rel, pe.img.data() + rva + 1, 4);
    return pe.va(rva) + 5 + rel;
}

namespace {

struct Durum {
    uint64_t adim = 0;
    uint64_t sinir = 400000;
    uint32_t dispatch = 0;
    VmSonuc* s = nullptr;
    const PE* pe = nullptr;
    bool durdur = false;
};

void kanal_kod(uc_engine* uc, uint64_t adres, uint32_t boy, void* ud) {
    Durum* d = static_cast<Durum*>(ud);
    if (d->durdur) return;
    if (d->adim >= d->sinir) { d->durdur = true; uc_emu_stop(uc); return; }
    uint8_t b[16];
    if (uc_mem_read(uc, adres, b, 2) != UC_ERR_OK) { d->durdur = true; uc_emu_stop(uc); return; }
    if (b[0] == 0xFF && b[1] == 0xE3) {   // jmp rbp = VM dispatch
        d->dispatch++;
        VmOlay o; o.tur = 'D'; o.adim = d->adim; o.adres = adres; o.komut = int(d->dispatch);
        d->s->olaylar.push_back(o);
    }
    if (VM_TEXT0 <= adres && adres < VM_TEXT1 && !(VM_GIRIS <= adres && adres < VM_GIRIS + 0x10)) {
        VmOlay o; o.tur = 'T'; o.adim = d->adim; o.adres = adres; o.komut = int(d->dispatch);
        d->s->olaylar.push_back(o);   // WrapPos gerçek .text koşusu
    }
    d->adim++;
}

void kanal_okuma(uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) {
    (void)uc; (void)tur; (void)deger;
    Durum* d = static_cast<Durum*>(ud);
    if (d->durdur) return;
    if ((VM_DATA0 <= adres && adres < VM_DATA1) || (VM_RDATA0 <= adres && adres < VM_RDATA1)) {
        VmOlay o; o.tur = 'R'; o.adim = d->adim; o.adres = adres; o.boy = uint32_t(boy);
        o.rva = adres - d->pe->base; o.komut = int(d->dispatch);
        uint8_t buf[8] = {0};
        if (boy <= 8 && uc_mem_read(uc, adres, buf, boy) == UC_ERR_OK) {
            uint64_t v = 0;
            memcpy(&v, buf, boy < 8 ? size_t(boy) : 8);
            o.deger = v;
        }
        d->s->olaylar.push_back(o);
    }
}

void kanal_yazma(uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) {
    (void)uc; (void)tur;
    Durum* d = static_cast<Durum*>(ud);
    if (d->durdur) return;
    if (VM_DATA0 <= adres && adres < VM_DATA1) {
        VmOlay o; o.tur = 'W'; o.adim = d->adim; o.adres = adres; o.boy = uint32_t(boy);
        o.deger = uint64_t(deger); o.rva = adres - d->pe->base; o.komut = int(d->dispatch);
        d->s->olaylar.push_back(o);
    }
}

bool kanal_eslenmemis(uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) {
    (void)tur; (void)boy; (void)deger; (void)ud;
    return uc_mem_map(uc, adres & ~0xFFFull, 0x1000, UC_PROT_ALL) == UC_ERR_OK;
}

} // namespace

VmSonuc vm_kos(const PE& pe, uint64_t yon, uint64_t adim_siniri) {
    VmSonuc S;
    uc_engine* uc = nullptr;
    if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
        S.hata = "unicorn acilamadi";
        return S;
    }
    uint32_t map_boy = (pe.boyut + 0xFFF) & ~0xFFFu;
    uc_mem_map(uc, pe.base, map_boy, UC_PROT_ALL);
    uc_mem_write(uc, pe.base, pe.img.data(), pe.img.size());
    uc_mem_map(uc, K_STAK, K_STAK_BOY, UC_PROT_ALL);
    uc_mem_map(uc, 0, 0x40000, UC_PROT_ALL);   // düşük VM-yığını (RBP=0 bölgesi)
    uint64_t rsp0 = K_STAK + K_STAK_BOY - 0x8000;
    uc_reg_write(uc, UC_X86_REG_RSP, &rsp0);
    uint64_t donus = VM_DONUS;
    uc_mem_write(uc, rsp0, &donus, 8);
    uint64_t R = K_STAK + 0x100000;
    const int yazar[] = {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RBP, UC_X86_REG_RSI,
                         UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10,
                         UC_X86_REG_R11, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
                         UC_X86_REG_R15};
    for (int r : yazar) uc_reg_write(uc, r, &R);
    uint64_t rcx = yon, rdx = 0x11;
    uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
    uc_reg_write(uc, UC_X86_REG_RDX, &rdx);

    Durum d;
    d.sinir = adim_siniri;
    d.s = &S;
    d.pe = &pe;
    uc_hook h1, h2, h3, h4;
    auto kod_kanal   = +[](uc_engine* uc, uint64_t adres, uint32_t boy, void* ud) { kanal_kod(uc, adres, boy, ud); };
    auto oku_kanal   = +[](uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) { kanal_okuma(uc, tur, adres, boy, deger, ud); };
    auto yaz_kanal   = +[](uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) { kanal_yazma(uc, tur, adres, boy, deger, ud); };
    auto harita_kanal= +[](uc_engine* uc, uc_mem_type tur, uint64_t adres, int32_t boy, int64_t deger, void* ud) -> bool { return kanal_eslenmemis(uc, tur, adres, boy, deger, ud); };
    uc_hook_add(uc, &h1, UC_HOOK_CODE, (void*)kod_kanal, &d, 1, ~0ull);
    uc_hook_add(uc, &h2, UC_HOOK_MEM_READ, (void*)oku_kanal, &d, 1, 0);
    uc_hook_add(uc, &h3, UC_HOOK_MEM_WRITE, (void*)yaz_kanal, &d, 1, 0);
    uc_hook_add(uc, &h4, UC_HOOK_MEM_UNMAPPED, (void*)harita_kanal, &d, 1, 0);

    uc_err err = uc_emu_start(uc, VM_GIRIS, VM_DONUS, 0, 0);
    uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    uint64_t eax = 0;
    uc_reg_read(uc, UC_X86_REG_EAX, &eax);
    S.toplam_adim = d.adim;
    S.dispatch = d.dispatch;
    S.durma_rip = rip;
    S.sonuc_eax = eax;
    S.temiz_donus = (err == UC_ERR_OK && rip == VM_DONUS);
    if (!S.temiz_donus)
        S.hata = "yurutme hata/donusb disi: err=" + std::to_string(int(err));
    uc_close(uc);
    return S;
}

} // namespace tc
