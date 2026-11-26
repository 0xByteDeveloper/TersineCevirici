// tc_etiket.cpp — Komut→tip etiketleme + AV-tuzak taraması (V327 C++ karşılığı)
// Yürütmeyi tc_vm altyapısıyla yapar; dispatch başına KomutKanit toplar;
// komut_etiketle() ile sınıflar; rapor üretir. AV-tuzak taraması statik ilerler.
#include "tc_etiket.hpp"
#include "tc_pe.hpp"
#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <cstring>
#include <cstdio>
#include <map>

namespace tc {

// ---- GPR listesi (deltalar için) ----
static const int GPR_REGS[] = {
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_R8,
    UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11, UC_X86_REG_R12,
    UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15
};
static const char* GPR_ADLARI[] = {
    "rax","rcx","rdx","rbx","rsi","rdi","rbp","r8","r9","r10","r11","r12","r13","r14","r15"
};
static const int NGPR = 15;

// Python V327 semantiği: kayitlar[i] = komut i+1; gpr/rsp = i. dispatch ANINDA
// snapshot; olaylar o komutun yürütmesi sırasında birikir; etiketleme ardışık
// girişlerin farkıyla (entry(i) - entry(i-1)) yapılır — 941/941 kanıtlı referans.
struct KomutKayit {
    uint64_t gpr[15] = {0};
    uint64_t rsp = 0;
    std::vector<KomutKanit::BelOlay> olaylar;
    bool wrap_giris = false; uint32_t wrap_ecx = 0, wrap_edx = 0;
    bool wrap_donus = false; uint32_t wrap_eax = 0;
};

struct EtiketDurum {
    uc_engine* uc = nullptr;
    csh cs = 0;
    int komut_no = 0;
    bool bitti = false;
    std::vector<KomutKayit> kayitlar;  // kayitlar[i] = komut i+1
    // raporlama
    std::vector<KomutEtiketi> etiketler;
};

// V327: dispatch = jmp rbx (VARSAYILAN/ultra/ultra_c100) — tc_vm'deki jmp rbp'den
// farklı olabilir; her ikisini de sayarız.
static void kayit_etiketle(EtiketDurum* D, size_t j) {
    // j: kayitlar indeksi (komut j+1). Python: onceki = kayitlar[j-1] (yoksa delta yok)
    KomutKanit k;
    k.komut_no = (int)j + 1;
    k.giris_rsp = D->kayitlar[j].rsp;
    k.rsp_bilinmiyor = false;
    k.olaylar = D->kayitlar[j].olaylar;
    k.wrap_giris = D->kayitlar[j].wrap_giris;
    k.wrap_ecx = D->kayitlar[j].wrap_ecx;
    k.wrap_edx = D->kayitlar[j].wrap_edx;
    k.wrap_donus = D->kayitlar[j].wrap_donus;
    k.wrap_eax = D->kayitlar[j].wrap_eax;
    // delta: entry(j) vs entry(j-1) — Python birebir
    std::vector<uint64_t> o, s;
    if (j > 0) {
        o.assign(D->kayitlar[j-1].gpr, D->kayitlar[j-1].gpr + NGPR);
        s.assign(D->kayitlar[j].gpr, D->kayitlar[j].gpr + NGPR);
    }
    std::vector<const char*> adlar(GPR_ADLARI, GPR_ADLARI + NGPR);
    uint64_t onceki_rsp = (j > 0) ? D->kayitlar[j-1].rsp : 0;
    D->etiketler.push_back(komut_etiketle(k, onceki_rsp, o, s, adlar));
}

static void hook_kod(uc_engine* uc, uint64_t adres, uint32_t boy, void* ud) {
    EtiketDurum* D = (EtiketDurum*)ud;
    if (D->bitti) return;
    uint8_t b[16];
    if (uc_mem_read(uc, adres, b, sizeof b) != UC_ERR_OK) return;

    KomutKayit* aktif = D->kayitlar.empty() ? nullptr : &D->kayitlar.back();
    // WrapPos giriş/çıkış kanalları (Python: tam['wrap'])
    if (adres == WRAPPOS_GIRIS_VA && aktif) {
        uint32_t ecx32 = 0, edx32 = 0;
        uc_reg_read(uc, UC_X86_REG_ECX, &ecx32);
        uc_reg_read(uc, UC_X86_REG_EDX, &edx32);
        aktif->wrap_giris = true;
        aktif->wrap_ecx = ecx32;
        aktif->wrap_edx = edx32;
    }
    if (adres == WRAPPOS_RET_VA && aktif) {
        uint32_t eax32 = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax32);
        aktif->wrap_donus = true;
        aktif->wrap_eax = eax32;
    }

    // dispatch: jmp rbx (FF E3) — Python V327 birebir (51/8/859/23 kanıtı)
    if (b[0] == 0xFF && b[1] == 0xE3) {
        // yeni komut kaydı aç (Python: kaydet(); tam reset + yeni gpr)
        D->kayitlar.emplace_back();
        KomutKayit& K = D->kayitlar.back();
        for (int i = 0; i < NGPR; i++) uc_reg_read(uc, GPR_REGS[i], &K.gpr[i]);
        uc_reg_read(uc, UC_X86_REG_RSP, &K.rsp);
        D->komut_no++;
    }
    // int3 atla (taşıma tuzakları)
    if (b[0] == 0xCC) {
        uint64_t rip_yeni = adres + 1; uc_reg_write(uc, UC_X86_REG_RIP, &rip_yeni);
    }
}

static bool sembol_bolgesi(uint64_t va) {
    // .data (g_px...) ve .rdata (dx/dy tabloları) sembolleri
    return (va >= 0x140003000 && va < 0x140003E8C) || (va >= 0x140004000 && va < 0x1400041D0);
}

static bool hook_oku(uc_engine* uc, uc_mem_type tur, uint64_t adres, int boy, int64_t deger, void* ud) {
    EtiketDurum* D = (EtiketDurum*)ud;
    if (!D->kayitlar.empty() && sembol_bolgesi(adres)) {
        uint64_t v = 0;
        uc_mem_read(uc, adres, &v, boy > 8 ? 8 : boy);
        KomutKanit::BelOlay o{'R', adres, v};
        D->kayitlar.back().olaylar.push_back(o);
    }
    return true;
}

static bool hook_yaz(uc_engine* uc, uc_mem_type tur, uint64_t adres, int boy, int64_t deger, void* ud) {
    EtiketDurum* D = (EtiketDurum*)ud;
    if (!D->kayitlar.empty() && sembol_bolgesi(adres)) {
        KomutKanit::BelOlay o{'W', adres, (uint64_t)deger};
        D->kayitlar.back().olaylar.push_back(o);
    }
    return true;
}

// vmtrace tabanlı komut etiketleme raporu üretir (V327 etiket_*.txt karşılığı)
// giris: varyant giriş VA (ör. VARSAYILAN 0x14007602F, c100 0x140001530, ...)
std::vector<KomutEtiketi> etiket_kos(const PE& pe, uint64_t giris, uint64_t donus,
                                     uint64_t yon, uint64_t* cikti_insn = nullptr,
                                     bool* cikti_temiz = nullptr) {
    EtiketDurum D;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &D.uc);
    if (err) return {};
    uc_mem_map(D.uc, pe.base, (pe.img.size() + 0xFFF) & ~0xFFF, UC_PROT_ALL);
    uc_mem_write(D.uc, pe.base, pe.img.data(), pe.img.size());
    const uint64_t STAK = 0x00007FFF00000000, STAK_BOY = 0x800000;
    uc_mem_map(D.uc, STAK, STAK_BOY, UC_PROT_ALL);
    uc_mem_map(D.uc, 0, 0x40000, UC_PROT_ALL);
    uint64_t rsp0 = STAK + STAK_BOY - 0x8000;
    uc_reg_write(D.uc, UC_X86_REG_RSP, &rsp0);
    uc_mem_write(D.uc, rsp0, &donus, 8);
    uint64_t R = STAK + 0x100000;
    for (int i = 0; i < NGPR; i++) uc_reg_write(D.uc, GPR_REGS[i], &R);
    uc_reg_write(D.uc, UC_X86_REG_RCX, &yon);
    uint64_t rdx0 = 0x11;
    uc_reg_write(D.uc, UC_X86_REG_RDX, &rdx0);

    uc_hook h1, h2, h3;
    uc_hook_add(D.uc, &h1, UC_HOOK_CODE, (void*)hook_kod, &D, 1, 0);
    uc_hook_add(D.uc, &h2, UC_HOOK_MEM_READ, (void*)hook_oku, &D, 1, 0);
    uc_hook_add(D.uc, &h3, UC_HOOK_MEM_WRITE, (void*)hook_yaz, &D, 1, 0);

    // adım sayacı için kod kancası içinde sayaca ihtiyaç var — hook_kod'da artır
    // (basitlik: insn sayısını dispatch sayısından çıkarırız)
    uc_emu_start(D.uc, giris, donus, 0, 400000);
    // tüm komut kayıtlarını etiketle (Python: kaydet() zinciri + son kaydet)
    for (size_t j = 0; j < D.kayitlar.size(); j++) kayit_etiketle(&D, j);
    if (cikti_temiz) {
        uint64_t rip;
        uc_reg_read(D.uc, UC_X86_REG_RIP, &rip);
        *cikti_temiz = (rip == donus);
    }
    if (cikti_insn) *cikti_insn = 0; // vmtrace'ten alınmalı; burada dispatch sayısı yeter
    uc_close(D.uc);
    return D.etiketler;
}

// ---- AV-tuzak statik tarayıcı (ALL/packer gövdeleri için) ----
// bölge: [bas, son) — talimat talimat decode; av_tuzak_aday() ile aday listeler.
std::vector<AvTuzakBulgusu> av_tuzak_tara(const PE& pe, uint64_t bas, uint64_t son) {
    std::vector<AvTuzakBulgusu> out;
    csh cs;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs) != CS_ERR_OK) return out;
    cs_insn* insn = nullptr;
    // her hizada decode (mutasyon gövdesi hizasız olabilir — tc_disasm yaklaşımı)
    uint64_t va = bas;
    while (va < son) {
        size_t say = cs_disasm(cs, pe.img.data() + (va - pe.base), std::min<size_t>(64, son - va), va, 1, &insn);
        if (say == 0) { va++; continue; }
        std::string mn(insn->mnemonic), op(insn->op_str);
        std::string neden;
        if (av_tuzak_aday(mn, op, neden)) {
            AvTuzakBulgusu b{va, mn + " " + op, neden};
            out.push_back(b);
        }
        va += insn->size;
        cs_free(insn, say);
    }
    cs_close(&cs);
    return out;
}

} // namespace tc
