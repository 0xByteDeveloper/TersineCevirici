// tc_disasm.cpp — Capstone sarmalayıcı uygulaması
#include "tc_disasm.hpp"
#include <cstring>

namespace tc {

Cozucu::Cozucu() {
    cs_open(CS_ARCH_X86, CS_MODE_64, &h_);
    cs_option(h_, CS_OPT_DETAIL, CS_OPT_ON);
}

Cozucu::~Cozucu() { if (h_) cs_close(&h_); }

bool Cozucu::coz(uint64_t adres, const uint8_t* kod, Insn& i) {
    cs_insn* ci = nullptr;
    size_t n = cs_disasm(h_, kod, 16, adres, 1, &ci);
    if (n != 1) { if (ci) cs_free(ci, n); return false; }
    i.adres = ci->address;
    i.boy = uint8_t(ci->size);
    if (i.boy > 16) i.boy = 16;
    memcpy(i.bayt, ci->bytes, i.boy);
    i.mnemonik = ci->mnemonic;
    i.op_str = ci->op_str;
    i.rip_hedef = 0;
    i.rip_var = false;
    // RIP-göreli hedef + jmp/call imm çözümü (Python rip_hedef karşılığı)
    cs_detail* d = ci->detail;
    bool jmp_call = (ci->id == X86_INS_JMP || ci->id == X86_INS_CALL);
    for (uint8_t k = 0; d && k < d->groups_count; ++k) {
        if (d->groups[k] == X86_GRP_JUMP || d->groups[k] == X86_GRP_CALL)
            jmp_call = true;
    }
    if (d) {
        for (size_t k = 0; k < d->x86.op_count; ++k) {
            const cs_x86_op& op = d->x86.operands[k];
            if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP) {
                i.rip_hedef = ci->address + ci->size + op.mem.disp;
                i.rip_var = true;
            } else if (op.type == X86_OP_IMM && jmp_call) {
                i.rip_hedef = uint64_t(op.imm);
                i.rip_var = true;
            }
        }
    }
    cs_free(ci, 1);
    return true;
}

void Cozucu::tum_hizalar(const PE& pe, uint32_t rva0, uint32_t rva1,
                         std::map<uint64_t, Insn>& cikti) {
    cikti.clear();
    for (uint32_t r = rva0; r + 1 < rva1 && r < pe.img.size(); ++r) {
        Insn i;
        if (coz(pe.va(r), pe.img.data() + r, i)) cikti.emplace(pe.va(r), std::move(i));
    }
}

uint32_t Cozucu::ara(const PE& pe, uint32_t rva0, uint32_t rva1,
                     const uint8_t* desen, size_t desen_boy) {
    if (rva1 > pe.img.size()) rva1 = uint32_t(pe.img.size());
    if (rva0 >= rva1 || desen_boy == 0 || rva1 - rva0 < desen_boy) return 0;
    const uint8_t* bas = pe.img.data() + rva0;
    for (uint32_t k = 0; k + desen_boy <= rva1 - rva0; ++k) {
        if (memcmp(bas + k, desen, desen_boy) == 0) return rva0 + k;
    }
    return 0;
}

} // namespace tc
