// tc_teshis.cpp — V336: otomatik teşhis + loader-akışı AV-tuzak taraması
#include "tc_teshis.hpp"
#include "tc_disasm.hpp"
#include <cstdio>
#include <cstring>

namespace tc {

TeshisRaporu teshis_yap(const PE& pe, uint64_t fonksiyon_va) {
    TeshisRaporu r;
    r.giris_va = fonksiyon_va;
    r.tamam = true;

    // 1) Bölüm-RSZ kalıbı: >=4 bölüm RSZ=0 → pack işareti
    int sanal_sayi = 0, toplam = 0;
    for (const auto& b : pe.bolumler) {
        toplam++;
        if (b.rsz == 0) sanal_sayi++;
    }
    if (sanal_sayi >= 4) r.rsz0_kalibi = true;

    // 2) props imzası + PACKER_INFO (unpack_tablo_bul zaten tarar)
    UnpackTablo T = unpack_tablo_bul(pe);
    r.props_var = T.tablo_off != 0;

    // 3) Fonksiyon girişindeki ilk bayt (VA → HAM dosya ofseti — V335 dersi)
    uint64_t off = 0;
    bool bulundu = false;
    for (const auto& b : pe.bolumler) {
        if (fonksiyon_va >= b.va && fonksiyon_va < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz)) {
            if (b.rsz) { off = b.ra + (fonksiyon_va - b.va); bulundu = true; }
            break;
        }
    }

    char buf[512];
    if (r.rsz0_kalibi && r.props_var) {
        TeshisBulgusu b;
        b.koruma = "ALL (Pack)";
        snprintf(buf, sizeof buf, "%d/%d bolum RSZ=0 + props imzasi + PACKER_INFO@0x%X (%zu akis)",
                 sanal_sayi, toplam, T.tablo_off, T.girisler.size());
        b.kanit = buf;
        b.oneri = "unpack-tam <dosya> <orijinal>  (5 LZMA akisi + OEP 32/32 otomatik)";
        r.bulgular.push_back(b);
        if (bulundu && off + 8 <= pe.ham.size()) {
            r.ilk_bayt = pe.ham[off];
            if (pe.ham[off] == 0x00) {
                TeshisBulgusu b2;
                b2.koruma = "govde paket icinde";
                b2.kanit = "fonksiyon girisi 00'larla dolu (kod .cqM/.vmp00 akisinda)";
                b2.oneri = "unpack-tam ciktisindaki decoded .text uzerinde girisler/etiket";
                r.bulgular.push_back(b2);
            }
        }
        return r;
    }

    if (!bulundu || off + 5 > pe.ham.size()) {
        TeshisBulgusu b;
        b.koruma = "bilinmiyor";
        snprintf(buf, sizeof buf, "fonksiyon VA'si bolumlerde cozulemedi (off=%llu, ham=%zu)",
                 (unsigned long long)off, pe.ham.size());
        b.kanit = buf;
        b.oneri = "giris-VA'yi kontrol et (img/ham uzay karisigi mi? — V335 dersi)";
        r.bulgular.push_back(b);
        return r;
    }

    r.ilk_bayt = pe.ham[off];
    if (r.ilk_bayt == 0xE9) {
        int32_t rel;
        memcpy(&rel, &pe.ham[off + 1], 4);
        r.jmp_hedefi = fonksiyon_va + 5 + (int64_t)rel;
        TeshisBulgusu b;
        if (r.jmp_hedefi < 0x100000) {          // gövde-içi (~0x62EB gibi)
            b.koruma = "Mutasyon";
            snprintf(buf, sizeof buf, "E9 -> 0x%llX (govde-ici, ~0x14000xxxx bandi)",
                     (unsigned long long)r.jmp_hedefi);
            b.kanit = buf;
            b.oneri = "mutasyon <dosya>  (statik devirt: 42/42 + junk raporu)";
        } else if (r.jmp_hedefi >= 0x140000000 && r.jmp_hedefi < 0x141000000) {
            b.koruma = "Sanallastirma (VM)";
            snprintf(buf, sizeof buf, "E9 -> 0x%llX (uzak VM bolgesi)",
                     (unsigned long long)r.jmp_hedefi);
            b.kanit = buf;
            b.oneri = "vmtrace <dosya> <orijinal> [yon]  (oracle 12/12 olay dogrulamasi)";
        } else {
            b.koruma = "ic-kopru (ultra / c100)";
            snprintf(buf, sizeof buf, "E9 -> 0x%llX (kripto kopru; pushfq+anahtar turetme arar)",
                     (unsigned long long)r.jmp_hedefi);
            b.kanit = buf;
            b.oneri = "TersineCevirici.md §5 kopru recetesi (CF senaryolari + CC/F4 atlama)";
        }
        r.bulgular.push_back(b);
    } else if (r.ilk_bayt == 0x00) {
        TeshisBulgusu b;
        b.koruma = "govde bosaltilmis (pack/VM)";
        b.kanit = "ilk bayt 00 — govde ya pakette ya VM'de";
        b.oneri = "bolum RSZ + props kontrolu (yukarida) + unpack-tam";
        r.bulgular.push_back(b);
    } else {
        TeshisBulgusu b;
        b.koruma = "korumasiz / bilinmeyen";
        snprintf(buf, sizeof buf, "ilk bayt 0x%02X — 0x14C0 koruma imzasi degil", r.ilk_bayt);
        b.kanit = buf;
        b.oneri = "giris-VA veya dosyayi kontrol et";
        r.bulgular.push_back(b);
    }
    return r;
}

// ---- YON 1: decode edilmis loader akisinda AV-tuzak adaylari ----
// [base + idx*scale - K] deseni: her-hiza cozumle, memory operand negatif disp +
// index'li ise aday yaz. (V327 kanit deseni: movzx r9d,[rdx+r9*2-0xf187d1a])
std::vector<std::string> av_tuzak_loader_tara(const std::vector<uint8_t>& veri,
                                              uint64_t bolum_va) {
    std::vector<std::string> rapor;
    char buf[512];
    snprintf(buf, sizeof buf, "LOADER AKIS TARAMASI: %zu bayt @VA 0x%llX (YON-1: .FYP statik avtuzak)",
             veri.size(), (unsigned long long)bolum_va);
    rapor.push_back(buf);

    Cozucu c;
    Insn insn;
    int aday = 0;
    // loader basi ilk 64KB (dolgu cc'lerden sonra VM verisi gelir)
    size_t limit = veri.size() < 0x10000 ? veri.size() : 0x10000;
    for (size_t i = 0; i + 16 < limit; i++) {
        if (!c.coz(bolum_va + i, veri.data() + i, insn)) continue;
        const std::string m = insn.mnemonik + " " + insn.op_str;
        // negatif disp: "- 0x" deseni; index'li: kopseti icinde '+' (base+idx*scale)
        size_t p = m.find(" - 0x");
        if (p == std::string::npos) continue;
        size_t ka = m.find('[');
        bool idx_var = false;
        if (ka != std::string::npos && ka < p) {
            size_t kb = m.find(']', ka);
            if (kb != std::string::npos) {
                std::string ic = m.substr(ka + 1, kb - ka - 1);
                idx_var = ic.find('+') != std::string::npos;
            }
        }
        if (!idx_var) continue;
        aday++;
        snprintf(buf, sizeof buf, "  ADAY #%d @VA 0x%llX (akis+0x%zX): %s",
                 aday, (unsigned long long)(bolum_va + i), i, m.c_str());
        rapor.push_back(buf);
        if (aday >= 40) { rapor.push_back("  ... 40+ aday — ilk 64KB siniri"); break; }
    }
    if (!aday)
        rapor.push_back("  aday yok (desen: [base + idx*scale - K]) — "
                        "kalan akis kosu-ani VEH kizlaginda");
    return rapor;
}

} // namespace tc
