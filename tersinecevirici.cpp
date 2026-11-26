// tersinecevirici.cpp — main: 4 alt komut (girisler | mutasyon | vmtrace | oracle)
#include "tc_pe.hpp"
#include "tc_disasm.hpp"
#include "tc_mutasyon.hpp"
#include "tc_vm.hpp"
#include "tc_oracle.hpp"
#include "tc_kurulum.hpp"
#include <cstdio>
#include <cstring>

using namespace tc;

static int cmd_girisler(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "kullanim: girisler <orijinal.exe> <korunmus1.exe> [korunmus2.exe ...]\n");
        return 2;
    }
    PE orij;
    std::string hata;
    if (!pe_yukle(argv[2], orij, hata)) { fprintf(stderr, "orijinal: %s\n", hata.c_str()); return 1; }
    printf("%-46s %-12s %s\n", "DOSYA", "0x14C0 JMP", "GOVDE-ORIJINALE-AYNI");
    for (int k = 3; k < argc; ++k) {
        PE pe;
        if (!pe_yukle(argv[k], pe, hata)) { printf("%-46s YUKLENEMEDI: %s\n", argv[k], hata.c_str()); continue; }
        uint64_t g = giris_coz(pe);
        bool ayni = pe.img.size() == orij.img.size() &&
                    pe.img.size() > 0x155B &&
                    memcmp(pe.img.data() + 0x14C0, orij.img.data() + 0x14C0, 0x155B - 0x14C0) == 0;
        printf("%-46s %-12s %s\n", argv[k], g ? "" : "(E9 yok)",
               g ? ([&]{ static char b[32]; snprintf(b, sizeof b, "0x%llX", (unsigned long long)g); return b; })() : "-",
               ayni ? "EVET" : "hayir");
    }
    return 0;
}

static int cmd_mutasyon(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "kullanim: mutasyon <korunmus.exe> [giris-va-hex]\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }
    uint64_t giris = argc > 3 ? adres_oku(argv[3]) : 0;
    if (!giris) {
        giris = giris_coz(pe);
        if (!giris) { fprintf(stderr, "0x14C0'da E9 jmp yok; giris-va verin\n"); return 1; }
    }
    Cozucu c;
    MutasyonSonuc S = mutasyon_coz(pe, c, giris);
    printf("MUTASYON GOVDESI 0x%llX (RVA 0x%X..0x%X)\n",
           (unsigned long long)giris, S.govde_rva0, S.govde_rva1);
    cizgi();
    for (auto& e : S.eslesmeler) {
        printf("  %-34s %s%s\n", e.etiket.c_str(),
               e.adres ? ([&]{ static char b[32]; snprintf(b, sizeof b, "0x%llX", (unsigned long long)e.adres); return b; })() : "BULUNAMADI",
               e.adres && !e.notlar.empty() ? ("  " + e.notlar).c_str() : "");
    }
    cizgi();
    size_t rip_toplam = 0;
    for (size_t k = 0; k < MOVEPLAYER_IMZA_SAYI; ++k) {
        uint64_t h = MOVEPLAYER_IMZALARI[k].hedef_va;
        if (h != 0 && h != 'D' && h != 'L') rip_toplam++;
    }
    printf("SONUC: %zu/%zu talimat | dal hedefi %zu/3 | RIP-hedef %zu/%zu | junk blok %zu\n",
           S.bulunan, S.toplam, S.dal_dogru, S.rip_dogru, rip_toplam, S.junklar.size());
    printf("JUNK DAGILIMI:\n");
    size_t oluyaz = 0, olubay = 0, akis = 0, diger = 0;
    for (auto& j : S.junklar) {
        if (j.tur == "olu-yazmac") oluyaz++;
        else if (j.tur == "olu-bayrak") olubay++;
        else if (j.tur == "akis-jmp") akis++;
        else diger++;
    }
    printf("  olu-yazmac %zu | olu-bayrak %zu | akis-jmp %zu | diger %zu\n", oluyaz, olubay, akis, diger);
    printf(S.birebir() ? "BIREBIR: EVET\n" : "BIREBIR: HAYIR\n");
    return S.birebir() ? 0 : 1;
}

static void olay_yaz(FILE* f, const VmSonuc& S, const char* etiket) {
    fprintf(f, "# %s: adim=%llu dispatch=%u donus=%s eax=%llu\n", etiket,
            (unsigned long long)S.toplam_adim, S.dispatch,
            S.temiz_donus ? "TEMIZ" : "HATALI", (unsigned long long)S.sonuc_eax);
    for (auto& o : S.olaylar) {
        if (o.tur == 'R') fprintf(f, "OKU  adim=%-6llu rva=0x%-6X boy=%u deger=%llu komut#%d\n",
                                  (unsigned long long)o.adim, uint32_t(o.rva), o.boy,
                                  (unsigned long long)o.deger, o.komut);
        else if (o.tur == 'W') fprintf(f, "YAZ  adim=%-6llu rva=0x%-6X boy=%u deger=%llu komut#%d\n",
                                       (unsigned long long)o.adim, uint32_t(o.rva), o.boy,
                                       (unsigned long long)o.deger, o.komut);
        else if (o.tur == 'T') fprintf(f, "TEXT adim=%-6llu va=0x%llX (WrapPos)\n",
                                       (unsigned long long)o.adim, (unsigned long long)o.adres);
    }
}

static int cmd_vmtrace(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "kullanim: vmtrace <korumali.exe> <orijinal.exe> [yon=4]\n");
        return 2;
    }
    PE pe, orij; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "korumali: %s\n", hata.c_str()); return 1; }
    if (!pe_yukle(argv[3], orij, hata)) { fprintf(stderr, "orijinal: %s\n", hata.c_str()); return 1; }
    uint64_t yon = argc > 4 ? adres_oku(argv[4], 4) : 4;
    uint64_t g = giris_coz(pe);
    printf("VM GIRISI: 0x%llX | yon=%llu\n", (unsigned long long)g, (unsigned long long)yon);
    VmSonuc vm = vm_kos(pe, yon);
    printf("VM: adim=%llu dispatch=%u donus=%s eax=%llu",
           (unsigned long long)vm.toplam_adim, vm.dispatch,
           vm.temiz_donus ? "TEMIZ" : "HATALI", (unsigned long long)vm.sonuc_eax);
    if (!vm.hata.empty()) printf(" (%s)", vm.hata.c_str());
    printf("\n");
    VmSonuc orc = oracle_kos(orij, yon);
    printf("ORACLE: adim=%llu donus=%s eax=%llu\n",
           (unsigned long long)orc.toplam_adim, orc.temiz_donus ? "TEMIZ" : "HATALI",
           (unsigned long long)orc.sonuc_eax);
    Karsilastirma K = olay_karsilastir(vm, orc);
    printf("KARSILASTIRMA: vm=%zu oracle=%zu eslesen=%zu → %s\n",
           K.vm_olay, K.oracle_olay, K.eslesen, K.birebir() ? "BIREBIR" : "kismi");
    FILE* f = fopen("vmtrace_cikti.txt", "w");
    if (f) { olay_yaz(f, vm, "VM"); olay_yaz(f, orc, "ORACLE"); fclose(f); printf("ayrinti: vmtrace_cikti.txt\n"); }
    return K.birebir() ? 0 : 1;
}

static int cmd_oracle(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "kullanim: oracle <orijinal.exe> [yon=4]\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }
    uint64_t yon = argc > 3 ? adres_oku(argv[3], 4) : 4;
    VmSonuc orc = oracle_kos(pe, yon);
    printf("ORACLE(yon=%llu): adim=%llu donus=%s eax=%llu olay=%zu\n",
           (unsigned long long)yon, (unsigned long long)orc.toplam_adim,
           orc.temiz_donus ? "TEMIZ" : "HATALI", (unsigned long long)orc.sonuc_eax,
           orc.olaylar.size());
    olay_yaz(stdout, orc, "ORACLE");
    return orc.temiz_donus ? 0 : 1;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("TersineCevirici — VMProtect 3.9.4 devirtualizer (V324 zinciri, C++)\n"
               "Alt komutlar:\n"
               "  girisler <orijinal.exe> <korunmus1.exe> [...]   0x14C0 jmp hedef envanteri\n"
               "  mutasyon <korunmus.exe> [giris-va]              birebir cikarim + junk raporu\n"
               "  vmtrace  <korumali.exe> <orijinal.exe> [yon]    VM iz + oracle karsilastirma\n"
               "  oracle  <orijinal.exe> [yon]                    dogal referans olay dizisi\n");
        return 0;
    }
    if (!strcmp(argv[1], "girisler"))  return cmd_girisler(argc, argv);
    if (!strcmp(argv[1], "mutasyon"))  return cmd_mutasyon(argc, argv);
    if (!strcmp(argv[1], "vmtrace"))   return cmd_vmtrace(argc, argv);
    if (!strcmp(argv[1], "oracle"))    return cmd_oracle(argc, argv);
    fprintf(stderr, "bilinmeyen alt komut: %s\n", argv[1]);
    return 2;
}
