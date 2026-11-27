// tersinecevirici.cpp — main: 6 alt komut (girisler | mutasyon | vmtrace | oracle | etiket | avtuzak)
#include "tc_pe.hpp"
#include "tc_disasm.hpp"
#include "tc_mutasyon.hpp"
#include "tc_vm.hpp"
#include "tc_oracle.hpp"
#include "tc_etiket.hpp"
#include "tc_unpack.hpp"
#include <fstream>
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

// ---- V327: komut→tip etiketleme (941/941 karşılığı) ----
static int cmd_etiket(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "kullanim: etiket <korumali.exe> <giris-va-hex> [yon=2]\n"
                        "  ornek: etiket Test_64_moveplayer_virtualization.vmp.exe 14007602F\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }
    uint64_t giris = adres_oku(argv[3]);
    if (!giris) { fprintf(stderr, "giris-va gecersiz\n"); return 1; }
    uint64_t yon = argc > 4 ? adres_oku(argv[4], 2) : 2;
    bool temiz = false;
    uint64_t insn = 0;
    std::vector<KomutEtiketi> E = etiket_kos(pe, giris, VM_DONUS, yon, &insn, &temiz);
    printf("KOMUT->TIP ETIKETLEME (giris=0x%llX yon=%llu donus=%s)\n",
           (unsigned long long)giris, (unsigned long long)yon, temiz ? "TEMIZ" : "HATALI");
    cizgi();
    std::map<std::string, int> dagilim;
    for (auto& e : E) {
        std::string temel = e.tip.substr(0, e.tip.find('('));
        dagilim[temel]++;
        printf("  komut#%-4d %-22s %s\n", e.komut_no, e.tip.c_str(), e.kanit.c_str());
    }
    cizgi();
    int vm_ic = 0, toplam = (int)E.size();
    for (auto& [k, v] : dagilim) {
        printf("  %-14s %d\n", k.c_str(), v);
        if (k == "VM-İÇ" || k == "VM-iç" || k.find("VM") == 0) vm_ic += v;
    }
    printf("TOPLAM: %d komut | VM-İÇ %d (%.0f%%) — obfuscasyon/yönetim\n",
           toplam, vm_ic, toplam ? 100.0 * vm_ic / toplam : 0.0);
    return temiz ? 0 : 1;
}

// ---- V327: AV-tuzak statik taraması (ALL/unpacker gövdeleri) ----
static int cmd_avtuzak(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "kullanim: avtuzak <korumali.exe> <bas-va-hex> <son-va-hex>\n"
                        "  ornek: avtuzak Test_64_ALL.vmp.exe 142998C82 142998D11\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }
    uint64_t bas = adres_oku(argv[3]), son = adres_oku(argv[4]);
    if (!bas || !son || son <= bas) { fprintf(stderr, "aralik gecersiz\n"); return 1; }
    std::vector<AvTuzakBulgusu> B = av_tuzak_tara(pe, bas, son);
    printf("AV-TUZAK ADAYLARI [0x%llX..0x%llX) — %zu adet\n",
           (unsigned long long)bas, (unsigned long long)son, B.size());
    cizgi();
    for (auto& b : B)
        printf("  0x%llX  %-44s %s\n", (unsigned long long)b.va, b.talimat.c_str(), b.neden.c_str());
    printf("NOT: aday = [base + idx*scale - K] deseni; kesin tuzak için koşu-anı\n"
           "     doğrulama gerekir (K == idx*scale → EA=base → bilinçli null-okuma).\n"
           "     V327 kanıtı: 0x142998CC2 movzx r9d,[rdx+r9*2-0xf187d1a] EA=rdx=8.\n");
    return 0;
}

// unpack (V333): ALL statik dekompres — props imzası → PACKER_INFO → LZMA akış listesi
// + known-plaintext import key. Bölümlerin geri yazımı harici (LZMA decode) yapılır;
// bu komut tabloyu, akış konumlarını ve import kayıtlarını çıkarır.
static int cmd_unpack(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "kullanim: unpack <korumali.exe> [bilinen-dll-adi]\n"
                        "  ornek: unpack Test_64_ALL.vmp.exe api-ms-win-crt-private-l1-1-0.dll\n"
                        "  cikti: PACKER_INFO tablosu + [Src][Dst] akis listesi + import tablosu\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }

    // Adim 2-3: props + PACKER_INFO
    UnpackTablo T = unpack_tablo_bul(pe);
    if (!T.tablo_off) {
        printf("PACKER_INFO bulunamadi — pack kapali olabilir (bolumler RSZ'li).\n");
        return 1;
    }
    printf("PROPS RVA=0x%X  PACKER_INFO tablo @0x%X  akis girisi=%zu\n",
           T.props_rva, T.tablo_off, T.girisler.size());
    cizgi();
    for (auto& g : T.girisler) {
        uint32_t off = 0;
        for (const auto& b : pe.bolumler)
            if (g.src >= b.va && g.src < b.va + (b.vsz > b.rsz ? b.vsz : b.rsz) && b.rsz)
                { off = b.ra + (g.src - b.va); break; }
        const char* ad = "?";
        for (const auto& b : pe.bolumler) if (g.dst == b.va) ad = b.ad.c_str();
        printf("  Src=0x%-8X Dst=0x%-8X (%-8s akis dosya-off=0x%X)\n", g.src, g.dst, ad, off);
    }
    printf("NOT: akislari LZMA FORMAT_RAW ile cozun (dict=1<<24, lc=3, lp=0, pb=2)\n"
           "     (V332 kaniti: .data 100%% birebir, .text korunan kod birebir)\n");

    // Adim 5: import key (known-plaintext)
    if (argc > 3) {
        uint32_t konum = 0;
        uint32_t key = unpack_key_bul(pe, argv[3], konum);
        if (key) {
            printf("\nIMPORT KEY=0x%08X (bilinen ad @0x%X)\n", key, konum);
            auto kayitlar = unpack_import_tara(pe, key);
            printf("IMPORT KAYITLARI: %zu\n", kayitlar.size());
            cizgi();
            size_t goster = kayitlar.size() > 20 ? 20 : kayitlar.size();
            for (size_t i = 0; i < goster; i++)
                printf("  @0x%06X  %-42s V1=0x%06X V2=0x%08X\n",
                       kayitlar[i].konum, kayitlar[i].ad.c_str(), kayitlar[i].v1, kayitlar[i].v2);
            if (kayitlar.size() > goster) printf("  ... +%zu daha\n", kayitlar.size() - goster);
        } else {
            printf("\nIMPORT KEY bulunamadi (bilinen dll adi eslesmedi)\n");
        }
    }
    return 0;
}

// V335: unpack-tam — 5 adımlı zinciri TEK KOMUTTA koşar: tablo + LZMA decode +
// orijinal karşılaştırma + OEP doğrulama + dosya çıktısı.
static int cmd_unpack_tam(int argc, char** argv) {
    if (argc < 4) {
        fprintf(stderr, "kullanim: unpack-tam <korumali.exe> <orijinal.exe> [cikti-dizini]\n"
                        "  ornek: unpack-tam Test_64_ALL.vmp.exe Test_64.exe ./cikti\n");
        return 2;
    }
    PE pe; std::string hata;
    if (!pe_yukle(argv[2], pe, hata)) { fprintf(stderr, "%s\n", hata.c_str()); return 1; }
    UnpackTablo T = unpack_tablo_bul(pe);
    if (!T.tablo_off) { printf("PACKER_INFO bulunamadi — pack kapali olabilir.\n"); return 1; }
    printf("PROPS RVA=0x%X  PACKER_INFO @0x%X  akis=%zu\n", T.props_rva, T.tablo_off, T.girisler.size());
    std::string dizin = argc > 4 ? argv[4] : "";
    UnpackSonuc s = unpack_tam(pe, T, argv[3], dizin);
    for (const auto& satir : s.rapor) printf("%s\n", satir.c_str());
    for (const auto& d : s.dosyalar) printf("YAZILDI: %s\n", d.c_str());
    printf("\nSONUC: %s\n", s.tamam ? "OEP 32/32 — UNPACK DOGRULANDI" : "bkz rapor satirlari");
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("TersineCevirici — VMProtect 3.9.4 devirtualizer (V324-V327 zinciri, C++)\n"
               "Alt komutlar:\n"
               "  girisler <orijinal.exe> <korunmus1.exe> [...]   0x14C0 jmp hedef envanteri\n"
               "  mutasyon <korunmus.exe> [giris-va]              birebir cikarim + junk raporu\n"
               "  vmtrace  <korumali.exe> <orijinal.exe> [yon]    VM iz + oracle karsilastirma\n"
               "  oracle  <orijinal.exe> [yon]                    dogal referans olay dizisi\n"
               "  etiket  <korumali.exe> <giris-va> [yon]         komut->tip semantik etiketleme (V327)\n"
               "  avtuzak <korumali.exe> <bas-va> <son-va>        AV-tuzak aday taramasi (V327 ALL teshisi)\n"
               "  unpack  <korumali.exe> [bilinen-dll]           ALL statik dekompres tablosu + import key (V333)\n");
        return 0;
    }
    if (!strcmp(argv[1], "girisler"))  return cmd_girisler(argc, argv);
    if (!strcmp(argv[1], "mutasyon"))  return cmd_mutasyon(argc, argv);
    if (!strcmp(argv[1], "vmtrace"))   return cmd_vmtrace(argc, argv);
    if (!strcmp(argv[1], "oracle"))    return cmd_oracle(argc, argv);
    if (!strcmp(argv[1], "etiket"))    return cmd_etiket(argc, argv);
    if (!strcmp(argv[1], "avtuzak"))   return cmd_avtuzak(argc, argv);
    if (!strcmp(argv[1], "unpack"))    return cmd_unpack(argc, argv);
    if (!strcmp(argv[1], "unpack-tam")) return cmd_unpack_tam(argc, argv);
    fprintf(stderr, "bilinmeyen alt komut: %s\n", argv[1]);
    return 2;
}
