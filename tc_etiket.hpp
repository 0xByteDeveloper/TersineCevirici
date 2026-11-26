// tc_etiket.hpp — Komut→tip semantik etiketleyici (V327 %100 etiketlemenin C++ karşılığı)
// ve AV-tuzak dedektörü (V327 ALL teşhisi: istisna-tabanlı unpacker).
//
// V327 bulguları (kanıt: work/v327/etiket_*.txt, 941/941 komut):
//   - dispatch-arası yazmaç deltaları + bellek olayları + WrapPos giriş/çıkış kanıtlarıyla
//     her VM komutu kullanıcı 42-tip sınıfına bağlanır:
//     LOAD / STORE / RMW / CALL(WrapPos) / PROLOG / EPILOG / ARITH-FUSE / VM-İÇ
//   - c100: 8 komutta tam okunuş LOAD(pos)→CALL×2→STORE(pos)→RMW (42 satır → 8 komut)
//   - ultra: 836/859 ARITH-FUSE = obfuscasyon katmanı (~49× VARSAYILAN)
//   - VARSAYILAN #14: dx+dy çift tablo okuması TEK komutta (derin füzyon kanıtı)
//
// V327 ALL teşhisi (kanıt: work/v327/kok_neden.txt):
//   - unpacker bilinçli NULL-page okuması yapar: movzx r9d,[rdx+r9*2-0xf187d1a]
//     (sabit = r9*2 → EA=rdx=8) → gerçek Windows'ta ACCESS_VIOLATION → VEH değer üretir
//   - tuzak değeri yığın-LUT indeksi olur: mov r9d,[rcx+r9*4] (rcx=yığın)
//   - emülatörde AV üretilemez → yanlış LUT → jmp r8 ile düşük belleğe kayar
//   - AV-tuzak deseni: [base + idx*scale - K] where K == idx*scale sabiti → EA=base
#ifndef TC_ETIKET_HPP
#define TC_ETIKET_HPP

#include "tc_vm.hpp"
#include "tc_pe.hpp"
#include <string>
#include <vector>
#include <sstream>

namespace tc {

// ---- V327 sabitleri (etiketleme sembolleri — kullanıcı listesinden) ----
constexpr uint64_t SYM_DX_TABLO   = 0x140003230;  // dx tablosu (MovePlayer+18 lea hedefi)
constexpr uint64_t SYM_DY_TABLO   = 0x140003240;  // dy tablosu
constexpr uint64_t SYM_G_PX       = 0x140004008;
constexpr uint64_t SYM_G_PY       = 0x14000400C;
constexpr uint64_t SYM_G_MAZE     = 0x140004010;
constexpr uint64_t SYM_G_SCORE    = 0x140004140;
constexpr uint64_t SYM_G_DOTS     = 0x140004144;
constexpr uint64_t WRAPPOS_GIRIS_VA = 0x140001470;  // WrapPos giriş (V323/V324'ten)
constexpr uint64_t WRAPPOS_RET_VA   = 0x1400014B8;  // WrapPos return sonrası

// Bellek olayının sembol adı (biliniyorsa), yoksa boş
inline std::string sembol_adi(uint64_t va) {
    switch (va) {
        case SYM_DX_TABLO: return "dx_tablo";
        case SYM_DY_TABLO: return "dy_tablo";
        case SYM_G_PX:     return "g_px";
        case SYM_G_PY:     return "g_py";
        case SYM_G_MAZE:   return "g_maze";
        case SYM_G_SCORE:  return "g_score";
        case SYM_G_DOTS:   return "g_dots";
        default: {
            // g_maze satır içi erişimler (maze[y*16+x] aralığı)
            if (va >= SYM_G_MAZE && va < SYM_G_MAZE + 0x100) return "g_maze[i]";
            return "";
        }
    }
}

// Tek bir VM komutunun dispatch-arası kanıt kümesi (V327 etiketleme girdisi)
struct KomutKanit {
    int         komut_no = 0;       // 1..N (dispatch sırası)
    uint64_t    giris_rsp = 0;      // komut girişinde RSP (PROLOG/EPILOG kanıtı)
    bool        rsp_bilinmiyor = true;
    // bellek olayları (yalnız .data/.rdata sembol erişimleri)
    struct BelOlay { char tur; uint64_t va; uint64_t deger; };
    std::vector<BelOlay> olaylar;
    // WrapPos kanıtı
    bool wrap_giris = false;
    uint64_t wrap_ecx = 0, wrap_edx = 0;   // giriş argümanları
    bool wrap_donus = false;
    uint64_t wrap_eax = 0;                 // dönüş değeri
};

// Etiket sonucu — kullanıcı 42-tip uzayının sınıf başlıkları
struct KomutEtiketi {
    int         komut_no = 0;
    std::string tip;        // LOAD/STORE/RMW/CALL(WrapPos)/PROLOG/EPILOG/ARITH-FUSE/VM-İÇ
    std::string kanit;      // insan-okur kanıt dizisi (rapora gider)
};

// Tek komutu sınıfla (V327 etiketleme algoritmasının birebir çevirisi).
// Öncelik: CALL > RMW > STORE > LOAD(tablo/pos/maze) > RSP-delta > Δregs > VM-İÇ
inline KomutEtiketi komut_etiketle(const KomutKanit& k, uint64_t onceki_rsp,
                                   const std::vector<uint64_t>& onceki_gpr,
                                   const std::vector<uint64_t>& simdi_gpr,
                                   const std::vector<const char*>& gpr_adlari) {
    KomutEtiketi e;
    e.komut_no = k.komut_no;
    std::ostringstream kanit;

    // WrapPos kanıtları her zaman yazılır
    if (k.wrap_giris) kanit << "WrapPos(" << k.wrap_ecx << "," << k.wrap_edx << ") çağrısı";
    if (k.wrap_donus) {
        if (kanit.tellp() > 0) kanit << "; ";
        kanit << "WrapPos→" << k.wrap_eax << " dönüş";
    }

    // bellek olayları kanıta
    std::vector<std::string> oku_sem, yaz_sem;
    std::vector<std::pair<std::string, uint64_t>> oku_det, yaz_det;
    for (const auto& o : k.olaylar) {
        std::string s = sembol_adi(o.va);
        if (s.empty()) s = "0x" + ([](uint64_t v){ char b[32]; snprintf(b, sizeof b, "%llX", (unsigned long long)v); return std::string(b); })(o.va);
        if (o.tur == 'R') { oku_sem.push_back(s); oku_det.emplace_back(s, o.deger); }
        else if (o.tur == 'W') { yaz_sem.push_back(s); yaz_det.emplace_back(s, o.deger); }
    }
    for (size_t i = 0; i < oku_det.size() && i < 3; i++)
        kanit << (i ? ", " : (kanit.tellp() > 0 ? "; oku: " : "oku: ")) << oku_det[i].first << "=" << oku_det[i].second;
    for (size_t i = 0; i < yaz_det.size() && i < 3; i++)
        kanit << (i ? ", " : (kanit.tellp() > 0 ? "; yaz: " : "yaz: ")) << yaz_det[i].first << "=" << yaz_det[i].second;

    // ---- sınıflama (V327 öncelik sırası) ----
    if (k.wrap_giris || k.wrap_donus) {
        e.tip = "CALL(WrapPos)";
    } else if (!oku_sem.empty() && !yaz_sem.empty()) {
        // aynı sembol okundu+yazıldı mı?
        bool ayni = false;
        for (auto& s : oku_sem) for (auto& t : yaz_sem) if (s == t) ayni = true;
        if (ayni) {
            e.tip = "RMW";
            for (auto& s : oku_sem) for (auto& t : yaz_sem) if (s == t && e.tip.find(s) == std::string::npos && s.find('[') == std::string::npos) e.tip += "(" + s + ")";
        } else {
            e.tip = "RMW";
        }
    } else if (!yaz_sem.empty()) {
        bool pos = false, score = false, dots = false, maze = false;
        for (auto& s : yaz_sem) {
            if (s == "g_px" || s == "g_py") pos = true;
            if (s == "g_score") score = true;
            if (s == "g_dots") dots = true;
            if (s == "g_maze" || s.find("g_maze[") == 0) maze = true;
        }
        if (pos && !score && !dots) e.tip = "STORE(pos)";
        else if (score || dots) e.tip = "RMW(g_score/g_dots)";
        else if (maze) e.tip = "STORE(maze)";
        else e.tip = "STORE";
    } else if (!oku_sem.empty()) {
        bool tablo = false, pos = false, maze = false;
        for (auto& s : oku_sem) {
            if (s == "dx_tablo" || s == "dy_tablo") tablo = true;
            if (s == "g_px" || s == "g_py") pos = true;
            if (s == "g_maze" || s.find("g_maze[") == 0) maze = true;
        }
        if (tablo) e.tip = "LOAD(tablo)";
        else if (pos) e.tip = "LOAD(pos)";
        else if (maze) e.tip = "LOAD(maze)";
        else e.tip = "LOAD";
    } else if (!k.rsp_bilinmiyor && onceki_rsp != 0 && k.giris_rsp != onceki_rsp) {
        int64_t d = (int64_t)(k.giris_rsp - onceki_rsp);
        if (d < 0 && d >= -0x40) e.tip = "PROLOG(push/sub rsp)";
        else if (d > 0 && d <= 0x40) e.tip = "EPILOG(pop/add rsp)";
        else e.tip = "VM-İÇ";
        kanit << (kanit.tellp() > 0 ? "; " : "") << "RSP " << (d >= 0 ? "+" : "") << d;
    } else {
        // yazmaç deltaları (V327: ≤2 yazmaç → SET/COPY benzeri, 3+ → ARITH/FUSE)
        int degisen = 0;
        std::string liste;
        for (size_t i = 0; i < onceki_gpr.size() && i < simdi_gpr.size(); i++) {
            if (onceki_gpr[i] != simdi_gpr[i]) {
                degisen++;
                if (liste.size() < 24) { if (!liste.empty()) liste += ","; liste += gpr_adlari[i]; }
            }
        }
        if (degisen >= 3) {
            e.tip = "ARITH/FUSE";
            kanit << (kanit.tellp() > 0 ? "; " : "") << "Δregs: " << liste;
        } else if (degisen >= 1) {
            e.tip = "SET/COPY";
            kanit << (kanit.tellp() > 0 ? "; " : "") << "Δregs: " << liste;
        } else {
            e.tip = "VM-İÇ";
            if (kanit.tellp() == 0) kanit << "görünür değişiklik yok (obfuscasyon/yönetim)";
        }
    }
    e.kanit = kanit.str();
    return e;
}

// ================= AV-TUZAK DEDEKTÖRÜ (V327 ALL teşhisi) =================
// Amaç: unpacker gövdesindeki bilinçli NULL-page tuzak talimatlarını statik bul.
// Desen (V327 kanıtı): [reg_base + reg_idx*S - K] where K == reg_idx*S değerinin
// kendisi → efektif adres = reg_base (unpacker bunu null yapar → AV).
// Örnek: movzx r9d, [rdx + r9*2 - 0xf187d1a]  (r9=0x78c3e8d → r9*2-0xf187d1a=0 → EA=rdx)
struct AvTuzakBulgusu {
    uint64_t    va;          // talimat adresi
    std::string talimat;     // "movzx r9d, [rdx + r9*2 - 0xf187d1a]"
    std::string neden;       // "sabit = idx*scale → EA=base (NULL-tuzak)"
};

// Capstone talimatında AV-tuzak deseni ara (cs_detail gerekmez — op_str yeterli)
// desen: op_str içinde "[A + B*2 - K]" veya "[A + B*4 - K]" ve komut anında B*K
// sabiti eşleşiyor — bunu koşu-anı doğrulaması gerektirir; statik aday listesi verir.
inline bool av_tuzak_aday(const std::string& mnemonic, const std::string& op_str,
                          std::string& neden) {
    if (mnemonic != "movzx" && mnemonic != "movzx_" && mnemonic != "mov" &&
        mnemonic != "movsxd" && mnemonic != "lea") return false;
    // "[base + idx*scale - const]" kalıbı: '-' ile biten sabit var ve idx*scale çarpanı var
    bool carpan_var = op_str.find("*2") != std::string::npos ||
                      op_str.find("*4") != std::string::npos ||
                      op_str.find("*8") != std::string::npos;
    bool neg_sabit = op_str.find(" - 0x") != std::string::npos;
    if (carpan_var && neg_sabit) {
        neden = "çarpan + negatif-sabit deseni (koşu-anı doğrulama gerekli)";
        return true;
    }
    return false;
}

} // namespace tc

// ---- uygulamalar (tc_etiket.cpp) ----
namespace tc {
// vmtrace tabanlı komut etiketleme: giris VA'dan yürütür, dispatch başına kanıt
// toplar, komut_etiketle() ile sınıflar (V327 etiket_*.txt karşılığı)
std::vector<KomutEtiketi> etiket_kos(const PE& pe, uint64_t giris, uint64_t donus,
                                     uint64_t yon, uint64_t* cikti_insn, bool* cikti_temiz);
// AV-tuzak statik tarayıcı: [bas, son) bölgesinde [base+idx*scale-K] desenleri
std::vector<AvTuzakBulgusu> av_tuzak_tara(const PE& pe, uint64_t bas, uint64_t son);
} // namespace tc

#endif // TC_ETIKET_HPP
