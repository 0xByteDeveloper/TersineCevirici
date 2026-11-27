// tc_lzma.hpp — LZMA1 FORMAT_RAW decoder (sistem liblzma) — V335
//
// Amaç: unpack zincirini TersineCevirici içine tamamlamak (V332/V334 yöntemi):
// props 5D 00 00 00 01 = LZMA1, lc=3 lp=0 pb=2, dict=1<<24, end-marker'lı, başlıksız.
// python `lzma.FORMAT_RAW` ile AYNI motor (liblzma) → birebir aynı çıktı.
#ifndef TC_LZMA_HPP
#define TC_LZMA_HPP

#include <cstdint>
#include <cstddef>
#include <vector>

namespace tc {

// lzma1_coz — ham LZMA1 akışını çözer (lc3/lp0/pb2/dict16MB sabit — VMProtect props'u).
// hedef_boyut>0: beklenen açılmış boyut (bölüm VSZ); 0: akış bitene dek.
// Dönüş: açılmış veri; hata durumunda boş vektör.
std::vector<uint8_t> lzma1_coz(const uint8_t* giris, size_t giris_boyut,
                               size_t hedef_boyut = 0);

} // namespace tc
#endif
