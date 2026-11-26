// tc_pe.hpp — PE64 yükleyici: V324 zincirindeki pe_yukle()'nin C++ karşılığı
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace tc {

struct Bolum {
    std::string ad;   // ".text", ".vmp0" ...
    uint32_t va;      // bölüm VA'sı (image base hariç)
    uint32_t vsz;     // sanal boyut
    uint32_t ra;      // dosya içindeki konum
    uint32_t rsz;     // ham boyut
};

struct PE {
    uint64_t    base = 0;   // ImageBase (0x140000000)
    std::vector<uint8_t> img;   // belleğe serilmiş görüntü (img[RVA])
    std::vector<Bolum>   bolumler;
    uint32_t    boyut = 0;  // SizeOfImage

    // RVA → görüntü içi indeks güvenli erişimi
    const uint8_t* rva(uint32_t rva_) const {
        return rva_ < img.size() ? img.data() + rva_ : nullptr;
    }
    uint8_t* rva(uint32_t rva_) { return rva_ < img.size() ? img.data() + rva_ : nullptr; }
    uint64_t va(uint32_t rva_) const { return base + rva_; }
    // VA'nın hangi RVA'ya düştüğü (base çıkarılır; base dışıysa 0 döner)
    uint32_t va2rva(uint64_t va_) const {
        return va_ >= base && va_ - base < img.size() ? uint32_t(va_ - base) : 0;
    }
};

// Dosyayı yükler; başarısızsa hata doldurur.
bool pe_yukle(const std::string& yol, PE& pe, std::string& hata);

} // namespace tc
