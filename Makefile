# TersineCevirici — derleme ayarları
# Capstone/Unicorn: test ortamında Python wheel paketlerinin içindeki kütüphaneler
# kullanıldı; kendi kurulumunuzda bu yolları değiştirin.
CAPSTONE_DIR ?= /home/z/.venv/lib/python3.12/site-packages/capstone
UNICORN_DIR  ?= /home/z/.venv/lib/python3.12/site-packages/unicorn

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter
INCLUDES := -I$(CAPSTONE_DIR)/include -I$(UNICORN_DIR)/include
LDFLAGS  := -L$(CAPSTONE_DIR)/lib -L$(UNICORN_DIR)/lib \
            -Wl,-rpath,$(CAPSTONE_DIR)/lib -Wl,-rpath,$(UNICORN_DIR)/lib \
            -lcapstone -lunicorn -llzma

SRCS := tc_pe.cpp tc_disasm.cpp tc_mutasyon.cpp tc_vm.cpp tc_oracle.cpp tc_etiket.cpp tc_unpack.cpp tc_lzma.cpp tc_teshis.cpp tersinecevirici.cpp
OBJS := $(SRCS:.cpp=.o)
HDRS := tc_pe.hpp tc_disasm.hpp tc_mutasyon.hpp tc_vm.hpp tc_oracle.hpp tc_etiket.hpp tc_kurulum.hpp tc_unpack.hpp tc_lzma.hpp tc_teshis.hpp

all: libtersinecevirici.a tersinecevirici

libtersinecevirici.a: tc_pe.o tc_disasm.o tc_mutasyon.o tc_vm.o tc_oracle.o tc_etiket.o tc_unpack.o tc_lzma.o tc_teshis.o
	ar rcs $@ $^

tersinecevirici: $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.cpp $(HDRS)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# sandbox testi: örnek korunmuş dosyalar varsa birebir çıkarımı teyit eder
TESTDIR ?= /home/z/my-project/work/v324/394_ciktilar
test: tersinecevirici
	./tersinecevirici girisler /home/z/my-project/upload/Test_64.exe \
		$(TESTDIR)/Test_64_mutation.vmp.exe \
		$(TESTDIR)/Test_64_moveplayer_virtualization.vmp.exe \
		$(TESTDIR)/Test_64_moveplayer_virtualization_complexity_100.vmp.exe \
		$(TESTDIR)/Test_64_ultra.vmp.exe \
		$(TESTDIR)/Test_64_ultra_complexity_100.vmp.exe
	./tersinecevirici mutasyon $(TESTDIR)/Test_64_mutation.vmp.exe
	./tersinecevirici oracle /home/z/my-project/upload/Test_64.exe 4
	./tersinecevirici vmtrace $(TESTDIR)/Test_64_moveplayer_virtualization.vmp.exe \
		/home/z/my-project/upload/Test_64.exe 4

clean:
	rm -f *.o *.a tersinecevirici

.PHONY: all test clean
