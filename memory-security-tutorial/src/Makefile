# Makefile for the memory-security-tutorial runnable examples.
#
#   make          build every example with INSECURE training flags -> bin/
#   make safe     build the *_safe hardened variants (where provided)
#   make asan     build *_asan variants with AddressSanitizer
#   make tsan     build the race example with ThreadSanitizer
#   make msan     build the uninitialized-memory example with MemorySanitizer (clang)
#   make clean
#
# ⚠️ The default build is DELIBERATELY insecure so the bugs reproduce. Only run
#    these in a throwaway VM/container. Disable ASLR while exploiting:
#        echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

CC      ?= gcc
CXX     ?= g++
CLANG   ?= clang

BIN     := bin

# Training flags: no canary, no PIE, executable stack, no optimization, debug.
VULN_CFLAGS := -g -O0 -fno-stack-protector -no-pie -z execstack \
               -Wno-deprecated-declarations -Wno-format-security \
               -fcf-protection=none

# Hardened flags for the *_safe builds (Chapter 13 recipe).
SAFE_CFLAGS := -g -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong \
               -fstack-clash-protection -fPIE -pie \
               -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fcf-protection=full \
               -Wall -Wextra -Wformat -Wformat-security -Werror=format-security \
               -DSAFE

C_SRCS   := $(wildcard [0-9][0-9]_*.c)
CPP_SRCS := $(wildcard [0-9][0-9]_*.cpp)
C_BINS   := $(patsubst %.c,$(BIN)/%,$(C_SRCS))
CPP_BINS := $(patsubst %.cpp,$(BIN)/%,$(CPP_SRCS))

# Files that provide a meaningful hardened build via -DSAFE.
SAFE_TARGETS := 01_stack_basic 10_format_leak

.PHONY: all safe asan tsan msan clean
all: $(C_BINS) $(CPP_BINS)
	@echo "Built insecure training binaries into ./$(BIN)/"

$(BIN):
	@mkdir -p $(BIN)

# Generic C build (insecure). 17_race_uaf needs -pthread.
$(BIN)/%: %.c | $(BIN)
	$(CC) $(VULN_CFLAGS) $(if $(filter 17_race_uaf,$*),-pthread,) $< -o $@

# Generic C++ build (insecure).
$(BIN)/%: %.cpp | $(BIN)
	$(CXX) $(VULN_CFLAGS) $< -o $@

safe: | $(BIN)
	@for t in $(SAFE_TARGETS); do \
	  echo "  SAFE  $$t -> $(BIN)/$${t%.*}_safe"; \
	  $(CC) $(SAFE_CFLAGS) $$t.c -o $(BIN)/$${t}_safe 2>&1 || \
	    echo "   (note: the safe build may REJECT the vulnerable form at compile time — that's intended)"; \
	done

# AddressSanitizer variants for the memory-corruption demos.
ASAN_TARGETS := 04_offbyone 05_heap_adjacent 06_heap_fnptr 07_uaf_fnptr \
                12_int_overflow 13_oob_read 15_cpp_vtable
asan: | $(BIN)
	@for t in $(ASAN_TARGETS); do \
	  if [ -f $$t.c ]; then \
	    echo "  ASAN  $$t"; $(CC) -g -O0 -fsanitize=address $$t.c -o $(BIN)/$${t}_asan; \
	  elif [ -f $$t.cpp ]; then \
	    echo "  ASAN  $$t"; $(CXX) -g -O0 -fsanitize=address $$t.cpp -o $(BIN)/$${t}_asan; \
	  fi; \
	done

tsan: | $(BIN)
	$(CC) -g -O1 -fsanitize=thread -pthread 17_race_uaf.c -o $(BIN)/17_race_uaf_tsan

msan: | $(BIN)
	@command -v $(CLANG) >/dev/null 2>&1 && \
	  $(CLANG) -g -O0 -fsanitize=memory 14_uninit_leak.c -o $(BIN)/14_uninit_leak_msan || \
	  echo "clang not found; MSan requires clang"

clean:
	rm -rf $(BIN)
