# Runnable examples

Every file here is a **complete, compilable** program matching a test case from
the chapters. The comments explain the code **line by line** — read the source,
not just the chapter.

> ⚠️ These are **deliberately vulnerable**. Build and run them **only in a
> throwaway VM/container**, never on a machine you care about, never networked.

## Build everything

```bash
cd src
make            # builds every example into ./bin/ with INSECURE training flags
make safe       # builds the *_safe hardened versions (where provided)
make clean
```

The default target uses the "training" flags so the bugs reproduce:
`-g -O0 -fno-stack-protector -no-pie -z execstack` and (for heap demos) a fixed
glibc behavior. Disable ASLR for the shell session before exploiting:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # re-enable with: ... 2
```

## Run / exploit

Each program's header comment shows how to trigger it and points to the matching
`exploits/*.py` pwntools script where relevant:

```bash
./bin/01_stack_basic $(python3 -c 'print("A"*40)')      # crash
python3 exploits/03_ret2win.py                           # get a shell (lab only)
./bin/07_uaf_fnptr                                       # UAF demo
ASAN_OPTIONS=detect_leaks=1 ./bin/asan_<x>               # sanitizer report
```

## Prove the fix

For files with a `*_safe` sibling (or a `SAFE` macro), rebuild with the fix and
confirm the same input no longer corrupts anything:

```bash
make safe && ./bin/01_stack_safe $(python3 -c 'print("A"*40)')   # handled cleanly
```

## File index

| File | Bug | Chapter |
|------|-----|---------|
| `01_stack_basic.c` | stack overflow → crash/offset | 02 |
| `02_stack_authflag.c` | overflow into adjacent flag | 02 |
| `03_ret2win.c` | return-address hijack to `win()` | 02 / 12 |
| `04_offbyone.c` | off-by-one / NUL | 02 |
| `05_heap_adjacent.c` | heap overflow into next object | 04 |
| `06_heap_fnptr.c` | heap overflow of a function pointer | 04 |
| `07_uaf_fnptr.c` | use-after-free fnptr hijack | 06 |
| `08_uaf_leak.c` | UAF / malloc-not-zeroed infoleak | 06 / 09 |
| `09_double_free.c` | double free | 06 |
| `10_format_leak.c` | format-string leak | 07 |
| `11_format_write.c` | format-string `%n` write | 07 |
| `12_int_overflow.c` | integer-overflow undersized alloc | 08 |
| `13_oob_read.c` | out-of-bounds read (Heartbleed shape) | 09 |
| `14_uninit_leak.c` | uninitialized-memory infoleak | 09 |
| `15_cpp_vtable.cpp` | C++ vtable hijack via UAF | 10 |
| `16_tcache_poison.c` | tcache poisoning primitive | 05 |
| `17_race_uaf.c` | data-race use-after-free | 11 |

`exploits/` holds pwntools scripts: `03_ret2win.py`, `11_format_write.py`,
`16_tcache_poison.py`.
