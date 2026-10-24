# Memory Bug Cheat Sheet (one-page field guide)

Quick reference. Each row: the bug, how to spot it, what it gives an attacker, and
the first-line fix. Full treatment in the linked chapters.

## Bug classes

| Bug | Tell (grep/pattern) | Impact | First-line fix | Chapter |
|-----|---------------------|--------|----------------|---------|
| Stack overflow | `gets`, `strcpy`, `scanf("%s")`, unbounded `memcpy`, attacker loop bound | overwrite return addr → RCE; adjacent flag → bypass | bound copies (`fgets`,`snprintf`,`memcpy`+n); canary/NX/ASLR | [02](02-stack-buffer-overflow.md) |
| Heap overflow | copy > `malloc` size; `strcat` on heap; `sizeof(int)` vs `sizeof *p` | corrupt next object (fnptr/len) or chunk metadata → RCE | bound copies; `calloc`; `sizeof *p`; ASan | [04](04-heap-overflow.md) |
| Heap technique | double-free, UAF, metadata overflow present | arbitrary alloc/write (tcache poison, dup, unlink, House-of) | don't create the bug; Full RELRO; modern glibc | [05](05-heap-techniques.md) |
| Use-after-free | `free(p)` then `p` used; dangling after `realloc`; callback holds ref | reclaim slot → fnptr/vtable hijack (RCE); UAF read → leak | `free(p);p=NULL`; single ownership/smart ptr; ASan | [06](06-use-after-free.md) |
| Double-free | `free(p)` twice; error-path free + cleanup free | free-list poison → alias → write primitive | `free;NULL`; single cleanup label | [06](06-use-after-free.md) |
| Format string | `printf(var)`, `syslog(_,var)`, format arg not a literal | `%p/%s` leak + `%n` arbitrary write → RCE; crash | `printf("%s",var)`; `-Werror=format-security` | [07](07-format-string.md) |
| Integer overflow | `malloc(a*b)`, `len-1` unsigned, wide→narrow assign | undersized alloc / huge length → overflow | `calloc`/`reallocarray`; `__builtin_mul_overflow`; UBSan | [08](08-integer-bugs.md) |
| Signed/unsigned | signed `len` + `>` check then `memcpy`; `jg` vs `ja` in asm | negative len → huge `size_t` → overflow | unsigned sizes; `(unsigned)idx<N` | [08](08-integer-bugs.md) |
| OOB read | echo attacker length; bad index; missing NUL | info disclosure (Heartbleed); pointer leak → defeat ASLR | validate length/index vs real size; ASan | [09](09-oob-and-misc.md) |
| OOB write | unchecked `table[i]=v`; negative index | write-what-where → RCE | `(unsigned)i<N`; checked containers | [09](09-oob-and-misc.md) |
| Uninitialized | use before set; `malloc` (not `calloc`); struct padding sent out | info leak (secrets/pointers), UB | `={0}`/`calloc`/`memset`; send only written bytes; MSan | [09](09-oob-and-misc.md) |
| NULL deref | unchecked `malloc`/`fopen`/lookup return | DoS (crash); kernel: historically more | check every return; UBSan `-fsanitize=null` | [09](09-oob-and-misc.md) |
| Wild pointer | uninitialized/fabricated pointer deref | corruption (worse than NULL) | init to `NULL`; never cast int→ptr; MSan | [09](09-oob-and-misc.md) |
| Memory leak | missing `free` on a path; lost last pointer | DoS (exhaustion) → secondary NULL-deref | RAII/single cleanup; Valgrind/LSan | [09](09-oob-and-misc.md) |
| Stack exhaustion | unbounded recursion; attacker-sized VLA/`alloca` | crash/corruption | bound depth; `-fstack-clash-protection` | [09](09-oob-and-misc.md) |
| C++ vtable hijack | UAF/overflow of a polymorphic object | overwrite vptr → fake vtable → RCE | RAII/smart ptr; CFI; no UAF | [10](10-cpp-bugs.md) |
| Type confusion | `static_cast`/`reinterpret_cast` without check | wrong-type fields → controlled call (browser #1) | `dynamic_cast`/`variant`/tagged; CFI | [10](10-cpp-bugs.md) |
| Use-after-move | use moved-from object; move ctor doesn't null source | double-free / UB | leave moved-from null; don't use it | [10](10-cpp-bugs.md) |
| Iterator invalidation | ref/ptr/iter kept across `push_back`/`erase`/rehash | UAF | re-acquire after mutation; use indices | [10](10-cpp-bugs.md) |
| TOCTOU / double-fetch | check then re-read shared/user value before use | overflow/UAF; priv-esc | lock; snapshot once then validate+use copy | [11](11-races.md) |
| Data-race UAF | concurrent free vs use; non-atomic `rc--` | UAF/double-free → RCE/LPE | mutex; atomic refcount; TSan; Rust | [11](11-races.md) |

## Dangerous → safe function map

| Avoid | Use |
|-------|-----|
| `gets(b)` | `fgets(b, sizeof b, stdin)` |
| `strcpy(d,s)` | `snprintf(d,sizeof d,"%s",s)` / `strlcpy` |
| `strcat(d,s)` | `snprintf` / `strlcat` with remaining size |
| `sprintf(d,…)` | `snprintf(d, sizeof d, …)` |
| `scanf("%s",b)` | `scanf("%31s", b)` |
| `printf(var)` | `printf("%s", var)` |
| `malloc(n*m)` | `calloc(n, m)` / `reallocarray` |
| raw `new`/`delete` | `unique_ptr`/`shared_ptr`/`vector`/`string` |
| `arr[i]` (i from input) | check `(unsigned)i < len` first |
| `rc--` (shared) | `atomic_fetch_sub` / `refcount_t` |

## Build/test flags

```bash
# Hardened build (production):
gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fstack-clash-protection \
    -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack -fcf-protection=full \
    -Wall -Wextra -Wformat-security -Werror=format-security -Wconversion
# C++: add -D_GLIBCXX_ASSERTIONS   Clang: -fsanitize=cfi -flto

# Find bugs (testing/CI):
-fsanitize=address      # overflow, UAF, double-free   (ASan)
-fsanitize=undefined    # integer overflow, null, OOB   (UBSan)
-fsanitize=memory       # uninitialized reads (Clang)   (MSan)
-fsanitize=thread       # data races                    (TSan)
-fsanitize=address,fuzzer   # libFuzzer harness
valgrind ./prog         # leaks + invalid access, no recompile

# Inspect a binary:
checksec --file=./prog
```

## The universal exploit pattern (to recognize chains)

```
bug (overflow/UAF/format/int)
  -> primitive (control rip, or write-what-where, or read)
  + info leak (defeat ASLR/canary/PIE)         <- half of every modern exploit
  -> aim at target (ret addr / GOT / vtable / hook / __free_hook / stdout vtable)
  -> code execution (ret2libc / ROP / syscall)
```

**The only thing that ends the chain is removing the bug** — safe APIs, bounds
checks, clear lifetimes, sanitizers + fuzzing, and memory-safe languages.
