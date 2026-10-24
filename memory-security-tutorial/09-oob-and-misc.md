# Chapter 9 — Out-of-Bounds, Uninitialized Memory & Misc Bugs

> The remaining core classes the user asked to see explained *deeply*: OOB read
> (Heartbleed), OOB write, uninitialized memory, NULL/wild pointers, memory
> leaks, and stack exhaustion. Each gets full "why/how/test cases/impact/fix".

---

## 9.1 Out-of-bounds READ (information disclosure)

### What / why
Reading past (or before) a buffer's bounds. No corruption — but it **leaks**
adjacent memory: other users' data, pointers (→ defeat ASLR), secret keys. It
happens because an **index or length isn't validated against the real buffer
size**, and C's `arr[i]` is just "base + i×size, dereference" with no check.

### Test case 1 — attacker-controlled read length (the Heartbleed shape)
```c
// o01_heartbleed.c
char buf[256];                     // holds a short message + lots of stale memory
unsigned n = read_u16_from_client();  // client CLAIMS the payload length
size_t got = fill_buf(buf);        // actually only `got` bytes are valid
send_to_client(buf, n);            // echoes n bytes -- but validates n against
                                   // nothing -> leaks up to 256 (or more) bytes
```
**Heartbleed (CVE-2014-0160)** was exactly this: OpenSSL's TLS heartbeat echoed a
client-supplied length without checking it against the actual payload size,
leaking up to **64 KB** of server memory per request — including private keys and
other users' sessions. One missing `if (payload_len > actual_len) return;`.

### Test case 2 — index read past an array
```c
// o02_index.c
int arr[8] = {0};
int i; scanf("%d", &i);
printf("%d\n", arr[i]);            // i=100 reads far past arr -> leak
```
### Test case 3 — missing NUL → `strlen`/`%s` over-read
```c
// o03_nonul.c
char buf[16];
memcpy(buf, src, 16);              // fills all 16, no room for terminator
printf("%s", buf);                 // reads until it finds a 0 somewhere past buf
```
### Impact
Info disclosure: secrets, and especially **pointers** that defeat ASLR/PIE/canary
— turning a "mere read" into the enabling half of an RCE chain.
### Fix
Validate every index/length against the **real** valid size *before* use
(`n = min(n, valid_len)`; reject invalid input). NUL-terminate explicitly. Test
with **ASan** (detects OOB read) and bounds-checked containers (`std::span`,
`.at()`).

---

## 9.2 Out-of-bounds WRITE (corruption)

### What / why
Writing past bounds — the corrupting cousin. Covered as overflow in Ch.2/4; the
pure "index write" form:
```c
// o04_idxwrite.c
long table[16];
int i; scanf("%d", &i);
table[i] = attacker_value;         // i out of range -> write-what-where
```
An unchecked **index write** is a direct arbitrary write: the attacker picks the
offset (and sometimes the value). Negative indices write *before* the array.
### Fix
`if ((unsigned)i < 16)` before every indexed write; prefer containers with
checked access in C++.

---

## 9.3 Uninitialized memory use

### What / why
Reading a variable or buffer **before it's written**. Its contents are leftover
bytes — stack garbage, or a **previous heap object's data** (possibly another
user's secret). Crucially, **`malloc` does NOT zero memory** (only `calloc`
does), so a fresh `malloc` can hand you a freed object's bytes.

### Test case 1 — uninitialized local used as size/pointer
```c
// o05_uninit_local.c
void f(int cond){
    int n;                         // not initialized
    if (cond) n = compute();
    char *p = malloc(n);           // if !cond, n is garbage -> giant/tiny alloc
    struct S s;                    // s.ptr uninitialized
    s.fn();                        // calls through an indeterminate pointer
}
```
### Test case 2 — uninitialized heap leaked to output (infoleak)
```c
// o06_uninit_heap.c
char *resp = malloc(64);           // contains a freed object's bytes
snprintf(resp, 64, "%s", name);    // only fills strlen(name)+1 bytes
send(fd, resp, 64);                // sends all 64 -> leaks the stale tail
```
### Test case 3 — struct padding leaked
```c
// o07_padding.c
struct msg { char type; /* 3 bytes PADDING here */ int len; };
struct msg m; m.type = 1; m.len = 8;   // padding bytes never initialized
send(fd, &m, sizeof m);                // leaks 3 bytes of stack/heap via padding
```
This is a huge source of **kernel infoleaks** (`copy_to_user` of a struct with
uninitialized holes — Chapter 14).
### Impact
Info leak (secrets, pointers), and **UB** (garbage pointer/size → crash or
corruption).
### Fix
Initialize at declaration (`int n = 0;`, `struct S s = {0};`, `char buf[64]={0}`),
use **`calloc`**, `memset` structs before filling (including padding), and send
only the bytes you actually wrote. **MemorySanitizer** (`-fsanitize=memory`,
Clang) is purpose-built for this; `-Wuninitialized`/`-Wmaybe-uninitialized` catch
the easy cases.

---

## 9.4 NULL-pointer dereference

### What / why
Dereferencing `NULL` (or a near-NULL offset), usually from an **unchecked
allocation failure** or unhandled error. Page 0 is unmapped, so in **user space**
it's almost always a **crash/DoS**. In the **kernel** historically it could be
exploited by `mmap`-ing page 0 — now blocked by `mmap_min_addr`, so mostly DoS
there too (but still a serious reliability bug).
```c
// o08_null.c
char *p = malloc(huge);   // returns NULL on failure
p[0] = 'x';               // NULL deref -> SIGSEGV
FILE *f = fopen(path,"r");
fread(buf,1,n,f);         // f may be NULL -> crash
struct node *n = find(k); // may return NULL
n->val = 1;               // unchecked -> crash
```
### Test case — near-NULL via struct offset
```c
struct big { char pad[0x2000]; int x; };
struct big *b = NULL;
b->x = 1;                 // writes to address 0x2000+offset, not literally 0
```
A NULL base + large field offset writes at a small non-zero address — the reason
kernels enforce a minimum mmap address.
### Impact
DoS (crash). Occasionally more in the kernel/embedded contexts.
### Fix
**Check every allocation and error return** before dereferencing. Use
`-fsanitize=null` (UBSan) and static analyzers; adopt a "nonnull" discipline and
annotations (`__attribute__((returns_nonnull))`, `_Nonnull`).

---

## 9.5 Wild / uninitialized pointers

### What / why
A pointer that was never set (or set to garbage) and then dereferenced — like
NULL deref but the target is **unpredictable**, so it can corrupt *anything*,
making it worse than NULL.
```c
// o09_wild.c
char *p;              // uninitialized -> indeterminate address
*p = 'A';             // writes to a random address -> corruption or crash
int *q = (int*)0xdeadbeef;  // bogus cast
*q = 0;               // wild write
```
### Fix
Always initialize pointers (`char *p = NULL;`), never fabricate pointers from
integers, and let MSan/ASan flag the use.

---

## 9.6 Memory leaks (resource exhaustion)

### What / why
Not a corruption bug, but a memory-safety-adjacent reliability/DoS issue: failing
to `free` reachable-but-unused memory. Over time the process grows until the OOM
killer strikes or allocations start failing (which then triggers the *NULL-deref*
bugs above).
```c
// o10_leak.c
for (;;){
    char *p = malloc(4096);   // never freed
    handle(p);                // leak each iteration -> unbounded growth
}
// also: early return before free; losing the only pointer (p = other;).
```
### Impact
DoS via exhaustion; secondary allocation-failure bugs. In long-running
servers/daemons this is a real security issue.
### Fix
Match every `malloc` with a `free` on **all** paths (single cleanup label / RAII /
smart pointers); detect with **Valgrind/Memcheck**, **ASan leak detector**
(`ASAN_OPTIONS=detect_leaks=1`), and LSan.

---

## 9.7 Stack exhaustion / unbounded recursion / huge VLA

### What / why
Growing the stack past its limit — via **unbounded recursion** or a large
`alloca`/VLA — runs into the **guard page** (crash) or, without a guard
("Stack Clash"), into the heap/other mappings (**corruption**).
```c
// o11_recurse.c
void rec(int n){ char frame[4096]; rec(n+1); }   // each call eats 4 KB -> blows stack
int vla(int n){ char buf[n]; use(buf); }          // attacker-controlled n
void *a(int n){ return alloca(n); }               // same, heap-adjacent corruption
```
### Test case — recursion driven by attacker input depth
```c
// o12_depth.c  — a recursive parser on nested input "[[[[...]]]]"
int parse(const char **s){
    if (**s=='['){ (*s)++; return parse(s); }     // deep nesting -> stack overflow
    return 0;
}
```
Deeply nested JSON/XML/regex input is a real DoS vector against recursive
parsers.
### Impact
Crash/DoS; possible corruption without guard pages.
### Fix
**Bound recursion depth** (convert to an explicit stack/iteration), avoid
attacker-sized `alloca`/VLA, and compile with **`-fstack-clash-protection`**
(probes each page so the guard page is always hit → clean crash, never a skip
into the heap).

---

## Recap
| Bug | Tell | Impact | Fix |
|-----|------|--------|-----|
| OOB read | echo attacker length / bad index | info leak (Heartbleed) | validate length/index vs real size; ASan |
| OOB write | unchecked index write | write-what-where | `(unsigned)i<N`; containers |
| Uninitialized | use before set; `malloc` not zeroed; struct padding | infoleak, UB | `={0}`/`calloc`/`memset`; MSan |
| NULL deref | unchecked malloc/error | DoS | check returns; UBSan |
| Wild pointer | uninit/fabricated pointer | corruption | init to NULL; MSan |
| Memory leak | missing `free` on a path | DoS (exhaustion) | RAII/single cleanup; Valgrind/LSan |
| Stack exhaustion | unbounded recursion / big VLA | crash/corruption | bound depth; `-fstack-clash-protection` |

Next: **[Chapter 10 — C++-specific memory bugs »](10-cpp-bugs.md)**
