# Chapter 9 — Out-of-Bounds, Uninitialized Memory & Misc Bugs

> The remaining core classes, explained *deeply*: OOB read (Heartbleed), OOB
> write, uninitialized memory, NULL/wild pointers, memory leaks, and stack
> exhaustion. Each gets a full "why / how / test cases / impact / fix".

---

## 9.0 In plain words (start here)

This chapter collects the memory bugs that aren't overflows-into-return-addresses
but matter just as much. The unifying idea, again, is Chapter 1's boxes:
touching boxes you shouldn't, or trusting boxes you never set.

- **Out-of-bounds (OOB) read** — reading boxes *past the end* of your data. You
  don't corrupt anything, but you *see* whatever was in the neighboring boxes:
  another user's data, a password, or a memory address. That's an **information
  leak** — and leaks are half of every modern exploit (they defeat ASLR). This is
  literally what Heartbleed was: a server handed back memory past the end of the
  real reply.
- **Out-of-bounds write** — the corrupting twin: writing to a box outside your
  array because the index was wrong. An attacker-chosen index is a "write
  anything, anywhere" primitive.
- **Uninitialized memory** — reading a box *before you put anything in it*. In C,
  a fresh local variable or a `malloc`'d buffer contains **leftover bytes from
  whatever used that memory before** (C's `malloc` does *not* zero memory). If
  those stale bytes were someone's secret and you send them out, that's a leak;
  if they were a stale pointer or size, that's a crash or corruption.
- **NULL / wild pointers** — using a pointer that points at box 0 (NULL) or at a
  garbage address. Usually a crash (denial of service), occasionally worse.
- **Memory leaks** — not corruption, but forgetting to `free` lockers until the
  storeroom fills up and the program dies. A slow denial of service.
- **Stack exhaustion** — calling functions so deeply (or allocating giant locals)
  that the stack runs out of room and smashes into something else.

Each section below gives the plain idea, several code examples, the real-world
impact (with the famous CVE where relevant), and the fix. The recurring cures are
boringly consistent: **validate indices and lengths before using them, and
initialize memory before you read it.**

---

## 9.1 Out-of-bounds READ (information disclosure)

### What / why
Reading past (or before) a buffer's bounds. No corruption — but it **leaks**
adjacent memory: other users' data, pointers (→ defeat ASLR), secret keys. It
happens because an **index or length isn't validated against the real buffer
size**, and C's `arr[i]` is just "base + i×size, dereference" with no check.

**Why a "read-only" bug is often as serious as a write.** Beginners
underestimate leaks because nothing is corrupted. But two things make OOB reads
devastating:
1. **They're silent and repeatable.** No crash, no log — so an attacker can
   repeat the leak thousands of times and reassemble large regions of memory
   (this is exactly how Heartbleed harvested keys). A write bug usually crashes
   eventually; a read bug just quietly hands over data.
2. **Leaked pointers defeat ASLR — the gateway to *every* write exploit.** Recall
   ASLR (Chapter 13) randomizes addresses so an attacker doesn't know where
   anything is. The moment an OOB read leaks *one* pointer (a return address, a
   libc pointer, a heap pointer), the attacker subtracts a known offset and
   recovers that whole region's base — and now a *separate* write bug becomes
   usable. That's why real exploits are "leak **then** corrupt": the read bug in
   this section is frequently the enabling half of a control-flow hijack
   elsewhere. A leak is rarely "just" a leak.

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

**The mental model: memory is never "blank," only "last used by someone."** When
you declare a local or call `malloc`, you don't get fresh zeroed boxes — you get
boxes that some *earlier* function call or allocation already wrote to, with
their old contents intact. The compiler/allocator doesn't clear them because
clearing costs cycles and C's philosophy is "don't pay for what you didn't ask
for." So an uninitialized read returns **whatever the previous occupant left**:
- a **local variable**'s bytes are whatever the last function whose frame
  overlapped this one wrote (Chapter 1: frames reuse the same stack region);
- a **`malloc`'d buffer**'s bytes are whatever the last object in that chunk
  contained before it was freed.

**Two distinct dangers, often confused:**
1. **Information leak (outbound).** If the stale bytes were a secret or a pointer
   and you send/return the buffer without fully overwriting it, you leak them —
   the same ASLR-defeating leak as an OOB read. Struct **padding** (§ test case 3)
   is the sneakiest version: you set every field but the invisible alignment
   bytes between fields stay stale, and `send(fd, &s, sizeof s)` ships them.
2. **Undefined behavior (inbound).** If the stale bytes are used as a **size** or
   a **pointer** — an uninitialized `len` passed to `memcpy`, an uninitialized
   `ptr` dereferenced — you get a wild allocation, a wild read/write, or a crash,
   and the behavior changes run to run (because the leftover bytes change). This
   is also a *reliability* nightmare: "works on my machine, crashes in
   production" is often an uninitialized read whose leftover bytes happened to be
   benign during testing.

The kernel version (`copy_to_user` of a struct with uninitialized padding) is one
of the most common Linux infoleaks and directly defeats KASLR — see Chapter 14
and the Dirty Pipe lab (a stale *flag*, the control-value cousin of this bug).

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
