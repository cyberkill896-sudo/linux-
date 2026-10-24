# Chapter 8 — Integer Bugs → Memory Corruption (10 test cases)

> Integers don't corrupt memory by themselves. They do it by **feeding a wrong
> size, length, or index** into an allocation, copy, or array access. Every
> integer bug in this chapter is a *setup* for a Chapter 2/4/9 memory bug.

---

## 8.0 In plain words (start here)

Computer integers are not like math integers. A math integer can be any size; a
computer integer lives in a **fixed number of bits** (commonly 32 or 64), so it
can only hold numbers up to a limit. When a calculation goes past that limit,
the value doesn't error — it silently **wraps around**, like a car odometer
rolling from 999999 back to 000000.

Two everyday examples:
- A 32-bit **unsigned** integer holds 0 up to 4,294,967,295. Add 1 to the max and
  it wraps to **0**. Subtract 1 from 0 and it wraps to **4,294,967,295**.
- Assigning a big number into a **smaller** type keeps only the low bits:
  storing 65537 into a 16-bit value gives **1**.

By themselves these are just wrong numbers. They become *memory* bugs when that
wrong number is used as a **size** (how many bytes to allocate or copy) or an
**index** (which element to touch). The classic disaster:

```c
char *p = malloc(count * size);   // count and size come from input
memcpy(p, src, count * size);     // copy that many bytes
```

If `count * size` is big enough to wrap, `malloc` is asked for a *tiny* amount
(say 4 bytes), succeeds, and then `memcpy` copies the *real* huge amount into
that tiny buffer → heap overflow (Chapter 4). The program never sees an error;
the multiplication just lied.

So the mental model for this whole chapter is: **an integer bug is a setup
move.** On its own it's a wrong number; combined with an allocation, a copy, or
an array index it becomes an overflow (Chapter 2/4), an out-of-bounds access
(Chapter 9), or an under-allocation. The five ways numbers go wrong are listed
next (§8.1), and each test case shows the wrong number turning into a real memory
bug.

Why these are so easy to miss: they're invisible in the C source (the code looks
like normal arithmetic) and there's no runtime error by default. You find them by
reasoning about limits, by using `calloc`/overflow-checked helpers, and by
running under **UBSan** (`-fsanitize=undefined`), which *does* flag the wrap.

---

## 8.1 The five integer hazards

1. **Overflow** — result exceeds the type's max and **wraps** (`0xFFFFFFFF+1 = 0`).
2. **Underflow** — unsigned subtraction goes below 0 and wraps to a **huge**
   value (`0u - 1 = 0xFFFFFFFF`).
3. **Truncation** — assigning a wide value to a narrow type drops high bits
   (`(short)0x10001 = 1`).
4. **Signedness** — the same bits mean different things as signed vs unsigned; a
   negative signed value becomes a huge unsigned one.
5. **Sign extension** — widening a signed narrow type propagates the sign bit
   (`(int)(char)0xFF = -1 = 0xFFFFFFFF`).

Why they're silent: unsigned overflow is **defined** to wrap (no error); signed
overflow is **undefined** (compiler may do anything); conversions are implicit.
Nothing warns at runtime by default.

---

## 8.2 Test case 1 — multiplication overflow → undersized allocation

```c
// i01_mul.c
#include <stdlib.h>
#include <string.h>
void *dup_items(size_t count, size_t size, void *src){
    void *p = malloc(count * size);     // count*size can wrap to a tiny value
    memcpy(p, src, count * size);       // ...but this is the same wrapped value
    return p;                           // ok here — but callers often use the
}                                       // REAL count elsewhere -> overflow
```
The dangerous version is when the **allocation** uses the wrapped product but a
**loop/copy uses the real count**:
```c
char *p = malloc(count * size);               // wraps -> small
for (size_t i=0;i<count;i++) p[i*size]=0;     // writes count*size real bytes -> OOB
```
**Fix:** `calloc(count,size)` (checks the multiply), or
`if (size && count > SIZE_MAX/size) abort();`, or `__builtin_mul_overflow`.

---

## 8.3 Test case 2 — unsigned underflow in a length calc

```c
// i02_underflow.c
void copy_body(char *pkt, unsigned total_len){
    unsigned body = total_len - HEADER_LEN;   // if total_len < HEADER_LEN...
    memcpy(dst, pkt + HEADER_LEN, body);       // body = 0xFFFFFFF.. -> massive copy
}
```
An attacker sends `total_len = 2` with `HEADER_LEN = 20`; `body` underflows to
`0xFFFFFFEE` → `memcpy` copies ~4 GB → overflow/crash. **Fix:** validate
`if (total_len < HEADER_LEN) reject;` *before* subtracting.

---

## 8.4 Test case 3 — signed/unsigned comparison bypass

```c
// i03_signedcmp.c
int read_data(int len){               // len is SIGNED and attacker-controlled
    char buf[128];
    if (len > 128) return -1;          // check looks fine...
    memcpy(buf, src, len);             // memcpy's 3rd arg is size_t (UNSIGNED)
}
```
Send `len = -1`. The check `-1 > 128` is **false** (passes!), but `memcpy`
converts `-1` to `size_t` = `0xFFFF...FF` → enormous copy → overflow. **Fix:** use
an **unsigned** length and check both ends: `if (len == 0 || len > sizeof buf)`.

---

## 8.5 Test case 4 — truncation to a narrow type

```c
// i04_truncate.c
char *recv_record(void){
    unsigned long real_len = read_u64_from_wire();   // e.g. 0x1_0000_0040
    unsigned short n = real_len;                      // truncates to 0x0040 = 64
    char *buf = malloc(n);                            // allocates 64 bytes
    read(fd, buf, real_len);                          // reads 0x100000040 bytes -> OOB
}
```
Allocation uses the **truncated** size; the copy uses the **full** size. Classic in
protocol parsers that mix `uint16`/`uint32`/`size_t`. **Fix:** use one wide type
consistently and bound it.

---

## 8.6 Test case 5 — sign extension turning small into huge

```c
// i05_signext.c
int process(char *p){
    char n = p[0];                 // a byte; if p[0]=0xFF this is -1 (signed char)
    size_t len = n;                // sign-extends: -1 -> 0xFFFF...FF
    memcpy(dst, p+1, len);         // huge copy
}
```
A single byte read as **signed** then widened sign-extends to a gigantic
`size_t`. **Fix:** read length bytes as `unsigned char`/`uint8_t` and assemble
explicitly.

---

## 8.7 Test case 6 — array index from signed int (negative index)

```c
// i06_negindex.c
int table[16];
int idx = atoi(argv[1]);           // signed; attacker passes -5 or 100
return table[idx];                 // negative or >=16 -> OOB read/write
```
Negative indices read/write **before** the array — a stealthy write-what-where.
**Fix:** `if ((unsigned)idx < 16)` (the cast makes negatives huge, so one check
covers both ends).

---

## 8.8 Test case 7 — pointer arithmetic overflow

```c
// i07_ptrarith.c
int is_within(char *base, size_t len, char *p){
    return p >= base && p < base + len;   // base+len can overflow the pointer,
}                                         // making the check wrongly pass
void copy(char *buf, size_t n){
    if (buf + n < buf) return;            // naive overflow check (UB, may be
    ...                                   // optimized away by the compiler!)
}
```
Pointer + length can wrap around the address space; bounds checks written as
`p + n` are both **UB** and unreliable (compilers assume no overflow and delete
the check). **Fix:** compare the *lengths/offsets*, not computed pointers:
`if (n > len - offset)`.

---

## 8.9 Test case 8 — the `malloc(0)` / zero-length trap

```c
// i08_zero.c
char *p = malloc(n);     // n==0: may return NULL or a unique 0-size pointer
p[0] = 'x';              // writing to a 0-byte (or NULL) allocation -> OOB/crash
char *q = calloc(0, 16); // also edge-casey
```
`malloc(0)` is implementation-defined (NULL or a minimal chunk); zero-length reads
from input often flow here. **Fix:** special-case `n == 0`; never assume ≥1 byte.

---

## 8.10 Test case 9 — loop counter type mismatch

```c
// i09_loop.c
void f(unsigned char count){
    for (unsigned char i = 0; i <= count; i++)   // if count==255, i<=255 is
        buf[i] = 0;                               // ALWAYS true -> infinite loop +
}                                                 // runaway OOB write
```
`i <= 255` can never be false for a `unsigned char i` → infinite loop writing past
`buf`. Mismatched/narrow counter types cause both infinite loops and OOB. **Fix:**
use `size_t`/`int` for counters and `<` with the exact count.

---

## 8.11 Test case 10 — `int` return value ignored / errno-style size

```c
// i10_retval.c
int n = read(fd, buf, sizeof buf);   // read returns -1 on error (ssize_t)
process(buf, n);                     // if n==-1, passed as size -> huge unsigned
```
I/O functions return **signed** counts and `-1` on error. Treating the result as
an unsigned size without checking `< 0` turns an error into a huge length. **Fix:**
`if (n < 0) handle_error(); else process(buf, (size_t)n);`.

---

## 8.12 How to see it at the assembly level

Integer bugs are invisible in C but obvious in asm — the **instruction width and
signedness** are explicit:

```asm
; (short)wide  -> truncation: only the low 16 bits move
  movzx  eax, ax          ; zero-extend 16->32 (unsigned)
  movsx  eax, al          ; SIGN-extend 8->32  (0xFF byte -> 0xFFFFFFFF)  <-- test 5
; signed vs unsigned compare use DIFFERENT branches:
  cmp    edi, 0x80
  jg     ok               ; JG = signed greater  -> -1 > 128 is FALSE (test 3 bug)
; vs the safe unsigned form:
  ja     fail             ; JA = unsigned above  -> 0xFFFFFFFF > 128 is TRUE
```
`movsx` vs `movzx`, and `jg/jl` (signed) vs `ja/jb` (unsigned), are exactly where
these bugs live. Reading the disassembly of a bounds check tells you instantly
whether it's signed-safe.

---

## 8.13 The fixes (general)
- **Use `size_t` for sizes/indices; validate before arithmetic**, and bound to a
  sane maximum.
- **`calloc` / `reallocarray`** for array sizing (built-in overflow checks).
- **`__builtin_{add,mul,sub}_overflow`** for explicit, portable checks.
- **Check I/O return values for `< 0`** before using as sizes.
- **`(unsigned)idx < N`** for one-line index bounds.
- **Compile with `-fsanitize=undefined`** (UBSan: catches signed overflow, bad
  shifts, OOB), `-Wconversion -Wsign-conversion -Wsign-compare` to flag risky
  conversions, and consider `-ftrapv`/`-fwrapv` to define overflow behavior.

---

## Recap
- Five hazards — overflow, underflow, truncation, signedness, sign extension —
  each silently produces a **wrong size/length/index** that then drives a real
  memory bug.
- Ten shapes: mul-overflow, underflow, signed compare, truncation, sign-extend,
  negative index, pointer arithmetic, `malloc(0)`, loop type, ignored retval.
- `movsx/movzx` and `jg/ja` in disassembly reveal them.
- Fix with `size_t`, `calloc`, builtin overflow checks, retval checks,
  `(unsigned)idx<N`, and UBSan.

Next: **[Chapter 9 — Out-of-bounds, uninitialized & misc »](09-oob-and-misc.md)**
