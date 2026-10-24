# Chapter 5 — Other Core Memory Bugs

> Overflow and UAF are the giants, but a complete picture needs the rest of the
> family. Each gets the same treatment: what, why, how, test cases, fix.

Contents: **format strings · integer overflow (→ memory bug) · off-by-one ·
out-of-bounds read · uninitialized memory · null-deref · double free (recap) ·
stack exhaustion**.

---

## 5.1 Format-string vulnerabilities

### What / why
`printf`-family functions read their formatting from a **format string** and pull
arguments from registers/stack accordingly. If **attacker-controlled data is used
*as* the format string**, the attacker controls how `printf` walks memory.

```c
printf(user_input);          // BUG
printf("%s", user_input);    // correct
```

### How
- `%x %x %x ...` / `%p %p ...` → **leak** values off the stack (addresses →
  defeat ASLR, canaries, secrets). This is a reliable **info-leak primitive**.
- `%s` with a leaked/placed pointer → dereference and dump arbitrary memory.
- **`%n`** → *writes* the number of bytes printed so far to the pointed-at
  address. Combined with field-width padding (`%100x%n`) and positional args
  (`%7$n`), this is an **arbitrary write** → classic full exploitation.

### Test case
```c
// fmt.c
#include <stdio.h>
int main(int argc, char **argv) {
    char buf[128];
    fgets(buf, sizeof buf, stdin);
    printf(buf);           // vulnerable
    return 0;
}
```
```bash
gcc -g -O0 -no-pie fmt.c -o fmt
echo 'AAAA %p %p %p %p %p %p' | ./fmt    # leaks stack words
echo '%7$p' | ./fmt                       # leak the 7th argument slot directly
```
(`%n` writes are blocked by glibc's **FORTIFY** on writable format strings in
many configs, and by `_FORTIFY_SOURCE`; leaks via `%p/%s` still work.)

### Fix
Never pass untrusted data as the format. Always `printf("%s", data)`,
`fprintf(f, "%s", data)`, etc. Compile with `-Wformat -Wformat-security`
(GCC/Clang flag this at compile time) and `-Werror=format-security`.

---

## 5.2 Integer overflow / underflow leading to memory corruption

### What / why
Integers are **fixed-width and wrap around**. An arithmetic result that exceeds
the type silently wraps. When that result is a **size or index**, it becomes a
memory bug.

```c
unsigned len = a + b;          // can wrap to a small number
char *p = malloc(len);         // too-small allocation
memcpy(p, src, a + b);         // ...copy uses the real (large) amount -> overflow
```

Signed overflow is **undefined behavior**; unsigned wraps modulo 2ⁿ. A very
common shape is `size - header_len` underflowing to a huge value when `size <
header_len`.

### Test cases
```c
// intof.c
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
void copy(uint16_t count) {           // count is 16-bit
    uint16_t total = count * 4;       // count=20000 -> 80000 wraps in 16 bits
    char *buf = malloc(total);        // allocates the wrapped (small) size
    memcpy(buf, src, count * 4);      // copies the intended large size -> OOB
}
```
Another: an attacker sends `length = 0`, code does `length - 1` on an unsigned
type → `0xFFFFFFFF`, used as a loop bound → massive overrun.

### Fix
- Use `calloc(count, size)` (checks the multiply) or explicit overflow checks
  (`if (count > SIZE_MAX / size) error;`), or builtins
  `__builtin_mul_overflow` / `__builtin_add_overflow`.
- Validate lengths against sane maxima *before* arithmetic.
- Compile with `-fsanitize=undefined` (UBSan) to catch signed overflow, and
  `-ftrapv`/`-fwrapv` as appropriate. Prefer `size_t` for sizes and check bounds.

---

## 5.3 Off-by-one errors

### What / why
A loop or index that is off by one byte/element: `<=` instead of `<`, forgetting
the NUL terminator's byte, `n+1` writes.

```c
char buf[16];
strncpy(buf, src, sizeof buf);   // may NOT NUL-terminate if src is 16+ long
buf[strlen(buf)] = 0;            // strlen walks off the end -> OOB read
// or:
for (i = 0; i <= n; i++) ...     // writes element [n], one past
```

### Why it matters
A single byte overwritten can be devastating when it's:
- the **low byte of a size field** (heap) → allocator confusion;
- the **low byte of a saved RBP** (stack) → frame-pointer pivot;
- a **NUL terminator** written one past a buffer ("off-by-one NUL") — a famous
  exploitable pattern.

### Fix
Off-by-one is a *discipline* bug: use `< size`, reserve room for the NUL
(`size-1` payload), prefer `snprintf`, and let ASan catch the rest.

---

## 5.4 Out-of-bounds (OOB) read — information disclosure

### What / why
Reading past (or before) the bounds of a buffer. No corruption — but it **leaks**
adjacent memory: other users' data, pointers (→ defeat ASLR), keys.

```c
// oob_read.c  -- the Heartbleed shape
char buf[256];
int n;
read_from_network(&n, buf);     // attacker controls n (a claimed length)
send_to_network(buf, n);        // echoes n bytes -- but buf holds <256 valid
```

**Heartbleed (CVE-2014-0160)** was exactly this: OpenSSL echoed back a client-
supplied length without checking it against the actual payload size, leaking up
to 64 KB of server memory per request (including private keys).

### Test case
```c
int arr[8] = {0};
int idx; scanf("%d", &idx);
printf("%d\n", arr[idx]);        // idx=100 reads far past arr -> leak
```

### Fix
Always validate the index/length against the **real** buffer size before using
it. Clamp (`n = min(n, valid_len)`), reject invalid input, and test with ASan
(detects OOB read) and bounds-checked containers.

---

## 5.5 Uninitialized memory use

### What / why
Reading a variable or heap buffer before it's been written. Its contents are
**whatever was there before** — stack garbage or a previous heap object's
leftovers (which may be *another user's secret*).

```c
// uninit.c
void f(void) {
    char buf[64];                 // not zeroed
    int n = strlen(buf);          // reads garbage; also may OOB if no NUL
    struct S s;                   // s.ptr uninitialized
    s.use();                      // uses an indeterminate pointer
}
```
`malloc` (unlike `calloc`) does **not** zero memory — a freshly malloc'd buffer
can contain a freed object's bytes. Sending that over the network = info leak.

### Fix
Initialize at declaration (`char buf[64] = {0};`, `struct S s = {0};`), use
`calloc`, and never send/compare uninitialized bytes. **MemorySanitizer**
(`-fsanitize=memory`, Clang) is purpose-built to find these; `-Wuninitialized`
catches the easy cases.

---

## 5.6 NULL-pointer dereference

### What / why
Dereferencing a `NULL` (or near-NULL) pointer, usually from an unchecked
allocation failure or an unhandled error path. In **user space** this is almost
always just a **crash/DoS** (page 0 is unmapped). In the **kernel**, historically,
a NULL deref could be exploited if an attacker could `mmap` page 0 — now blocked
by `mmap_min_addr`, so it's mostly a DoS there too, but still a reliability bug.

```c
char *p = malloc(huge);   // returns NULL on failure
p[0] = 'x';               // NULL deref -> crash
```

### Fix
Check every allocation and error return; don't deref before validating. Static
analyzers and `-fsanitize=null` (UBSan) flag these.

---

## 5.7 Double free (recap / placement)

Covered in Chapter 4 as a lifetime bug. Mentioned here for completeness: it's
both a lifetime bug *and* a heap-metadata-corruption bug. Fix: `free; ptr=NULL`,
single ownership, smart pointers.

---

## 5.8 Stack exhaustion / unbounded recursion

### What / why
Unbounded recursion or a huge `alloca`/VLA grows the stack past its limit into
the guard page → crash, or (without a guard page, historically "Stack Clash")
into the heap/other mappings → corruption.

```c
void rec(int n){ char big[1<<16]; rec(n+1); }   // blows the stack
int vla(int n){ char buf[n]; ... }               // n attacker-controlled
```

### Fix
Bound recursion depth, avoid attacker-sized VLAs/`alloca`, use heap with checks.
Modern GCC/kernel use **stack guard pages / `-fstack-clash-protection`**.

---

## Chapter 5 recap — the quick field guide

| Bug | One-line tell | Primary impact | First-line fix |
|-----|---------------|----------------|----------------|
| Format string | `printf(userdata)` | leak + arbitrary write (`%n`) | `printf("%s", userdata)` |
| Integer overflow | `malloc(a*b)`, `len-1` unsigned | undersized alloc → overflow | `calloc`, overflow checks |
| Off-by-one | `<=`, forgot NUL | 1-byte metadata corruption | `< size`, reserve NUL |
| OOB read | echo attacker length | info disclosure (Heartbleed) | validate length vs real size |
| Uninitialized | use before set; `malloc` not zeroed | info leak, UB | `={0}`/`calloc`, MSan |
| NULL deref | unchecked `malloc`/error | DoS (crash) | check returns |
| Stack exhaustion | unbounded recursion/VLA | crash/corruption | bound depth, guard pages |

Next: the defenses that make all of the above hard — and how attackers adapt.
**[Chapter 6: Mitigations & how they're bypassed »](06-mitigations.md)**
