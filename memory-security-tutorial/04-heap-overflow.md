# Chapter 4 — Heap Overflows & Corruption (10 test cases)

> Same root cause as the stack overflow — writing past a buffer — but now the
> adjacent memory is **another object** or **allocator metadata**.

---

## 4.0 In plain words (start here)

A heap overflow is the exact same mistake as Chapter 2 — writing more into a
buffer than it can hold — except the buffer lives in a **heap locker**
(Chapter 3) instead of on the stack. So what gets trampled is different:

- On the **stack**, overflowing hit the saved return address (a clear "win" for
  an attacker).
- On the **heap**, there is no return address next door. Instead you hit either
  **(a)** the *next object* sitting just above you in the storeroom, or **(b)**
  the clerk's *metadata tag* for the next locker.

Case (a) is the most common and the easiest to reason about: if the object next
to yours happens to hold a **function pointer**, a **length**, or an
**"is_admin" flag**, your overflow rewrites it, and now the program calls your
address / copies your size / treats you as admin. Case (b) corrupts the clerk's
bookkeeping, which is more powerful but needs the allocator knowledge from
Chapter 3 (and the techniques in Chapter 5).

One extra wrinkle vs. the stack: heap lockers aren't laid out in a fixed order
you can assume. So real heap exploitation includes **"grooming"** — making a
careful sequence of `malloc`/`free` calls so the object you want to corrupt ends
up right after the buffer you can overflow. The test cases below focus on the
corruption itself; grooming is covered in Chapters 5–6.

Keep Chapter 3's picture in mind: your data, then (just above) the next chunk's
**metadata tag**, then the next object. Overflow walks through them in that
order.

---

## 4.1 Why the heap version is different

- No single "return address" sits next to a heap buffer. Instead you corrupt:
  1. **the next object's data** (flags, lengths, **function pointers / C++
     vtables**) — easiest, most common in the real world; or
  2. **the next chunk's metadata** (`size`, `prev_size`, `fd/bk/next`) — tricks
     the allocator itself into an arbitrary write (Chapter 5).
- Heap layout is less rigid than the stack, so attackers **groom** the heap
  (allocate/free in a pattern) to place the victim right after the overflowing
  buffer.

---

## 4.2 Test case 1 — overflow into the next object's data

```c
// h01_adjacent.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    char *a = malloc(24);
    char *b = malloc(24);                 // physically just above a
    printf("a=%p b=%p gap=%ld\n", a, b, b-a);
    strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");  // 32 bytes into 24
    printf("b = %s\n", b);                 // b now shows spilled 'A's
    free(a); free(b);
}
```
**Walk it with the chunk picture from Chapter 3.** `malloc(24)` twice gives two
lockers of chunk size `0x20`, and because the allocator carves them from the same
region in order, `b` sits right above `a` (the program prints `gap` to show this;
it's typically `0x20`). Memory looks like:

```
   a's user data (24 bytes)  |  b's chunk header (prev_size,size)  |  b's user data
   ^ strcpy starts here, writing 32 'A's -----------> runs through all of this
```

`strcpy(a, <32 A's>)` writes 32 bytes starting at `a`. The first 24 fill `a`'s
own locker; bytes 24–31 spill **past `a`**, first over `b`'s chunk header (the
`size`/`prev_size` metadata the clerk uses) and then into `b`'s user data — which
is why `printf("b = %s")` now shows `A`s even though nobody wrote to `b`.

**Why it matters:** there's no return address up here (that's the stack), but `b`
is a *real object the program will use later*. If `b` holds a length, a flag, a
pointer, or (next test case) a function pointer, the overflow just handed its
contents to the attacker. And because you also trampled `b`'s chunk header, the
later `free(b)` may abort with "corrupted size vs. prev_size" — the allocator
noticing its bookkeeping was wrecked. (Try uncommenting the frees to see it.)

**Fix:** write no more than the locker holds — `memcpy(a, src, n <= 24 ? n : 24)`
— and track sizes explicitly; prefer `calloc` for arrays (Chapter 3).

---

## 4.3 Test case 2 — overwrite an adjacent function pointer (heap "ret2win")

```c
// h02_fnptr.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct widget { char name[16]; void (*action)(void); };
void normal(void){ puts("normal"); }
void danger(void){ puts("DANGER: hijacked heap function pointer!"); }
int main(int c, char **v){
    struct widget *w = malloc(sizeof *w);
    w->action = normal;
    strcpy(w->name, v[1]);        // >16 bytes overwrites w->action
    w->action();                  // calls whatever action now points to
    free(w);
}
```
```bash
gcc -g -O0 h02_fnptr.c -o h02
objdump -d h02 | grep '<danger>:'
./h02 $(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*16+b"\x?? ...")')
```
**Why this is the heap's version of ret2win.** The struct `widget` places a
buffer `name[16]` immediately before a **function pointer `action`** (fields are
laid out in declaration order, Chapter 2 test 12). So the single locker for `w`
looks like: `[ name: 16 bytes ][ action: 8 bytes ]`. `strcpy(w->name, v[1])` with
no bound writes past `name` straight into `action`. The attacker supplies 16
filler bytes then the 8-byte address of `danger` (little-endian), and the very
next line, `w->action()`, calls it.

Notice there was **no `free`, no return address, no stack** involved — just one
heap object whose code pointer sits after an overflowable buffer. This is exactly
how it works in C++ too, except the code pointer is the object's hidden **vtable
pointer** at offset 0 (Chapter 10), which is why heap overflows and
use-after-frees so reliably become code execution in browsers.

**The payload (why the bytes look the way they do):**
```bash
objdump -d h02 | grep '<danger>:'        # e.g. 0000000000401162 <danger>:
./h02 "$(python3 -c 'import sys,struct; sys.stdout.buffer.write(b"A"*16 + struct.pack("<Q", 0x401162))')"
```
16 `A`s reach `action`; `struct.pack("<Q", addr)` writes the 8-byte
little-endian address over it. (Built `-no-pie` so `danger`'s address is fixed.)

**Fix:** `snprintf(w->name, sizeof w->name, "%s", v[1])` so the write can never
reach `action`; put pointers before buffers; and `-fsanitize=cfi` aborts a call
through a corrupted pointer.

---

## 4.4 Test case 3 — length-field corruption → secondary overflow

```c
// h03_lenfield.c
struct buf { size_t len; char data[32]; };
void grow(struct buf *b, char *src){
    memcpy(b->data, src, b->len);   // if a PRECEDING overflow set b->len huge...
}
```
**The two-step amplification.** On its own this `grow` function looks safe — it
copies exactly `b->len` bytes, a bound. The danger is that `b->len` lives in heap
memory, so a *different* bug (an overflow of whatever object sits just below this
`struct buf`) can first overwrite `b->len` with a huge value. Then this
"well-behaved" `memcpy(b->data, src, b->len)` copies that huge amount → a massive
heap overflow — and the code that does it contains no obvious bug at all.

This is why length/size fields stored in attacker-reachable memory are dangerous:
a tiny initial overflow (even one byte, next test case) that changes a length
becomes a *large* controlled overflow at the point the length is used. Auditors
learn to flag "a size read from a struct that another buffer could overflow
into."

**Fix:** keep lengths out of overflowable reach where possible, re-validate a
size against the real buffer capacity right before using it
(`if (b->len > sizeof b->data) abort();`), and don't trust any in-memory length
you didn't just compute yourself.

---

## 4.5 Test case 4 — off-by-one / poison NUL byte

```c
// h04_poison_nul.c
char *a = malloc(0x18);        // chunk size 0x20, usable 0x18
char *b = malloc(0x18);
strcpy(a, big_24_byte_string); // writes a[0..23]; a[24] = '\0' is 1 past
                               // -> clears the low byte of b's size field
```
**How one byte becomes a weapon.** A very common off-by-one is writing the string
terminator one byte too far: you fill a 24-byte (`0x18`) buffer with a 24-byte
string and `strcpy` also writes the `'\0'` at index 24 — one past the end. From
Chapter 3, the byte right after `a`'s user data is the **low byte of the next
chunk's `size` field**. Recall a `size` of `0x21` means "chunk size `0x20`, with
the PREV_INUSE bit set." Overwriting its low byte with `0x00` turns `0x21` into
`0x00` (or, in the classic version, clears just the PREV_INUSE bit), corrupting
the allocator's idea of chunk sizes and whether the previous chunk is in use.

**Why attackers love it.** By lying about a chunk's size or its "previous chunk
is free" bit, the attacker tricks `free`/`malloc` into **merging or overlapping
chunks** — ending up with two allocations that share memory (an "overlapping
chunks" primitive, Chapter 5). From there they edit one allocation to rewrite the
other's header / function pointer / length. Whole published exploits ("poison
null byte," House of Einherjar) are built from this *single* out-of-bounds NUL.

**The lesson for a defender:** on the heap, an off-by-one is **not** a minor
cosmetic bug — one byte into the allocator's metadata is a real exploitation
primitive. Reserve room for the terminator (`strcpy` needs `size-1` of payload),
use `snprintf`, and test with ASan, which flags the single-byte write instantly.

---

## 4.6 Test case 5 — integer overflow in the size (undersized alloc)

```c
// h05_intmul.c
void *make(size_t count, size_t size){
    void *p = malloc(count * size);   // count*size wraps -> tiny allocation
    for (size_t i=0;i<count;i++) ((char**)p)[i] = 0;  // writes count*size bytes
    return p;                                          // -> heap overflow
}
```
`malloc(0x100000000 * 0x10)` on 64-bit, or any 32-bit `count*size` that wraps,
allocates far less than the loop writes. **Use `calloc(count,size)`** (it detects
the overflow and fails) or check `count > SIZE_MAX/size` first. (Full treatment:
Chapter 8.)

---

## 4.7 Test case 6 — overflow via `realloc` size confusion

```c
// h06_realloc.c
char *p = malloc(64);
size_t n = get_len();            // attacker-influenced
p = realloc(p, n);               // if n==0: glibc frees p and returns NULL/min
memcpy(p, src, 64);              // but code still assumes 64 bytes -> overflow
```
`realloc` with a smaller size shrinks the usable region; code that still writes
the old size overflows. `realloc(p,0)` is also a trap (frees `p`). Always use the
*new* size and check the return.

---

## 4.8 Test case 7 — `strcat` onto a heap buffer

```c
// h07_strcat.c
char *msg = malloc(32);
strcpy(msg, prefix);          // prefix 20 bytes
strcat(msg, user_suffix);     // appends with no remaining-size check -> overflow
```
Same family as the stack `strcat`, but corrupts heap metadata/objects. Track the
remaining space: `strncat(msg, suf, 32 - strlen(msg) - 1)` or `snprintf`.

---

## 4.9 Test case 8 — array of pointers overflow (write-what-where seed)

```c
// h08_ptrarray.c
char **arr = malloc(4 * sizeof(char*));   // 4 slots
for (int i=0;i<n;i++) arr[i] = strdup(lines[i]);  // n>4 overflows the array
```
Overflowing an array of **pointers** is especially powerful: subsequent code
*dereferences* those slots, so corrupting them yields controlled reads/writes.

---

## 4.10 Test case 9 — mismatched allocation vs. use size

```c
// h09_sizemismatch.c
struct hdr { int type; int len; };
struct hdr *h = malloc(sizeof(int));   // only 4 bytes allocated...
h->len = 0;                            // ...but writing 8 bytes (two ints) -> OOB
```
Allocating for the wrong type/size (`sizeof(int)` instead of `sizeof(*h)`) is a
subtle, common overflow. Prefer `malloc(sizeof *h)` (the dereferenced form) so the
size always matches the pointer's type.

---

## 4.11 Test case 10 — `calloc` vs `malloc` for zeroing (and its overflow check)

```c
// h10_calloc.c
// BAD: malloc leaves garbage AND no overflow check on the multiply
int *v = malloc(n * sizeof(int));
// GOOD: calloc zeroes AND rejects n*sizeof(int) overflow (returns NULL)
int *v2 = calloc(n, sizeof(int));
```
`calloc` gives you two defenses at once: zero-initialization (kills the
uninitialized-read infoleak, Chapter 9) and a built-in multiply-overflow check.
Prefer it for arrays.

---

## 4.12 Impact

- Corrupt an **adjacent object** → flip flags, resize buffers, hijack **function
  pointers / vtables** → control flow or logic bypass.
- Corrupt **allocator metadata** → an **arbitrary write** primitive → full
  compromise (Chapter 5).
- Combined with an **info leak** (defeat ASLR), heap bugs give reliable RCE.
  Modern browser/kernel exploits are overwhelmingly heap bugs, because stacks are
  so well defended now.

---

## 4.13 The fixes

- **Bound every copy to the allocation size**; recompute remaining space for
  appends.
- **Track sizes explicitly**; never trust a length from input or from
  corruptible heap memory without re-validating.
- **`calloc` / checked multiplication** for `count * size`; **`sizeof *p`** for
  allocation.
- **`free(p); p = NULL;`** to blunt UAF/double-free (Chapters 5–6).
- C++: prefer `std::vector`/`std::string` and `.at()` over raw buffers.
- Build/test with **ASan** (`-fsanitize=address`) — detects heap overflow, with
  the exact chunk and both allocation/overflow stack traces; harden production
  with `MALLOC_CHECK_`, GWP-ASan, scudo, or hardened_malloc.

```c
snprintf(w->name, sizeof w->name, "%s", v[1]);   // h02 fix: can't reach ->action
```

---

## Recap
- Heap overflow corrupts **the next object** (often a function pointer/length) or
  **chunk metadata**; off-by-one is a real one-byte primitive on the heap.
- Ten shapes here: adjacent data, function pointer, length field, poison-NUL,
  int-mul, realloc, strcat, pointer array, size mismatch, calloc.
- Fix with bounded copies, explicit sizes, `calloc`, `sizeof *p`, and ASan.

Next, how corrupted metadata becomes an arbitrary write:
**[Chapter 5 — Heap exploitation techniques »](05-heap-techniques.md)**
