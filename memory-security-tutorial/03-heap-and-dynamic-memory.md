# Chapter 3 — The Heap & Dynamic Memory

> The stack is simple and automatic. The heap is a *managed* data structure with
> its own bookkeeping — and that bookkeeping is itself memory you can corrupt.

---

## 3.1 What the heap is

The **heap** is the region for allocations whose size or lifetime isn't known at
compile time:

```c
char *p = malloc(100);   // ask the allocator for 100 bytes
...
free(p);                 // give them back
```

`malloc`/`free` (and C++ `new`/`delete`) are **library functions**, not CPU
instructions. On Linux, glibc's allocator is **ptmalloc2**. It carves big memory
regions (obtained via `brk`/`mmap` from the kernel) into **chunks** and tracks
which are free vs. in use. **That tracking metadata lives inline, right next to
your data** — which is the root of heap exploitation.

---

## 3.2 How glibc lays out a chunk

A malloc chunk looks like this (64-bit):

```
            +------------------------+
   chunk -> |  prev_size (8 bytes)   |  (only meaningful if prev chunk is free)
            +------------------------+
            |  size (8 bytes)        |  size of THIS chunk + 3 flag bits
            +------------------------+
 user ptr-> |  user data ...         |  <- malloc() returns THIS address
            |                        |
            +------------------------+
```

- The pointer `malloc` returns points at the **user data**, 16 bytes *after* the
  chunk start. The `size` field sits **just before** your data.
- The low 3 bits of `size` are **flags** (the sizes are always 16-aligned, so
  those bits are free): `PREV_INUSE (A)`, `IS_MMAPPED (M)`, `NON_MAIN_ARENA (N)`.
- When a chunk is **freed**, glibc reuses the user-data area to store **free-list
  pointers** (`fd`/`bk`, and for tcache a `next` pointer). So a dangling pointer
  into a freed chunk now points at *allocator pointers* — the mechanism behind
  many UAF exploits (Chapter 4).

### Free lists / bins (why reuse is predictable)

glibc keeps freed chunks in several lists so it can hand them back fast:

- **tcache** (per-thread cache, glibc ≥ 2.26): small, LIFO, very fast. The first
  thing beginners target today.
- **fastbins**: small fixed sizes, LIFO.
- **unsorted / small / large bins**: everything else.

The practical takeaway for a learner: **the last chunk you freed of a given size
is usually the next one `malloc` hands back.** This determinism is what makes
heap bugs exploitable — you can make a future allocation land on memory you still
have a stale pointer to.

Inspect it live:

```bash
gdb -q ./prog      # with pwndbg/GEF:
#   heap          -> list chunks
#   bins          -> show tcache/fastbins/etc
#   vis           -> visualize the heap
```

---

## 3.3 Heap buffer overflow

Same root cause as the stack version — writing past the end of a buffer — but now
the adjacent memory is **the next chunk's metadata** or **the next object**.

```c
// heapof.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char *a = malloc(16);
    char *b = malloc(16);          // likely adjacent, just above `a`
    printf("a=%p b=%p (diff=%ld)\n", a, b, b - a);

    strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); // 32 'A's into a 16-byte buf
    // we've now written into b's chunk header and b's data
    printf("b now = %s\n", b);
    free(a); free(b);              // may crash: b's metadata corrupted
    return 0;
}
```

```bash
gcc -g -O0 heapof.c -o heapof && ./heapof
```

Two distinct damage modes:

1. **Data corruption of the next object.** If `b` is, say, a struct holding a
   function pointer or a length or an "is_admin" flag, overflowing `a` rewrites
   it. No allocator tricks needed — this is the most common *real-world* heap
   overflow and the easiest to reason about.

2. **Metadata corruption.** Overwriting the next chunk's `size` or free-list
   pointers tricks the allocator itself. Classic techniques (mostly of
   historical/CTF interest, hardened against over the years):
   - **unlink exploit** — corrupt `fd`/`bk` so `unlink()` does an arbitrary
     write.
   - **House of Force / Spirit / Einherjar / Orange** — a whole family of
     "House of ___" techniques that abuse specific allocator invariants.
   - **tcache poisoning** — overwrite a freed chunk's `next` pointer so a later
     `malloc` returns an **arbitrary address** (today's most common CTF heap
     primitive; see Chapter 4).

---

## 3.4 Test cases

### (a) Overflow into an adjacent object's function pointer

```c
// obj_overflow.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct widget { char name[16]; void (*action)(void); };
void normal(void) { puts("normal action"); }
void danger(void) { puts("DANGER: hijacked function pointer!"); }

int main(int argc, char **argv) {
    struct widget *w = malloc(sizeof *w);
    w->action = normal;
    // BUG: copies attacker data into name[] with no bound, runs into action
    strcpy(w->name, argv[1]);
    w->action();               // calls whatever `action` now points to
    free(w);
    return 0;
}
```

Overflowing `name` past 16 bytes overwrites `action`. Feed it the address of
`danger` (or any gadget) and the indirect call is hijacked. This is the heap
analogue of the stack return-address overwrite — **a corrupted code pointer**.

### (b) Length field corruption → secondary overflow

```c
struct buf { size_t len; char data[32]; };
// overflow of a PRECEDING allocation into this struct's `len`
// makes later `memcpy(dst, src, b->len)` copy a huge attacker-chosen size.
```

Corrupting a size/length used by a later copy turns a small overflow into a big
one. Watch for this pattern in code review.

### (c) Integer overflow in the size argument (ties to Chapter 5)

```c
void *p = malloc(count * size);   // count*size can wrap to a tiny value
memcpy(p, src, count * size);     // ...but copy uses the real (huge) amount
```

`malloc(a * b)` where `a*b` overflows `size_t` allocates too little, then the
copy overflows the heap. **Use `calloc(count, size)`** (it checks for overflow)
or validate the multiplication.

---

## 3.5 Impact

- Overwriting an **adjacent object** → corrupt flags, lengths, or **function
  pointers / C++ vtables** → control flow or logic bypass.
- Overwriting **allocator metadata** → eventually an **arbitrary write**
  primitive → full compromise.
- Combined with an info leak to defeat ASLR, heap bugs give reliable remote code
  execution. Think browser/kernel exploits — most modern RCE chains are heap
  bugs, not stack ones, because stacks are so well-defended now.

---

## 3.6 The fix

- **Bound every copy to the allocation size** (same `snprintf`/`memcpy`-with-n
  discipline as the stack).
- **Track sizes explicitly**; never trust a length that came from input without
  validating it against the real buffer.
- **Use `calloc` / overflow-checked multiplication** for `count * size`.
- **Zero or poison freed memory** where it matters; set pointers to `NULL` after
  `free` (helps with UAF, Chapter 4).
- In C++, prefer `std::vector`/`std::string` and `.at()` (bounds-checked) over
  raw arrays and pointers.
- Build with the allocator's own hardening: glibc checks (`MALLOC_CHECK_`,
  `tcache` key checks in modern glibc), and run under **ASan** during testing —
  it detects heap overflows and UAF immediately with a precise report.

```c
// safe version of obj_overflow.c
snprintf(w->name, sizeof w->name, "%s", argv[1]);   // can't reach ->action
```

---

## Chapter 3 recap

- The heap is managed by **malloc/free** using **inline metadata** (`size`,
  free-list pointers) stored right next to your data.
- Allocation reuse is **deterministic** (tcache/fastbins LIFO), which is what
  makes heap bugs exploitable.
- A heap overflow corrupts either the **next object** (often a function pointer
  or length) or **allocator metadata** (→ arbitrary write via tcache poisoning,
  unlink, House-of-*).
- Fix with bounded copies, explicit size tracking, `calloc`, and C++ containers;
  find them with ASan.

Next: the related — and today extremely common — lifetime bug.
**[Chapter 4: Use-after-free & dangling pointers »](04-use-after-free.md)**
