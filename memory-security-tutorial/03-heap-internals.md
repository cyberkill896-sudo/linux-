# Chapter 3 — The Heap & Dynamic Memory (internals)

> The stack is automatic and simple. The heap is a *managed data structure* whose
> bookkeeping lives right next to your data — and that bookkeeping is itself
> corruptible. You must understand the allocator before the heap bugs make sense.

Target allocator: **glibc ptmalloc2** (Linux default). jemalloc/tcmalloc/musl
differ in detail but share the ideas.

---

## 3.0 In plain words (start here)

In Chapter 1 the **stack** was automatic: locals appear when a function is
entered and vanish when it returns, and the CPU manages it with `rsp`. But often
a program doesn't know *at compile time* how much memory it needs, or needs some
memory to outlive the function that created it (e.g. "load a file of unknown
size and keep it around"). For that it uses the **heap**.

Think of the heap as a big storeroom, and `malloc`/`free` as the **clerk** who
hands out lockers:

- `p = malloc(100)` = "clerk, give me a locker big enough for 100 bytes." The
  clerk finds space, and hands you a key (`p`, a pointer to your locker).
- `free(p)` = "I'm done with this locker, take it back." The clerk marks it
  available so it can be handed to the next request.

Here's the catch that makes the heap a security topic: to track which lockers are
free, how big each is, and which free locker comes next, the clerk scribbles
**bookkeeping notes on little tags attached to each locker — and those tags sit
right next to your data**. This bookkeeping is called **chunk metadata**.

Two consequences follow, and they power all of Chapters 4–6:

1. If you **write past the end of your locker**, you scribble over the *next*
   locker's tag (or its contents). Now the clerk's notes are wrong — and an
   attacker chose what they say. (Heap overflow, Chapter 4.)
2. The clerk's behavior is **predictable**: hand back a locker and the very next
   same-size request usually gets that exact locker again. That predictability is
   what lets an attacker arrange for memory to be reused in a way they control
   (use-after-free and the techniques in Chapters 5–6).

This chapter is the "how the clerk actually works" reference. It's the most
mechanical chapter in the course; you don't need to memorize every bin, but you
*do* need the chunk picture (§3.2) and the idea that **freed memory gets reused
predictably** (§3.3). Skim the rest and come back when a later chapter needs it.

Glossary for this chapter:
- **chunk** — one locker: your data plus its metadata tag.
- **metadata** — the clerk's notes stored next to your data (size, flags, and,
  once freed, links to other free chunks).
- **bin / free list** — the clerk's lists of available lockers, grouped by size.
- **tcache** — a small, fast per-thread list of recently freed lockers, checked
  first (modern glibc). This is the one beginners meet most.

---

## 3.1 malloc/free are library code, not CPU instructions

```c
char *p = malloc(100);   // library asks kernel for memory, carves a chunk
free(p);                 // library returns the chunk to a free list
```

The library obtains big regions from the kernel via **`brk`/`sbrk`** (grows the
heap segment) or **`mmap`** (for large requests, ≥ ~128 KB by default), then
subdivides them into **chunks**.

```bash
strace -e trace=brk,mmap ./prog 2>&1 | head   # watch the kernel calls
```

---

## 3.2 Chunk layout (the critical diagram)

A 64-bit malloc chunk:

```
            +------------------------+
   chunk -> |  prev_size  (8 B)      |  usable as user data of the PREVIOUS
            |                        |  chunk when prev is in use (overlap trick)
            +------------------------+
            |  size       (8 B)      |  size of THIS chunk | 3 flag bits
            +------------------------+
 user ptr-> |  fd / user data        |  <- malloc() RETURNS this address
            |  bk / user data        |     when freed, fd/bk store free-list links
            |  ...                    |
            +------------------------+
```

- `malloc` returns a pointer **16 bytes past** the chunk start; the **`size`
  field sits 8 bytes before** the returned pointer. (`chunk = user_ptr - 16`.)
- Chunk sizes are **16-byte aligned**, so the low 3 bits of `size` are free for
  **flags**:
  - **`PREV_INUSE` (0x1)** — is the *previous* chunk in use? (If 0, `prev_size`
    is valid and this chunk can be consolidated backward.)
  - **`IS_MMAPPED` (0x2)** — chunk came from `mmap`.
  - **`NON_MAIN_ARENA` (0x4)** — belongs to a non-main arena (threads).
- Minimum chunk is 32 bytes; a `malloc(1)` and `malloc(24)` both yield a 32-byte
  chunk (usable size 24). This rounding is why small overflows often still land
  in the next chunk's header.

When a chunk is **freed**, glibc **reuses the user-data area** to store
free-list pointers (`fd`, `bk`, and for tcache a `next`/`key`). So a dangling
pointer into a freed chunk now aliases *allocator pointers* — the mechanism
behind UAF and tcache poisoning (Chapters 5–6).

---

## 3.3 Bins: the free lists (why reuse is predictable)

Freed chunks are sorted into bins for fast reuse. **Determinism here is what makes
heap bugs exploitable** — you can predict which chunk the next `malloc` returns.

| Bin | Sizes (64-bit) | Order | Notes |
|-----|----------------|-------|-------|
| **tcache** | ≤ 1032 B, 64 bins, 7 chunks each | **LIFO** (singly linked via `next`) | per-thread, no locking, checked first (glibc ≥ 2.26). Today's #1 target. |
| **fastbins** | ≤ 160 B, singly linked | **LIFO** | fast, chunks keep `PREV_INUSE` set (not consolidated) |
| **unsorted bin** | any | FIFO-ish | staging area after free before sorting |
| **small bins** | < 1024 B, exact-size | FIFO (doubly linked) | |
| **large bins** | ≥ 1024 B, size ranges | sorted | split/coalesce |
| **top chunk** | the "wilderness" | — | the big remaining region; served when no bin fits |

Key consequences to internalize:

- **The last chunk you freed of a given size is usually the next one handed
  back.** (tcache/fastbin LIFO.) This lets you make a *future* allocation land on
  memory you still have a stale pointer to.
- A freed tcache chunk stores `next` = pointer to the next free chunk of that
  size. Corrupt `next` → control where the *2nd* malloc returns (**tcache
  poisoning**).
- fastbins never consolidate immediately, so a **fastbin dup** (freeing the same
  chunk twice) puts it on the list twice.

**Why "determinism" is the whole game — the deep point.** An exploit needs to
*predict and control* which memory `malloc` returns. If allocation were random,
use-after-free and the techniques in Chapters 5–6 wouldn't work. But the bins
make it predictable in two ways the attacker exploits:

1. **Reuse is positional and immediate (LIFO).** `free(x); ... y = malloc(same
   size)` returns `x`'s *exact* address, right now, no randomness. So an attacker
   can free a victim object and *immediately* reclaim its slot with an object
   they control (the "reclaim" of Chapter 6), knowing precisely where it lands.
2. **Same size ⇒ same bin ⇒ same slot.** Objects are binned by size, so to reuse
   a freed object's memory you allocate something of the **same size class**.
   This is why real exploits talk about "a spray object of the right size" — they
   pick an allocation whose size matches the victim's so it draws from the same
   bin. (In the kernel, Chapter 14, this is choosing `msg_msg`/`sk_buff` of the
   victim's size.)

So the allocator's performance optimizations — caching freed chunks and handing
the hottest one back first — are *exactly* what give an attacker a reliable,
predictable building block. Every heap technique in Chapter 5 and every UAF in
Chapter 6 rests on this determinism; the hardening in later glibc (randomized
bins, Safe-Linking) is partly an attempt to claw some unpredictability back.

---

## 3.4 Consolidation (coalescing) and `top`

When you free a chunk whose physical neighbor is also free, glibc **merges**
them (via `unlink` for doubly-linked bins) to fight fragmentation, using the
`prev_size`/`PREV_INUSE` fields. Corrupting those fields is how classic
**unlink** and **House of ___** attacks trick the allocator into writing where
the attacker wants (Chapter 5).

---

## 3.5 See it live (do this before Chapters 4–6)

```c
// heapwalk.c
#include <stdlib.h>
#include <string.h>
int main(void){
    char *a = malloc(24);  strcpy(a, "AAAA");
    char *b = malloc(24);  strcpy(b, "BBBB");
    char *c = malloc(24);
    free(b);               // b -> tcache[0x20]
    free(a);               // a -> tcache[0x20] (now head; next -> b)
    char *d = malloc(24);  // returns a (LIFO) -- SAME address as a
    return (int)(size_t)(a==d);
}
```
```bash
gcc -g -O0 heapwalk.c -o heapwalk
gdb -q ./heapwalk      # with pwndbg/GEF:
```
```gdb
(gdb) break 12
(gdb) run
(gdb) heap            # list all chunks with sizes/flags
(gdb) bins            # show tcache/fastbins contents
(gdb) x/8gx a-16      # dump a's chunk header: prev_size | size | fd ...
(gdb) vis             # (pwndbg) color-coded heap visualization
```

Watch, after the two `free`s, `tcache[0x20]` hold `a -> b`, and confirm the next
`malloc(24)` returns `a`'s exact address. *Seeing* the LIFO reuse is what makes
every later technique intuitive.

### Reading a chunk header in a hexdump

```
0x5555...010:  0x0000000000000000  0x0000000000000021   <- prev_size | size(0x20|PREV_INUSE=1)
0x5555...020:  0x0000000041414141  0x0000000000000000   <- user data ("AAAA")
```
`0x21` = size `0x20` with the low bit (`PREV_INUSE`) set. Recognizing `0x21`,
`0x31`, `0x41`… as "size + in-use flag" is an essential heap-reading skill.

---

## Recap
- Heap memory is carved into **chunks** with inline metadata (`size` + flags,
  and `fd/bk/next` reused when freed).
- Freed chunks go to **tcache/fastbins/unsorted/small/large** bins; **LIFO reuse
  is deterministic**, which is what makes heap bugs exploitable.
- `malloc` returns `chunk+16`; `size` is at `user_ptr-8`; `0x21`-style values =
  size|flags.
- Learn to read chunks with `heap`/`bins`/`vis` in GDB now.

Next: **[Chapter 4 — Heap overflows & corruption »](04-heap-overflow.md)**
