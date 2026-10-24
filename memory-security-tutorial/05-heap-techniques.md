# Chapter 5 — Heap Exploitation Techniques

> How a heap bug (overflow, UAF, double-free) becomes a **write primitive** by
> abusing the allocator. These are the classic CTF/"how2heap" techniques. They
> are **version-sensitive** — glibc has hardened each over time — so treat them
> as concept education; the point is *how allocator invariants get abused*, not a
> copy-paste weapon. Study them in a lab against your own binaries.

Reference to replay these safely: shellphish's **how2heap** repo demonstrates
each against specific glibc versions with full commentary.

---

## 5.0 In plain words (start here)

Chapter 4 showed a heap overflow corrupting a neighbor. This chapter answers the
next question: *once I can corrupt the clerk's bookkeeping (Chapter 3), how do I
turn that into real power?*

The goal of every technique here is to get one of two "superpowers," called
**primitives**:

- **arbitrary write** ("write-what-where") — make the program write a value *you
  choose* to an address *you choose*; or
- **arbitrary allocation** — trick `malloc` into handing you a locker at an
  address *you choose*, so you can then read/write there.

Either one is game over, because you aim it at something sensitive (a saved
return address, a function pointer the program will call, etc.) and overwrite it
with your target.

The common recipe is always the same four beats:
1. a **bug** (overflow / use-after-free / double-free) lets you corrupt some of
   the clerk's metadata — usually a chunk's size, or a **free-list link** (the
   "which free locker comes next" pointer);
2. you write a **lie** into that metadata;
3. the clerk, believing the lie, later hands you a locker where you want, or
   performs a write you control;
4. you aim that at a **target** and trigger it.

The named techniques (**tcache poisoning, fastbin dup, unlink, the "House of…"
family**) are just different *specific lies* for different allocator versions.
Two honest cautions for a beginner:

- These are **version-specific**. glibc keeps adding checks (Safe-Linking, tcache
  keys, size sanity checks), so a technique that worked on one glibc fails on the
  next. The *idea* (abuse an allocator invariant) is the durable lesson; the
  exact bytes are not.
- Modern techniques almost always need an **information leak first** (Chapter 7
  or 9) to learn a heap or libc address, because the newer checks compare against
  real addresses.

If you're new, read §5.1 (the mental model) and §5.2 (tcache poisoning — the one
beginners meet in CTFs), run `src/16_tcache_poison.c`, and treat the "House of…"
catalog as "know the name and the idea" until you need the depth.

---

## 5.1 The mental model

Every technique has the same shape:

1. A bug lets you **corrupt metadata** (a chunk `size`, or a free-list pointer
   `fd`/`bk`/`next`).
2. You make the allocator **believe a lie** about the heap.
3. A later `malloc` then returns a **pointer you control**, or a `free`/`unlink`
   performs a **write you control** — i.e. an **arbitrary write (write-what-
   where)**.
4. You aim that write at a **target**: a saved return address, a GOT entry (no
   Full RELRO), `__malloc_hook`/`__free_hook` (old glibc), `__exit_funcs`, a
   function pointer, or `stdout`'s vtable (FSOP).

With an arbitrary write + an info leak (Chapter 9) you get code execution.

---

## 5.2 tcache poisoning (the modern beginner technique)

glibc ≥ 2.26. A freed tcache chunk stores a **`next`** pointer (singly-linked
LIFO). If a bug lets you overwrite `next`, you choose where the **second** malloc
of that size returns.

**First, understand what the tcache free list *is*.** When you `free` a small
chunk, glibc doesn't scrub it — it repurposes the first 8 bytes of your old data
as a **`next` pointer** linking to the previous freed chunk of that size, and
stores the list head in a per-thread array. Allocation is just "unlink the head":
`malloc` returns the head chunk and sets the head to `head->next`. It's a plain
singly-linked stack (LIFO), and — crucially — **the links live inside the freed
chunks themselves**, i.e. in memory your bug may still be able to write.

**The poison, step by step** (map each line to the list state):

```
 free(a):        tcache[0x40] head -> a ,  a.next = NULL
 *(size_t*)a = &target:                     a.next = &target   (the LIE)
                 tcache[0x40] head -> a -> target   (allocator now believes
                                                     `target` is a free chunk!)
 x = malloc(0x30): returns a   ; head -> target
 y = malloc(0x30): returns &target        <-- malloc handed us a pointer we chose
```

The allocator never checks that `&target` is a real chunk it ever gave out — it
just trusts the `next` link it finds in a freed chunk. By overwriting that link
(via a use-after-free write or a heap overflow into the freed chunk), you make
the **second** `malloc` of that size return **any address you want**. Point it at
a GOT entry, a saved return address, `__free_hook` (old glibc), or a function
pointer, and the following write through `y` is your **write-what-where**.

That is the whole primitive: *the free list is attacker-writable, so you forge a
fake "next free chunk" and malloc hands it to you.*

```c
// tcache_poison.c  (educational; glibc with no/weak safe-linking)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    size_t target[4];                       // pretend this is a sensitive object
    printf("target @ %p\n", (void*)target);

    char *a = malloc(0x30);
    free(a);                                 // tcache[0x40]: head -> a, a.next = 0
    // BUG (UAF/overflow) overwrites a->next with &target:
    *(size_t*)a = (size_t)target;            // poison the `next` pointer

    char *x = malloc(0x30);                  // returns a (head)
    char *y = malloc(0x30);                  // returns &target  <-- arbitrary ptr!
    strcpy(y, "owned");                      // write into target
    printf("target[0]=%p\n", (void*)target[0]);
    return 0;
}
```

**Hardening you'll meet:**
- **Safe-Linking (glibc ≥ 2.32):** `next` is stored XOR-obfuscated with
  `(chunk_addr >> 12)`. You must leak a heap address to forge a valid `next`.
- **tcache key (glibc ≥ 2.29):** each freed tcache chunk stores a `key`; `free`
  checks it to catch immediate double-frees.
- **count checks (glibc ≥ 2.33+):** alignment and count sanity checks.

So the modern recipe needs a **heap leak** first — which is itself a good lesson
in why info leaks are half of exploitation.

---

## 5.3 fastbin dup (double-free into fastbins)

Fastbins are singly-linked LIFO and chunks keep `PREV_INUSE` (not consolidated).
Freeing the same chunk twice puts it on the list twice → two allocations alias →
forge a chunk.

```c
// fastbin_dup.c  (educational)
char *a = malloc(0x40);
char *b = malloc(0x40);
free(a);
free(b);        // needed: glibc forbids freeing the SAME chunk at the fastbin
free(a);        // top twice in a row -> interleave with b to bypass the check
// fastbin: a -> b -> a ...
char *x = malloc(0x40);   // = a
char *y = malloc(0x40);   // = b
char *z = malloc(0x40);   // = a again (duplicate!) -> x and z alias
```
glibc's "double free or corruption (fasttop)" check only compares against the
*current* top of the fastbin, hence the `a,b,a` interleave. Modern tcache makes
the tcache-dup variant even simpler (subject to the `key` check above).

---

## 5.4 Double-free → use the alias

```c
// double_free.c
char *p = malloc(32);
free(p);
free(p);        // same chunk on the free list twice
char *x = malloc(32);   // = p
char *y = malloc(32);   // = p (alias!)  -> writing x changes y's "object"
```
Two "independent" objects share memory → corrupt one via the other. Combined with
poisoning, the second allocation can be pointed anywhere. (glibc tcache `key`
aborts the naive immediate double-free; bypass needs clearing the key via another
bug.)

---

## 5.5 The unlink attack (classic, mostly historical)

Doubly-linked bins maintain `fd`/`bk`. Consolidation calls `unlink(P)`:

```c
// simplified glibc unlink
FD = P->fd;  BK = P->bk;
FD->bk = BK;      // *(FD + offsetof(bk)) = BK
BK->fd = FD;      // *(BK + offsetof(fd)) = FD   <-- two controlled writes
```
If an overflow sets `P->fd` and `P->bk`, `unlink` writes `BK` to `FD->bk` and
`FD` to `BK->fd` — an **arbitrary write**. The classic target was a GOT entry.

**Mitigation:** modern glibc adds the **unlink integrity check**
`FD->bk == P && BK->fd == P` (and size==prev_size), which defeats the naive
version. The modern variant forges those back-pointers to point at a controlled
location (a pointer to the chunk), which is why unlink today needs a pointer to
your own pointer — a neat illustration of how a one-line check reshapes a whole
technique.

---

## 5.6 "House of ___" family (overview)

A catalog of techniques, each abusing a specific allocator invariant. Know the
*idea* of each; depth is version-specific:

- **House of Force** — overflow the **top chunk's size** to `0xffff...ff`, so a
  huge `malloc(evil_size)` moves `top` to an arbitrary address; the next malloc
  returns there. (Killed by top-size sanity checks in glibc ≥ 2.29.)
- **House of Spirit** — `free()` a **fake chunk** you crafted in writable memory
  (e.g. on the stack) so a later malloc returns your fake chunk → controlled
  pointer. You must craft valid `size`/alignment and a valid *next* chunk header.
- **House of Einherjar** — abuse the **`PREV_INUSE` bit + `prev_size`** (a single
  off-by-one NUL byte is enough) to force backward consolidation into a fake
  chunk, yielding **overlapping chunks**.
- **House of Orange** — turn a top-chunk overflow into a freed chunk via
  `sysmalloc`, then do **FSOP** (file-stream-oriented programming) on `_IO_FILE`
  to get control via `stdout`'s vtable.
- **House of Lore / Botcake / Rabbit / Mind / Gods...** — later additions, each
  tuned to specific hardened glibc versions.

The meta-lesson: the allocator is a program with invariants; every "House" is a
proof that violating one invariant yields a primitive. Hardening = adding checks
for those invariants.

---

## 5.7 Overlapping chunks (the unifying primitive)

Many techniques aim to make **two chunks overlap** — a single region the
allocator hands out as two "independent" objects. Then:
- allocate object A and victim B overlapping;
- edit A to rewrite B's **header / vtable / function pointer / length**;
- use B normally → it behaves on attacker data.

Overlap is created by corrupting a `size` (make a chunk "swallow" its neighbor),
by poison-NUL/Einherjar backward-consolidation, or by fastbin/tcache dup. It's the
heap's version of "two pointers to one object."

---

## 5.8 Where the write goes (targets) — and RELRO's effect

| Target | Needs | Blocked by |
|--------|-------|------------|
| GOT entry | **Partial** RELRO (GOT writable) | **Full RELRO** |
| `__malloc_hook`/`__free_hook` | glibc < 2.34 | removed in glibc ≥ 2.34 |
| saved return address | a stack leak | — |
| `_IO_FILE` vtable (FSOP) | file-stream leak | `_IO_vtable_check` |
| `__exit_funcs` (atexit) | glibc internals | PTR_MANGLE |
| app function pointer / vtable | know its address | CFI |

This table is why **Full RELRO** and the removal of malloc hooks mattered so
much: they deleted the easiest targets, pushing attackers toward FSOP and app
data.

---

## 5.9 A complete (conceptual) chain

```
heap overflow bug
   -> corrupt tcache `next` (tcache poisoning)      [primitive: arbitrary alloc]
   + heap leak (defeat Safe-Linking)                [from a UAF read / %p]
   + libc leak (defeat ASLR)                         [from an unsorted-bin fd, etc]
   -> malloc returns a chunk over __free_hook / a GOT entry / stdout vtable
   -> write system (or a one-gadget) there
   -> next free()/exit triggers system("/bin/sh")
```
Every real heap exploit is this pattern: **bug → metadata lie → controlled
alloc/write → aim at a target → trigger**. If you can narrate those five steps,
you understand heap exploitation.

---

## 5.10 Defenses (and how to not write these bugs)

- **Don't create the primitive:** no overflows (Chapter 4), no UAF/double-free
  (Chapter 6). Every technique here needs a bug first.
- **`free(p); p=NULL;`**, single ownership, `calloc`, bounds everywhere.
- **Build hardened:** Full RELRO (`-Wl,-z,relro,-z,now`), and keep a modern glibc
  (Safe-Linking, tcache key, hook removal, top/size checks).
- **Detect in testing:** ASan finds the underlying overflow/UAF before any of
  this is possible; fuzz with it on.
- **Production hardening:** GWP-ASan (sampling), scudo, hardened_malloc, and
  `MALLOC_CHECK_`/`glibc.malloc.check`.

---

## Recap
- Heap techniques convert a metadata-corruption bug into a **write primitive**:
  tcache poisoning, fastbin/tcache dup, double-free alias, unlink, the House-of
  family — usually via **overlapping chunks**.
- Each is **glibc-version-specific**; Safe-Linking, tcache keys, unlink checks,
  top-size checks, and hook removal have progressively defanged them.
- The universal pattern is **bug → lie → controlled alloc/write → target →
  trigger**, and it needs an **info leak** to beat ASLR/Safe-Linking.
- The only real fix is **not creating the bug** + hardened build + sanitizers.

Next: the lifetime bug that often *provides* the primitive above.
**[Chapter 6 — Use-after-free & dangling pointers »](06-use-after-free.md)**
