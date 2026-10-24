# Chapter 4 — Use-After-Free & Dangling Pointers

> Buffer overflows are about writing to the wrong *place*. Use-after-free is
> about using memory at the wrong *time*. It is the dominant bug class in modern
> browsers, kernels, and language runtimes.

---

## 4.1 What it is

A **use-after-free (UAF)** is using a pointer **after** the memory it points to
has been **freed**. The pointer still holds the old address — it is now a
**dangling pointer** — but the allocator considers that memory available and may
hand it to a *different* allocation. Reading or writing through the dangling
pointer then touches whatever now lives there.

```c
char *p = malloc(32);
free(p);          // memory returned to the allocator
strcpy(p, "hi");  // USE-AFTER-FREE: p is dangling
```

Related lifetime bugs covered here:

- **Double free** — calling `free(p)` twice.
- **Dangling stack pointer** — returning/keeping a pointer to a local.
- **Type confusion via UAF** — the slot is reused by an object of a *different
  type*.

---

## 4.2 Why it happens

Because C/C++ make **you** responsible for object lifetime, and nothing stops you
from keeping a copy of a pointer after you free the thing it points to. Common
real causes:

- **Aliasing**: two pointers to one object; one path frees it, the other keeps
  using it.
- **Error paths**: `free` on an error branch, then the pointer is used by cleanup
  code.
- **Callbacks / long-lived references**: an object is registered somewhere (event
  handler, cache, list) and freed elsewhere without unregistering.
- **Reference-count bugs**: `refcount` goes to zero too early (very common in
  kernels, Chapter 7).
- **Container invalidation**: `std::vector` reallocates and invalidates existing
  iterators/pointers.

---

## 4.3 How it happens — and why it's exploitable

The exploit power comes from **allocator reuse determinism** (Chapter 3). The
attacker's recipe is almost always this "reclaim" pattern:

```
1. Allocate a victim object V (say it holds a function pointer / vtable).
2. Free V   -> V's slot goes on a free list; your pointer to V is now dangling.
3. Allocate a NEW object of the SAME SIZE, filled with attacker data.
   The allocator hands back V's exact slot -> attacker data now sits where V was.
4. Use the dangling pointer to V -> you dereference attacker-controlled bytes
   (e.g. a fake function pointer / fake vtable) -> control flow hijack.
```

Step 3 is called **"heap grooming" / "reclaiming the slot."** The fact that
`malloc` of the same size returns the just-freed chunk is what makes this
reliable.

### Annotated test case — UAF function-pointer hijack

```c
// uaf.c  (educational)
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct object { void (*run)(void); char tag[24]; };

void legit(void)   { puts("legit object ran"); }
void pwned(void)   { puts("UAF: attacker-controlled call!"); }

int main(void) {
    struct object *o = malloc(sizeof *o);   // (1) allocate victim
    o->run = legit;

    free(o);                                 // (2) free it -> o dangles
    // o is NOT set to NULL (that's the bug)

    // (3) reclaim the same-size slot with attacker data:
    unsigned long *reclaim = malloc(sizeof *o);
    reclaim[0] = (unsigned long)pwned;       // overwrite the `run` slot

    // (4) use the dangling pointer:
    o->run();                                // calls pwned(), not legit()
    return 0;
}
```

```bash
gcc -g -O0 uaf.c -o uaf && ./uaf     # prints "UAF: attacker-controlled call!"
# Now prove the bug detector catches it:
gcc -g -O0 -fsanitize=address uaf.c -o uaf_asan && ./uaf_asan
#   -> AddressSanitizer: heap-use-after-free, with allocation/free stack traces
```

In the real world you don't literally write these four lines; the two sides
(free here, reclaim there) are far apart in a big codebase — which is exactly why
UAFs are hard to spot by eye and why sanitizers/fuzzers matter.

---

## 4.4 Double free

```c
// doublefree.c
char *p = malloc(32);
free(p);
free(p);         // double free: p's chunk is put on the free list twice
```

Why it's dangerous: the free list now contains the **same chunk twice**, so two
future `malloc`s return the **same memory** as if it were two independent
objects. Writing to one corrupts the other → a powerful primitive. Classic
**"fastbin dup" / "tcache dup"** CTF techniques are built on this.

Modern glibc adds a **tcache key**: each freed tcache chunk stores a key, and
`free` checks it to detect an immediate double-free (abort with "free(): double
free detected in tcache 2"). It's a mitigation, not a cure — bypassable by
clearing the key via another bug.

---

## 4.5 Dangling stack pointers

UAF isn't only about the heap:

```c
// dangle_stack.c
int *get_ptr(void) {
    int x = 42;
    return &x;        // BUG: x lives on get_ptr's frame, destroyed on return
}
int main(void) {
    int *p = get_ptr();
    // p points into a dead stack frame; the next call overwrites it
    printf("%d\n", *p);   // undefined: may print 42, garbage, or crash
    return 0;
}
```

Also: keeping a pointer to a `std::vector` element after `push_back` reallocates,
or to a C++ object after it goes out of scope. Same lifetime mistake, different
region. Compile with `-Wall -Wreturn-local-addr` — GCC/Clang warn on the obvious
cases, and `-fsanitize=address` catches stack-use-after-return/scope.

---

## 4.6 Type confusion (via UAF or bad casts)

When a freed slot is reused by an object of a **different type**, the dangling
pointer interprets the new object's bytes as the *old* type's layout — e.g.
treating an attacker-controlled integer field as a **vtable pointer**. This is
the heart of most browser JS-engine exploits (an object freed during a callback,
reclaimed as a typed array, etc.).

Type confusion also occurs **without** UAF, via unchecked downcasts:

```c
// Treating a Base* that is really a Cat* as if it were a Dog*,
// so a Dog method reads Cat fields at the wrong offsets.
```

The fix is the same spirit: don't let an object be used as a type it isn't —
`dynamic_cast`/tagged unions/`std::variant` in C++, and never reuse freed memory
as a different type without reinitializing through the correct type.

---

## 4.7 Impact

- **Arbitrary code execution** via hijacked function pointers / vtables (the
  usual outcome in browsers and kernels).
- **Information disclosure**: reading the reclaimed slot leaks whatever data now
  lives there (pointers → defeat ASLR; secrets → direct leak).
- **Privilege escalation** in kernel UAF (Chapter 7) — among the most common
  Linux LPE primitives of the last decade.

UAF + an info leak is the standard 2-bug combo for a full modern exploit: leak to
defeat ASLR, UAF to get control.

---

## 4.8 The fix

**Make lifetimes unambiguous and kill dangling pointers.**

1. **`free(p); p = NULL;`** — a dangling pointer set to `NULL` turns a silent UAF
   into an immediate, obvious `NULL` deref crash (and `free(NULL)` is a safe
   no-op, so it also neutralizes double-free). Cheap, effective habit.
2. **Single ownership.** Be clear about *who* frees an object. In C++, use
   **`std::unique_ptr`** (one owner, frees automatically) and
   **`std::shared_ptr`/`weak_ptr`** (reference-counted) instead of raw
   `new`/`delete`.
3. **Don't keep raw pointers/iterators across operations that may invalidate
   them** (container growth, rehash, callbacks that may free).
4. **Reference counting done right** — increment *before* handing out a
   reference, decrement after; audit every early-return path.
5. **Rust** eliminates this class at compile time via ownership/borrow checking —
   the strongest structural fix for new code.
6. **Tooling**: AddressSanitizer (`-fsanitize=address`) and
   MemorySanitizer detect UAF/double-free at runtime with exact traces; fuzz with
   them on (Chapter 8). Hardened allocators (glibc tcache key, GWP-ASan,
   scudo, hardened_malloc) raise the cost in production.

```c
// safe pattern
free(o);
o = NULL;          // any later o->run() now crashes cleanly instead of UAF
```

---

## Chapter 4 recap

- **UAF** = using memory after `free`; the stale pointer is **dangling**.
- Exploited via **slot reclamation**: free the victim, allocate attacker data of
  the same size into the same slot, then use the dangling pointer (often a
  **function pointer/vtable** → RCE).
- **Double free** poisons the free list so two allocations alias.
- **Dangling stack pointers** and **type confusion** are the same lifetime
  mistake in other clothes.
- Fix with `free;NULL`, single ownership / smart pointers, careful refcounting,
  Rust, and ASan.

Next: the remaining core bug classes every learner should recognize.
**[Chapter 5: Other memory bugs »](05-other-memory-bugs.md)**
