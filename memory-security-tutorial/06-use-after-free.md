# Chapter 6 — Use-After-Free & Dangling Pointers (9 test cases)

> Overflows are about writing to the wrong *place*; UAF is about using memory at
> the wrong *time*. It is the dominant bug class in modern browsers, kernels, and
> runtimes.

---

## 6.0 In plain words (start here)

Back to the storeroom analogy (Chapter 3). You ask the clerk for a locker and get
a key (`p = malloc(...)`). Later you say "I'm done" (`free(p)`) and the clerk
takes the locker back to hand to someone else. **But you kept a copy of the
key.** A **use-after-free** is using that old key *after* you returned the
locker.

Why is that dangerous and not just wrong? Because the clerk may have already
given your old locker to **someone else's request**, who filled it with *their*
stuff. When you (or an attacker-triggered code path) use your stale key:

- **reading** through it shows you the new occupant's data — maybe a secret, or a
  memory address that defeats ASLR (an *info leak*);
- **writing** through it corrupts the new occupant's object;
- and most dangerously, if the object stored a **function pointer** and the new
  occupant is attacker-controlled data, then the program "calls the function" at
  an address the attacker chose → code execution.

A pointer like this — one that still points at memory that has been freed — is
called a **dangling pointer**. The attacker's standard trick is the **reclaim**:
(1) get the program to free the victim object, (2) immediately make a *same-size*
allocation they control so the clerk hands back that exact locker filled with
*their* bytes, (3) get the program to use the dangling pointer. Step 2 works
because of the predictable reuse from Chapter 3.

Two close cousins live in this chapter: **double-free** (saying "I'm done" with
the same locker twice, which corrupts the clerk's free list) and **dangling stack
pointers** (keeping the address of a local after its function returned — the
stack version of the same lifetime mistake).

The single cheapest habit that kills most of these: after `free(p)`, set
`p = NULL`. Then using the stale key crashes immediately and obviously instead of
silently touching someone else's locker. §6.15 covers the real fixes.

---

## 6.1 What it is

A **use-after-free (UAF)** uses a pointer **after** its memory was `free`d. The
pointer still holds the old address — a **dangling pointer** — but the allocator
may have handed that memory to a different allocation. Reading/writing through it
touches whatever lives there now.

```c
char *p = malloc(32);
free(p);           // memory returned to allocator
strcpy(p, "hi");   // USE-AFTER-FREE: p dangles
```

## 6.2 Why it happens

C/C++ make **you** manage lifetime; nothing stops you keeping a pointer after
freeing its target. Real causes: **aliasing** (two pointers, one frees),
**error paths** (free then cleanup uses it), **callbacks/caches** holding
references, **refcount bugs** (count hits 0 too early), **container
invalidation** (`vector` realloc).

## 6.3 Why it's exploitable — the "reclaim" pattern

```
1. Allocate victim V (holds a function pointer / vtable).
2. free(V)  -> V's slot goes on a free list; your pointer to V dangles.
3. Allocate a NEW same-size object filled with attacker bytes.
   The allocator returns V's EXACT slot (LIFO) -> attacker data sits where V was.
4. Use the dangling pointer V->fn() -> you call attacker-controlled bytes.
```
Step 3 ("heap grooming / reclaiming the slot") works because of **deterministic
reuse** (Chapter 3). Same-size allocation = same slot back.

---

## 6.4 Test case 1 — UAF function-pointer hijack

```c
// u01_fnptr.c
#include <stdio.h>
#include <stdlib.h>
struct object { void (*run)(void); char tag[24]; };
void legit(void){ puts("legit"); }
void pwned(void){ puts("UAF: attacker-controlled call!"); }
int main(void){
    struct object *o = malloc(sizeof *o);      // (1) victim
    o->run = legit;
    free(o);                                    // (2) freed; o dangles (not NULL)
    unsigned long *r = malloc(sizeof *o);       // (3) reclaim same-size slot
    r[0] = (unsigned long)pwned;                //     overwrite the `run` field
    o->run();                                   // (4) calls pwned()
}
```
```bash
gcc -g -O0 u01_fnptr.c -o u01 && ./u01            # "UAF: attacker-controlled call!"
gcc -g -O0 -fsanitize=address u01_fnptr.c -o u01a && ./u01a
#   -> AddressSanitizer: heap-use-after-free, with alloc + free stack traces
```

**Line by line, with the heap state at each step:**
1. `o = malloc(sizeof *o)` — the clerk hands out a locker big enough for the
   struct. `o->run = legit` stores the address of the legitimate function in the
   **first 8 bytes** of that locker (because `run` is the first field).
2. `free(o)` — the locker goes back on the tcache free list. **`o` still holds
   the old address** (we deliberately didn't null it) — it is now a *dangling
   pointer*. The clerk, meanwhile, has written its own bookkeeping (the tcache
   `next`/`key`) into the first 16 bytes of that locker, partly over where `run`
   was.
3. `r = malloc(sizeof *o)` — same size as before, so by tcache's LIFO rule the
   clerk hands back the **exact same locker**. Now `r` and the stale `o` point at
   the *same memory*. `r[0] = (unsigned long)pwned` writes the attacker's chosen
   function address into the first 8 bytes — i.e. into what `o->run` reads.
4. `o->run()` — the program follows the dangling pointer, reads the first 8 bytes
   (now `pwned`), and calls it. Control hijacked.

**The key realization:** steps 2 and 4 would, in real code, be in *completely
different places* — the object is freed by one subsystem and used by another that
didn't get the memo. Step 3 (the attacker getting a same-size allocation in
between) is "heap grooming." Nothing here is exotic; it's just lifetime confusion
plus predictable reuse (Chapter 3).

**Why the first field being a function pointer matters:** the attacker only needs
to control the bytes at offset 0 of the reclaimed locker, and `run` lives there.
If `run` were buried later in the struct, the attacker would need to control that
offset instead. Objects whose first field is a pointer the program later calls
(callbacks, C++ vtables) are the juiciest UAF targets.

**ASan** labels all three sites for you — "allocated by" (the malloc), "freed by"
(the free), and the use — which is the fastest way to understand *any* real UAF.

---

## 6.5 Test case 2 — UAF read → info leak

```c
// u02_leak.c
char *secret = malloc(32); strcpy(secret, "SUPERSECRETKEY");
free(secret);
char *p = malloc(32);              // reclaims the same chunk
// p's contents are the OLD bytes (allocator doesn't zero on malloc):
printf("leaked: %s\n", p);         // may print "SUPERSECRETKEY"
```
**The two facts that combine here:** (1) `free` does not erase your data — it
just marks the locker reusable; (2) `malloc` does **not** zero the memory it
hands out (only `calloc` does). So the newly-`malloc`'d `p` points at a locker
still containing the old `"SUPERSECRETKEY"` bytes, and reading `p` prints them.
In the real world the "read" is usually the program doing something legitimate
with the fresh buffer — logging it, sending it over the network — while
unknowingly exposing stale contents.

**Why a leak is half of a modern exploit.** A leaked *secret* (a key, a token) is
bad on its own. But the truly valuable leak is a leaked **pointer**. Remember
ASLR (Chapter 13) randomizes addresses each run, so an attacker normally doesn't
know where anything is. If a freed object contained a pointer (e.g. a vtable
pointer, a `next` link, a saved address) and the attacker can read it back
through a UAF, they learn a real runtime address and can compute the rest of a
region's layout — defeating ASLR. That's why real exploits pair a **UAF read**
(leak → beat ASLR) with a **UAF write** (hijack control): the "full combo."

**Fix.** Zero sensitive buffers before freeing (`explicit_bzero`/`memset`), use
`calloc` for anything you might read before fully initializing, and — the
structural fix — don't reference freed memory at all (`free; ptr=NULL`, single
ownership).

---

## 6.6 Test case 3 — double-free

```c
// u03_doublefree.c
char *p = malloc(32);
free(p);
free(p);     // chunk placed on the free list twice -> two mallocs alias it
```
**Why freeing twice is a weapon, not just a mistake.** The first `free(p)` puts
the locker on the free list. The second `free(p)` puts the **same locker on the
list again** — so the list now contains it twice. The next two `malloc`s of that
size therefore hand out the **same address twice**, as if they were two separate
objects. Now the program has two "independent" pointers that are secretly the
same memory: writing through one changes the other under the program's feet. From
there an attacker can forge the free-list link stored in the chunk and make a
later `malloc` return an **arbitrary address** (the "tcache/fastbin dup" →
poisoning techniques of Chapter 5).

**The modern speed bump.** glibc ≥ 2.29 stores a random **key** in each freed
tcache chunk and checks it on `free`; an immediate second `free` of the same
chunk is detected and the program aborts with *"free(): double free detected in
tcache 2."* This stops the naive case but is **not a cure** — an attacker who can
overwrite that key (via another bug) or who interleaves frees of different chunks
can still get a duplicate.

**Fix.** `free(p); p = NULL;`. Because `free(NULL)` is defined to do nothing, a
second `free(p)` after nulling is a harmless no-op. Combined with single
ownership (one clear owner frees each object exactly once), double-free simply
cannot happen.

---

## 6.7 Test case 4 — use-after-realloc

```c
// u04_realloc.c
char *a = malloc(64);
char *alias = a;                    // second pointer to the same block
char *b = realloc(a, 4096);         // realloc may MOVE the block
// `a`/`alias` now dangle if realloc relocated it:
alias[0] = 'x';                     // UAF write through the stale pointer
```
**What `realloc` really does.** `realloc(a, 4096)` means "resize the locker `a`
to 4096 bytes." The clerk tries to grow it in place, but if there isn't room, it
**allocates a brand-new, bigger locker, copies your data over, frees the old
one, and returns the new address.** So after `realloc`, the old address may be
dead. The function's return value is the *only* pointer you may trust.

**The trap is the aliases you forgot.** Here `alias` was a second copy of `a`
made before the `realloc`. Code often has several pointers or cached offsets into
a buffer. `b = realloc(a, ...)` updates `b`, but `a` and `alias` still hold the
**old** address — which may now be freed. `alias[0] = 'x'` is then a
use-after-free write. This bites people in data structures that store interior
pointers (linked lists, parse trees) into a buffer that later gets `realloc`'d to
grow.

**Also watch:** `realloc(p, 0)` is a footgun — on many implementations it frees
`p` and returns `NULL`, so `p = realloc(p, 0)` both frees and loses the pointer;
and if `realloc` *fails* it returns `NULL` **without** freeing the original, so
`p = realloc(p, n)` on failure leaks the original (you should assign to a temp
and check it first).

**Fix.** After every `realloc`, discard all old copies and re-derive every
pointer/offset from the returned value:
```c
char *tmp = realloc(a, 4096);
if (!tmp) { /* handle error; `a` is still valid here */ }
a = tmp;                 // update the single owning pointer
// recompute any interior pointers from `a` now
```

---

## 6.8 Test case 5 — dangling pointer to a stack local

```c
// u05_stack.c
int *get(void){ int x = 42; return &x; }  // x dies when get() returns
int main(void){
    int *p = get();
    foo();                 // overwrites that stack region
    printf("%d\n", *p);    // reads garbage / crashes (UB)
}
```
**Why this is UAF without any heap.** Recall from Chapter 1 that a function's
locals live in its **stack frame**, which exists only while the function runs and
is reclaimed the instant it returns. `x` is a local of `get`, so `&x` is an
address inside `get`'s frame. When `get` returns, that frame is gone — the memory
is immediately reused by the *next* function call. So `p` is a dangling pointer
into dead stack memory.

`foo()` is called next, and its frame reuses the very bytes `x` occupied,
overwriting them. So `*p` reads whatever `foo` left there — garbage, or a value
an attacker influenced by controlling what `foo` does. It's the same "use after
the memory's lifetime ended" bug as heap UAF, just on the stack. (It might
*appear* to "work" sometimes if nothing has overwritten the bytes yet — that's
the insidious part of undefined behavior.)

**Fix.** Never return or store the address of a local beyond its scope. Return by
value, or have the caller pass in a buffer, or allocate on the heap (and then own
that allocation properly). Compilers catch the easy cases: `-Wreturn-local-addr`
(a warning you should treat as an error) and `-fsanitize=address` (detects
stack-use-after-return/scope at runtime).

---

## 6.9 Test case 6 — dangling via early free on error path

```c
// u06_errorpath.c
int process(Conn *c){
    char *buf = malloc(c->len);
    if (parse(buf) < 0) { free(buf); /* forgot to return! */ }
    use(buf);              // on the error branch, buf is freed -> UAF
    free(buf);             // ...and this is now a double-free too
}
```
**Why this is the UAF you'll actually write.** The hijack in test case 1 was a
neat demo; *this* is how UAFs really ship. The error branch frees `buf` to clean
up, but the author forgot a `return` (or `goto done`), so control **falls
through** to the normal path that still uses `buf` — a use-after-free — and then
hits `free(buf)` again — a double-free. Both bugs from one missing `return`. In a
200-line function with several error branches, this is genuinely easy to miss in
review.

**Trace it:** `parse(buf) < 0` → enter the `if` → `free(buf)` (locker returned) →
`}` ends the `if` → execution continues to `use(buf)` (UAF) → `free(buf)`
(double-free). Had the author written `if (...) { free(buf); return -1; }`, both
problems vanish.

**Fix — the "single exit" pattern** that mature C codebases (e.g. the Linux
kernel) use:
```c
int process(Conn *c){
    int rc = 0;
    char *buf = malloc(c->len);
    if (!buf) return -1;
    if (parse(buf) < 0) { rc = -1; goto out; }   // one place to clean up
    use(buf);
out:
    free(buf);
    buf = NULL;        // belt-and-suspenders against a later stray use
    return rc;
}
```
Every path leaves through `out:`, which frees exactly once. This single-cleanup
discipline eliminates the whole family of error-path free bugs.

---

## 6.10 Test case 7 — callback / long-lived reference

```c
// u07_callback.c
Widget *w = make_widget();
register_timer(w);          // framework keeps a pointer to w
destroy_widget(w);          // frees w but never unregisters the timer
// later, the timer fires -> callback dereferences freed w -> UAF
```
**Why this dominates real-world (especially browser) UAFs.** Modern programs are
full of things that **hold a pointer to an object for later**: a timer that will
fire, an event listener, a cache entry, a work queue item, an observer. When you
`destroy_widget(w)` and free `w`, that other holder *still* has the pointer. When
the timer later fires and calls back into `w`, it dereferences freed memory — UAF
— and often at an attacker-chosen later time (the attacker can trigger the
callback after grooming the heap to reclaim `w`'s slot).

This "freed while still referenced by a pending task" pattern is the shape of the
majority of browser JavaScript-engine 0-days: a script frees an object during a
callback the engine invoked mid-operation, then the engine keeps using its cached
pointer. (See cve-labs and Chapter 10's type-confusion for the browser version.)

**Fix.** Ownership and registration must be symmetric: whatever registers a
reference must unregister it before (or as part of) destroy. Concretely:
unregister the timer/listener in `destroy_widget` *before* freeing, or — better —
use reference counting / smart pointers so the object isn't freed while any
holder still references it (next test case, and §6.15).

---

## 6.11 Test case 8 — reference-count bug

```c
// u08_refcount.c
void put(Obj *o){ if (--o->rc == 0) free(o); }
Obj *get(Obj *o){ o->rc++; return o; }
// BUG: a path hands out a reference WITHOUT calling get() (missing rc++),
// so an extra put() drops rc to 0 while a user still holds a pointer -> UAF.
// Mirror bug: forgetting put() -> leak. A race on rc++/-- -> UAF (Chapter 11).
```
**What reference counting is for.** When many parts of a program share one
object, nobody can safely say "I'll free it" — someone else might still be using
it. The standard solution is a counter `rc` on the object: every holder does
`get` (`rc++`) when it takes a reference and `put` (`rc--`) when done; whoever
drops it to zero frees it. Done correctly, the object lives exactly as long as
someone references it. It's "garbage collection by hand."

**How it goes wrong — three ways:**
- **Missing `get` (the code shown):** some path hands out a pointer to the object
  but forgets to `rc++`. Now the count is one too low. The next `put` frees the
  object while a holder still has a pointer → **UAF**. This is the most common
  refcount bug.
- **Missing `put`:** the mirror image — the count never reaches zero, so the
  object is never freed → **memory leak**.
- **Non-atomic `rc++`/`rc--` under threads:** `rc--` is really load–decrement–
  store; two threads can interleave and lose a decrement, so `rc` ends up wrong →
  either a premature free (UAF) or a leak. This is a **race** (Chapter 11).

**Why it's so common in real code.** Reference counting is spread across many
functions and many error paths; one forgotten `get`/`put` on one rare branch is
enough. It is endemic in C kernels, COM, and Objective-C-style code. The Linux
kernel introduced **`refcount_t`** — a counter whose operations are atomic *and*
**saturate** (they refuse to wrap past 0 or the max) — specifically to blunt the
under/overflow versions of this bug (Chapter 14).

**Fix.** Make `get`/`put` perfectly symmetric (every reference handed out is
counted), audit every early-return path, use atomic operations if the object is
shared across threads, and in C++ let the compiler do it with
`std::shared_ptr`/`weak_ptr` (§6.15) instead of a hand-rolled counter.

---

## 6.12 Test case 9 — C++ iterator / reference invalidation (UAF in disguise)

```cpp
// u09_iterator.cpp
std::vector<int> v = {1,2,3};
int &r = v[0];            // reference into the buffer
int *p = &v[2];
v.push_back(4);           // may REALLOCATE the buffer -> r and p dangle
r = 10;                   // UAF write
for (auto it = v.begin(); it != v.end(); ++it)
    if (*it == 2) v.erase(it);   // erase invalidates `it` -> UAF on ++it
```
**Why this is UAF even though there's no `free` in sight.** A `std::vector`
stores its elements in a single heap buffer. A **reference** (`int &r = v[0]`) or
**pointer** (`int *p = &v[2]`) or **iterator** points *into* that buffer. When
you `push_back` and the vector runs out of capacity, it does exactly what
`realloc` did in test case 4: allocates a bigger buffer, copies the elements,
and **frees the old one**. Your `r`, `p`, and any iterators still point into the
freed old buffer → using them is a use-after-free, hidden behind friendly C++
syntax.

The `erase` example is the same idea in miniature: `erase(it)` removes an element
and shifts the rest, which **invalidates `it`**; the loop's `++it` then advances a
dangling iterator. (The classic fix is `it = v.erase(it);` — `erase` returns a
valid iterator to the next element.)

**The general rule, which every C++ programmer must internalize:** any operation
that can change a container's size may **invalidate** pointers/references/
iterators into it — the exact rules are per-container and are specified in the
standard (e.g. `vector::push_back` invalidates everything on reallocation;
`unordered_map` rehash invalidates iterators but not references; `list` is
stable). Don't memorize all of them at first; instead adopt the habit: **don't
hold a raw pointer/reference/iterator across a mutation** — re-acquire it
afterward, or index by position. (Chapter 10 covers C++ memory bugs in depth.)

---

## 6.13 Type confusion via UAF

When the reclaimed slot is filled by a **different type**, the dangling pointer
reads the new object's bytes as the *old* layout — e.g. an attacker-controlled
integer field lands where a **vtable pointer** was. This is the heart of most
JS-engine exploits (object freed in a callback, reclaimed as a typed array). See
Chapter 10 for type confusion in general.

---

## 6.14 Impact
- **Arbitrary code execution** (hijacked function pointers/vtables) — the usual
  browser/kernel outcome.
- **Info disclosure** (UAF read leaks reclaimed data → defeat ASLR).
- **Privilege escalation** (kernel UAF, Chapter 14).
UAF + info leak is the standard 2-bug modern exploit.

---

## 6.15 The fixes
1. **`free(p); p = NULL;`** — turns a silent UAF into an obvious NULL-deref crash,
   and makes double-free a safe no-op. Cheapest high-value habit.
2. **Single ownership.** Be explicit about who frees. In C++ use
   **`std::unique_ptr`** (one owner), **`shared_ptr`/`weak_ptr`** (refcounted),
   RAII — never raw `new`/`delete`.
3. **Don't keep raw pointers/iterators across invalidating operations**
   (container growth, rehash, callbacks that may free).
4. **Refcount carefully**: increment *before* handing out a reference; audit every
   early return; make ++/-- atomic if shared.
5. **Rust** removes this class at compile time (ownership/borrow checker).
6. **Tooling:** ASan/MSan detect UAF/double-free with traces; fuzz with them on;
   hardened allocators (tcache key, GWP-ASan, scudo) raise production cost.

---

## Recap
- UAF = using memory after `free`; the stale pointer is **dangling**.
- Exploited via **same-size slot reclamation**; often a function pointer/vtable →
  RCE, or a UAF read → info leak.
- Nine shapes: fnptr hijack, leak, double-free, use-after-realloc, dangling
  stack, error-path free, callback, refcount, iterator invalidation.
- Fix: `free;NULL`, single ownership/smart pointers, careful refcounting, Rust,
  ASan.

Next: **[Chapter 7 — Format-string vulnerabilities »](07-format-string.md)**
