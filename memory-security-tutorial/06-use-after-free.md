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
UAF (or just malloc-not-zeroing) leaks whatever was in the freed slot — secrets,
or **pointers** that defeat ASLR. UAF-read + UAF-write is the full combo.

---

## 6.6 Test case 3 — double-free

```c
// u03_doublefree.c
char *p = malloc(32);
free(p);
free(p);     // chunk placed on the free list twice -> two mallocs alias it
```
Modern glibc aborts with *"free(): double free detected in tcache 2"* via the
tcache **key**. It's a mitigation, not a cure (clear the key via another bug).
Exploited as **fastbin/tcache dup** (Chapter 5). Fix: `free(p); p=NULL;`
(`free(NULL)` is a safe no-op, so this neutralizes it).

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
`realloc` can return a **new** address and free the old one. Every pointer into
the old block (`a`, `alias`, saved offsets) is now dangling. Re-fetch all
pointers from the `realloc` return value.

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
Returning (or storing) the address of a local is a dangling **stack** pointer.
`-Wall -Wreturn-local-addr` warns; `-fsanitize=address` catches
use-after-return/scope.

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
The single most common real-world UAF: a `free` on an error branch that falls
through to normal use/cleanup. Fix with a single cleanup label (`goto out;`) and
`buf=NULL` after free.

---

## 6.10 Test case 7 — callback / long-lived reference

```c
// u07_callback.c
Widget *w = make_widget();
register_timer(w);          // framework keeps a pointer to w
destroy_widget(w);          // frees w but never unregisters the timer
// later, the timer fires -> callback dereferences freed w -> UAF
```
Objects registered with event loops/caches/observers must **unregister on
destroy**. This is the shape of most GUI/browser UAFs (object freed while still
referenced by a pending task).

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
Off-by-one reference counting is endemic in C kernels and COM/ObjC-style code.
The kernel uses saturating `refcount_t` to blunt under/overflow (Chapter 14).

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
Container growth/erase invalidates pointers, references, and iterators into it.
Re-acquire them after any mutation, or use indices. (More C++: Chapter 10.)

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
