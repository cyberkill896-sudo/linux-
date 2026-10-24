# Chapter 11 — Race Conditions → Memory Corruption

> Concurrency turns "safe" code unsafe: two threads (or a thread and a signal, or
> userspace and the kernel) touch the same memory and the *interleaving* creates
> a bug that doesn't exist in any single ordering. Races are the hardest memory
> bugs to find because they're nondeterministic — and they power some of the most
> famous Linux exploits (Dirty COW, Dirty Pipe).

---

## 11.0 In plain words (start here)

So far every bug lived in a single stream of instructions. Modern programs run
**several at once** — multiple threads, or the kernel handling two of your
requests simultaneously. A **race condition** is a bug that only appears for
certain *timings* of those parallel streams.

The classic shape is **TOCTOU** — "Time Of Check To Time Of Use." A program
*checks* something ("is this pointer valid?", "do I have permission?") and then,
a few instructions later, *uses* it. If another thread changes the thing **in the
gap between the check and the use**, the check was true but the use is now wrong.

A kitchen analogy: you look in the fridge and see milk (the check), then turn to
get a glass; meanwhile your roommate takes the milk; you reach back in and
pour... nothing (the use). Nobody did anything individually wrong — the bug is in
the *interleaving*.

In memory terms this produces the same corruptions as earlier chapters, but
reached through timing:
- one thread **frees** an object while another is still **using** it → a
  use-after-free (Chapter 6) that no single-threaded path has;
- two threads both do `count--` on a shared counter and one update is lost →
  a reference count that hits zero too early → another use-after-free or
  double-free;
- the kernel reads a size from your memory, checks it, then reads it **again** to
  use it, and you changed it in between (a "double-fetch") → an overflow.

What makes races dangerous is exactly what makes them hard to test: they're
**nondeterministic**. The code can pass a million test runs and then fail — or be
*forced* to fail by an attacker who widens the timing window on purpose (Dirty
COW did this to get root). The fixes are about removing the gap: **lock** the
check-and-use together, **snapshot** an untrusted value once and only use the
copy, or use **atomic** operations for shared counters.

---

---

## 11.1 Why races cause memory corruption

A memory-safety invariant ("this pointer is valid", "this length ≤ this buffer")
holds at the moment you **check** it, but another actor changes the state before
you **use** it. The gap between check and use is the vulnerability. Four flavors:

1. **TOCTOU** (time-of-check to time-of-use) — classic check/use gap.
2. **Double-fetch** — reading the same untrusted value twice (common at the
   user/kernel boundary).
3. **Data race on a shared object** — concurrent free vs. use → **UAF**; or
   concurrent writes → torn/inconsistent state.
4. **Signal-handler reentrancy** — a handler interrupts and mutates state mid-use.

---

## 11.2 Test case 1 — data-race UAF (free vs. use)

```c
// r01_race_uaf.c  (build: gcc -g -O0 -pthread r01_race_uaf.c -fsanitize=thread)
#include <pthread.h>
#include <string.h>
struct obj { char buf[32]; };
struct obj *g;                       // shared pointer

void *user(void *_){ for(;;){ if(g) strcpy(g->buf, "work"); } return 0; }   // USE
void *killer(void *_){ for(;;){ free(g); g = malloc(sizeof *g); } return 0; } // FREE+realloc

int main(){
    g = malloc(sizeof(struct obj));
    pthread_t a,b;
    pthread_create(&a,0,user,0);
    pthread_create(&b,0,killer,0);    // between `if(g)` and strcpy, killer frees g
    pthread_join(a,0); pthread_join(b,0);
}
```
Thread A checks `g` non-null, then — *before* it dereferences — thread B frees it.
A's `strcpy` is now a **UAF write**. No single-threaded path has this bug; the
interleaving creates it. `-fsanitize=thread` (TSan) reports the race with both
stacks.

---

## 11.3 Test case 2 — TOCTOU on a shared length/flag

```c
// r02_toctou_len.c
struct conn { int len; char *buf; size_t cap; };   // shared across threads
void writer(struct conn *c, char *src){
    if (c->len <= c->cap) {            // CHECK
        /* another thread raises c->len here */
        memcpy(c->buf, src, c->len);   // USE: c->len now > cap -> overflow
    }
}
```
A validated field is re-read at use time after another thread changed it. **Fix:**
snapshot the value into a local under a lock, validate the local, use the local.

---

## 11.4 Test case 3 — double-fetch (the user/kernel classic)

```c
// r03_doublefetch.c  (kernel-style pseudocode)
long handle_ioctl(struct req __user *u){
    if (u->len > MAX) return -EINVAL;     // FETCH #1 from userspace: validate
    char *k = kmalloc(u->len);            // (len still looks fine)
    copy_from_user(k, u->data, u->len);   // FETCH #2: another user thread changed
                                          // u->len to something huge -> overflow
}
```
**Why this is subtler than an ordinary TOCTOU.** The dangerous detail is that
`u` is a pointer into **userspace memory** (`__user`), which the attacker's
process *fully owns and can modify from another thread at any instant*. The
kernel reads `u->len` **twice**: once to validate it (`u->len > MAX`) and once to
use it (as the `copy_from_user` size). Those are two separate memory reads of the
same attacker-controlled location. The attacker runs a second thread that sits in
a tight loop flipping `u->len` between a small, valid value and a huge one:

```
 attacker thread:   while(1){ u->len = 8; u->len = 0xffffffff; }
 kernel:            [reads u->len = 8 -> passes check]
                    [attacker flips to 0xffffffff]
                    [reads u->len = 0xffffffff -> copies 4 GB into an 8-byte alloc]
```

The attacker just has to win the race once (loop + retry), and the validated
value is **not** the value used — a kernel heap overflow with attacker data. Note
the allocation size and the copy size were read *independently*, so "I checked
it" is simply false by the time the copy runs.

**Why the fix works.** `copy_from_user(&kreq, u, sizeof kreq)` pulls the whole
request into **kernel** memory *once*. Kernel memory can't be modified by the
attacker's other thread, so after that single copy you have a stable snapshot:
validate `kreq.len` and use `kreq.len`, and they're guaranteed identical because
they're the same kernel variable. The rule generalizes beyond the kernel:
**read an untrusted value exactly once into memory you control, then validate
and use only that copy** — never re-read the attacker's storage. This is a
real, recurring kernel pattern (Chapter 14); the kernel even has tooling to flag
double-fetches.

---

## 11.5 Test case 4 — non-atomic refcount race → UAF

```c
// r04_refcount_race.c
void put(struct obj *o){
    o->rc--;                 // NON-atomic read-modify-write
    if (o->rc == 0) free(o); // two threads can both see rc reach 0 -> double free
}                            // or both decrement from 2 -> rc=0 while one still uses o
```
`rc--` compiles to load/dec/store; two threads interleaving lose an update, so the
count is wrong → **UAF or double-free**. **Fix:** atomic ops
(`atomic_fetch_sub`, C++ `std::atomic`, kernel `refcount_t` which also saturates).
This is *extremely* common in kernels and is why `refcount_t` exists.

---

## 11.6 Test case 5 — signal-handler reentrancy

```c
// r05_signal.c
char *g_buf;
void handler(int sig){ free(g_buf); g_buf = NULL; }  // runs at any instruction
int main(){
    signal(SIGINT, handler);
    g_buf = malloc(64);
    strcpy(g_buf, data);      // if SIGINT arrives mid-strcpy, handler frees g_buf
    use(g_buf);               // -> UAF; also free() is not async-signal-safe
}
```
A signal handler interrupts the main flow at an arbitrary point and mutates shared
state → UAF/double-free, and calling non-**async-signal-safe** functions
(`malloc`/`free`/`printf`) in a handler is itself UB. **Fix:** handlers should only
set a `volatile sig_atomic_t` flag; do the real work in the main loop.

---

## 11.7 Test case 6 — file-system TOCTOU (symlink race)

```c
// r06_fs_toctou.c
if (access(path, W_OK) == 0) {     // CHECK: do we have permission?
    int fd = open(path, O_WRONLY); // USE: attacker swapped `path` for a symlink
    write(fd, data, n);            //      to /etc/passwd in between -> write there
}
```
Not a *memory* corruption, but the same TOCTOU shape and a classic privilege-
escalation bug in setuid programs. **Fix:** `open` first then `fstat`/`O_NOFOLLOW`
on the fd — operate on the handle, not the name.

---

## 11.8 Famous kernel races (study material)

- **Dirty COW (CVE-2016-5195):** a race in copy-on-write page handling let an
  unprivileged user win a race against the memory manager and write to read-only
  file mappings → overwrite setuid binaries → **root**. A pure interleaving bug.
- **Dirty Pipe (CVE-2022-0847):** an uninitialized pipe-buffer flag (a lifetime
  bug, amplified by timing) allowed writing into read-only files.
- **CVE-2021-22555 (netfilter):** a heap OOB combined with races for a full LPE.

These are patched; read their write-ups to see how a race becomes a reliable
exploit (attackers widen the race window with scheduling tricks, memory pressure,
or `userfaultfd`/`FUSE` to *pause* the kernel at the perfect instant).

---

## 11.9 Impact
- **UAF / double-free / overflow** reached only under the right timing → RCE or
  LPE.
- **Privilege escalation** (Dirty COW/Pipe), **auth/permission bypass** (TOCTOU).
- **Nondeterministic** — may pass tests thousands of times, then fail (or be
  *forced* to fail by an attacker). That unpredictability is why they're so
  dangerous.

---

## 11.10 The fixes
1. **Lock shared mutable state** (mutex/rwlock) around check-and-use; keep the
   critical section covering *both*.
2. **Snapshot untrusted values once** into local/kernel memory, then validate and
   use only the snapshot (kills double-fetch and shared-field TOCTOU).
3. **Atomic reference counts** (`std::atomic`, C `_Atomic`, kernel `refcount_t`).
4. **Operate on handles, not names** (fds) to kill filesystem TOCTOU;
   `O_NOFOLLOW`, `openat`.
5. **Signal handlers do minimal, async-signal-safe work** (set a flag only).
6. **Immutable / message-passing designs** (share nothing) avoid the class
   entirely; Rust's `Send`/`Sync` + borrow checker prevent data races at compile
   time.
7. **Tooling:** **ThreadSanitizer** (`-fsanitize=thread`) finds data races;
   stress/loop tests, `rr` for record-replay, and KCSAN in the kernel.

---

## Recap
- Races create memory bugs in the **gap between check and use**: TOCTOU,
  double-fetch, data-race UAF, non-atomic refcounts, signal reentrancy.
- They're nondeterministic and attacker-widenable (Dirty COW/Pipe), yielding RCE
  or root.
- Fix with **locking, single-snapshot validation, atomics, handles-not-names,
  minimal signal handlers**, and TSan; Rust prevents data races structurally.

Next: **[Chapter 12 — Code reuse: ret2libc, ROP & friends »](12-code-reuse.md)**
