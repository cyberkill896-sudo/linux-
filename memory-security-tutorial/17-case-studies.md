# Chapter 17 — Real-World CVE Case Studies

> Theory meets reality. Each case is a famous, **patched** vulnerability dissected
> with the same lens as the rest of the course: the bug class, the exact root
> cause, the primitive, the impact, and the one-line-ish fix. These are study
> material — the point is to recognize these shapes in real code.

For each: **what the code did wrong**, **why it was exploitable**, and **the fix**.

---

## 17.1 Heartbleed — OpenSSL TLS heartbeat OOB read (CVE-2014-0160, 2014)

**Class:** out-of-bounds read / missing length validation (Chapter 9).

**Root cause.** TLS has a "heartbeat" keep-alive: the client sends a payload and a
**length**, the server echoes that many bytes back. OpenSSL allocated a response
of the client-supplied length and `memcpy`'d from the request — **without checking
that the claimed length matched the actual payload received**:

```c
/* simplified from t1_lib.c / d1_both.c */
unsigned char *p = &s->s3->rrec.data[0];
unsigned short payload;
n2s(p, payload);                 /* read the CLIENT's claimed length (up to 65535) */
/* ... no check that `payload` <= actual record length ... */
unsigned char *buffer = OPENSSL_malloc(1 + 2 + payload + padding);
memcpy(bp, pl, payload);         /* copies `payload` bytes from the request buffer */
```

**Why exploitable.** A client could claim `payload = 65535` while sending a 1-byte
payload. The `memcpy` then read up to ~64 KB **past** the real request data,
copying adjacent process memory — private keys, session cookies, other users'
plaintext — into the reply. Pure **info leak**, no crash, repeatable at will.

**Impact.** Mass disclosure of server memory (including TLS private keys) across
a huge fraction of the internet. No code execution needed to be catastrophic.

**Fix.** Validate the claimed length against the record actually received:

```c
if (1 + 2 + payload + 16 > s->s3->rrec.length)
    return 0;                    /* silently drop malformed heartbeats */
```

**Lesson.** The single most important habit in this whole course: **a length
that comes from input must be validated against the real buffer size before
use.** One missing `if`.

---

## 17.2 The Morris Worm — fingerd stack overflow (1988)

**Class:** stack buffer overflow (Chapter 2).

**Root cause.** The `fingerd` daemon read a network request into a fixed stack
buffer with `gets()`:

```c
char line[512];
gets(line);                      /* unbounded read from the network */
```

**Why exploitable.** A request longer than 512 bytes overwrote the return address
on the VAX stack; the worm supplied shellcode and redirected execution to it
(the stack was executable; NX didn't exist). Self-propagating.

**Impact.** One of the first internet worms; took down ~10% of the 1988 internet
and directly motivated CERT and modern vuln response.

**Fix.** `fgets(line, sizeof line, stdin)` — and, decades later, NX, ASLR, and
stack canaries so even a missed bound is far harder to exploit.

**Lesson.** This is literally `01_stack_basic.c` / Chapter 2, on a network
daemon. The oldest bug class is still with us.

---

## 17.3 Dirty COW — kernel copy-on-write race (CVE-2016-5195, 2016)

**Class:** race condition → UAF-like write to read-only memory (Chapter 11, 14).

**Root cause.** The kernel's memory manager handled copy-on-write (COW) of private
mappings non-atomically. By racing `madvise(MADV_DONTNEED)` against writes to a
`/proc/self/mem` handle of a read-only file mapping, an unprivileged process could
win a race where the kernel wrote to the **original** read-only page instead of a
private copy.

**Why exploitable.** Winning the race let a normal user **write to read-only
files they could only read** — e.g. overwrite a setuid-root binary or
`/etc/passwd` → instant root. The race window was tiny but reliably winnable with
two busy threads (one `madvise`, one writing), no memory-pressure tricks needed.

**Impact.** Universal Linux local privilege escalation (kernels ~2007–2016),
including Android. Trivially reliable, hence "Dirty".

**Fix.** Make the COW decision atomic (a new `FOLL_COW` flag so the fault handler
can't be tricked into treating a forced COW as already-done).

**Lesson.** Concurrency turns a "read-only" guarantee into a write primitive. The
bug exists only in the **interleaving** (Chapter 11).

---

## 17.4 Dirty Pipe — uninitialized pipe buffer flag (CVE-2022-0847, 2022)

**Class:** uninitialized memory / state confusion (Chapter 9, 14).

**Root cause.** A refactor left the `pipe_buffer.flags` field **uninitialized**
when reusing pipe buffer structures. In particular `PIPE_BUF_FLAG_CAN_MERGE` could
be left set from a previous use, so a page cache page spliced into a pipe was
wrongly marked as mergeable/writable.

**Why exploitable.** By `splice()`-ing a read-only file's page cache into a pipe
and then writing to the pipe, an unprivileged user could **modify the page cache
of a read-only file** — overwriting files they could only read (e.g. inject into
a root-owned binary / `/etc/passwd`) → root. No race needed; deterministic.

**Impact.** Linux LPE (kernels ≥ 5.8), including Android 12. As powerful as Dirty
COW but easier/deterministic.

**Fix.** Initialize `buf->flags = 0` when adding to a pipe buffer.

**Lesson.** **Uninitialized memory isn't just an info leak** — a stale *flag* can
silently grant write permission. Initialize everything (Chapter 9); `init_on_
alloc`/`init_on_free` would have blunted it.

---

## 17.5 A UAF in a browser (type confusion shape)

**Class:** use-after-free → type confusion → RCE (Chapters 6, 10). Representative
of the many WebKit/V8/Blink CVEs rather than one specific number.

**Root cause.** A JS object is freed during a callback (e.g. a getter or a
`valueOf` that the engine invokes mid-operation), but the engine keeps using a
raw pointer it cached before the callback. The attacker reclaims the freed slot
with a differently-typed object (often an `ArrayBuffer`/typed array whose contents
they control).

**Why exploitable.** The stale pointer now reads attacker bytes as the original
type's layout — e.g. a length or a backing-store pointer the attacker fully
controls → arbitrary read/write in the renderer → combined with a sandbox escape,
full RCE. This "free during callback, reclaim with typed array" is the archetypal
modern exploit.

**Impact.** Drive-by RCE from a malicious web page; the staple of real-world
browser 0-days.

**Fix.** Hold strong references across callbacks (don't cache raw pointers that a
re-entrant callback can invalidate); the engines added extensive **UAF
mitigations** (MiraclePtr/BackupRefPtr in Chrome, pointer "poisoning", isolated
heaps/PartitionAlloc, V8 sandbox).

**Lesson.** The exact `07_uaf_fnptr.c` / `15_cpp_vtable.cpp` pattern, at scale:
**don't keep a raw pointer across any operation that might free the object.**

---

## 17.6 Stagefright — Android media parser integer overflow → heap overflow (CVE-2015-1538 and friends, 2015)

**Class:** integer overflow → heap buffer overflow (Chapters 8, 4).

**Root cause.** Android's `libstagefright` parsed MP4 metadata. A size field from
the (attacker-supplied) media file was used in an arithmetic expression that
**overflowed**, producing a too-small allocation, after which the parser copied
the real (larger) amount:

```c
size_t size = ...;               /* from the file */
uint8_t *buffer = new uint8_t[size + something];   /* size+N overflows -> tiny */
memcpy(buffer, data, size);                        /* copies the real size -> overflow */
```

**Why exploitable.** The media could be delivered via **MMS** and parsed
**without the user opening it** — "zero-click." The heap overflow corrupted
adjacent objects / metadata → RCE in the media server process.

**Impact.** ~95% of Android devices at the time; remote zero-click. Prompted
Android's monthly security patch program and heap hardening.

**Fix.** Overflow-checked size arithmetic (`SIZE_MAX` checks /
`__builtin_mul_overflow`), bounds on parsed sizes, and sandboxing/isolation of
the media server.

**Lesson.** `12_int_overflow.c` in a real parser: **validate and overflow-check
every size that comes from untrusted input before allocating.**

---

## 17.7 sudo Baron Samedit — off-by-one/overflow via unescaped backslash (CVE-2021-3156, 2021)

**Class:** heap buffer overflow from an off-by-one / length miscalculation
(Chapters 2, 4, 8).

**Root cause.** When `sudo` ran in "shell" mode and parsed a command line ending
in a single backslash, its unescaping loop miscounted, copying past the end of a
heap buffer (`user_args`) — an attacker-controlled heap overflow.

**Why exploitable.** Any local user (no sudo permissions needed) could overflow
the heap with controlled data and corrupt adjacent allocator/program structures →
root. Reliable across major distros.

**Impact.** Universal local root on default `sudo` configs for ~10 years of
versions.

**Fix.** Correct the escape-handling length accounting so the copy stays in
bounds.

**Lesson.** A subtle **length miscalculation** in string handling (here around
escaping) is a heap overflow — exactly the "attacker-controlled length / off-by-
one" theme of Chapters 2 and 8. Fuzzing the argument parser would have found it.

---

## 17.8 Patterns across every case

| CVE | Class | Root cause in one line | Course chapter |
|-----|-------|------------------------|----------------|
| Heartbleed | OOB read | echoed a client length without checking it | 9 |
| Morris/fingerd | stack overflow | `gets()` into a fixed buffer | 2 |
| Dirty COW | race → write | non-atomic COW fault | 11, 14 |
| Dirty Pipe | uninitialized flag | stale `flags` granted write | 9, 14 |
| Browser UAF | UAF → type confusion | raw pointer kept across a callback | 6, 10 |
| Stagefright | int overflow → heap overflow | `size+N` wrapped → tiny alloc | 8, 4 |
| Baron Samedit | heap overflow | escape-length miscount | 2, 4, 8 |

Notice: **every one is a class you already learned.** Real vulnerabilities are not
exotic — they're the textbook bugs, in large codebases, found (and fixed) with the
exact habits in Chapter 15: validate lengths, bound copies, clear lifetimes,
overflow-check arithmetic, initialize memory, and **fuzz with sanitizers**.

---

## Recap
- The famous CVEs map **one-to-one** onto this course's bug classes.
- The fixes are almost always a **single missing check**, a **bounded copy**, an
  **initialization**, or an **atomic/locked** operation.
- Reading patched-CVE write-ups (and their diffs) is the best bridge from
  "I understand the concept" to "I can spot it in real code."

Go back to **[`EXERCISES.md`](EXERCISES.md)** capstone (#55) and write up your own
bug in exactly this format.
