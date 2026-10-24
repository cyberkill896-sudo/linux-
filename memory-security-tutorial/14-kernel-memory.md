# Chapter 14 — Kernel Memory Vulnerabilities

> The same bug classes (overflow, UAF, integer, race) exist in the kernel, but
> the context changes everything: a kernel bug compromises the **whole machine**
> (unprivileged user → root). Conceptual chapter — understand the model, the
> extra bug shapes, and the defenses. Study only in a **throwaway VM**.

---

## 14.0 In plain words (start here)

Everything so far attacked a single *program*. The **kernel** is the master
program that runs the whole computer: it owns all memory, all hardware, and
decides what every other program is allowed to do. It runs in a privileged CPU
mode (**ring 0**). So a memory bug in the kernel isn't "take over one app" — it's
"take over the entire machine," turning an ordinary unprivileged user into
**root**. That's called **local privilege escalation (LPE)**, and it's why
kernel bugs are so valuable.

The bug *classes* are the same ones you already know — overflow, use-after-free,
integer overflow, race — but three things make the kernel special:

1. **The attack surface is the boundary between your program and the kernel.**
   Every time a program asks the kernel to do something (a *syscall*, an
   `ioctl`, a write to `/proc`, a network packet, a mounted filesystem image),
   it hands the kernel data. If the kernel mishandles that data, that's the bug.
   This creates kernel-only bug shapes — like trusting a length or a pointer that
   came from user space.
2. **The kernel must never trust user-supplied pointers or sizes**, and it uses
   special functions (`copy_from_user`, `copy_to_user`) to move data across the
   boundary safely. Forgetting a check there, or reading a user value *twice*
   (a "double-fetch" race), is a classic kernel bug.
3. **Leaking kernel memory to a user** is uniquely bad: it reveals kernel
   addresses that defeat KASLR (the kernel's ASLR), enabling the next step of an
   exploit. A struct with uninitialized padding bytes copied out to userspace is
   a real, common leak.

The dominant modern kernel bug is the **use-after-free in the slab allocator**
(the kernel's version of the heap clerk from Chapter 3), very often caused by a
**reference-counting** mistake, then exploited by "spraying" look-alike objects
to reclaim the freed slot — the same reclaim idea as Chapter 6, at kernel scale.

This chapter is conceptual (you don't write a kernel exploit here). The goal is
to recognize these shapes and know the defenses (SMEP/SMAP/KPTI, `refcount_t`,
slab hardening, KASAN). **Only ever experiment in a disposable virtual machine** —
a kernel bug can corrupt or crash the whole system.

---

## 14.1 Why the kernel is different

- **Privilege:** kernel code runs in **ring 0** with full access to all memory
  and hardware. A memory bug → **local privilege escalation (LPE)**.
- **No per-process isolation of the damage:** a bad write can corrupt any
  structure system-wide.
- **Attack surface = the syscall/driver boundary:** every `syscall`, `ioctl`,
  `/proc`/`/sys` write, netlink message, eBPF program, filesystem image, and
  device driver that takes user input. Third-party/GPU/USB **drivers** are
  historically the buggiest.
- **Allocator:** the **SLUB slab allocator** groups objects by type/size into
  caches, making UAF reclamation even more controllable than userspace malloc.

---

## 14.2 The user/kernel boundary — the #1 kernel-specific source

The kernel must never trust a userspace pointer or length; it uses validating
accessors:
```c
copy_from_user(kbuf, uptr, len);   // user -> kernel (checks uptr range)
copy_to_user(uptr, kbuf, len);     // kernel -> user
get_user(x, uptr); put_user(x, uptr);
```

### Bug 1 — missing length check → slab/stack overflow
```c
// k01_missing_check.c (driver pseudocode)
char kbuf[64];
copy_from_user(&r, arg, sizeof r);     // ok
copy_from_user(kbuf, r.data, r.len);   // r.len unchecked -> kernel overflow
// FIX: if (r.len > sizeof kbuf) return -EINVAL;
```
Same discipline as userspace, blast radius = the whole kernel.

### Bug 2 — uninitialized kernel memory → infoleak
```c
// k02_infoleak.c
struct info { int a; /* 4 bytes PADDING */ long b; } s;
s.a = 1; s.b = 2;                      // padding never initialized
copy_to_user(uptr, &s, sizeof s);      // leaks 4 bytes of kernel stack/heap
// FIX: memset(&s, 0, sizeof s); before filling  (or init_on_alloc)
```
Leaking kernel **pointers** this way defeats **KASLR** — the enabling half of a
kernel exploit. A massive historical bug source.

### Bug 3 — double-fetch TOCTOU
```c
// k03_doublefetch.c
if (uptr->len > MAX) return -EINVAL;   // FETCH #1: validate
kbuf = kmalloc(uptr->len, GFP_KERNEL);
copy_from_user(kbuf, uptr->data, uptr->len);  // FETCH #2: another user thread
                                              // changed len -> overflow
// FIX: copy the whole request in ONCE, then validate+use the kernel copy
```
(See Chapter 11 §4.)

### Bug 4 — writing where a user pointer says
Dereferencing a user-supplied pointer in kernel context without the accessors →
arbitrary kernel read/write. **SMAP/SMEP** (below) harden this.

---

## 14.3 Kernel UAF & reference-count bugs (the dominant modern class)

Like userspace UAF (Chapter 6), reclaimed from the **slab**:

```
1. A kernel object holding a function pointer / `ops` struct is freed
   (often via a refcount bug: count hits 0 while a reference is still used).
2. Attacker sprays same-size allocations they control via a syscall that
   allocates from the SAME slab cache  (msg_msg, sk_buff, setxattr, pipe_buffer,
   user_key_payload, ...).
3. The dangling pointer's ->op() now runs attacker-influenced data.
```
- **Refcount bugs** (`refcount_t` under/overflow, `kref` misuse) are among the
  most common CVEs; the kernel added **`refcount_t` with saturation** to blunt
  them.
- **Heap spraying** with controllable-size/content objects is the kernel's
  reclaim primitive; "elastic objects" like `msg_msg` are favorites.

```c
// k04_refcount.c
void release(struct obj *o){ if (atomic_dec_and_test(&o->ref)) kfree(o); }
// BUG: a path returns a reference without atomic_inc(&o->ref)
//      -> an extra release() frees o while still referenced -> UAF
```

**Why the kernel heap is *easier* to exploit than userspace, step by step.**
This is the deep reason kernel UAF dominates LPE:

1. **The slab groups objects by size/type into caches.** The SLUB allocator
   keeps per-type caches (`kmalloc-64`, `kmalloc-256`, dedicated caches for
   `cred`, `file`, etc.). Objects of the same size come from the same cache and
   are reused LIFO — just like tcache (Chapter 3), but even more predictable
   because the kernel is one big long-lived process with well-known object sizes.
2. **The attacker has a rich menu of "spray" objects.** From userspace, specific
   syscalls allocate kernel objects of attacker-chosen **size** and partly
   attacker-chosen **contents**: `msg_msg` (System V message queues — nearly
   arbitrary size and contents, hence "elastic"), `sk_buff` (network buffers),
   `setxattr`/`user_key_payload` (controlled bytes), `pipe_buffer`, etc. So after
   freeing the victim, the attacker calls such a syscall with the victim's exact
   size to **reclaim the freed slot with bytes they control** — the Chapter 6
   reclaim, but with a reliable, scriptable spray primitive built into the
   kernel's own API.
3. **The reclaimed object is full of *pointers the kernel will use*.** Kernel
   objects are thick with function-pointer tables (`file_operations`,
   `proto_ops`, `->release`, etc.). Overwriting one with the spray and then
   triggering the dangling reference's callback redirects **kernel** control flow.
4. **The prize is `struct cred`.** The classic finish is to corrupt a process's
   credential structure (set uid/gid to 0) or to call
   `commit_creds(prepare_kernel_cred(NULL))` — turning the calling process into
   root. No file to overwrite, no service to restart: instant privilege
   escalation.

**Reference counting is the usual root cause** (`refcount_t` under/overflow,
`kref` misuse). The `k04` snippet shows the canonical form: a code path hands out
a pointer to `o` without the matching `atomic_inc`, so the count is one too low
and a later `release` frees `o` while a user still holds it. Because kernels are
massively concurrent, a **race** on the increment/decrement (Chapter 11) produces
the same under-count. The kernel introduced **`refcount_t`** — atomic *and*
**saturating** (it refuses to wrap past 0 or the max and warns) — specifically to
convert these silent under/overflows into loud, non-exploitable failures.

---

## 14.4 Other kernel-specific shapes

- **`ioctl`/`setsockopt` integer overflow** on a size → slab overflow (Chapter 8,
  higher stakes).
- **Parser OOB** on untrusted data: filesystem images (mount a crafted FS),
  network packets, USB descriptors, compression. Fuzzed heavily by syzkaller.
- **eBPF verifier bugs:** the verifier must prove programs safe; a flaw → attacker
  runs semi-arbitrary in-kernel code. A recurring high-value LPE source.
- **Races:** Dirty COW, Dirty Pipe (Chapter 11) — the kernel is massively
  concurrent, so TOCTOU/data-race UAF abound.
- **NULL deref:** mostly DoS now (`mmap_min_addr` blocks mapping page 0).

---

## 14.5 Impact
- **Local privilege escalation to root** (overwrite `struct cred`, or
  `commit_creds(prepare_kernel_cred(0))`, or corrupt page tables).
- **Container / VM escape**, **KASLR/secure-boot defeat**, persistent rootkits.
- **System-wide panic** (DoS).

---

## 14.6 Kernel mitigations (parallels to Chapter 13, plus kernel-only)

| Mitigation | What it does |
|------------|--------------|
| **KASLR / FG-KASLR** | randomize kernel base / function layout |
| **SMEP** | kernel can't **execute** userspace pages (kills "ret2user" shellcode) |
| **SMAP** | kernel can't **access** userspace pages except via accessors (kills many arbitrary-write tricks) |
| **KPTI** | split user/kernel page tables (Meltdown mitigation; also hardens) |
| **STACKPROTECTOR** | kernel stack canaries |
| **`refcount_t`** | saturating counters stop refcount under/overflow |
| **SLAB_FREELIST_HARDENED / RANDOM**, **init_on_alloc/free** | harden slab freelist; zero memory to kill infoleak/UAF reuse |
| **kCFI / CFI** | validate indirect calls |
| **hardened usercopy** | bounds-check `copy_{to,from}_user` against object size |
| **seccomp / namespaces / LSMs (SELinux, AppArmor, lockdown)** | shrink reachable attack surface |

Defense-in-depth matters even more here because one bug is so powerful.

---

## 14.7 How to study the kernel safely
- **Never** test on a machine you care about. Use **QEMU/KVM** with a debug-built
  kernel; snapshot so you can revert after a panic.
- **KASAN** (`CONFIG_KASAN=y`) = kernel ASan: reports OOB/UAF with traces.
  **KCSAN** for data races. **KMSAN** for uninitialized memory.
- **syzkaller** (coverage-guided kernel fuzzer) finds these automatically and
  gives reproducers — reading its reports is a superb education.
- Read patched-CVE write-ups: Dirty COW, Dirty Pipe, CVE-2021-22555,
  nf_tables/io_uring bugs, plus `Documentation/security/` and the kernelctf
  program. (All patched → study material, not live weapons.)

---

## Recap
- Kernel bugs are the **same classes** but yield **root / whole-machine**
  compromise.
- The **user/kernel boundary** adds unique bugs: missing length checks,
  **uninitialized-memory infoleaks** (defeat KASLR), **double-fetch TOCTOU**.
- **UAF + refcount bugs + races + slab spray** dominate modern LPE.
- Mitigations mirror userspace plus kernel-only **SMEP/SMAP/KPTI**, hardened
  usercopy, `refcount_t`, slab hardening, `init_on_free`.
- Study only in a **VM** with KASAN; let **syzkaller** show you how bugs are
  found.

Next: **[Chapter 15 — Practice, tooling & resources »](15-practice-and-resources.md)**
