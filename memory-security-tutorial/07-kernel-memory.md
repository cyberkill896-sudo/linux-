# Chapter 7 — Kernel Memory Vulnerabilities

> The same bug classes (overflow, UAF, integer overflow) exist in the kernel —
> but the context makes them more powerful and the rules different. A userspace
> RCE compromises one process; a kernel bug compromises the **whole machine**.
> This chapter is conceptual: understand the model, the extra bug shapes, and the
> defenses. (Writing a working kernel exploit is advanced and target-specific;
> that's out of scope — the goal is understanding.)

---

## 7.1 Why the kernel is different

- **Privilege:** kernel code runs in **ring 0** with full access to all memory
  and hardware. A memory bug there → **local privilege escalation (LPE)**:
  unprivileged user → root. That's why kernel LPE bugs are so prized.
- **No clean separation per fault:** a bad write can corrupt any structure in the
  whole system.
- **The attack surface is the syscall/driver boundary:** every `syscall`,
  `ioctl`, `/proc`/`/sys` write, netlink message, filesystem image, or device
  driver that takes user input is a potential entry point. Drivers (especially
  third-party/GPU/USB) are historically the buggiest.
- **Shared, long-lived allocators:** the kernel's **slab allocator** (SLUB)
  groups objects by type/size into caches, which makes UAF reclamation even more
  controllable than userspace malloc.

---

## 7.2 The user/kernel boundary — the #1 kernel-specific bug source

The kernel must never **trust a userspace pointer** or blindly copy to/from it.
It must use the accessor functions that validate the address range:

```c
copy_from_user(kbuf, user_ptr, len);   // user -> kernel, checks user_ptr
copy_to_user(user_ptr, kbuf, len);     // kernel -> user, checks user_ptr
get_user(x, uptr); put_user(x, uptr);
```

Bugs here:

- **Missing/incorrect length check** before `copy_from_user` → **kernel buffer
  overflow** (stack or slab).
- **Double-fetch / TOCTOU:** the kernel reads a user value twice (e.g. a length),
  and a second thread changes it between the two reads — the check passes on the
  first read, the use acts on the second. Fix: copy once into kernel memory, then
  validate and use the kernel copy.
- **Leaking uninitialized kernel memory to userspace** via `copy_to_user` of a
  struct with **padding/holes** not zeroed → **infoleak** (kernel pointers →
  defeat KASLR). Fix: `memset(&s, 0, sizeof s)` before filling, or use
  designated initializers carefully.
- **Writing where a user pointer says** without `access_ok`/the accessors →
  arbitrary kernel write. **SMAP/SMEP** (below) hardens this.

### Illustrative (conceptual) driver bug

```c
// a toy ioctl handler -- DO NOT write code like this
static long dev_ioctl(struct file *f, unsigned cmd, unsigned long arg) {
    char kbuf[64];
    struct req r;
    copy_from_user(&r, (void __user *)arg, sizeof r);  // ok
    // BUG: r.len comes from userspace, not checked against sizeof(kbuf)
    copy_from_user(kbuf, r.data, r.len);               // kernel stack overflow
    ...
}
```
The fix is `if (r.len > sizeof kbuf) return -EINVAL;` before the copy — the exact
same discipline as userspace, but the blast radius is the whole kernel.

---

## 7.3 Kernel UAF & reference-count bugs (the dominant modern class)

Just like userspace (Chapter 4), but reclaimed from the **slab cache**:

1. A kernel object (often holding a **function pointer / `ops` struct pointer**)
   is freed — frequently due to a **refcount bug**: `refcount` hits zero while a
   reference is still in use (missing `get`, extra `put`, or a race).
2. The attacker triggers allocation of a **same-size object** they control the
   contents of (**heap spraying** via a syscall that allocates from the same
   cache — e.g. `msg_msg`, `sk_buff`, `setxattr`, pipe buffers).
3. The dangling pointer's `->function()` call now runs attacker-influenced data.

Reference-count bugs specifically (`refcount_t` underflow/overflow, `kref`
misuse) are among the most common CVEs; the kernel added `refcount_t` with
saturation precisely to blunt them.

Races (`use-after-free` triggered by concurrency) are huge in the kernel because
it's massively multithreaded — **Dirty COW (CVE-2016-5195)** was a race in the
copy-on-write page handling that let unprivileged users write to read-only
mappings → root. **Dirty Pipe (CVE-2022-0847)** was an uninitialized pipe-buffer
flag bug enabling writes into read-only files.

---

## 7.4 Other kernel-specific shapes

- **`ioctl`/`setsockopt` integer overflow** on a size → slab overflow (same as
  Chapter 5, higher stakes).
- **Out-of-bounds in a parser** for untrusted data: filesystem images, network
  packets, USB descriptors, compressed data. Mounting a crafted filesystem or
  plugging a malicious USB stick exercises kernel parsers.
- **BPF / verifier bugs:** the eBPF verifier is supposed to prove programs safe;
  a verifier flaw → attacker runs semi-arbitrary code in-kernel. A recurring,
  high-value LPE source.
- **Per-CPU / RCU lifetime bugs**, **list-corruption** from races.

---

## 7.5 Impact

- **Local privilege escalation** to root (the usual goal): overwrite credentials
  (`struct cred`), call `commit_creds(prepare_kernel_cred(0))`, or corrupt page
  tables.
- **Container/VM escape**, **secure-boot/KASLR defeat**, persistent rootkits.
- **System-wide crash** (kernel panic) as DoS.

---

## 7.6 Kernel mitigations (parallels to Chapter 6, plus kernel-only)

| Mitigation | What it does |
|------------|--------------|
| **KASLR / FG-KASLR** | randomize kernel base / function layout |
| **SMEP** | kernel can't **execute** userspace pages (kills "ret2user" shellcode) |
| **SMAP** | kernel can't **access** userspace pages except via accessors (kills many arbitrary-write tricks) |
| **KPTI** | separate page tables for user/kernel (Meltdown mitigation; also hardens) |
| **stack canaries / `CONFIG_STACKPROTECTOR`** | as userspace |
| **`refcount_t`** | saturating counters to stop refcount under/overflow |
| **`CONFIG_SLAB_FREELIST_HARDENED`**, random freelist, **`init_on_alloc`/`init_on_free`** | harden the slab, zero memory to kill infoleaks/UAF reuse |
| **kCFI / CFI** | validate indirect calls |
| **`hardened usercopy`** | bounds-check `copy_{to,from}_user` against object size |
| **seccomp / namespaces / LSMs (SELinux, AppArmor, lockdown)** | shrink the reachable attack surface |

Defense-in-depth is even more important here because a single kernel bug is so
powerful.

---

## 7.7 How to study the kernel safely

- **Never** test on a machine you care about. Use a **QEMU/KVM VM** with a kernel
  you built with debug symbols; snapshot it so you can revert after a panic.
- Learn with **syzkaller** (Google's coverage-guided kernel fuzzer) — it finds
  these bugs automatically and gives reproducers; reading its reports is a superb
  education.
- Enable **KASAN** (Kernel AddressSanitizer, `CONFIG_KASAN=y`) in your test
  kernel — it reports kernel OOB/UAF with full traces, exactly like userspace
  ASan.
- Read real write-ups: the kernel's own `Documentation/security/`, the
  **kernelctf** program, and public LPE write-ups (Dirty COW, Dirty Pipe,
  CVE-2021-22555, nf_tables bugs) — with the CVEs now patched, these are study
  material, not live weapons.

---

## Chapter 7 recap

- Kernel bugs are the **same classes** (overflow/UAF/intoverflow) but yield
  **root / full-machine** compromise.
- The **user/kernel boundary** adds unique bugs: missing length checks,
  **double-fetch TOCTOU**, and **uninitialized-memory infoleaks** via
  `copy_to_user`.
- **UAF + refcount bugs + races** (SLUB reclamation, heap spray) dominate modern
  kernel LPE.
- Mitigations mirror userspace (KASLR, canaries, CFI) plus kernel-only ones
  (**SMEP/SMAP/KPTI**, hardened usercopy, `refcount_t`, slab hardening,
  `init_on_free`).
- Study only in a **throwaway VM** with KASAN; let **syzkaller** show you how
  bugs are found.

Next: how to actually practice all of this, and where to go deeper.
**[Chapter 8: Practice, tooling & resources »](08-practice-and-resources.md)**
