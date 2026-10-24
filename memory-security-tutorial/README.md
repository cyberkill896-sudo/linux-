# Memory Corruption & Binary Security — A Complete Tutorial

A beginner-to-advanced course on **memory-safety vulnerabilities** in native
(C/C++/assembly) programs: how program memory is laid out, how each class of bug
arises, *why* it happens at the machine level, how it is exploited in principle,
and how modern systems defend against it.

This is **educational, defensive-oriented material** — standard
university/CTF-level content (think *Hacking: The Art of Exploitation*, CMU's
Attack Lab, pwn.college, how2heap). The goal: understand these bugs well enough
to **find and fix them in your own code** and to compete in CTFs / do authorized
research. Only run the examples against **your own programs in your own lab VM**.

---

## Course map

Go in order the first time; each chapter builds on the last. Every vulnerability
chapter has **many annotated test cases** and ends with the safe fix.

| # | Chapter | What you learn |
|---|---------|----------------|
| 1 | [Memory layout of a binary](01-memory-layout.md) | ELF sections, stack, heap, registers, the call stack, calling conventions, endianness. |
| 2 | [Stack buffer overflows](02-stack-buffer-overflow.md) | 12 test cases: locals, saved regs, return address, off-by-one, loop bounds, memcpy, argv/env, alloca/VLA, array index, struct padding. |
| 3 | [The heap & dynamic memory](03-heap-internals.md) | ptmalloc internals: chunks, flags, bins/tcache, consolidation — the model heap bugs exploit. |
| 4 | [Heap overflows & corruption](04-heap-overflow.md) | 10 test cases: adjacent-object/metadata overflow, length-field corruption, off-by-one NUL, calloc vs malloc. |
| 5 | [Heap exploitation techniques](05-heap-techniques.md) | tcache poisoning, fastbin dup, double-free, unlink, House of Force/Einherjar/Spirit, overlapping chunks (conceptual + PoCs). |
| 6 | [Use-after-free & dangling pointers](06-use-after-free.md) | 9 test cases: UAF reclaim, double-free, use-after-realloc, dangling stack, callback/refcount, iterator invalidation. |
| 7 | [Format-string vulnerabilities](07-format-string.md) | 8 test cases: leaks, `%n` writes, positional args, GOT overwrite, direct parameter access, `%s` crash. |
| 8 | [Integer bugs → memory corruption](08-integer-bugs.md) | 10 test cases: overflow, underflow, truncation, signedness, sign-extension, pointer arithmetic, `malloc(a*b)`. |
| 9 | [Out-of-bounds, uninitialized & misc](09-oob-and-misc.md) | OOB read/write, Heartbleed shape, uninitialized read/infoleak, wild/NULL pointers, memory leaks, stack exhaustion. |
| 10 | [C++-specific memory bugs](10-cpp-bugs.md) | vtable hijack, type confusion, use-after-move, `delete` vs `delete[]`, placement-new, iterator/reference invalidation, slicing. |
| 11 | [Race conditions → memory corruption](11-races.md) | TOCTOU, double-fetch, data-race UAF, signal-handler reentrancy, Dirty COW/Dirty Pipe shapes. |
| 12 | [Code reuse: ret2libc, ROP & friends](12-code-reuse.md) | ret2win, ret2libc, ROP chains, GOT overwrite, ret2csu, stack pivot, SROP, ret2dlresolve (conceptual). |
| 13 | [Mitigations & how they're bypassed](13-mitigations.md) | Canary, NX, ASLR/PIE, RELRO, FORTIFY, CFI/CET/PAC, hardened allocators — the arms race. |
| 14 | [Kernel memory vulnerabilities](14-kernel-memory.md) | user/kernel boundary, double-fetch, kernel UAF/refcount, slab spray, SMEP/SMAP/KPTI/KASAN. |
| 15 | [Practice, tooling & resources](15-practice-and-resources.md) | Lab setup, sanitizers, fuzzing, debuggers, CTF sites, books, a study plan. |
| 16 | [Shellcode & ret2shellcode](16-shellcode.md) | what shellcode is, `execve("/bin/sh")` byte-by-byte, NOP sleds, why NX killed it, ret2mprotect, encoders/egg-hunters. |
| 17 | [Real-world CVE case studies](17-case-studies.md) | Heartbleed, Morris worm, Dirty COW, Dirty Pipe, a browser UAF, Stagefright, sudo Baron Samedit — each dissected. |

### Also in this course

- **[`src/`](src/README.md)** — **runnable, heavily-commented** `.c`/`.cpp`
  programs for the test cases, a `Makefile` (insecure `make` + hardened
  `make safe` + `make asan/tsan/msan`), and pwntools exploit scripts in
  `src/exploits/`. Read the code — the comments explain each bug line by line.
- **[`EXERCISES.md`](EXERCISES.md)** — 55 practice questions and labs
  (⭐ beginner → ⭐⭐⭐ advanced) covering every chapter, with a capstone.
- **[`SOLUTIONS.md`](SOLUTIONS.md)** — worked answers and walkthroughs. Try the
  exercises first.
- **[`CHEATSHEET.md`](CHEATSHEET.md)** — one-page field guide to every bug class,
  its tell, and its fix.

---

## Prerequisites

- **C basics**: pointers, arrays, functions, `malloc`/`free`.
- **A Linux terminal.** A little **assembly** curiosity (Chapter 1 teaches the
  minimum; you don't need to know it already).

## Set up a safe lab first

Use a throwaway Linux VM or container.

```bash
sudo apt update
sudo apt install -y build-essential gdb gcc-multilib python3 python3-pip git
pip3 install --user pwntools
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"   # GEF (or install pwndbg)
```

Standard **training** compile line (deliberately insecure so mechanics are
visible — Chapter 13 explains every flag):

```bash
gcc -g -O0 -fno-stack-protector -z execstack -no-pie vuln.c -o vuln
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space   # disable ASLR; re-enable with 2
```

> These flags make programs insecure on purpose. Never ship anything built this
> way. Re-enable ASLR (`2`) when done.

Start with **[Chapter 1 »](01-memory-layout.md)**.
