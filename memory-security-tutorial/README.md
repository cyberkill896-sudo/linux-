# Memory Corruption & Binary Security — A Complete Tutorial

A beginner-to-advanced course on **memory-safety vulnerabilities** in native
(C/C++/assembly) programs: how program memory is laid out, how each class of
bug arises, *why* it happens at the machine level, how it is exploited in
principle, and — just as important — how modern systems defend against it.

This is **educational, defensive-oriented material**. The goal is to understand
these bugs well enough to *find and fix them in your own code* and to compete in
CTFs / do authorized security research. Everything here is standard
university-level computer-security content (think *Hacking: The Art of
Exploitation*, CMU's Bomb/Attack Lab, OST's pwn courses). Only run the examples
against **your own programs in your own lab VM**.

---

## How to read this course

Go in order the first time — each chapter builds on the previous one.

| # | Chapter | What you learn |
|---|---------|----------------|
| 1 | [Memory layout of a binary](01-memory-layout.md) | ELF sections, stack, heap, registers, the call stack, calling conventions. The mental model everything else needs. |
| 2 | [Stack buffer overflows](02-stack-buffer-overflow.md) | The classic bug. Overwriting locals, saved registers, and the return address. Return-address hijacking. |
| 3 | [The heap & dynamic memory](03-heap-and-dynamic-memory.md) | How `malloc`/`free` work, chunk metadata, heap overflows. |
| 4 | [Use-after-free & dangling pointers](04-use-after-free.md) | Lifetime bugs, dangling pointers, type confusion via UAF. |
| 5 | [Other memory bugs](05-other-memory-bugs.md) | Format strings, integer overflow→overflow, double-free, off-by-one, OOB read (Heartbleed-style), uninitialized memory. |
| 6 | [Mitigations & how they're bypassed](06-mitigations.md) | Stack canaries, NX/DEP, ASLR, PIE, RELRO, CFI — and ROP / ret2libc at a conceptual level. |
| 7 | [Kernel memory vulnerabilities](07-kernel-memory.md) | Why the kernel is different, kernel UAF, ref-count bugs, the user/kernel boundary. |
| 8 | [Practice, tooling & resources](08-practice-and-resources.md) | Safe lab setup, sanitizers, fuzzing, debuggers, CTF practice sites, books. |

Each vulnerability chapter follows the same structure:

- **What it is** — a plain-language definition.
- **Why it happens** — the language/hardware reason the bug is even possible.
- **How it happens** — annotated vulnerable code + memory diagrams.
- **Multiple test cases** — several small programs showing variants.
- **Impact** — what an attacker gains.
- **The fix** — the correct, safe way to write the same code.

---

## Prerequisites

- **C basics**: variables, pointers, arrays, functions, `malloc`/`free`.
- **Comfort with a Linux terminal.**
- A little **assembly** curiosity. Chapter 1 teaches the minimum x86-64 you need;
  you do **not** need to already know assembly.

## Set up a safe lab first (do this before Chapter 2)

Use a throwaway Linux VM (Ubuntu/Debian in VirtualBox, or a container). Install
the toolchain:

```bash
sudo apt update
sudo apt install -y build-essential gdb gcc-multilib \
                    python3 python3-pip git
# Nice-to-haves used later:
pip3 install --user pwntools
# GDB enhancement (pick one): GEF or pwndbg
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"   # GEF
```

To **reproduce** classic bugs you must *turn off* modern protections while
learning (Chapter 6 explains each flag). A standard "training" compile line:

```bash
gcc -g -O0 -fno-stack-protector -z execstack -no-pie vuln.c -o vuln
# and disable ASLR for the shell session:
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

> These flags make programs *deliberately insecure* so the mechanics are
> visible. Never ship anything built this way. Re-enable ASLR with `2` when done.

Ready? Start with **[Chapter 1: Memory layout of a binary »](01-memory-layout.md)**
