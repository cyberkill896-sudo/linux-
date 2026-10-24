# Chapter 13 — Mitigations & How They're Bypassed

> Each defense below removed a cheap exploit technique; attackers answered with a
> costlier one. Understanding the arms race lets you **harden your own software**
> and understand why real exploits are multi-stage. Bypasses are **conceptual** —
> enough to grasp the race, not a how-to against real targets.

---

## 13.0 In plain words (start here)

The earlier chapters make exploitation sound easy. On a 1996 system it *was*.
Since then, compilers and operating systems have added layers of defense, and
each one took away a cheap trick. This chapter explains each defense in terms of
*which attack step it blocks* and *how attackers adapted* — because you can't
harden software well without knowing what each flag actually buys.

It helps to see exploitation as a short pipeline, and each defense as a wall
across one stage:

1. **find a bug** → a buffer overflow, UAF, etc. (nothing here prevents the bug
   itself — that's what safe coding and sanitizers are for);
2. **get a primitive** → control the return address, or get a write-what-where;
3. **know where to aim** → the addresses of your target and your gadgets;
4. **run code** → shellcode, or a ROP chain.

The big four defenses each block one stage:

- **Stack canary** blocks step 2 for stack overflows: a secret value sits between
  your buffer and the return address, and is checked before `ret`; a linear
  overflow trips it and the program aborts.
- **NX (No-eXecute)** blocks step 4's easy path: the stack/heap can't be
  executed, so injected shellcode won't run (forcing the ROP of Chapter 12).
- **ASLR + PIE** blocks step 3: addresses are randomized each run, so you can't
  hard-code them.
- **RELRO** removes a popular *target* for step 2 (the GOT, a table of function
  pointers), by making it read-only.

The theme of the chapter: **no single defense is complete, and attackers chain
bypasses.** A memory leak (Chapter 7/9) defeats ASLR and canaries; ROP defeats
NX; "data-only" attacks sidestep the newest control-flow defenses. That's exactly
why real modern exploits are multi-stage, and why the only thing that *ends* the
arms race is removing the bug (safe APIs, sanitizers, fuzzing, memory-safe
languages). The table in §13.9 is a build recipe you can actually apply to your
own code.

---

## 13.1 The exploitation pipeline (so defenses make sense)

A full memory-corruption exploit usually needs, in order:
1. a **bug** (overflow/UAF/format/int) → a write or control primitive;
2. **addresses** (where is my target? where is libc?);
3. a way to **redirect control** (`rip`) or **corrupt critical data**;
4. **code to run** (inject, or reuse via ROP).

Each mitigation attacks one stage. Defense in depth breaks several at once.

---

## 13.2 Stack canaries (stack-smashing protection)

**What:** the prologue stores a random **canary** between locals and the saved
RBP/return address; the epilogue checks it before `ret`. A linear overflow that
reaches the return address must overwrite the canary first → mismatch → `__stack_
chk_fail` aborts (`*** stack smashing detected ***`).

```
[ buffers ] [ CANARY ] [ saved rbp ] [ return address ]
```
In assembly:
```asm
  mov    rax, fs:0x28        ; load canary from thread-local storage
  mov    [rbp-0x8], rax      ; place it just below saved rbp
  ...                        ; function body
  mov    rax, [rbp-0x8]
  sub    rax, fs:0x28        ; compare
  jne    __stack_chk_fail    ; abort if changed
  leave ; ret
```
**Enable:** `-fstack-protector-strong` (distro default). Check: `checksec` shows
"Canary found". The low byte of the canary is `\x00` to stop string-based leaks.

**How it actually stops the attack.** A buffer overflow writes *upward*,
contiguously, from the buffer toward the return address (Chapter 2). The canary
sits *between* them, so a linear overflow that wants to reach the return address
**must write through the canary slot first**, changing its value. The epilogue
re-reads that slot and compares it to the real canary (kept safe in thread-local
storage at `fs:0x28`); any mismatch calls `__stack_chk_fail`, which prints
`*** stack smashing detected ***` and aborts **before** the `ret` ever uses the
corrupted return address. So the attacker's hijack never happens — the program
dies cleanly instead.

**Why the low byte is `\x00`.** The canary's least-significant byte is forced to
`00`. Since most overflows come from string functions that stop at a NUL, this
means a string-based overflow that *reads* toward the canary tends to stop at
that `00`, making the canary harder to leak via naive string bugs. It's a small
hardening on top of the main mechanism.

**The three bypasses, and the reasoning behind each:**
1. **Leak it, then replay it.** The canary only works because the attacker
   *doesn't know its value*. If a **separate info-leak bug** (a format string
   `%p`, Chapter 7; an OOB read, Chapter 9) reveals the canary, the attacker
   simply includes that exact value at the canary's position in the overflow
   payload. The epilogue compares "canary" to "same canary" → match → no abort,
   and the overwritten return address beyond it still takes effect. This is why
   real exploits are "leak **then** smash."
2. **Don't cross the canary at all.** The canary only guards the path to the
   *return address*. If the function uses attacker-corruptible data *before* it
   returns — an adjacent local flag (Chapter 2 test 2), or a **function pointer /
   C++ vtable pointer** the function calls — you hijack via that, and `ret` (and
   its check) is never reached. Likewise a bug that writes to a chosen index
   (not a contiguous overflow) can overwrite the return address *without*
   touching the canary.
3. **Brute force on forking servers.** A server that `fork()`s to handle each
   connection gives every child the **same** canary as the parent (fork copies
   memory; the canary isn't re-randomized). So an attacker overwrites one canary
   byte at a time: a wrong guess crashes the child (but the server keeps
   running), a right guess doesn't — 256 tries per byte, 8 bytes = ~2048
   connections to recover the whole canary. Only works where crashes are cheap
   and the canary is stable across children.

**The takeaway:** a canary turns a *simple linear stack overflow* from "instant
RCE" into "need a second (leak) bug or a non-linear primitive." It raises the
cost; it doesn't remove the bug.

---

## 13.3 NX / DEP / W^X (non-executable data)

**What:** memory is **writable xor executable**. Stack/heap are non-executable
(CPU NX bit), so injected shellcode faults when executed. **Enable:** default;
`-z execstack` disables it (used only to demo old shellcode). `checksec`: "NX
enabled".

**Bypassed by code reuse** (Chapter 12): **ret2libc**, **ROP**, **JOP** — don't
inject code, reuse executable code already mapped. NX is *why* ROP exists.

---

## 13.4 ASLR & PIE (address randomization)

**What:** **ASLR** randomizes base addresses of stack, heap, and libraries each
run; **PIE** extends it to the main binary's own code/data.
**Enable:** ASLR = kernel (`/proc/sys/kernel/randomize_va_space` = `2`); PIE =
`-pie -fPIE` (default). `checksec`: "PIE enabled".

**Bypassed by:**
- **Info leak** — the universal ASLR killer. Leak one address from a region,
  subtract a known offset → whole region's base. Most exploits are **leak +
  corrupt** (Chapters 7, 9, 12).
- **Partial overwrite** — the low 12 bits (page offset) aren't randomized, so
  overwriting only low byte(s) of a pointer redirects within a known page.
- **Non-PIE binary** — its code is at a fixed address even under ASLR → free ROP
  gadgets. That's why PIE matters.
- Low **entropy** on 32-bit → brute-forceable.

---

## 13.5 RELRO (GOT hardening)

Dynamic calls go through the **GOT** (filled lazily via the **PLT**). Overwriting
a GOT entry redirects a call.
- **Partial RELRO:** some sections RO; **GOT still writable** (lazy binding).
- **Full RELRO** (`-Wl,-z,relro,-z,now`): all relocations resolved at startup,
  GOT marked **read-only** → GOT overwrite blocked.
`checksec` shows the level. Full RELRO is cheap — prefer it. (See Chapter 12 §9.)

---

## 13.6 FORTIFY_SOURCE

`-D_FORTIFY_SOURCE=2 -O2`: the compiler replaces known-size calls (`memcpy`,
`strcpy`, `sprintf`, `printf` with literal formats…) with checked variants
(`__memcpy_chk`) that **abort on overflow** when the destination size is known,
and restricts `%n` in writable format strings. Nearly free. `=3` (newer glibc/
GCC) checks more dynamic cases.

---

## 13.7 Control-Flow Integrity & hardware (the newest layer)

- **CFI** (Clang `-fsanitize=cfi`; kernel kCFI): indirect calls/jumps must target
  a **valid function of the right type** → breaks vtable/function-pointer hijack
  and many ROP/JOP entries.
- **Shadow stack / Intel CET:** hardware keeps a protected copy of return
  addresses; a mismatch at `ret` faults → defeats ROP's core trick.
- **ARM PAC** (pointer authentication): signs pointers (including return
  addresses) with a key; forging one fails the auth check. **BTI** restricts
  indirect-branch targets.
- **SafeStack:** moves buffers to a separate stack from return addresses.

These push attackers toward **data-only attacks** (corrupt *data*, not control
flow — flip an `is_admin`, enlarge a length), which CFI doesn't stop.

---

## 13.8 Allocator & memory hardening

- **glibc:** Safe-Linking (tcache/fastbin pointer obfuscation), tcache **key**
  (double-free detection), unlink/top-size checks, **removal of malloc/free
  hooks** (≥ 2.34), `glibc.malloc.check`/`MALLOC_CHECK_`.
- **Hardened allocators:** scudo (Android), hardened_malloc (GrapheneOS),
  PartitionAlloc (Chrome), **GWP-ASan** (sampling UAF/overflow detector in
  production).
- **`-fsanitize=address/undefined/memory/thread`** in testing/CI; **`init_on_
  alloc`/`init_on_free`** (kernel) and `-ftrivial-auto-var-init=zero` to kill
  uninitialized-memory infoleaks.

---

## 13.9 `checksec` and a hardening recipe

```bash
checksec --file=./prog        # or: pwn checksec ./prog
```
Reports RELRO / Canary / NX / PIE / Fortify. "No RELRO / No canary / NX disabled /
No PIE" = soft target; the opposite = hardened.

**Compile your own code hardened:**
```bash
gcc -O2 -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong -fstack-clash-protection \
    -fPIE -pie \
    -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
    -fcf-protection=full \
    -Wall -Wextra -Wformat -Wformat-security -Werror=format-security \
    -Wconversion -Wsign-conversion \
    myprog.c -o myprog
# C++: add -D_GLIBCXX_ASSERTIONS ; Clang: -fsanitize=cfi -flto -fvisibility=hidden
```
System: keep ASLR = `2`, enable CET/PAC where supported, consider a hardened
allocator, run sanitizers + fuzzing in CI.

---

## 13.10 Why bugs still get exploited

No single mitigation is complete, and they compose imperfectly:
- bug + **info leak** → defeats ASLR & canary;
- **ROP** → defeats NX;
- **data-only** → sidesteps CFI;
- **misconfiguration** (non-PIE, Partial RELRO, execstack) is common in legacy
  software.

Hence: **eliminating the bug** (safe APIs, sanitizers, fuzzing, memory-safe
languages) beats relying on mitigations. Mitigations raise cost; memory safety
removes the class.

---

## Recap
| Mitigation | Stops | Bypassed by |
|------------|-------|-------------|
| Stack canary | ret-addr overwrite via linear overflow | canary leak; non-crossing writes; brute force |
| NX / W^X | injected shellcode | ret2libc / ROP / JOP |
| ASLR / PIE | hard-coded addresses | info leak; partial overwrite; non-PIE |
| Full RELRO | GOT overwrite | (forces FSOP/other targets) |
| FORTIFY | known-size overflows, `%n` | unknown-size / heap bugs |
| CFI / CET / PAC | control-flow hijack / ROP | data-only attacks |
| Allocator hardening | tcache/unlink/hook abuse | heap leak + newer techniques |

Modern RCE = **leak + corrupt + ROP/CFI-bypass** — which is why it's hard, and why
safe coding is the real win.

Next: **[Chapter 14 — Kernel memory vulnerabilities »](14-kernel-memory.md)**
