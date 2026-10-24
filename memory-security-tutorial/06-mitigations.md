# Chapter 6 — Mitigations & How They're Bypassed

> Modern exploitation is an arms race. Each defense below removed a cheap exploit
> technique; attackers responded with a more expensive one. Understanding the
> defenses is how you both **harden your own software** and understand why real
> exploits are now multi-stage. (Bypasses here are described **conceptually** —
> enough to understand the arms race, not a how-to against real targets.)

---

## 6.1 The exploitation pipeline (so defenses make sense)

A full memory-corruption exploit usually needs, in order:

1. A **bug** (overflow / UAF / etc.) giving a write or control primitive.
2. **Knowledge of addresses** (where is my target? where is libc?).
3. A way to **redirect control** (`rip`) or **corrupt critical data**.
4. **Code to run** (injected shellcode, or reused existing code).

Each mitigation attacks one stage. Defense in depth means breaking several at
once.

---

## 6.2 Stack canaries (stack-smashing protection)

**What:** the compiler places a random "canary" value between the local buffers
and the saved RBP/return address in the prologue, and checks it in the epilogue
*before* `ret`. A linear stack overflow that reaches the return address must
first overwrite the canary; the mismatch aborts the program (`*** stack
smashing detected ***`).

```
[ buffers ] [ CANARY ] [ saved rbp ] [ return address ]
             ^ overflow must clobber this to reach ret addr
```

**Enable:** `-fstack-protector-strong` (default on most distros).
Check a binary: `checksec --file=./prog` (shows "Canary found").

**Bypassed by:**
- **Info leak** of the canary (e.g. a format-string `%p`), then include the
  correct canary in the payload.
- **Overwrites that don't cross the canary** (overwriting an adjacent local, or a
  pointer the function uses before returning) — canaries only guard the
  return-address path.
- **Brute force** on forking servers (child inherits parent's canary) — niche.

---

## 6.3 NX / DEP (non-executable data, W^X)

**What:** memory is either **writable or executable, never both** (W^X). The
stack and heap are marked non-executable (the CPU's NX bit). Injected shellcode
on the stack won't run — jumping to it faults.

**Enable:** default; `-z execstack` *disables* it (we only use that in Chapter 2
to demo old-style shellcode). `checksec` shows "NX enabled".

**Bypassed by code reuse** — don't inject code, **reuse code already marked
executable**:
- **ret2libc**: set the return address to libc's `system`, with `"/bin/sh"`'s
  address arranged as its argument (in `rdi` on x86-64, via a gadget).
- **ROP (Return-Oriented Programming)**: chain many short instruction sequences
  ("gadgets") each ending in `ret`, stitched together via a stack full of
  addresses, to perform arbitrary computation **without injecting any code**. ROP
  is Turing-complete in practice. **JOP** (jump-oriented) is the `jmp`-based
  cousin.

ROP is the central modern technique precisely because NX killed shellcode.
Tools: `ROPgadget`, `ropper`, pwntools' `ROP()` autochainer.

---

## 6.4 ASLR & PIE (address randomization)

**What:** **ASLR** randomizes the base addresses of the stack, heap, and
shared libraries each run, so the attacker can't hard-code target addresses.
**PIE** (Position-Independent Executable) extends randomization to the main
binary's own `.text`/`.data` too.

**Enable:** ASLR is a kernel feature (`/proc/sys/kernel/randomize_va_space`,
`2` = full). PIE: `-pie -fPIE` (default on modern distros; `-no-pie` disables, as
we do for teaching). `checksec` shows "PIE enabled".

**Bypassed by:**
- **Info leak** — the universal ASLR-killer. Leak *one* address from a known
  region (via format string, OOB read, UAF read) and you recover the whole
  region's base by subtracting a known offset. Most real exploits are
  **leak + corrupt**.
- **Partial overwrites** — randomization leaves the low 12 bits (page offset)
  fixed, so overwriting only the low byte(s) of a pointer can redirect within a
  known page without knowing the full address.
- **Non-PIE binaries** — if the main binary isn't PIE, its code addresses are
  fixed even under ASLR (great for ROP gadgets). That's why PIE matters.

---

## 6.5 RELRO (GOT hardening)

**What:** dynamically linked programs call library functions through the
**GOT** (Global Offset Table), filled in lazily by the **PLT**. A classic target
was overwriting a GOT entry to redirect a function call. **RELRO** makes reloc
sections read-only:
- **Partial RELRO**: some sections RO; GOT still writable (lazy binding).
- **Full RELRO** (`-Wl,-z,relro,-z,now`): entire GOT resolved at startup and
  marked **read-only** → GOT overwrite blocked.

`checksec` shows the RELRO level. Full RELRO is cheap; prefer it.

---

## 6.6 Fortify Source

**What:** `-D_FORTIFY_SOURCE=2 -O2` makes glibc/GCC replace known-size calls
(`memcpy`, `strcpy`, `sprintf`, `printf` with literal formats...) with checked
versions (`__memcpy_chk`) that **abort on overflow** when the destination size is
known at compile time. Also blocks `%n` in writable-memory format strings. Nearly
free; turn it on.

---

## 6.7 Control-Flow Integrity (CFI) & hardware help

The newest layer tries to stop **control-flow hijacking directly**:

- **CFI** (Clang `-fsanitize=cfi`, kernel's kCFI): checks that an indirect
  call/jump targets a **valid** function of the right type — breaks vtable/
  function-pointer hijacking and most ROP entry points.
- **Shadow stack / Intel CET**: hardware keeps a protected copy of return
  addresses; a mismatch at `ret` faults → defeats ROP's core trick. ARM has
  **PAC** (pointer authentication) and **BTI** (branch-target identification).
- **SafeStack**: isolates the "unsafe" buffers from return addresses on a
  separate stack.

These shift exploitation toward **data-only attacks** (corrupt *data*, not
control flow — e.g. flip an `is_admin` flag, point a length at a bigger buffer),
which CFI doesn't stop. The arms race continues.

---

## 6.8 Putting it together — `checksec` and a hardening recipe

Inspect any binary:

```bash
checksec --file=./prog
# or: pwn checksec ./prog
```

Reports: RELRO, Canary, NX, PIE, Fortify. "No RELRO / No canary / NX disabled /
No PIE" is a soft target; "Full RELRO / Canary / NX / PIE / Fortified" is
hardened.

**Compile your own code hardened:**

```bash
gcc -O2 -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -fPIE -pie \
    -Wl,-z,relro,-z,now \
    -Wl,-z,noexecstack \
    -fstack-clash-protection \
    -Wformat -Wformat-security -Werror=format-security \
    myprog.c -o myprog
```

And at the system level: keep ASLR at `2`, enable CET/PAC where the hardware
supports it, and consider a hardened allocator.

---

## 6.9 Why bugs still get exploited

No single mitigation is complete, and they combine imperfectly:

- A bug + an **info leak** defeats ASLR and canaries.
- **ROP** defeats NX.
- **Data-only** attacks sidestep CFI.
- **Mis-configuration** (non-PIE, no RELRO, execstack) is common in legacy
  software.

This is exactly why **eliminating the bug** (safe APIs, sanitizers, fuzzing,
memory-safe languages) beats relying on mitigations alone. Mitigations raise the
cost; memory safety removes the bug class.

---

## Chapter 6 recap

| Mitigation | Stops | Bypassed by |
|------------|-------|-------------|
| Stack canary | return-addr overwrite via linear overflow | canary leak; non-crossing writes |
| NX / W^X | injected shellcode | ret2libc / ROP (code reuse) |
| ASLR / PIE | hard-coded addresses | info leak; partial overwrite; non-PIE |
| RELRO (full) | GOT overwrite | (forces other targets) |
| FORTIFY | known-size overflows, `%n` | unknown-size / heap bugs |
| CFI / CET / PAC | control-flow hijack / ROP | data-only attacks |

Takeaway: modern RCE = **leak + corrupt + ROP/CFI-bypass**, which is why it's
hard — and why safe coding is the real win.

Next: the kernel, where the stakes and the rules change.
**[Chapter 7: Kernel memory vulnerabilities »](07-kernel-memory.md)**
