# Chapter 12 — Code Reuse: ret2libc, ROP & Friends

> When **NX** made injected shellcode non-executable (Chapter 13), attackers
> stopped injecting code and started **reusing code already in the process**.
> This chapter explains that family at the assembly level. It's conceptual
> education for CTFs/authorized research — the mechanics, not a targeted weapon.

Prereq: Chapter 2 (return-address control). Everything here assumes you can
already overwrite a saved return address; the question is *what to point it at*
when you can't run your own bytes.

---

## 12.0 In plain words (start here)

By Chapter 2 you can overwrite the return address, so you control where the CPU
jumps. The obvious plan — "put my own machine code (shellcode) on the stack and
jump to it" — **does not work** on modern systems, because **NX** (Chapter 13)
marks the stack non-executable: the CPU refuses to run instructions from it.

So attackers switched tactics: instead of bringing their own code, they **reuse
code that is already in the program and already allowed to execute** — chiefly
the C library (**libc**), which is loaded into every process and contains handy
functions like `system()` (which runs a shell command).

Two levels of this:

- **ret2libc** — point the return address straight at an existing function such
  as `system`, having arranged its argument so it runs `system("/bin/sh")`. No
  new code at all; you just "return into libc."
- **ROP (Return-Oriented Programming)** — when no single function does what you
  want, you stitch together dozens of *tiny* existing snippets. Each snippet is a
  couple of instructions that ends in `ret` — called a **gadget**. Here's the key
  trick: because `ret` jumps to whatever address is on top of the stack, if you
  fill the stack with a *list of gadget addresses*, each gadget runs and its
  final `ret` automatically launches the next one. You've turned "a stack full of
  addresses" into "a little program" built entirely from fragments of the
  victim's own code.

An analogy: you can't write your own ransom note (NX), so you cut individual
words out of a newspaper the victim already owns and paste them into the sentence
you want. Each word is a gadget; the pasted-together sentence is the ROP chain.

Two realities make this harder (and explain why real exploits have multiple
stages):
- Under **ASLR** (Chapter 13) you don't know *where* libc's functions/gadgets
  are each run, so you first need an **information leak** to learn one address and
  compute the rest.
- The calling convention matters: to call `system("/bin/sh")` on 64-bit Linux the
  string's address must be in the `rdi` register (Chapter 1 §1.7), so you need a
  gadget like `pop rdi ; ret` to load it.

The rest of this chapter builds these step by step at the assembly level. It's
conceptual/CTF education — the mechanics, not a targeted weapon.

---

## 12.1 The core idea

The stack, after an overflow, is a **list of 8-byte values**. `ret` pops one into
`rip` and jumps. If the thing you jump to **also ends in `ret`**, it will pop the
*next* value and jump again. So a stack full of carefully chosen addresses becomes
a **program** made of existing instruction fragments. That's return-oriented
programming.

```
   saved rip  ->  [ addr of gadget1 ]   ret pops this -> execute gadget1 -> its ret
                  [ data for gadget1 ]
                  [ addr of gadget2 ]   gadget1's ret pops this -> gadget2 -> ret
                  [ addr of gadget3 ]
                  ...
```

---

## 12.2 ret2win (warm-up, no NX issue)

If the binary already contains a useful function (CTF `win()`/`give_shell()`),
just overwrite the return address with its address (Chapter 2, test 3). No gadgets
needed. The stepping stone to the real techniques.

---

## 12.3 ret2libc — call a libc function (defeats NX)

libc is mapped executable and full of useful functions — notably
`system("/bin/sh")`. To *call* `system` you must satisfy the calling convention:
on **x86-64**, the first argument goes in **`rdi`**. So you need a gadget that
loads `rdi` from the stack:

```asm
pop rdi ; ret        ; pops the next stack value into rdi, then returns
```

Stack layout for `system("/bin/sh")`:

```
[ saved rip ]  ->  [ addr of `pop rdi ; ret` ]   ; gadget
                   [ addr of "/bin/sh" string ]  ; popped into rdi (arg1)
                   [ addr of a bare `ret` ]      ; stack-alignment fixup (movaps)
                   [ addr of system ]            ; finally call system
```

Finding the pieces:
```bash
ROPgadget --binary ./libc.so.6 | grep ': pop rdi ; ret'
strings -a -t x libc.so.6 | grep /bin/sh      # offset of the "/bin/sh" string
```
On **x86 (32-bit)** it's even simpler — args are on the stack:
`[system][fake_ret][&"/bin/sh"]`.

pwntools:
```python
rop = ROP(libc)
rop.call('system', [next(libc.search(b'/bin/sh\x00'))])
payload = b'A'*offset + rop.chain()
```

**Why the `pop rdi` gadget matters:** it's the bridge between "I control the
stack" and "I control a register." Controlling argument registers is the whole
game on x86-64.

---

## 12.4 ROP — chaining gadgets into arbitrary computation

When no single function does what you want, chain **gadgets** — short sequences
ending in `ret` — to build the operation. Common gadget types:

```asm
pop rdi ; ret            ; set arg1
pop rsi ; ret            ; set arg2
pop rdx ; ret            ; set arg3
pop rax ; ret            ; set syscall number / return reg
mov [rdi], rsi ; ret     ; WRITE: *rdi = rsi   (write-what-where)
mov rax, [rdi] ; ret     ; READ
add rsp, 0x8 ; ret       ; adjust stack
syscall ; ret            ; invoke a kernel call
xchg rax, rsp ; ret      ; stack pivot (below)
```

Example: perform the `execve("/bin/sh",0,0)` **syscall** directly (no libc
`system` needed), which is just:

```
set rax = 59 (SYS_execve)      via  pop rax ; ret ; 59
set rdi = &"/bin/sh"           via  pop rdi ; ret ; addr
set rsi = 0                    via  pop rsi ; ret ; 0
set rdx = 0                    via  pop rdx ; ret ; 0
invoke                         via  syscall ; ret
```

Each line is one gadget address + its data on the stack. ROP is **Turing-
complete** given a rich enough gadget set; in practice you only need enough to set
up one syscall or `system`. **JOP** (jump-oriented programming) is the variant
using `jmp`-ending gadgets when `ret`s are scarce/guarded (e.g. under shadow
stacks).

---

## 12.5 Finding gadgets

```bash
ROPgadget --binary ./vuln                 # list all gadgets
ropper --file ./vuln --search 'pop rdi'   # targeted search
# pwntools auto-builds chains:
python3 -c 'from pwn import *; r=ROP(ELF("./vuln")); r.call("puts",[0x...]); print(r.dump())'
```
Gadgets come from the binary itself and from **libc**. Because gadgets are just
byte sequences that *happen* to decode to `...; ret`, x86's variable-length
instructions mean they're abundant — you can jump into the *middle* of an
intended instruction and get a different, useful one.

---

## 12.6 The leak problem (why ROP needs an info leak)

Under **ASLR/PIE**, you don't know libc's or the binary's base, so you don't know
gadget/function addresses. Standard solution — a **two-stage** exploit:

```
Stage 1 (ROP): call puts(puts@got)  -> leaks libc's real address of puts
               then return to main / the vulnerable function again
Stage 2 (ROP): compute libc base = leaked_puts - known_offset,
               build the real system("/bin/sh") chain with correct addresses
```
`puts(got_entry)` prints a live libc pointer; subtract the known offset of `puts`
within that libc version → **libc base** → every gadget/function address. This
"leak then pivot" is the canonical modern stack exploit. (It's also why knowing
the exact libc version matters — see the libc-database / `libc.rip`.)

---

## 12.7 ret2csu — control rdx/rsi when gadgets are scarce

Statically linked or stripped binaries may lack `pop rsi/rdx` gadgets. The
compiler-generated `__libc_csu_init` contains a reliable sequence that `pop`s
`rbx/rbp/r12/r13/r14/r15` and then `mov`s them into `rdx/rsi/rdi` before a call —
a universal gadget for setting up 3-argument calls. Knowing `ret2csu` exists is
enough; pwntools' `ROP` uses it automatically. (Newer GCC changed the init
routines, so modern targets vary.)

---

## 12.8 Stack pivot — when the overflow space is tiny

Sometimes you can only overwrite a few bytes past the return address — not enough
for a whole chain. A **stack pivot** gadget points `rsp` at memory you *do*
control (a large buffer elsewhere), and the ROP chain runs from there:

```asm
pop rsp ; ret            ; rsp = attacker-chosen address
xchg rax, rsp ; ret      ; if you control rax
leave ; ret              ; rsp = rbp ; pop rbp  (pivot via a controlled rbp)
add rsp, 0x100 ; ret     ; skip forward
```
Pivoting is the bridge from a **small** overflow to a **large** heap/BSS-resident
chain. The `leave; ret` pivot connects to the off-by-one saved-RBP overwrite from
Chapter 2.

---

## 12.9 GOT overwrite (data-only control-flow hijack)

With **Partial RELRO**, the **GOT** is writable. A write primitive (ROP
`mov [rdi],rsi`, a format-string `%n`, or an arbitrary-write heap primitive) can
overwrite a GOT entry (e.g. `strlen@got`) with the address of `system`. The next
call to that function jumps to `system` instead. **Full RELRO** maps the GOT
read-only after startup and kills this — one of the cheapest, most effective
hardening flags.

---

## 12.10 SROP — Sigreturn-Oriented Programming

The kernel's `sigreturn` syscall restores **all** registers from a `sigcontext`
frame on the stack. If you can call `sigreturn` (a single gadget) with a **fake
frame** you wrote, you set *every* register at once — `rax,rdi,rsi,rdx,rip,rsp`,
everything — with just one gadget plus data. Great when gadgets are scarce.
pwntools has `SigreturnFrame()` to build the frame. Elegant demonstration that the
kernel's own convenience features become exploitation tools.

---

## 12.11 ret2dlresolve — no libc leak needed

Instead of leaking libc, abuse the dynamic linker's lazy-resolution machinery
(`_dl_runtime_resolve` + forged `.rel.plt`/`.dynsym`/`.dynstr` structures) to make
the linker *resolve and call* `system` for you. Removes the need for an info leak
on non-Full-RELRO binaries. Advanced; pwntools has `Ret2dlresolvePayload`.

---

## 12.12 Impact
These are **techniques, not bugs** — they convert a control-flow primitive
(Chapter 2/4/5/7) into **arbitrary code execution despite NX and ASLR**. Together
with a leak they are how essentially every modern userspace stack/heap bug reaches
RCE.

---

## 12.13 Defenses (and how they shift the attacker)
- **Full RELRO** → no GOT overwrite.
- **Shadow stack / Intel CET, ARM PAC/BTI** → `ret` to a non-return site faults →
  breaks ROP's core trick (pushes attackers to JOP/data-only).
- **CFI** (`-fsanitize=cfi`, kCFI) → indirect calls must hit valid targets → breaks
  vtable/function-pointer entry and many JOP chains.
- **ASLR/PIE** → forces the info-leak stage; **PIE + no fixed gadgets** raises cost.
- **Smaller attack surface / static analysis / memory safety** → remove the
  *bug* so there's no control primitive to reuse code with.

The arms race: NX → code reuse (ROP); ASLR → leaks; RELRO → FSOP/other targets;
CET/CFI → data-only attacks. **Eliminating the bug is the only thing that ends the
chain.**

---

## Recap
- Code reuse defeats NX by chaining **existing** executable code via the stack of
  addresses `ret` walks.
- **ret2libc** calls `system` (set `rdi` with `pop rdi ; ret`); **ROP** chains
  gadgets into arbitrary syscalls/computation; **JOP/SROP/ret2csu/ret2dlresolve**
  are variants for constrained targets; **stack pivot** scales a tiny overflow;
  **GOT overwrite** is data-only hijack.
- All need an **info leak** under ASLR (the `puts(puts@got)` pattern).
- Defenses (Full RELRO, CET/shadow-stack, CFI, ASLR) each remove one technique;
  only memory safety removes the bug.

Next: **[Chapter 13 — Mitigations & how they're bypassed »](13-mitigations.md)**
