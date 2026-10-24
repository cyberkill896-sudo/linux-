# Chapter 2 — Stack Buffer Overflows (12 test cases)

> The original, canonical memory-corruption bug ("Smashing the Stack for Fun and
> Profit", Aleph One, 1996). Master this and every other bug is a variation.
> Needs Chapter 1 (the stack frame, `call`/`ret`). We start gentle, then go all
> the way to real exploitation.

---

## 2.0 In plain words (start here)

Picture a row of memory boxes from Chapter 1. A **buffer** is just a handful of
adjacent boxes a program set aside for some data — say 16 boxes for a 16-byte
name. The boxes *right after* those 16 don't belong to the name; they hold other
things the program needs, including (eventually) the **return address** — the
"sticky note" that says where to go when the current function finishes (Chapter 1
§1.6).

Now imagine the program copies a name into those 16 boxes **without checking how
long the name is**. If someone gives it a 40-character name, the program writes
40 boxes' worth of data starting at box 0 — filling the 16 name boxes and then
*spilling over* into the boxes after it. It's like pouring 40 cl of water into a
16 cl glass: the extra 24 cl runs onto the table and into whatever is sitting
next to the glass.

That "whatever is next to it" includes the return-address sticky note. So the
attacker, just by sending a long enough name with specific bytes at the end, can
**overwrite the note** with an address of their choosing. When the function
finishes and the CPU reads the note (the `ret` instruction from Chapter 1), it
jumps to the attacker's address instead of back to the caller. The attacker now
controls what code runs.

That's the entire idea. The rest of this chapter makes it precise, shows it
happening at the machine-code level, gives you twelve variations to recognize,
and ends with how it's actually exploited on modern systems.

Three terms you'll see throughout:
- **buffer** — a fixed-size group of boxes for data (e.g. `char buf[16]`).
- **overflow** — writing past the end of those boxes into neighbors.
- **return address** — the saved "where to resume" note, sitting just above the
  buffers in the stack frame; the prime overwrite target.

---

## 2.1 What it is

A **buffer overflow** writes **more data into a buffer than it can hold**, so the
write spills into *adjacent* memory. When the buffer is a **local variable on the
stack**, adjacent memory includes the saved frame pointer and the **return
address**. Overwrite the return address → when the function runs `ret`, the CPU
jumps wherever you told it.

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
**What happens, step by step.** `main` has two locals: `pass[16]` and `authed`.
The compiler places them in `main`'s stack frame, typically adjacent, with
`authed` just above `pass` (toward higher addresses). `authed` starts at 0, so
the `if` would normally take the `else` branch — access denied. `gets(pass)`
reads an entire line from the user with **no length limit** (that is the whole
reason `gets` was removed from the C standard). If the user types 16 characters,
`pass` is exactly full and `authed` is untouched. If the user types 17 or more
**non-zero** characters, byte number 17 (and beyond) is written *past* the end of
`pass`, into the bytes that store `authed`. Any non-zero byte landing there makes
`authed` non-zero, so `if (authed)` is now true → access granted, with no
password ever checked.

**Why `volatile`.** Without it, an optimizing compiler might notice that nothing
in the *source* ever assigns `authed` and "prove" it is always 0, deleting the
check entirely. `volatile` forces the compiler to actually read `authed` from
memory each time, so the demo behaves predictably. (In real code the flag is set
by legitimate logic elsewhere; `volatile` here just stands in for "the compiler
can't assume it stays 0.")

**Why this matters more than it looks.** You did *not* need to control the return
address, defeat a canary, or know any address. You flipped one integer next to a
buffer. This "overwrite the neighbor" pattern is the **most common real-world
consequence** of an overflow, because the neighbor is often exactly the kind of
value that gates behavior: an `is_authenticated` flag, a length field used by a
later copy, a privilege level, or a function pointer the code will call. Many
shipped CVEs are "corrupt an adjacent field," not "full control-flow hijack."

**Finding the exact offset on your build.** Field order and padding are
compiler- and flag-dependent, so don't assume "17." Measure it in GDB:
```gdb
break <line of the if>
run
p &pass            # e.g. 0x7fffffffe230
p &authed          # e.g. 0x7fffffffe240
# distance = &authed - &pass; type that many bytes, then one more non-zero byte
```
If `authed` turns out to be *below* `pass` on your build, this particular
overflow won't reach it (overflow only goes upward) — which is itself a useful
lesson about how layout decides exploitability.

**The fix.** Bound the read to the buffer and never let a security decision
depend on a value sitting next to an unbounded buffer:
```c
fgets(pass, sizeof pass, stdin);   // reads at most 15 chars + NUL; never overruns
```

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
**What this demonstrates.** This is the first *full control-flow hijack*. The
program contains a function `win()` that spawns a shell but is **never called**
on the normal path — `main` only calls `vuln`. If we can make the program run
`win` anyway, we've proven we control execution. This "reach the hidden win
function" exercise is the canonical first pwn challenge ("ret2win").

**Walking the exploit.**
1. `vuln` declares `buf[32]` and calls `gets(buf)` — the same unbounded-read bug.
   Its stack frame is: `buf` (32 bytes), then the saved RBP (8 bytes), then the
   return address (8 bytes) — exactly the Chapter 1 picture.
2. To reach the return address we must fill `32 + 8 = 40` bytes, so the **offset**
   is 40. (Always verify with a cyclic pattern — §2.4 — rather than trusting the
   arithmetic; alignment padding can change it.)
3. We find `win`'s address. Because the binary is built `-no-pie`, that address
   is **fixed** every run, so we can hard-code it. `objdump -d t03 | grep
   '<win>:'` prints it; pwntools reads it as `e.sym['win']`.
4. The payload is `b'A'*40 + p64(win_addr)`: 40 filler bytes to reach the return
   slot, then `win`'s address written over the return address. `p64` encodes it
   as 8 little-endian bytes (Chapter 1 §1.8).
5. When `vuln` finishes, `ret` pops our `win` address into `rip` and the program
   "returns" into `win`, which runs `system("/bin/sh")` → a shell.

**The alignment gotcha (important, real).** On x86-64, the ABI requires `rsp` to
be 16-byte aligned when a `call` happens. libc functions such as `system` use SSE
instructions like `movaps [rsp], xmm0` that **fault** if `rsp` is misaligned. Our
single return-address overwrite can leave `rsp` 8 off, so `system` crashes inside
libc instead of giving a shell. The fix is to jump first to a harmless `ret`
gadget (any lone `ret` instruction in the binary): executing it pops 8 bytes,
nudging `rsp` by 8 back into alignment, and its own `ret` then continues to
`win`. So the robust payload is `b'A'*40 + p64(ret_gadget) + p64(win_addr)`.
pwntools' `ROP(e)` inserts this automatically — but now you know *why* that extra
gadget appears in write-ups. It's not magic; it's the ABI's alignment rule.

**On a modern (hardened) build** `win` wouldn't exist and the binary would be PIE
(so `win`'s address is randomized) with a stack canary (so the linear overflow
aborts first). Then you'd need the Chapter 12/13 techniques: leak an address to
defeat PIE, leak the canary, and build a ROP chain instead of a single address.
The *offset* and the *overflow* are identical; only what you place after the
offset changes.

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
**The bug is the `<=`.** A loop that should copy 16 bytes (`i` from 0 to 15)
instead runs `i` from 0 to 16 *inclusive* — 17 iterations — because of `<=`
instead of `<`. The extra write, `buf[16] = src[16]`, lands one byte past the end
of `buf`. This "fencepost error" (named after the "how many posts for a 10-metre
fence?" puzzle) is one of the most common real bugs, and it looks completely
innocent in a code review.

**Why one byte can be enough.** It depends on what sits in that one byte just
above `buf`. If `buf` ends exactly where the **saved RBP** begins, `buf[16]`
overwrites the **least-significant byte of the saved RBP**. Recall from Chapter 1
that the function epilogue is `leave` (= `mov rsp, rbp ; pop rbp`) then `ret`.
After this function returns, its *caller* eventually runs its own `leave`, which
does `mov rsp, rbp` using the RBP we just corrupted — so the caller's stack
pointer is now pointing a bit lower/higher than it should, into memory the
attacker influenced. The caller's subsequent `ret` then reads its "return
address" from that shifted location. With careful setup an attacker uses this
"frame-pointer overwrite" / "stack pivot" to redirect execution even though they
only changed **one byte**.

Even when it isn't the saved RBP, a one-byte overwrite of an adjacent length or
flag (as in test case 2) can be decisive. The heap has an even more famous
one-byte bug — the "poison NUL byte," where a stray terminator corrupts the next
chunk's size (Chapter 4).

**The fix.** Use `<` and reserve room for the terminator:
```c
for (size_t i = 0; i + 1 < sizeof buf && src[i]; i++) buf[i] = src[i];
buf[i] = '\0';          // always leave space for the NUL
```
Compile-time help: `-fsanitize=address` flags the 1-byte write immediately, and
`-fstack-protector-strong` turns a saved-RBP overwrite into a detected abort.

---

## 2.8 Test case 5 — off-by-one NUL from strncpy

```c
// t05_strncpy_nul.c
char buf[16];
strncpy(buf, src, sizeof buf);   // if strlen(src) >= 16, buf is NOT terminated
printf("%s", buf);               // prints past buf -> OOB read / leak
buf[strlen(buf)] = '!';          // strlen walks past -> OOB write
```
**The subtle trap.** Programmers reach for `strncpy` thinking "the `n` makes it
safe." But `strncpy(dst, src, n)` has a surprising rule: it copies at most `n`
bytes, and it only writes a terminating NUL **if `src` is shorter than `n`**. If
`src` is `n` bytes or longer, it copies exactly `n` bytes and stops — leaving
`dst` **with no `\0` at the end**. So `buf` is now a 16-byte blob of characters
with no terminator.

**Why that is dangerous — two separate bugs follow.** A C string is "characters
until a `\0`." If there's no `\0` inside `buf`, every function that looks for one
keeps reading *past* `buf` into neighboring memory until it happens to find a
zero byte somewhere:
- `printf("%s", buf)` reads and prints those neighboring bytes — an
  **out-of-bounds read / information leak** (it dumps whatever is on the stack
  after `buf`, possibly a canary or a pointer).
- `strlen(buf)` returns a length longer than 16, so `buf[strlen(buf)] = '!'`
  writes `'!'` at some offset *past* `buf` — an **out-of-bounds write** whose
  position you don't control.

So a "safe-looking" `strncpy` quietly becomes both a leak and a corruption.

**The fix.** Either terminate explicitly after `strncpy`, or use a function that
always terminates:
```c
strncpy(buf, src, sizeof buf - 1);
buf[sizeof buf - 1] = '\0';          // guarantee termination
// or simply:
snprintf(buf, sizeof buf, "%s", src); // always NUL-terminates, never overruns
```
(On BSD/macOS, `strlcpy` always terminates and is the intended replacement.)

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
**Why this is the most important shape to recognize.** In real software the
overflow length almost never comes from `strlen` of a local string — it comes
from **a number the attacker supplies**: a "content-length" header, a record
count in a file, a field in a network packet. Here `scanf("%d", &n)` reads that
number straight from input, and the loop then writes `n` bytes into a 64-byte
buffer with no check. The attacker simply sends `n = 200` and writes 136 bytes
past `buf` — through the saved RBP and return address — with full control over
the content (each `getchar()` byte).

This is exactly the bug in the **login-server walkthrough**
([`walkthroughs/01-login-server`](walkthroughs/01-login-server/WALKTHROUGH.md))
and in real CVEs like Heartbleed (a length field trusted without checking,
Chapter 9 / cve-labs) — the pattern is everywhere a program reads "how many" from
an untrusted source.

**Two things to notice about the code:**
- `n` is a signed `int`. If the attacker sends a *negative* number, the
  comparison `i < n` is immediately false (no iterations) — but if `n` were later
  used as a `size_t` in a `memcpy`, a negative value becomes a gigantic unsigned
  length (Chapter 8). Mixing signed input with unsigned sizes is its own bug.
- There is no upper bound at all. The only correct version checks `n` against the
  real capacity *before* the loop.

**The fix.**
```c
if (n < 0 || n > (int)sizeof buf) { /* reject */ return; }
for (int i = 0; i < n; i++) buf[i] = getchar();
```
Validate every length/count from input against the actual destination size, as
the first thing you do with it.

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
**The lesson beginners miss: "safe-looking" functions are not safe.** `memcpy`,
`memmove`, `read`, and `recv` all take an explicit length, so they *feel* safer
than `strcpy`. But they copy **exactly the length you give them**, no more and no
less — they do not know or check the size of the destination. If that length came
from the attacker (here `srclen` is a parameter ultimately fed from the wire),
then a length larger than `sizeof buf` overflows `buf[128]` just as thoroughly as
`gets` would. The function did its job correctly; the *caller* passed a bad size.

This is why "we use `memcpy` with a length, so we're fine" is a false sense of
security. The length is the thing that must be validated, every time, against the
real destination capacity.

A second subtlety: with `read`/`recv`, the return value tells you how many bytes
were *actually* read, and it can be `-1` on error. Passing a buffer size that's
too big is one bug; using the *return value* without checking for `-1` (which
becomes a huge number if treated as unsigned) is a second (Chapter 8).

**The fix.** Clamp to the destination, or reject anything too big:
```c
if (srclen > sizeof buf) return -1;      // reject (preferred: don't silently truncate)
memcpy(buf, src, srclen);
// or clamp when truncation is acceptable:
memcpy(buf, src, srclen < sizeof buf ? srclen : sizeof buf);
```

---

## 2.11 Test case 8 — the `scanf`/`sprintf`/`strcat` family

```c
// t08_family.c
char buf[8];
scanf("%s", buf);                    // unbounded; use "%7s"
sprintf(buf, "Hello %s", name);      // format expansion overflows; use snprintf
strcat(buf, suffix);                 // appends with no size check; use strlcat
```
**Each line, and why it overflows:**
- `scanf("%s", buf)` — `%s` reads characters until whitespace with **no limit**,
  identical in danger to `gets`. The fix is a *field width*: `%7s` reads at most
  7 characters into an 8-byte buffer (width = size − 1, leaving room for the
  NUL). Beginners forget the width constantly.
- `sprintf(buf, "Hello %s", name)` — `sprintf` expands the format and writes the
  result with no size limit. Even if `buf` could hold `"Hello "`, a long `name`
  blows past it. `snprintf(buf, sizeof buf, ...)` is the bounded version.
- `strcat(buf, suffix)` — `strcat` finds the end of whatever is already in `buf`
  and appends `suffix` after it, again with no awareness of `buf`'s capacity. If
  `buf` is already half full and `suffix` is long, you overflow. The bounded
  cousin is `strlcat` (BSD) or computing the remaining room yourself:
  `strncat(buf, suffix, sizeof buf - strlen(buf) - 1)`.

All three are the same root cause as `gets`: **the function has no idea how big
the destination is**, so the programmer must supply (and respect) that size. The
reason there are so many of these functions is historical — the original C
library predates any bounds-checking convention. Learn to spot the whole family:
`gets, strcpy, strcat, sprintf, vsprintf, scanf("%s"), gets_s`-misuse — and
replace each with its size-taking counterpart.

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
**Why command-line input counts as "attacker-controlled."** It's easy to think
"`argv[1]` is just what the user typed, that's not an attack." But consider a
**setuid-root** program (one that runs as root no matter who launches it, like
`sudo`, `ping`, or `passwd`). An ordinary unprivileged user launches it and
**fully controls its `argv` and environment variables**. So `strcpy(path,
argv[1])` with a 4000-byte `argv[1]` lets that user overflow `path[64]` inside a
root process — and a successful control-flow hijack then runs code *as root*.
That is **local privilege escalation**, and it's exactly how real bugs like sudo
Baron Samedit (cve-labs/03) were reached. The environment (`getenv("HOME")`,
etc.) is equally attacker-controlled and equally dangerous.

**Historical bonus.** Before ASLR, attackers also used **long environment
variables** as a convenient place to *store* their shellcode: env vars live near
the top of the stack at a fairly predictable address, so you could stuff shellcode
into `EGG=<nops><shellcode>` and jump to roughly where it landed. ASLR
(Chapter 13) killed that predictability.

**The fix.** Treat `argv`/`envp` like any other untrusted input — bound the copy:
```c
snprintf(path, sizeof path, "%s", argv[1]);
```
and, for setuid programs, sanitize the environment and drop privileges as early
as possible.

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
**What `alloca`/VLAs actually do.** Normal locals have a fixed size the compiler
knows, so it reserves space with one `sub rsp, <constant>` in the prologue
(Chapter 1 §1.6). `alloca(n)` and C99 variable-length arrays (`char vla[n]`)
instead reserve space **at runtime** by subtracting a *runtime* value from `rsp`:
`sub rsp, n`. If `n` is attacker-controlled, the attacker controls **how far the
stack pointer jumps**.

**Why that's dangerous — the "stack clash."** The stack has a limited region and
is followed (at lower addresses) by a guard page and then other mappings (the
heap, libraries). A huge `n` moves `rsp` so far down that it **skips over the
guard page** and lands in, or past, another mapping. Now writes intended for the
"array" actually land in unrelated memory — the stack and heap *collide*. This is
the **Stack Clash** class (CVE-2017-1000364 and friends). A negative or
absurdly-large `n` can also simply corrupt the frame or crash.

**The fix.** Don't make stack allocations depend on untrusted sizes. Use a fixed
maximum, or allocate on the **heap** with a checked size (and handle allocation
failure). Compile with **`-fstack-clash-protection`**, which makes the compiler
"probe" each page as it grows the stack so the guard page can never be jumped
over silently.

---

## 2.14 Test case 11 — array index write out of bounds

```c
// t11_index.c
int table[10];
int idx; scanf("%d", &idx);
table[idx] = 0x41414141;   // idx=50 or -3 writes far outside table
```
**Why an unchecked index is even more powerful than a plain overflow.** A normal
overflow writes *sequentially* past the end of a buffer — you corrupt neighbors
in order. An unchecked **index** lets the attacker pick the offset directly:
`table[idx] = value` computes `address_of_table + idx * sizeof(int)` and writes
there. By choosing `idx`, the attacker chooses *which* memory box to hit, and
(here) the value too. That's close to the ultimate primitive — a
**"write-what-where."**

**Both directions are dangerous.** `idx = 50` writes 50 elements *past* `table`
(into whatever is at higher addresses); `idx = -3` writes *before* `table` (lower
addresses). Negative indices surprise people because `arr[-3]` is perfectly legal
C — it's just `*(arr + (-3))`. So a signed index you forgot to lower-bound is a
bug even if you checked the upper bound.

**The one-line fix, and why the cast matters.**
```c
if ((unsigned)idx < 10) table[idx] = value;   // else reject
```
Casting `idx` to `unsigned` folds *both* checks into one: a negative `idx`
becomes a huge unsigned number, which fails `< 10`, so the single comparison
rejects negatives and too-large values at once. (This is the standard idiom; just
make sure `10` is the real element count.)

---

## 2.15 Test case 12 — struct with buffer + pointer (intra-struct overflow)

```c
// t12_struct.c
struct conn { char name[32]; void (*cb)(void); };
void setname(struct conn *c, char *s){ strcpy(c->name, s); }  // overflows into cb
```
**Why this one is especially nasty.** Fields of a struct are laid out in memory
**in declaration order**, so `cb` sits directly after `name` in the same struct,
at higher addresses. Overflowing `name` therefore writes straight into `cb` — and
`cb` is a **function pointer the program will later call** (`c->cb()`). So the
attacker doesn't even need the return address or the stack frame: overwrite `cb`
with the address of their choosing, and the program itself calls it the next time
it invokes the callback. This is the same idea as a C++ object's vtable pointer
(Chapter 10) and as the heap function-pointer overwrite (Chapter 4).

A struct like this can live **anywhere** — on the stack, on the heap, or as a
global — and the bug is identical in each case, which is why this pattern shows
up across all the memory regions.

**Two fixes, and the trade-off:**
- **Bound the copy** (always correct): `snprintf(c->name, sizeof c->name, "%s",
  s)` so the write can never reach `cb`.
- **Reorder fields** so the pointer comes *before* the buffer: then an overflow
  of `name` runs off the end of the struct into other memory rather than into
  `cb` first. This is a hardening nicety, *not* a substitute for bounding — the
  overflow still happens, it just doesn't immediately hit the code pointer.
Compilers/CFI (`-fsanitize=cfi`) can also catch a call through a corrupted
pointer at runtime (Chapter 13).

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

## 2.18 Advanced: what a real stack exploit looks like *today*

The simple "overwrite the return address with my shellcode's location" worked in
1996. On a modern Linux box, three defenses (all in Chapter 13) stand in the way,
and a real exploit is a sequence of steps to get around each one. Understanding
*why* the simple attack no longer works is what separates beginner from advanced.

**Obstacle 1 — the stack isn't executable (NX).** You can still overwrite the
return address, but you can no longer point it at bytes *you* put on the stack,
because the CPU refuses to execute stack memory. **Workaround:** don't inject
code — *reuse* code that is already executable. Point the return address at an
existing function (e.g. libc's `system`) or chain together tiny existing snippets
("gadgets"). This is **ret2libc / ROP**, Chapter 12. The overflow from this
chapter is still the way in; only the *payload after the offset* changes.

**Obstacle 2 — a stack canary.** The compiler places a secret random value (the
"canary") between the buffers and the return address, and checks it is unchanged
right before `ret`. A linear overflow that reaches the return address must first
overwrite the canary, so the check fails and the program aborts. **Workaround:**
first *leak* the canary value (e.g. via a format-string bug, Chapter 7, or an
out-of-bounds read, Chapter 9), then include the correct canary in your payload
so the check still passes. Or target something the function uses *before* it
returns (a local function pointer), so `ret` is never reached. This is why real
write-ups are usually "bug A leaks a secret, bug B overflows" — the **info leak**
is half the work.

**Obstacle 3 — ASLR/PIE.** Addresses (libc, the stack, even the program's own
code) are randomized each run, so you can't hard-code where `system` or your
gadgets live. **Workaround:** leak *one* address from a region, then compute the
rest by adding/subtracting known fixed offsets within that region. A single
leaked libc pointer reveals libc's whole layout.

So a modern stack exploit is typically: **(1)** use the overflow (or a second
bug) to *leak* a canary and a libc address; **(2)** use the overflow again to
place a **ROP chain** that calls `system("/bin/sh")` with the now-known
addresses, including the correct canary. The hands-on versions are in Chapter 12
(ROP), Chapter 13 (each defense), and the login-server walkthrough
([`walkthroughs/01-login-server`](walkthroughs/01-login-server/WALKTHROUGH.md)),
which derives the offset from the disassembly and drives it to a shell.

**Advanced nuances worth knowing now:**
- **16-byte stack alignment.** x86-64 libc functions use SSE instructions
  (`movaps`) that fault unless `rsp` is 16-byte aligned at the call. ret2libc
  payloads often need an extra bare `ret` gadget to fix alignment — a real
  constraint, not a mystery (Chapter 2 §2.6 shows it).
- **Saved-RBP (frame pointer) overwrite.** You don't always need the full return
  address. Overwriting just the low byte(s) of the saved `rbp` (an off-by-one,
  §2.7) can pivot the caller's stack on its own `leave; ret` — a subtler but real
  primitive.
- **Partial overwrites.** Under ASLR the low 12 bits of an address are *not*
  randomized (they're the page offset), so overwriting only the low byte or two
  of a saved pointer can redirect execution within a known page without needing a
  full leak.
- **Not all control is the return address.** A local function pointer, a C++
  object's vtable pointer on the stack, or a `longjmp` buffer are all control
  data an overflow can hit *before* `ret` — defeating canaries, which only guard
  the return path.

---

## Recap
- Past-the-end stack writes hit **saved RBP** and the **return address**; `ret`
  then jumps to attacker data.
- It manifests 12 ways here — raw copies, off-by-one, attacker lengths, indices,
  argv/env, alloca/VLA, intra-struct — all the same root cause.
- Fix by **bounding copies/indices** + canary/NX/ASLR/FORTIFY + ASan.

Next: **[Chapter 3 — The heap & dynamic memory »](03-heap-internals.md)**
