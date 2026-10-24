# Chapter 7 — Format-String Vulnerabilities (8 test cases)

> A bug that gives you **both** an arbitrary memory *read* (leak) **and** an
> arbitrary *write* from a single `printf` — one of the most powerful primitives
> when it exists.

---

## 7.0 In plain words (start here)

When you call `printf("Hello %s, you are %d", name, age)`, the first argument is
a **format string**: a template with `%`-placeholders. `printf` reads it
left-to-right, and every time it meets a `%`-placeholder it grabs "the next
argument" and formats it. `%s` means "treat the next argument as text," `%d`
means "as a number," and so on.

Crucially, **`printf` figures out how many arguments to use by counting the
placeholders in the format string** — it has no other way to know. It just trusts
the template.

Now the bug. Suppose a lazy programmer writes:

```c
printf(name);          // instead of printf("%s", name)
```

If `name` is `"Alice"`, this prints `Alice` — looks fine. But `name` comes from
the user, and if the user types `"%s%s%s%x"`, then *their text becomes the
template*. `printf` now dutifully looks for four arguments that the programmer
never passed — so it reads whatever happens to be lying around in registers and
on the stack, and prints that. The user just made `printf` **leak memory**.

It gets worse. One placeholder, **`%n`**, doesn't print anything — it *writes* the
number of characters printed so far into a memory address taken from "the next
argument." With the right crafted format string, an attacker turns that into
"write a value I choose to an address I choose" — an **arbitrary write**, which
leads to full code execution.

So a single misuse — passing user data where a literal template belongs — hands
an attacker **both** a memory read (via `%x`/`%p`/`%s`) and a memory write (via
`%n`). That's why it's one of the most powerful bug classes when it appears.

The fix is almost insultingly simple and worth stating up front: **always make
the format string a literal you wrote**, and pass user data as an argument:
`printf("%s", name)`. The compiler flag `-Wformat-security` will even refuse to
build the dangerous form. The rest of the chapter shows exactly how the read and
write primitives work so you can recognize and exploit (and fix) them.

Quick placeholder cheat (full detail in §7.3):
- `%p` / `%x` → print a value off the stack (a **leak**).
- `%s` → treat the next value as a pointer and print the text there (**read**).
- `%n` → **write** the count-so-far to an address (**write**).
- `%7$p` → "the 7th argument, directly" (positional — pick your target).

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
`%6$p` = "give me parameter #6." The `N$` syntax is **positional**: it jumps
directly to the Nth variadic argument instead of consuming them one by one. This
matters because you usually want one *specific* value — a saved return address (→
defeat PIE), the stack canary, or a libc pointer (→ defeat ASLR) — and you don't
want to count dozens of `%p`s to reach it.

**How to find the index N for a value you care about — two sub-skills:**

1. *Find where your own input lands.* Send a unique marker followed by many
   positional reads and see which one echoes your marker:
   ```bash
   printf 'ABCD %1$p %2$p %3$p %4$p %5$p %6$p %7$p %8$p' | ./f01
   ```
   When one of them prints `0x44434241` (that's `"ABCD"` little-endian, Chapter 1
   §1.8), that index is the start of *your buffer* on the stack. Knowing this
   index is the key that unlocks the **write** primitive (test case 4): you place
   a target *address* in your buffer, then use `%<that index>$n` to write through
   it.
2. *Identify a leaked value by its shape.* As you walk indices, recognize values
   by their high bytes (next section): `0x7f...` is a libc/stack pointer,
   `0x55.../0x56...` is a PIE code/data pointer, a word ending in `00` that
   changes every run is likely the canary.

So the workflow is: **leak to find your buffer's index and to grab the
canary/libc/PIE pointers, then use those in the write stage.** Finding "which
`$N` is my buffer" is the single most important measurement in format-string
exploitation.

---

## 7.6 Test case 3 — leaking the canary & defeating ASLR

```c
// f03_recon.c — same vulnerable printf, richer stack
#include <stdio.h>
void vuln(void){ char buf[128]; fgets(buf,sizeof buf,stdin); printf(buf); }
int main(void){ vuln(); vuln(); }   // loop so you can leak then exploit
```
**How to read the stack dump — identifying each kind of value.** When you print
many stack words with `%N$lx`, you're looking at a snapshot of whatever happens
to be in `vuln`'s frame and below: saved registers, leftover values, and
pointers. You classify them by their top bytes and by how they change between
runs:

- **The stack canary** (Chapter 13): a 64-bit value whose **lowest byte is `00`**
  (glibc deliberately makes the low byte a NUL to stop string-based leaks) and
  whose other 7 bytes are random — and it is **different on every run**. If you
  see `0x<random>...00`, that's almost certainly the canary. You need its value
  to survive a stack overflow that crosses it, so you leak it first, then include
  it unchanged in your overflow payload.
- **A libc pointer**: starts with `0x7f` (on 64-bit Linux, shared libraries map
  high). Any one libc address minus the *known fixed offset* of that symbol
  within the specific libc build gives you **libc base** → every libc function
  and ROP gadget address → ASLR defeated for libc (Chapter 13).
- **A PIE pointer**: starts with `0x55` or `0x56` — a pointer into the program's
  own randomized code/data. Subtract the symbol's known file offset to get the
  **program base**, defeating PIE.
- **A stack pointer**: also `0x7ff...`, pointing near other stack addresses —
  useful if you need to know where your buffer lives (e.g. for a stack pivot).

The `vuln(); vuln();` loop in the code exists so you can do this in two passes:
**first** call leaks the canary/libc/PIE values; you compute the real addresses;
**second** call sends the actual exploit using them. That two-stage "leak, then
act" structure is exactly how real exploits defeat ASLR and canaries.

Format strings are the classic **info-leak half** of an exploit precisely because
they read arbitrary stack words with **no crash** — you can probe as much as you
like, which is a luxury most bugs don't give you.

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
