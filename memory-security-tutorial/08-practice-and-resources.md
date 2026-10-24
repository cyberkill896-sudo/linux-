# Chapter 8 — Practice, Tooling & Resources

> Reading about memory bugs makes you recognize them. *Finding and exploiting
> them in a lab* makes you understand them. This chapter is your practice plan.

---

## 8.1 Your workflow for each bug class

For every chapter 2–7, do this loop:

1. **Compile the vulnerable example** from the chapter (insecure flags — see
   README lab setup).
2. **Reproduce the crash** and read it in GDB: where did it fault, what's in
   `rip`/`rsp`?
3. **Find the offset** with a cyclic pattern.
4. **Build the minimal exploit** (ret2win is the ideal first target — no
   shellcode, no ROP).
5. **Rewrite the code safely** and confirm the exploit no longer works.
6. **Turn on a sanitizer** and watch it pinpoint the bug automatically.

Step 5 is the one that makes you a better engineer, not just a breaker.

---

## 8.2 The toolbox

### Debuggers
- **GDB** + **GEF** or **pwndbg** — essential. Teaches you the stack/heap live.
  Key commands: `break`, `run`, `stepi`, `info registers`, `x/16gx $rsp`,
  `heap`, `bins`, `vis`, `checksec`, `pattern create/search`.

### Exploit framework
- **pwntools** (Python): `process`, `remote`, `ELF`, `ROP`, `cyclic`, `p64/u64`,
  `shellcraft`. The standard for CTF pwn and PoCs.

### Static & binary analysis
- `checksec`, `readelf`, `objdump -d`, `nm`, `strings`, `ltrace`, `strace`.
- **Ghidra** / **radare2** / **Binary Ninja** / **IDA** — decompile and
  reverse-engineer binaries.
- **ROPgadget** / **ropper** — find ROP gadgets.

### Dynamic bug finders (use these on YOUR code!)
- **AddressSanitizer** `-fsanitize=address` — heap/stack/global overflow, UAF,
  double-free. Fast, precise, start here.
- **UndefinedBehaviorSanitizer** `-fsanitize=undefined` — integer overflow, bad
  shifts, misaligned/null pointers.
- **MemorySanitizer** `-fsanitize=memory` (Clang) — uninitialized reads.
- **ThreadSanitizer** `-fsanitize=thread` — data races (→ race-based UAF).
- **Valgrind/Memcheck** — no recompile needed; slower; great for leaks + invalid
  access.

### Fuzzers (find bugs automatically)
- **libFuzzer** (`-fsanitize=fuzzer`) and **AFL++** — coverage-guided fuzzing.
  Write a small harness that feeds input to your parser; run with ASan on. This
  is how most real memory bugs are found today.
- **syzkaller** — kernel fuzzing (Chapter 7).

### A minimal fuzz harness example
```c
// fuzz_target.c  —  build: clang -g -O1 -fsanitize=address,fuzzer fuzz_target.c
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    parse_my_format(data, size);   // your code under test
    return 0;
}
```
Run it; ASan + the fuzzer will hand you a crashing input for any overflow/UAF in
`parse_my_format`.

---

## 8.3 Practice environments (legal, intentionally vulnerable)

Practice only on targets that **invite** it:

- **pwn.college** — superb free, structured course (memory, shellcode, ROP,
  kernel). Start here if you want a curriculum.
- **picoCTF** — beginner-friendly CTF with a permanent practice gym.
- **ROP Emporium** — focused, progressive ROP challenges.
- **OverTheWire** (Narnia, Behemoth) and **exploit.education** (Protostar,
  Phoenix) — classic wargames for overflow basics.
- **CMU Bomb Lab / Attack Lab** (public) — the gold-standard teaching labs.
- **HackTheBox / pwnable.kr / pwnable.tw** — harder, CTF-style.
- Your **own VM** running your **own vulnerable programs** — always fair game.

**Rules of engagement:** only attack systems you own or are explicitly authorized
to test. Unauthorized exploitation is illegal regardless of skill or intent. CTFs
and the sites above exist so you never need to cross that line.

---

## 8.4 Books & deep references

- **"Hacking: The Art of Exploitation"** (Erickson) — the classic, hands-on intro
  (overflow, shellcode, networking). Great first book.
- **"The Shellcoder's Handbook"** — broader, deeper exploitation.
- **"A Guide to Kernel Exploitation"** (Perla & Oldani) — kernel-focused.
- **"Practical Binary Analysis"** (Andriesse) — binary analysis/instrumentation.
- **"Computer Systems: A Programmer's Perspective" (CS:APP)** — the systems
  foundation (chapters on machine code, the stack, linking); pairs with CMU's
  labs.
- **Papers:** "Smashing the Stack for Fun and Profit" (Aleph One), "Return-
  oriented Programming" (Shacham), the "SoK: Eternal War in Memory" survey
  (Szekeres et al.) — an excellent map of the whole field.
- **"The C Programming Language" (K&R)** + reading the glibc malloc source and
  **sploitfun** / **how2heap** ( shellphish) for heap internals.

---

## 8.5 A suggested 6-week study plan

| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | Chapter 1 + CS:APP machine-code chapters; GDB fluency | single-step `add.c`, draw the stack from memory |
| 2 | Chapter 2; exploit.education Protostar stack0–stack5 | working ret2win exploit |
| 3 | Chapter 3 + how2heap first few; heap in pwndbg | explain tcache reuse in your own words |
| 4 | Chapter 4; write & detect a UAF with ASan | UAF PoC + the safe rewrite |
| 5 | Chapters 5–6; ROP Emporium split/callme | a hand-built ROP chain |
| 6 | Chapter 7 concepts + run syzkaller in a VM; read one CVE write-up end-to-end | a one-page write-up of a real bug |

Then: do picoCTF / pwn.college pwn tracks continuously.

---

## 8.6 The defensive mindset (the real goal)

Everything you learned to *break*, you now know how to *prevent*:

1. **Bound every copy** to the destination size (Chapter 2, 3).
2. **Never pass untrusted data as a format string** (Chapter 5).
3. **Check integer arithmetic** used for sizes (Chapter 5).
4. **Make lifetimes unambiguous**: `free; ptr=NULL`, single ownership, smart
   pointers, RAII (Chapter 4).
5. **Validate all lengths/indices from input** before use (Chapter 5, 7).
6. **Compile hardened** (canary, NX, PIE, Full RELRO, FORTIFY, CFI — Chapter 6).
7. **Run sanitizers in CI and fuzz continuously** (this chapter).
8. **Prefer memory-safe languages** (Rust) for new, security-critical code — it
   removes the entire bug class at compile time.

The best exploit developers are also the best defenders, because they know
exactly where the bodies are buried.

---

## Course recap

You now have the full arc:

- **Ch.1** — the memory map (sections, stack frame, registers, `call`/`ret`).
- **Ch.2** — stack overflow → return-address hijack.
- **Ch.3** — heap internals → heap overflow / metadata corruption.
- **Ch.4** — use-after-free, double-free, dangling pointers, type confusion.
- **Ch.5** — format string, integer overflow, off-by-one, OOB read,
  uninitialized memory, NULL deref, stack exhaustion.
- **Ch.6** — canary / NX / ASLR-PIE / RELRO / FORTIFY / CFI and the arms race.
- **Ch.7** — kernel: same bugs, root-level stakes, boundary bugs, kernel
  mitigations.
- **Ch.8** — tooling, fuzzing, legal practice, and the defensive mindset.

Go build the labs, break your own code, then fix it. That loop is the whole
skill.
