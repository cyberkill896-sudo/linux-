# Chapter 15 — Practice, Tooling & Resources

> Reading makes you *recognize* memory bugs. Finding and exploiting them in a lab
> makes you *understand* them. This is your practice plan.

---

## 15.1 The loop to run on every chapter (2–14)

1. **Compile** the vulnerable example (insecure training flags — README lab).
2. **Reproduce the crash**; read it in GDB (`rip`, `rsp`, fault address).
3. **Find the offset** with a cyclic pattern.
4. **Build the minimal exploit** (ret2win first — no shellcode, no ROP).
5. **Rewrite the code safely**; confirm the exploit no longer works.
6. **Turn on a sanitizer** and watch it pinpoint the bug automatically.

Step 5 is what makes you a better engineer, not just a breaker.

---

## 15.2 The toolbox

**Debuggers** — GDB + **GEF** or **pwndbg** (essential):
`break`, `run`, `stepi`, `info registers`, `x/16gx $rsp`, `heap`, `bins`, `vis`,
`checksec`, `pattern create/search`, `telescope`.

**Exploit framework** — **pwntools** (Python): `process`, `remote`, `ELF`, `ROP`,
`cyclic`, `p64/u64`, `fmtstr_payload`, `shellcraft`, `SigreturnFrame`.

**Static/binary analysis** — `checksec`, `readelf`, `objdump -d -M intel`, `nm`,
`strings`, `ltrace`, `strace`; **Ghidra**/**radare2**/**Binary Ninja**/**IDA**
(decompile); **ROPgadget**/**ropper** (gadgets).

**Dynamic bug finders (use on YOUR code):**
- **AddressSanitizer** `-fsanitize=address` — heap/stack/global overflow, UAF,
  double-free. Start here.
- **UBSan** `-fsanitize=undefined` — integer overflow, bad shifts, misaligned/null.
- **MemorySanitizer** `-fsanitize=memory` (Clang) — uninitialized reads.
- **ThreadSanitizer** `-fsanitize=thread` — data races.
- **Valgrind/Memcheck** — no recompile; slower; leaks + invalid access.

**Fuzzers (find bugs automatically):** **libFuzzer** (`-fsanitize=fuzzer`),
**AFL++**, **honggfuzz**; **syzkaller** (kernel). Fuzzing + ASan is how most real
memory bugs are found today.

```c
// minimal libFuzzer harness — build: clang -g -O1 -fsanitize=address,fuzzer t.c
#include <stddef.h>
#include <stdint.h>
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size){
    parse_my_format(data, size);   // your code under test
    return 0;
}
```
Run it; ASan + the fuzzer hands you a crashing input for any overflow/UAF.

---

## 15.3 Legal practice environments

Only attack targets that **invite** it:
- **pwn.college** — free, structured curriculum (memory, shellcode, ROP, kernel).
  Best starting point.
- **picoCTF** — beginner-friendly, permanent practice gym.
- **ROP Emporium** — focused, progressive ROP challenges.
- **exploit.education** (Protostar, Phoenix) & **OverTheWire** (Narnia, Behemoth)
  — classic overflow wargames.
- **CMU Bomb Lab / Attack Lab** (public) — gold-standard teaching labs.
- **how2heap** (shellphish) — replay every heap technique against specific glibc.
- **pwnable.kr / pwnable.tw / HackTheBox** — harder, CTF-style.
- Your **own VM** running your **own vulnerable programs** — always fair game.

**Rules of engagement:** only test systems you own or are explicitly authorized to
test. Unauthorized exploitation is illegal regardless of intent — the sites above
exist so you never need to cross that line.

---

## 15.4 Books & key references
- **"Hacking: The Art of Exploitation"** (Erickson) — best hands-on intro.
- **"The Shellcoder's Handbook"** — broader, deeper exploitation.
- **"A Guide to Kernel Exploitation"** (Perla & Oldani).
- **"Practical Binary Analysis"** (Andriesse).
- **CS:APP — "Computer Systems: A Programmer's Perspective"** — the systems
  foundation (machine code, stack, linking); pairs with the CMU labs.
- **Papers:** "Smashing the Stack for Fun and Profit" (Aleph One); "Return-into-
  libc"/"ROP" (Shacham); **"SoK: Eternal War in Memory"** (Szekeres et al.) — the
  best single map of this whole field.
- **Heap:** glibc malloc source, sploitfun, Azeria/how2heap write-ups.

---

## 15.5 A suggested 8-week plan
| Week | Focus | Deliverable |
|------|-------|-------------|
| 1 | Ch.1 + CS:APP machine-code; GDB/disassembly fluency | single-step `asm_demo.c`, draw the frame from memory |
| 2 | Ch.2; Protostar stack0–5 | a working ret2win exploit + the safe rewrite |
| 3 | Ch.3–4 + how2heap basics; heap in pwndbg | explain tcache LIFO reuse in your own words |
| 4 | Ch.5–6; write & detect a UAF with ASan | UAF PoC + vtable-hijack PoC + fixes |
| 5 | Ch.7–8; format-string leak→write; integer bugs | `fmtstr_payload` GOT overwrite in a lab |
| 6 | Ch.9–11; OOB/uninit; C++ vtable; a TSan race | 3 small PoCs, each with its fix |
| 7 | Ch.12–13; ROP Emporium split/callme/write4 | a hand-built ROP chain + leak stage |
| 8 | Ch.14 concepts; run syzkaller in a VM; read one CVE end-to-end | one-page write-up of a real (patched) bug |

Then: do pwn.college / picoCTF pwn tracks continuously.

---

## 15.6 The defensive mindset (the real goal)

Everything you learned to break, you now know how to prevent:
1. **Bound every copy/index** to the destination size (Ch.2,4,9).
2. **Never pass untrusted data as a format string** (Ch.7).
3. **Check integer arithmetic** used for sizes/indices (Ch.8).
4. **Make lifetimes unambiguous:** `free;ptr=NULL`, single ownership, smart
   pointers, RAII (Ch.6,10).
5. **Validate all lengths/indices from input** before use (Ch.9,14).
6. **Lock/snapshot shared state; atomic refcounts** (Ch.11).
7. **Compile hardened:** canary, NX, PIE, Full RELRO, FORTIFY, CFI (Ch.13).
8. **Run sanitizers in CI and fuzz continuously** (this chapter).
9. **Prefer memory-safe languages (Rust)** for new security-critical code — it
   removes the entire class at compile time.

The best exploit developers are the best defenders: they know exactly where the
bodies are buried.

---

## Course recap — the whole arc
- **Ch.1** memory map (sections, stack frame, registers, `call`/`ret`).
- **Ch.2** stack overflow → return-address hijack (12 cases + asm).
- **Ch.3–5** heap internals → heap overflow → exploitation techniques.
- **Ch.6** use-after-free / double-free / dangling / type confusion.
- **Ch.7** format strings (leak + `%n` write).
- **Ch.8** integer bugs → wrong size/length/index.
- **Ch.9** OOB read/write, uninitialized, NULL/wild, leaks, stack exhaustion.
- **Ch.10** C++ vtable hijack, type confusion, lifetime traps.
- **Ch.11** races (TOCTOU, double-fetch, data-race UAF).
- **Ch.12** code reuse (ret2libc, ROP, SROP, pivots).
- **Ch.13** mitigations and the arms race.
- **Ch.14** kernel memory bugs and LPE.
- **Ch.15** tooling, fuzzing, legal practice, defensive mindset.

Build the labs, break your own code, then fix it. That loop is the whole skill.
See **[`CHEATSHEET.md`](CHEATSHEET.md)** for the one-page field guide.
