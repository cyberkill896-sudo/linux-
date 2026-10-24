# Practice Questions & Labs

Work these after each chapter. Mix of **concept questions** (test understanding),
**code-audit questions** (spot the bug), and **hands-on labs** (build/exploit in
your VM). Answers and walkthroughs in **[`SOLUTIONS.md`](SOLUTIONS.md)** — try
first, then check.

Difficulty: ⭐ beginner · ⭐⭐ intermediate · ⭐⭐⭐ advanced.

---

## Chapter 1 — Memory layout

1. ⭐ Name the six main regions of a process's address space from low to high
   address. Which are writable? Which are executable?
2. ⭐ A `static int counter = 0;` inside a function — which segment holds it, and
   how long does it live? What about a `const char *s = "hi";` (both the pointer
   and the string)?
3. ⭐⭐ Draw the stack frame of `void f(void){ char buf[20]; long x; }`. Where is
   the return address relative to `buf`? Which way does `strcpy(buf, …)` grow?
4. ⭐⭐ Explain in one sentence each what `call` and `ret` do to `rsp` and `rip`.
   Why does `ret` "trust" the stack?
5. ⭐⭐ The value `0x401136` must be written as a return address. Give the 8 bytes
   as they appear in memory (little-endian).
6. ⭐⭐⭐ Run `./src/bin/01_stack_basic` under GDB, break on `vuln`, and record the
   addresses of `buf`, saved RBP, and the return address. Compute the exact
   offset from `buf` to the return address and explain any padding.

---

## Chapter 2 — Stack buffer overflows

7. ⭐ Why is `gets()` impossible to use safely? What's the drop-in replacement?
8. ⭐ For `char buf[64];`, what single-line change makes `strcpy(buf,s)` safe
   using `snprintf`?
9. ⭐⭐ Audit: find the bug and fix it.
   ```c
   void greet(char *name){ char msg[32]; sprintf(msg, "Hello, %s!", name); puts(msg); }
   ```
10. ⭐⭐ In `03_ret2win.c`, the offset to the return address is 40 but `buf` is
    only 32 bytes. Where do the other 8 bytes come from?
11. ⭐⭐ Lab: build `02_stack_authflag`, and find the exact input length that
    flips `authed` on *your* compiler (use GDB to inspect `&pass` and `&authed`).
12. ⭐⭐⭐ Lab: exploit `03_ret2win` by hand (no pwntools) — find `win` with
    `objdump`, find the offset with a cyclic pattern, and build the payload with
    `python3 -c`. Explain why you may need an extra `ret` gadget.
13. ⭐⭐⭐ Why does a single-byte overflow of the saved RBP ("off-by-one") matter?
    Trace what `leave; ret` does with a corrupted saved RBP.

---

## Chapter 3–5 — Heap

14. ⭐ What does `malloc` return relative to the chunk start, and where is the
    `size` field? What are the three flag bits in `size`?
15. ⭐ Why is `0x21` a common value to see in a chunk's `size` field for a
    `malloc(24)`?
16. ⭐⭐ After `free(a); free(b);` of two 24-byte chunks, which does the next
    `malloc(24)` return, and why? What ordering does tcache use?
17. ⭐⭐ Audit: why is this a heap overflow, and how would you size it correctly?
    ```c
    struct rec { int id; char note[16]; };
    struct rec *r = malloc(sizeof(int));   r->id = 1;  strcpy(r->note, s);
    ```
18. ⭐⭐⭐ Explain tcache poisoning in four steps. What two glibc mitigations make
    it harder, and what must you leak to defeat Safe-Linking?
19. ⭐⭐⭐ Lab: run `16_tcache_poison`. If `y` doesn't equal `&target`, your glibc
    has Safe-Linking — use the helper in `exploits/16_tcache_poison.py` to
    compute the encoded `next` and explain the formula.

---

## Chapter 6 — Use-after-free

20. ⭐ What is a dangling pointer? What single habit converts most silent UAFs
    into obvious crashes?
21. ⭐⭐ Explain the "reclaim" pattern that makes a UAF exploitable. Why does the
    reclaiming allocation have to be the *same size*?
22. ⭐⭐ Audit: find two bugs.
    ```c
    char *buf = malloc(n);
    if (parse(buf) < 0) free(buf);
    use(buf);
    free(buf);
    ```
23. ⭐⭐ Why is `use-after-realloc` easy to introduce? What must you do after
    every `realloc`?
24. ⭐⭐⭐ Lab: build `07_uaf_fnptr` under ASan and read the report. Identify, from
    the trace, the allocation site, the free site, and the use site.

---

## Chapter 7 — Format strings

25. ⭐ Why is `printf(user)` dangerous but `printf("%s", user)` safe?
26. ⭐⭐ What does each do: `%p`, `%s`, `%n`, `%7$p`, `%100c`? Which give read vs
    write?
27. ⭐⭐ Lab: using `10_format_leak`, find which `%N$p` prints your own input
    buffer. Explain how you confirmed it.
28. ⭐⭐⭐ Lab: using `11_format_write` (+ `exploits/11_format_write.py`), set
    `target` to `0xdeadbeef`. Explain why 64-bit writes are done with `%hhn` in
    pieces rather than a single `%n`.
29. ⭐⭐⭐ Which compile flag would have rejected both vulnerable programs at build
    time? Why don't the training builds use it?

---

## Chapter 8 — Integer bugs

30. ⭐ Distinguish overflow, underflow, truncation, signedness, and sign
    extension with a one-line example each.
31. ⭐⭐ Audit: why does this pass the size check yet overflow?
    ```c
    int len = get_len();           // attacker-controlled
    if (len > 1024) return -1;
    memcpy(buf, src, len);         // buf is 1024 bytes
    ```
32. ⭐⭐ Why is `calloc(n, size)` safer than `malloc(n * size)` for arrays — name
    *two* reasons.
33. ⭐⭐⭐ Lab: find the input to `12_int_overflow` that makes the 32-bit product
    wrap to less than 8, and confirm the overflow under ASan. Show the
    arithmetic.
34. ⭐⭐⭐ In disassembly, which instructions/branches reveal a signed vs unsigned
    comparison, and a sign-extension vs zero-extension?

---

## Chapter 9 — OOB / uninitialized / misc

35. ⭐ What single missing check caused Heartbleed? State it as an `if`.
36. ⭐⭐ Why does `malloc` returning stale data constitute an info leak, and how
    does `calloc` help? Why isn't `calloc` always the answer?
37. ⭐⭐ Audit: what leaks here, and how many bytes?
    ```c
    struct { uint8_t a; uint32_t b; } m; m.a=1; m.b=2; send(fd, &m, sizeof m);
    ```
38. ⭐⭐⭐ Lab: build `14_uninit_leak` under MSan (clang) and `13_oob_read` under
    ASan; capture both reports and explain what each sanitizer detected that the
    other wouldn't.

---

## Chapter 10 — C++

39. ⭐ Where does the vptr live in an object, and why does that make it a target?
40. ⭐⭐ Explain type confusion. Why is `static_cast` dangerous where
    `dynamic_cast` is safe?
41. ⭐⭐ Audit: what's wrong, and what's the RAII fix?
    ```cpp
    char *b = new char[256]; read_into(b); process(b); delete b;
    ```
42. ⭐⭐⭐ Lab: run `15_cpp_vtable` and, from the disassembly of `b->run()`, show
    the three instructions that load the vptr, index the vtable, and call.

---

## Chapter 11 — Races

43. ⭐ Define TOCTOU in one sentence; give a filesystem example and a memory
    example.
44. ⭐⭐ Why is a double-fetch at the user/kernel boundary exploitable? What's the
    one-line fix pattern?
45. ⭐⭐⭐ Lab: build `17_race_uaf` under TSan and capture the race report. Then
    fix it with a mutex and confirm TSan is clean.
46. ⭐⭐⭐ Why does `rc--` being non-atomic cause UAF *and* double-free? What kernel
    type fixes this and how?

---

## Chapter 12–13 — Code reuse & mitigations

47. ⭐ Why did NX make injected shellcode stop working, and what did attackers do
    instead?
48. ⭐⭐ To call `system("/bin/sh")` on x86-64, which register must hold the
    `/bin/sh` pointer, and which gadget sets it?
49. ⭐⭐ Explain "leak then pivot": why does ROP under ASLR need an info-leak
    stage, and how does `puts(puts@got)` provide it?
50. ⭐⭐ For each: canary, NX, ASLR/PIE, Full RELRO, CFI — name one technique it
    stops and one way it's bypassed.
51. ⭐⭐⭐ Run `checksec` on `03_ret2win` (training) and on its `make safe` build.
    List every difference and what each means for an attacker.

---

## Chapter 14 — Kernel

52. ⭐ Why is a kernel memory bug more severe than a userspace one?
53. ⭐⭐ Name the three user/kernel-boundary bug shapes and the accessor functions
    the kernel must use.
54. ⭐⭐⭐ Explain how a slab UAF + a controllable-size spray object (e.g.
    `msg_msg`) leads to LPE, and which mitigations (SMAP, SLAB hardening,
    `init_on_free`, kCFI) interrupt which step.

---

## Capstone (⭐⭐⭐)

55. Pick ONE class (overflow / UAF / format / heap). Write your own tiny
    vulnerable program, exploit it to get a shell in your VM, then rewrite it
    safely and prove the exploit fails. Write a one-page report: the bug, the
    primitive, the leak, the target, the fix. (This is the exact shape of a real
    vulnerability disclosure.)
