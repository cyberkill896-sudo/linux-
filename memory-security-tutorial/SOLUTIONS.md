# Solutions & Walkthroughs

Answers to **[`EXERCISES.md`](EXERCISES.md)**. Try each question first. For labs,
the point is the *process*, so these explain the reasoning, not just the result.

---

## Chapter 1

**1.** Low→high: `.text` (code, RO+exec), `.rodata` (RO), `.data` (init globals,
RW), `.bss` (zeroed globals, RW), heap (RW, grows up), stack (RW, grows down).
Only `.text` is executable; `.data/.bss/heap/stack` are writable but **not**
executable (NX).

**2.** `static int counter` → `.bss` (if 0) or `.data` (if non-zero init); lives
the whole program. `const char *s = "hi";` → the **string** `"hi"` is in
`.rodata`; the **pointer** `s`, being a local, is on the stack (or a register).

**3.** Frame (high→low): `[return address][saved RBP][x][buf[16..19]][buf[0..3]]`.
The return address is **above** `buf` (higher address); `strcpy` writes from
`buf` **upward** toward it. So overflowing `buf` reaches `x`, then saved RBP,
then the return address.

**4.** `call` pushes the address of the next instruction (`rsp -= 8`) then sets
`rip` to the target. `ret` pops `[rsp]` into `rip` (`rsp += 8`). `ret` "trusts"
the stack because the CPU has no notion of a legitimate vs forged return address
— it just loads 8 bytes.

**5.** `36 11 40 00 00 00 00 00`.

**6.** Expect `ret_addr − &buf == 24` on a typical `-O0 -no-pie` build (16 for
`buf` + 8 for saved RBP), but the compiler may pad `buf`'s region to a 16-byte
boundary, so **measure**. The padding exists for stack alignment, not for safety.

---

## Chapter 2

**7.** `gets` has no size parameter — it reads until newline/EOF regardless of
the destination size, so any input longer than the buffer overflows it. Replace
with `fgets(buf, sizeof buf, stdin)`.

**8.** `snprintf(buf, sizeof buf, "%s", s);`

**9.** `sprintf` has no bound; a long `name` overflows `msg[32]`. Fix:
`snprintf(msg, sizeof msg, "Hello, %s!", name);`

**10.** `32` bytes fill `buf`; the next `8` overwrite the **saved RBP**; the
8 after that (bytes 40..47) hit the return address. So offset = 32 + 8 = 40.

**11.** `gdb --args ./bin/02_stack_authflag`; `break` on the `if`; `run`;
`p &pass` and `p &authed`. The flip length = `(&authed − &pass) + 1` (one
non-zero byte into `authed`). It varies by compiler/flags — that's the lesson.

**12.** `objdump -d bin/03_ret2win | grep '<win>:'` → `WIN`. Offset via cyclic:
`gdb`, run with `cyclic 200`, `cyclic -l $rsp` → `40`. Payload:
`python3 -c 'import sys;sys.stdout.buffer.write(b"A"*40 + <ret_gadget> + <WIN>)'`.
The extra bare `ret` fixes 16-byte alignment so `system`'s `movaps` doesn't
fault.

**13.** `leave` = `mov rsp, rbp ; pop rbp`. A corrupted low byte of saved RBP
makes the *caller's* `rbp` point to attacker-influenced memory; on the caller's
own `leave; ret`, `rsp` is set from that bad `rbp`, so the next `ret` pops a
return address from a location the attacker controls → control-flow hijack from
a single byte.

---

## Chapter 3–5

**14.** `malloc` returns `chunk + 16` (past `prev_size` and `size`); `size` is at
`user_ptr − 8`. Flags: `PREV_INUSE (0x1)`, `IS_MMAPPED (0x2)`,
`NON_MAIN_ARENA (0x4)`.

**15.** `malloc(24)` needs 24 usable bytes; with the 8-byte `size` field and
16-byte alignment the chunk is `0x20`, and `PREV_INUSE` sets the low bit → the
`size` field reads `0x21`.

**16.** `malloc(24)` returns the **last freed** 24-byte chunk — `a` if you did
`free(b); free(a);` — because tcache is **LIFO** (singly linked, newest at head).

**17.** `malloc(sizeof(int))` allocates 4 bytes, but `r` is a `struct rec` (20+
bytes); writing `r->id` and `r->note` overflows immediately. Fix:
`malloc(sizeof *r)` (always size by the dereferenced pointer) and bound the
`strcpy` with `snprintf(r->note, sizeof r->note, "%s", s)`.

**18.** (1) free a chunk; (2) its `next` field now links the tcache list;
(3) overwrite `next` (via UAF/overflow) with a target address; (4) `malloc`
twice — the second returns the target. Mitigations: **tcache key** (detects
double-free) and **Safe-Linking** (`next` XOR'd with `chunk>>12`), which forces
you to **leak a heap address** to forge a valid encoded `next`.

**19.** See `protect_ptr(pos, ptr) = (pos>>12) ^ ptr`, where `pos` is the freed
chunk's address (the location of its `next`). You write that encoded value so
that after glibc de-obfuscates it, the allocator follows `ptr`. The `>>12`
aligns to the page so the top bits of the heap address mask the pointer.

---

## Chapter 6

**20.** A dangling pointer still holds the address of freed memory. Habit:
`free(p); p = NULL;` — a later deref then crashes immediately (and double-free
becomes a safe no-op).

**21.** Free the victim, then allocate attacker-controlled data of the **same
size** so the allocator returns the **same chunk** (LIFO), placing your bytes
where the old object was; then the dangling pointer reads your bytes. Same size =
same bin = same chunk back; a different size comes from a different bin and won't
reuse the slot.

**22.** (1) On the error branch, `buf` is freed but execution falls through to
`use(buf)` → **UAF**. (2) Then `free(buf)` runs again → **double-free**. Fix:
`if (parse(buf) < 0){ free(buf); buf=NULL; return; }` (single exit, null the
pointer).

**23.** `realloc` may **move** the block and free the old one, so every existing
pointer into it dangles. After every `realloc`, reassign from its return value
and discard all old copies/offsets.

**24.** ASan prints three stacks: **allocated by** (the `malloc` in `main`),
**freed by** (the `free`), and the **use** (the `o->run()` read) — each with
file:line. That triplet is the anatomy of every UAF.

---

## Chapter 7

**25.** `printf(user)` lets the user's `%`-conversions drive memory access
(`%p/%s/%n`). `printf("%s", user)` treats the user bytes purely as a string
argument — no conversions are taken from attacker data.

**26.** `%p` print a pointer-sized stack word (**read**); `%s` dereference the
next word as `char*` (**read**, arbitrary if you control it); `%n` **write** the
printed-byte count to the next word's address (**write**); `%7$p` directly read
argument #7 (**read**, positional); `%100c` print 100 chars (sets the count for a
following `%n`).

**27.** Send `AAAA%1$p%2$p...` (or `pwn fmtstr`), increasing N until a `%N$p`
prints `0x41414141`/`0x...41414141` — that N is your buffer's arg index. Confirm
by changing `AAAA`→`BBBB` and seeing the printed value change accordingly.

**28.** The script leaks the offset, reads `&target` from the banner, and calls
`fmtstr_payload(offset, {target: 0xdeadbeef}, write_size="byte")`. 64-bit writes
use `%hhn` (1 byte) at `addr, addr+1, …` because `%n` writes the *printed count*;
printing 0xdeadbeef (≈3.7 billion) bytes to do one 4-byte write is impossible, so
you split into byte-sized counts and write each byte.

**29.** `-Werror=format-security` (with `-Wformat`) makes
`printf(non_literal)` a compile error. Training builds omit it (`-Wno-format-
security`) precisely so the vulnerable form compiles for study.

---

## Chapter 8

**30.** overflow: `UINT_MAX + 1 == 0`; underflow: `0u - 1 == UINT_MAX`;
truncation: `(uint16_t)0x10001 == 1`; signedness: `(size_t)(-1) == SIZE_MAX`;
sign extension: `(int)(char)0xFF == -1`.

**31.** `len` is **signed**; `-1 > 1024` is false so the check passes, but
`memcpy`'s size is `size_t`, so `-1` becomes `SIZE_MAX` → enormous copy. Fix:
use an **unsigned** length and check `if (len == 0 || len > sizeof buf)`.

**32.** (1) `calloc` **zero-initializes** (kills uninitialized-read leaks).
(2) `calloc` **checks `n*size` for overflow** and returns NULL instead of
under-allocating. `malloc(n*size)` does neither.

**33.** `count * sizeof(long)` with 32-bit `unsigned`: pick `count` so
`count*8 mod 2^32 < 8`, e.g. `count = 0x20000000` → `0x20000000*8 =
0x100000000 ≡ 0 (mod 2^32)` → `malloc(0)`; the loop then writes `count*8` bytes.
ASan reports `heap-buffer-overflow`.

**34.** Signed compares use `jg/jl/jge/jle`; unsigned use `ja/jb/jae/jbe`.
Sign-extension is `movsx`/`movsxd`; zero-extension is `movzx`.

---

## Chapter 9

**35.** `if (claimed_length > actual_payload_length) return error;` — OpenSSL
echoed `claimed` bytes without comparing it to what the client actually sent.

**36.** A fresh `malloc` can return a just-freed chunk still holding old data; if
that reaches output, secrets/pointers leak. `calloc` zeroes it. It's not always
the answer because zeroing costs cycles on hot paths and you may legitimately
fill the whole buffer before reading — the real rule is "don't read/send
uninitialized bytes."

**37.** Leaks **3 bytes** of padding between `a` (offset 0) and `b` (offset 4,
4-aligned). Those 3 bytes are never written, so `sizeof m == 8` sends 1+3+4 and
the 3 are stale. Fix: `memset(&m,0,sizeof m)` first.

**38.** MSan flags the **use of uninitialized values** (the padding bytes in
`14_uninit_leak`) — a bug ASan can't see because the memory is validly
allocated. ASan flags the **out-of-bounds read** in `13_oob_read` (reading past
the valid region) — a bug MSan doesn't specialize in. Different tools, different
classes; run both.

---

## Chapter 10

**39.** The vptr is the **first 8 bytes** of a polymorphic object, in writable
(heap/stack) memory, pointing at the read-only vtable. Overwriting those 8 bytes
(UAF reclaim, overflow from the previous object) redirects every virtual call.

**40.** Type confusion = using memory of type A as type B, so fields are read at
the wrong offsets (e.g. a data field where a function pointer is expected).
`static_cast` does **no runtime check**; `dynamic_cast` checks the actual type
and returns null/throws on mismatch.

**41.** Raw `new[]`/`delete` mismatch (`delete` vs `delete[]`) and a leak if
`read_into`/`process` throw. RAII fix: `std::vector<char> b(256);` — automatic
sizing, automatic free on scope exit / exception.

**42.** Disassemble `main`; around the second `b->run()` you'll see
`mov rax,[b]` (load vptr) → `mov rax,[rax]` (vtable[0]) → `call rax`. After the
UAF plant, `[b]` is `&fake_vtable` and `[rax]` is `&pwned`.

---

## Chapter 11

**43.** TOCTOU: a resource's state changes between when you **check** it and when
you **use** it. FS: `access()` says writable, attacker swaps a symlink, `open()`
hits `/etc/passwd`. Memory: thread checks `ptr != NULL`, another frees it before
the deref.

**44.** The kernel reads a userspace value (e.g. a length) **twice**; a second
user thread changes it between reads, so the validated value isn't the one used
→ overflow. Fix: `copy_from_user` the whole request **once** into kernel memory,
then validate and use only that copy.

**45.** `make tsan && ./bin/17_race_uaf_tsan` → "data race" with the `free` and
`strcpy` stacks. Fix: guard the check-and-use with a `pthread_mutex` around both
the `local = g` read and the `strcpy` (and the killer's `free`/reassign); TSan
then reports clean.

**46.** `rc--` is load/decrement/store; two threads can interleave so one
decrement is lost → `rc` too high (leak) or both see 0 → **double-free**; a
missing increment → `rc` hits 0 while referenced → **UAF**. Kernel `refcount_t`
uses atomic ops **and saturates** (won't wrap past 0/UINT_MAX), preventing the
under/overflow.

---

## Chapter 12–13

**47.** NX marks the stack/heap non-executable, so injected shellcode faults when
executed. Attackers switched to **code reuse** (ret2libc, ROP) — reusing the
already-executable libc/binary code.

**48.** `rdi` must hold the `/bin/sh` pointer (first arg, SysV). Gadget:
`pop rdi ; ret`.

**49.** Under ASLR you don't know libc's base, so you can't hard-code
gadget/function addresses. Stage 1 ROP calls `puts(puts@got)`, which prints
libc's *runtime* address of `puts`; subtract the known offset → libc base →
every address. Stage 2 builds the real `system("/bin/sh")` chain.

**50.** Canary: stops linear return-address overwrite; bypass = leak the canary.
NX: stops injected shellcode; bypass = ROP. ASLR/PIE: stops hard-coded addresses;
bypass = info leak. Full RELRO: stops GOT overwrite; bypass = other targets
(FSOP). CFI: stops indirect-call hijack; bypass = data-only attacks.

**51.** Training `03_ret2win`: `No canary`, `NX` may be disabled (execstack),
`No PIE`, `Partial RELRO`. `make safe`: `Canary found`, `NX enabled`,
`PIE enabled`, `Full RELRO`. Each line removes a technique (fixed gadget
addresses, shellcode, GOT overwrite, linear overwrite), forcing the attacker into
leak+ROP+data-only.

---

## Chapter 14

**52.** Kernel code runs in ring 0 with full access to all memory/hardware; a
bug yields root / whole-machine compromise (LPE), not just one process, and can
corrupt any system structure.

**53.** (1) missing length check before `copy_from_user` (overflow);
(2) uninitialized kernel memory / struct padding sent via `copy_to_user`
(infoleak → KASLR defeat); (3) double-fetch TOCTOU. Accessors:
`copy_from_user`/`copy_to_user`/`get_user`/`put_user` (they validate the user
range).

**54.** Free a kernel object holding an `ops`/function pointer (often via a
refcount bug) → spray same-size objects you control (e.g. `msg_msg`) to reclaim
the slot → trigger the dangling pointer's callback → control flow. Interruptions:
**SMAP/SMEP** stop pivoting to userspace code/data; **SLAB_FREELIST_HARDENED**
and **RANDOM** hinder predictable reuse; **init_on_free** zeroes freed memory
(kills the stale pointer/leak); **kCFI** blocks the hijacked indirect call.

---

## Capstone (55)

A good report mirrors a CVE advisory: **Summary** (one line), **Affected
code/version**, **Bug class & root cause** (with the offending line),
**Primitive** (control `rip` / write-what-where / read), **Exploitation**
(leak → target → payload, with the offset and addresses), **Impact** (RCE/LPE/
DoS/infoleak), **Fix** (the diff), and **Detection** (which sanitizer/fuzzer
would have caught it). If your safe rewrite makes the same exploit fail *and* a
fuzzer with ASan no longer finds a crash, you've closed the loop.
