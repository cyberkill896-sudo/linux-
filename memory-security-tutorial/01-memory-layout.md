# Chapter 1 — The Memory Layout of a Binary

> You cannot understand a memory bug until you can picture *where* every byte
> lives. This chapter is the map. Everything in later chapters is "what happens
> when we write to the wrong place on this map."

---

## 1.1 From source code to a running process

```
hello.c  --(compiler: gcc)-->  hello.o  --(linker: ld)-->  ./hello  (ELF file)
                                                                 |
                                                       (loader / execve)
                                                                 v
                                                    a PROCESS in RAM
```

- The **ELF file** (Executable and Linkable Format on Linux) is a file on disk.
  It is a blueprint: "here is the code, here are the initialized globals, load
  me like this."
- When you run it, the **loader** maps pieces of that file into **virtual
  memory** and creates a **process**. The vulnerabilities we study are about
  corrupting the process's memory at runtime.

Inspect an ELF with:

```bash
file ./hello
readelf -h ./hello      # ELF header
readelf -S ./hello      # section headers
size ./hello            # sizes of text/data/bss
```

---

## 1.2 The virtual address space (the big picture)

Every process gets its **own private virtual address space**. On 64-bit Linux it
looks roughly like this (high addresses on top):

```
   HIGH ADDRESSES  0x7fff_ffff_ffff
  +---------------------------------+
  |         Kernel space            |   (not accessible from user mode)
  +---------------------------------+
  |         [ stack ]               |   grows DOWNWARD (toward lower addrs)
  |            |                    |
  |            v                    |
  |                                 |
  |   (unmapped gap)                |
  |                                 |
  |            ^                    |
  |            |                    |
  |   [ mmap / shared libs ]        |   libc, mapped files, big mallocs
  |                                 |
  |            ^                    |
  |            |                    |
  |         [ heap ]                |   grows UPWARD; malloc()/free()
  +---------------------------------+
  |   .bss   (uninitialized globals)|   zero-filled at start
  +---------------------------------+
  |   .data  (initialized globals)  |   e.g. int g = 5;
  +---------------------------------+
  |   .rodata (read-only constants) |   string literals, const tables
  +---------------------------------+
  |   .text  (machine code)         |   your compiled functions (read+exec)
  +---------------------------------+
   LOW ADDRESSES   0x0000_0000_0000
```

Key properties that *cause* or *prevent* bugs:

- **Stack grows down, heap grows up.** They approach each other.
- **.text is read-only + executable.** You cannot (normally) overwrite code.
- **.data/.bss/heap/stack are read-write but *not* executable** on modern
  systems (the **NX bit** — Chapter 6). That is why attackers moved from
  "inject code" to "reuse existing code" (ROP).

### See it yourself

```c
// map.c
#include <stdio.h>
#include <stdlib.h>
int g_init = 5;          // .data
int g_uninit;            // .bss
const char *msg = "hi";  // "hi" in .rodata, pointer in .data
int main(void) {
    int local = 1;               // stack
    int *h = malloc(sizeof(int)); // *h on heap, h on stack
    printf("&g_init  (.data)  = %p\n", (void*)&g_init);
    printf("&g_uninit(.bss)   = %p\n", (void*)&g_uninit);
    printf("msg str  (.rodata)= %p\n", (void*)msg);
    printf("&local   (stack)  = %p\n", (void*)&local);
    printf("h        (heap)   = %p\n", (void*)h);
    printf("&main    (.text)  = %p\n", (void*)main);
    free(h);
    return 0;
}
```

```bash
gcc -no-pie -g map.c -o map && ./map
cat /proc/$(pgrep map)/maps   # or run under gdb and `info proc mappings`
```

You'll see stack addresses near `0x7fff...`, heap low, `.text` lowest. The exact
numbers move with ASLR (Chapter 6), but the *relative* layout holds.

---

## 1.3 The segments in detail

| Segment | Holds | Writable? | Executable? | Lifetime |
|---------|-------|-----------|-------------|----------|
| `.text` | compiled instructions | no | **yes** | whole run |
| `.rodata` | string literals, `const` data | no | no | whole run |
| `.data` | initialized globals/statics | yes | no | whole run |
| `.bss` | zero-initialized globals/statics | yes | no | whole run |
| heap | `malloc`/`new` allocations | yes | no | until `free`/program end |
| stack | locals, args, return addresses | yes | no | per function call |

- **Globals and `static` locals** live in `.data`/`.bss` for the *entire*
  program — a single fixed address. Easy to reason about; overflow here
  corrupts neighboring globals.
- **Heap** memory lives until *you* free it. Forgetting = leak; freeing too
  early = **use-after-free** (Chapter 4); freeing twice = **double-free**.
- **Stack** memory is automatic: created on function entry, destroyed on return.
  Returning a pointer to a local is a dangling pointer. The stack is where the
  classic overflow lives (Chapter 2).

---

## 1.4 The stack and the call stack (the heart of it)

The **stack** is a region of memory used as a LIFO structure for function calls.
Two registers manage it on x86-64:

- **`rsp`** — the *stack pointer*, points at the current **top** of the stack
  (the lowest in-use address, since it grows down).
- **`rbp`** — the *base/frame pointer*, a stable anchor for the **current
  function's frame**.

Every function call builds a **stack frame** containing:

```
         higher addresses
  +-----------------------------+
  |  ... caller's frame ...      |
  +-----------------------------+
  |  argument 7, 8, ...          |  (first 6 args go in registers)
  +-----------------------------+
  |  RETURN ADDRESS              |  <-- pushed by the `call` instruction
  +-----------------------------+
  |  saved RBP (caller's)        |  <-- `push rbp` in function prologue
  +-----------------------------+  <-- RBP points here
  |  local variable 1            |
  |  local variable 2            |
  |  buffer[...]                 |
  +-----------------------------+  <-- RSP points here (top)
         lower addresses
```

**This picture is the single most important diagram in the course.** Notice the
**return address sits just above the local buffers**. If a buffer write runs
past its end — *upward, toward higher addresses* — it marches straight into the
saved RBP and then the **return address**. That is a stack buffer overflow.

### What `call` and `ret` actually do

- `call func` → pushes the address of the *next* instruction (where to resume)
  onto the stack, then jumps to `func`.
- `ret` → pops that saved address off the stack into `rip` (the instruction
  pointer) and continues there.

So **`ret` blindly trusts whatever 8 bytes are at `[rsp]`**. If an overflow put
an attacker's address there, `ret` jumps to it. No magic — the CPU just does
what the stack says. This is the mechanism behind return-address hijacking,
ret2libc, and ROP.

### Function prologue / epilogue (what the compiler emits)

```asm
func:
    push   rbp            ; save caller's frame pointer
    mov    rbp, rsp       ; establish our frame
    sub    rsp, 0x20      ; reserve 0x20 bytes for locals
    ...                   ; function body
    leave                 ; = mov rsp, rbp ; pop rbp   (tear down frame)
    ret                   ; pop return address into rip
```

---

## 1.5 Registers you must know (x86-64)

| Register | Role |
|----------|------|
| `rip` | instruction pointer — the address of the next instruction. **The ultimate target**: control `rip` and you control execution. |
| `rsp` | stack pointer (top of stack) |
| `rbp` | base/frame pointer |
| `rdi, rsi, rdx, rcx, r8, r9` | first 6 integer/pointer **function arguments**, in that order |
| `rax` | return value / syscall number |
| general | `rbx, r10–r15` scratch/callee-saved |

The **System V AMD64 calling convention** (Linux): args 1–6 go in
`rdi, rsi, rdx, rcx, r8, r9`; the return value comes back in `rax`. Knowing this
tells you *which registers an attacker must control* to call, say,
`system("/bin/sh")` — you need `/bin/sh`'s address in `rdi`. (Chapter 6.)

---

## 1.6 Endianness (why exploit bytes look "backwards")

x86 is **little-endian**: the least-significant byte is stored first (lowest
address). The 4-byte value `0x08048000` is stored in memory as:

```
address:  +0    +1    +2    +3
bytes:    00    80    04    08
```

So when you craft an address to overwrite a return address, you write its bytes
reversed. In pwntools you never do this by hand — `p64(0x401136)` produces the
correct little-endian 8 bytes. But you must *recognize* the pattern in hex dumps.

---

## 1.7 Pointers, bytes, and why C lets this happen

C's core design choices are *why* memory bugs exist at all:

1. **No bounds checking.** `arr[i]` compiles to "address of `arr` + `i`×size,
   dereference." The CPU doesn't know how big `arr` is. `i` out of range just
   reads/writes whatever is there.
2. **Manual lifetime.** You call `free`. The language doesn't track whether other
   pointers still refer to that memory → UAF/double-free.
3. **Pointers are just integers.** A pointer can point *anywhere*; arithmetic on
   it is unchecked.
4. **Undefined behavior (UB).** The standard says out-of-bounds access, UAF, etc.
   are UB — the compiler may do *anything*, including optimizations that make the
   bug worse.

Memory-safe languages (Rust, Java, Go, Python) add bounds checks, garbage
collection, or ownership/borrow checking to remove these foot-guns — at some
runtime or ergonomic cost. Understanding the C model shows you exactly what
those languages are protecting you from.

---

## 1.8 A tiny bit of assembly reading practice

Compile and disassemble so the abstract becomes concrete:

```c
// add.c
int add(int a, int b) { return a + b; }
int main(void) { return add(2, 3); }
```

```bash
gcc -g -O0 -no-pie add.c -o add
objdump -d --no-show-raw-insn add | sed -n '/<add>:/,/ret/p'
gdb -q ./add         # then:  break main / run / stepi / info registers / x/8gx $rsp
```

Reading disassembly and single-stepping in GDB while watching `rsp`, `rbp`, and
`rip` change is the fastest way to *internalize* the stack diagram above. Do it
once now; it pays off in every later chapter.

---

## Chapter 1 recap

- A process has distinct regions: **.text (code, exec, RO)**, **.rodata/.data/.bss
  (globals)**, **heap (dynamic, grows up)**, **stack (automatic, grows down)**.
- The **stack frame** holds locals, saved `rbp`, and the **return address** — in
  that order, with the return address *above* the buffers.
- `call` pushes a return address; `ret` pops it into `rip` and **trusts it
  blindly**.
- C does **no bounds checking** and uses **manual lifetimes** — the root of every
  bug in this course.

Next: we overflow a buffer and watch the return address get clobbered.
**[Chapter 2: Stack buffer overflows »](02-stack-buffer-overflow.md)**
