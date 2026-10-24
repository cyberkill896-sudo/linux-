# Chapter 1 — The Memory Layout of a Binary

> You cannot understand a memory bug until you can picture *where* every byte
> lives. This chapter is the map. We go slowly and assume no prior knowledge of
> assembly or how memory works. Everything in later chapters is just "what
> happens when a program writes to the wrong place on this map."

If one part feels obvious, skim it. If a later chapter confuses you, the answer
is almost always back here.

---

## 1.0 First, what *is* memory?

Think of your computer's RAM (memory) as an enormous row of numbered boxes.

```
 box number:  0    1    2    3    4    5    6    7    8   ...
 contents:  [  ][  ][  ][  ][  ][  ][  ][  ][  ] ...
```

- Each box holds exactly **one byte** (a number from 0 to 255).
- Each box has a unique **address** — its box number. On a 64-bit computer those
  numbers can be huge (up to about 18 quintillion), which is why you see
  addresses written as big hexadecimal values like `0x7fffffffe2a0`.
- A **pointer** is just a value that *is* an address — "the data you want is in
  box number 0x7fffffffe2a0."

That's the whole model. Everything else — variables, the stack, the heap, code —
is just "which boxes, holding what, and who is allowed to read/write/execute
them." When we say a bug "overwrites the return address," we literally mean the
program wrote bytes into boxes it shouldn't have.

> **Hex refresher.** Programmers write addresses in **hexadecimal** (base 16,
> digits `0–9` then `a–f`). `0x` just means "this is hex." One hex digit = 4
> bits; two hex digits = one byte. So `0x41` is one byte = 65 = the letter `'A'`.
> You'll see `"AAAA"` show up as `0x41414141` constantly — that's four `'A'`
> bytes in a row.

---

## 1.1 From source code to a running program

You write C source, but the CPU runs numbers. Here is the pipeline:

```
hello.c  --(compiler: gcc)-->  hello.o  --(linker: ld)-->  ./hello  (ELF file)
                                                                 |
                                                       (loader / execve)
                                                                 v
                                                    a PROCESS running in RAM
```

Step by step:

1. **Compiler** turns your human-readable C into **machine code** (raw CPU
   instructions as bytes) and packages it in an object file.
2. **Linker** stitches object files and libraries together into one finished
   program file.
3. That finished file is an **ELF file** (Executable and Linkable Format — the
   standard program-file format on Linux). It is a **blueprint** sitting on your
   disk: "here is the code, here are the pre-set global values, load me like
   this." It is *not* running yet — it's just a file.
4. When you type `./hello`, the **loader** (part of the OS) reads that blueprint
   and copies its pieces into memory boxes, sets things up, and starts it. Now it
   is a **process** — a running program with its own memory.

**Every vulnerability in this course is about corrupting a *process's* memory
while it runs.** The ELF file on disk is just the starting template.

Look at a real ELF file:

```bash
file ./hello        # tells you it's an ELF 64-bit executable
readelf -h ./hello  # the ELF header (where code starts, etc.)
readelf -S ./hello  # the "sections" — the named regions we'll meet below
size ./hello        # how big the code / data regions are
```

---

## 1.2 The process address space (the big map)

When your program runs, the OS gives it a private set of memory boxes called its
**virtual address space**. "Virtual" means each program *thinks* it has the whole
memory to itself; the OS secretly maps those to real RAM. You don't need to worry
about that trick — just know each process has its own private map.

Here's that map. By convention we draw **high addresses (big box numbers) at the
top** and low addresses at the bottom:

```
   HIGH ADDRESSES  (e.g. 0x7fffffffffff)
  +---------------------------------+
  |         Kernel space            |  the OS lives here; your program can't touch it
  +---------------------------------+
  |         [ the STACK ]           |  local variables, function calls
  |            |                    |  ↓ GROWS DOWNWARD (toward smaller addresses)
  |            v                    |
  |                                 |
  |        (big empty gap)          |
  |                                 |
  |            ^                    |
  |            |                    |
  |   [ mmap / shared libraries ]   |  libc and other libraries loaded here
  |                                 |
  |            ^                    |
  |            |                    |  ↑ the HEAP grows UPWARD
  |         [ the HEAP ]            |  memory from malloc()/new
  +---------------------------------+
  |   .bss    (zeroed globals)      |
  +---------------------------------+
  |   .data   (preset globals)      |
  +---------------------------------+
  |   .rodata (read-only constants) |
  +---------------------------------+
  |   .text   (the machine code)    |  your compiled program instructions
  +---------------------------------+
   LOW ADDRESSES  (e.g. 0x400000)
```

Two facts to burn in now, because they drive everything:

- **The stack grows DOWN and the heap grows UP**, toward each other. "Grows down"
  means each new thing on the stack goes at a *smaller* address than the last.
  (This feels backwards; §1.5 makes it concrete.)
- **Code (`.text`) can be executed but not written; data/stack/heap can be
  written but not executed** on modern systems. That "writable XOR executable"
  rule (called **NX** / No-eXecute) is why attackers can't just dump their own
  code onto the stack and run it — Chapter 13 covers this. For now: code and data
  live in different neighborhoods with different rules.

### See the real map of a running program

```bash
cat /proc/self/maps        # the memory map of the `cat` process itself
# or, for a program you're debugging in gdb:
gdb ./hello  ->  (gdb) run  ->  (gdb) info proc mappings
```

You'll see the stack up near `0x7fff...`, libraries in the middle, your code down
low. The exact numbers change every run (that randomization is **ASLR**,
Chapter 13), but the *shape* above always holds.

---

## 1.3 The segments, one at a time (beginner view)

Each named region ("segment" or "section") holds a different kind of thing.
Here's what actually goes where, with tiny examples.

| Segment | Holds | Can write? | Can execute? | Lives for |
|---------|-------|-----------|-------------|-----------|
| `.text` | the machine code of your functions | no | **yes** | whole program |
| `.rodata` | read-only constants (string literals, `const` tables) | no | no | whole program |
| `.data` | globals/statics with a non-zero starting value | yes | no | whole program |
| `.bss` | globals/statics that start at zero | yes | no | whole program |
| heap | memory you request with `malloc`/`new` | yes | no | until you `free` it |
| stack | local variables, function bookkeeping | yes | no | one function call |

Mapping that to code:

```c
#include <stdio.h>
#include <stdlib.h>

int   g_counter = 5;          // .data   (a global with a non-zero initial value)
int   g_total;                // .bss    (a global starting at 0)
const char *msg = "hello";    // "hello" bytes live in .rodata; the pointer msg in .data

int main(void) {
    int local = 1;                  // STACK  (a normal local variable)
    static int seen = 0;            // .bss/.data (static: like a global, kept across calls)
    char *buf = malloc(100);        // the 100 bytes are on the HEAP;
                                    // the pointer `buf` is a local on the STACK
    // ... use buf ...
    free(buf);                      // hand the heap memory back
    return 0;
}
```

Notice the recurring split: **the pointer and the thing it points to can live in
different segments.** `buf` (a local pointer) sits on the stack; the 100 bytes it
points to sit on the heap. `msg` sits in `.data`; the `"hello"` text sits in
`.rodata`. Keeping "the pointer" separate from "the pointed-to data" in your head
prevents most beginner confusion.

### Why globals are "easy" and the stack/heap are "interesting"

A global lives at **one fixed address for the whole program** — simple. A stack
local is **created when its function is entered and destroyed when the function
returns** — so the same memory box gets reused for different variables over time
(this is why "use a pointer to a local after the function returned" is a bug —
Chapter 6). Heap memory lives **until you explicitly free it** — so forgetting to
free leaks memory, and freeing too early or twice is a bug (Chapters 5–6).

---

## 1.4 The stack explained with an analogy

Beginners get stuck on "the stack" because the word is overloaded. Here it means
one specific region of memory that the CPU uses like a **stack of plates**:

- You **push** a plate onto the top.
- You **pop** the top plate off.
- You always take the most recent one first. This is called **LIFO** — Last In,
  First Out.

Why does a program need this? Because functions call other functions, which call
others, and each one needs its own scratch space, and they must come back in the
reverse order they were called. A stack is the perfect structure for "last called
is first to return."

The CPU keeps one special register (a register is a tiny, ultra-fast storage slot
inside the CPU itself — see §1.6) called **`rsp`**, the **stack pointer**, that
always points at the **top plate** — i.e. the current top of the stack.

Because the stack **grows downward**, "push" means "move `rsp` to a *smaller*
address and put the value there," and "pop" means "read the value and move `rsp`
back to a *larger* address." Don't memorize the direction; just remember: **`rsp`
always points at the newest thing on the stack.**

---

## 1.5 A stack frame: one function's scratch space

Every time a function is called, it gets its own chunk of the stack called a
**stack frame**. The frame holds that function's local variables plus a little
bookkeeping. Here is the layout of one frame (high addresses on top):

```
   higher addresses
  +-----------------------------+
  |  ... the CALLER's frame ...  |
  +-----------------------------+
  |  RETURN ADDRESS              |  ← "where do I go back to when I'm done?"
  +-----------------------------+
  |  saved RBP (caller's RBP)    |  ← so we can restore the caller's frame
  +-----------------------------+  ← RBP points here (a stable anchor for this frame)
  |  local variable 1           |
  |  local variable 2           |
  |  char buffer[...]           |
  +-----------------------------+  ← RSP points here (the very top)
   lower addresses
```

Two registers manage this:

- **`rsp`** — the stack pointer, points at the top (lowest in-use address).
- **`rbp`** — the **base pointer** (or **frame pointer**), a *fixed anchor* for
  the current frame. The compiler often refers to locals as "rbp minus some
  offset," so having a steady `rbp` makes the generated code simple.

**The single most important thing in this entire course** is where the **return
address** sits: it is stored **just above the local variables**, at a *higher*
address than the buffers. So if a program writes past the end of a local buffer —
writing *upward*, toward higher addresses — it marches straight through the saved
`rbp` and into the **return address**. That is a stack buffer overflow
(Chapter 2). Stare at the diagram until that sentence is obvious.

---

## 1.6 `call` and `ret`, explained slowly (the part you asked about)

These two instructions are how functions start and finish. We'll walk through
them one micro-step at a time, showing the stack and the two key registers after
each step. This is the heart of the whole subject, so we go slow.

Two registers to watch:

- **`rip`** — the **instruction pointer**. It holds the address of the *next*
  instruction the CPU will run. The CPU automatically does: "read the instruction
  at `rip`, run it, move `rip` to the following instruction, repeat." Whoever
  controls `rip` controls what code runs. **`rip` is the ultimate prize for an
  attacker.**
- **`rsp`** — the stack pointer from §1.4.

### What `call func` does

Imagine `main` is running and reaches `call func`. The CPU must do two things:
(1) remember where to come back to, and (2) jump into `func`. `call` does both:

```
BEFORE  call func:
   rip = 0x1000   (the `call func` instruction itself)
   the instruction right AFTER the call is at 0x1005
   rsp = 0x7fffffffe0a0   (top of stack right now)
   stack top:  [ ... main's stuff ... ]

STEP 1 of `call`:  push the RETURN ADDRESS (0x1005) onto the stack.
   - "push" = move rsp down by 8 (addresses are 8 bytes on 64-bit), then store.
   - rsp becomes 0x7fffffffe098
   - the 8 bytes at 0x7fffffffe098 now hold 0x1005
   stack top:  [ 0x1005 ]  [ ... main's stuff ... ]
                  ^ this is the "return address": where to resume in main

STEP 2 of `call`:  jump to func.
   - rip = address of func, say 0x2000
   - the CPU now starts running func's instructions
```

In plain words: **`call` writes a sticky note on the stack that says "when you
finish, come back to address 0x1005," and then jumps into the function.** That
sticky note is the **return address**.

### What `ret` does

At the end of `func`, the CPU runs `ret`. It is the exact reverse of step 1 of
`call`:

```
BEFORE ret:
   rsp = 0x7fffffffe098
   stack top:  [ 0x1005 ]  ← the return address `call` left here
   rip = (somewhere inside func)

STEP of `ret`:  pop the top value into rip.
   - read the 8 bytes at rsp (= 0x1005)
   - set rip = 0x1005          ← jump back into main, right after the call
   - move rsp up by 8 (= 0x7fffffffe0a0)   ← the note is gone
   execution continues in main at 0x1005
```

In plain words: **`ret` reads the sticky note off the top of the stack and jumps
to whatever address it says.**

### The dangerous part — in one sentence

`ret` **blindly trusts** whatever 8 bytes are currently on top of the stack. It
does not check that they're the original note. So **if a bug has overwritten
those 8 bytes with an address the attacker chose, `ret` will happily jump there.**
That is the mechanism behind return-address hijacking, ret2libc, and ROP
(Chapters 2 and 12). The CPU isn't "tricked" by anything clever — it just does
what the stack tells it, and the stack got corrupted.

### How the compiler brackets every function (prologue & epilogue)

When you write a function, the compiler automatically wraps it with a few
setup/teardown instructions. You don't type these; they're generated. Reading
them demystifies the frame:

```asm
func:
    push   rbp          ; save the CALLER's base pointer onto the stack
    mov    rbp, rsp     ; set OUR base pointer to the current top -> anchor this frame
    sub    rsp, 0x20    ; reserve 0x20 (32) bytes of space for our local variables
    ...                 ; <-- the body of the function runs here
    leave               ; shorthand for: mov rsp, rbp ; pop rbp  (undo the frame)
    ret                 ; pop the return address into rip (see above)
```

- **`push rbp`** saves the caller's anchor so we can restore it later.
- **`mov rbp, rsp`** makes `rbp` the stable anchor of *this* frame.
- **`sub rsp, 0x20`** moves the top of the stack down to carve out room for
  locals (remember: down = toward smaller addresses = "allocate stack space").
- **`leave`** throws the frame away by moving `rsp` back up and restoring the old
  `rbp`.
- **`ret`** returns, as described above.

If you only remember one thing: **a function call leaves a return address on the
stack, right above the local variables, and `ret` jumps to whatever is there.**

---

## 1.7 Registers you'll keep seeing

A **register** is a tiny storage slot *inside* the CPU — far faster than RAM, and
there are only a handful. The CPU does its work in registers and uses memory for
everything that doesn't fit. On 64-bit x86 ("x86-64" / "amd64") the ones that
matter to us:

| Register | Beginner description |
|----------|----------------------|
| `rip` | **instruction pointer** — address of the next instruction. Control this = control the program. |
| `rsp` | **stack pointer** — top of the stack. |
| `rbp` | **base/frame pointer** — the current frame's anchor. |
| `rdi, rsi, rdx, rcx, r8, r9` | the **first six arguments** passed to a function, in that order. |
| `rax` | the **return value** of a function (and the syscall number). |
| `rbx, r10–r15` | general-purpose scratch space. |

That argument order is a rule called the **calling convention** (specifically the
"System V AMD64" convention used on Linux): argument 1 goes in `rdi`, argument 2
in `rsi`, and so on; the answer comes back in `rax`. Why do *attackers* care?
Because to make a program call, say, `system("/bin/sh")`, they must arrange for a
pointer to the text `"/bin/sh"` to be sitting in `rdi` before the call — the
convention tells them exactly which register to aim for (Chapter 12).

> The names look weird: the 64-bit register is `rax`, its lower 32 bits are
> `eax`, its lower 16 bits are `ax`, its lowest 8 bits are `al`. Same storage,
> different-sized views. You'll see `eax` in 32-bit code and `rax` in 64-bit.

---

## 1.8 Endianness — why addresses look "backwards" in memory

When a multi-byte value is stored in memory, which byte goes in the first box?
x86 uses **little-endian**: the **least-significant byte goes first** (at the
lowest address). This trips up every beginner, so here's a concrete example.

Take the 4-byte value `0x0A0B0C0D`. Its bytes, most-significant first, are
`0A 0B 0C 0D`. Stored little-endian in memory:

```
 address:  +0    +1    +2    +3
 byte:     0D    0C    0B    0A      ← reversed! least-significant (0D) first
```

So when an exploit needs to place the address `0x00401136` into memory (say, as a
return address), the bytes written are `36 11 40 00 00 00 00 00` — reversed, and
padded to 8 bytes for 64-bit. You will see this constantly in payloads.

You rarely do this by hand. In the exploit scripts we use **pwntools**, where
`p64(0x401136)` produces exactly those 8 little-endian bytes for you. But you need
to *recognize* the reversed pattern when you read a hex dump, so you don't think
the data is corrupted when it's just little-endian.

---

## 1.9 Pointers, and why C allows all these bugs

A **pointer** is a variable whose value is a memory address (a box number).
`char *p = buf;` means "`p` holds the address of `buf`." `*p` means "the byte in
the box that `p` points at." `p[3]` means "the byte three boxes past where `p`
points."

C's design choices are the *reason* memory bugs exist at all — this is worth
stating plainly so later chapters make sense:

1. **No bounds checking.** `arr[i]` compiles to "take the address of `arr`, add
   `i × element size`, read/write that box." The CPU has **no idea** how big
   `arr` is. If `i` is too big, you read or write a box that belongs to something
   else. Nothing stops you. (This is overflow / out-of-bounds — Chapters 2, 4, 9.)
2. **You manage lifetime by hand.** You decide when to `free` heap memory. The
   language doesn't track whether other pointers still refer to it, so freeing too
   early (dangling pointer, Chapter 6) or twice (double-free) is entirely
   possible.
3. **A pointer can point anywhere**, and you can do arithmetic on it with no
   checks. A wrong calculation silently points into the wrong place.
4. **"Undefined behavior."** The C standard says that out-of-bounds access,
   use-after-free, etc. are *undefined* — the compiler may do literally anything,
   including optimizations that make the bug stranger.

Languages like **Rust, Java, Go, and Python** remove these foot-guns by adding
automatic bounds checks, garbage collection, or compile-time ownership rules — at
some cost in speed or flexibility. Learning the C model shows you *exactly* what
those languages are protecting you from, and why so much security-critical code
is being rewritten in Rust.

---

## 1.10 Do this now — make it concrete (10 minutes)

Reading about the stack is nothing like watching it move. Run this once:

```c
// add.c
int add(int a, int b) { return a + b; }
int main(void) { return add(2, 3); }
```

```bash
gcc -g -O0 -no-pie add.c -o add

# 1) See the actual machine code and the prologue/epilogue from §1.6:
objdump -d --no-show-raw-insn -M intel add | sed -n '/<add>:/,/ret/p'

# 2) Single-step it and WATCH rsp, rbp, rip change:
gdb -q ./add
```

In gdb, try these commands in order and read the output each time:

```gdb
break main            # stop when main starts
run
info registers rip rsp rbp     # note the three values
x/4gx $rsp            # show 4 stack slots at the top (gx = 8-byte hex)
stepi                 # execute ONE instruction
stepi                 # ...and again; watch rsp/rip move after each
break add
continue              # run until `add` is entered
x/gx $rsp             # the top of the stack here is the RETURN ADDRESS into main
```

That last line is the payoff: the 8 bytes on top of the stack when `add` begins
are the address the program will jump back to in `main`. Seeing it with your own
eyes — a plain address sitting on the stack, nothing protecting it — is the moment
Chapter 2 becomes obvious.

---

## Chapter 1 recap (in plain words)

- Memory is a huge array of numbered **boxes**; an **address** is a box number; a
  **pointer** is a value that is an address.
- A running program's memory has regions: **code (`.text`, executable, read-only)**,
  **constants (`.rodata`)**, **globals (`.data`/`.bss`)**, the **heap** (manual,
  grows up), and the **stack** (automatic, grows down).
- The **stack** works like a stack of plates (LIFO); **`rsp`** points at the top.
  Each function gets a **frame** holding its locals, a saved `rbp`, and — just
  above the locals — the **return address**.
- **`call`** pushes a return address and jumps into the function; **`ret`** pops
  that address into **`rip`** and jumps back — *trusting whatever is on the stack*.
  Corrupt that saved address and you redirect the program.
- Registers live inside the CPU; **`rip`** is the instruction pointer (the prize),
  and arguments go in **`rdi, rsi, rdx, rcx, r8, r9`**.
- x86 is **little-endian**, so multi-byte values are stored least-significant byte
  first (addresses look "reversed" in memory).
- C does **no bounds checking** and uses **manual lifetimes** — the root of every
  bug in this course.

Now we make a buffer overflow actually happen and watch the return address get
clobbered: **[Chapter 2 — Stack buffer overflows »](02-stack-buffer-overflow.md)**
