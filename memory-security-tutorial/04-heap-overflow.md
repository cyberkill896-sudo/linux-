# Chapter 4 — Heap Overflows & Corruption (10 test cases)

> Same root cause as the stack overflow — writing past a buffer — but now the
> adjacent memory is **another object** or **allocator metadata**.

---

## 4.1 Why the heap version is different

- No single "return address" sits next to a heap buffer. Instead you corrupt:
  1. **the next object's data** (flags, lengths, **function pointers / C++
     vtables**) — easiest, most common in the real world; or
  2. **the next chunk's metadata** (`size`, `prev_size`, `fd/bk/next`) — tricks
     the allocator itself into an arbitrary write (Chapter 5).
- Heap layout is less rigid than the stack, so attackers **groom** the heap
  (allocate/free in a pattern) to place the victim right after the overflowing
  buffer.

---

## 4.2 Test case 1 — overflow into the next object's data

```c
// h01_adjacent.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(void){
    char *a = malloc(24);
    char *b = malloc(24);                 // physically just above a
    printf("a=%p b=%p gap=%ld\n", a, b, b-a);
    strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");  // 32 bytes into 24
    printf("b = %s\n", b);                 // b now shows spilled 'A's
    free(a); free(b);
}
```
The write past `a` runs through `a`'s remaining space, through `b`'s chunk header
(`prev_size`/`size`), into `b`'s data. If `b` held something trusted, it's now
attacker-controlled.

---

## 4.3 Test case 2 — overwrite an adjacent function pointer (heap "ret2win")

```c
// h02_fnptr.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct widget { char name[16]; void (*action)(void); };
void normal(void){ puts("normal"); }
void danger(void){ puts("DANGER: hijacked heap function pointer!"); }
int main(int c, char **v){
    struct widget *w = malloc(sizeof *w);
    w->action = normal;
    strcpy(w->name, v[1]);        // >16 bytes overwrites w->action
    w->action();                  // calls whatever action now points to
    free(w);
}
```
```bash
gcc -g -O0 h02_fnptr.c -o h02
objdump -d h02 | grep '<danger>:'
./h02 $(python3 -c 'import sys;sys.stdout.buffer.write(b"A"*16+b"\x?? ...")')
```
This is the heap analogue of a return-address overwrite: **a corrupted code
pointer**. In C++ the corrupted pointer is often a **vtable pointer** (Chapter 10).

---

## 4.4 Test case 3 — length-field corruption → secondary overflow

```c
// h03_lenfield.c
struct buf { size_t len; char data[32]; };
void grow(struct buf *b, char *src){
    memcpy(b->data, src, b->len);   // if a PRECEDING overflow set b->len huge...
}
```
A small overflow that corrupts a neighboring object's **length** turns a later,
"well-behaved" `memcpy(dst, src, obj->len)` into a huge overflow. Watch for any
length that lives in heap memory that another buffer could reach.

---

## 4.5 Test case 4 — off-by-one / poison NUL byte

```c
// h04_poison_nul.c
char *a = malloc(0x18);        // chunk size 0x20, usable 0x18
char *b = malloc(0x18);
strcpy(a, big_24_byte_string); // writes a[0..23]; a[24] = '\0' is 1 past
                               // -> clears the low byte of b's size field
```
A single NUL written past `a` flips `b`'s `size` low byte (e.g. `0x21`→`0x00`),
corrupting the chunk-size/PREV_INUSE bookkeeping. The **"poison null byte"** and
**"off-by-one"** techniques build full exploits from this one byte by creating
**overlapping chunks**. Lesson: on the heap, *one byte is a real primitive*.

---

## 4.6 Test case 5 — integer overflow in the size (undersized alloc)

```c
// h05_intmul.c
void *make(size_t count, size_t size){
    void *p = malloc(count * size);   // count*size wraps -> tiny allocation
    for (size_t i=0;i<count;i++) ((char**)p)[i] = 0;  // writes count*size bytes
    return p;                                          // -> heap overflow
}
```
`malloc(0x100000000 * 0x10)` on 64-bit, or any 32-bit `count*size` that wraps,
allocates far less than the loop writes. **Use `calloc(count,size)`** (it detects
the overflow and fails) or check `count > SIZE_MAX/size` first. (Full treatment:
Chapter 8.)

---

## 4.7 Test case 6 — overflow via `realloc` size confusion

```c
// h06_realloc.c
char *p = malloc(64);
size_t n = get_len();            // attacker-influenced
p = realloc(p, n);               // if n==0: glibc frees p and returns NULL/min
memcpy(p, src, 64);              // but code still assumes 64 bytes -> overflow
```
`realloc` with a smaller size shrinks the usable region; code that still writes
the old size overflows. `realloc(p,0)` is also a trap (frees `p`). Always use the
*new* size and check the return.

---

## 4.8 Test case 7 — `strcat` onto a heap buffer

```c
// h07_strcat.c
char *msg = malloc(32);
strcpy(msg, prefix);          // prefix 20 bytes
strcat(msg, user_suffix);     // appends with no remaining-size check -> overflow
```
Same family as the stack `strcat`, but corrupts heap metadata/objects. Track the
remaining space: `strncat(msg, suf, 32 - strlen(msg) - 1)` or `snprintf`.

---

## 4.9 Test case 8 — array of pointers overflow (write-what-where seed)

```c
// h08_ptrarray.c
char **arr = malloc(4 * sizeof(char*));   // 4 slots
for (int i=0;i<n;i++) arr[i] = strdup(lines[i]);  // n>4 overflows the array
```
Overflowing an array of **pointers** is especially powerful: subsequent code
*dereferences* those slots, so corrupting them yields controlled reads/writes.

---

## 4.10 Test case 9 — mismatched allocation vs. use size

```c
// h09_sizemismatch.c
struct hdr { int type; int len; };
struct hdr *h = malloc(sizeof(int));   // only 4 bytes allocated...
h->len = 0;                            // ...but writing 8 bytes (two ints) -> OOB
```
Allocating for the wrong type/size (`sizeof(int)` instead of `sizeof(*h)`) is a
subtle, common overflow. Prefer `malloc(sizeof *h)` (the dereferenced form) so the
size always matches the pointer's type.

---

## 4.11 Test case 10 — `calloc` vs `malloc` for zeroing (and its overflow check)

```c
// h10_calloc.c
// BAD: malloc leaves garbage AND no overflow check on the multiply
int *v = malloc(n * sizeof(int));
// GOOD: calloc zeroes AND rejects n*sizeof(int) overflow (returns NULL)
int *v2 = calloc(n, sizeof(int));
```
`calloc` gives you two defenses at once: zero-initialization (kills the
uninitialized-read infoleak, Chapter 9) and a built-in multiply-overflow check.
Prefer it for arrays.

---

## 4.12 Impact

- Corrupt an **adjacent object** → flip flags, resize buffers, hijack **function
  pointers / vtables** → control flow or logic bypass.
- Corrupt **allocator metadata** → an **arbitrary write** primitive → full
  compromise (Chapter 5).
- Combined with an **info leak** (defeat ASLR), heap bugs give reliable RCE.
  Modern browser/kernel exploits are overwhelmingly heap bugs, because stacks are
  so well defended now.

---

## 4.13 The fixes

- **Bound every copy to the allocation size**; recompute remaining space for
  appends.
- **Track sizes explicitly**; never trust a length from input or from
  corruptible heap memory without re-validating.
- **`calloc` / checked multiplication** for `count * size`; **`sizeof *p`** for
  allocation.
- **`free(p); p = NULL;`** to blunt UAF/double-free (Chapters 5–6).
- C++: prefer `std::vector`/`std::string` and `.at()` over raw buffers.
- Build/test with **ASan** (`-fsanitize=address`) — detects heap overflow, with
  the exact chunk and both allocation/overflow stack traces; harden production
  with `MALLOC_CHECK_`, GWP-ASan, scudo, or hardened_malloc.

```c
snprintf(w->name, sizeof w->name, "%s", v[1]);   // h02 fix: can't reach ->action
```

---

## Recap
- Heap overflow corrupts **the next object** (often a function pointer/length) or
  **chunk metadata**; off-by-one is a real one-byte primitive on the heap.
- Ten shapes here: adjacent data, function pointer, length field, poison-NUL,
  int-mul, realloc, strcat, pointer array, size mismatch, calloc.
- Fix with bounded copies, explicit sizes, `calloc`, `sizeof *p`, and ASan.

Next, how corrupted metadata becomes an arbitrary write:
**[Chapter 5 — Heap exploitation techniques »](05-heap-techniques.md)**
