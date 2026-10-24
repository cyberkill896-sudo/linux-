# Walkthroughs — full programs mapped to memory

Unlike the short, one-bug files in [`../src/`](../src/README.md), these are
**complete, realistic programs** (framing layers, session state, menus,
callbacks) with the vulnerability embedded in context. Each has a deep
`WALKTHROUGH.md` that maps **every relevant line to the exact bytes it touches**
— stack frames with real `rbp` offsets, heap chunks with real addresses — then
reproduces, exploits (to a shell), and fixes the bug.

> ⚠️ Deliberately vulnerable. Build and run only in a throwaway VM/container.
> Disable ASLR while exploiting: `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`.

| # | Program | Bug class | Memory focus |
|---|---------|-----------|--------------|
| 1 | [`01-login-server/`](01-login-server/WALKTHROUGH.md) | stack buffer overflow in a length-prefixed protocol handler | **stack frame**: locals → saved RBP → return address, offset derived from disassembly and confirmed with a cyclic pattern; ret2win to a shell |
| 2 | [`02-note-manager/`](02-note-manager/WALKTHROUGH.md) | heap overflow + use-after-free + double-free in a menu-driven object manager | **heap chunks**: same-size tcache reuse, a note's callback at chunk offset 0, overflow into the neighbor's callback → shell; ASan reports for each bug |

Each folder has: the program (`server.c` / `notes.c`), an `exploit.py` payload
builder, and the `WALKTHROUGH.md`. All examples are **verified to build, to
exploit (root shell in the lab), to be caught by AddressSanitizer, and to be
fixed by the `-DSAFE` build.**

## Quick start

```bash
# Example 1 — stack overflow server
cd 01-login-server
gcc -g -O0 -fno-stack-protector -no-pie -DWITH_WIN server.c -o server_win
(python3 exploit.py ret2win; echo 'id') | ./server_win     # -> hijack + shell
# read WALKTHROUGH.md alongside

# Example 2 — heap note manager
cd ../02-note-manager
gcc -g -O0 -fno-stack-protector -no-pie notes.c -o notes
admin=$(./notes <<< '6' | sed -n 's/.*admin_shell is at //p' | tr -d ')')
(python3 exploit.py overflow $admin; echo 'id') | ./notes   # -> hijack + shell
```

Read these **after** Chapters 2 (stack) and 3–6 (heap/UAF); they're the "putting
it together on real code" capstones for those chapters.
