/* 03_ret2win.c  —  Chapter 2 & 12: return-address hijack to a hidden function.
 *
 * The classic CTF "ret2win": overwrite the saved return address with the
 * address of win(), which is never called on the normal path.
 *
 * BUILD (Makefile does this): -fno-stack-protector -no-pie  so (a) there is no
 * canary between buf and the return address, and (b) win()'s address is fixed
 * (no PIE), so we can hardcode it.
 *
 * STEPS
 *   1) Find win():            objdump -d bin/03_ret2win | grep '<win>:'
 *   2) Find the offset:       gdb, cyclic pattern -> offset to saved RIP
 *   3) Payload = b'A'*offset + p64(win_addr)   (+ a ret gadget for alignment)
 *   See exploits/03_ret2win.py for the automated version (pwntools finds the
 *   offset and the alignment ret gadget for you).
 *
 * ALIGNMENT NOTE (x86-64): system() internally uses `movaps`, which faults
 * unless RSP is 16-byte aligned at the call. If win() crashes inside system(),
 * prepend a bare `ret` gadget so RSP shifts by 8. pwntools' ROP() handles it.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win(void)                    /* the target: never reached by normal flow */
{
    puts("[win] control-flow hijacked -> spawning a shell (lab only)");
    system("/bin/sh");
}

__attribute__((noinline))
void vuln(void)
{
    char buf[32];
    puts("send your input:");
    fflush(stdout);
    gets(buf);                    /* THE BUG: unbounded read into 32 bytes */
}

int main(void)
{
    /* unbuffered stdio so the shell's I/O behaves under pwntools */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    vuln();
    puts("vuln() returned normally (you did NOT hijack control)");
    return 0;
}

/* FIX: fgets(buf, sizeof buf, stdin);  — the return address is then never
 * reachable from buf. Plus -fstack-protector-strong would abort on the
 * overwrite, and PIE would randomize win()'s address. */
