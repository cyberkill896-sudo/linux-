/* 01_stack_basic.c  —  Chapter 2: the canonical stack buffer overflow.
 *
 * WHAT TO OBSERVE
 *   ./bin/01_stack_basic AAAA                      -> prints, exits cleanly
 *   ./bin/01_stack_basic $(python3 -c 'print("A"*16)')  -> fills buf exactly
 *   ./bin/01_stack_basic $(python3 -c 'print("A"*40)')  -> SIGSEGV
 *
 * WHY THE CRASH HAPPENS
 *   `buf` is 16 bytes. strcpy() copies the argument byte-for-byte until it hits
 *   the terminating NUL of the *source* — it NEVER looks at how big `buf` is.
 *   So a 40-byte argument writes 40 bytes starting at buf, marching UPWARD in
 *   memory (toward higher addresses) through:
 *       buf[0..15]      (16 bytes, the legitimate buffer)
 *       saved RBP       (next 8 bytes)
 *       return address  (next 8 bytes)   <-- bytes 24..31 land here
 *   When vuln() runs `ret`, the CPU pops those 8 attacker bytes into RIP and
 *   jumps there. 0x4141414141414141 ("AAAAAAAA") is unmapped -> segfault.
 *
 * FIND THE EXACT OFFSET (don't guess):
 *   gdb --args ./bin/01_stack_basic $(python3 -c 'print("A"*80)')   # (use cyclic)
 *   pwndbg> cyclic 80          # paste as the arg, run, then:
 *   pwndbg> cyclic -l $rsp     # prints the offset to the saved return address
 */
#include <stdio.h>
#include <string.h>

/* 'noinline' keeps vuln() as its own stack frame so the diagram above holds
 * exactly; -O0 (set by the Makefile) also prevents the compiler from inlining
 * or optimizing the buffer away. */
__attribute__((noinline))
void vuln(const char *input)
{
    char buf[16];                 /* 16-byte destination on vuln()'s stack frame */
#ifdef SAFE
    /* THE FIX: snprintf writes at most sizeof(buf) bytes and always
     * NUL-terminates, so a 40-byte argument is simply truncated to 15 chars. */
    snprintf(buf, sizeof buf, "%s", input);
#else
    strcpy(buf, input);           /* THE BUG: unbounded copy into a fixed buffer */
#endif
    printf("You entered: %s\n", buf);
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s <string>\n", argv[0]);
        return 1;
    }
    vuln(argv[1]);                /* argv[1] is fully attacker-controlled */
    puts("vuln() returned normally");   /* only prints if we DIDN'T hijack ret */
    return 0;
}

/* `make safe` rebuilds this file with -DSAFE into ./bin/01_stack_safe, which
 * takes the snprintf() path above. Confirm the fix:
 *     ./bin/01_stack_safe $(python3 -c 'print("A"*40)')   # no crash, truncated
 */
