/* 02_stack_authflag.c  —  Chapter 2: overflow into an ADJACENT local.
 *
 * You don't always need to control RIP. Here the overflow just flips a
 * neighboring variable — an authentication bypass with no return-address work.
 *
 * RUN
 *   printf 'hunter2\n'                  | ./bin/02_stack_authflag   -> denied
 *   python3 -c 'print("A"*40)'         | ./bin/02_stack_authflag    -> GRANTED
 *
 * WHY
 *   `pass` and `authed` are both locals in main()'s frame. The compiler lays
 *   them out adjacently on the stack. gets() reads an entire line with NO size
 *   limit, so a long line overruns `pass` and writes into `authed`. Any
 *   non-zero byte landing in `authed` makes `if (authed)` true.
 *
 *   NOTE: exact adjacency/order is compiler- and flag-dependent. If it doesn't
 *   flip on your build, inspect the layout:
 *       gdb> break <line of the if>  ; run ; p &pass ; p &authed
 *   and adjust the padding length. The *lesson* — an overflow clobbers whatever
 *   the compiler placed next to the buffer — is the point, not the exact count.
 */
#include <stdio.h>

int main(void)
{
    volatile int authed = 0;      /* 'volatile' stops the optimizer from folding
                                     this into a constant so the demo is stable */
    char pass[16];

    printf("password: ");
    fflush(stdout);
    gets(pass);                   /* THE BUG: gets() has no bound. Deprecated for
                                     exactly this reason; the linker will warn. */

    if (authed)
        puts("ACCESS GRANTED (you overflowed into `authed`!)");
    else
        puts("denied");
    return 0;
}

/* FIX: use fgets() with the buffer size, and never make a security decision
 * depend on a variable that sits next to an unbounded buffer:
 *     fgets(pass, sizeof pass, stdin);
 */
