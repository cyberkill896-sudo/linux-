/* 10_format_leak.c  —  Chapter 7: format-string information leak.
 *
 * printf(user_input) lets the USER choose the format. Each %p consumes a
 * "next argument" that was never actually passed, so printf reads register/
 * stack words and prints them -> a reliable, crash-free memory leak.
 *
 * RUN
 *   echo 'AAAA %p %p %p %p %p %p %p %p' | ./bin/10_format_leak
 *     AAAA 0x... 0x... ... 0x41414141...   <- your "AAAA" appears -> that %p
 *                                              index is the offset to your buffer
 *   echo '%6$p'  | ./bin/10_format_leak      <- direct access to arg #6
 *   echo '%7$s'  | ./bin/10_format_leak      <- deref arg #7 as char* (arb read)
 *
 * Compile-time: -Wformat-security would REJECT this line. The Makefile omits it
 * on purpose so the bug exists; `make safe` adds it and the safe build fails to
 * compile the vulnerable form (that's the point).
 */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char buf[128];
    if (!fgets(buf, sizeof buf, stdin))
        return 1;
    buf[strcspn(buf, "\n")] = '\0';   /* strip newline */

#ifdef SAFE
    printf("%s", buf);            /* FIX: user data is an ARGUMENT, not the format */
#else
    printf(buf);                  /* THE BUG: user data IS the format string */
#endif
    putchar('\n');
    return 0;
}

/* WHY IT LEAKS (x86-64 SysV): the first variadic args come from registers
 * rsi,rdx,rcx,r8,r9, then the stack. printf has no idea none were passed; it
 * trusts the format and dumps those slots. On 32-bit, ALL args are on the
 * stack right above the return address, which is why %p %p %p walks the frame. */
