/* 11_format_write.c  —  Chapter 7: format-string ARBITRARY WRITE via %n.
 *
 * %n writes the number of bytes printed SO FAR to the address held in the next
 * argument. Combine field-width padding (to set the count) with positional
 * args (%N$n, to pick the target slot) and you get a controlled memory write.
 *
 * GOAL: set the global `target` to a chosen value without any code assigning it.
 *
 * RUN (see exploits/11_format_write.py for the pwntools version that computes
 * everything automatically with fmtstr_payload):
 *   ./bin/11_format_write
 *     target @ 0x<addr>   target = 0
 *     (type a payload that places &target in a stack slot, then %<width>c%N$n)
 *
 * Writing a full 64-bit value byte-by-byte uses %hhn (1-byte) writes at
 * addr, addr+1, addr+2, ... — printing 4 billion chars is impractical, so you
 * split the value. pwntools' fmtstr_payload(offset, {addr: value}) builds it.
 */
#include <stdio.h>
#include <string.h>

int target = 0;                   /* the victim; nothing ever assigns it legit */

int main(void)
{
    char buf[256];
    printf("target @ %p   target = %d\n", (void*)&target, target);

    if (!fgets(buf, sizeof buf, stdin))
        return 1;
    buf[strcspn(buf, "\n")] = '\0';

    printf(buf);                  /* THE BUG: enables %p (leak) and %n (write) */
    putchar('\n');

    printf("after: target = %d (0x%x)\n", target, target);
    return 0;
}

/* Example idea (addresses depend on your build; let pwntools do it):
 *   payload = p64(&target) + b"%<N>$n"   where N is the stack-arg index of the
 *   p64(&target) you just placed, and the printed length before %n is the value
 *   you want written. Use %<width>c to pad the count up to that value.
 *
 * FIX: printf("%s", buf). Also -D_FORTIFY_SOURCE=2 blocks %n in writable
 * format strings, and -Wformat-security rejects the code at compile time. */
