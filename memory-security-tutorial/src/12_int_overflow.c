/* 12_int_overflow.c  —  Chapter 8: integer overflow -> undersized allocation
 *                        -> heap overflow.
 *
 * The allocation size is computed as count*size. If that product WRAPS around
 * the integer type, malloc gets a tiny number, but the loop that fills the
 * buffer uses the REAL count -> it writes far past the allocation.
 *
 * RUN
 *   ./bin/12_int_overflow 1                 -> fine
 *   ./bin/12_int_overflow 1431655766        -> count*8 overflows 32-bit -> OOB
 *   make asan && ./bin/12_int_overflow_asan 1431655766
 *     -> AddressSanitizer: heap-buffer-overflow (write past the tiny region)
 *
 * 1431655766 * 8 = 11453246128, which modulo 2^32 (4294967296) = 2863311528...
 * the point is the product no longer equals count*8, so malloc under-allocates.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <count>\n", argv[0]); return 1; }

    /* 'unsigned' (32-bit) product wraps silently. Even size_t can wrap for
     * large enough inputs; the bug is the SAME shape. */
    unsigned count = (unsigned)strtoul(argv[1], NULL, 0);
    unsigned bytes = count * (unsigned)sizeof(long);   /* THE WRAP happens here */

    printf("count=%u  requested bytes (wrapped)=%u\n", count, bytes);

    long *buf = malloc(bytes);    /* allocates the WRAPPED (too-small) size */
    if (!buf) { perror("malloc"); return 1; }

    /* The loop uses the REAL count, not the wrapped byte size -> writes
     * count*8 bytes into a buffer that holds `bytes` bytes. */
    for (unsigned i = 0; i < count; i++)
        buf[i] = 0x4141414141414141UL;   /* heap overflow once i*8 >= bytes */

    puts("done (if you got here without a crash, try a bigger count or ASan)");
    free(buf);
    return 0;
}

/* FIX: calloc() checks count*size for overflow and returns NULL instead of
 * under-allocating:
 *     long *buf = calloc(count, sizeof(long));
 *     if (!buf) { ... }         // handles both OOM and the overflow case
 * Or check explicitly: if (count > UINT_MAX / sizeof(long)) abort();
 * Also compile with -fsanitize=undefined to trap the overflow at runtime. */
