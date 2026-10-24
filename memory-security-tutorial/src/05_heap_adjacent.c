/* 05_heap_adjacent.c  —  Chapter 4: heap overflow into the NEXT object.
 *
 * Two same-size heap chunks are usually physically adjacent. Overflowing the
 * first writes through its chunk, through the second chunk's 16-byte header,
 * and into the second object's data.
 *
 * RUN
 *   ./bin/05_heap_adjacent
 *     a=0x...  b=0x...  gap=0x20        <- b is 0x20 bytes above a (chunk size)
 *     b before = 'BBBB'
 *     b after  = 'AAAA...'              <- b's data was clobbered by a's overflow
 *
 * ASan shows the precise overflow:
 *   make asan && ./bin/05_heap_adjacent_asan
 *     -> heap-buffer-overflow WRITE ... 0 bytes to the right of 24-byte region
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *a = malloc(24);         /* usable 24; chunk is 0x20 incl. header */
    char *b = malloc(24);
    strcpy(b, "BBBB");

    printf("a=%p  b=%p  gap=0x%lx\n", (void*)a, (void*)b, (unsigned long)(b - a));
    printf("b before = '%s'\n", b);

    /* THE BUG: write 40 bytes into a 24-byte allocation. Bytes 24..39 spill
     * past `a`: first into `b`'s chunk header (prev_size/size), then into b's
     * user data. */
    memset(a, 'A', 40);
    a[39] = '\0';

    printf("b after  = '%s'\n", b);   /* b now shows spilled 'A's */

    /* free(a); free(b);  <- often aborts: "corrupted size vs. prev_size"
     * because we trampled b's chunk header. Uncomment to see the allocator
     * detect the metadata corruption. */
    return 0;
}

/* FIX: never write more than the allocation size.
 *     memcpy(a, src, n <= 24 ? n : 24);   or track the size and bound every
 * write. Prefer calloc for arrays (zeroing + overflow-checked multiply). */
