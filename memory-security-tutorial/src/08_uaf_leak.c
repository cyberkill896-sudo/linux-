/* 08_uaf_leak.c  —  Chapter 6/9: information leak via freed/uninitialized heap.
 *
 * Two facts combine into a leak:
 *   - malloc() does NOT zero memory (only calloc does).
 *   - a freed chunk is handed back to the next same-size malloc intact.
 * So a new allocation can contain a previous object's bytes — here, a secret.
 *
 * RUN
 *   ./bin/08_uaf_leak
 *     secret at 0x... = 'SUPER_SECRET_KEY_123'
 *     re-malloc'd at 0x...  (same address)
 *     leaked: 'SUPER_SECRET_KEY_123'       <- the freed secret reappears
 *
 * IMPORTANT DETAIL (why we read from an OFFSET): when a chunk is freed into the
 * tcache, glibc writes two 8-byte fields — `next` and `key` — into the FIRST 16
 * bytes of the chunk's user area. That clobbers the first 16 bytes of our
 * string. The rest of the freed data is left untouched, so we store the secret
 * past those first 16 bytes and read it back from there. (This is itself a real
 * lesson: freed memory is partly overwritten by allocator bookkeeping, but the
 * tail still leaks.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SECRET "SUPER_SECRET_KEY_123"

int main(void)
{
    /* Use a larger chunk and place the secret AFTER the first 16 bytes, which
     * the tcache will reuse for its next/key metadata on free(). */
    char *secret = malloc(64);
    memset(secret, 0, 64);
    strcpy(secret + 16, SECRET);          /* secret lives at offset 16.. */
    printf("secret at %p = '%s'\n", (void*)(secret + 16), secret + 16);
    free(secret);                          /* tcache overwrites bytes 0..15 only */

    /* A later same-size allocation reclaims that chunk. We never zero it. */
    char *p = malloc(64);                  /* == secret's old address */
    printf("re-malloc'd at %p  (same address)\n", (void*)p);

    /* Reading the uninitialized tail leaks the stale secret. In a real server
     * this is `send(fd, p, 64)` echoing memory the attacker should never see.
     * Replace the string with a POINTER and you leak an address -> ASLR
     * defeated (Chapter 13). */
    printf("leaked: '%s'\n", p + 16);
    free(p);
    return 0;
}

/* FIX: zero sensitive memory before freeing (memset/explicit_bzero), use
 * calloc() for buffers you'll read before fully writing, and never send more
 * bytes than you actually wrote. */
