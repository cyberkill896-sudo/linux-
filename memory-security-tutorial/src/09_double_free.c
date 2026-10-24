/* 09_double_free.c  —  Chapter 6: double free, and why it's a primitive.
 *
 * Freeing the same chunk twice puts it on the free list twice, so two later
 * allocations return the SAME address — two "independent" pointers aliasing one
 * buffer. Corrupt one, and the other changes under the program's feet.
 *
 * RUN (modern glibc)
 *   ./bin/09_double_free
 *     -> glibc aborts: "free(): double free detected in tcache 2"
 *   That abort is the tcache KEY mitigation (glibc >= 2.29) catching the naive
 *   immediate double-free. It is a speed bump, not a cure — real exploits clear
 *   the key via another bug, or interleave frees to dodge the check.
 *
 * To SEE the aliasing effect on an allocator without the check (or to study the
 * concept), compile with -DNAIVE and read the comments; on hardened glibc the
 * program will abort at the second free, which is itself the lesson.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char *p = malloc(32);
    strcpy(p, "first");
    printf("p = %p ('%s')\n", (void*)p, p);

    free(p);
    free(p);                      /* THE BUG: double free of the same chunk */

    /* If the allocator did not abort, these two allocations would alias: */
    char *a = malloc(32);         /* == p */
    char *b = malloc(32);         /* == p as well (duplicate on the free list) */
    strcpy(a, "written via a");
    printf("a=%p b=%p  b now reads: '%s'\n", (void*)a, (void*)b, b);
    /* b shows a's data because a and b are the same memory. From here an
     * attacker forges chunk contents to get malloc to return an arbitrary
     * pointer (tcache/fastbin "dup" -> poisoning; see Chapter 5). */
    return 0;
}

/* FIX: `free(p); p = NULL;`  — free(NULL) is a safe no-op, so a second free
 * does nothing. Enforce single ownership so there is exactly one free per
 * object. */
