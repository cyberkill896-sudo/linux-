/* 04_offbyone.c  —  Chapter 2: the off-by-one (fencepost) error.
 *
 * A single byte past the end is still a bug. Here a `<=` writes one element too
 * many; depending on layout it corrupts the least-significant byte of the saved
 * frame pointer (RBP), which can pivot the stack on `leave; ret`.
 *
 * RUN under ASan to see it pinpointed regardless of layout:
 *   make asan && ./bin/04_offbyone_asan $(python3 -c 'print("A"*16)')
 *     -> AddressSanitizer: stack-buffer-overflow ... WRITE of size 1 at buf[16]
 */
#include <stdio.h>
#include <string.h>

__attribute__((noinline))
void copy_exact(const char *src)
{
    char buf[16];
    size_t n = strlen(src);
    if (n > 16) n = 16;           /* programmer THINKS this is safe... */

    /* THE BUG: i runs 0..n INCLUSIVE because of `<=`. When n==16 this writes
     * buf[0]..buf[16] — that's 17 bytes into a 16-byte buffer. buf[16] is one
     * past the end. */
    for (size_t i = 0; i <= n; i++)
        buf[i] = src[i];

    printf("copied %zu bytes: %.16s\n", n, buf);
}

int main(int argc, char **argv)
{
    copy_exact(argc > 1 ? argv[1] : "0123456789ABCDEF");
    return 0;
}

/* FIX: use `<` (strictly less than) and reserve room for the terminator:
 *     for (size_t i = 0; i < n && i < sizeof buf - 1; i++) buf[i] = src[i];
 *     buf[i] = '\0';
 * Off-by-one bugs are a discipline problem; `< size` and "reserve the NUL" kill
 * almost all of them. */
