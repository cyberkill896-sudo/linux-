/* 14_uninit_leak.c  —  Chapter 9: uninitialized-memory infoleak via struct
 *                       padding (the classic kernel copy_to_user leak shape).
 *
 * A struct with a small field followed by a wider one has PADDING bytes the
 * compiler inserts for alignment. If you set the fields but never zero the
 * struct, those padding bytes keep whatever was on the stack -> if you then
 * send the whole struct out, you leak that stale memory.
 *
 * RUN under MemorySanitizer (Clang) to see it flagged precisely:
 *   clang -g -O0 -fsanitize=memory 14_uninit_leak.c -o bin/14_uninit_leak_msan
 *   ./bin/14_uninit_leak_msan
 *     -> MemorySanitizer: use-of-uninitialized-value (the padding bytes)
 *
 * Plain run just prints the raw bytes so you can SEE non-zero padding:
 *   ./bin/14_uninit_leak
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>

struct msg {
    uint8_t  type;     /* 1 byte  */
                       /* 3 (or 7) bytes of PADDING inserted here for alignment */
    uint32_t len;      /* 4 bytes, must be 4-aligned */
};

static void dump(const void *p, size_t n, const char *label)
{
    const unsigned char *b = p;
    printf("%s: ", label);
    for (size_t i = 0; i < n; i++) printf("%02x ", b[i]);
    putchar('\n');
}

int main(void)
{
    /* Put junk on the stack so the padding is visibly non-zero in the demo. */
    volatile unsigned char scratch[sizeof(struct msg)];
    memset((void*)scratch, 0xCC, sizeof scratch);

    struct msg m;                 /* NOT zero-initialized */
    m.type = 1;
    m.len  = 0x41424344;
    /* The 3 padding bytes between `type` and `len` were never written. */

    dump(&m, sizeof m, "leaky  ");   /* padding shows stale bytes -> this is what
                                        a send(fd,&m,sizeof m) would leak */

    /* FIX: zero the whole struct first (covers padding), THEN set fields. */
    struct msg safe;
    memset(&safe, 0, sizeof safe);
    safe.type = 1;
    safe.len  = 0x41424344;
    dump(&safe, sizeof safe, "safe   ");   /* padding is 00 -> nothing leaks */
    return 0;
}

/* FIX recap: memset(&m,0,sizeof m) before filling (or `struct msg m = {0};`),
 * and only ever transmit bytes you actually initialized. In the kernel this is
 * the difference between a safe copy_to_user and a KASLR-defeating infoleak. */
