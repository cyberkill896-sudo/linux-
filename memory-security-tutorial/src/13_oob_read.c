/* 13_oob_read.c  —  Chapter 9: out-of-bounds READ (the Heartbleed shape).
 *
 * The program stores a short message in a big buffer, then "echoes" back a
 * CLIENT-SUPPLIED length without checking it against how many bytes are
 * actually valid. The extra bytes are stale memory -> information disclosure.
 *
 * RUN
 *   printf 'hi\n5\n'   | ./bin/13_oob_read     -> echoes 5 bytes (ok-ish)
 *   printf 'hi\n200\n' | ./bin/13_oob_read     -> echoes 200 bytes, leaking the
 *                                                 uninitialized tail of buf
 *   make asan && printf 'hi\n5000\n' | ./bin/13_oob_read_asan
 *     -> AddressSanitizer: (eventually) global/stack-buffer-overflow READ
 *
 * This is exactly CVE-2014-0160 (Heartbleed) in miniature: OpenSSL echoed a
 * client length field without checking it against the real payload size,
 * leaking up to 64 KB of server memory (private keys, other users' data).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void)
{
    char buf[256];
    /* Pre-fill with a recognizable "secret" so leaked bytes are visible. In a
     * real server this region would hold other clients' data / keys. */
    memset(buf, 0, sizeof buf);
    memcpy(buf + 64, "LEAKED_SECRET_REGION", 20);

    char line[64];
    /* "payload": first line is the message, second line is the claimed length */
    if (!fgets(buf, sizeof buf, stdin)) return 1;       /* message */
    size_t actual = strcspn(buf, "\n");                 /* real valid length */
    buf[actual] = '\0';

    if (!fgets(line, sizeof line, stdin)) return 1;      /* claimed length */
    unsigned long claimed = strtoul(line, NULL, 0);

    printf("you sent %zu valid bytes; echoing %lu bytes:\n", actual, claimed);

    /* THE BUG: we write `claimed` bytes to stdout from buf, but only `actual`
     * are valid. No check that claimed <= actual (or even <= sizeof buf). */
    fwrite(buf, 1, claimed, stdout);
    putchar('\n');
    return 0;
}

/* FIX: validate the length against what is actually valid, and clamp:
 *     if (claimed > actual) claimed = actual;           // never echo stale data
 *     if (claimed > sizeof buf) claimed = sizeof buf;    // never read past buf
 * The one missing comparison is the entire Heartbleed bug. */
