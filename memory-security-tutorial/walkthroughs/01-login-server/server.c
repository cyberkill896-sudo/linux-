/* server.c  —  a realistic length-prefixed protocol handler with a stack
 * buffer overflow in the LOGIN handler.
 *
 * This is written the way real network daemons are structured: a framing layer
 * that reads [type][length][payload] records off a stream, a dispatcher, and
 * per-command handlers that parse the payload into local structures. The bug is
 * the kind that ships in production: a handler trusts a length field and copies
 * a payload into a fixed stack buffer.
 *
 * It reads the protocol from STDIN so you can run it without a socket. To make
 * it a real TCP service in your lab:
 *     socat TCP-LISTEN:4000,reuseaddr,fork EXEC:./server
 *
 * WIRE FORMAT (all little-endian):
 *     u8  type        1=LOGIN, 2=ECHO, 3=QUIT
 *     u32 length      number of payload bytes that follow
 *     u8  payload[length]
 *
 * For LOGIN the payload is:  u32 name_len ; u8 name[name_len] ; u8 pin[4]
 *
 * BUILD (lab, insecure so the bug reproduces):
 *     gcc -g -O0 -fno-stack-protector -no-pie server.c -o server
 * BUILD (ASan, to see the overflow pinpointed):
 *     gcc -g -O0 -fsanitize=address server.c -o server_asan
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* ---- framing layer -------------------------------------------------------- */

enum { CMD_LOGIN = 1, CMD_ECHO = 2, CMD_QUIT = 3 };

/* read exactly n bytes from stdin (like recv() with a loop) */
static int read_exact(void *dst, size_t n)
{
    uint8_t *p = dst;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(STDIN_FILENO, p + got, n - got);
        if (r <= 0) return -1;          /* EOF or error */
        got += (size_t)r;
    }
    return 0;
}

/* read one u8 / u32 header field off the stream */
static int read_u8 (uint8_t  *v) { return read_exact(v, 1); }
static int read_u32(uint32_t *v) { return read_exact(v, 4); }

/* ---- a per-session structure, like a real server keeps per client --------- */

struct session {
    char     user[32];                  /* current logged-in user name */
    uint32_t uid;                       /* resolved user id            */
    int      authenticated;             /* 0/1                         */
};

/* resolve a pin to a uid (toy "database") */
static uint32_t lookup_uid(const uint8_t pin[4])
{
    /* pretend table: pin 0000 -> uid 1000, else 0 */
    if (pin[0]==0 && pin[1]==0 && pin[2]==0 && pin[3]==0) return 1000;
    return 0;
}

/* A hidden "win" target for the ret2win walkthrough (Chapter 2/12). Compile
 * with -DWITH_WIN to include it; it is never called on the normal path, so
 * reaching it proves control-flow hijack. */
#ifdef WITH_WIN
__attribute__((used))
static void win(void)
{
    puts("[win] handle_login's return address was hijacked -> shell (lab only)");
    system("/bin/sh");
}
#endif

/* ---- the vulnerable handler ---------------------------------------------- */
/*
 * handle_login() parses a LOGIN payload that has ALREADY been read into
 * `payload` (length `plen`). It copies the client-supplied name into a FIXED
 * 32-byte stack buffer using the client-supplied name_len. That is the bug: the
 * name can be longer than the buffer.
 */
static void handle_login(struct session *s, const uint8_t *payload, uint32_t plen)
{
    char     name[32];                  /* fixed stack buffer — the target     */
    uint8_t  pin[4];
    uint32_t name_len;

    if (plen < 4) { puts("LOGIN: short payload"); return; }

    /* first 4 bytes of the payload are the attacker-controlled name length */
    memcpy(&name_len, payload, 4);

#ifdef SAFE
    /* THE FIX: bound name_len to the destination AND to the available payload
     * before copying. Rebuild with -DSAFE to get server_safe. */
    if (name_len > sizeof(name) || (uint64_t)name_len + 4 > plen) {
        puts("LOGIN: bad name length");
        return;
    }
    memcpy(name, payload + 4, name_len);
#else
    /* THE BUG: we copy name_len bytes into name[32] with no check that
     * name_len <= sizeof(name). A LOGIN with name_len = 200 overflows `name`,
     * runs through `pin`, `name_len`, the saved RBP, and into handle_login()'s
     * RETURN ADDRESS. See WALKTHROUGH.md for the exact byte map. */
    memcpy(name, payload + 4, name_len);
#endif

    /* the pin follows the name in the payload */
    memcpy(pin, payload + 4 + name_len, 4);

    s->uid = lookup_uid(pin);
    s->authenticated = (s->uid != 0);
    snprintf(s->user, sizeof s->user, "%s", name);

    printf("LOGIN: user='%s' uid=%u auth=%d\n", s->user, s->uid, s->authenticated);
}

/* a benign handler, for contrast */
static void handle_echo(const uint8_t *payload, uint32_t plen)
{
    fwrite("ECHO: ", 1, 6, stdout);
    fwrite(payload, 1, plen, stdout);
    putchar('\n');
}

/* ---- the dispatch loop (the "server") ------------------------------------- */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    struct session s;
    memset(&s, 0, sizeof s);

    puts("protocol server ready");

    for (;;) {
        uint8_t  type;
        uint32_t length;

        if (read_u8(&type) < 0)   break;        /* connection closed */
        if (read_u32(&length) < 0) break;

        /* read the payload. A real server caps this; note the cap here is
         * larger than `name` (32), which is what lets LOGIN overflow. */
        if (length > 4096) { puts("payload too large"); break; }
        uint8_t *payload = malloc(length ? length : 1);
        if (read_exact(payload, length) < 0) { free(payload); break; }

        switch (type) {
        case CMD_LOGIN: handle_login(&s, payload, length); break;
        case CMD_ECHO:  handle_echo(payload, length);      break;
        case CMD_QUIT:  free(payload); puts("bye"); return 0;
        default:        printf("unknown command %u\n", type); break;
        }
        free(payload);
    }
    return 0;
}

/* THE FIX (see server_safe.c): validate name_len against the destination size
 * BEFORE copying, and validate that name_len + 4 fits within plen:
 *
 *     if (name_len > sizeof(name) || (uint64_t)name_len + 4 > plen) {
 *         puts("LOGIN: bad name length"); return;
 *     }
 *     memcpy(name, payload + 4, name_len);
 */
