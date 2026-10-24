/* 06_heap_fnptr.c  —  Chapter 4: heap overflow overwriting a FUNCTION POINTER.
 *
 * The heap analogue of a return-address overwrite: corrupt a code pointer stored
 * in a heap object, then watch the indirect call jump to attacker-chosen code.
 *
 * RUN
 *   ./bin/06_heap_fnptr normal                      -> "normal action"
 *   ./bin/06_heap_fnptr $(python3 -c '                \
 *       import sys,struct; sys.stdout.buffer.write(   \
 *       b"A"*16 + struct.pack("<Q", 0x<danger_addr>))')  -> "DANGER..."
 *
 *   Get danger()'s address first:
 *       objdump -d bin/06_heap_fnptr | grep '<danger>:'
 *   (Built -no-pie so the address is fixed.)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct widget {
    char name[16];                /* the overflowable buffer */
    void (*action)(void);         /* a code pointer, physically right after name */
};

void normal(void) { puts("normal action"); }
void danger(void) { puts("DANGER: hijacked heap function pointer!"); }

int main(int argc, char **argv)
{
    struct widget *w = malloc(sizeof *w);
    w->action = normal;           /* legitimate default */

    if (argc > 1)
        /* THE BUG: strcpy into name[16] with no bound. 16 bytes fill name; the
         * next 8 bytes overwrite w->action. The attacker supplies the raw
         * address of danger() (little-endian) as bytes 16..23. */
        strcpy(w->name, argv[1]);

    w->action();                  /* indirect call through the (maybe clobbered)
                                     pointer -> whatever action now points to */
    free(w);
    return 0;
}

/* FIX: bound the copy so it can never reach ->action:
 *     snprintf(w->name, sizeof w->name, "%s", argv[1]);
 * Defense in depth: put pointers BEFORE buffers in structs, and compile with
 * CFI (-fsanitize=cfi) so an indirect call to a non-function aborts. */
