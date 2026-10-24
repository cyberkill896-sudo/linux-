/* notes.c  —  a realistic menu-driven "note manager" with heap bugs.
 *
 * This mirrors how real programs manage dynamic objects: an array of pointers to
 * heap-allocated records, each record carrying a CALLBACK (like a C++ vtable or
 * a plugin's handler) plus data. Menu-driven CRUD (create/read/update/delete) is
 * exactly the shape of countless real services and CTF "notebook" pwnables.
 *
 * It contains three classic, independent bugs:
 *   (A) USE-AFTER-FREE: delete_note() frees the record but does NOT clear the
 *       slot pointer, so view/edit after delete operate on freed memory. Because
 *       each record's first field is a FUNCTION POINTER, reclaiming the freed
 *       chunk with a new note lets an attacker control that pointer -> the
 *       view callback jumps to attacker-chosen code.
 *   (B) DOUBLE FREE: delete_note() can be called twice on the same slot.
 *   (C) HEAP OVERFLOW: edit_note() reads a caller-supplied length into the
 *       fixed-size data[] without bounding it to sizeof(data).
 *
 * BUILD (lab):   gcc -g -O0 -fno-stack-protector -no-pie notes.c -o notes
 * BUILD (ASan):  gcc -g -O0 -fsanitize=address notes.c -o notes_asan
 * BUILD (safe):  gcc -g -O0 -fno-stack-protector -no-pie -DSAFE notes.c -o notes_safe
 *
 * DRIVE IT: feed the menu on stdin, e.g.  printf '1\n...\n' | ./notes
 * (see commands.txt and WALKTHROUGH.md for exact scripts)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAX_NOTES 16
#define DATA_CAP  40            /* fixed data capacity per note */

/* Each note begins with a function pointer, like an object's vtable slot. */
struct note {
    void (*print)(struct note *self);   /* callback at OFFSET 0 of the chunk */
    size_t len;                          /* bytes of valid data              */
    char   data[DATA_CAP];               /* the note body                    */
};

static struct note *notes[MAX_NOTES];    /* global table of note pointers    */

/* the default, legitimate callback */
static void default_print(struct note *self)
{
    printf("note: %.*s\n", (int)self->len, self->data);
}

/* a "secret" function that should never run — the hijack target for bug (A) */
static void admin_shell(struct note *self)
{
    (void)self;
    puts("[admin_shell] note callback hijacked -> shell (lab only)");
    system("/bin/sh");
}

/* read a line, strip newline, return length */
static size_t read_line(char *buf, size_t cap)
{
    if (!fgets(buf, (int)cap, stdin)) { buf[0] = 0; return 0; }
    size_t n = strcspn(buf, "\n");
    buf[n] = 0;
    return n;
}

static int read_int(void)
{
    char line[32];
    read_line(line, sizeof line);
    return (int)strtol(line, NULL, 0);
}

/* ---- commands ------------------------------------------------------------ */

/* CREATE: allocate a record, install the default callback, copy data (bounded
 * here — add is NOT the buggy path). */
static void add_note(void)
{
    int i;
    for (i = 0; i < MAX_NOTES; i++) if (!notes[i]) break;
    if (i == MAX_NOTES) { puts("no free slots"); return; }

    struct note *n = malloc(sizeof *n);   /* 56 bytes -> chunk size 0x40 */
    if (!n) { puts("oom"); return; }
    n->print = default_print;             /* callback lives at chunk offset 0 */

    char tmp[256];
    printf("content: "); fflush(stdout);
    size_t got = read_line(tmp, sizeof tmp);
    if (got > DATA_CAP) got = DATA_CAP;   /* add() bounds correctly */
    memcpy(n->data, tmp, got);
    n->len = got;

    notes[i] = n;
    printf("created note %d at %p (print=%p)\n", i, (void*)n, (void*)n->print);
}

/* READ: invoke the note's callback. If the slot was deleted but not cleared,
 * this is a USE-AFTER-FREE indirect call (bug A's trigger). */
static void view_note(void)
{
    printf("index: "); fflush(stdout);
    int i = read_int();
    if (i < 0 || i >= MAX_NOTES || !notes[i]) { puts("bad index"); return; }
    notes[i]->print(notes[i]);            /* indirect call through heap memory */
}

/* UPDATE: overwrite the data of an existing note. */
static void edit_note(void)
{
    printf("index: "); fflush(stdout);
    int i = read_int();
    if (i < 0 || i >= MAX_NOTES || !notes[i]) { puts("bad index"); return; }

    printf("new length: "); fflush(stdout);
    int len = read_int();

    char tmp[256];
    printf("new content: "); fflush(stdout);
    read_line(tmp, sizeof tmp);

#ifdef SAFE
    if (len < 0 || (size_t)len > DATA_CAP) { puts("length too large"); return; }
    memcpy(notes[i]->data, tmp, (size_t)len);     /* bounded to the buffer */
    notes[i]->len = (size_t)len;
#else
    /* THE BUG (C): `len` is attacker-controlled and NOT checked against
     * DATA_CAP, so this memcpy overflows data[40] into the next heap chunk
     * (and, for len>56, into that chunk's note->print callback). */
    memcpy(notes[i]->data, tmp, (size_t)len);
    notes[i]->len = (size_t)len;
#endif
    puts("updated");
}

/* DELETE: free the record. */
static void delete_note(void)
{
    printf("index: "); fflush(stdout);
    int i = read_int();
    if (i < 0 || i >= MAX_NOTES || !notes[i]) { puts("bad index"); return; }

    free(notes[i]);
#ifdef SAFE
    notes[i] = NULL;              /* THE FIX for bugs (A) and (B): clear the slot */
#else
    /* THE BUG (A)+(B): the slot still points at freed memory. A later
     * view/edit is a use-after-free; a second delete is a double free. */
#endif
    puts("deleted");
}

static void list_notes(void)
{
    for (int i = 0; i < MAX_NOTES; i++)
        if (notes[i])
            printf("  [%d] %p len=%zu print=%p\n",
                   i, (void*)notes[i], notes[i]->len, (void*)notes[i]->print);
}

/* print the address of admin_shell so the walkthrough can build the payload
 * without ASLR math (it's -no-pie, so this is fixed anyway). */
static void banner(void)
{
    puts("== note manager ==");
    printf("(hint for the lab: admin_shell is at %p)\n", (void*)&admin_shell);
    puts("1 add  2 view  3 edit  4 delete  5 list  6 quit");
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    banner();
    for (;;) {
        printf("> "); fflush(stdout);
        switch (read_int()) {
        case 1: add_note();    break;
        case 2: view_note();   break;
        case 3: edit_note();   break;
        case 4: delete_note(); break;
        case 5: list_notes();  break;
        case 6: puts("bye");   return 0;
        default: puts("?");    break;
        }
    }
}
