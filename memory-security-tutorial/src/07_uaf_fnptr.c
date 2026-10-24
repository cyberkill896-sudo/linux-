/* 07_uaf_fnptr.c  —  Chapter 6: use-after-free function-pointer hijack.
 *
 * The four-step UAF "reclaim" pattern in one file:
 *   1) allocate a victim object that holds a function pointer
 *   2) free it (the pointer `o` now DANGLES — we deliberately don't NULL it)
 *   3) allocate a new same-size object filled with attacker bytes; the allocator
 *      hands back the SAME chunk (tcache LIFO), so our bytes land where `o` was
 *   4) call through the dangling pointer -> we invoke attacker-controlled bytes
 *
 * RUN
 *   ./bin/07_uaf_fnptr            -> "UAF: attacker-controlled call!"
 *   make asan && ./bin/07_uaf_fnptr_asan
 *     -> AddressSanitizer: heap-use-after-free, with allocation AND free traces
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct object {
    void (*run)(void);            /* first field = easiest to target */
    char  tag[24];
};

void legit(void) { puts("legit object ran"); }
void pwned(void) { puts("UAF: attacker-controlled call!"); }

int main(void)
{
    /* (1) allocate victim */
    struct object *o = malloc(sizeof *o);
    o->run = legit;
    printf("victim at %p, run=%p (legit)\n", (void*)o, (void*)o->run);

    /* (2) free it — `o` is now dangling. In real code this free and the use
     * below are far apart (different functions / threads / callbacks). */
    free(o);

    /* (3) reclaim the exact same chunk with attacker data. Same request size
     * => tcache returns the just-freed chunk. We write pwned's address into
     * offset 0, which is where `run` lives. */
    unsigned long *reclaim = malloc(sizeof *o);
    reclaim[0] = (unsigned long)&pwned;
    printf("reclaimed chunk at %p, planted run=%p (pwned)\n",
           (void*)reclaim, (void*)reclaim[0]);

    /* (4) use the dangling pointer */
    o->run();                     /* reads o->run (now = &pwned) and calls it */
    return 0;
}

/* FIX: `free(o); o = NULL;`  turns step (4) into an immediate, obvious NULL
 * deref instead of a silent hijack. Better: single ownership via smart pointers
 * (C++) or Rust's borrow checker so a freed object can't be referenced at all. */
