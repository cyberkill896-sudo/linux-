/* 17_race_uaf.c  —  Chapter 11: a data-race use-after-free.
 *
 * No single thread has a bug. The bug lives in the INTERLEAVING: one thread
 * checks a shared pointer and is about to use it; the other frees it in the gap
 * between the check and the use.
 *
 * BUILD: needs -pthread (Makefile handles it). Best observed under TSan:
 *   make tsan && ./bin/17_race_uaf_tsan
 *     -> ThreadSanitizer: data race ... with the free() and the strcpy() stacks
 *
 * Plain build may run fine many times then crash — that nondeterminism is
 * exactly why races are dangerous and hard to test for.
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct obj { char buf[32]; };
static struct obj *g;                       /* shared between threads */
static volatile int stop;

/* USER thread: checks g, then dereferences it. */
static void *user(void *_)
{
    (void)_;
    for (int i = 0; i < 2000000 && !stop; i++) {
        struct obj *local = g;              /* CHECK (read the pointer) */
        if (local)                          /* ...looks valid... */
            strcpy(local->buf, "work");     /* USE: but g may be freed by now */
    }
    return NULL;
}

/* KILLER thread: repeatedly frees and reallocates g. */
static void *killer(void *_)
{
    (void)_;
    for (int i = 0; i < 2000000 && !stop; i++) {
        free(g);                            /* frees the chunk `user` may be in */
        g = malloc(sizeof *g);              /* new chunk (may reuse the old one) */
    }
    return NULL;
}

int main(void)
{
    g = malloc(sizeof *g);
    pthread_t a, b;
    pthread_create(&a, NULL, user,   NULL);
    pthread_create(&b, NULL, killer, NULL);
    pthread_join(a, NULL);
    stop = 1;
    pthread_join(b, NULL);
    puts("done (run under TSan to see the race even if it didn't crash)");
    free(g);
    return 0;
}

/* FIX: protect the check-and-use as ONE critical section under a mutex, or use
 * an atomic refcount so the object can't be freed while referenced, or hand
 * ownership between threads by message passing (share nothing). Rust's
 * Send/Sync + borrow checker reject this at compile time. */
