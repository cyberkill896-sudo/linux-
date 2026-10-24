// 15_cpp_vtable.cpp  —  Chapter 10: C++ vtable hijack via use-after-free.
//
// A polymorphic C++ object begins with a hidden VPTR pointing at its class's
// vtable (array of virtual-function addresses). The vptr is the first 8 bytes
// of the object and lives in WRITABLE memory. Overwrite it (here via a UAF
// reclaim) and the next virtual call jumps through your FAKE vtable.
//
// RUN
//   ./bin/15_cpp_vtable            -> "vtable hijacked!"
//   make asan && ./bin/15_cpp_vtable_asan
//     -> AddressSanitizer: heap-use-after-free on the virtual call
//
// Build: g++ -g -O0 (Makefile). -O0 keeps the object layout obvious.

#include <cstdio>
#include <cstdlib>
#include <cstring>

struct Base {
    virtual void run() { puts("Base::run (legit)"); }
    char data[16];
};

void pwned() { puts("vtable hijacked! (attacker code)"); }

int main()
{
    Base *b = new Base();                 // object: [ vptr ][ data[16] ]
    printf("object at %p, vptr=%p\n", (void*)b, *(void**)b);
    b->run();                             // normal virtual dispatch

    delete b;                             // freed; b dangles (not nulled)

    // Reclaim the same-size slot and plant a FAKE vtable. The object's first 8
    // bytes (the vptr) must point at an array whose slot [0] is our function,
    // because run() is the first virtual method (vtable index 0).
    static unsigned long fake_vtable[1];
    fake_vtable[0] = (unsigned long)&pwned;

    unsigned long *reclaim = (unsigned long*)malloc(sizeof(Base));
    reclaim[0] = (unsigned long)fake_vtable;   // overwrite vptr with &fake_vtable

    // Use the dangling pointer. The compiler emits:
    //   mov rax,[b]        ; rax = vptr        (now = &fake_vtable)
    //   mov rax,[rax+0]    ; rax = vtable[0]   (now = &pwned)
    //   call rax           ; -> pwned()
    b->run();
    return 0;
}

// FIX: never use an object after delete. Use std::unique_ptr so ownership and
// lifetime are explicit (the raw pointer can't outlive the object by accident),
// and compile with -fsanitize=cfi (Clang) so a virtual call whose target isn't
// a valid method of the right type aborts. Rust removes the class entirely.
