# Chapter 10 — C++-Specific Memory Bugs

> C++ adds abstractions — objects, virtual dispatch, templates, RAII — that both
> *prevent* some bugs and *create* new ones. The star is **type confusion**, and
> the recurring exploitation target is the **vtable pointer**.

---

## 10.1 How virtual dispatch works (so vtable hijacking makes sense)

A polymorphic C++ object begins with a hidden **vptr** — a pointer to its class's
**vtable** (array of virtual-function pointers):

```
   object in memory
   +------------------+        vtable (in .rodata, read-only)
   | vptr  -----------+------> [ &Base::foo ][ &Base::bar ][ ... ]
   +------------------+
   | member fields... |
   +------------------+
```

A virtual call `obj->foo()` compiles to roughly:

```asm
  mov    rax, [obj]        ; rax = vptr (first 8 bytes of the object)
  mov    rax, [rax + 0]    ; rax = vtable[0] = &foo
  mov    rdi, obj          ; `this` pointer -> rdi
  call   rax               ; indirect call through the vtable
```

**The critical fact:** the vptr is the **first field** of the object and lives in
**writable** memory (the object), while the vtable itself is read-only. So if any
bug lets you overwrite the object's first 8 bytes (a heap overflow into the next
object, a UAF reclaim, a bad write), you control the vptr → you point it at a
**fake vtable** full of attacker addresses → the next virtual call jumps there.
This is **vtable hijacking**, the C++ analogue of return-address/function-pointer
overwrite.

---

## 10.2 Test case 1 — vtable hijack via UAF

```cpp
// c01_vtable_uaf.cpp
#include <cstdio>
#include <cstdlib>
#include <cstring>
struct Base { virtual void run(){ puts("Base::run"); } };
void pwned(){ puts("vtable hijacked!"); }

int main(){
    Base *b = new Base();            // object with a vptr
    delete b;                        // freed; b dangles
    // reclaim the slot with attacker data: first 8 bytes = fake vptr
    unsigned long *fake = (unsigned long*)malloc(sizeof(Base));
    unsigned long fakevt[1] = { (unsigned long)pwned };
    fake[0] = (unsigned long)fakevt; // object.vptr -> fakevt
    b->run();                        // reads b->vptr (attacker) -> calls pwned()
}
```
```bash
g++ -g -O0 c01_vtable_uaf.cpp -o c01 && ./c01     # "vtable hijacked!"
g++ -g -O0 -fsanitize=address c01_vtable_uaf.cpp -o c01a && ./c01a   # UAF report
```

---

## 10.3 Test case 2 — type confusion via bad downcast

```cpp
// c02_typeconfusion.cpp
struct Animal { virtual void speak(){} };
struct Cat : Animal { int lives = 9;  void speak() override { } };
struct Dog : Animal { void (*bark)(); void speak() override { } };

void handle(Animal *a, bool isDog){
    if (isDog) {                      // caller LIES about the type
        Dog *d = static_cast<Dog*>(a);// unchecked downcast
        d->bark();                    // if `a` is really a Cat, reads Cat::lives
    }                                 // as a function pointer -> controlled call
}
```
**Type confusion** = treating memory of type A as type B. A `static_cast` does no
runtime check, so a `Cat` reinterpreted as a `Dog` reads `lives` (attacker-
settable) where `bark` should be → call through attacker data. This is the #1
**browser JS-engine** bug class (an object confused for a differently-shaped one).
**Fix:** `dynamic_cast` (returns null on mismatch), tagged types, `std::variant`.

---

## 10.4 Test case 3 — use-after-move

```cpp
// c03_uaf_move.cpp
#include <string>
#include <utility>
std::string s = "hello";
std::string t = std::move(s);     // s is now in a valid-but-unspecified state
printf("%zu\n", s.size());        // reading moved-from s: not UAF-crash, but a
s[0] = 'H';                       // logic/UB hazard; for custom types often a
                                  // dangling-pointer / double-free bug
```
After `std::move`, the source object's resources were transferred. For standard
types it's "valid but unspecified"; for **hand-written move constructors that
forget to null the source pointer**, the moved-from object still points at memory
the destination now owns → **double-free on destruction**. **Fix:** in move
ctors/assignment, always leave the source in a destructible null state; don't use
moved-from objects.

---

## 10.5 Test case 4 — `delete` vs `delete[]` mismatch

```cpp
// c04_delete_mismatch.cpp
int *a = new int[10];
delete a;             // WRONG: should be delete[] a; -> heap corruption / leak
char *p = new char;
delete[] p;           // WRONG: should be delete p;  -> corruption
```
`new[]` may store an element count just before the array; `delete` (scalar)
doesn't account for it and calls the wrong deallocation path → corruption or
missing destructor calls. **Fix:** match them exactly, or better, use
`std::vector`/`std::unique_ptr<T[]>` so you never call `delete` by hand.

---

## 10.6 Test case 5 — placement-new / manual lifetime mistakes

```cpp
// c05_placement.cpp
alignas(T) char storage[sizeof(T)];
T *p = new (storage) T();     // placement-new: construct in existing storage
// BUG 1: forgetting to call p->~T() explicitly -> resource leak / logic bug
// BUG 2: using `storage` as another type without destroying T first -> confusion
// BUG 3: letting `storage` go out of scope while p is still used -> UAF
```
Placement-new decouples allocation from construction; you must manually destroy
and must not alias the storage as another live type. Powerful but footgun-heavy.

---

## 10.7 Test case 6 — reference/iterator/pointer invalidation

```cpp
// c06_invalidation.cpp
std::vector<int> v{1,2,3};
int &r = v[0];
v.push_back(4);        // reallocation invalidates r
r = 10;                // UAF write

std::unordered_map<int,int> m;
auto &val = m[1];
m[2] = 2;              // rehash may invalidate `val`
val = 5;              // UAF

for (auto it=v.begin(); it!=v.end(); ++it)
    if (*it==2) v.erase(it);   // erase invalidates it -> ++it is UAF
```
Each container has precise invalidation rules; violating them is a UAF. **Fix:**
re-acquire references after mutation, use indices, or use the return value of
`erase`. (See also Chapter 6, test 9.)

---

## 10.8 Test case 7 — object slicing (not memory-unsafe, but a correctness trap)

```cpp
// c07_slicing.cpp
struct Base { int x; virtual void f(){} };
struct Derived : Base { int y; void f() override {} };
void take(Base b){ b.f(); }    // by VALUE: copies only the Base part ("slicing")
Derived d; take(d);            // d's Derived part is lost; b.f() calls Base::f
```
Passing a derived object **by value** to a base parameter slices off the derived
part (and resets the vptr to Base). Not a corruption bug, but a frequent logic bug
that can defeat security checks implemented in overrides. **Fix:** pass by
reference/pointer (`const Base&`).

---

## 10.9 Test case 8 — exceptions and leaks/partial construction

```cpp
// c08_exceptions.cpp
void f(){
    char *buf = new char[1024];
    may_throw();          // if it throws, buf leaks (no RAII to free it)
    delete[] buf;
}
```
An exception between raw `new` and `delete` leaks. Worse, a constructor that
throws after acquiring some resources can leave a half-constructed object. **Fix:**
RAII everywhere (`std::vector`, `unique_ptr`) so stack unwinding frees resources
automatically.

---

## 10.10 Impact
- **vtable hijack / type confusion → arbitrary code execution** (the dominant
  browser-exploit path).
- **Double-free / UAF** from move and delete-mismatch bugs → corruption.
- **Leaks** from exception-unsafe raw ownership.

---

## 10.11 The fixes (C++ discipline)
1. **RAII + smart pointers**: `unique_ptr` (sole owner), `shared_ptr`/`weak_ptr`
   (shared), `vector`/`string` over raw arrays. This removes most manual-lifetime
   bugs.
2. **`dynamic_cast` / `std::variant` / tagged unions** instead of unchecked
   `static_cast`/`reinterpret_cast` — kills type confusion.
3. **Rule of 0/3/5**: if you write one of destructor/copy/move, write (or
   `=delete`/`=default`) the others; leave moved-from objects null.
4. **`.at()`** (bounds-checked) and re-acquire iterators after mutation.
5. **Pass polymorphic objects by reference/pointer**, never by value.
6. **Build hardened:** `-fsanitize=address,undefined`, `-D_GLIBCXX_ASSERTIONS`
   (bounds-checks libstdc++), `-fsanitize=cfi` (Clang, catches vtable/type
   confusion at the call site), `-fstack-protector-strong`.
7. **Prefer Rust** for new memory-critical components.

---

## Recap
- C++ objects start with a **vptr** in writable memory → overwriting it (via
  UAF/overflow) is **vtable hijacking** → RCE.
- **Type confusion** (bad `static_cast`/reinterpret) treats memory as the wrong
  type → controlled calls; the top browser bug class.
- **Use-after-move, delete/delete[] mismatch, placement-new, iterator
  invalidation, slicing, exception leaks** are C++-specific lifetime traps.
- Fix with **RAII + smart pointers**, checked casts, rule of 0/3/5, CFI, and
  sanitizers.

Next: **[Chapter 11 — Race conditions → memory corruption »](11-races.md)**
