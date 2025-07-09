---
title: Arena Allocator Default to allocating from the back!
slug: arena-allocator--default-to-allocating-from-the-back
summary: Reserve the front of an Arena allocator for growing data structures.
created_at: 2025-07-07
updated_at: 2025-07-08
---

# Arena Allocator: Default to allocating from the back!


[The Arena Allocator](https://www.rfleury.com/p/untangling-lifetimes-the-arena-allocator)
is a simple, yet powerful, memory management technique. However, most
arena allocators leave untapped potential by only using one end. It
wasn't until recently that I discovered how you can intelligently make
use of **both ends** of an Arena.

Key insight: reserve the front for growing data structures (strings,
arrays) while allocating objects from the back. This prevents
intermediate allocations from fragmenting your growing data structures
at the front.

**Typical Arena implementation, without dual-ended arena allocations:**

```c
s = s8concat(arena, s, s8("Hello "));
// Arena: [Hello ░░░░░░░░░░░░░░░░░░░]

char *data = allocate_data(arena);  // Interrupts our string!
// Arena: [Hello [data]░░░░░░░░░░░░░]

s = s8concat(arena, s, s8("World"));
// Arena: [Hello [data]Hello World░░]
//                     ^Must copy "Hello"
```

**With dual-ended arena allocations:**

```c
s = s8concat(arena, s, s8("Hello "));
// Arena: [Hello ░░░░░░░░░░░░░░░░░░░]

char *data = allocate_data(arena);
// Arena: [Hello ░░░░░░░░░░░░░[data]]

s = s8concat(arena, s, s8("World")); // No relocation needed!
// Arena: [Hello World░░░░░░░░[data]]
```

Neat! No copies! We effectively get a string builder without having to
preallocate a block of memory up front and without any re-allocation
if we would exceed that block of memory. Instead the string will
naturally grow until Arena is exhausted. (Note that Depending on
situation this might be a bad thing)

## Pros:

- **Reduce fragmentation and reallocations**: Contiguous data structures remain unfragmented by intermediate allocations, eliminating expensive copying operations when extending existing buffers.
- **No explicit upper limit**: Data structures can grow naturally until arena exhaustion, avoiding the complexity of predicting and pre-allocating buffer sizes.

## Cons:

- **Implicit Single builder constraint**: The front of the arena can
  only be used by one growing data structure at a time. If multiple
  objects need to be built concurrently (e.g., building two strings
  simultaneously), the second allocation will trigger a copy of the
  first string to make room. This defeats the zero-copy optimization
  and reverts to standard arena behavior, though this scenario is
  uncommon in practice.
- **Implementation complexity**: Requires dual-ended Arena
  implementation, and dual-ended aware data structures.

## `s8concatv` Implementation

This implementation is heavily influenced by [Chris Wellons](https://nullprogram.com/)'s design.

```c
#define new(a, t, n)     ((t *)arena_alloc(a, sizeof(t), _Alignof(t), (n)))
#define newbeg(a, t, n)  ((t *)arena_alloc_beg(a, sizeof(t), _Alignof(t), (n)))
#define s8(s)            (S8){(U8 *)s, countof(s)-1}

typedef struct { U8 *data; Iz len; } S8;
typedef struct { U8 *beg; U8 *end; } Arena;

static U8 *arena_alloc(Arena *a, Iz objsize, Iz align, Iz count) {
  Iz padding = (Uz)a->end & (align - 1);
  tassert((count <= (a->end - a->beg - padding) / objsize) && "out of memory");
  Iz total = objsize * count;
  return memset(a->end -= total + padding, 0, total);
}

static U8 *arena_alloc_beg(Arena *a, Iz objsize, Iz align, Iz count) {
  Iz padding = -(Uz)(a->beg) & (align - 1);
  Iz total   = padding + objsize * count;
  tassert(total < (a->end - a->beg) && "out of memory");
  U8 *p = a->beg + padding;
  memset(p, 0, objsize * count);
  a->beg += total;
  return p;
}

```

```c
```

```c
static S8 s8concatv(Arena *a, S8 head, S8 *ss, Iz count) {
  S8 r = {0};

  // Check if head string is already at the front of arena
  if (!head.data || (U8 *)(head.data+head.len) != a->beg) {
    // Copy head to front of arena
    S8 copy = head;
    copy.data = newbeg(a, U8, head.len);
    if (head.len) memcpy(copy.data, head.data, head.len);
    head = copy;
  }

  // Append additional strings contiguously
  for (Iz i = 0; i < count; i++) {
    S8 tail = ss[i];
    U8 *data = newbeg(a, U8, tail.len);
    if (tail.len) memcpy(data, tail.data, tail.len);
    head.len += tail.len;
  }

  return head;
}
```

The magic of `s8concatv` happens in the first check: if the head
string is already positioned at the front of the arena (its end
matches `a->beg`), we can append directly without copying. This
creates a contiguous result regardless of how many concatenations we
perform. And if your Arena defaults to allocating from the back,
intermediate allocations won't interfere with future concatenations,
allowing them to continue growing in-place.

For convenience, we can also define a macro to accept variadic
arguments like in the example above.

```c
#define s8concat(arena, head, ...)                                                   \
  s8concatv(arena, head, ((S8[]){__VA_ARGS__}), (countof(((S8[]){__VA_ARGS__}))))

[...]

s = s8concat(arena, s8("Hello"), s8("World"));
// Arena: [Hello World░░░░░░░░░░░░░░░░░░░]
```
