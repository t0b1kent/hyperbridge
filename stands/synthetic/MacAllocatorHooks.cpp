// SPDX-License-Identifier: MIT
// Copyright (c) 2026 HyperBridge contributors
#include <FEXCore/Utils/AllocatorHooks.h>

#include <malloc/malloc.h>
#include <stdlib.h>
#include <unistd.h>

namespace FEXCore::Allocator {
void InitializeThread() {}

void* malloc(size_t size) {
  return ::malloc(size);
}
void* calloc(size_t n, size_t size) {
  return ::calloc(n, size);
}
void* memalign(size_t align, size_t s) {
  void* p = nullptr;
  if (align < sizeof(void*)) {
    align = sizeof(void*);
  }
  return ::posix_memalign(&p, align, s) == 0 ? p : nullptr;
}
void* valloc(size_t size) {
  return ::valloc(size);
}
int posix_memalign(void** r, size_t a, size_t s) {
  return ::posix_memalign(r, a, s);
}
void* realloc(void* ptr, size_t size) {
  return ::realloc(ptr, size);
}
void free(void* ptr) {
  ::free(ptr);
}
size_t malloc_usable_size(void* ptr) {
  return ::malloc_size(ptr);
}
void* aligned_alloc(size_t a, size_t s) {
  return memalign(a, s);
}
void aligned_free(void* ptr) {
  ::free(ptr);
}
} 
