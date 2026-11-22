#ifndef STADIA_ARM_PHASE103_STRING_H
#define STADIA_ARM_PHASE103_STRING_H
/* Freestanding C standard-library declaration, for compilation ONLY.
   A real firmware needs a separately verified C runtime implementation. */
#include <stddef.h>
void *memset(void *s, int value, size_t count);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);
#endif
