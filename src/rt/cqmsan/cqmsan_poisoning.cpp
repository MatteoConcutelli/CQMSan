//===-- cqmsan_poisoning.cpp --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
//===----------------------------------------------------------------------===//

#include "cqmsan_poisoning.h"

#include "../interception/interception.h"
#include "cqmsan_origin.h"
#include "cqmsan_thread.h"
#include "../sanitizer_common/sanitizer_common.h"

#include "cqmsan_shadow_constants.h"


// DECLARE_REAL is a macro that defines a function prototype for the real
// implementation of a function, which is used to intercept calls to that
// function and redirect them to the real implementation.
DECLARE_REAL(void *, memset, void *dest, int c, SIZE_T n)
DECLARE_REAL(void *, memcpy, void *dest, const void *src, SIZE_T n)
DECLARE_REAL(void *, memmove, void *dest, const void *src, SIZE_T n)

namespace __cqmsan {

// Does this memory contain a poisoned byte?
// if yes return the origin
// returns 0 if all bytes are initialized
__sanitizer::u32 GetOriginIfPoisoned(__sanitizer::uptr addr, __sanitizer::uptr size) {
  unsigned char *s = (unsigned char *)MEM_TO_SHADOW(addr);
  for (__sanitizer::uptr i = 0; i < size; ++i)
    if (s[i]) return *(__sanitizer::u32 *)SHADOW_TO_ORIGIN(((__sanitizer::uptr)s + i) & ~3UL);
  return 0;
}


// for each byte not initialized in the source area,
// set the same origin in the corresponding destination byte.
void SetOriginIfPoisoned(__sanitizer::uptr addr, __sanitizer::uptr src_shadow, __sanitizer::uptr size,
                         __sanitizer::u32 src_origin) {
  __sanitizer::uptr dst_s = MEM_TO_SHADOW(addr);
  __sanitizer::uptr src_s = src_shadow;
  __sanitizer::uptr src_s_end = src_s + size;

  for (; src_s < src_s_end; ++dst_s, ++src_s)
    if (*(u8 *)src_s) *(__sanitizer::u32 *)SHADOW_TO_ORIGIN(dst_s & ~3UL) = src_origin;
}

// Copies origin metadata from src to dst, creating chained origin IDs as necessary.
void CopyOrigin(const void *dst, const void *src, __sanitizer::uptr size,
                __sanitizer::StackTrace *stack) {
  if (!MEM_IS_APP(dst) || !MEM_IS_APP(src)) return;

  __sanitizer::uptr d = (__sanitizer::uptr)dst;
  __sanitizer::uptr beg = d & ~3UL;
  // Copy left unaligned origin if that memory is poisoned.
  if (beg < d) {
    __sanitizer::u32 o = GetOriginIfPoisoned((__sanitizer::uptr)src, beg + 4 - d);
    if (o) {
      if (__cqmsan_get_track_origins() > 1) o = ChainOrigin(o, static_cast<__sanitizer::StackTrace*>(stack));
      *(__sanitizer::u32 *)MEM_TO_ORIGIN(beg) = o;
    }
    beg += 4;
  }

  __sanitizer::uptr end = (d + size) & ~3UL;
  // If both ends fall into the same 4-byte slot, we are done.
  if (end < beg) return;

  // Copy right unaligned origin if that memory is poisoned.
  if (end < d + size) {
    __sanitizer::u32 o = GetOriginIfPoisoned((__sanitizer::uptr)src + (end - d), (d + size) - end);
    if (o) {
      if (__cqmsan_get_track_origins() > 1) o = ChainOrigin(o, static_cast<__sanitizer::StackTrace*>(stack));
      *(__sanitizer::u32 *)MEM_TO_ORIGIN(end) = o;
    }
  }

  if (beg < end) {
    // Align src up.
    __sanitizer::uptr s = ((__sanitizer::uptr)src + 3) & ~3UL;
    // FIXME: factor out to cqmsan_copy_origin_aligned
    if (__cqmsan_get_track_origins() > 1) {
      __sanitizer::u32 *src = (__sanitizer::u32 *)MEM_TO_ORIGIN(s);
      __sanitizer::u32 *src_s = (__sanitizer::u32 *)MEM_TO_SHADOW(s);
      __sanitizer::u32 *src_end = (__sanitizer::u32 *)MEM_TO_ORIGIN(s + (end - beg));
      __sanitizer::u32 *dst = (__sanitizer::u32 *)MEM_TO_ORIGIN(beg);
      __sanitizer::u32 src_o = 0;
      __sanitizer::u32 dst_o = 0;
      for (; src < src_end; ++src, ++src_s, ++dst) {
        if (!*src_s) continue;
        if (*src != src_o) {
          src_o = *src;
          dst_o = ChainOrigin(src_o, static_cast<__sanitizer::StackTrace*>(stack));
        }
        *dst = dst_o;
      }
    } else {
      REAL(memcpy)((void *)MEM_TO_ORIGIN(beg), (void *)MEM_TO_ORIGIN(s),
                   end - beg);
    }
  }
}

void ReverseCopyOrigin(const void *dst, const void *src, __sanitizer::uptr size,
                       __sanitizer::StackTrace *stack) {
  if (!MEM_IS_APP(dst) || !MEM_IS_APP(src))
    return;

  __sanitizer::uptr d = (__sanitizer::uptr)dst;
  __sanitizer::uptr end = (d + size) & ~3UL;

  // Copy right unaligned origin if that memory is poisoned.
  if (end < d + size) {
    __sanitizer::u32 o = GetOriginIfPoisoned((__sanitizer::uptr)src + (end - d), (d + size) - end);
    if (o) {
      if (__cqmsan_get_track_origins() > 1)
        o = ChainOrigin(o, static_cast<__sanitizer::StackTrace*>(stack));
      *(__sanitizer::u32 *)MEM_TO_ORIGIN(end) = o;
    }
  }

  __sanitizer::uptr beg = d & ~3UL;

  if (beg + 4 < end) {
    // Align src up.
    __sanitizer::uptr s = ((__sanitizer::uptr)src + 3) & ~3UL;
    if (__cqmsan_get_track_origins() > 1) {
      __sanitizer::u32 *src = (__sanitizer::u32 *)MEM_TO_ORIGIN(s + end - beg - 4);
      __sanitizer::u32 *src_s = (__sanitizer::u32 *)MEM_TO_SHADOW(s + end - beg - 4);
      __sanitizer::u32 *src_begin = (__sanitizer::u32 *)MEM_TO_ORIGIN(s);
      __sanitizer::u32 *dst = (__sanitizer::u32 *)MEM_TO_ORIGIN(end - 4);
      __sanitizer::u32 src_o = 0;
      __sanitizer::u32 dst_o = 0;
      for (; src >= src_begin; --src, --src_s, --dst) {
        if (!*src_s) continue;
        if (*src != src_o) {
          src_o = *src;
          dst_o = ChainOrigin(src_o, static_cast<__sanitizer::StackTrace*>(stack));
        }
        *dst = dst_o;
      }
    } else {
      REAL(memmove)
      ((void *)MEM_TO_ORIGIN(beg), (void *)MEM_TO_ORIGIN(s), end - beg - 4);
    }
  }

  // Copy left unaligned origin if that memory is poisoned.
  if (beg < d) {
    __sanitizer::u32 o = GetOriginIfPoisoned((__sanitizer::uptr)src, beg + 4 - d);
    if (o) {
      if (__cqmsan_get_track_origins() > 1)
        o = ChainOrigin(o, static_cast<__sanitizer::StackTrace*>(stack));
      *(__sanitizer::u32 *)MEM_TO_ORIGIN(beg) = o;
    }
  }
}

void MoveOrigin(const void *dst, const void *src, __sanitizer::uptr size,
                __sanitizer::StackTrace *stack) {
  // If destination origin range overlaps with source origin range, move
  // origins by coping origins in a reverse order; otherwise, copy origins in
  // a normal order.
  __sanitizer::uptr src_aligned_beg = reinterpret_cast<__sanitizer::uptr>(src) & ~3UL;
  __sanitizer::uptr src_aligned_end = (reinterpret_cast<__sanitizer::uptr>(src) + size) & ~3UL;
  __sanitizer::uptr dst_aligned_beg = reinterpret_cast<__sanitizer::uptr>(dst) & ~3UL;
  if (dst_aligned_beg < src_aligned_end && dst_aligned_beg >= src_aligned_beg)
    return ReverseCopyOrigin(dst, src, size, stack);
  return CopyOrigin(dst, src, size, stack);
}

void MoveShadowAndOrigin(const void *dst, const void *src, __sanitizer::uptr size,
                         __sanitizer::StackTrace *stack) {
  if (!MEM_IS_APP(dst)) return;
  if (!MEM_IS_APP(src)) return;
  if (src == dst) return;
  // MoveOrigin transfers origins by refering to their shadows. So we
  // need to move origins before moving shadows.
  if (__cqmsan_get_track_origins())
    MoveOrigin(dst, src, size, stack);
  REAL(memmove)((void *)MEM_TO_SHADOW((__sanitizer::uptr)dst),
                (void *)MEM_TO_SHADOW((__sanitizer::uptr)src), size);
}

void CopyShadowAndOrigin(const void *dst, const void *src, __sanitizer::uptr size,
                         __sanitizer::StackTrace *stack) {
  if (!MEM_IS_APP(dst)) return;
  if (!MEM_IS_APP(src)) return;
  // Because origin's range is slightly larger than app range, memcpy may also
  // cause overlapped origin ranges.
  REAL(memcpy)((void *)MEM_TO_SHADOW((__sanitizer::uptr)dst),
               (void *)MEM_TO_SHADOW((__sanitizer::uptr)src), size);
  if (__cqmsan_get_track_origins())
    MoveOrigin(dst, src, size, stack);
}

void CopyMemory(void *dst, const void *src, __sanitizer::uptr size, __sanitizer::StackTrace *stack) {
  REAL(memcpy)(dst, src, size);
  CopyShadowAndOrigin(dst, src, size, stack);
}

// [DONE] 14/05
void SetShadow(const void *ptr, uptr size, u8 value) {
  uptr PageSize = GetPageSizeCached();
  uptr shadow_beg = MEM_TO_SHADOW(ptr);
  uptr shadow_end = shadow_beg + size;

  if (value || shadow_end - shadow_beg < common_flags()->clear_shadow_mmap_threshold) {
    REAL(memset)((void *)shadow_beg, value, shadow_end - shadow_beg);
  } else {
    // Optimize zeroing out shadow memory by unmapping whole pages.
    uptr page_beg = RoundUpTo(shadow_beg, PageSize);
    uptr page_end = RoundDownTo(shadow_end, PageSize);

    if (page_beg >= page_end) {
      REAL(memset)((void *)shadow_beg, 0, shadow_end - shadow_beg);
    } else {
      if (page_beg != shadow_beg)
        REAL(memset)((void *)shadow_beg, 0, page_beg - shadow_beg);
      if (page_end != shadow_end)
        REAL(memset)((void *)page_end, 0, shadow_end - page_end);
      if (!MmapFixedSuperNoReserve(page_beg, page_end - page_beg))
        Die();

      if (__cqmsan_get_track_origins()) {
        // No need to set origin for zero shadow, but we can release pages.
        uptr origin_beg = RoundUpTo(MEM_TO_ORIGIN(ptr), PageSize);
        if (!MmapFixedSuperNoReserve(origin_beg, page_end - page_beg))
          Die();
      }
    }
  }
}


void SetOrigin(const void *dst, __sanitizer::uptr size, __sanitizer::u32 origin) {

  // Origin mapping is 4 bytes per 4 bytes of application memory.
  // Here we extend the range such that its left and right bounds are both
  // 4 byte aligned.
  __sanitizer::uptr x = MEM_TO_ORIGIN((__sanitizer::uptr)dst);
  __sanitizer::uptr beg = x & ~3UL;               // align down.
  __sanitizer::uptr end = (x + size + 3) & ~3UL;  // align up.
  u64 origin64 = ((u64)origin << 32) | origin;
  // This is like memset, but the value is 32-bit. We unroll by 2 to write
  // 64 bits at once. May want to unroll further to get 128-bit stores.
  // (writes faster)

  if (beg & 7ULL) {
    *(__sanitizer::u32 *)beg = origin;
    beg += 4;
  }
  for (__sanitizer::uptr addr = beg; addr < (end & ~7UL); addr += 8) *(u64 *)addr = origin64;
  if (end & 7ULL) *(__sanitizer::u32 *)(end - 4) = origin;
  
}

// Marks memory as uninitialized, filling the shadow memory with 1s
void PoisonMemory(const void *dst, __sanitizer::uptr size, __sanitizer::StackTrace *stack) {
  SetShadow(dst, size, (u8)-1);

  if (__cqmsan_get_track_origins()) {
    CQMsanThread *t = GetCurrentThread();
    if (t && t->InSignalHandler())
      return;
    Origin o = Origin::CreateHeapOrigin(stack);
    SetOrigin(dst, size, o.raw_id());
  }
 
}

}  // namespace __cqmsan
