//===-- cqmsan_allocator.cpp -------------------------- ---------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// MemorySanitizer allocator.
//===----------------------------------------------------------------------===//

#include "cqmsan_allocator.h"

#include "cqmsan.h"
#include "cqmsan_interface_internal.h"
#include "cqmsan_origin.h"
#include "cqmsan_poisoning.h"
#include "cqmsan_thread.h"
#include "../sanitizer_common/sanitizer_allocator.h"
#include "../sanitizer_common/sanitizer_allocator_checks.h"
#include "../sanitizer_common/sanitizer_allocator_interface.h"
#include "../sanitizer_common/sanitizer_allocator_report.h"
#include "../sanitizer_common/sanitizer_errno.h"

#include "cqmsan_shadow_constants.h"

using namespace __cqmsan;

namespace {
struct Metadata {
  __sanitizer::uptr requested_size;
};

// Handles actions on memory mapping and unmapping, such as unpoisoning
// and releasing shadow/origin memory pages.
struct CQMsanMapUnmapCallback {
  // This callback is called when a new memory mapping is created.
  // no-op
  void OnMap(__sanitizer::uptr p, __sanitizer::uptr size) const {}
  // no-op 
  void OnMapSecondary(__sanitizer::uptr p, __sanitizer::uptr size, __sanitizer::uptr user_begin,
                      __sanitizer::uptr user_size) const {}
  void OnUnmap(__sanitizer::uptr p, __sanitizer::uptr size) const {
    __cqmsan_unpoison((void *)p, size);

    // We are about to unmap a chunk of user memory.
    // Mark the corresponding shadow memory as not needed.
    __sanitizer::uptr shadow_p = MEM_TO_SHADOW(p);
    ReleaseMemoryPagesToOS(shadow_p, shadow_p + size);
    if (__cqmsan_get_track_origins()) {
      __sanitizer::uptr origin_p = MEM_TO_ORIGIN(p);
      ReleaseMemoryPagesToOS(origin_p, origin_p + size);
    }
  }
};

// Note: to ensure that the allocator is compatible with the application memory
// layout (especially with high-entropy ASLR), kSpaceBeg and kSpaceSize must be
// duplicated as MappingDesc::ALLOCATOR in cqmsan.h.
#if defined(__mips64)
const __sanitizer::uptr kMaxAllowedMallocSize = 2UL << 30;

struct AP32 {
  static const __sanitizer::uptr kSpaceBeg = 0;
  static const u64 kSpaceSize = SANITIZER_MMAP_RANGE_SIZE;
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = __sanitizer::CompactSizeClassMap;
  static const __sanitizer::uptr kRegionSizeLog = 20;
  using AddressSpaceView = LocalAddressSpaceView;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
};
using PrimaryAllocator = SizeClassAllocator32<AP32>;
#elif defined(__x86_64__)
#if SANITIZER_NETBSD || SANITIZER_LINUX
const __sanitizer::uptr kAllocatorSpace = 0x700000000000ULL; // Linux case
#else
const __sanitizer::uptr kAllocatorSpace = 0x600000000000ULL;
#endif
const __sanitizer::uptr kMaxAllowedMallocSize = 1ULL << 40;

struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const __sanitizer::uptr kSpaceBeg = kAllocatorSpace;
  static const __sanitizer::uptr kSpaceSize = 0x40000000000;  // 4T.
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

using PrimaryAllocator = SizeClassAllocator64<AP64>;

#elif defined(__loongarch_lp64)
const __sanitizer::uptr kAllocatorSpace = 0x700000000000ULL;
const __sanitizer::uptr kMaxAllowedMallocSize = 8UL << 30;

struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const __sanitizer::uptr kSpaceBeg = kAllocatorSpace;
  static const __sanitizer::uptr kSpaceSize = 0x40000000000;  // 4T.
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

using PrimaryAllocator = SizeClassAllocator64<AP64>;

#elif defined(__powerpc64__)
const __sanitizer::uptr kMaxAllowedMallocSize = 2UL << 30;  // 2G

struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const __sanitizer::uptr kSpaceBeg = 0x300000000000;
  static const __sanitizer::uptr kSpaceSize = 0x020000000000;  // 2T.
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

using PrimaryAllocator = SizeClassAllocator64<AP64>;
#elif defined(__s390x__)
const __sanitizer::uptr kMaxAllowedMallocSize = 2UL << 30;  // 2G

struct AP64 {  // Allocator64 parameters. Deliberately using a short name.
  static const __sanitizer::uptr kSpaceBeg = 0x440000000000;
  static const __sanitizer::uptr kSpaceSize = 0x020000000000;  // 2T.
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};

using PrimaryAllocator = SizeClassAllocator64<AP64>;
#elif defined(__aarch64__)
const __sanitizer::uptr kMaxAllowedMallocSize = 8UL << 30;

struct AP64 {
  static const __sanitizer::uptr kSpaceBeg = 0xE00000000000ULL;
  static const __sanitizer::uptr kSpaceSize = 0x40000000000;  // 4T.
  static const __sanitizer::uptr kMetadataSize = sizeof(Metadata);
  using SizeClassMap = DefaultSizeClassMap;
  using MapUnmapCallback = CQMsanMapUnmapCallback;
  static const __sanitizer::uptr kFlags = 0;
  using AddressSpaceView = LocalAddressSpaceView;
};
using PrimaryAllocator = SizeClassAllocator64<AP64>;
#endif
using Allocator = CombinedAllocator<PrimaryAllocator>;
using AllocatorCache = Allocator::AllocatorCache;
}  // namespace __cqmsan

static Allocator allocator;
static AllocatorCache fallback_allocator_cache;
static StaticSpinMutex fallback_mutex;

static __sanitizer::uptr max_malloc_size;

void __cqmsan::CQMsanAllocatorInit() {
  SetAllocatorMayReturnNull(__sanitizer::common_flags()->allocator_may_return_null);
  allocator.Init(__sanitizer::common_flags()->allocator_release_to_os_interval_ms);
  if (__sanitizer::common_flags()->max_allocation_size_mb)
    max_malloc_size = Min(__sanitizer::common_flags()->max_allocation_size_mb << 20,
                          kMaxAllowedMallocSize);
  else
    max_malloc_size = kMaxAllowedMallocSize;
}

void __cqmsan::LockAllocator() { allocator.ForceLock(); }

void __cqmsan::UnlockAllocator() { allocator.ForceUnlock(); }

AllocatorCache *GetAllocatorCache(CQMsanThreadLocalMallocStorage *ms) {
  CHECK_LE(sizeof(AllocatorCache), sizeof(ms->allocator_cache));
  return reinterpret_cast<AllocatorCache *>(ms->allocator_cache);
}

void CQMsanThreadLocalMallocStorage::Init() {
  allocator.InitCache(GetAllocatorCache(this));
}

void CQMsanThreadLocalMallocStorage::CommitBack() {
  allocator.SwallowCache(GetAllocatorCache(this));
  allocator.DestroyCache(GetAllocatorCache(this));
}

static void *CQMsanAllocate(__sanitizer::BufferedStackTrace *stack, __sanitizer::uptr size, __sanitizer::uptr alignment,
                          bool zero) {
  if (UNLIKELY(size > max_malloc_size)) {
    if (AllocatorMayReturnNull()) {
      Report("WARNING: CompilerQEMUMemorySanitizer failed to allocate 0x%zx bytes\n", size);
      return nullptr;
    }
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportAllocationSizeTooBig(size, max_malloc_size, stack);
  }
  if (UNLIKELY(IsRssLimitExceeded())) {
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportRssLimitExceeded(stack);
  }
  CQMsanThread *t = GetCurrentThread();
  void *allocated;
  if (t) {
    // if we have a thread-local storage, use it.
    AllocatorCache *cache = GetAllocatorCache(&t->malloc_storage());
    allocated = allocator.Allocate(cache, size, alignment);
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocated = allocator.Allocate(cache, size, alignment);
  }

  if (UNLIKELY(!allocated)) {
    SetAllocatorOutOfMemory();
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportOutOfMemory(size, stack);
  }
  
  auto *meta = reinterpret_cast<Metadata *>(allocator.GetMetaData(allocated));
  meta->requested_size = size;
  if (zero) {
    if (allocator.FromPrimary(allocated))
      __cqmsan_clear_and_unpoison(allocated, size);
    else
      __cqmsan_unpoison(allocated, size);  // Mem is already unoed.
  } else if (flags()->poison_in_malloc) {
    __cqmsan_poison(allocated, size);
    if (__cqmsan_get_track_origins()) {
      stack->tag = __sanitizer::StackTrace::TAG_ALLOC;
      Origin o = Origin::CreateHeapOrigin(stack);
      __cqmsan_set_origin(allocated, size, o.raw_id());
    }
  }
  UnpoisonParam(2);
  RunMallocHooks(allocated, size);
  return allocated;
}

void __cqmsan::CQMsanDeallocate(__sanitizer::BufferedStackTrace *stack, void *p) {
  DCHECK(p);
  UnpoisonParam(1);
  RunFreeHooks(p);

  Metadata *meta = reinterpret_cast<Metadata *>(allocator.GetMetaData(p));
  __sanitizer::uptr size = meta->requested_size;
  meta->requested_size = 0;
  // This memory will not be reused by anyone else, so we are free to keep it
  // poisoned. The secondary allocator will unmap and unpoison by
  // CQMsanMapUnmapCallback, no need to poison it here.
  if (flags()->poison_in_free && allocator.FromPrimary(p)) {
    __cqmsan_poison(p, size);
    if (__cqmsan_get_track_origins()) {
      stack->tag = __sanitizer::StackTrace::TAG_DEALLOC;
      Origin o = Origin::CreateHeapOrigin(stack);
      __cqmsan_set_origin(p, size, o.raw_id());
    }
  }
  if (CQMsanThread *t = GetCurrentThread()) {
    AllocatorCache *cache = GetAllocatorCache(&t->malloc_storage());
    allocator.Deallocate(cache, p);
  } else {
    SpinMutexLock l(&fallback_mutex);
    AllocatorCache *cache = &fallback_allocator_cache;
    allocator.Deallocate(cache, p);
  }
}

static void *CQMsanReallocate(__sanitizer::BufferedStackTrace *stack, void *old_p,
                            __sanitizer::uptr new_size, __sanitizer::uptr alignment) {
  Metadata *meta = reinterpret_cast<Metadata*>(allocator.GetMetaData(old_p));
  __sanitizer::uptr old_size = meta->requested_size;
  __sanitizer::uptr actually_allocated_size = allocator.GetActuallyAllocatedSize(old_p);
  if (new_size <= actually_allocated_size) {
    // We are not reallocating here.
    meta->requested_size = new_size;
    if (new_size > old_size) {
      if (flags()->poison_in_malloc) {
        stack->tag = __sanitizer::StackTrace::TAG_ALLOC;
        PoisonMemory((char *)old_p + old_size, new_size - old_size, stack);
      }
    }
    return old_p;
  }
  __sanitizer::uptr memcpy_size = Min(new_size, old_size);
  void *new_p = CQMsanAllocate(stack, new_size, alignment, false);
  if (new_p) {
    CopyMemory(new_p, old_p, memcpy_size, stack);
    CQMsanDeallocate(stack, old_p);
  }
  return new_p;
}

static void *CQMsanCalloc(__sanitizer::BufferedStackTrace *stack, __sanitizer::uptr nmemb, __sanitizer::uptr size) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportCallocOverflow(nmemb, size, stack);
  }
  return CQMsanAllocate(stack, nmemb * size, sizeof(u64), true);
}

static const void *AllocationBegin(const void *p) {
  if (!p)
    return nullptr;
  void *beg = allocator.GetBlockBegin(p);
  if (!beg)
    return nullptr;
  auto *b = reinterpret_cast<Metadata *>(allocator.GetMetaData(beg));
  if (!b)
    return nullptr;
  if (b->requested_size == 0)
    return nullptr;

  return beg;
}

static __sanitizer::uptr AllocationSizeFast(const void *p) {
  return reinterpret_cast<Metadata *>(allocator.GetMetaData(p))->requested_size;
}

static __sanitizer::uptr AllocationSize(const void *p) {
  if (!p)
    return 0;
  if (allocator.GetBlockBegin(p) != p)
    return 0;
  return AllocationSizeFast(p);
}

void *__cqmsan::cqmsan_malloc(__sanitizer::uptr size, __sanitizer::BufferedStackTrace *stack) {
  return SetErrnoOnNull(CQMsanAllocate(stack, size, sizeof(u64), false));
}

void *__cqmsan::cqmsan_calloc(__sanitizer::uptr nmemb, __sanitizer::uptr size, __sanitizer::BufferedStackTrace *stack) {
  return SetErrnoOnNull(CQMsanCalloc(stack, nmemb, size));
}

void *__cqmsan::cqmsan_realloc(void *ptr, __sanitizer::uptr size, __sanitizer::BufferedStackTrace *stack) {
  if (!ptr)
    return SetErrnoOnNull(CQMsanAllocate(stack, size, sizeof(u64), false));
  if (size == 0) {
    CQMsanDeallocate(stack, ptr);
    return nullptr;
  }
  return SetErrnoOnNull(CQMsanReallocate(stack, ptr, size, sizeof(u64)));
}

void *__cqmsan::cqmsan_reallocarray(void *ptr, __sanitizer::uptr nmemb, __sanitizer::uptr size,
                                __sanitizer::BufferedStackTrace *stack) {
  if (UNLIKELY(CheckForCallocOverflow(size, nmemb))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportReallocArrayOverflow(nmemb, size, stack);
  }
  return cqmsan_realloc(ptr, nmemb * size, stack);
}

void *__cqmsan::cqmsan_valloc(__sanitizer::uptr size, __sanitizer::BufferedStackTrace *stack) {
  return SetErrnoOnNull(CQMsanAllocate(stack, size, GetPageSizeCached(), false));
}

void *__cqmsan::cqmsan_pvalloc(__sanitizer::uptr size, __sanitizer::BufferedStackTrace *stack) {
  __sanitizer::uptr PageSize = GetPageSizeCached();
  if (UNLIKELY(CheckForPvallocOverflow(size, PageSize))) {
    errno = errno_ENOMEM;
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportPvallocOverflow(size, stack);
  }
  // pvalloc(0) should allocate one page.
  size = size ? RoundUpTo(size, PageSize) : PageSize;
  return SetErrnoOnNull(CQMsanAllocate(stack, size, PageSize, false));
}

void *__cqmsan::cqmsan_aligned_alloc(__sanitizer::uptr alignment, __sanitizer::uptr size,
                                 __sanitizer::BufferedStackTrace *stack) {
  if (UNLIKELY(!CheckAlignedAllocAlignmentAndSize(alignment, size))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportInvalidAlignedAllocAlignment(size, alignment, stack);
  }
  return SetErrnoOnNull(CQMsanAllocate(stack, size, alignment, false));
}

void *__cqmsan::cqmsan_memalign(__sanitizer::uptr alignment, __sanitizer::uptr size,
                            __sanitizer::BufferedStackTrace *stack) {
  if (UNLIKELY(!IsPowerOfTwo(alignment))) {
    errno = errno_EINVAL;
    if (AllocatorMayReturnNull())
      return nullptr;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportInvalidAllocationAlignment(alignment, stack);
  }
  return SetErrnoOnNull(CQMsanAllocate(stack, size, alignment, false));
}

int __cqmsan::cqmsan_posix_memalign(void **memptr, __sanitizer::uptr alignment, __sanitizer::uptr size,
                                __sanitizer::BufferedStackTrace *stack) {
  if (UNLIKELY(!CheckPosixMemalignAlignment(alignment))) {
    if (AllocatorMayReturnNull())
      return errno_EINVAL;
    GET_FATAL_STACK_TRACE_IF_EMPTY(stack);
    ReportInvalidPosixMemalignAlignment(alignment, stack);
  }
  void *ptr = CQMsanAllocate(stack, size, alignment, false);
  if (UNLIKELY(!ptr))
    // OOM error is already taken care of by CQMsanAllocate.
    return errno_ENOMEM;
  CHECK(IsAligned((__sanitizer::uptr)ptr, alignment));
  *memptr = ptr;
  return 0;
}

extern "C" {
__sanitizer::uptr __sanitizer_get_current_allocated_bytes() {
  __sanitizer::uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatAllocated];
}

__sanitizer::uptr __sanitizer_get_heap_size() {
  __sanitizer::uptr stats[AllocatorStatCount];
  allocator.GetStats(stats);
  return stats[AllocatorStatMapped];
}

__sanitizer::uptr __sanitizer_get_free_bytes() { return 1; }

__sanitizer::uptr __sanitizer_get_unmapped_bytes() { return 1; }

__sanitizer::uptr __sanitizer_get_estimated_allocated_size(__sanitizer::uptr size) { return size; }

int __sanitizer_get_ownership(const void *p) { return AllocationSize(p) != 0; }

const void *__sanitizer_get_allocated_begin(const void *p) {
  return AllocationBegin(p);
}

__sanitizer::uptr __sanitizer_get_allocated_size(const void *p) { return AllocationSize(p); }

__sanitizer::uptr __sanitizer_get_allocated_size_fast(const void *p) {
  DCHECK_EQ(p, __sanitizer_get_allocated_begin(p));
  __sanitizer::uptr ret = AllocationSizeFast(p);
  DCHECK_EQ(ret, __sanitizer_get_allocated_size(p));
  return ret;
}

void __sanitizer_purge_allocator() { allocator.ForceReleaseToOS(); }
}
