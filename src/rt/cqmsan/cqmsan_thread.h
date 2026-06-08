//===-- msan_thread.h -------------------------------------------*- C++ -*-===//
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

#ifndef CQMSAN_THREAD_H
#define CQMSAN_THREAD_H

#include "cqmsan_allocator.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_posix.h"

using namespace __sanitizer;

namespace __cqmsan {

class CQMsanThread {
 public:
  static CQMsanThread *Create(thread_callback_t start_routine, void *arg);
  static void TSDDtor(void *tsd);
  void Destroy();

  void Init();  // Should be called from the thread itself.
  thread_return_t ThreadStart();

  __sanitizer::uptr stack_top();
  __sanitizer::uptr stack_bottom();
  __sanitizer::uptr tls_begin() { return tls_begin_; }
  __sanitizer::uptr tls_end() { return tls_end_; }
  bool IsMainThread() { return start_routine_ == nullptr; }

  bool AddrIsInStack(__sanitizer::uptr addr);

  bool InSignalHandler() { return in_signal_handler_; }
  void EnterSignalHandler() { in_signal_handler_++; }
  void LeaveSignalHandler() { in_signal_handler_--; }

  void StartSwitchFiber(__sanitizer::uptr bottom, __sanitizer::uptr size);
  void FinishSwitchFiber(__sanitizer::uptr *bottom_old, __sanitizer::uptr *size_old);

  CQMsanThreadLocalMallocStorage &malloc_storage() { return malloc_storage_; }

  int destructor_iterations_;
  __sanitizer_sigset_t starting_sigset_;

 private:
  // NOTE: There is no CQMsanThread constructor. It is allocated
  // via mmap() and *must* be valid in zero-initialized state.
  void SetThreadStackAndTls();
  void ClearShadowForThreadStackAndTLS();
  struct StackBounds {
    __sanitizer::uptr bottom;
    __sanitizer::uptr top;
  };
  StackBounds GetStackBounds() const;
  thread_callback_t start_routine_;
  void *arg_;

  bool stack_switching_;

  StackBounds stack_;
  StackBounds next_stack_;

  __sanitizer::uptr tls_begin_;
  __sanitizer::uptr tls_end_;

  unsigned in_signal_handler_;

  CQMsanThreadLocalMallocStorage malloc_storage_;
};

CQMsanThread *GetCurrentThread();
void SetCurrentThread(CQMsanThread *t);

} // namespace __cqmsan

#endif // CQMSAN_THREAD_H
