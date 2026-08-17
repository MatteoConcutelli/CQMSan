//===-- cqmsan_flags.inc ------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// CQMSan runtime flags.
//
//===----------------------------------------------------------------------===//
#ifndef CQMSAN_FLAG
# error "Define CQMSAN_FLAG prior to including this file!"
#endif

// CQMSAN_FLAG(Type, Name, DefaultValue, Description)
// See COMMON_FLAG in sanitizer_flags.inc for more details.

CQMSAN_FLAG(int, exit_code, -1,
          "DEPRECATED. Use exitcode from common flags instead.")
CQMSAN_FLAG(int, origin_history_size, Origin::kMaxDepth, "")
CQMSAN_FLAG(int, origin_history_per_stack_limit, 20000, "")
CQMSAN_FLAG(bool, poison_heap_with_zeroes, false, "")
CQMSAN_FLAG(bool, poison_stack_with_zeroes, false, "")
CQMSAN_FLAG(bool, poison_in_malloc, true, "")
CQMSAN_FLAG(bool, poison_in_free, false, "")
CQMSAN_FLAG(bool, poison_in_dtor, false, "")
CQMSAN_FLAG(bool, report_umrs, true, "")
CQMSAN_FLAG(bool, wrap_signals, true, "")
CQMSAN_FLAG(bool, print_stats, false, "")
CQMSAN_FLAG(bool, halt_on_error, false, "")
CQMSAN_FLAG(bool, atexit, false, "")
CQMSAN_FLAG(int, store_context_size, 20,
          "Like malloc_context_size, but for uninit stores.")
