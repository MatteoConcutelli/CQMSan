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
CQMSAN_FLAG(bool, poison_in_free, true, "")
CQMSAN_FLAG(bool, poison_in_dtor, false, "")
CQMSAN_FLAG(bool, report_umrs, true, "")
CQMSAN_FLAG(bool, wrap_signals, true, "")
CQMSAN_FLAG(bool, print_stats, false, "")
CQMSAN_FLAG(bool, halt_on_error, false, "")
CQMSAN_FLAG(bool, atexit, false, "")
CQMSAN_FLAG(int, store_context_size, 20,
          "Like malloc_context_size, but for uninit stores.")

// [skip_known_sites] Before doing any work for a fired UMR check (stack unwind, AFL map
// update, dirty sentinel), consult the AFL shared map: if the byte of this warning site
// already carries CQMSAN_AFL_ERROR, the site was reported earlier in this fuzzing session
// (afl-fuzz never clears msan_bits in FILTERING/EDGES mode) and afl-fuzz would not
// re-validate it anyway (check_msan_trace fires only on !ERROR(old) && ERROR(new)).
// Skipping it turns repeated firings of known sites (loops, FP floods) from ~2.5us
// (unwind) into a load+branch, and leaves the sentinel untouched so afl-fuzz skips
// the 64KB map scan on execs that only re-fire known sites. Policy note: it also drops
// PC_EDGE/CS/CS_EDGE novelties of an already-known PC ("same PC = same verdict").
// Standalone (no AFL shm): degenerates to a per-process dedup of the report path.
// cqmsan_report_count still counts every firing. Diagnostic handlers (__cqmsan_warning,
// noreturn, _noupdate) are not filtered.
CQMSAN_FLAG(bool, skip_known_sites, true,
          "Skip unwind+map update for UMR sites whose ERROR bit is already set in the AFL map.")
