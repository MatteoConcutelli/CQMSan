//===-- msan_report.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file is a part of MemorySanitizer. MSan-private header for error
/// reporting functions.
///
//===----------------------------------------------------------------------===//

#ifndef CQMSAN_REPORT_H
#define CQMSAN_REPORT_H

#include "../sanitizer_common/sanitizer_internal_defs.h"
#include "../sanitizer_common/sanitizer_stacktrace.h"

namespace __cqmsan {

void ReportUMR(__sanitizer::StackTrace*stack, __sanitizer::u32 origin);
void ReportExpectedUMRNotFound(__sanitizer::StackTrace*stack);
void ReportStats();
void ReportAtExitStatistics();
void DescribeMemoryRange(const void *x, __sanitizer::uptr size);
void ReportUMRInsideAddressRange(const char *function, const void *start,
                                 __sanitizer::uptr size, __sanitizer::uptr offset);

}  // namespace __cqmsan

#endif  // CQMSAN_REPORT_H
