//===-- cqmsan_flags.h --------------------------------------------*- C++ -*-===//
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
#ifndef CQMSAN_FLAGS_H
#define CQMSAN_FLAGS_H

namespace __cqmsan {

struct Flags {
#define CQMSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "cqmsan_flags.inc"
#undef CQMSAN_FLAG

  void SetDefaults();
};

Flags *flags();

}  // namespace __cqmsan

#endif  // CQMSAN_FLAGS_H
