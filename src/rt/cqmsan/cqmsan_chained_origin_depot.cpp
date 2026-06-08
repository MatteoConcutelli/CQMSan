//===-- cqmsan_chained_origin_depot.cpp -------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// A storage for chained origins.
//===----------------------------------------------------------------------===//

#include "cqmsan_chained_origin_depot.h"

#include "../sanitizer_common/sanitizer_chained_origin_depot.h"

namespace __cqmsan {

static __sanitizer::ChainedOriginDepot chainedOriginDepot;

__sanitizer::StackDepotStats ChainedOriginDepotGetStats() {
  return chainedOriginDepot.GetStats();
}

bool ChainedOriginDepotPut(__sanitizer::u32 here_id, __sanitizer::u32 prev_id, __sanitizer::u32 *new_id) {
  return chainedOriginDepot.Put(here_id, prev_id, new_id);
}

__sanitizer::u32 ChainedOriginDepotGet(__sanitizer::u32 id, __sanitizer::u32 *other) {
  return chainedOriginDepot.Get(id, other);
}

void ChainedOriginDepotBeforeFork() { chainedOriginDepot.LockBeforeFork(); }

void ChainedOriginDepotAfterFork(bool fork_child) {
  chainedOriginDepot.UnlockAfterFork(fork_child);
}

} // namespace __cqmsan
