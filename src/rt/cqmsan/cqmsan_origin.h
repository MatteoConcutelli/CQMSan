//===-- cqmsan_origin.h ----------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Origin id utils.
//===----------------------------------------------------------------------===//

#ifndef CQMSAN_ORIGIN_H
#define CQMSAN_ORIGIN_H

#include "../sanitizer_common/sanitizer_stackdepot.h"
#include "cqmsan_chained_origin_depot.h"

namespace __cqmsan {

// Origin handling.
//
// Origin is a 32-bit identifier that is attached to any uninitialized value in
// the program and describes, more or less exactly, how this memory came to be
// uninitialized.
//
// There are 3 kinds of origin ids:
// 1xxx xxxx xxxx xxxx   heap origin id
// 0000 xxxx xxxx xxxx   stack origin id
// 0zzz xxxx xxxx xxxx   chained origin id
//
// Heap origin id describes a heap memory allocation and contains (in the xxx
// part) a value of StackDepot.
//
// Stack origin id describes a stack memory allocation and contains (in the xxx
// part) an index into StackOriginDescr and StackOriginPC. We don't store a
// stack trace for such origins for performance reasons.
//
// Chained origin id describes an event of storing an uninitialized value to
// memory. The xxx part is a value of ChainedOriginDepot, which is a mapping of
// (stack_id, prev_id) -> id, where
//  * stack_id describes the event.
//    StackDepot keeps a mapping between those and corresponding stack traces.
//  * prev_id is another origin id that describes the earlier part of the
//    uninitialized value history.
// Following a chain of prev_id provides the full recorded history of an
// uninitialized value.
//
// This, effectively, defines a tree (or 2 trees, see below) where nodes are
// points in value history marked with origin ids, and edges are events that are
// marked with stack_id.
//
// The "zzz" bits of chained origin id are used to store the length (or depth)
// of the origin chain.

class Origin {
 public:
  static bool isValidId(__sanitizer::u32 id) { return id != 0 && id != (__sanitizer::u32)-1; }

  __sanitizer::u32 raw_id() const { return raw_id_; }
  bool isHeapOrigin() const {
    // 0xxx xxxx xxxx xxxx
    return raw_id_ >> kHeapShift == 0;
  }
  bool isStackOrigin() const {
    // 1000 xxxx xxxx xxxx
    return (raw_id_ >> kDepthShift) == (1 << kDepthBits);
  }
  bool isChainedOrigin() const {
    // 1zzz xxxx xxxx xxxx, zzz != 000
    return (raw_id_ >> kDepthShift) > (1 << kDepthBits);
  }
  __sanitizer::u32 getChainedId() const {
    CHECK(isChainedOrigin());
    return raw_id_ & kChainedIdMask;
  }
  __sanitizer::u32 getStackId() const {
    CHECK(isStackOrigin());
    return raw_id_ & kChainedIdMask;
  }
  __sanitizer::u32 getHeapId() const {
    CHECK(isHeapOrigin());
    return raw_id_ & kHeapIdMask;
  }

  // Returns the next origin in the chain and the current stack trace.
  Origin getNextChainedOrigin(__sanitizer::StackTrace*stack) const {
    CHECK(isChainedOrigin());
    __sanitizer::u32 prev_id;
    __sanitizer::u32 stack_id = ChainedOriginDepotGet(getChainedId(), &prev_id);
    if (stack) *stack = __sanitizer::StackDepotGet(stack_id);
    return Origin(prev_id);
  }

  __sanitizer::StackTrace getStackTraceForHeapOrigin() const {
    return __sanitizer::StackDepotGet(getHeapId());
  }

  static Origin CreateStackOrigin(__sanitizer::u32 id) {
    CHECK((id & kStackIdMask) == id);
    return Origin((1 << kHeapShift) | id);
  }

  static Origin CreateHeapOrigin(__sanitizer::StackTrace*stack) {
    __sanitizer::u32 stack_id = StackDepotPut(*stack);
    CHECK(stack_id);
    CHECK((stack_id & kHeapIdMask) == stack_id);
    return Origin(stack_id);
  }

  static Origin CreateChainedOrigin(Origin prev, __sanitizer::StackTrace*stack) {
    int depth = prev.isChainedOrigin() ? prev.depth() : 0;
    // depth is the length of the chain minus 1.
    // origin_history_size of 0 means unlimited depth.
    if (flags()->origin_history_size > 0) {
      if (depth + 1 >= flags()->origin_history_size) {
        return prev;
      } else {
        ++depth;
        CHECK(depth < (1 << kDepthBits));
      }
    }

    __sanitizer::StackDepotHandle h = __sanitizer::StackDepotPut_WithHandle(*stack);
    if (!h.valid()) return prev;

    if (flags()->origin_history_per_stack_limit > 0) {
      int use_count = h.use_count();
      if (use_count > flags()->origin_history_per_stack_limit) return prev;
    }

    __sanitizer::u32 chained_id;
    bool inserted = ChainedOriginDepotPut(h.id(), prev.raw_id(), &chained_id);
    CHECK((chained_id & kChainedIdMask) == chained_id);

    if (inserted && flags()->origin_history_per_stack_limit > 0)
      h.inc_use_count_unsafe();

    return Origin((1 << kHeapShift) | (depth << kDepthShift) | chained_id);
  }

  static Origin FromRawId(__sanitizer::u32 id) {
    return Origin(id);
  }

 private:
  static const int kDepthBits = 3;
  static const int kDepthShift = 32 - kDepthBits - 1;

  static const int kHeapShift = 31;
  static const __sanitizer::u32 kChainedIdMask = ((__sanitizer::u32)-1) >> (32 - kDepthShift);
  static const __sanitizer::u32 kStackIdMask = ((__sanitizer::u32)-1) >> (32 - kDepthShift);
  static const __sanitizer::u32 kHeapIdMask = ((__sanitizer::u32)-1) >> (32 - kHeapShift);

  __sanitizer::u32 raw_id_;

  explicit Origin(__sanitizer::u32 raw_id) : raw_id_(raw_id) {}

  int depth() const {
    CHECK(isChainedOrigin());
    return (raw_id_ >> kDepthShift) & ((1 << kDepthBits) - 1);
  }

 public:
  static const int kMaxDepth = (1 << kDepthBits) - 1;
};

}  // namespace __cqmsan

#endif  // CQMSAN_ORIGIN_H
