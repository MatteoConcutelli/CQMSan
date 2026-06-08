//===-- cqmsan_shadow_constants.h ---------------------*- C++ -*-===//
//
// Defines the shadow value semantics for CQMSAN.
// Single source of truth so the convention can be flipped in one place.
//
//===----------------------------------------------------------------===//
#ifndef CQMSAN_SHADOW_CONSTANTS_H
#define CQMSAN_SHADOW_CONSTANTS_H

#include "../sanitizer_common/sanitizer_internal_defs.h"

namespace __cqmsan {
    constexpr __sanitizer::u8 kShadowCleanByte  = 0x00;
    constexpr __sanitizer::u8 kShadowPoisonByte = 0xFF;

    // Multi-byte forms per type-generic compares.
    constexpr __sanitizer::uptr kShadowCleanInt  =
        (__sanitizer::uptr)(kShadowCleanByte == 0x00 ? 0 : ~__sanitizer::uptr(0));
    constexpr __sanitizer::uptr kShadowPoisonInt =
        (__sanitizer::uptr)(kShadowPoisonByte == 0x00 ? 0 : ~__sanitizer::uptr(0));

}  // namespace __cqmsan

#endif  // CQMSAN_SHADOW_CONSTANTS_H