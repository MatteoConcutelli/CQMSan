//===-- cqmsan_dl.cpp -------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// Helper functions for unpoisoning results of dladdr and dladdr1.
//===----------------------------------------------------------------------===//

#include "cqmsan_dl.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>

#include "cqmsan_poisoning.h"

namespace __cqmsan {

void UnpoisonDllAddrInfo(void *info) {
  Dl_info *ptr = (Dl_info *)(info);
  __cqmsan_unpoison(ptr, sizeof(*ptr));
  if (ptr->dli_fname)
    __cqmsan_unpoison(ptr->dli_fname, __sanitizer::internal_strlen(ptr->dli_fname) + 1);
  if (ptr->dli_sname)
    __cqmsan_unpoison(ptr->dli_sname, __sanitizer::internal_strlen(ptr->dli_sname) + 1);
}

#if SANITIZER_GLIBC
void UnpoisonDllAddr1ExtraInfo(void **extra_info, int flags) {
  if (flags == RTLD_DL_SYMENT) {
    __cqmsan_unpoison(extra_info, sizeof(void *));

    ElfW(Sym) *s = *((ElfW(Sym) **)(extra_info));
    __cqmsan_unpoison(s, sizeof(ElfW(Sym)));
  } else if (flags == RTLD_DL_LINKMAP) {
    __cqmsan_unpoison(extra_info, sizeof(void *));

    struct link_map *map = *((struct link_map **)(extra_info));

    // Walk forward
    for (auto *ptr = map; ptr; ptr = ptr->l_next) {
      __cqmsan_unpoison(ptr, sizeof(struct link_map));
      if (ptr->l_name)
        __cqmsan_unpoison(ptr->l_name, __sanitizer::internal_strlen(ptr->l_name) + 1);
    }

    if (!map)
      return;

    // Walk backward
    for (auto *ptr = map->l_prev; ptr; ptr = ptr->l_prev) {
      __cqmsan_unpoison(ptr, sizeof(struct link_map));
      if (ptr->l_name)
        __cqmsan_unpoison(ptr->l_name, __sanitizer::internal_strlen(ptr->l_name) + 1);
    }
  }
}
#endif

}  // namespace __cqmsan
