# Third-Party Notices

CQMSan incorporates and/or builds upon third-party software. This file documents the
origin and license of each component. The corresponding license texts apply to the
respective files; per-file headers (SPDX identifiers) are authoritative where present.

---

## 1. LLVM / compiler-rt — MemorySanitizer (incorporated)
- **What:** the CQMSan LLVM pass (`CompilerQEMUMemorySanitizer`) is derived from LLVM's
  `MemorySanitizer.cpp`; the runtime (`cqmsan-rt/`, incl. `sanitizer_common`, `interception`). Most runtime files carry the original
  `// Part of the LLVM Project … SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception`
  header (retained).
- **License:** Apache License 2.0 **WITH LLVM-exception** (see `LICENSE`).
- **Copyright:** the LLVM Project contributors.
- **Modifications:** the propagation logic of MemorySanitizer has been removed/altered to
  implement an opportunistic, check-at-load detector; files have been renamed/adapted
  (`msan`→`cqmsan`). Modified files are marked where applicable.

## 2. AFL++ / AFL-QMSan (incorporated — patched core files)
- **What:** this repository vendors a small set of **patched** AFL core files (under the
  base fuzzer image): `include/afl-fuzz.h`, `src/afl-fuzz-run.c`, `src/afl-common.c`,
  `instrumentation/afl-llvm-common.cc`, `instrumentation/afl-gcc-common.h`,
  `utils/aflpp_driver/aflpp_driver.c`. See `PATCH_AFL_cqmsan.md` for the rationale.
- **Upstream:** AFL++ (https://github.com/AFLplusplus/AFLplusplus), and the
  **AFL-QMSan** fork (https://github.com/Heinzeen/AFL-QMSan).
- **License:** Apache License 2.0.
- **Copyright:** the AFL++ authors; original AFL by Michał Zalewski; AFL-QMSan by its authors.
- **Modifications:** the vendored files are **modified** from upstream (see
  `PATCH_AFL_cqmsan.md`). As required by Apache-2.0 §4, modifications are noted.
- **Note:** the full AFL-QMSan tree (including its **QEMU mode**) is **cloned at build time**
  by the Dockerfiles and is **not** redistributed in this repository.

## 3. QMSan (design basis — feedback logic)
- **What:** CQMSan's AFL bitmap feedback (error / pc-edge / callstack / callstack-edge) and
  its two-tier opportunistic+accurate scheme follow the design of **QMSan**
  (`msan-giovese`). The CQMSan implementation lives in its own (LLVM-derived) runtime.
- **Upstream:** https://github.com/Heinzeen/QMSan
- **Reference:** Marini et al., *“QMSan”*, NDSS 2025 *(verify exact authors/title/venue)*.
- **License:** QMSan is a **composite**: GNU GPL-2.0 (QEMU-related parts),
  Apache-2.0 (AFL++-related parts), BSD-2-Clause (`libqasan` and other non-QEMU files).
  The feedback logic referenced here corresponds to the **non-QEMU (BSD-2-Clause)** portion.
- **Note:** **no QEMU / no GPL-2.0 code from QMSan is redistributed** in this repository;
  QMSan is **cloned at build time** (as the accurate detector via `QMSAN_PATH`) when used.

## 4. Valgrind (runtime dependency — accurate detector)
- **What:** used as one option for the **accurate detector** (`valgrind
  --expensive-definedness-checks=yes`). Invoked at runtime; **not** redistributed here.
- **Upstream:** https://valgrind.org
- **License:** GNU GPL-2.0. (As an *invoked external tool*, not linked/redistributed, it
  does not impose GPL obligations on this repository.)

---

### Summary of redistribution
| Component | In this repo? | License of what's here |
|---|---|---|
| CQMSan pass + runtime (LLVM-derived) | **vendored** | Apache-2.0 WITH LLVM-exception |
| AFL core patches (6 files) | **vendored (modified)** | Apache-2.0 |
| AFL-QMSan full tree / QEMU mode | cloned at build | — (not redistributed) |
| QMSan (incl. QEMU/GPL parts) | cloned at build | — (not redistributed) |
| Valgrind | external tool, invoked | — (not redistributed) |

Because no QEMU/GPL-2.0 code is redistributed here, the repository as distributed is
under **Apache-2.0 WITH LLVM-exception** (`LICENSE`), with the vendored AFL files under the
compatible **Apache-2.0**. See `GUIDA_licenze_cqmsan.md` for the reasoning.

> This notice is provided in good faith and is **not legal advice**. Verify upstream
> author names, the QMSan citation, and your institution's policy before publishing.
