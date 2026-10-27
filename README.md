# CQMSan: a compiler-level opportunistic sanitizer

CQMSan detects **uses of uninitialised memory (UUM)** in programs under fuzzing. It is a compiler-level **opportunistic** detector: instead of propagating shadow state through every computation, as MemorySanitizer does, it checks the shadow **at every load**, reports what it finds to the fuzzer, and lets the program continue. Candidate violations are then confirmed by a binary-level **accurate detector** (Valgrind Memcheck), so no false alarm reaches the user and libraries that were not recompiled remain supported.

The design follows the two-tier, opportunistic approach that [QMSan][qmsan] introduced at the binary level, and realises it inside the compiler (LLVM 19).

|                                | Level         | Model                                              |
| ------------------------------ | ------------- | -------------------------------------------------- |
| [MemorySanitizer (MSan)][msan] | compiler      | propagates shadow, checks at sinks                 |
| [QMSan][qmsan]                 | binary (QEMU) | opportunistic, checks at loads + accurate detector |
| **CQMSan** (this repository)   | compiler      | opportunistic, checks at loads + accurate detector |

## How it works

- **Opportunistic detector, compiled in.** An LLVM pass (`CompilerQEMUMemorySanitizer`, LLVM 19), registered at the end of the optimisation pipeline. It keeps a byte-granular shadow of memory: a store marks its destination initialised, the allocator and the stack instrumentation mark new memory uninitialised, and every load checks the shadow of the bytes it reads. Computed values carry no shadow, so the cost is a fixed amount of work per memory access.
- **Run-time library** (`libcqmsan_rt`, derived from MSan's compiler-rt runtime). On a violation it records the site, and its calling context, in a violation map shared with AFL++, kept separate from the coverage map, and returns: the program keeps running. After each execution AFL++ reads that map, and only a violation it has not seen before triggers the accurate detector.
- **Accurate detector, on the binary.** The fuzzer re-runs an input under Valgrind Memcheck only when it exhibits a violation it has not seen before, and only once per violation. Memcheck runs on an uninstrumented build of the target, so it also sees libraries that were not recompiled; only violations it confirms are reported.
- **Fuzzer.** A patched [AFL-QMSan][aflqmsan] (AFL++ 4.10c) drives both detectors.

By checking at the load, CQMSan also reports a call through a function pointer that was never written, a position MSan does not check.

## Results

From the evaluation in the thesis: 24-hour campaigns, 5 trials, on the eight programs of Google's fuzzer test suite used by QMSan (c-ares, guetzli, json, libxml2, openssl, pcre2, re2, woff2), against MSan with the same compiler, flags, harness and fuzzer.

- **Detection:** at parity with MSan, with no false positive reaching the user.
- **Coverage:** essentially the same code explored, measured on a common uninstrumented binary; where the two differ, CQMSan reaches more edges.
- **Throughput:** that of MSan (geometric mean 0.98), while supporting libraries that were not recompiled.

## Repository layout

```
src/
  pass/      LLVM 19 pass plugin (CompilerQEMUMemorySanitizer.{h,cpp})
  rt/        run-time library: cqmsan/ (CQMSan runtime), sanitizer_common/, interception/
  aflpp/     patched files for AFL-QMSan (commit d252acf05b6a7414235897a809ae007a3ba24b54)
LICENSE
THIRD_PARTY_NOTICES.md
```

## Build

Requirements: LLVM/Clang 19, CMake, Valgrind, and ahec ckout of [AFL-QMSan][aflqmsan].

1. **Fuzzer.** Clone AFL-QMSan at commit `d252acf05b6a7414235897a809ae007a3ba24b54`, copy the files of `src/aflpp/` over it (same relative paths), and build:
   ```bash
   CFLAGS="-DQMSAN -DQMSAN_FILTERING -DQMSAN_CALLSTACK_EDGES -DQMSAN_CALLSTACK -DQMSAN_EDGES" make clean all
   ```
2. **Pass.** Build `src/pass/` as an out-of-tree LLVM 19 pass plugin; it produces `libCompilerQEMUMemorySanitizer.so`.
3. **Run-time library.** Build the sources of `src/rt/` (`cqmsan/`, `sanitizer_common/`, `interception/`) as a static library, `libcqmsan_rt.a`, with `-O3 -fPIC -fno-rtti -fno-exceptions`. Defining `CQMSAN_GLIBC_ALLOC` replaces the sanitizer allocator with a thin layer over glibc's.

## Usage

Compile the target with AFL++'s compiler wrapper, load the pass, and link the runtime:

```bash
export CC=$AFL/afl-clang-fast CXX=$AFL/afl-clang-fast++
export CFLAGS="-O1 -g -fPIE -pie -fno-omit-frame-pointer \
               -fpass-plugin=<path>/libCompilerQEMUMemorySanitizer.so"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-L<path-to-runtime>"
export LIBS="-l:libcqmsan_rt.a -lm -lpthread -ldl -lrt -lstdc++"
# then build the target as usual (./configure && make, cmake, ...)
```

Build the same target a second time **without** the pass and the runtime: this is the binary the accurate detector runs under Valgrind. Then fuzz:

```bash
export CQMSAN_OPTIONS="symbolize=0"
export AFL_CQMSAN_ACCURATE_TARGET=<path-to-uninstrumented-binary>
$AFL/afl-fuzz -m none -i ./in -o ./out -- ./target_cqmsan @@
```

Code that must not be instrumented, such as the harness's `main` and input handling, can be listed in a file named by `CQMSAN_IGNORELIST`, read by the pass at compile time (same syntax as a sanitizer ignorelist).

## Configuration

Run-time options are passed through `CQMSAN_OPTIONS` (for example `symbolize=0`). Pass options are LLVM `cl::opt`s, given with `-mllvm -<option>=<value>`. The main ones:

| Option | Default | Meaning |
| ------ | ------- | ------- |
| `cqmsan-keep-going` | `true` | continue after reporting a violation (the opportunistic mode) |
| `cqmsan-fast-warning` | `true` | report handler that only updates the fuzzer's map (no printing, no symbolisation); turn off for debugging |
| `cqmsan-unpoison-stores` | `true` | a store marks its destination initialised |
| `cqmsan-check-returns` | `true` | check in the callee that a returned scalar is initialised |
| `cqmsan-bb-coalesced-checks` | `true` | merge the checks of a basic block |
| `cqmsan-sink-checks` | `true` | move a load's check down to the first use that matters, fusing checks |
| `cqmsan-skip-afl-runtime-accesses` | `true` | do not instrument accesses to AFL++'s own state (coverage map, guards) |
| `cqmsan-check-access-address` | `false` | also check the shadow of the pointer used by a load or store |
| `cqmsan-poison-stack` | `true` | mark new stack variables uninitialised |
| `cqmsan-instrument-loads` / `-stores` | `true` | ablation switches: `false` leaves loads / stores uninstrumented |
| `cqmsan-check-loads` | `true` | ablation switch: `false` loads the shadow but emits no check |

The full list, with descriptions, is at the top of `src/pass/CompilerQEMUMemorySanitizer.cpp`.

## Credits and licensing

- The pass and the run-time library are **derived from LLVM's MemorySanitizer and compiler-rt**; most files keep their `SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception` headers.
- A small set of **AFL++ / [AFL-QMSan][aflqmsan]** files is included with modifications (Apache-2.0).
- The two-tier design and the fuzzer feedback follow **QMSan**: M. Marini, D. C. D'Elia, M. Payer, L. Querzoni, *"QMSan: Efficiently Detecting Uninitialized Memory Errors During Fuzzing"*, NDSS 2025.
- **QMSan, AFL-QMSan, QEMU and Valgrind are not redistributed here**: they are obtained separately, so no GPL-2.0 code is shipped in this repository.

**License:** Apache License 2.0 WITH LLVM-exception, see [`LICENSE`](LICENSE). Attribution and provenance of all third-party code: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

## Citation

CQMSan was developed for the master's thesis below (Sapienza University of Rome, MSc in Cybersecurity).

```bibtex
@mastersthesis{concutelli2026cqmsan,
  author = {Matteo Concutelli},
  title  = {Compatibility and Efficiency Trade-offs in Detecting {UUM} Bugs: A Compiler-assisted Approach},
  school = {Sapienza University of Rome},
  year   = {2026},
  note   = {Advisor: Prof. Daniele Cono D'Elia; co-advisor: Dr. Matteo Marini}
}
```

[msan]: https://clang.llvm.org/docs/MemorySanitizer.html
[qmsan]: https://github.com/Heinzeen/QMSan
[aflqmsan]: https://github.com/Heinzeen/AFL-QMSan
