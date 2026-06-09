# Compile-level QMSan

CQMSan brings QMSan's _**opportunistic**_ UMR-detection strategy from the **binary level (QEMU)** down to the **compile level (LLVM)**. Instead of fully propagating shadow state like MemorySanitizer, it performs a cheap **check at each load** ("is the valude I just loaded coming from uninitialized memory?") and turns UMR events into **extra coverage feedback** for the fuzzer.

|       | Level | Model | Completeness |
|  ---  |  ---  |  ---  |      ---     |
|**[MemorySanitizer (MSan)][msan]** | compile | propagates shadow, checks at _sinks_ | precise (oracle) |
|**[QMSan][qmsan]**| binary (QEMU) | opportunistic, checks at loads | incomplete by design |
| **CQMSan** (this) | compile | opportunistic, checks at loads | inclomplete by design |

## How it works

- **LLVM pass** (`CompilerQEMUMemorySAnitizer`, LLVM 19): registered at the end of the optimization pipeline (`OptimizerLast`), faithfully replicating MSan's upstream sanitizer scheduling and post-instrumentation cleanup. For every load it inserts a shadow load and a check; loads that can be _statically proven initialized_ are elided.
- **Runtime** (`libcqmsan_rt`, derived from compiler-rt): on a UMR it writes UMR-derived signals into the AFL++ shared bitmap: _error site_, _pc-edge_, _callstack hash_, and _callstack-edge_. So the fuzzer is guided toward new uninitialized-use contexts, not just new code edges.
- **Two-tier detection** (as in QMSan): a fast **_opportunistic_** detector during fuzzing plus an **_accurate detector_** (Valgrind - a precise propagating oracle) to verify candidates and filter false positives.
- Designed to run under a **custom AFL++ (AFL-QMSan)** fork-server.

## Build & usage

Build the toolchain (LLVM 19 pass + runtime + instrumented targets):
```bash
# 1) base images (AFL++/AFL-QMSan, then the CQMSan pass + runtime)
docker build -t base-aflpp dockers/base-images/base-aflpp
docker build -t base-cqmsan dockers/base-images/base-cqmsan

# 2) an instrumented fuzz target
docker build -t <target>_cqmsan dockers/targets/<target>_cqmsan
```
Instrument your own target with the pass and link the runtime:

[TOOD] Case if you are testing a library with make etc..

```bash
clang -O1 -fno-ommit-frame-pointer \
      -fpass-plugin=<path>/libCompilerQEMUMemorySanitizer.so \
      your_target.c -o your_target \
      -L<path>/cqmsan-rt/build -l:libcqmsan_rt.a
```

Then fuzz with the AFL-QMSan fork-server (keep-going, no shadow propagation):
```bash
$AFL/afl-fuzz -m none -i ./in -o ./out -- ./your_target @@
```

## Configuration

Runtime (`CQMSAN_OPTIONS`, e.g. `symbolize=0`), and pass options ('cl:opt'):

| Option | Default | Meaning |
|  ----  | ------- | ------- |
|`cqmsan-fast-warning`         | `true` | bitmap-only warning handler for campaigns (skips symbolize/printf)| 
|`cqmsan-check-access-address` | `false` | also check the *pointer* shadow on load/store (MSan-upstream default)|
|`cqmsan-instrument-loads`     | `true` | when `false`, loads are left untouched - **upper-bound ablation** |
|`cqmsan-check-load`           | `true` | when `false`, load shadow but emit no check |
|`cqmsan-keep-going`           |   -    | continue after an error (default opportunistic mode) |

## Research context & findings [TODO]
CQMSan was built to ask: **does QMSan's opportunistic approach still pay off once moved to the compile level?**
The answer this project documents is:
- On C targets CQMSan _reaches parity_ with MSan, but **does not surpass it** - there is a structural **structural ceiling**.
- The reason: CQMSan's per-load check is a **side-effecting** operation (it reports), so the optimizer _cannot remove it_, even for dead loads. MSan's shadow is **side_effect-free SSA**, so dead/redundant shadow work is removed by **DCE/CSE** for free. At compile level MSan thus gets propagation *cheaply* and is also *more complete*.
- The opportunistic trade-off is worthwile **at the binary level** (QMSan, where full propagation under emulation is prohibitiveli expensive), but **not at the compile level**.

This makes CQMSan primarly a _**research artifact**_ that explains *why* the compile-level opportunistic design hits a ceiling - not a drop-in faster alternative to MSan.

## Repository layout

```
TODO
```

## Credits & licensing
- The pass and runtime are _derived from LLVM's MemorySanitizer / compiler-rt_; most files retain their `SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception` headers.
- A small set of _AFL++ / [AFL-QMSan][aflqmsan]_ core files is vendored _with modifications_ (Apache-2.0)
- The fuzzing-feedback design follows _[QMSan][qmsan]_ (Heinzeen) - **_Marini et al._, "QMSan", NDSS 2025**.
- **QMSan / AFL-QMSan / QEMU / Valgrind are NOT redistributed here** - they are cloned at build time, so no GPL-2.0 code is shipped in this repo.

**License** **Apache License 2.0 WITH LLVM-exception** - see [`LICENSE`](LICENSE).
Attribution and provenance of all third-party code: [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).

[aflqmsan]: https://github.com/Heinzeen/AFL-QMSan

## Citation

If you use CQMSan, please cite this:
```bibtex
[TODO]
```

[msan]: https://github.com/google/sanitizers/wiki/memorysanitizer
[qmsan]: https://github.com/Heinzeen/QMSan

