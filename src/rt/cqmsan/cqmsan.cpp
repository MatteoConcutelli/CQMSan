//===-- cqmsan.cpp ----------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of MemorySanitizer.
//
// MemorySanitizer runtime. [TODO]
//===----------------------------------------------------------------------===//

#include "cqmsan.h"

#include "cqmsan_chained_origin_depot.h"
#include "cqmsan_origin.h"
#include "cqmsan_poisoning.h"
#include "cqmsan_report.h"
#include "cqmsan_thread.h"
#include "../sanitizer_common/sanitizer_atomic.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_flag_parser.h"
#include "../sanitizer_common/sanitizer_flags.h"
#include "../sanitizer_common/sanitizer_interface_internal.h"
#include "../sanitizer_common/sanitizer_libc.h"
#include "../sanitizer_common/sanitizer_procmaps.h"
#include "../sanitizer_common/sanitizer_stackdepot.h"
#include "../sanitizer_common/sanitizer_stacktrace.h"
#include "../sanitizer_common/sanitizer_symbolizer.h"

#include <sys/shm.h>
#include <stdlib.h>
#include <stdio.h>

#include <link.h>

// [TODO] future work remove
#include "../ubsan/ubsan_flags.h"
#include "../ubsan/ubsan_init.h"

#include "cqmsan_shadow_constants.h"

// ACHTUNG! No system header includes in this file.

using namespace __sanitizer;

// Globals.
static THREADLOCAL int cqmsan_expect_umr = 0;
static THREADLOCAL int cqmsan_expected_umr_found = 0;

// Function argument shadow. Each argument starts at the next available 8-byte
// aligned address.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __cqmsan_param_tls[kCQMsanParamTlsSize / sizeof(u64)];


// Function argument origin. Each argument starts at the same offset as the
// corresponding shadow in (__cqmsan_param_tls). Slightly weird, but changing this
// would break compatibility with older prebuilt binaries.
SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL __sanitizer::u32 __cqmsan_param_origin_tls[kCQMsanParamTlsSize / sizeof(__sanitizer::u32)];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL u64 __cqmsan_retval_tls[kCQMsanRetvalTlsSize / sizeof(u64)];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL __sanitizer::u32 __cqmsan_retval_origin_tls;

alignas(16) SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL u64
    __cqmsan_va_arg_tls[kCQMsanParamTlsSize / sizeof(u64)];

alignas(16) SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL __sanitizer::u32
    __cqmsan_va_arg_origin_tls[kCQMsanParamTlsSize / sizeof(__sanitizer::u32)];

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL __sanitizer::uptr __cqmsan_va_arg_overflow_size_tls;

SANITIZER_INTERFACE_ATTRIBUTE
THREADLOCAL __sanitizer::u32 __cqmsan_origin_tls;

// [DONE] 13/05 - load_addr not used
// AFL bitmap feedback enrichment: XOR-fold of stack frames captured at UMR.
__sanitizer::uptr __cqmsan_callstack_hash;
__sanitizer::uptr load_addr;

extern "C" SANITIZER_WEAK_ATTRIBUTE const int __cqmsan_track_origins;
// This is a compile-time constant, so we can use it in the linker script.

#undef __cqmsan_get_track_origins
// [DONE] 13/05 - track_origins is not enabled for the opportunistic mode
int __cqmsan_get_track_origins() {
  return 0;
}
#define __cqmsan_get_track_origins() (0)

extern "C" SANITIZER_WEAK_ATTRIBUTE const int __cqmsan_keep_going;

namespace __cqmsan {

// ------------------------------------------------------------------------------

// [TODO] future work remove
__thread int __cqmsan_checks_disabled = 0;

// it checks it we are inside in a symbolizer or in a stack unwinder
static THREADLOCAL int is_in_symbolizer_or_unwinder;
static void EnterSymbolizerOrUnwider() { ++is_in_symbolizer_or_unwinder; }
static void ExitSymbolizerOrUnwider() { --is_in_symbolizer_or_unwinder; }
bool IsInSymbolizerOrUnwider() { return is_in_symbolizer_or_unwinder; }

struct UnwinderScope {
  UnwinderScope() { EnterSymbolizerOrUnwider(); }
  ~UnwinderScope() { ExitSymbolizerOrUnwider(); }
};

static Flags cqmsan_flags;

Flags *flags() { return &cqmsan_flags; }

int cqmsan_inited = 0;
bool cqmsan_init_is_running;

int cqmsan_report_count = 0;

// Array of stack origins.
// FIXME: make it resizable.
// Although BSS memory doesn't cost anything until used, it is limited to 2GB
// in some configurations (e.g., "relocation R_X86_64_PC32 out of range:
// ... is not in [-2147483648, 2147483647]; references section '.bss'").
// We use kNumStackOriginDescrs * (sizeof(char*) + sizeof(__sanitizer::uptr)) == 64MB.
#if SANITIZER_PPC
// soft_rss_limit test (release_origin.c) fails on PPC if kNumStackOriginDescrs
// is too high
static const __sanitizer::uptr kNumStackOriginDescrs = 1 * 1024 * 1024;
#else
static const __sanitizer::uptr kNumStackOriginDescrs = 4 * 1024 * 1024;
#endif  // SANITIZER_PPC
static const char *StackOriginDescr[kNumStackOriginDescrs];
static __sanitizer::uptr StackOriginPC[kNumStackOriginDescrs];
static atomic_uint32_t NumStackOriginDescrs;


void Flags::SetDefaults() {
#define CQMSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "cqmsan_flags.inc"
#undef CQMSAN_FLAG
}


// keep_going is an old name for halt_on_error,
// and it has inverse meaning.
class FlagHandlerKeepGoing final : public FlagHandlerBase {
  bool *halt_on_error_;

 public:
  explicit FlagHandlerKeepGoing(bool *halt_on_error)
      : halt_on_error_(halt_on_error) {}
  bool Parse(const char *value) final {
    bool tmp;
    FlagHandler<bool> h(&tmp);
    if (!h.Parse(value)) return false;
    *halt_on_error_ = !tmp;
    return true;
  }
  bool Format(char *buffer, __sanitizer::uptr size) final {
    const char *keep_going_str = (*halt_on_error_) ? "false" : "true";
    return FormatString(buffer, size, keep_going_str);
  }
};



static void RegisterCQMsanFlags(FlagParser *parser, Flags *f) {
#define CQMSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "cqmsan_flags.inc"
#undef CQMSAN_FLAG

  FlagHandlerKeepGoing *fh_keep_going = new (GetGlobalLowLevelAllocator())
      FlagHandlerKeepGoing(&f->halt_on_error);
  parser->RegisterHandler("keep_going", fh_keep_going,
                          "deprecated, use halt_on_error");
}

// [DONE] 13/05
static void InitializeFlags() {
  SetCommonFlagsDefaults();
  { // temporary scope for CommonFlags.
    CommonFlags cf;
    cf.CopyFrom(*__sanitizer::common_flags());
    cf.external_symbolizer_path = GetEnv("CQMSAN_SYMBOLIZER_PATH");
    //Printf("%s", cf.external_symbolizer_path);
    cf.malloc_context_size = 20;
    cf.handle_ioctl = true;
    // FIXME: test and enable.
    cf.check_printf = false;
    cf.intercept_tls_get_addr = true;
    cf.abort_on_error = true; // For AFL
    
    OverrideCommonFlags(cf); // write
  }

  Flags *f = flags();
  f->SetDefaults();

  FlagParser parser;
  RegisterCQMsanFlags(&parser, f);
  RegisterCommonFlags(&parser);

/* [TODO] future work remove
#if CQMSAN_CONTAINS_UBSAN
  __ubsan::Flags *uf = __ubsan::flags();
  uf->SetDefaults();

  FlagParser ubsan_parser;
  __ubsan::RegisterUbsanFlags(&ubsan_parser, uf);
  RegisterCommonFlags(&ubsan_parser);
#endif
*/

  // Override from user-specified string.
  parser.ParseString(__cqmsan_default_options());

/*
#if CQMSAN_CONTAINS_UBSAN
  const char *ubsan_default_options = __ubsan_default_options();
  ubsan_parser.ParseString(ubsan_default_options);
#endif
*/

  parser.ParseStringFromEnv("CQMSAN_OPTIONS");

/*
#if CQMSAN_CONTAINS_UBSAN
  ubsan_parser.ParseStringFromEnv("UBSAN_OPTIONS");
#endif
*/

  InitializeCommonFlags();

  if (Verbosity()) ReportUnrecognizedFlags();

  if (__sanitizer::common_flags()->help) parser.PrintFlagDescriptions();

  // Check if deprecated exit_code CQMSan flag is set.
  if (f->exit_code != -1) {
    if (Verbosity())
      Printf("CQMSAN_OPTIONS=exit_code is deprecated! "
             "Please use CQMSAN_OPTIONS=exitcode instead.\n");
    CommonFlags cf;
    cf.CopyFrom(*__sanitizer::common_flags());
    cf.exitcode = f->exit_code;
    OverrideCommonFlags(cf);

  }

  // Check flag values:
  if (f->origin_history_size < 0 ||
      f->origin_history_size > Origin::kMaxDepth) {
    Printf(
        "Origin history size invalid: %d. Must be 0 (unlimited) or in [1, %d] "
        "range.\n",
        f->origin_history_size, Origin::kMaxDepth);
    Die();
  }
   
  // Limiting to kStackDepotMaxUseCount / 2 to avoid overflow in
  // __sanitizer::StackDepotHandle::inc_use_count_unsafe.
  if (f->origin_history_per_stack_limit < 0 ||
      f->origin_history_per_stack_limit > kStackDepotMaxUseCount / 2) {
    Printf(
        "Origin per-stack limit invalid: %d. Must be 0 (unlimited) or in [1, "
        "%d] range.\n",
        f->origin_history_per_stack_limit, kStackDepotMaxUseCount / 2);
    Die();
  }
  if (f->store_context_size < 1) f->store_context_size = 1;
}

// [DONE] 13/05
void PrintWarningWithOrigin(__sanitizer::uptr pc, __sanitizer::uptr bp, __sanitizer::u32 origin) {
  if (cqmsan_expect_umr) {
    __cqmsan_origin_tls = origin;
    cqmsan_expected_umr_found = 1;
    return;
  }

  // Dedup for-pc: if we have already reported an UMR at this pc, skip the rest of the reporting chain.
  // (stack unwind + cqmsan_update_map + ReportUMR).
  // AFL already registered the edge at the first UMR, in case this is a no-op in the common case of repeated UMRs at the same pc.
  //if (!MarkUMRSeen(pc)) return;

  ++cqmsan_report_count;

  GET_FATAL_STACK_TRACE_PC_BP(pc, bp);
  cqmsan_update_map(&stack);

  __sanitizer::u32 report_origin =
    (0 && Origin::isValidId(origin)) ? origin : 0;
  ReportUMR(&stack, report_origin);

  if (0 && !Origin::isValidId(origin)) {
    Printf(
        "  ORIGIN: invalid (%x). Might be a bug in CompilerQEMUMemorySanitizer origin "
        "tracking.\n    This could still be a bug in your code, too!\n",
        origin);
  }
  
}

// [DONE] 13/05
void UnpoisonParam(__sanitizer::uptr n) {
  internal_memset(__cqmsan_param_tls, 0, n * sizeof(*__cqmsan_param_tls));
}

// [DONE] 13/05
// Backup CQMSan runtime TLS state.
// Implementation must be async-signal-safe.
// Instances of this class may live on the signal handler stack, and data size
// may be an issue.
void ScopedThreadLocalStateBackup::Backup() {
  va_arg_overflow_size_tls = __cqmsan_va_arg_overflow_size_tls;
}

// [DONE] 13/05
void ScopedThreadLocalStateBackup::Restore() {
  // A lame implementation that only keeps essential state and resets the rest.
  __cqmsan_va_arg_overflow_size_tls = va_arg_overflow_size_tls;

  internal_memset(__cqmsan_param_tls, 0, sizeof(__cqmsan_param_tls));
  internal_memset(__cqmsan_retval_tls, 0, sizeof(__cqmsan_retval_tls));
  internal_memset(__cqmsan_va_arg_tls, 0, sizeof(__cqmsan_va_arg_tls));
  internal_memset(__cqmsan_va_arg_origin_tls, 0,
                  sizeof(__cqmsan_va_arg_origin_tls));

  if (__cqmsan_get_track_origins()) {
    internal_memset(&__cqmsan_retval_origin_tls, 0,
                    sizeof(__cqmsan_retval_origin_tls));
    internal_memset(__cqmsan_param_origin_tls, 0,
                    sizeof(__cqmsan_param_origin_tls));
  }
}

void UnpoisonThreadLocalState() {
}

const char *GetStackOriginDescr(__sanitizer::u32 id, __sanitizer::uptr *pc) {
  CHECK_LT(id, kNumStackOriginDescrs);
  if (pc) *pc = StackOriginPC[id];
  return StackOriginDescr[id];
}

__sanitizer::u32 ChainOrigin(__sanitizer::u32 id, __sanitizer::StackTrace *stack) {
  CQMsanThread *t = GetCurrentThread();
  if (t && t->InSignalHandler())
    return id;

  Origin o = Origin::FromRawId(id);
  stack->tag = __sanitizer::StackTrace::TAG_UNKNOWN;
  Origin chained = Origin::CreateChainedOrigin(o, stack);
  return chained.raw_id();
}

// Current implementation separates the 'id_ptr' from the 'descr' and makes
// 'descr' constant.
// Previous implementation 'descr' is created at compile time and contains
// '----' in the beginning.  When we see descr for the first time we replace
// '----' with a uniq id and set the origin to (id | (31-th bit)).
static inline void SetAllocaOrigin(void *a, __sanitizer::uptr size, __sanitizer::u32 *id_ptr, char *descr,
                                   __sanitizer::uptr pc) {
  static const __sanitizer::u32 dash = '-';
  static const __sanitizer::u32 first_timer =
      dash + (dash << 8) + (dash << 16) + (dash << 24);
  __sanitizer::u32 id = *id_ptr;
  if (id == 0 || id == first_timer) {
    __sanitizer::u32 idx = atomic_fetch_add(&NumStackOriginDescrs, 1, memory_order_relaxed);
    CHECK_LT(idx, kNumStackOriginDescrs);
    StackOriginDescr[idx] = descr;
    StackOriginPC[idx] = pc;
    id = Origin::CreateStackOrigin(idx).raw_id();
    *id_ptr = id;
  }
  __cqmsan_set_origin(a, size, id);
}

#define MAP_SIZE_POW2 16
#define MAP_SIZE (1U << MAP_SIZE_POW2)
//#define MAP_SIZE 256 // for testing

static u8 dummy[MAP_SIZE]; /* costs MAP_SIZE but saves a few instructions */
u8* cqmsan_area_ptr = dummy;

// for debugging
void null_function() {}

// [DONE] 14/05 maintained the AFL-CQMSan shared memory attachment logic
void cqmsan_attach_afl_shm() {
  //Printf("CQMSAN: attaching to AFL shared memory\n");

  // Opt-in: when set, any failure to attach the AFL shared memory is fatal.
  // Use this in fuzzing campaigns so a misconfigured fork server cannot
  // silently run with coverage feedback disabled. Leave unset for standalone
  // crash reproduction (where running without AFL shm is legitimate).
  const bool require_shm = getenv("CQMSAN_REQUIRE_AFL_SHM") != nullptr;

  char *id_str = getenv("__MSAN_AFL_SHM_ID");

  if (!id_str) {
    // No AFL shared memory id. This is normal for a standalone/repro run, but
    // during a fuzzing campaign it means AFL receives ZERO UMR feedback while
    // the run still looks successful. Make it impossible to miss.
    Printf("==CQMSAN== WARNING: __MSAN_AFL_SHM_ID not set: running WITHOUT AFL "
           "coverage feedback (standalone mode). UMR signals are discarded.\n");
    if (require_shm) {
      Printf("==CQMSAN== FATAL: CQMSAN_REQUIRE_AFL_SHM set but no shm id.\n");
      Die();
    }
    return;
  }

  int msid = atoi(id_str);
  if (msid <= 0) {
    // id_str is present but malformed: almost always a real misconfiguration.
    Printf("==CQMSAN== ERROR: __MSAN_AFL_SHM_ID=\"%s\" is invalid (msid=%d): "
           "AFL coverage feedback DISABLED.\n", id_str, msid);
    if (require_shm) Die();
    return;
  }

  void *p = shmat(msid, NULL, 0);
  if (p == (void *)-1) {
    perror("cqmsan: shmat __MSAN_AFL_SHM_ID");
    Die();
  }

  cqmsan_area_ptr = (u8*)p;
  //null_function(); // for debugging

  Printf("==CQMSAN== Attached to AFL shared memory %p\n", cqmsan_area_ptr);

  /* If AFL_INST_RATIO or similar is set, touch a byte so parent doesn't give up */
  if (getenv("AFL_INST_RATIO")) cqmsan_area_ptr[0] = 1;

}

#define CQMSAN_AFL_UNTOUCHED             0
#define CQMSAN_AFL_CLEAN                 (1 << 0)
#define CQMSAN_AFL_ERROR                 (1 << 1)
#define CQMSAN_AFL_MEMORY                (1 << 2)
#define CQMSAN_AFL_PC_EDGE               (1 << 3)
#define CQMSAN_AFL_CS                    (1 << 4)
#define CQMSAN_AFL_CS_EDGE               (1 << 5)

__sanitizer::uptr last_edge = 0;
__sanitizer::uptr last_cs_edge = 0;



//#ifdef CQMSAN_AFL
void cqmsan_update_map(__sanitizer::BufferedStackTrace* stack){
    //Printf("CQMSAN: updating map for pc=%p, bp=%p\n", (void *)pc, (void *)bp);
    //TODO: (pc - load_addr) assumes that we are using no_lib mode
    //i.e. we only find candidates in the binary and not in the libraries
    uptr pc = stack->trace_buffer[0];
    //Printf("CQMSAN: updating map for pc=%p\n", (void *)pc);

    // on-demand hashing using BufferedStackTrace for calculate cqmsan_callstack_hash
    __cqmsan_callstack_hash = 0;
    for (u32 i = 0; i < stack->size; ++i) {
      uptr pc_i = stack->trace_buffer[i];
      //Printf("  frame %02u: pc %p\n", i, (void *)pc_i);
      __cqmsan_callstack_hash ^= pc_i;
    }
    // ------------------------------------------------------------------------------
    
    //edges between instructions
    // where I am = cqmsan_callstack^(pc-load_addr)
    // where I was = last_cs_edge >> 1
    uint32_t idx = ((__cqmsan_callstack_hash)^(last_cs_edge >> 1)) % MAP_SIZE;
    last_cs_edge = __cqmsan_callstack_hash;

/*
#ifdef AFL_ONLY_EDGES
    //if we are only looking for edges, we don't need to use bitfields
    if(!cqmsan_area_ptr[idx]){
        cqmsan_area_ptr[idx] = CQMSAN_AFL_CS_EDGE;
        last_cs_edge = cqmsan_callstack;
        cqmsan_area_ptr[MAP_SIZE - 1] = 0xff;
    }
    return;
#endif
*/
    
    //instruction
    cqmsan_area_ptr[ pc % MAP_SIZE] |= CQMSAN_AFL_ERROR;

    //edges between instructions
    cqmsan_area_ptr[((last_edge >> 1) ^ pc ) % MAP_SIZE]
                    |= CQMSAN_AFL_PC_EDGE;
    last_edge = pc;

    //instruction and memory
    //cqmsan_area_ptr[((pc - load_addr)^ptr) % MAP_SIZE] |= CQMSAN_AFL_MEMORY;

    //callstack
    cqmsan_area_ptr[__cqmsan_callstack_hash % MAP_SIZE] |= CQMSAN_AFL_CS;

    //edges between whole callstacks
    cqmsan_area_ptr[idx] |= CQMSAN_AFL_CS_EDGE;
    //last_cs_edge = cqmsan_callstack^(pc-load_addr);

    //lastly, set this to 0xff so that AFL knows we found something
    cqmsan_area_ptr[MAP_SIZE - 1] = 0xff;

}
//#endif

}  // namespace __cqmsan

// [DONE] 13/05
// fast when -fno-omit-frame-pointer, otherwise it is a fallback to slow unwinder.
void __sanitizer::BufferedStackTrace::UnwindImpl(
    __sanitizer::uptr pc, __sanitizer::uptr bp, void *context, bool request_fast, __sanitizer::u32 max_depth) {
  using namespace __cqmsan;
  CQMsanThread *t = GetCurrentThread();
  if (!t || !__sanitizer::StackTrace::WillUseFastUnwind(request_fast)) {
    // Block reports from our interceptors during _Unwind_Backtrace.
    UnwinderScope sym_scope;
    return Unwind(max_depth, pc, bp, context, t ? t->stack_top() : 0,
                  t ? t->stack_bottom() : 0, false);
  }
  if (__sanitizer::StackTrace::WillUseFastUnwind(request_fast))
    Unwind(max_depth, pc, bp, nullptr, t->stack_top(), t->stack_bottom(), true);
  else
    Unwind(max_depth, pc, 0, context, 0, 0, false);
}


// Interface.

using namespace __cqmsan;

// [DONE] 13/05
//#define CQMSAN_MAYBE_WARNING(type, size)              \
//  void __cqmsan_maybe_warning_##size(type s, __sanitizer::u32 o) { \
//    GET_CALLER_PC_BP;                               \
//    if (UNLIKELY(s)) {                              \
//      PrintWarningWithOrigin(pc, bp, o);            \
//      if (__cqmsan::flags()->halt_on_error) {       \
//        Die();                                      \
//      }                                             \
//    }                                               \
//  }

// [DONE] 13/05 - optimized version with early exit if s is zero, to avoid the overhead 
// of GET_CALLER_PC_BP and PrintWarningWithOrigin in the common case of no warning.
#define CQMSAN_MAYBE_WARNING(type, size) \
    void __cqmsan_maybe_warning_##size(type s, __sanitizer::u32 o) { \
      if (LIKELY(!s)) return; \
      GET_CALLER_PC_BP; \
      PrintWarningWithOrigin(pc, bp, o); \
      if (__cqmsan::flags()->halt_on_error) Die(); \
    }


CQMSAN_MAYBE_WARNING(u8, 1)
CQMSAN_MAYBE_WARNING(u16, 2)
CQMSAN_MAYBE_WARNING(u32, 4)
CQMSAN_MAYBE_WARNING(u64, 8)

// [DONE] 13/05 - cutted directly the API for storing origin
//#define CQMSAN_MAYBE_STORE_ORIGIN(type, size)                       \
  void __cqmsan_maybe_store_origin_##size(type s, void *p, __sanitizer::u32 o) { \
    if (UNLIKELY(s)) {                                            \
      if (__cqmsan_get_track_origins() > 1) {                       \
        GET_CALLER_PC_BP;                                         \
        GET_STORE_STACK_TRACE_PC_BP(pc, bp);                      \
        o = ChainOrigin(o, &stack);                               \
      }                                                           \
      *(__sanitizer::u32 *)MEM_TO_ORIGIN((__sanitizer::uptr)p & ~3UL) = o;                  \
    }                                                             \
  }

//CQMSAN_MAYBE_STORE_ORIGIN(u8, 1)
//CQMSAN_MAYBE_STORE_ORIGIN(u16, 2)
//CQMSAN_MAYBE_STORE_ORIGIN(__sanitizer::u32, 4)
//CQMSAN_MAYBE_STORE_ORIGIN(u64, 8)


#include "sanitizer_symbolizer.h"
#include "cqmsan_origin.h"  // where is defined Origin::FromRawId, used in PrintWarningWithOrigin

// [OPTIMIZATION] 22/05
void __cqmsan_warning_fast() {
  GET_CALLER_PC_BP;
  GET_FATAL_STACK_TRACE_PC_BP(pc, bp);
  
  __cqmsan::cqmsan_update_map(&stack);
  ++cqmsan_report_count;

  if (__cqmsan::flags()->halt_on_error) {
    Die();
  }
}

// [DONE] 13/05
void __cqmsan_warning() {
  GET_CALLER_PC_BP;  
  PrintWarningWithOrigin(pc, bp, 0);
  if (__cqmsan::flags()->halt_on_error) {
    if (__cqmsan::flags()->print_stats)
      ReportStats();
    //Printf("Exiting\n");
    Die();
  }
}

// [DONE] 13/05
void __cqmsan_warning_noreturn() {
  GET_CALLER_PC_BP;
  PrintWarningWithOrigin(pc, bp, 0);
  if (__cqmsan::flags()->print_stats)
    ReportStats();
  //Printf("Exiting\n");
  Die();
}

// [DONE] 13/05 - removed since no origin tracking
//void __cqmsan_warning_with_origin(__sanitizer::u32 origin) {
//  GET_CALLER_PC_BP;
//  PrintWarningWithOrigin(pc, bp, origin);
//  if (__cqmsan::flags()->halt_on_error) {
//    if (__cqmsan::flags()->print_stats)
//      ReportStats();
//    //Printf("Exiting\n");
//    Die();
//  }
//}

// [DONE] 13/05 - removed since no origin tracking
//void __cqmsan_warning_with_origin_noreturn(__sanitizer::u32 origin) {
//  GET_CALLER_PC_BP;
//  PrintWarningWithOrigin(pc, bp, origin);
//  if (__cqmsan::flags()->print_stats)
//    ReportStats();
  //Printf("Exiting\n");
//  Die();
//}

//[DONE] 13/05
static void OnStackUnwind(const SignalContext &sig, const void *,
                          __sanitizer::BufferedStackTrace *stack) {
  stack->Unwind(__sanitizer::StackTrace::GetNextInstructionPc(sig.pc), sig.bp, sig.context,
                __sanitizer::common_flags()->fast_unwind_on_fatal);
}

//[DONE] 13/05
static void CQMsanOnDeadlySignal(int signo, void *siginfo, void *context) {
  HandleDeadlySignal(siginfo, context, GetTid(), &OnStackUnwind, nullptr);
}

//[DONE] 13/05
static void CheckUnwind() {
  GET_FATAL_STACK_TRACE_PC_BP(__sanitizer::StackTrace::GetCurrentPc(), GET_CURRENT_FRAME());
  stack.Print();
}


// [DONE] 13/05
// entry point for the CQMSan runtime.
void __cqmsan_init() {
  CHECK(!cqmsan_init_is_running);
  if (cqmsan_inited) return;
  cqmsan_init_is_running = 1;
  SanitizerToolName = "CompilerQEMUMemorySanitizer";

  AvoidCVE_2016_2143();

  CacheBinaryName();
  InitializeFlags();

  SetCheckUnwindCallback(CheckUnwind);

  __sanitizer_set_report_path(__sanitizer::common_flags()->log_path);
  
  InitializeInterceptors();
  InstallAtForkHandler();
  CheckASLR();
  InitTlsSize();
  InstallDeadlySignalHandlers(CQMsanOnDeadlySignal);
  InstallAtExitHandler();

  DisableCoreDumperIfNecessary();
  if (StackSizeIsUnlimited()) {
    VPrintf(1, "Unlimited stack, doing reexec\n");
    // A reasonably large stack size. It is bigger than the usual 8Mb, because,
    // well, the program could have been run with unlimited stack for a reason.
    SetStackSizeLimitInBytes(32 * 1024 * 1024);
    ReExec();
  }

  __cqmsan_clear_on_return();
  if (__cqmsan_get_track_origins())
    VPrintf(1, "cqmsan_track_origins\n");
  if (!InitShadowWithReExec(__cqmsan_get_track_origins())) {
    Printf("FATAL: CompilerQEMUMemorySanitizer can not mmap the shadow memory.\n");
    Printf("FATAL: Make sure to compile with -fPIE and to link with -pie.\n");
    Printf("FATAL: Disabling ASLR is known to cause this error.\n");
    Printf("FATAL: If running under GDB, try "
           "'set disable-randomization off'.\n");
    DumpProcessMap();
    Die();
  }

  Symbolizer::GetOrInit()->AddHooks(EnterSymbolizerOrUnwider,
                                       ExitSymbolizerOrUnwider);
  
  InitializeCoverage(__sanitizer::common_flags()->coverage, __sanitizer::common_flags()->coverage_dir); 

  CQMsanTSDInit(CQMsanTSDDtor);
  CQMsanAllocatorInit();

  CQMsanThread *main_thread = CQMsanThread::Create(nullptr, nullptr);
  SetCurrentThread(main_thread);
  main_thread->Init();

/* [TODO] future work
#if CQMSAN_CONTAINS_UBSAN
  __ubsan::InitAsPlugin();
#endif
*/
  cqmsan_init_is_running = 0;
  cqmsan_inited = 1; // checked by the interceptors

  // After cqmsan_inited = 1 since interceptors are called and they check that variable
  cqmsan_attach_afl_shm();


}

// [DONE] 13/05
void __cqmsan_set_keep_going(int keep_going) {
  flags()->halt_on_error = !keep_going;
}

// [DONE] 13/05
void __cqmsan_set_expect_umr(int expect_umr) {
  if (expect_umr) {
    cqmsan_expected_umr_found = 0;
  } else if (!cqmsan_expected_umr_found) {
    GET_CALLER_PC_BP;
    GET_FATAL_STACK_TRACE_PC_BP(pc, bp);
    ReportExpectedUMRNotFound(&stack);
    Die();
  }
  cqmsan_expect_umr = expect_umr;
}

// [DONE] 13/05
void __cqmsan_print_shadow(const void *x, __sanitizer::uptr size) {
  if (!MEM_IS_APP(x)) {
    Printf("Not a valid application address: %p\n", x);
    return;
  }

  DescribeMemoryRange(x, size);
}

// [DONE] 13/05
void __cqmsan_dump_shadow(const void *x, __sanitizer::uptr size) {
  if (!MEM_IS_APP(x)) {
    Printf("Not a valid application address: %p\n", x);
    return;
  }

  unsigned char *s = (unsigned char*)MEM_TO_SHADOW(x);
  Printf("%p[%p]  ", (void *)s, x);
  for (__sanitizer::uptr i = 0; i < size; i++)
    Printf("%x%x ", s[i] >> 4, s[i] & 0xf);
  Printf("\n");
}

// [DONE] 13/05
sptr __cqmsan_test_shadow(const void *x, uptr size) {
  if (!MEM_IS_APP(x)) return -1;
  unsigned char *s = (unsigned char *)MEM_TO_SHADOW((uptr)x);
  if (__sanitizer::mem_is_zero((const char *)s, size))
    return -1;
  // Slow path: loop through again to find the location.
  for (uptr i = 0; i < size; ++i)
    if (s[i])
      return i;
  return -1;
}

// [DONE] 13/05
void __cqmsan_check_mem_is_initialized(const void *x, __sanitizer::uptr size) {
  if (!__cqmsan::flags()->report_umrs) return;
  sptr offset = __cqmsan_test_shadow(x, size);
  if (offset < 0)
    return;

  GET_CALLER_PC_BP;
  // Early-exit dedup: if this PC is already in the set, skip the rest of the reporting chain.
  //if (__cqmsan::IsUMRSeen(pc)) return;

  ReportUMRInsideAddressRange(__func__, x, size, offset);
  __cqmsan::PrintWarningWithOrigin(pc, bp,
                                 __cqmsan_get_origin(((const char *)x) + offset));
  if (__cqmsan::flags()->halt_on_error) {
    //Printf("Exiting\n");
    Die();
  }
}

// [DONE] 13/05
int __cqmsan_set_poison_in_malloc(int do_poison) {
  int old = flags()->poison_in_malloc;
  flags()->poison_in_malloc = do_poison;
  return old;
}

// [DONE] 13/05
int __cqmsan_has_dynamic_component() { return false; }

// [DONE] 13/05
NOINLINE
void __cqmsan_clear_on_return() {
  __cqmsan_param_tls[0] = 0;
}

// [DONE] 13/05
void __cqmsan_partial_poison(const void* data, void* shadow, __sanitizer::uptr size) {
  internal_memcpy((void*)MEM_TO_SHADOW((__sanitizer::uptr)data), shadow, size);
}

// [DONE] 13/05
void __cqmsan_load_unpoisoned(const void *src, __sanitizer::uptr size, void *dst) {
  internal_memcpy(dst, src, size);
  __cqmsan_unpoison(dst, size);
}

// [DONE] 13/05
void __cqmsan_set_origin(const void *a, __sanitizer::uptr size, __sanitizer::u32 origin) {
  if (__cqmsan_get_track_origins()) SetOrigin(a, size, origin);
}

// [DONE] 13/05
void __cqmsan_set_alloca_origin(void *a, __sanitizer::uptr size, char *descr) {
  SetAllocaOrigin(a, size, reinterpret_cast<__sanitizer::u32 *>(descr), descr + 4,
                  GET_CALLER_PC());
}

// [DONE] 13/05
void __cqmsan_set_alloca_origin4(void *a, __sanitizer::uptr size, char *descr, __sanitizer::uptr pc) {
  // Intentionally ignore pc and use return address. This function is here for
  // compatibility, in case program is linked with library instrumented by
  // older clang.
  SetAllocaOrigin(a, size, reinterpret_cast<__sanitizer::u32 *>(descr), descr + 4,
                  GET_CALLER_PC());
}

// [DONE] 13/05
void __cqmsan_set_alloca_origin_with_descr(void *a, __sanitizer::uptr size, __sanitizer::u32 *id_ptr,
                                         char *descr) {
  SetAllocaOrigin(a, size, id_ptr, descr, GET_CALLER_PC());
}

// [DONE] 13/05
void __cqmsan_set_alloca_origin_no_descr(void *a, __sanitizer::uptr size, __sanitizer::u32 *id_ptr) {
  SetAllocaOrigin(a, size, id_ptr, nullptr, GET_CALLER_PC());
}

// [DONE] 13/05
__sanitizer::u32 __cqmsan_chain_origin(__sanitizer::u32 id) {
  GET_CALLER_PC_BP;
  GET_STORE_STACK_TRACE_PC_BP(pc, bp);
  return ChainOrigin(id, static_cast<__sanitizer::StackTrace*>(&stack));
}

// [DONE] 13/05
__sanitizer::u32 __cqmsan_get_origin(const void *a) {
  if (!__cqmsan_get_track_origins()) return 0;
  __sanitizer::uptr x = (__sanitizer::uptr)a;
  __sanitizer::uptr aligned = x & ~3ULL;
  uptr origin_ptr = MEM_TO_ORIGIN(aligned);
  return *(__sanitizer::u32*)origin_ptr;
}

// [DONE] 13/05
int __cqmsan_origin_is_descendant_or_same(__sanitizer::u32 this_id, __sanitizer::u32 prev_id) {
  Origin o = Origin::FromRawId(this_id);
  while (o.raw_id() != prev_id && o.isChainedOrigin())
    o = o.getNextChainedOrigin(nullptr);
  return o.raw_id() == prev_id;
}

// [DONE] 13/05
__sanitizer::u32 __cqmsan_get_umr_origin() {
  return __cqmsan_origin_tls;
}

u16 __sanitizer_unaligned_load16(const uu16 *p) {
  internal_memcpy(&__cqmsan_retval_tls[0], (void *)MEM_TO_SHADOW((__sanitizer::uptr)p),
                  sizeof(uu16));
  if (__cqmsan_get_track_origins())
    __cqmsan_retval_origin_tls = GetOriginIfPoisoned((__sanitizer::uptr)p, sizeof(*p));
  return *p;
}

__sanitizer::u32 __sanitizer_unaligned_load32(const uu32 *p) {
  internal_memcpy(&__cqmsan_retval_tls[0], (void *)MEM_TO_SHADOW((__sanitizer::uptr)p),
                  sizeof(uu32));
  if (__cqmsan_get_track_origins())
    __cqmsan_retval_origin_tls = GetOriginIfPoisoned((__sanitizer::uptr)p, sizeof(*p));
  return *p;
}

// [DONE] 13/05
u64 __sanitizer_unaligned_load64(const uu64 *p) {
  internal_memcpy(&__cqmsan_retval_tls[0], (void *)MEM_TO_SHADOW((__sanitizer::uptr)p),
                  sizeof(uu64));
  if (__cqmsan_get_track_origins())
    __cqmsan_retval_origin_tls = GetOriginIfPoisoned((__sanitizer::uptr)p, sizeof(*p));
  return *p;
}

void __sanitizer_unaligned_store16(uu16 *p, u16 x) {
  static_assert(sizeof(uu16) == sizeof(u16), "incompatible types");
  u16 s;
  internal_memcpy(&s, &__cqmsan_param_tls[1], sizeof(uu16));
  internal_memcpy((void *)MEM_TO_SHADOW((__sanitizer::uptr)p), &s, sizeof(uu16));
  
  if (s && __cqmsan_get_track_origins())
    if (uu32 o = __cqmsan_param_origin_tls[2])
      SetOriginIfPoisoned((__sanitizer::uptr)p, (__sanitizer::uptr)&s, sizeof(s), o);
  *p = x;
}

void __sanitizer_unaligned_store32(uu32 *p, __sanitizer::u32 x) {
  static_assert(sizeof(uu32) == sizeof(__sanitizer::u32), "incompatible types");
  __sanitizer::u32 s;
  internal_memcpy(&s, &__cqmsan_param_tls[1], sizeof(uu32));
  internal_memcpy((void *)MEM_TO_SHADOW((__sanitizer::uptr)p), &s, sizeof(uu32));

  if (s && __cqmsan_get_track_origins())
    if (uu32 o = __cqmsan_param_origin_tls[2])
      SetOriginIfPoisoned((__sanitizer::uptr)p, (__sanitizer::uptr)&s, sizeof(s), o);
  *p = x;
}

// [DONE] 13/05
void __sanitizer_unaligned_store64(uu64 *p, u64 x) {
  u64 s = __cqmsan_param_tls[1];
  *(uu64 *)MEM_TO_SHADOW((__sanitizer::uptr)p) = s;

  if (s && __cqmsan_get_track_origins())
    if (uu32 o = __cqmsan_param_origin_tls[2])
      SetOriginIfPoisoned((__sanitizer::uptr)p, (__sanitizer::uptr)&s, sizeof(s), o);
    *p = x;
}

// [DONE] 13/05
void __cqmsan_set_death_callback(void (*callback)(void)) {
  SetUserDieCallback(callback);
}

// [DONE] 13/05
void __cqmsan_start_switch_fiber(const void *bottom, __sanitizer::uptr size) {
  CQMsanThread *t = GetCurrentThread();
  if (!t) {
    VReport(1, "__cqmsan_start_switch_fiber called from unknown thread\n");
    return;
  }
  t->StartSwitchFiber((__sanitizer::uptr)bottom, size);
}

// [DONE] 13/05
void __cqmsan_finish_switch_fiber(const void **bottom_old, __sanitizer::uptr *size_old) {
  CQMsanThread *t = GetCurrentThread();
  if (!t) {
    VReport(1, "__cqmsan_finish_switch_fiber called from unknown thread\n");
    return;
  }
  t->FinishSwitchFiber((__sanitizer::uptr *)bottom_old, (__sanitizer::uptr *)size_old);

  internal_memset(__cqmsan_param_tls, 0, sizeof(__cqmsan_param_tls));
  internal_memset(__cqmsan_retval_tls, 0, sizeof(__cqmsan_retval_tls));
  internal_memset(__cqmsan_va_arg_tls, 0, sizeof(__cqmsan_va_arg_tls));

  if (__cqmsan_get_track_origins()) {
    internal_memset(__cqmsan_param_origin_tls, 0,
                    sizeof(__cqmsan_param_origin_tls));
    internal_memset(&__cqmsan_retval_origin_tls, 0,
                    sizeof(__cqmsan_retval_origin_tls));
    internal_memset(__cqmsan_va_arg_origin_tls, 0,
                    sizeof(__cqmsan_va_arg_origin_tls));
  }
}

// [DONE] 13/05
SANITIZER_INTERFACE_WEAK_DEF(const char *, __cqmsan_default_options, void) {
  return "";
}

// [DONE] 13/05
// API implementation
extern "C" {
    SANITIZER_INTERFACE_ATTRIBUTE
    void __sanitizer_print_stack_trace() {
      GET_FATAL_STACK_TRACE_PC_BP(__sanitizer::StackTrace::GetCurrentPc(), GET_CURRENT_FRAME());
      stack.Print();
    }
    SANITIZER_INTERFACE_ATTRIBUTE
    void __cqmsan_disable_checks() {
        __cqmsan::__cqmsan_checks_disabled++;
    }
    
    SANITIZER_INTERFACE_ATTRIBUTE
    void __cqmsan_enable_checks() {
        __cqmsan::__cqmsan_checks_disabled--;
    }

    SANITIZER_INTERFACE_ATTRIBUTE
    void __cqmsan_unpoison(const void *a, uptr size);

} // extern "C"
