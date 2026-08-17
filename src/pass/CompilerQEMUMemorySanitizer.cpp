//===- CompilerQEMUMemorySanitizer.cpp - opportunistic UMR detector -------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Derived from LLVM's MemorySanitizer.cpp. Modified for CQMSan: removes shadow
// propagation and implements opportunistic check-at-load UMR detection with
// AFL coverage feedback.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/APInt.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/GlobalsModRef.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/Argument.h"
#include "llvm/IR/AttributeMask.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IntrinsicsAArch64.h"
#include "llvm/IR/IntrinsicsX86.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/ValueMap.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Support/Alignment.h"
#include "llvm/Support/AtomicOrdering.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/DebugCounter.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Support/VirtualFileSystem.h"
#include "llvm/TargetParser/Triple.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <numeric>
#include <string>
#include <tuple>

#include "CompilerQEMUMemorySanitizer.h"

// replicating msan pipeline 
#include "llvm/Transforms/Scalar/EarlyCSE.h"
#include "llvm/Transforms/InstCombine/InstCombine.h"
#include "llvm/Transforms/Scalar/JumpThreading.h"
#include "llvm/Transforms/Scalar/GVN.h"
#include "llvm/Analysis/GlobalsModRef.h"

using namespace llvm;

#define DEBUG_TYPE "cqmsan"

// TODO - not used
DEBUG_COUNTER(DebugInsertCheck, "cqmsan-insert-check",
    "Controls which checks to insert");

DEBUG_COUNTER(DebugInstrumentInstruction, "cqmsan-instrument-instruction",
    "Controls which instruction to instrument");


// Thread Local Storage buffers handling //

static const Align kShadowTLSAlignment = Align(8);
// These constants must be kept in sync with the ones in cqmsan.h.
static const unsigned kParamTLSSize = 800;
static const unsigned kRetvalTLSSize = 800;

// Accesses sizes are powers of two: 1, 2, 4, 8.
static const size_t kNumberOfAccessSizes = 4;


// ------------- FLAGS --------------- //

static cl::opt<bool> ClSkipProvableCleanLoads("cqmsan-skip-provable-clean-loads",
    cl::desc("Skip loads that can be proven to be clean (no UMR)"),
    cl::Hidden, cl::init(false));

static cl::opt<bool> ClPCOnly(
    "cqmsan_pc-only",
    cl::desc("Fast warning updated the AFL map by PC only (no unwind, no CS_EDGE)."
             "Requires -cqmsan-fast-warning. "),
    cl::Hidden, cl::init(false));

// [OPTIMIZATION]
static cl::opt<bool> ClFastWarning(
    "cqmsan-fast-warning",
    cl::desc("Use bitmap-only warning handler (__cqmsan_warning_fast) instead "
             "of full-diagnostic handler. Skips stack unwind, symbolize, and "
             "stderr Printf. Preserves AFL bitmap signal. Recommended for "
             "fuzzing campaigns; not recommended for developer debugging."),
    cl::Hidden, cl::init(true));

// [PARAMETIZATION]
static cl::opt<bool> ClColdWarning(
    "cqmsan-cold-warning",
    cl::desc("Mark warning handler as cold (keep out of I-cache hot path)."),
    cl::Hidden, cl::init(true)); // when not sure that the warning function is cold, leave it to the compiler to decide. 
    // It may be hot if the program is small and the warning is triggered often.

// [PARAMETRIZATION]
// TODO - understand if this is correct for CQMSan
static cl::opt<bool> ClTrustReturn(
    "cqmsan-trust-return",
    cl::desc("Trust return values from functions"),
    cl::Hidden, cl::init(true));

// [OPTIMIZATION]
static cl::opt<bool> ClBBCoalescedChecks(
    "cqmsan-bb-coalesced-checks",
    cl::desc("Group shadow checks per basic block."),
    cl::Hidden, cl::init(false)); 
    // TODO - adjust and validate the soundess of isImmediateEssentialSink()

static cl::opt<bool> ClKeepGoing("cqmsan-keep-going",
    cl::desc("keep going after reporting a UMR"),
    cl::Hidden, cl::init(true));

// disable only for debug
static cl::opt<bool> ClPoisonStack("cqmsan-poison-stack",
    cl::desc("poison uninitialized stack variables"), 
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClPoisonStackWithCall("cqmsan-poison-stack-with-call",
    cl::desc("poison uninitialized stack variables with a call"),
    cl::Hidden, cl::init(false));   // enable only for debug

static cl::opt<int> ClPoisonStackPattern("cqmsan-poison-stack-pattern",
    cl::desc("poison uninitialized stack variables with the given pattern"),
    cl::Hidden, cl::init(0xff)); 

// Reduce false negatives since it poisons uninitialized variables in the stack
static cl::opt<bool> ClPoisonUndef("cqmsan-poison-undef",
    cl::desc("poison undef temps"), 
    cl::Hidden, cl::init(true));

// Reduce false negatives. Without we lost UMR stack slot reuse 
static cl::opt<bool> ClHandleLifetimeIntrinsics("cqmsan-handle-lifetime-intrinsics",
    cl::desc("when possible, poison scoped variables at the beginning of the scope " 
             "(slower, but more precise)"),
    cl::Hidden, cl::init(true));

// When compiling the Linux kernel, we sometimes see false positives
// being unable to understand that inline assembly calls may initialize
// local variables.
// This flag makes the compiler conservatively unpoison every memory location
// passed into an assembly call. Note that this may cause false positives.
// Because it's impossible to figure out the array sizes, we can only unpoison
// the first sizeof(type) bytes for each type* pointer.
static cl::opt<bool> ClHandleAsmConservative("cqmsan-handle-asm-conservative",
    cl::desc("conservative handling of inline assembly"), cl::Hidden,
    cl::init(false));
    // when true it reduces the false positives, but it may cause false negatives 
    // (e.g. if the inline assembly does not initialize the entire array)
    // So in opportunistic mode we leave it to false, to avoid false negatives and 
    // let the fuzzer find and filter the False positives. 

// This flag controls whether we check the shadow of the address
// operand of load or store. Such bugs are very rare, since load from
// a garbage address typically results in SEGV, but still happen
// (e.g. only lower bits of address are garbage, or the access happens
// early at program startup where malloc-ed memory is more likely to
// be zeroed). As of 2012-08-28 this flag adds 20% slowdown.
static cl::opt<bool> ClCheckAccessAddress(
    "cqmsan-check-access-address",
    cl::desc("report accesses through a pointer which has poisoned shadow"),
    cl::Hidden, cl::init(false));  // MSan upstream uses false.
                                   // Removes the shadow check on the ADDRESS at every
                                   // load/store

static cl::opt<bool> ClEagerChecks("cqmsan-eager-checks",
    cl::desc("check arguments and return values at function call boundaries"),
    cl::Hidden, cl::init(true)); // avoid using TLS for noundef arguments
    // upstream default false

// When there will be too much instrumentation, use callbacks instead of inline checks.
// This is a heuristic to avoid code size blowup and compile time blowup.
static cl::opt<int> ClInstrumentationWithCallThreshold("cqmsan-instrumentation-with-call-threshold",
cl::desc(
    "If the function being instrumented requires more than "
    "this number of checks and origin stores, use callbacks instead of "
    "inline checks (-1 means never use callbacks)."),
cl::Hidden, cl::init(3500));

// Reduce possible false negatives when true, avoiding the skip of costant shadow values
static cl::opt<bool> ClCheckConstantShadow("cqmsan-check-constant-shadow",
    cl::desc("Insert checks for constant shadow values"),
    cl::Hidden, cl::init(true));

// This is off by default because of a bug in gold:
// https://sourceware.org/bugzilla/show_bug.cgi?id=19002
static cl::opt<bool> ClWithComdat("cqmsan-with-comdat",
        cl::desc("Place MSan constructors in comdat sections"),
        cl::Hidden, cl::init(false));

/* SHADOW MAPPING */
// TODO - future work is to handle these 3 options.

// These options allow to specify custom memory map parameters
// See MemoryMapParams for details.
static cl::opt<uint64_t> ClAndMask("cqmsan-and-mask",
    cl::desc("Define custom CQMSan AndMask"),
    cl::Hidden, cl::init(0));

static cl::opt<uint64_t> ClXorMask("cqmsan-xor-mask",
    cl::desc("Define custom CQMSan XorMask"),
    cl::Hidden, cl::init(0));

static cl::opt<uint64_t> ClShadowBase("cqmsan-shadow-base",
    cl::desc("Define custom CQMSan ShadowBase"),
    cl::Hidden, cl::init(0));

// "Use of uninitialized value at %s...", stack_name
// TODO - not used
static cl::opt<bool> ClPrintStackNames("cqmsan-print-stack-names",
    cl::desc("Print name of local stack variable"),
    cl::Hidden, cl::init(false));

/// ------------------------------ABLATION--------------------------------------------- ///

// Default true ⇒ default behavior UNCHANGED. 
// ONLY used to measure the load-skipping throughput 
// ceiling (they are NOT real detectors: setting false loses detection).
//
// ClInstrumentLoads=false : visitLoadInst does not instrument loads at all (no
// shadow-loads, no checks; the load shadow is treated as clean). This is the ceiling:
// no load-skipping optimization can go faster than this.
// Per-target selection: -mllvm -cqmsan-instrument-loads=0
static cl::opt<bool> ClInstrumentLoads(
    "cqmsan-instrument-loads",
    cl::desc("Instrument loads (shadow load + check). false = upper-bound ablation."),
    cl::Hidden, cl::init(true));

// ClCheckLoads=false : the shadow load is loaded but the UMR check is NOT
// issued. Without propagation, the shadow load becomes dead and the DCE removes it ⇒ in
// practice, it collapses on instrument-loads=0 (useful for confirming that the cost is the
// shadow load, not just the check branch).
// Per-target selection: -mllvm -cqmsan-check-loads=0
static cl::opt<bool> ClCheckLoads(
    "cqmsan-check-loads",
    cl::desc("Emit the UMR check at loads. false = load shadow but never check."),
    cl::Hidden, cl::init(true));

static cl::opt<bool> ClInstrumentStores(
    "cqmsan-instrument-stores",
    cl::desc("Instrument stores (shadow store). false = ablation, no shadow store."),
    cl::Hidden, cl::init(true));

/// ------------------------------------------------------------------------------------ ///


// Define the constructor name and the init function name of the runtime library
const char kCQMSanModuleCtorName[] = "cqmsan.module_ctor";
const char kCQMSanInitName[] = "__cqmsan_init";

namespace { // architecture memory map parameters

    // Memory map parameters used in application-to-shadow address calculation.
    // Offset = (Addr & ~AndMask) ^ XorMask
    // Shadow = ShadowBase + Offset
    struct MemoryMapParams {
        uint64_t AndMask;
        uint64_t XorMask;
        uint64_t ShadowBase;
    };

    // not used for now
    struct PlatformMemoryMapParams {
        const MemoryMapParams *bits32;
        const MemoryMapParams *bits64;
    };

    // x86_64 Linux
    static const MemoryMapParams Linux_X86_64_MemoryMapParams = {
        0,              // AndMask (not used)
        0x500000000000, // XorMask
        0               // ShadowBase
    };

    /* [TODO] future work add platform-specific memory map parameters */

};

//===-------------------------CompilerQEMUMemorySanitizerClass---------------------===//

namespace {

/// Instrument functions of a module to detect uninitialized reads.
///
/// Instantiating CompilerQEMUMemorySanitizer inserts the cqmsan runtime library API function
/// declarations into the module if they don't exist already. Instantiating
/// ensures the __cqmsan_init function is in the list of global constructors for
/// the module.
class CompilerQEMUMemorySanitizer {
public:
    CompilerQEMUMemorySanitizer(Module &M, CompilerQEMUMemorySanitizerOptions Options)
        : Recover(Options.Recover), EagerChecks(Options.EagerChecks){
        initializeModule(M);
    }

    // CQMSan cannot be moved or copied because of MapParams.
    // Move constructor
    CompilerQEMUMemorySanitizer(CompilerQEMUMemorySanitizer &&) = delete;
    // Move assignment
    CompilerQEMUMemorySanitizer &operator=(CompilerQEMUMemorySanitizer &&) = delete;
    // Copy constructor
    CompilerQEMUMemorySanitizer(const CompilerQEMUMemorySanitizer &) = delete;
    // Copy assignment
    CompilerQEMUMemorySanitizer &operator=(const CompilerQEMUMemorySanitizer &) = delete;

    // Entry point for function instrumentation. 
    // Called for each function in the module by CompilerQEMUMemorySanitizerPass.
    // Construct the CompilerQEMUMemorySanitizerVisitor.
    // Return true if the function has been modified, false otherwise.
    bool sanitizeFunction(Function &F, TargetLibraryInfo &TLI);

private:
    // InstructionVisitor that performs the actual instrumentation of the function.
    friend struct CompilerQEMUMemorySanitizerVisitor;

    // Handle variadic functions and their calling convenctions (for different architectures).
    // TODO - For now Linux x86_64 only
    friend struct VarArgHelperBase;
    friend struct VarArgAMD64Helper;
    friend struct VarArgNoOpHelper; // For unknown architectures

    void initializeModule(Module &M);
    void createUserspaceApi(Module &M, const TargetLibraryInfo &TLI);
    void initializeCallbacks(Module &M, const TargetLibraryInfo &TLI);

    bool Recover;           // If true, continue after the error (ClKeepGoing)
    bool EagerChecks;

    Triple TargetTriple;    // Linux/x86_64 etc.
    LLVMContext *C;

    Type *IntptrTy;         // i64 on x86_64
    PointerType *PtrTy;     // ptr type

    /// TLS shadow channels ///
    /// Thread-local shadow storage for function parameters.
    Value *ParamTLS;
    /// Thread-local shadow storage for function return value.
    Value *RetvalTLS;
    /// Thread-local shadow storage for in-register va_arg function.
    Value *VAArgTLS;
    /// Thread-local shadow storage for va_arg overflow area.
    Value *VAArgOverflowSizeTLS;

    /// Are the instrumentation callbacks set up?
    bool CallbacksInitialized = false;

    /// FunctionCallee for runtime HELPERS ///
    
    // These arrays are indexed by log2(AccessSize).
    FunctionCallee MaybeWarningFn[kNumberOfAccessSizes];

    /// The run-time callback to print a warning.
    FunctionCallee WarningFn;
    /// Run-time helper that poisons stack on function entry.
    FunctionCallee CQMSanPoisonStackFn;
    /// CQMSan runtime replacements for memmove, memcpy and memset.
    FunctionCallee MemmoveFn, MemcpyFn, MemsetFn;
#ifdef CQMSAN_FLIP_CONVENTION
    /// [FLIP experiment] range-list lookup: is this app address inside a
    /// statically-initialized (loader-mapped) region? See __cqmsan_is_static_range.
    FunctionCallee IsStaticRangeFn;
#endif
    
    // Memory map parameters used in application-to-shadow calculation.
    const MemoryMapParams *MapParams;
    /// Custom memory map parameters used when -msan-shadow-base is provided
    MemoryMapParams CustomMapParams;

    MDNode *ColdCallWeights;

};

/// \brief Inserts a global constructor into the module to initialize the CQMSan runtime.
///
/// This function ensures that the runtime initialization function
/// (__cqmsan_init) is called at application startup, before the
/// main() function executes.
///
/// Use `getOrCreateSanitizerCtorAndInitFunctions` to create a
/// stub constructor function (cqmsan.module_ctor) that invokes __cqmsan_init. This constructor
/// is then added to the module's list of global constructors (`llvm.global_ctors`)
/// with priority 0 (first-come, first-served execution).
///
/// It also handles the `ClWithComdat` option to place the constructor in a
/// Comdat section, allowing the linker to deduplicate constructors if the same
/// runtime is statically linked multiple times.
///
/// \param M The LLVM module into which to inject the constructor.
void insertModuleCtor(Module &M) {
    getOrCreateSanitizerCtorAndInitFunctions(
        M, kCQMSanModuleCtorName, kCQMSanInitName,
        /*InitArgTypes=*/{},
        /*InitArgs=*/{},
        // This callback is invoked when the functions are created the first
        // time. Hook them into the global ctors list in that case:
        [&](Function *Ctor, FunctionCallee) {
            if (!ClWithComdat) {
                appendToGlobalCtors(M, Ctor, 0);
                return;
            }
            Comdat *CQMSanCtorComdat = M.getOrInsertComdat(kCQMSanModuleCtorName);
            Ctor->setComdat(CQMSanCtorComdat);
            appendToGlobalCtors(M, Ctor, 0, Ctor);
        });
}

template <class T> T getOptOrDefault(const cl::opt<T> &Opt, T Default) {
    return (Opt.getNumOccurrences() > 0) ? Opt : Default;
}

} // end anonymous namespace


// ___________________________CompilerQEMUMemorySanitizer___________________________//

CompilerQEMUMemorySanitizerOptions::CompilerQEMUMemorySanitizerOptions(bool R,
    bool EagerChecks)
    : Recover(ClKeepGoing),
      EagerChecks(ClEagerChecks) {}

PreservedAnalyses CompilerQEMUMemorySanitizerPass::run(Module &M, ModuleAnalysisManager &AM) {

    insertModuleCtor(M); // ensure the __cqmsan_init is called before main()

    // get the function analysis manager from the module analysis manager
    auto &FAM = AM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    bool Modified = false;

    // Foreach function in the module, apply the CompilerQEMUMemorySanitizer instrumentation
    for (Function &F : M) {
        if (F.empty())
            continue;

        CompilerQEMUMemorySanitizer CQMSan(*F.getParent(), Options);
        Modified |= CQMSan.sanitizeFunction(F, FAM.getResult<TargetLibraryAnalysis>(F));
    }

    if (!Modified)
        return PreservedAnalyses::all();

    PreservedAnalyses PA = PreservedAnalyses::none();
    // GlobalsAA is considered stateless and does not get invalidated unless
    // explicitly invalidated; PreservedAnalyses::none() is not enough. Sanitizers
    // make changes that require GlobalsAA to be invalidated.
    PA.abandon<GlobalsAA>();
    return PA;

}

void CompilerQEMUMemorySanitizerPass::printPipeline(
    raw_ostream &OS, function_ref<StringRef(StringRef)> MapClassName2PassName) {
  static_cast<PassInfoMixin<CompilerQEMUMemorySanitizerPass> *>(this)->printPipeline(
      OS, MapClassName2PassName);
  OS << '<';
  if (Options.Recover)
    OS << "recover;";
  if (Options.EagerChecks)
    OS << "eager-checks;";
  OS << '>';
}

// Used for declaring globals as "__cqmsan_retval_tls"...
static Constant *getOrInsertGlobal(Module &M, StringRef Name, Type *Ty) {
  return M.getOrInsertGlobal(Name, Ty, [&] {
    return new GlobalVariable(M, Ty, false, GlobalVariable::ExternalLinkage,
                              nullptr, Name, nullptr,
                              GlobalVariable::InitialExecTLSModel);
  });
}

void CompilerQEMUMemorySanitizer::createUserspaceApi(Module &M, const TargetLibraryInfo &TLI) {
    IRBuilder<> IRB(*C);

    // [OPTIMIZATION]
    // TODO - future work: add a noreturn variant of the fast warning handler, to avoid the stack unwind and keep going after the warning.
    StringRef WarningFnName = Recover ? "__cqmsan_warning" : "__cqmsan_warning_noreturn";
    if (ClFastWarning && ClPCOnly)
        WarningFnName = "__cqmsan_warning_fast_pconly";
    else if (ClFastWarning)
        WarningFnName = "__cqmsan_warning_fast";
    
    // [OPTIMIZATION] - warning handler attributes
    // Cold: keep warning callsites out of I-cache hot path (.text.cold layout)
    // NoUnwind: warning never throws C++ exceptions, omit unwind tables
    // NoReturn: only for the noreturn variant — fast/keep-going return normally
    AttributeList Attrs = AttributeList();
    Attrs = Attrs.addFnAttribute(*C, Attribute::NoUnwind);
    if (ClColdWarning) {
        Attrs = Attrs.addFnAttribute(*C, Attribute::Cold);
    }

    if (!Recover && !ClFastWarning) {
        Attrs = Attrs.addFnAttribute(*C, Attribute::NoReturn);
    }

    WarningFn = M.getOrInsertFunction(WarningFnName, Attrs, IRB.getVoidTy());

    // Create the global TLS variables.    
    RetvalTLS =
      getOrInsertGlobal(M, "__cqmsan_retval_tls",
                        ArrayType::get(IRB.getInt64Ty(), kRetvalTLSSize / 8));

    ParamTLS =
      getOrInsertGlobal(M, "__cqmsan_param_tls",
                            ArrayType::get(IRB.getInt64Ty(), kParamTLSSize / 8));

    VAArgTLS =
      getOrInsertGlobal(M, "__cqmsan_va_arg_tls",
                        ArrayType::get(IRB.getInt64Ty(), kParamTLSSize / 8));

    VAArgOverflowSizeTLS = 
      getOrInsertGlobal(M, "__cqmsan_va_arg_overflow_size_tls",
                                           IRB.getIntPtrTy(M.getDataLayout()));
    
    // obtain __cqmsan_maybe_warning_X functions (X=1,2,4,8)
    // ( defined in the runtime library as CQMSAN_MAYBE_WARNING(u8, X) )
    for (size_t AccessSizeIndex = 0; AccessSizeIndex < kNumberOfAccessSizes;
        AccessSizeIndex++) {

        unsigned AccessSize = 1 << AccessSizeIndex;

        std::string FunctionName = ClFastWarning ? "__cqmsan_maybe_warning_fast_" : "__cqmsan_maybe_warning_";

        if (ClFastWarning && ClPCOnly) {
            FunctionName = "__cqmsan_maybe_warning_fast_pconly_";
        }
        FunctionName += itostr(AccessSize);

        MaybeWarningFn[AccessSizeIndex] = M.getOrInsertFunction(
            FunctionName, TLI.getAttrList(C, {0, 1}, /*Signed=*/false),
            IRB.getVoidTy(), IRB.getIntNTy(AccessSize * 8), IRB.getInt32Ty());

    }

    CQMSanPoisonStackFn = M.getOrInsertFunction("__cqmsan_poison_stack",
                                            IRB.getVoidTy(), PtrTy, IntptrTy);

}

/// Insert extern declaration of runtime-provided functions and globals.
void CompilerQEMUMemorySanitizer::initializeCallbacks(Module &M, const TargetLibraryInfo &TLI) {
    
    // Only do this once.
    if (CallbacksInitialized)
        return;

    IRBuilder<> IRB(*C);

    // Initialize callbacks that are common for kernel and userspace
    // instrumentation.
    MemmoveFn = M.getOrInsertFunction("__cqmsan_memmove", PtrTy, PtrTy, PtrTy, IntptrTy);
    MemcpyFn  = M.getOrInsertFunction("__cqmsan_memcpy", PtrTy, PtrTy, PtrTy, IntptrTy); 
    MemsetFn  = M.getOrInsertFunction("__cqmsan_memset",
                                            TLI.getAttrList(C, {1}, /*Signed=*/true),
                                            PtrTy, PtrTy, IRB.getInt32Ty(), IntptrTy);
#ifdef CQMSAN_FLIP_CONVENTION
    IsStaticRangeFn = M.getOrInsertFunction("__cqmsan_is_static_range",
                                            IRB.getInt1Ty(), IntptrTy);
#endif

    createUserspaceApi(M, TLI);
    CallbacksInitialized = true;

}

/// Module-level initialization.
///
/// inserts a call to __cqmsan_init to the module's constructor list.
void CompilerQEMUMemorySanitizer::initializeModule(Module &M) {
    auto &DL            = M.getDataLayout();                       // wich endianness, size of types, etc.
    TargetTriple        = llvm::Triple(M.getTargetTriple());   // which OS, arch, etc.
    bool ShadowPassed   = ClShadowBase.getNumOccurrences() > 0;
    
    // Check the overrides first
    if (ShadowPassed) {
        CustomMapParams.AndMask     = ClAndMask;
        CustomMapParams.XorMask     = ClXorMask;
        CustomMapParams.ShadowBase  = ClShadowBase;
        MapParams = &CustomMapParams;
    } else {
        switch (TargetTriple.getOS()) {
            case Triple::Linux:
                switch (TargetTriple.getArch()) {
                    case Triple::x86_64:
                        MapParams = &Linux_X86_64_MemoryMapParams;
                        break;
                    default:
                    report_fatal_error("unsupported architecture");
                }
                break;
            default:
                report_fatal_error(Twine("unsupported operating system: ") + TargetTriple.str());
        }
    }
  
    C = &(M.getContext());
    IRBuilder<> IRB(*C);
    IntptrTy = IRB.getIntPtrTy(DL); // Get the integer type with the size of a pointer in the default address space. (i64 or i32)
    PtrTy = IRB.getPtrTy();
    
    ColdCallWeights = MDBuilder(*C).createUnlikelyBranchWeights(); // Create a metadata node for unlikely branch weights.
    
    if (Recover) {
        M.getOrInsertGlobal("__cqmsan_keep_going", IRB.getInt32Ty(), [&] {
            return new GlobalVariable(M, IRB.getInt32Ty(), true,
                                    GlobalValue::WeakODRLinkage,
                                    IRB.getInt32(Recover), "__cqmsan_keep_going");
        });
    }

}

namespace {

/// A helper class that handles instrumentation of VarArg
/// functions on a particular platform.
///
/// Implementations are expected to insert the instrumentation
/// necessary to propagate argument shadow through VarArg function
/// calls. Visit* methods are called during an InstVisitor pass over
/// the function, and should avoid creating new basic blocks. A new
/// instance of this class is created for each instrumented function.
struct VarArgHelper {
  virtual ~VarArgHelper() = default;

  /// Visit a CallBase.
  virtual void visitCallBase(CallBase &CB, IRBuilder<> &IRB) = 0;

  /// Visit a va_start call.
  virtual void visitVAStartInst(VAStartInst &I) = 0;

  /// Visit a va_copy call.
  virtual void visitVACopyInst(VACopyInst &I) = 0;

  /// Finalize function instrumentation.
  ///
  /// This method is called after visiting all interesting (see above)
  /// instructions in a function.
  virtual void finalizeInstrumentation() = 0;
};

struct CompilerQEMUMemorySanitizerVisitor;

} // end anonymous namespace


static VarArgHelper *CreateVarArgHelper(Function &Func, CompilerQEMUMemorySanitizer &CQMSan,
                                        CompilerQEMUMemorySanitizerVisitor &Visitor);


static unsigned TypeSizeToSizeIndex(TypeSize TS) {
    if (TS.isScalable())
        // Scalable types unconditionally take slowpaths.
        return kNumberOfAccessSizes;

    unsigned TypeSizeFixed = TS.getFixedValue();
    
    if (TypeSizeFixed <= 8)
        return 0;
    
    return Log2_32_Ceil((TypeSizeFixed + 7) / 8);
}


//____________________________________________________________________________________//
//____________________________________________________________________________________//
//________________________CompilerQEMUMemorySanitizerVisitor_________________________//
//____________________________________________________________________________________//
//____________________________________________________________________________________//

namespace {

/// Helper class to attach debug information of the given instruction onto new
/// instructions inserted after.
class NextNodeIRBuilder : public IRBuilder<> {
    public:
      explicit NextNodeIRBuilder(Instruction *IP) : IRBuilder<>(IP->getNextNode()) {
        SetCurrentDebugLocation(IP->getDebugLoc());
    }
};

struct CompilerQEMUMemorySanitizerVisitor : public InstVisitor<CompilerQEMUMemorySanitizerVisitor> {

    Function &F;
    CompilerQEMUMemorySanitizer &CQMS;
    SmallVector<PHINode *, 16> ShadowPHINodes;
    // IR <-> ShadowValue
    ValueMap<Value *, Value *> ShadowMap;
    std::unique_ptr<VarArgHelper> VAHelper;
    const TargetLibraryInfo *TLI;   // for recognizing libc functions
    Instruction *FnPrologueEnd;
    // List of instructions to instrument in a second time (see runOnFunction)
    SmallVector<Instruction *, 16> Instructions;    

    bool InsertChecks;
    bool PoisonStack;
    bool PoisonUndef;
    // [Disallignment with 19.x version]
    // bool PoisonUndefVectors;

    struct ShadowAndInsertPoint {
        Value *Shadow;
        Instruction *OrigIns;

        ShadowAndInsertPoint(Value *S, Instruction *I)
            : Shadow(S), OrigIns(I) {}
    };

    SmallVector<ShadowAndInsertPoint, 16> InstrumentationList;
    bool InstrumentLifetimeStart = ClHandleLifetimeIntrinsics;
    SmallSetVector<AllocaInst *, 16> AllocaSet;
    SmallVector<std::pair<IntrinsicInst *, AllocaInst *>, 16> LifetimeStartList;
    // For instrument the store in a second time
    SmallVector<StoreInst *, 16> StoreList;
    int64_t SplittableBlocksCount = 0;


    CompilerQEMUMemorySanitizerVisitor(Function &F, CompilerQEMUMemorySanitizer &CQMS, const TargetLibraryInfo &TLI)
        : F(F), CQMS(CQMS), VAHelper(CreateVarArgHelper(F, CQMS, *this)), TLI(&TLI) {
        
        // [TODO] future work: handle this
        // CQMSAN is loaded as an out-of-tree pass via -fpass-plugin: Clang doesn't automatically add
        // Attribute::SanitizeMemory to functions (it only does so with -fsanitize=memory).
        F.addFnAttr(Attribute::SanitizeMemory);
        bool SanitizeFunction = F.hasFnAttribute(Attribute::SanitizeMemory);
        InsertChecks = SanitizeFunction;
        PoisonStack = SanitizeFunction && ClPoisonStack;
        PoisonUndef = SanitizeFunction && ClPoisonUndef;
        // [Disallignment with 19.x version]
        //PoisonUndefVectors = SanitizeFunction && ClPoisonUndefVectors;
        
        // In the presence of unreachable blocks, we may see Phi nodes with
        // incoming nodes from such blocks. Since InstVisitor skips unreachable
        // blocks, such nodes will not have any shadow value associated with them.
        // It's easier to remove unreachable blocks than deal with missing shadow.
        removeUnreachableBlocks(F); 

        CQMS.initializeCallbacks(*F.getParent(), TLI);
        // prologue delineation
        FnPrologueEnd = IRBuilder<>(&F.getEntryBlock(), F.getEntryBlock().getFirstNonPHIIt()) 
                                .CreateIntrinsic(Intrinsic::donothing, {}, {}); // no value-arg

        LLVM_DEBUG(if (!InsertChecks) dbgs()
               << "MemorySanitizer is not inserting checks into '"
               << F.getName() << "'\n");
        
    }

    /// Decide whether to use call-based instrumentation instead of
    /// branch-based checks for this shadow value.
    /// Call-based checks emit a direct __cqmsan_warning_N call, while
    /// branch-based checks split the block and insert an icmp/br sequence.
    bool instrumentWithCalls(Value *V) {
        // Constants likely will be eliminated by follow-up passes.
        // If V is a constant, never use calls:
        if (isa<Constant>(V))
            return false;
        
        //this counter tracks how many times we've considered call-based instrumentation.
        ++SplittableBlocksCount;
        
        // Compare against user-configurable threshold:
        //    - If threshold < 0 → never switch to calls.
        //    - Otherwise, once the count exceeds the threshold, return true
        //      to switch to call-based instrumentation.
        return ClInstrumentationWithCallThreshold >= 0 &&
                SplittableBlocksCount > ClInstrumentationWithCallThreshold;
    }

    bool isInPrologue(Instruction &I) {
        return I.getParent() == FnPrologueEnd->getParent() &&
                (&I == FnPrologueEnd || I.comesBefore(FnPrologueEnd));
    }

    void materializeStores() {
        
        for (StoreInst *SI : StoreList) {
            
            IRBuilder<> IRB(SI);
            Value *Val = SI->getValueOperand();
            Value *Addr = SI->getPointerOperand();

            Value *Shadow = SI->isAtomic() ? getCleanShadow(Val) : getShadow(Val);
            
            Type *ShadowTy = Shadow->getType();
            const Align Alignment = SI->getAlign();

            Value *ShadowPtr = getShadowPtr(Addr, IRB, ShadowTy, Alignment, /*isStore*/ true);
        
            [[maybe_unused]] StoreInst *NewSI = IRB.CreateAlignedStore(Shadow, ShadowPtr, Alignment);
            LLVM_DEBUG(dbgs() << "  STORE: " << *NewSI << "\n");
            
            if (SI->isAtomic())
                SI->setOrdering(addReleaseOrdering(SI->getOrdering()));
            
        }
    }

    /// Helper function to insert an CQMSan warning at IRB's current insert point.
    /// CQMSan does not implement origin tracking (vedi docs/flags/ClTrackOrigins.md),
    /// so the warning call takes no arguments.
    void insertWarningFn(IRBuilder<> &IRB) {
        IRB.CreateCall(CQMS.WarningFn)->setCannotMerge();
    }

    void materializeOneCheck(IRBuilder<> &IRB, Value *ConvertedShadow) {
        const DataLayout &DL = F.getDataLayout();
        TypeSize TypeSizeInBits = DL.getTypeSizeInBits(ConvertedShadow->getType());
        unsigned SizeIndex = TypeSizeToSizeIndex(TypeSizeInBits);

        if (instrumentWithCalls(ConvertedShadow) && SizeIndex < kNumberOfAccessSizes) {
            // Path OUT-OF-LINE: call helper
            FunctionCallee Fn = CQMS.MaybeWarningFn[SizeIndex];
            ConvertedShadow = convertShadowToScalar(ConvertedShadow, IRB);
            Value *ConvertedShadow2 = IRB.CreateZExt(
                ConvertedShadow, IRB.getIntNTy(8 * (1 << SizeIndex)));
            CallBase *CB = IRB.CreateCall(Fn,
                {ConvertedShadow2, (Value *)IRB.getInt32(0)});
            CB->addParamAttr(0, Attribute::ZExt);
            CB->addParamAttr(1, Attribute::ZExt);
        } else {
            // Path INLINE: split + warning
            Value *Cmp = convertToBool(ConvertedShadow, IRB, "_cqmscmp");
            Instruction *CheckTerm = SplitBlockAndInsertIfThen(
                Cmp, &*IRB.GetInsertPoint(), !CQMS.Recover && !ClFastWarning, CQMS.ColdCallWeights);
            IRB.SetInsertPoint(CheckTerm);
            insertWarningFn(IRB);
        }
    }

    void materializeInstructionChecks(ArrayRef<ShadowAndInsertPoint> InstructionChecks) {
        const DataLayout &DL = F.getDataLayout();
        
        Instruction *OrigIns = InstructionChecks.front().OrigIns;
        Value *Shadow = nullptr;
        
        for (const auto &ShadowData : InstructionChecks) {
            assert(ShadowData.OrigIns == OrigIns);
            IRBuilder<> IRB(OrigIns);
            Value *ConvertedShadow = ShadowData.Shadow;
            
            if (auto *ConstantShadow = dyn_cast<Constant>(ConvertedShadow)) {
                if (!ClCheckConstantShadow || ConstantShadow->isZeroValue()) {
                    // Skip, value is initialized or const shadow is ignored.
                    continue;
                }
                
                // known non-zero constant shadow value: emit warning immediately (at runtime)
                if (llvm::isKnownNonZero(ConvertedShadow, DL)) {
                    insertWarningFn(IRB);
                    if (!CQMS.Recover)
                        return;
                    continue;
                }
            }
            
            if (!Shadow) {
                Shadow = ConvertedShadow;
                continue;
            }
            
            Shadow = convertToBool(Shadow, IRB, "_cqmscmp");
            ConvertedShadow = convertToBool(ConvertedShadow, IRB, "_cqmscmp");
            Shadow = IRB.CreateOr(Shadow, ConvertedShadow, "_cqmsor");
        }
        
        if (Shadow) {
            IRBuilder<> IRB(OrigIns);
            materializeOneCheck(IRB, Shadow);
        }

    }
    
    void materializeChecksLegacy() {
#ifndef NDEBUG
    // For assert below.
    SmallPtrSet<Instruction *, 16> Done;
#endif

    for (auto I = InstrumentationList.begin(); I != InstrumentationList.end();) {
        auto OrigIns = I->OrigIns;
        // Checks are grouped by the original instruction. We call all
        // `insertShadowCheck` for an instruction at once.
        assert(Done.insert(OrigIns).second);
        auto J = std::find_if(I + 1, InstrumentationList.end(),
                            [OrigIns](const ShadowAndInsertPoint &R) {
                                return OrigIns != R.OrigIns;
                            });
        // Process all checks of instruction at once.
        materializeInstructionChecks(ArrayRef<ShadowAndInsertPoint>(I, J));
        I = J;
    }

        //LLVM_DEBUG(dbgs() << "DONE:\n" << F);
    }

    // TODO - controllare la correttezza di questa funzione, non è chiaro se sia sufficiente per tutti i casi
    bool isImmediateEssentialSink(Instruction *OrigIns) const {
        // Indirect call: ptr deve essere checked PRIMA della call execution
        if (auto *CB = dyn_cast<CallBase>(OrigIns))
            if (CB->isIndirectCall())
                return true;
        // Memory intrinsics: OOB execution prima del check sarebbe catastrofica
        if (isa<MemIntrinsic>(OrigIns)) return true;
        // Atomic: race effects materializzati prima del check
        if (isa<AtomicCmpXchgInst>(OrigIns) || isa<AtomicRMWInst>(OrigIns))
            return true;
        return false;
    }

    // Helper
    Value *normalizeShadow(IRBuilder<> &IRB, Value *S) {
#ifdef CQMSAN_FLIP_CONVENTION
        // [FLIP experiment] 0=uninit: an element is poisoned iff it is 0, so a
        // vector is poisoned iff ANY element is 0 <=> AND-reduce is 0 (not all
        // elements nonzero). Mirror of the non-flip OR-reduce below.
        if (S->getType()->isVectorTy())
            S = IRB.CreateAndReduce(S);
        return IRB.CreateICmpEQ(S, Constant::getNullValue(S->getType()));
#else
        if (S->getType()->isVectorTy())
            S = IRB.CreateOrReduce(S);
        return IRB.CreateICmpNE(S, Constant::getNullValue(S->getType()));
#endif
    }

    void materializeChecks() {

        if (!ClBBCoalescedChecks) {
            materializeChecksLegacy();   // original path
            return;
        }

        // TODO - risolvere la soundness di isImmediateEssentialSink() per arrivare in questo punto
        // rende grossolano il feedback ad AFL
        // Optimization: coalesce all checks in a BB into a single check at the terminator.
        DenseMap<BasicBlock *, SmallVector<Value *, 8>> BBShadows;

        for (auto It = InstrumentationList.begin(); It != InstrumentationList.end(); ++It) {
            if (isImmediateEssentialSink(It->OrigIns)) {
                // Materialize subito al sink originale
                IRBuilder<> IRB(It->OrigIns);
                materializeOneCheck(IRB, It->Shadow);
            } else {
                // Accumula per BB
                BasicBlock *BB = It->OrigIns->getParent();
                BBShadows[BB].push_back(It->Shadow);
            }
        }

        // Per ogni BB, emette UN check al terminator
        for (auto &Entry : BBShadows) {
            BasicBlock *BB = Entry.first;
            auto &Shadows = Entry.second;
            if (Shadows.empty()) continue;

            Instruction *Term = BB->getTerminator();
            IRBuilder<> IRB(Term);

            // OR di tutti shadow → i1 normalizzato
            Value *Accumulated = normalizeShadow(IRB, Shadows[0]);
            for (size_t i = 1; i < Shadows.size(); ++i) {
                Value *S = normalizeShadow(IRB, Shadows[i]);
                Accumulated = IRB.CreateOr(Accumulated, S);
            }

            materializeOneCheck(IRB, Accumulated);
        }
    }

    bool runOnFunction() {

        // Iterate all BBs in depth-first order and create shadow instructions
        // only for load and stores
        for (BasicBlock *BB : depth_first(FnPrologueEnd->getParent()))
            visit(*BB);

        // `visit` above only collects instructions. Process them after iterating
        // CFG to avoid requirement on CFG transformations.
        for (Instruction *I : Instructions)
            InstVisitor<CompilerQEMUMemorySanitizerVisitor>::visit(*I);

        // Finalize PHI nodes.
        for (PHINode *PN : ShadowPHINodes) {
            PHINode *PNS = cast<PHINode>(getShadow(PN));
            size_t NumValues = PN->getNumIncomingValues();
            for (size_t v = 0; v < NumValues; v++) {
                PNS->addIncoming(getShadow(PN, v), PN->getIncomingBlock(v));
            }
        }

        VAHelper->finalizeInstrumentation();

        // Poison llvm.lifetime.start intrinsics, if we haven't fallen back to
        // instrumenting only allocas.
        if (InstrumentLifetimeStart) {
            for (auto Item : LifetimeStartList) {
                instrumentAlloca(*Item.second, Item.first);
                AllocaSet.remove(Item.second);
            }
        }

        // Poison the allocas for which we didn't instrument the corresponding
        // lifetime intrinsics.
        for (AllocaInst *AI : AllocaSet)
            instrumentAlloca(*AI);
        
        // Insert shadow value checks (deferred from visit phase).
        materializeChecks();

        // Delayed instrumentation of StoreInst.
        // This may not add new address checks.
        materializeStores();

        return true;
    }

    /// Compute the shadow type that corresponds to a given Value.
    Type *getShadowTy(Value *V) { return getShadowTy(V->getType()); }

    /// Compute the shadow type that corresponds to a given Type.
    Type *getShadowTy(Type *OrigTy) {

        if (!OrigTy->isSized()) {
            return nullptr;
        }
        
        // For integer type, shadow is the same as the original type.
        // This may return weird-sized types like i1.
        if (IntegerType *IT = dyn_cast<IntegerType>(OrigTy))
            return IT;
        
        const DataLayout &DL = F.getDataLayout();
        
        if (VectorType *VT = dyn_cast<VectorType>(OrigTy)) {
            uint32_t EltSize = DL.getTypeSizeInBits(VT->getElementType());
            return VectorType::get(IntegerType::get(*CQMS.C, EltSize),
                                    VT->getElementCount());
        }

        if (ArrayType *AT = dyn_cast<ArrayType>(OrigTy)) {
            return ArrayType::get(getShadowTy(AT->getElementType()),
                                AT->getNumElements());
        }
        
        if (StructType *ST = dyn_cast<StructType>(OrigTy)) {
            SmallVector<Type *, 4> Elements;
            
            for (unsigned i = 0, n = ST->getNumElements(); i < n; i++)
                Elements.push_back(getShadowTy(ST->getElementType(i)));
            
            StructType *Res = StructType::get(*CQMS.C, Elements, ST->isPacked());
            LLVM_DEBUG(dbgs() << "getShadowTy: " << *ST << " ===> " << *Res << "\n");
            return Res;
        }

        uint32_t TypeSize = DL.getTypeSizeInBits(OrigTy);
        return IntegerType::get(*CQMS.C, TypeSize);
    }

    /// Extract combined shadow of struct elements as a bool
    Value *collapseStructShadow(StructType *Struct, Value *Shadow,
                                IRBuilder<> &IRB) {
        Value *FalseVal = IRB.getIntN(/* width */ 1, /* value */ 0);
        Value *Aggregator = FalseVal;

        for (unsigned Idx = 0; Idx < Struct->getNumElements(); ++Idx) {
            // Combine by ORing together each element's bool shadow
            Value *ShadowItem = IRB.CreateExtractValue(Shadow, Idx);
            Value *ShadowBool = convertToBool(ShadowItem, IRB); // return 1 if poisoned
    
            if (Aggregator != FalseVal)
                Aggregator = IRB.CreateOr(Aggregator, ShadowBool);
            else
                Aggregator = ShadowBool;
        }

        return Aggregator;
    }

    /// Extract combined shadow of array elements.
    /// Returns scalar shadow != 0 if any element is poisoned.
    Value *collapseArrayShadow(ArrayType *Array, Value *Shadow,
                            IRBuilder<> &IRB) {
        if (!Array->getNumElements())
            return IRB.getIntN(/* width */ 1, /* value */ 0);  // empty array → clean
        
        Value *FirstItem = IRB.CreateExtractValue(Shadow, 0);
        Value *Aggregator = convertShadowToScalar(FirstItem, IRB);
        
        for (unsigned Idx = 1; Idx < Array->getNumElements(); ++Idx) {
            Value *ShadowItem = IRB.CreateExtractValue(Shadow, Idx);
            Value *ShadowInner = convertShadowToScalar(ShadowItem, IRB);
            Aggregator = IRB.CreateOr(Aggregator, ShadowInner);
        }
        
        return Aggregator;
    }

    /// Convert a shadow value to its flattened scalar form.
    /// The resulting value can be used to check initialization (e.g., via comparison with 0).
    /// Note: this does not itself apply poisoned/unpoisoned logic — just aggregation.
    Value *convertShadowToScalar(Value *V, IRBuilder<> &IRB) {
        Type *Ty = V->getType();
        
        if (StructType *Struct = dyn_cast<StructType>(Ty))
            return collapseStructShadow(Struct, V, IRB);
        
        if (ArrayType *Array = dyn_cast<ArrayType>(Ty))
            return collapseArrayShadow(Array, V, IRB);
        
        if (isa<VectorType>(Ty)) {
            if (isa<ScalableVectorType>(Ty))
#ifdef CQMSAN_FLIP_CONVENTION
                return convertShadowToScalar(IRB.CreateAndReduce(V), IRB);
#else
                return convertShadowToScalar(IRB.CreateOrReduce(V), IRB);
#endif
            
            unsigned BitWidth =
                Ty->getPrimitiveSizeInBits().getFixedValue();
            return IRB.CreateBitCast(V, IntegerType::get(*CQMS.C, BitWidth));
        }
        
        return V;
    }
    
    // Convert a scalar value to an i1 by comparing with 0
    Value *convertToBool(Value *V, IRBuilder<> &IRB, const Twine &name = "") {
        Type *VTy = V->getType();
        if (!VTy->isIntegerTy()) {
            return convertToBool(convertShadowToScalar(V, IRB), IRB, name);
        }
        if (VTy->getIntegerBitWidth() == 1) {
            // Just converting a bool to a bool, so do nothing.
            return V; // already i1, no need to invert
        }
#ifdef CQMSAN_FLIP_CONVENTION
        // [FLIP experiment] 0=uninit: poisoned iff raw shadow == 0.
        return IRB.CreateICmpEQ(V, ConstantInt::get(VTy, 0), name);
#else
        return IRB.CreateICmpNE(V, ConstantInt::get(VTy, 0), name);  // post-G1
#endif
    }

    Type *ptrToIntPtrType(Type *PtrTy) const {
        if (VectorType *VectTy = dyn_cast<VectorType>(PtrTy)) {
            return VectorType::get(ptrToIntPtrType(VectTy->getElementType()),
                                VectTy->getElementCount());
        }
        assert(PtrTy->isIntOrPtrTy());
        return CQMS.IntptrTy;
    }

    Type *getPtrToShadowPtrType(Type *IntPtrTy, Type *ShadowTy) const {
        if (VectorType *VectTy = dyn_cast<VectorType>(IntPtrTy)) {
          return VectorType::get(
              getPtrToShadowPtrType(VectTy->getElementType(), ShadowTy),
              VectTy->getElementCount());
        }
        assert(IntPtrTy == CQMS.IntptrTy);
        return CQMS.PtrTy;
    }

    Constant *constToIntPtr(Type *IntPtrTy, uint64_t C) const {
        if (VectorType *VectTy = dyn_cast<VectorType>(IntPtrTy)) {
            return ConstantVector::getSplat(
                VectTy->getElementCount(),
                constToIntPtr(VectTy->getElementType(), C));
        }
        assert(IntPtrTy == CQMS.IntptrTy);
        return ConstantInt::get(CQMS.IntptrTy, C);
    }

    /// Returns the integer shadow offset that corresponds to a given
    /// application address, whereby:
    ///
    ///     Offset = (Addr & ~AndMask) ^ XorMask
    ///     Shadow = ShadowBase + Offset
    ///
    /// Note: for efficiency, many shadow mappings only require use the XorMask
    ///       and OriginBase; the AndMask and ShadowBase are often zero.
    Value *getShadowPtrOffset(Value *Addr, IRBuilder<> &IRB) {
        Type *IntptrTy = ptrToIntPtrType(Addr->getType());
        Value *OffsetLong = IRB.CreatePointerCast(Addr, IntptrTy);

        if (uint64_t AndMask = CQMS.MapParams->AndMask)
            OffsetLong = IRB.CreateAnd(OffsetLong, constToIntPtr(IntptrTy, ~AndMask));
        if (uint64_t XorMask = CQMS.MapParams->XorMask)
            OffsetLong = IRB.CreateXor(OffsetLong, constToIntPtr(IntptrTy, XorMask));

        return OffsetLong;
    }

    /// Compute the shadow and origin addresses corresponding to a given
    /// application address.
    ///
    /// Shadow = ShadowBase + Offset
    /// Addr can be a ptr or <N x ptr>. In both cases ShadowTy the shadow type of
    /// a single pointee.
    /// Returns shadow_ptr or <<N x shadow_ptr>
    Value* getShadowPtrUserspace(Value *Addr, IRBuilder<> &IRB, Type *ShadowTy, [[maybe_unused]] MaybeAlign Alignment) {

        VectorType *VectTy = dyn_cast<VectorType>(Addr->getType());
        if (!VectTy) {
            assert(Addr->getType()->isPointerTy());
        } else {
            assert(VectTy->getElementType()->isPointerTy());
        }

        Value *ShadowOffset = getShadowPtrOffset(Addr, IRB); 
        // returns the offset calculator instruction
        // Offset = (Addr & ~AndMask) ^ XorMask

        Value *ShadowLong = ShadowOffset;
        Type *IntptrTy = ptrToIntPtrType(Addr->getType());

        // if the shadow base is customized
        if (uint64_t ShadowBase = CQMS.MapParams->ShadowBase) {
            ShadowLong =
                IRB.CreateAdd(ShadowLong, constToIntPtr(IntptrTy, ShadowBase));
        }

        Value *ShadowPtr = IRB.CreateIntToPtr(
            ShadowLong, getPtrToShadowPtrType(IntptrTy, ShadowTy));
        // inttoptr casting
        
        return ShadowPtr; // returns % = inttoptr i64 %ShadowLong to ptr 
    }
 
    Value* getShadowPtr(Value *Addr, IRBuilder<> &IRB,
        Type *ShadowTy, MaybeAlign Alignment, [[maybe_unused]] bool isStore) {
        return getShadowPtrUserspace(Addr, IRB, ShadowTy, Alignment);
    }

    /// Compute the shadow address for a given function argument.
    ///
    /// Shadow = ParamTLS+ArgOffset.
    Value *getShadowPtrForArgument(IRBuilder<> &IRB, int ArgOffset) {
        Value *Base = IRB.CreatePointerCast(CQMS.ParamTLS, CQMS.IntptrTy);
        if (ArgOffset)
            Base = IRB.CreateAdd(Base, ConstantInt::get(CQMS.IntptrTy, ArgOffset));
        return IRB.CreateIntToPtr(Base, IRB.getPtrTy(0), "_cqmsarg");
    }

    /// Compute the shadow address for a retval.
    Value *getShadowPtrForRetval(IRBuilder<> &IRB) {
        return IRB.CreatePointerCast(CQMS.RetvalTLS, IRB.getPtrTy(0), "_cqmsret");
    }

    /// Set SV to be the shadow value for V.
    void setShadow(Value *V, Value *SV) {
        assert(!ShadowMap.count(V) && "Values may only have one shadow");
        ShadowMap[V] = SV;
    }

#ifdef CQMSAN_FLIP_CONVENTION
    // [FLIP experiment] Recursive all-ones constant builder, factored out so
    // both getCleanShadow and getPoisonedShadow can use it depending on which
    // one the flip makes "the all-ones one". Handles int/vector directly,
    // array/struct recursively (identical logic to the non-flipped
    // getPoisonedShadow below, just under a neutral name).
    Constant *getAllOnesShadow(Type *ShadowTy) {
        assert(ShadowTy);
        if (isa<IntegerType>(ShadowTy) || isa<VectorType>(ShadowTy))
            return Constant::getAllOnesValue(ShadowTy);
        if (ArrayType *AT = dyn_cast<ArrayType>(ShadowTy)) {
            SmallVector<Constant *, 4> Vals(AT->getNumElements(),
                                        getAllOnesShadow(AT->getElementType()));
            return ConstantArray::get(AT, Vals);
        }
        if (StructType *ST = dyn_cast<StructType>(ShadowTy)) {
            SmallVector<Constant *, 4> Vals;
            for (unsigned i = 0, n = ST->getNumElements(); i < n; i++)
                Vals.push_back(getAllOnesShadow(ST->getElementType(i)));
            return ConstantStruct::get(ST, Vals);
        }
        llvm_unreachable("Unexpected shadow type");
    }
#endif

    // create clean shadow value for a given type as initialized
    Constant *getCleanShadow(Type *OrigTy) {
        Type *ShadowTy = getShadowTy(OrigTy);
        if (!ShadowTy)
            return nullptr;
#ifdef CQMSAN_FLIP_CONVENTION
        return getAllOnesShadow(ShadowTy);  // 0=uninit: clean is all-ones
#else
        return Constant::getNullValue(ShadowTy);
#endif
    }

    /// Create a clean shadow value for a given value.
    Constant *getCleanShadow(Value *V) { return getCleanShadow(V->getType()); }

    /// Create a dirty shadow of a given shadow type.
    Constant *getPoisonedShadow(Type *ShadowTy) {
        assert(ShadowTy);
#ifdef CQMSAN_FLIP_CONVENTION
        return Constant::getNullValue(ShadowTy);  // 0=uninit: poison is all-zero
#else
        if (isa<IntegerType>(ShadowTy) || isa<VectorType>(ShadowTy))
            return Constant::getAllOnesValue(ShadowTy);

        if (ArrayType *AT = dyn_cast<ArrayType>(ShadowTy)) {
            SmallVector<Constant *, 4> Vals(AT->getNumElements(),
                                        getPoisonedShadow(AT->getElementType()));
            return ConstantArray::get(AT, Vals);
        }

        if (StructType *ST = dyn_cast<StructType>(ShadowTy)) {
            SmallVector<Constant *, 4> Vals;
            for (unsigned i = 0, n = ST->getNumElements(); i < n; i++)
                Vals.push_back(getPoisonedShadow(ST->getElementType(i)));
            return ConstantStruct::get(ST, Vals);
        }
        llvm_unreachable("Unexpected shadow type");
#endif
    }

    /// Create a dirty shadow for a given value.
    Constant *getPoisonedShadow(Value *V) {
        Type *ShadowTy = getShadowTy(V);
        if (!ShadowTy)
            return nullptr;
        return getPoisonedShadow(ShadowTy);
    }

    /// Get the shadow value for a given Value.
    ///
    /// This function either returns the value set earlier with setShadow,
    /// or extracts if from ParamTLS (for function arguments).
    Value *getShadow(Value *V) {

        if (Instruction *I = dyn_cast<Instruction>(V)) {
            // Functions with no_sanitize attribute - clean
            if (I->getMetadata(LLVMContext::MD_nosanitize))
                return getCleanShadow(V);
            
            // For instructions the shadow is already stored in the map.
            Value *Shadow = ShadowMap[V];
            if (!Shadow) {
                // OLD
                //  LLVM_DEBUG(dbgs() << "No shadow: " << *V << "\n" << *(I->getParent()));
                //  assert(Shadow && "No shadow for a value");ù
                // NEW
                // Se l'istruzione non è stata strumentata (es. prologo, o saltata),
                // assumiamo che il suo valore sia pulito/inizializzato.
                LLVM_DEBUG(dbgs() << "No shadow found for: " << *V << " -> Returning Clean Shadow\n");
                return getCleanShadow(V);
            }
            return Shadow;
        }  

        // Handle fully undefined values
        if ([[maybe_unused]] UndefValue *U = dyn_cast<UndefValue>(V)) {
            Value *AllOnes = PoisonUndef ? getPoisonedShadow(V) : getCleanShadow(V);
            LLVM_DEBUG(dbgs() << "Undef: " << *U << " ==> " << *AllOnes << "\n");
            return AllOnes;
        }

        
        if (Argument *A = dyn_cast<Argument>(V)) {
            return getCleanShadow(V);
        }
        
        // For everything else the shadow is clean.
        return getCleanShadow(V);

    }
    
    /// Get the shadow for i-th argument of the instruction I.
    Value *getShadow(Instruction *I, int i) {
        return getShadow(I->getOperand(i));
    }

    /// Remember the place where a shadow check should be inserted.
    ///
    /// This location will be later instrumented with a check that will print a
    /// UMR warning in runtime if the shadow value is not 0.
    void pushShadowCheck(Value *Shadow, Instruction *OrigIns) {
        assert(Shadow);
        if (!InsertChecks)
            return;
        
#ifndef NDEBUG
        Type *ShadowTy = Shadow->getType();
        assert((isa<IntegerType>(ShadowTy) || isa<VectorType>(ShadowTy) ||
                isa<StructType>(ShadowTy) || isa<ArrayType>(ShadowTy)) &&
            "Can only insert checks for integer, vector, and aggregate shadow types");
#endif
        
        InstrumentationList.push_back(ShadowAndInsertPoint(Shadow, OrigIns));
    }

    /// Remember the place where a shadow check should be inserted.
    ///
    /// This location will be later instrumented with a check that will print a
    /// UMR warning in runtime if the value is not fully defined.
    void insertShadowCheck(Value *Val, Instruction *OrigIns) {
        assert(Val);
        Value *Shadow;
        if (ClCheckConstantShadow) {
            Shadow = getShadow(Val);
        } else {
            Shadow = dyn_cast_or_null<Instruction>(getShadow(Val));
        }
        if (!Shadow) return;
        pushShadowCheck(Shadow, OrigIns);
    }

    AtomicOrdering addReleaseOrdering(AtomicOrdering a) {
        switch (a) {
            case AtomicOrdering::NotAtomic:
                return AtomicOrdering::NotAtomic;
            case AtomicOrdering::Unordered:
            case AtomicOrdering::Monotonic:
            case AtomicOrdering::Release:
                return AtomicOrdering::Release;
            case AtomicOrdering::Acquire:
            case AtomicOrdering::AcquireRelease:
                return AtomicOrdering::AcquireRelease;
            case AtomicOrdering::SequentiallyConsistent:
                return AtomicOrdering::SequentiallyConsistent;
        }
        llvm_unreachable("Unknown ordering");
    }

    Value *makeAddReleaseOrderingTable(IRBuilder<> &IRB) {
      constexpr int NumOrderings = (int)AtomicOrderingCABI::seq_cst + 1;
      uint32_t OrderingTable[NumOrderings] = {};

      OrderingTable[(int)AtomicOrderingCABI::relaxed] =
          OrderingTable[(int)AtomicOrderingCABI::release] =
              (int)AtomicOrderingCABI::release;
      OrderingTable[(int)AtomicOrderingCABI::consume] =
          OrderingTable[(int)AtomicOrderingCABI::acquire] =
              OrderingTable[(int)AtomicOrderingCABI::acq_rel] =
                  (int)AtomicOrderingCABI::acq_rel;
      OrderingTable[(int)AtomicOrderingCABI::seq_cst] =
          (int)AtomicOrderingCABI::seq_cst;

      return ConstantDataVector::get(IRB.getContext(), OrderingTable);
    }

    AtomicOrdering addAcquireOrdering(AtomicOrdering a) {
        switch (a) {
            case AtomicOrdering::NotAtomic:
                return AtomicOrdering::NotAtomic;
            case AtomicOrdering::Unordered:
            case AtomicOrdering::Monotonic:
            case AtomicOrdering::Acquire:
                return AtomicOrdering::Acquire;
            case AtomicOrdering::Release:
            case AtomicOrdering::AcquireRelease:
                return AtomicOrdering::AcquireRelease;
            case AtomicOrdering::SequentiallyConsistent:
                return AtomicOrdering::SequentiallyConsistent;
        }
        llvm_unreachable("Unknown ordering");
    }

    Value *makeAddAcquireOrderingTable(IRBuilder<> &IRB)
    {
      constexpr int NumOrderings = (int)AtomicOrderingCABI::seq_cst + 1;
      uint32_t OrderingTable[NumOrderings] = {};

      OrderingTable[(int)AtomicOrderingCABI::relaxed] =
          OrderingTable[(int)AtomicOrderingCABI::acquire] =
              OrderingTable[(int)AtomicOrderingCABI::consume] =
                  (int)AtomicOrderingCABI::acquire;
      OrderingTable[(int)AtomicOrderingCABI::release] =
          OrderingTable[(int)AtomicOrderingCABI::acq_rel] =
              (int)AtomicOrderingCABI::acq_rel;
      OrderingTable[(int)AtomicOrderingCABI::seq_cst] =
          (int)AtomicOrderingCABI::seq_cst;

      return ConstantDataVector::get(IRB.getContext(), OrderingTable);
    }

    // ------------------- Visitors.
    using InstVisitor<CompilerQEMUMemorySanitizerVisitor>::visit;

    /// \brief Visitor entry point for each individual statement.
    ///
    /// This function acts as a preliminary filter and collector. It is called
    /// for each statement in the visited basic blocks (during the first pass of runOnFunction).
    ///
    /// Its main tasks are:
    /// 1. Ignore statements explicitly marked with 'nosanitize' metadata.
    /// 2. Ignore statements that are part of the function's prologue (which should not be touched).
    /// 3. Manage debug counters (DebugCounter) to allow bug bisecting,
    ///     while ensuring that skipped statements still have a valid shadow (Clean).
    /// 4. Add valid instructions to the `Instructions` list for deferred instrumentation.
    ///
    /// \param I The current statement to visit.
    void visit(Instruction &I) {
        
        if (I.getMetadata(LLVMContext::MD_nosanitize))
            return;

        // Don't want to visit if we're in the prologue
        if (isInPrologue(I))
            return;
        
        if (!DebugCounter::shouldExecute(DebugInstrumentInstruction)) {
            LLVM_DEBUG(dbgs() << "Skipping instruction: " << I << "\n");
            // We still need to set the shadow and origin to clean values.
            setShadow(&I, getCleanShadow(&I));
            return;
        }

        Instructions.push_back(&I);
    }

    bool hasDominatingConstantStoreInBB(AllocaInst *AI, LoadInst *LI) {
        BasicBlock *BB = LI->getParent();
        if (AI->getParent() != BB) return false;

        // Strip a load as "clean" ONLY if a dominant store covers
        // EXACTLY the location read. Using stripInBoundsConstantOffsets() on the
        // store pointer, a store at `gep AI, off` would be stripped to AI and
        // treated as if it initialized the entire alloca (while only writing a
        // portion) → a load from unwritten bytes would be incorrectly stripped (FALSE
        // NEGATIVE). We therefore require: same pointer as the load, constant value,
        // and store size >= the load.
        const DataLayout &DL = LI->getModule()->getDataLayout();
        Value *LPtr = LI->getPointerOperand();
        uint64_t LSize = DL.getTypeStoreSize(LI->getType());

        for (Instruction *I = AI->getNextNode(); I && I != LI; I = I->getNextNode()) {
            // Intermediate call: conservative, abort
            if (auto *CB = dyn_cast<CallBase>(I))
                if (!isa<IntrinsicInst>(CB) || CB->mayWriteToMemory())
                    return false;

            if (auto *SI = dyn_cast<StoreInst>(I)) {
                if (SI->getPointerOperand() == LPtr &&
                    isa<Constant>(SI->getValueOperand()) &&
                    DL.getTypeStoreSize(SI->getValueOperand()->getType()) >= LSize)
                    return true; 
                return false;
            }
        }
        return false;
    }

    bool isLoadFromGlobalConstant(LoadInst *LI) {
        Value *Ptr = LI->getPointerOperand()->stripInBoundsConstantOffsets();
        auto *GV = dyn_cast<GlobalVariable>(Ptr);
        return GV && GV->isConstant() && GV->hasInitializer()
            && !GV->isExternallyInitialized();
    }

    bool canProveLoadIsClean(LoadInst *LI) {
        // [TODO] if this work, implement this flag then
        if (!ClSkipProvableCleanLoads) return false;

        // R1
        if (isLoadFromGlobalConstant(LI)) return true;

        // R2
        Value *Ptr = LI->getPointerOperand()->stripInBoundsConstantOffsets();
        if (auto *AI = dyn_cast<AllocaInst>(Ptr))
            if (hasDominatingConstantStoreInBB(AI, LI))
                return true;

        return false;
    }

    /// Instrument LoadInst
    ///
    /// Loads the corresponding shadow and (optionally) origin.
    /// Optionally, checks that the load address is fully defined.
    void visitLoadInst(LoadInst &I) {
        assert(I.getType()->isSized() && "Load type must have size");
        assert(!I.getMetadata(LLVMContext::MD_nosanitize));
        
        // [ABLATION upper-bound] Do not instrment loads: shadow clean, no memory access, no checks.
        // This is the limit of the optimization of the load instrumentation.
        if (!ClInstrumentLoads) {
            setShadow(&I, getCleanShadow(&I));
            return;
        }

        IRBuilder<> IRB(&I);
        Type *ShadowTy        = getShadowTy(&I);
        Value *Addr           = I.getPointerOperand();
        const Align Alignment = I.getAlign();

        bool insertedShadowLoad = false;

        if (canProveLoadIsClean(&I)) {
            LLVM_DEBUG(dbgs() << "Load is provably clean: " << I << "\n");
            setShadow(&I, getCleanShadow(&I));
        } else {
            
            Value *ShadowPtr       = getShadowPtr(Addr, IRB, ShadowTy, Alignment, /*isStore*/ false);
            LoadInst *LoadedShadow = IRB.CreateAlignedLoad(ShadowTy, ShadowPtr, Alignment, "_cqmsld");
            Value *EffectiveShadow = LoadedShadow;

#ifdef CQMSAN_FLIP_CONVENTION
            // [FLIP experiment, fast/slow path] Under 0=uninit, a never-explicitly-
            // written global (loader-initialized .data/.bss) has virgin
            // shadow=0=poisoned by default, which is wrong (the loader DID
            // initialize it) — the "globals become FP-prone" problem documented in
            // STUDIO_unpoison_punti_e_costo.md §9-bis. Mirrors QMSan's own fix
            // (msan_giovese_add_mmap/check_addr_mmap_list, verified in
            // qemu/linux-user/elfload.c): a runtime range-list of loader-mapped
            // segments, consulted here to override the shadow to clean for
            // addresses inside a known-initialized range, WITHOUT ever writing
            // shadow bytes for that region.
            //
            // Unlike the first version of this experiment, the range-list call is
            // NOT made unconditionally on every load. QMSan's own equivalent check
            // (msan-giovese-inl.h) is short-circuited: `((~res & MSAN_8)!=0) &&
            // msan_giovese_check_addr(ptr)` — the expensive list walk runs only
            // when the raw shadow already looks poisoned, to disambiguate a real
            // bug from a loader-initialized false alarm. Mirrored here as a real
            // fast/slow basic-block split: for the overwhelming majority of loads
            // (genuinely defined memory, RawPoisoned=false), __cqmsan_is_static_range
            // never runs at all.
            Value *RawPoisoned = convertToBool(LoadedShadow, IRB, "_cqmsrawpoison");
            BasicBlock *FastBB = IRB.GetInsertBlock();
            Instruction *SlowTerm = SplitBlockAndInsertIfThen(
                RawPoisoned, &*IRB.GetInsertPoint(), /*Unreachable*/false, CQMS.ColdCallWeights);
            BasicBlock *SlowBB = SlowTerm->getParent();
            BasicBlock *TailBB = SlowTerm->getSuccessor(0);

            IRBuilder<> SlowIRB(SlowTerm);
            Value *AddrInt      = SlowIRB.CreatePtrToInt(Addr, CQMS.IntptrTy);
            Value *IsStatic     = SlowIRB.CreateCall(CQMS.IsStaticRangeFn, {AddrInt});
            Value *SlowShadow   = SlowIRB.CreateSelect(IsStatic, getCleanShadow(&I), LoadedShadow,
                                                        "_cqmsstaticsel");
            Value *SlowPoisoned = SlowIRB.CreateNot(IsStatic, "_cqmsslowpoison");

            IRB.SetInsertPoint(TailBB, TailBB->begin());
            PHINode *ShadowPhi = IRB.CreatePHI(ShadowTy, 2, "_cqmsshadowphi");
            ShadowPhi->addIncoming(LoadedShadow, FastBB);
            ShadowPhi->addIncoming(SlowShadow, SlowBB);
            PHINode *PoisonedPhi = IRB.CreatePHI(IRB.getInt1Ty(), 2, "_cqmspoisonedphi");
            PoisonedPhi->addIncoming(ConstantInt::getFalse(IRB.getContext()), FastBB);
            PoisonedPhi->addIncoming(SlowPoisoned, SlowBB);

            EffectiveShadow = ShadowPhi;
            Value *EffectivePoisoned = PoisonedPhi;
#endif

            setShadow(&I, EffectiveShadow);
            insertedShadowLoad = true;

            if (ClCheckLoads) {
#ifdef CQMSAN_FLIP_CONVENTION
                pushShadowCheck(EffectivePoisoned, &I);
#else
                pushShadowCheck(EffectiveShadow, &I);
#endif
            }

        }

        // Optional: check that the load address is fully defined.
        // Captures UMR on uninitialized address (e.g., `int *p; *p = 1;`).
        if (ClCheckAccessAddress)
            insertShadowCheck(I.getPointerOperand(), &I);
        
        // Atomic correctness: Instrumented loads add a shadow load BEFORE
        // the original load. To ensure happens-before between the two, the ordering
        // of the original load must be at least acquired.
        if (insertedShadowLoad && I.isAtomic())
            I.setOrdering(addAcquireOrdering(I.getOrdering()));
        
    }

    /// Instrument StoreInst
    /// 
    /// Just collect all the store instructions for successively instrument them with
    /// materializeStores() function
    void visitStoreInst(StoreInst &I) {
        if (!ClInstrumentStores) return;
        
        StoreList.push_back(&I);
        // Optional: check that the store destination address is fully defined.
        // Captures UMR on uninitialized address (e.g., `int *p; *p = 1;`).
        if (ClCheckAccessAddress)
            insertShadowCheck(I.getPointerOperand(), &I);
    }

    void handleCASOrRMW(Instruction &I) {
        assert(isa<AtomicRMWInst>(I) || isa<AtomicCmpXchgInst>(I));

        IRBuilder<> IRB(&I);
        Value *Addr = I.getOperand(0);
        Value *Val = I.getOperand(1);
        Value *ShadowPtr = getShadowPtr(Addr, IRB, getShadowTy(Val), Align(1), /*isStore*/ true);

        if (ClCheckAccessAddress)
            insertShadowCheck(Addr, &I);

        // Only test the conditional argument of cmpxchg instruction.
        // The other argument can potentially be uninitialized, but we can not
        // detect this situation reliably without possible false positives.
        if (isa<AtomicCmpXchgInst>(I))
            insertShadowCheck(Val, &I);

        IRB.CreateStore(getCleanShadow(Val), ShadowPtr);
        setShadow(&I, getCleanShadow(&I));
    }
    
    void visitAtomicRMWInst(AtomicRMWInst &I) {
        handleCASOrRMW(I);
        I.setOrdering(addReleaseOrdering(I.getOrdering()));
    }

    void visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
        handleCASOrRMW(I);
        I.setSuccessOrdering(addReleaseOrdering(I.getSuccessOrdering()));
    }

    /// Instrument llvm.memmove
    ///
    /// At this point we don't know if llvm.memmove will be inlined or not.
    /// If we don't instrument it and it gets inlined,
    /// our interceptor will not kick in and we will lose the memmove.
    /// If we instrument the call here, but it does not get inlined,
    /// we will memove the shadow twice: which is bad in case
    /// of overlapping regions. So, we simply lower the intrinsic to a call.
    ///
    /// Similar situation exists for memcpy and memset.
    void visitMemMoveInst(MemMoveInst &I) {
        getShadow(I.getArgOperand(1)); // Ensure shadow initialized
        IRBuilder<> IRB(&I);
        IRB.CreateCall(CQMS.MemmoveFn,
                    {I.getArgOperand(0), I.getArgOperand(1),
                        IRB.CreateIntCast(I.getArgOperand(2), CQMS.IntptrTy, false)});
        I.eraseFromParent();
    }

    /// Instrument memcpy
    ///
    /// Similar to memmove: avoid copying shadow twice. This is somewhat
    /// unfortunate as it may slowdown small constant memcpys.
    /// FIXME: consider doing manual inline for small constant sizes and proper
    /// alignment.
    ///
    /// Note: This also handles memcpy.inline, which promises no calls to external
    /// functions as an optimization. However, with instrumentation enabled this
    /// is difficult to promise; additionally, we know that the MSan runtime
    /// exists and provides __cqmsan_memcpy(). Therefore, we assume that with
    /// instrumentation it's safe to turn memcpy.inline into a call to
    /// __cqmsan_memcpy(). Should this be wrong, such as when implementing memcpy()
    /// itself, instrumentation should be disabled with the no_sanitize attribute.
    void visitMemCpyInst(MemCpyInst &I) {
        getShadow(I.getArgOperand(1)); // Ensure shadow initialized
        IRBuilder<> IRB(&I);
        IRB.CreateCall(CQMS.MemcpyFn,
                    {I.getArgOperand(0), I.getArgOperand(1),
                        IRB.CreateIntCast(I.getArgOperand(2), CQMS.IntptrTy, false)});
        I.eraseFromParent();
    }
    
    // Same as memcpy.
    void visitMemSetInst(MemSetInst &I) {
        IRBuilder<> IRB(&I);
        IRB.CreateCall(
            CQMS.MemsetFn,
            {I.getArgOperand(0),
            IRB.CreateIntCast(I.getArgOperand(1), IRB.getInt32Ty(), false),
            IRB.CreateIntCast(I.getArgOperand(2), CQMS.IntptrTy, false)});
        I.eraseFromParent();
    }
    
    void visitVAStartInst(VAStartInst &I) { VAHelper->visitVAStartInst(I); }

    void visitVACopyInst(VACopyInst &I) { VAHelper->visitVACopyInst(I); }

    /// Handle vector store-like intrinsics.
    ///
    /// Instrument intrinsics that look like a simple SIMD store: writes memory,
    /// has 1 pointer argument and 1 vector argument, returns void.
    bool handleVectorStoreIntrinsic(IntrinsicInst &I) {
        assert(I.arg_size() == 2);

        IRBuilder<> IRB(&I);
        Value *Addr = I.getArgOperand(0);
        Value *Shadow = getShadow(&I, 1);
        Value *ShadowPtr;

        // We don't know the pointer alignment (could be unaligned SSE store!).
        // Have to assume to worst case.
        ShadowPtr = getShadowPtr(
            Addr, IRB, Shadow->getType(), Align(1), /*isStore*/ true);
        IRB.CreateAlignedStore(Shadow, ShadowPtr, Align(1));
        
        if (ClCheckAccessAddress)
            insertShadowCheck(Addr, &I);
        
        return true;
    }
    
    /// Handle vector load-like intrinsics.
    ///
    /// Instrument intrinsics that look like a simple SIMD load: reads memory,
    /// has 1 pointer argument, returns a vector.
    bool handleVectorLoadIntrinsic(IntrinsicInst &I) {
        assert(I.arg_size() == 1);

        IRBuilder<> IRB(&I);
        Value *Addr = I.getArgOperand(0);

        Type *ShadowTy = getShadowTy(&I);
        Value *ShadowPtr = nullptr;
        const Align Alignment = Align(1);
        
        ShadowPtr = getShadowPtr(Addr, IRB, ShadowTy, Alignment, /*isStore*/ false);
        LoadInst *LoadedShadow = IRB.CreateAlignedLoad(ShadowTy, ShadowPtr, Alignment, "_cqmsld");
        
        setShadow(&I, LoadedShadow);
        
        // same push logic as visitLoadInst
        pushShadowCheck(LoadedShadow, &I);
        
        if (ClCheckAccessAddress)
            insertShadowCheck(Addr, &I);

        return true;
    }

    /// Heuristically instrument unknown intrinsics.
    ///
    /// The main purpose of this code is to do something reasonable with all
    /// random intrinsics we might encounter, most importantly - SIMD intrinsics.
    /// We recognize several classes of intrinsics by their argument types and
    /// ModRefBehaviour and apply special instrumentation when we are reasonably
    /// sure that we know what the intrinsic does.
    ///
    /// We special-case intrinsics where this approach fails. See llvm.bswap
    /// handling as an example of that.
    bool handleUnknownIntrinsic(IntrinsicInst &I) {
        unsigned NumArgOperands = I.arg_size();
        if (NumArgOperands == 0)
            return false;

        if (NumArgOperands == 2 && I.getArgOperand(0)->getType()->isPointerTy() &&
            I.getArgOperand(1)->getType()->isVectorTy() &&
            I.getType()->isVoidTy() && !I.onlyReadsMemory()) {
            // This looks like a vector store.
            return handleVectorStoreIntrinsic(I);
        }

        if (NumArgOperands == 1 && I.getArgOperand(0)->getType()->isPointerTy() &&
            I.getType()->isVectorTy() && I.onlyReadsMemory()) {
            // This looks like a vector load.
            return handleVectorLoadIntrinsic(I);
        }

        // FIXME: detect and handle SSE maskstore/maskload
        return false;
    }

    void handleLifetimeStart(IntrinsicInst &I) {
        if (!PoisonStack)
            return;

        // which alloca this lifetime.start refers to
        AllocaInst *AI = llvm::findAllocaForValue(I.getArgOperand(1));
        if (!AI)
            InstrumentLifetimeStart = false;   // fallback: do not instrument lifetime.start if we can't find the alloca
        else
            LifetimeStartList.push_back(std::make_pair(&I, AI));

    }

    void handleStmxcsr(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Addr = I.getArgOperand(0);
        Type *Ty = IRB.getInt32Ty();
        Value *ShadowPtr =
            getShadowPtr(Addr, IRB, Ty, Align(1), /*isStore*/ true);

        IRB.CreateStore(getCleanShadow(Ty), ShadowPtr);

        if (ClCheckAccessAddress)
            insertShadowCheck(Addr, &I);
    }

    void handleLdmxcsr(IntrinsicInst &I) {
        if (!InsertChecks)
            return;

        IRBuilder<> IRB(&I);
        Value *Addr = I.getArgOperand(0);
        Type *Ty = IRB.getInt32Ty();
        const Align Alignment = Align(1);
        Value *ShadowPtr = getShadowPtr(Addr, IRB, Ty, Alignment, /*isStore*/ false);

        if (ClCheckAccessAddress)
            insertShadowCheck(Addr, &I);

        Value *Shadow = IRB.CreateAlignedLoad(Ty, ShadowPtr, Alignment, "_ldmxcsr");
        pushShadowCheck(Shadow, &I);

    }
    
    void handleMaskedExpandLoad(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Ptr = I.getArgOperand(0);
        Value *Mask = I.getArgOperand(1);
        Value *PassThru = I.getArgOperand(2);

        if (ClCheckAccessAddress) {
            insertShadowCheck(Ptr, &I);
            insertShadowCheck(Mask, &I);
        }

        Type *ShadowTy = getShadowTy(&I);
        Type *ElementShadowTy = cast<VectorType>(ShadowTy)->getElementType();
        Value *ShadowPtr =
            getShadowPtr(Ptr, IRB, ElementShadowTy, Align(1), /*isStore*/ false);

        Value *Shadow = IRB.CreateMaskedExpandLoad(
            ShadowTy, ShadowPtr, Mask, getShadow(PassThru), "_cqmsmaskedexpload");

        setShadow(&I, Shadow);
    }

    void handleMaskedCompressStore(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Values = I.getArgOperand(0);
        Value *Ptr = I.getArgOperand(1);
        Value *Mask = I.getArgOperand(2);

        if (ClCheckAccessAddress) {
            insertShadowCheck(Ptr, &I);
            insertShadowCheck(Mask, &I);
        }

        Value *Shadow = getShadow(Values);
        Type *ElementShadowTy =
            getShadowTy(cast<VectorType>(Values->getType())->getElementType());
        Value *ShadowPtr =
            getShadowPtr(Ptr, IRB, ElementShadowTy, Align(1), /*isStore*/ true);

        IRB.CreateMaskedCompressStore(Shadow, ShadowPtr, Mask);
    }

    void handleMaskedGather(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Ptrs = I.getArgOperand(0);
        const Align Alignment(
            cast<ConstantInt>(I.getArgOperand(1))->getZExtValue());
        Value *Mask = I.getArgOperand(2);
        Value *PassThru = I.getArgOperand(3);

        if (ClCheckAccessAddress) {
            insertShadowCheck(Mask, &I);
            Type *PtrsShadowTy = getShadowTy(Ptrs);
#ifdef CQMSAN_FLIP_CONVENTION
            // [FLIP experiment] inactive-lane fill must be "clean" = all-ones under flip.
            Value *MaskedPtrShadow = IRB.CreateSelect(
                Mask, getShadow(Ptrs), getAllOnesShadow(PtrsShadowTy),
                "_cqmsmaskedptrs");
#else
            Value *MaskedPtrShadow = IRB.CreateSelect(
                Mask, getShadow(Ptrs), Constant::getNullValue(PtrsShadowTy),
                "_cqmsmaskedptrs");
#endif
            pushShadowCheck(MaskedPtrShadow, &I);
        }

        Type *ShadowTy = getShadowTy(&I);
        Type *ElementShadowTy = cast<VectorType>(ShadowTy)->getElementType();
        Value *ShadowPtrs = getShadowPtr(
            Ptrs, IRB, ElementShadowTy, Alignment, /*isStore*/ false);

        Value *Shadow =
            IRB.CreateMaskedGather(ShadowTy, ShadowPtrs, Alignment, Mask,
                                getShadow(PassThru), "_cqmsmaskedgather");
        setShadow(&I, Shadow);
    }

    void handleMaskedScatter(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Values = I.getArgOperand(0);
        Value *Ptrs = I.getArgOperand(1);
        const Align Alignment(
            cast<ConstantInt>(I.getArgOperand(2))->getZExtValue());
        Value *Mask = I.getArgOperand(3);

        if (ClCheckAccessAddress) {
            insertShadowCheck(Mask, &I);
            Type *PtrsShadowTy = getShadowTy(Ptrs);
#ifdef CQMSAN_FLIP_CONVENTION
            // [FLIP experiment] inactive-lane fill must be "clean" = all-ones under flip.
            Value *MaskedPtrShadow = IRB.CreateSelect(
                Mask, getShadow(Ptrs), getAllOnesShadow(PtrsShadowTy),
                "_cqmsmaskedptrs");
#else
            Value *MaskedPtrShadow = IRB.CreateSelect(
                Mask, getShadow(Ptrs), Constant::getNullValue(PtrsShadowTy),
                "_cqmsmaskedptrs");
#endif
            pushShadowCheck(MaskedPtrShadow, &I);
        }

        Value *Shadow = getShadow(Values);
        Type *ElementShadowTy =
            getShadowTy(cast<VectorType>(Values->getType())->getElementType());
        Value *ShadowPtrs = getShadowPtr(
            Ptrs, IRB, ElementShadowTy, Alignment, /*isStore*/ true);

        IRB.CreateMaskedScatter(Shadow, ShadowPtrs, Alignment, Mask);
    }

    void handleMaskedStore(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *V = I.getArgOperand(0);
        Value *Ptr = I.getArgOperand(1);
        const Align Alignment(
            cast<ConstantInt>(I.getArgOperand(2))->getZExtValue());
        Value *Mask = I.getArgOperand(3);
        Value *Shadow = getShadow(V);
        
        if (ClCheckAccessAddress) {
            insertShadowCheck(Ptr, &I);
            insertShadowCheck(Mask, &I);
        }
        
        Value *ShadowPtr;
        ShadowPtr = getShadowPtr(
            Ptr, IRB, Shadow->getType(), Alignment, /*isStore*/ true);

        IRB.CreateMaskedStore(Shadow, ShadowPtr, Alignment, Mask);

        return;
    }

    void handleMaskedLoad(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *Ptr = I.getArgOperand(0);
        const Align Alignment(
            cast<ConstantInt>(I.getArgOperand(1))->getZExtValue());
        Value *Mask = I.getArgOperand(2);
        Value *PassThru = I.getArgOperand(3);

        if (ClCheckAccessAddress) {
            insertShadowCheck(Ptr, &I);
            insertShadowCheck(Mask, &I);
        }

        Type *ShadowTy = getShadowTy(&I);
        Value *ShadowPtr =
            getShadowPtr(Ptr, IRB, ShadowTy, Alignment, /*isStore*/ false);
        setShadow(&I, IRB.CreateMaskedLoad(ShadowTy, ShadowPtr, Alignment, Mask,
                                        getShadow(PassThru), "_cqmsmaskedld"));

        return;
    }
    
    void visitIntrinsicInst(IntrinsicInst &I) {
        switch (I.getIntrinsicID()) {
            case Intrinsic::lifetime_start:
                handleLifetimeStart(I);
            break;
            case Intrinsic::launder_invariant_group:
            case Intrinsic::strip_invariant_group:
                setShadow(&I, getShadow(I.getArgOperand(0))); // Best C++ coverage with std::launder 
            break;
            case Intrinsic::masked_compressstore:
                handleMaskedCompressStore(I);
            break;
            case Intrinsic::masked_expandload:
                handleMaskedExpandLoad(I);
            break;
            case Intrinsic::masked_gather:
                handleMaskedGather(I);
            break;
            case Intrinsic::masked_scatter:
                handleMaskedScatter(I);
            break;
            case Intrinsic::masked_store:
                handleMaskedStore(I);
            break;
            case Intrinsic::masked_load:
                handleMaskedLoad(I);
            break;
            case Intrinsic::is_constant:
                // The result of llvm.is.constant() is always defined.
                setShadow(&I, getCleanShadow(&I));
            break;
            case Intrinsic::x86_sse_stmxcsr:
                handleStmxcsr(I);
            break;
            case Intrinsic::x86_sse_ldmxcsr:
                handleLdmxcsr(I);
            break;
            default:
                if (!handleUnknownIntrinsic(I))
                    visitInstruction(I);
                break;
        }
    }

    void visitLibAtomicLoad(CallBase &CB) {
        // Since we use getNextNode here, we can't have CB terminate the BB.
        assert(isa<CallInst>(CB));

        IRBuilder<> IRB(&CB);
        Value *Size = CB.getArgOperand(0);
        Value *SrcPtr = CB.getArgOperand(1);
        Value *DstPtr = CB.getArgOperand(2);
        Value *Ordering = CB.getArgOperand(3);
        // Convert the call to have at least Acquire ordering to make sure
        // the shadow operations aren't reordered before it.
        Value *NewOrdering =
            IRB.CreateExtractElement(makeAddAcquireOrderingTable(IRB), Ordering);
        CB.setArgOperand(3, NewOrdering);

        NextNodeIRBuilder NextIRB(&CB);
        Value *SrcShadowPtr =
            getShadowPtr(SrcPtr, NextIRB, NextIRB.getInt8Ty(), Align(1),
                                /*isStore*/ false);
        Value *DstShadowPtr =
            getShadowPtr(DstPtr, NextIRB, NextIRB.getInt8Ty(), Align(1),
                                /*isStore*/ true);

        NextIRB.CreateMemCpy(DstShadowPtr, Align(1), SrcShadowPtr, Align(1), Size);
    }

    void visitLibAtomicStore(CallBase &CB) {
        IRBuilder<> IRB(&CB);
        Value *Size = CB.getArgOperand(0);
        Value *DstPtr = CB.getArgOperand(2);
        Value *Ordering = CB.getArgOperand(3);
        // Convert the call to have at least Release ordering to make sure
        // the shadow operations aren't reordered after it.
        Value *NewOrdering =
            IRB.CreateExtractElement(makeAddReleaseOrderingTable(IRB), Ordering);
        CB.setArgOperand(3, NewOrdering);

        Value *DstShadowPtr =
            getShadowPtr(DstPtr, IRB, IRB.getInt8Ty(), Align(1),
                                /*isStore*/ true);

        // Atomic store always paints clean shadow/origin. See file header.
        IRB.CreateMemSet(DstShadowPtr, getCleanShadow(IRB.getInt8Ty()), Size,
                        Align(1));
    }

    void visitCallBase(CallBase &CB) {
        assert(!CB.getMetadata(LLVMContext::MD_nosanitize));

        // 1. Inline ASM dispatch
        if (CB.isInlineAsm()) {
            if (ClHandleAsmConservative)
                visitAsmInstruction(CB);
            else
                visitInstruction(CB);
            return;
        }

        // 2. LibAtomic dispatch (memory ops via TCG-style libcall)
        LibFunc LF;
        if (TLI->getLibFunc(CB, LF)) {
            switch (LF) {
                case LibFunc_atomic_load:
                    if (!isa<CallInst>(CB)) {
                        llvm::errs() << "CQMSAN -- cannot instrument invoke of "
                                        "libatomic load. Ignoring!\n";
                        break;
                    }
                    visitLibAtomicLoad(CB);
                    return;
                case LibFunc_atomic_store:
                    visitLibAtomicStore(CB);
                    return;
                default:
                    break;
            }
        }

        // 3. Remove ReadOnly / Speculatable to prevent the optimizer from
        //    dropping our instrumentation.
        if (auto *Call = dyn_cast<CallInst>(&CB)) {
            assert(!isa<IntrinsicInst>(Call) && "intrinsics are handled elsewhere");

            AttributeMask B;
            B.addAttribute(Attribute::Memory).addAttribute(Attribute::Speculatable);

            Call->removeFnAttrs(B);
            if (Function *Func = Call->getCalledFunction()) {
                Func->removeFnAttrs(B);
            }

            maybeMarkSanitizerLibraryCallNoBuiltin(Call, TLI);
        }

        IRBuilder<> IRB(&CB);

        bool MayCheckCall = CQMS.EagerChecks;

        if (Function *Func = CB.getCalledFunction()) {
            // __sanitizer_unaligned_{load,store} functions may be called by users
            // and always expects shadows in the TLS. So don't check them.
            MayCheckCall &= !Func->getName().starts_with("__sanitizer_unaligned_");
        }

        // 5. VarArgs handling — SIZE-ONLY (opportunistic).
        //    No shadow is propagated: the helper only tells the callee how big
        //    the overflow area is (1 i64 TLS store), so va_start can unpoison
        //    the stack-passed varargs too. See VarArgAMD64Helper::visitCallBase.
        FunctionType *FT = CB.getFunctionType();
        if (FT->isVarArg()) {
            VAHelper->visitCallBase(CB, IRB);
        }

        // 6. Return value handling — TrustReturn policy
        //    if ClTrustReturn → clean; else → pre-zero + load dalla TLS
        //    In-module callees → read shadow from retval TLS (callee writes it).
        if (!CB.getType()->isSized()) return;
        if (isa<CallInst>(CB) && cast<CallInst>(CB).isMustTailCall())
            return;

        if (MayCheckCall && CB.hasRetAttr(Attribute::NoUndef)) {
            setShadow(&CB, getCleanShadow(&CB));
            return;
        }

        Function *CalledFunc = CB.getCalledFunction();
        //bool TrustReturn = !CalledFunc || CalledFunc->isDeclaration();
        //bool TrustReturn = true;

        if (ClTrustReturn) {
            setShadow(&CB, getCleanShadow(&CB));
            return;
        }

        // Pre-zero RetvalTLS: defensive for internal calls that might be
        // nosanitized (do not write TLS). If the call is instrumented, it will overwrite.
        // LLVM DSE deletes this store if it is dead.
        IRBuilder<> IRBBefore(&CB);
        IRBBefore.CreateAlignedStore(getCleanShadow(&CB), getShadowPtrForRetval(IRBBefore),
                                        kShadowTLSAlignment);

        // In-module callee: load shadow from retval TLS after the call.
        //
        // Two cases:
        //  - CallInst: next instruction in the same BB
        //  - InvokeInst: NormalDest BB (the "no exception" path). We insert the load
        //    at the beginning of NormalDest, but only if NormalDest has a single
        //    predecessor (avoids cross-edge complications).
        BasicBlock::iterator NextInsn;
        if (isa<CallInst>(CB)) {
            NextInsn = ++CB.getIterator();
            assert(NextInsn != CB.getParent()->end());
        } else {
            // InvokeInst: terminator of the BB. The retval is consumed in the
            // NormalDest BB ("success" continuation; exception path goes to UnwindDest).
            BasicBlock *NormalDest = cast<InvokeInst>(CB).getNormalDest();
            if (!NormalDest->getSinglePredecessor()) {
                // NormalDest has multiple predecessors (e.g., merged from multiple
                // invokes). Inserting the retval-shadow load at its start would
                // incorrectly apply to all incoming paths. Conservative fallback:
                // assume clean. To improve precision we would need to split the edge
                // between this BB and NormalDest (SplitEdge), but that introduces
                // its own complications. See MSan upstream FIXME.
                setShadow(&CB, getCleanShadow(&CB));
                return;
            }
            NextInsn = NormalDest->getFirstInsertionPt();
            assert(NextInsn != NormalDest->end() &&
                "Could not find insertion point for retval shadow load");
        }

        IRBuilder<> IRBAfter(&*NextInsn);
        Value *RetvalShadow = IRBAfter.CreateAlignedLoad(
            getShadowTy(&CB),
            getShadowPtrForRetval(IRBAfter),
            kShadowTLSAlignment,
            "_cqmsret");
        setShadow(&CB, RetvalShadow);

    }

    // Helper: detect if V is the result of a musttail call.
    // Skip writing retval TLS for these (mustTail ABI propagates return directly).
    static bool isAMustTailRetVal(Value *RetVal) {
        if (auto *I = dyn_cast<BitCastInst>(RetVal)) {
            RetVal = I->getOperand(0);
        }
        if (auto *I = dyn_cast<CallInst>(RetVal)) {
            return I->isMustTailCall();
        }
        return false;
    }

    // [OPPORTUNISTIC 2026-07-29] Lightweight return-value SINK check.
    //
    // Why this exists: removing eager return handling entirely (no check, no
    // retval-TLS store — see visitCallBase's TrustReturn fast path) left one
    // real, measured soundness gap: a local that mem2reg promotes straight to a
    // register (never touching memory, e.g. `int x; if (c) x = 5; return x;`)
    // can carry a PHI with a genuine `undef` incoming edge all the way to a
    // `ret`, with NO load ever occurring on that path — so check-at-load can
    // never observe it. Census across 4 targets (re2, json, pcre2, c-ares)
    // found this pattern live on 2/4 (pcre2 2/80 = 2.5%, c-ares 1/41 = 2.4% of
    // phi-valued returns) — small but real and reproducible.
    //
    // The fix is a SINK check, symmetric to why PHI itself is kept: it costs
    // nothing extra at runtime for the ~100% of returns whose shadow is
    // provably clean (constant-shadow checks are folded/DCE'd — same argument
    // as the old eager-check comment), and it does NOT reintroduce the
    // retval-TLS propagation machinery: the caller side is untouched, still
    // always assumes clean (ClTrustReturn policy in visitCallBase, unchanged).
    // Gated on NoUndef exactly like the old eager-check was, to keep the
    // false-positive surface unchanged (a non-noundef return is not asserted
    // to be fully defined by the ABI, so we must not flag it opportunistically).
    void visitReturnInst(ReturnInst &I) {
#ifdef CQMSAN_FLIP_CONVENTION
        // [FLIP experiment] Known, documented limitation, not fixed: for a
        // NoUndef-returning function whose return value isn't specifically
        // propagated (e.g. an arithmetic result — "no propagation" means
        // getShadow() defaults such values to getCleanShadow()), this check
        // ends up materialized as an unconditional call to the warning
        // handler instead of being folded away like the non-flip case (where
        // the equivalent constant-shadow check is discarded by
        // insertShadowCheck's dyn_cast<Instruction> filter before ever
        // reaching codegen). Root cause not isolated within this
        // experiment's time budget — the return-check machinery is optional
        // (§9.C in the AUDIT), so it's disabled here rather than shipped
        // broken; the load-check + static-range mechanism this experiment
        // is actually testing is unaffected.
        return;
#else
        Value *RetVal = I.getReturnValue();
        if (!RetVal) return;                       // void return
        if (isAMustTailRetVal(RetVal)) return;     // mustTail

        if (F.hasRetAttribute(Attribute::NoUndef))
            insertShadowCheck(RetVal, &I);

        // No retval-TLS store: the caller always assumes clean (ClTrustReturn=true)
#endif
    }
    
    void visitPHINode(PHINode &I) {
        IRBuilder<> IRB(&I);
        ShadowPHINodes.push_back(&I);
        setShadow(&I, IRB.CreatePHI(getShadowTy(&I), I.getNumIncomingValues(), "_cqmsphi_s"));
    }

    void poisonAllocaUserspace(AllocaInst &I, IRBuilder<> &IRB, Value *Len) {
        if (PoisonStack && ClPoisonStackWithCall) {
            IRB.CreateCall(CQMS.CQMSanPoisonStackFn, {&I, Len});
        } else {
            // If not PoisonStack fill with zeroes (cleaned)
            Value *ShadowBase = getShadowPtr(
                &I, IRB, IRB.getInt8Ty(), Align(1), /*isStore*/ true);

#ifdef CQMSAN_FLIP_CONVENTION
            // [FLIP experiment] 0=uninit: poison/clean bytes are bit-complements
            // of the non-flipped ones (default 0xff poison -> 0x00; clean
            // fallback 0x00 -> 0xff).
            Value *PoisonValue = IRB.getInt8(PoisonStack ? (uint8_t)~ClPoisonStackPattern : 0xff);
#else
            Value *PoisonValue = IRB.getInt8(PoisonStack ? ClPoisonStackPattern : 0);
#endif
            IRB.CreateMemSet(ShadowBase, PoisonValue, Len, I.getAlign());
        }
    }
    
    void instrumentAlloca(AllocaInst &I, Instruction *InsPoint = nullptr) {
        if (!InsPoint)
            InsPoint = &I;
        
        NextNodeIRBuilder IRB(InsPoint);
        const DataLayout &DL = F.getDataLayout();
        TypeSize TS = DL.getTypeAllocSize(I.getAllocatedType());
        Value *Len = IRB.CreateTypeSize(CQMS.IntptrTy, TS);
        
        if (I.isArrayAllocation())
            Len = IRB.CreateMul(Len,
                        IRB.CreateZExtOrTrunc(I.getArraySize(), CQMS.IntptrTy));
        
        poisonAllocaUserspace(I, IRB, Len);
    }
    
    void visitAllocaInst(AllocaInst &I) {
        setShadow(&I, getCleanShadow(&I));
        // We'll get to this alloca later unless it's poisoned at the corresponding
        // llvm.lifetime.start.
        AllocaSet.insert(&I);
    }

    void instrumentAsmArgument(Value *Operand, Type *ElemTy, Instruction &I,
                                IRBuilder<> &IRB, const DataLayout &DL,
                                bool isOutput) {
        // For each assembly argument, we check its value for being initialized.
        // If the argument is a pointer, we assume it points to a single element
        // of the corresponding type (or to a 8-byte word, if the type is unsized).
        // Each such pointer is instrumented with a call to the runtime library.
        Type *OpType = Operand->getType();
        // Check the operand value itself.
        // TODO - removed, opportunistic only unpoison the output. // insertShadowCheck(Operand, &I);
        if (!OpType->isPointerTy() || !isOutput) {
            assert(!isOutput);
            return;
        }
        if (!ElemTy->isSized())
            return;
        auto Size = DL.getTypeStoreSize(ElemTy);
        Value *SizeVal = IRB.CreateTypeSize(CQMS.IntptrTy, Size);
        
        // ElemTy, derived from elementtype(), does not encode the alignment of
        // the pointer. Conservatively assume that the shadow memory is unaligned.
        // When Size is large, avoid StoreInst as it would expand to many
        // instructions.
        auto ShadowPtr =
            getShadowPtrUserspace(Operand, IRB, IRB.getInt8Ty(), Align(1));
        if (Size <= 32)
            IRB.CreateAlignedStore(getCleanShadow(ElemTy), ShadowPtr, Align(1));
        else
            IRB.CreateMemSet(ShadowPtr, ConstantInt::getNullValue(IRB.getInt8Ty()),
                            SizeVal, Align(1));
        
    }

    /// Get the number of output arguments returned by pointers.
    int getNumOutputArgs(InlineAsm *IA, CallBase *CB) {
        int NumRetOutputs = 0;
        int NumOutputs = 0;
        Type *RetTy = cast<Value>(CB)->getType();
        if (!RetTy->isVoidTy()) {
            // Register outputs are returned via the CallInst return value.
            auto *ST = dyn_cast<StructType>(RetTy);
            if (ST)
                NumRetOutputs = ST->getNumElements();
            else
                NumRetOutputs = 1;
        }
        InlineAsm::ConstraintInfoVector Constraints = IA->ParseConstraints();
        for (const InlineAsm::ConstraintInfo &Info : Constraints) {
            switch (Info.Type) {
                case InlineAsm::isOutput:
                    NumOutputs++;
                    break;
                default:
                    break;
            }
        }
        return NumOutputs - NumRetOutputs;
    }

    void visitAsmInstruction(Instruction &I) {
        // Conservative inline assembly handling: check for poisoned shadow of
        // asm() arguments, then unpoison the result and all the memory locations
        // pointed to by those arguments.
        // An inline asm() statement in C++ contains lists of input and output
        // arguments used by the assembly code. These are mapped to operands of the
        // CallInst as follows:
        //  - nR register outputs ("=r) are returned by value in a single structure
        //  (SSA value of the CallInst);
        //  - nO other outputs ("=m" and others) are returned by pointer as first
        // nO operands of the CallInst;
        //  - nI inputs ("r", "m" and others) are passed to CallInst as the
        // remaining nI operands.
        // The total number of asm() arguments in the source is nR+nO+nI, and the
        // corresponding CallInst has nO+nI+1 operands (the last operand is the
        // function to be called).
        const DataLayout &DL = F.getDataLayout();
        CallBase *CB = cast<CallBase>(&I);
        IRBuilder<> IRB(&I);
        InlineAsm *IA = cast<InlineAsm>(CB->getCalledOperand());
        int OutputArgs = getNumOutputArgs(IA, CB);
        // The last operand of a CallInst is the function itself.
        int NumOperands = CB->getNumOperands() - 1;

        // Check input arguments. Doing so before unpoisoning output arguments, so
        // that we won't overwrite uninit values before checking them.
        for (int i = OutputArgs; i < NumOperands; i++) {
            Value *Operand = CB->getOperand(i);
            instrumentAsmArgument(Operand, CB->getParamElementType(i), I, IRB, DL,
                                    /*isOutput*/ false);
        }

        // Unpoison output arguments. This must happen before the actual InlineAsm
        // call, so that the shadow for memory published in the asm() statement
        // remains valid.
        for (int i = 0; i < OutputArgs; i++) {
            Value *Operand = CB->getOperand(i);
            instrumentAsmArgument(Operand, CB->getParamElementType(i), I, IRB, DL,
                                    /*isOutput*/ true);
        }

        setShadow(&I, getCleanShadow(&I));

    }

    void visitInstruction(Instruction &I) {
        // Everything else (instructions not explicitly handled by the visitor):
        // opportunistic policy → no eager checks. Just mark the result as clean.
        // UMR detection is delegated to load-site checks (visitLoadInst).
        LLVM_DEBUG(dbgs() << "DEFAULT: " << I << "\n");

        // Skip instructions whose type is not sized (e.g. void) or whose
        // shadow type cannot be computed (rare cases like landingpad tokens).
        // Without this guard, setShadow may fail downstream or generate
        // malformed IR for tokens/metadata-like values.
        if (!I.getType()->isSized())
            return;

        setShadow(&I, getCleanShadow(&I));
    }
    
};

struct VarArgHelperBase : public VarArgHelper {
    Function &F;
    CompilerQEMUMemorySanitizer &CQMS;
    CompilerQEMUMemorySanitizerVisitor &CQMSV;
    SmallVector<CallInst *, 16> VAStartInstrumentationList;
    const unsigned VAListTagSize;

    VarArgHelperBase(Function &F, CompilerQEMUMemorySanitizer &CQMS,
                    CompilerQEMUMemorySanitizerVisitor &CQMSV, unsigned VAListTagSize)
        : F(F), CQMS(CQMS), CQMSV(CQMSV), VAListTagSize(VAListTagSize) {}

    Value *getShadowAddrForVAArgument(IRBuilder<> &IRB, unsigned ArgOffset) {
        Value *Base = IRB.CreatePointerCast(CQMS.VAArgTLS, CQMS.IntptrTy);
        return IRB.CreateAdd(Base, ConstantInt::get(CQMS.IntptrTy, ArgOffset));
    }

    /// Compute the shadow address for a given va_arg.
    Value *getShadowPtrForVAArgument(IRBuilder<> &IRB, unsigned ArgOffset) {
        Value *Base = IRB.CreatePointerCast(CQMS.VAArgTLS, CQMS.IntptrTy);
        Base = IRB.CreateAdd(Base, ConstantInt::get(CQMS.IntptrTy, ArgOffset));
        return IRB.CreateIntToPtr(Base, CQMS.PtrTy, "_cqmsarg_va_s");
    }

    /// Compute the shadow address for a given va_arg.
    Value *getShadowPtrForVAArgument(IRBuilder<> &IRB, unsigned ArgOffset,
                                    unsigned ArgSize) {
        // Make sure we don't overflow __cqmsan_va_arg_tls.
        if (ArgOffset + ArgSize > kParamTLSSize)
            return nullptr;
        return getShadowPtrForVAArgument(IRB, ArgOffset);
    }

    void CleanUnusedTLS(IRBuilder<> &IRB, Value *ShadowBase,
                      unsigned BaseOffset) {
        // The tails of __cqmsan_va_arg_tls is not large enough to fit full
        // value shadow, but it will be copied to backup anyway. Make it
        // clean.
        if (BaseOffset >= kParamTLSSize)
            return;
        Value *TailSize =
            ConstantInt::getSigned(IRB.getInt32Ty(), kParamTLSSize - BaseOffset);
        IRB.CreateMemSet(ShadowBase, ConstantInt::getNullValue(IRB.getInt8Ty()),
                        TailSize, Align(8));
    }

    void unpoisonVAListTagForInst(IntrinsicInst &I) {
        IRBuilder<> IRB(&I);
        Value *VAListTag = I.getArgOperand(0);
        const Align Alignment = Align(8);
        auto ShadowPtr = CQMSV.getShadowPtr(
            VAListTag, IRB, IRB.getInt8Ty(), Alignment, /*isStore*/ true);

        // Unpoison the whole __va_list_tag.
        IRB.CreateMemSet(ShadowPtr, Constant::getNullValue(IRB.getInt8Ty()),
                        VAListTagSize, Alignment, false);
    }

    void visitVAStartInst(VAStartInst &I) override {
        if (F.getCallingConv() == CallingConv::Win64)
            return;
        VAStartInstrumentationList.push_back(&I);
        unpoisonVAListTagForInst(I);
    }

    void visitVACopyInst(VACopyInst &I) override {
        if (F.getCallingConv() == CallingConv::Win64)
            return;
        unpoisonVAListTagForInst(I);
    }
};

// TODO - remove if not used after the modifications on visitCallBase
/// AMD64-specific implementation of VarArgHelper.
struct VarArgAMD64Helper : public VarArgHelperBase {
  // An unfortunate workaround for asymmetric lowering of va_arg stuff.
  // See a comment in visitCallBase for more details.
  static const unsigned AMD64GpEndOffset = 48; // AMD64 ABI Draft 0.99.6 p3.5.7
  static const unsigned AMD64FpEndOffsetSSE = 176;
  // If SSE is disabled, fp_offset in va_list is zero.
  static const unsigned AMD64FpEndOffsetNoSSE = AMD64GpEndOffset;

  unsigned AMD64FpEndOffset;
  AllocaInst *VAArgTLSCopy = nullptr;
  AllocaInst *VAArgTLSOriginCopy = nullptr;
  Value *VAArgOverflowSize = nullptr;

  enum ArgKind { AK_GeneralPurpose, AK_FloatingPoint, AK_Memory };

    VarArgAMD64Helper(Function &F, CompilerQEMUMemorySanitizer &CQMS,
                        CompilerQEMUMemorySanitizerVisitor &CQMSV)
        : VarArgHelperBase(F, CQMS, CQMSV, /*VAListTagSize=*/24) {

        AMD64FpEndOffset = AMD64FpEndOffsetSSE;
        for (const auto &Attr : F.getAttributes().getFnAttrs()) {
            if (Attr.isStringAttribute() &&
                (Attr.getKindAsString() == "target-features")) {
                    if (Attr.getValueAsString().contains("-sse"))
                    AMD64FpEndOffset = AMD64FpEndOffsetNoSSE;
                    break;
            }
        }
    }

    ArgKind classifyArgument(Value *arg) {
        // A very rough approximation of X86_64 argument classification rules.
        Type *T = arg->getType();
        if (T->isX86_FP80Ty())
            return AK_Memory;
        if (T->isFPOrFPVectorTy())
            return AK_FloatingPoint;
        if (T->isIntegerTy() && T->getPrimitiveSizeInBits() <= 64)
            return AK_GeneralPurpose;
        if (T->isPointerTy())
            return AK_GeneralPurpose;
            
        return AK_Memory;
    }

    // [OPPORTUNISTIC 28/07] Size-only varargs handling.
    // The old MSan design stored each vararg's SHADOW into __cqmsan_va_arg_tls
    // (shadow propagation through the call). Opportunistic CQMSan does not
    // propagate through calls, but the callee still needs to know HOW BIG the
    // overflow area (stack-passed varargs, beyond 6 GP / 8 FP registers) is:
    // the caller's argument stores happen at machine level and never update
    // shadow, so without unpoisoning that area at va_start the callee's va_arg
    // loads would read STALE (possibly poisoned) shadow -> false positives.
    // We walk the args with the AMD64 ABI classification purely at COMPILE
    // time and emit a single i64 store of the overflow size. The va_arg TLS
    // itself is never written (stays zero), so finalizeInstrumentation
    // degenerates into unpoison-on-write of reg-save area + overflow area.
    void visitCallBase(CallBase &CB, IRBuilder<> &IRB) override {
        unsigned GpOffset = 0;
        unsigned FpOffset = AMD64GpEndOffset;
        unsigned OverflowOffset = AMD64FpEndOffset;
        const DataLayout &DL = F.getDataLayout();

        for (const auto &[ArgNo, A] : llvm::enumerate(CB.args())) {
            bool IsFixed = ArgNo < CB.getFunctionType()->getNumParams();
            bool IsByVal = CB.paramHasAttr(ArgNo, Attribute::ByVal);

            if (IsByVal) {
                // ByVal arguments always go to the overflow area.
                // Fixed arguments passed through the overflow area will be stepped
                // over by va_start, so don't count them towards the offset.
                if (IsFixed)
                    continue;
                assert(A->getType()->isPointerTy());
                Type *RealTy = CB.getParamByValType(ArgNo);
                OverflowOffset += alignTo(DL.getTypeAllocSize(RealTy), 8);
            } else {
                ArgKind AK = classifyArgument(A);
                if (AK == AK_GeneralPurpose && GpOffset >= AMD64GpEndOffset)
                    AK = AK_Memory;
                if (AK == AK_FloatingPoint && FpOffset >= AMD64FpEndOffset)
                    AK = AK_Memory;

                switch (AK) {
                    // Fixed args consume GP/FP slots too: they must be counted
                    // so later varargs spill to memory at the right point.
                    case AK_GeneralPurpose:
                        GpOffset += 8;
                        break;
                    case AK_FloatingPoint:
                        FpOffset += 16;
                        break;
                    case AK_Memory:
                        // Fixed stack args are stepped over by va_start.
                        if (IsFixed)
                            continue;
                        OverflowOffset += alignTo(DL.getTypeAllocSize(A->getType()), 8);
                        break;
                }
            }
        }

        Constant *OverflowSize =
            ConstantInt::get(IRB.getInt64Ty(), OverflowOffset - AMD64FpEndOffset);

        IRB.CreateStore(OverflowSize, CQMS.VAArgOverflowSizeTLS);
    }

    void finalizeInstrumentation() override {
        assert(!VAArgOverflowSize && !VAArgTLSCopy &&
            "finalizeInstrumentation called twice");
        
        if (!VAStartInstrumentationList.empty()) {
            // If there is a va_start in this function, make a backup copy of
            // va_arg_tls somewhere in the function entry block.
            IRBuilder<> IRB(CQMSV.FnPrologueEnd);
            
            VAArgOverflowSize =
                IRB.CreateLoad(IRB.getInt64Ty(), CQMS.VAArgOverflowSizeTLS);
            
            Value *CopySize = IRB.CreateAdd(
                ConstantInt::get(CQMS.IntptrTy, AMD64FpEndOffset), VAArgOverflowSize);
            
            VAArgTLSCopy = IRB.CreateAlloca(Type::getInt8Ty(*CQMS.C), CopySize);
            VAArgTLSCopy->setAlignment(kShadowTLSAlignment);

            IRB.CreateMemSet(VAArgTLSCopy, Constant::getNullValue(IRB.getInt8Ty()),
                            CopySize, kShadowTLSAlignment, false);

            Value *SrcSize = IRB.CreateBinaryIntrinsic(
                Intrinsic::umin, CopySize,
                ConstantInt::get(CQMS.IntptrTy, kParamTLSSize));
            IRB.CreateMemCpy(VAArgTLSCopy, kShadowTLSAlignment, CQMS.VAArgTLS,
                            kShadowTLSAlignment, SrcSize);
            
        }

        // Instrument va_start.
        // Copy va_list shadow from the backup copy of the TLS contents.
        for (CallInst *OrigInst : VAStartInstrumentationList) {
            NextNodeIRBuilder IRB(OrigInst);
            Value *VAListTag = OrigInst->getArgOperand(0);

            Value *RegSaveAreaPtrPtr = IRB.CreateIntToPtr(
                IRB.CreateAdd(IRB.CreatePtrToInt(VAListTag, CQMS.IntptrTy),
                                ConstantInt::get(CQMS.IntptrTy, 16)),
                CQMS.PtrTy);
            
            Value *RegSaveAreaPtr = IRB.CreateLoad(CQMS.PtrTy, RegSaveAreaPtrPtr);

            Value *RegSaveAreaShadowPtr;
            const Align Alignment = Align(16);
            RegSaveAreaShadowPtr =
                    CQMSV.getShadowPtr(RegSaveAreaPtr, IRB, IRB.getInt8Ty(),
                                        Alignment, /*isStore*/ true);

            IRB.CreateMemCpy(RegSaveAreaShadowPtr, Alignment, VAArgTLSCopy, Alignment,
                            AMD64FpEndOffset);
            
            Value *OverflowArgAreaPtrPtr = IRB.CreateIntToPtr(
                IRB.CreateAdd(IRB.CreatePtrToInt(VAListTag, CQMS.IntptrTy),
                                ConstantInt::get(CQMS.IntptrTy, 8)),
                CQMS.PtrTy);

            Value *OverflowArgAreaPtr =
                IRB.CreateLoad(CQMS.PtrTy, OverflowArgAreaPtrPtr);

            Value *OverflowArgAreaShadowPtr =
                CQMSV.getShadowPtr(OverflowArgAreaPtr, IRB, IRB.getInt8Ty(),
                                        Alignment, /*isStore*/ true);

            Value *SrcPtr = IRB.CreateConstGEP1_32(IRB.getInt8Ty(), VAArgTLSCopy,
                                                    AMD64FpEndOffset);
            IRB.CreateMemCpy(OverflowArgAreaShadowPtr, Alignment, SrcPtr, Alignment,
                            VAArgOverflowSize);
            
        }
    }
};

/// A no-op implementation of VarArgHelper.
///
/// Used on architectures other than x86_64 where CQMSAN does not propagate
/// shadow through variadic boundaries. To reduce false positives, this
/// implementation still unpoisons the va_list_tag at va_start; everything
/// else is a true no-op.
struct VarArgNoOpHelper : public VarArgHelper {
    Function &F;
    CompilerQEMUMemorySanitizer &CQMS;
    CompilerQEMUMemorySanitizerVisitor &CQMSV;

    VarArgNoOpHelper(Function &F, CompilerQEMUMemorySanitizer &CQMS,
                     CompilerQEMUMemorySanitizerVisitor &CQMSV)
        : F(F), CQMS(CQMS), CQMSV(CQMSV) {}

    void visitCallBase(CallBase &CB, IRBuilder<> &IRB) override {}

    void visitVAStartInst(VAStartInst &I) override {
        // Unpoison the va_list_tag to avoid false positives.
        // 32 bytes is a conservative size for most non-x86_64 ABIs
        // (AArch64 va_list_tag = 32B; smaller for PPC64/MIPS64).
        IRBuilder<> IRB(&I);
        Value *VAListTag = I.getArgOperand(0);
        const Align Alignment = Align(8);

        Value *ShadowPtr = CQMSV.getShadowPtr(
            VAListTag, IRB, IRB.getInt8Ty(), Alignment, /*isStore*/ true);

        IRB.CreateMemSet(ShadowPtr,
                         Constant::getNullValue(IRB.getInt8Ty()),
                         ConstantInt::get(CQMS.IntptrTy, 32),
                         Alignment);
    }

    void visitVACopyInst(VACopyInst &I) override {}

    void finalizeInstrumentation() override {}
};

} // end anonymous namespace 

static VarArgHelper *CreateVarArgHelper(Function &Func, CompilerQEMUMemorySanitizer &CQMSan,
                                        CompilerQEMUMemorySanitizerVisitor &Visitor) {
    // VarArg handling is only implemented on AMD64. False positives are
    // possible on other platforms (mitigated by VarArgNoOpHelper unpoisoning
    // the va_list_tag at va_start).
    Triple TargetTriple(Func.getParent()->getTargetTriple());

    if (TargetTriple.getArch() == Triple::x86_64)
        return new VarArgAMD64Helper(Func, CQMSan, Visitor);

    return new VarArgNoOpHelper(Func, CQMSan, Visitor);
}


//____________________________________________________________________________________//
//____________________________________________________________________________________//
//_________________________________ LLVM PASS ________________________________________//
//____________________________________________________________________________________//
//____________________________________________________________________________________//

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
    return {LLVM_PLUGIN_API_VERSION, "CompilerQEMUMemorySanitizer",
            LLVM_VERSION_STRING,
        [](PassBuilder &PB) {
            // 1) Manual registration: `opt -passes=cqmsan`
            PB.registerPipelineParsingCallback(
                [](StringRef Name, ModulePassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                    if (Name == "cqmsan") {
                        CompilerQEMUMemorySanitizerOptions Opts(ClKeepGoing, ClEagerChecks);
                        MPM.addPass(CompilerQEMUMemorySanitizerPass(Opts));
                        return true;
                    }
                    return false;
                });
            
           
            // 2) Auto-injection at the END of the optimization pipeline
            //    (consistent with MSan upstream, which uses OptimizerLastEPCallback
            //    to prevent post-instrumentation optimizations from interfering
            //    with shadow propagation).
            PB.registerOptimizerLastEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                    CompilerQEMUMemorySanitizerOptions Opts(ClKeepGoing, ClEagerChecks);
                    MPM.addPass(CompilerQEMUMemorySanitizerPass(Opts));

                    // Replicate MSan upstream's post-instrumentation cleanup pipeline.
                    // Source: clang/lib/CodeGen/BackendUtil.cpp::addSanitizers().
                    if (Level != OptimizationLevel::O0) {
                        MPM.addPass(RequireAnalysisPass<GlobalsAA, Module>());
                        FunctionPassManager FPM;
                        FPM.addPass(EarlyCSEPass(true /* mem-ssa */));
                        FPM.addPass(InstCombinePass());
                        FPM.addPass(JumpThreadingPass());
                        FPM.addPass(GVNPass());
                        FPM.addPass(InstCombinePass());
                        MPM.addPass(createModuleToFunctionPassAdaptor(std::move(FPM)));
                    }
                });
        }
    };
}

// ---------------------------------------------------------------------------
// Compile-time function ignorelist.
//
// WHY THIS EXISTS:
// CQMSan runs as an out-of-tree pass loaded with -fpass-plugin, NOT via
// -fsanitize=memory. That has two consequences the frontend would normally
// handle for us:
//   1. Clang never attaches Attribute::SanitizeMemory to functions, so the
//      Visitor force-adds it unconditionally (see the Visitor constructor).
//   2. Clang never consults a sanitizer ignorelist, so nothing is excluded.
// Combined, that means EVERY function gets instrumented, including code that
// must not be. This gate restores the exclusion: sanitizeFunction() calls it
// BEFORE building the Visitor, so an ignored function never reaches the
// force-add and stays completely untouched.
//
// This is the compile-time analogue of QMSan's runtime exclusion of non-app
// code. Difference in granularity: QMSan filters dynamically, per memory
// access, by PC; this filters statically, all-or-nothing per function. Same
// intent (skip non-target code), coarser knob.
//
// TWO LAYERS:
//   - A hardcoded default that is ALWAYS active (the equivalent of upstream
//     msan_ignorelist.txt). Currently just __gxx_personality_*: it is invoked
//     by the uninitialized/uninstrumented C++ unwinder, so instrumenting it
//     produces false positives on every exception unwind.
//   - An opt-in list from the CQMSAN_IGNORELIST env var. Same file syntax as
//     -fsanitize-ignorelist= (LLVM SpecialCaseList). Lines with no [section]
//     header apply to any query:
//         fun:GLOB   skip functions whose IR name matches GLOB
//         src:GLOB   skip functions whose source file matches GLOB
//     Not set => no extra exclusions (pure opt-in, no behavior change).
//     Note: src: only works with debug info (-g); the path is reconstructed
//     from DISubprogram and may not match the frontend's src: semantics, so
//     prefer wide globs (src:*runner.cc*) over exact paths.
//
// EFFECT AND DANGER:
// An ignored function receives NO instrumentation at all (no stack/alloca
// poisoning, no shadow stores, no load checks) — as if the plugin never ran
// on it. Because we do not propagate shadow (0 = initialized), this cuts BOTH
// ways depending on the buffer's shadow baseline:
//   - False negative: an ignored function writes a clean-baseline buffer
//     (stack/global). Its shadow stays 0. If the data was actually uninit and
//     is later read by instrumented code, the UMR is lost.
//   - False positive: an ignored function fills a poisoned-baseline buffer
//     (e.g. heap from malloc, which the allocator poisons) via its own
//     compiled stores. The shadow stays poisoned, so instrumented code reading
//     it reports a spurious UMR (wasted Valgrind replay). Mitigated when the
//     fill goes through an intercepted libc call (memcpy/read/...), since the
//     interceptor unpoisons the destination.
// Rule of thumb: only ignore harness/driver code that does not produce values
// consumed downstream. NEVER ignore the fuzz-target functions.
// ---------------------------------------------------------------------------
static const SpecialCaseList *getCQMSanIgnorelist() {
    
    static const std::unique_ptr<SpecialCaseList> List = [] {

        const char *Path = std::getenv("CQMSAN_IGNORELIST");
        if (!Path || !*Path)
            return std::unique_ptr<SpecialCaseList>();

        auto FS = vfs::getRealFileSystem();
        std::string Error;
        std::unique_ptr<SpecialCaseList> SCL =
            SpecialCaseList::create({Path}, *FS, Error);

        if (!SCL)
            report_fatal_error(Twine("CQMSAN_IGNORELIST: unable to read '") +
                                Path + "': " + Error);

        return SCL;

    }();

    return List.get();
}

static bool isFunctionIgnored(const Function &F) {
    StringRef FuncName = F.getName();
    // Default ignorelist: ALWAYS active (equivalent to msan_ignorelist.txt)
    if (FuncName.starts_with("__gxx_personality"))
        return true;

    // Optional layer from env var
    const SpecialCaseList *IgnoreList = getCQMSanIgnorelist();
    if (!IgnoreList)
        return false;
    if (IgnoreList->inSection("cqmsan", "fun", FuncName))
        return true;
    if (const DISubprogram *SP = F.getSubprogram()) {
        std::string SourceFile = SP->getFilename().str();
        if (!SP->getDirectory().empty())
            SourceFile = SP->getDirectory().str() + "/" + SourceFile;
        if (IgnoreList->inSection("cqmsan", "src", SourceFile))
            return true;
    }
    return false;
}

bool CompilerQEMUMemorySanitizer::sanitizeFunction(Function &F,
                                                   TargetLibraryInfo &TLI) {
    if (F.getName() == kCQMSanModuleCtorName)
        return false;

    if (F.hasFnAttribute(Attribute::DisableSanitizerInstrumentation))
        return false;

    if (isFunctionIgnored(F))
        return false;

    CompilerQEMUMemorySanitizerVisitor Visitor(F, *this, TLI);

    // Clear out memory attributes.
    AttributeMask B;
    B.addAttribute(Attribute::Memory).addAttribute(Attribute::Speculatable);
    F.removeFnAttrs(B);

    return Visitor.runOnFunction();
}
