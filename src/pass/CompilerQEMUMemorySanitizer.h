#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_COMPILERQEMUMEMORYSANITIZER_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_COMPILERQEMUMEMORYSANITIZER_H

#include "llvm/ADT/STLFunctionalExtras.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Support/Compiler.h"

namespace llvm {
class Module;
class StringRef;
class raw_ostream;

struct CompilerQEMUMemorySanitizerOptions {
  CompilerQEMUMemorySanitizerOptions() : CompilerQEMUMemorySanitizerOptions(false, false){};
  CompilerQEMUMemorySanitizerOptions(bool Recover) : CompilerQEMUMemorySanitizerOptions(Recover, false) {}
  CompilerQEMUMemorySanitizerOptions(bool Recover, bool EagerChecks);

  bool Recover;
  bool EagerChecks;
};

/// A module pass for CQMSan instrumentation.
///
/// Instruments functions to detect uninitialized reads. This function pass
/// inserts calls to runtime library functions. If the functions aren't declared
/// yet, the pass inserts the declarations. Otherwise the existing globals are
/// used.
///
/// CQMSan is the compiler-level porting of QMSan (Marini et al., NDSS 2025),
/// implementing the opportunistic detector at the LLVM IR level.
struct CompilerQEMUMemorySanitizerPass : public PassInfoMixin<CompilerQEMUMemorySanitizerPass> {
  CompilerQEMUMemorySanitizerPass(CompilerQEMUMemorySanitizerOptions Options) : Options(Options) {}

  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  void printPipeline(raw_ostream &OS,
                     function_ref<StringRef(StringRef)> MapClassName2PassName);

  static bool isRequired() { return true; }

private:
  CompilerQEMUMemorySanitizerOptions Options;
};
} // namespace llvm

#endif /* LLVM_TRANSFORMS_INSTRUMENTATION_COMPILERQEMUMEMORYSANITIZER_H */
