//
// Created by machiry on 4/19/22.
//

#ifndef FUZZERR_INSTRUMENTATIONHELPERS_H
#define FUZZERR_INSTRUMENTATIONHELPERS_H

#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/DebugLoc.h>
#include <llvm/IR/DerivedTypes.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InstrTypes.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Metadata.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "ErrCheckLevelInfo.h"
#include "HeuristicInfo.h"

using namespace llvm;

class InstrumentationHelper {
  public:
    explicit InstrumentationHelper(Module *M) { CM = M; }

    virtual ~InstrumentationHelper() { CM = nullptr; }

    Function *getGetBitFn();

    Function *getInitValidBitCountFn();

    Function *getSaveTotalGetBitCallCountFn();

    Function *getOrInsertFn(const std::string &FnName, FunctionType *Typ);

    Value *createBitToBool(Value *bit, IRBuilder<> &builder);

    CallInst *createCallToGetBit(heuristicid HeuristicID, IRBuilder<> &builder, int &counter,
                                 LEVEL level);

  private:
    Module *CM;
};
#endif // FUZZERR_INSTRUMENTATIONHELPERS_H
