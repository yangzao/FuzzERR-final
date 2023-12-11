//
// Created by machiry on 4/19/22.
//

#ifndef FUZZERR_LLVMHELPERS_H
#define FUZZERR_LLVMHELPERS_H

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
#include <set>

using namespace llvm;

ConstantInt *getConstZero(Type *IntTy, LLVMContext &Ctx);
ConstantInt *getConstMinusOne(Type *IntTy, LLVMContext &Ctx);
ConstantInt *getConstOne(Type *IntTy, LLVMContext &Ctx);
Type *getConditionIntPtrTy(Type *IntTy, LLVMContext &Ctx);
bool isReachableFrom(BasicBlock *StartBB, BasicBlock *TargetBB);

#endif // FUZZERR_LLVMHELPERS_H
