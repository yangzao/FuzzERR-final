//
// Created by machiry on 4/19/22.
//
#include "LLVMHelpers.h"

ConstantInt *getConstZero(Type *IntTy, LLVMContext &Ctx) {
    if (IntTy == Type::getInt1Ty(Ctx)) {
        return ConstantInt::get(Type::getInt1Ty(Ctx), 0);
    } else if (IntTy == Type::getInt8Ty(Ctx)) {
        return ConstantInt::get(Type::getInt8Ty(Ctx), 0);
    } else if (IntTy == Type::getInt16Ty(Ctx)) {
        return ConstantInt::get(Type::getInt16Ty(Ctx), 0);
    } else if (IntTy == Type::getInt32Ty(Ctx)) {
        return ConstantInt::get(Type::getInt32Ty(Ctx), 0);
    } else if (IntTy == Type::getInt64Ty(Ctx)) {
        return ConstantInt::get(Type::getInt64Ty(Ctx), 0);
    } else {
        errs() << "unknown integer type for condition!\n";
        // DISCUSS: how to error early in these conditions?
        exit(1);
    }
}

ConstantInt *getConstMinusOne(Type *IntTy, LLVMContext &Ctx) {
    if (IntTy == Type::getInt1Ty(Ctx)) {
        return ConstantInt::get(Type::getInt1Ty(Ctx), -1);
    } else if (IntTy == Type::getInt8Ty(Ctx)) {
        return ConstantInt::get(Type::getInt8Ty(Ctx), -1);
    } else if (IntTy == Type::getInt16Ty(Ctx)) {
        return ConstantInt::get(Type::getInt16Ty(Ctx), -1);
    } else if (IntTy == Type::getInt32Ty(Ctx)) {
        return ConstantInt::get(Type::getInt32Ty(Ctx), -1);
    } else if (IntTy == Type::getInt64Ty(Ctx)) {
        return ConstantInt::get(Type::getInt64Ty(Ctx), -1);
    } else {
        errs() << "unknown integer type for condition!\n";
        // DISCUSS: how to error early in these conditions?
        exit(1);
    }
}

ConstantInt *getConstOne(Type *IntTy, LLVMContext &Ctx) {
    if (IntTy == Type::getInt1Ty(Ctx)) {
        return ConstantInt::get(Type::getInt1Ty(Ctx), 1);
    } else if (IntTy == Type::getInt8Ty(Ctx)) {
        return ConstantInt::get(Type::getInt8Ty(Ctx), 1);
    } else if (IntTy == Type::getInt16Ty(Ctx)) {
        return ConstantInt::get(Type::getInt16Ty(Ctx), 1);
    } else if (IntTy == Type::getInt32Ty(Ctx)) {
        return ConstantInt::get(Type::getInt32Ty(Ctx), 1);
    } else if (IntTy == Type::getInt64Ty(Ctx)) {
        return ConstantInt::get(Type::getInt64Ty(Ctx), 1);
    } else {
        errs() << "unknown integer type for condition!\n";
        // DISCUSS: how to error early in these conditions?
        exit(1);
    }
}

Type *getConditionIntPtrTy(Type *IntTy, LLVMContext &Ctx) {
    if (IntTy == Type::getInt1Ty(Ctx)) {
        return Type::getInt1PtrTy(Ctx);
    } else if (IntTy == Type::getInt16Ty(Ctx)) {
        return Type::getInt16PtrTy(Ctx);
    } else if (IntTy == Type::getInt32Ty(Ctx)) {
        return Type::getInt32PtrTy(Ctx);
    } else if (IntTy == Type::getInt64Ty(Ctx)) {
        return Type::getInt64PtrTy(Ctx);
    } else {
        errs() << "unkown type for SwitchInst condition!\n";
        // DISCUSS: how to error early in these conditions?
        exit(1);
    }
}

bool isReachableFrom(BasicBlock *StartBB, BasicBlock *TargetBB) {
    std::vector<BasicBlock *> worklist;
    std::set<BasicBlock *> visited;
    worklist.push_back(StartBB);
    bool FoundInTrueSuccessorPath = false;
    while (!worklist.empty()) {
        BasicBlock *CurBB = worklist.back();
        worklist.pop_back();
        if (visited.find(CurBB) != visited.end()) {
            continue;
        }

        // check if CurBB is the one that contain the errloc
        if (CurBB == TargetBB) {
            return true;
        }

        visited.insert(CurBB);
        Instruction *Term = CurBB->getTerminator();
        for (auto i = 0; i < Term->getNumSuccessors(); i++) {
            BasicBlock *SuccessorBB = Term->getSuccessor(i);
            if (visited.find(SuccessorBB) == visited.end()) {
                worklist.push_back(SuccessorBB);
            }
        }
    }
    return false;
}
