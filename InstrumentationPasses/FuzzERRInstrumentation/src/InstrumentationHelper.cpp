//
// Created by machiry on 4/19/22.
//

#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_os_ostream.h>

#include "InstrumentationHelper.h"
#include "LLVMHelpers.h"

Function *InstrumentationHelper::getOrInsertFn(const std::string &FnName, FunctionType *Typ) {
    FunctionCallee FnCallee = CM->getOrInsertFunction(FnName, Typ);

    // tmp: @shank
    assert(FnCallee.getFunctionType() == Typ && "Function type mismatch");
    assert(FnCallee.getCallee() && "Failed to get function");

    auto *Fn = dyn_cast<Function>(FnCallee.getCallee());

    if (!Fn) {
        errs() << "[!] " << FnName << "() needs to be included in the module.\n";
        exit(1);
    }
    return Fn;
}

Function *InstrumentationHelper::getGetBitFn() {
    // return type -> int (0/1)
    Type *returnType = Type::getInt32Ty(CM->getContext());

    // args -> id, heuristicid, level
    std::vector<Type *> args{Type::getInt32Ty(CM->getContext()), Type::getInt32Ty(CM->getContext()),
                             Type::getInt32Ty(CM->getContext())};

    FunctionType *Typ = FunctionType::get(returnType, args, false);

    return getOrInsertFn("fuzzerr_get_bit", Typ);
}

Function *InstrumentationHelper::getInitValidBitCountFn() {
    Type *returnType = Type::getVoidTy(CM->getContext());
    std::vector<Type *> args{Type::getInt32Ty(CM->getContext())};
    FunctionType *Typ = FunctionType::get(returnType, args, false);
    return getOrInsertFn("init_valid_mask_count", Typ);
}

Function *InstrumentationHelper::getSaveTotalGetBitCallCountFn() {
    Type *returnType = Type::getVoidTy(CM->getContext());
    // std::vector<Type *> args{Type::getInt32Ty(CM->getContext())};
    FunctionType *Typ = FunctionType::get(returnType, false);
    return getOrInsertFn("save_total_get_bit_call_count", Typ);
}

Value *InstrumentationHelper::createBitToBool(Value *bit, IRBuilder<> &builder) {
    // only valid for integer types
    assert(bit->getType()->isIntegerTy());

    ConstantInt *z = getConstZero(bit->getType(), CM->getContext());
    Value *tobool = builder.CreateICmpNE(bit, z, "tobool");
    return tobool;
}

CallInst *InstrumentationHelper::createCallToGetBit(heuristicid HeuristicID, IRBuilder<> &builder,
                                                    int &counter, LEVEL level) {
    dbgs() << ">>   createCallToGetBit for mask_id:" << std::to_string(counter)
           << " and hid:" << HeuristicID << '\n';
    Constant *id = ConstantInt::get(Type::getInt32Ty(CM->getContext()), counter);
    counter++;
    Constant *hid = ConstantInt::get(Type::getInt32Ty(CM->getContext()), HeuristicID);
    Constant *levelConst = ConstantInt::get(Type::getInt32Ty(CM->getContext()), level);
    std::vector<Value *> args{id, hid, levelConst};
    Function *getBitFn = getGetBitFn();
    CallInst *getBitInst = builder.CreateCall(getBitFn, args);
    return getBitInst;
}
