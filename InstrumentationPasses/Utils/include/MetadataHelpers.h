//
// Created by machiry on 4/19/22.
//

#ifndef FUZZERR_METADATAHELPERS_H
#define FUZZERR_METADATAHELPERS_H

#include <llvm/IR/Metadata.h>
#include <llvm/IR/Attributes.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>

using namespace llvm;

/// return the FileName of the file containing the given Function
std::string getFileName(Function &F);

#endif //FUZZERR_METADATAHELPERS_H
