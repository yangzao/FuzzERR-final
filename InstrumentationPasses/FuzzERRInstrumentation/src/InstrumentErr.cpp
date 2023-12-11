#include <alloca.h>
#include <boost/filesystem.hpp>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <llvm-13/llvm/IR/Constant.h>
#include <llvm-13/llvm/IR/Instructions.h>
#include <map>
#include <set>
#include <string>

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
#include <llvm/IR/Verifier.h>
#include <llvm/Pass.h>
#include <llvm/Support/Casting.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Debug.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>

#include <nlohmann/json.hpp>
#include <tuple>

#include "ErrBlockHandler.h"
#include "ErrCheckLevelInfo.h"
#include "HeuristicInfo.h"
#include "InstrumentationHelper.h"

#include "LLVMHelpers.h"
#include "MetadataHelpers.h"
#include "Utils.h"

using namespace llvm;

// for convenience
using json = nlohmann::json;

namespace {
    enum Mode { Normal, Fifuzz };

    static cl::opt<std::string>
        ProjectErrblocksJson("errblocks", cl::desc("path to project errblocks.json file"));

    static cl::opt<int32_t>
        StartCounter("startCounter",
                     cl::desc("the starting counter to use for id of instrumented locations"));

    static cl::opt<cl::boolOrDefault> NoCtor("noCtor", cl::desc("dont add the constructor"));

    static cl::opt<cl::boolOrDefault> DumbMode(
        "dumbMode",
        cl::desc("instrument all branch statements wihtout any analysis (in short, in dumb mode)"));

    static cl::opt<std::string>
        FnIgnoreList("fnIgnoreList",
                     cl::desc("path to file containing list of functions to ignore"));

    static cl::opt<Mode> OptMode("mode", cl::desc("Normal or Fifuzz mode"),
                                 cl::values(clEnumValN(Mode::Normal, "normal", "normal mode"),
                                            clEnumValN(Mode::Fifuzz, "fifuzz", "fifuzz mode")),
                                 cl::init(Mode::Normal));

    /// the counter that shall be used as an 'id' for the different
    /// error checks that are being instrumented
    int counter = 0;

    struct InstrumentErrPass : public ModulePass {
        static char ID;

        ErrGuardsInfo EGInfo;
        ErrPointsInfo EPInfo;

        std::set<std::string> IgnoredFunctions;

        InstrumentationHelper *InstrHelper;

        InstrumentErrPass() : ModulePass(ID) {}

        bool normalMode(Module &M) {
            bool edited = false;
            for (Function &F : M) {
                // does the function have a body?
                if (!F.isDeclaration()) {
                    std::string FnName = F.getName().str();
                    dbgs() << "[+] " << FnName << '\n';

                    if (IgnoredFunctions.find(FnName) != IgnoredFunctions.end()) {
                        dbgs() << ">> ignoring function: " << FnName
                               << " due to IgnoredFunctions list\n";
                        continue;
                    }

                    if (DumbMode) {
                        for (BasicBlock &BB : F) {
                            for (Instruction &I : BB) {
                                if (BranchInst *BI = dyn_cast<BranchInst>(&I)) {
                                    if (BI->isConditional()) {
                                        instrumentForBranchInDumbMode(BI,
                                                                      BranchWithErrLoc::TruePath);
                                        edited = true;
                                    }
                                }
                            }
                        }

                    } else {
                        // early return if we dont have any errblock for a function with this
                        // name
                        if (!EGInfo.hasErrCheckInfo(FnName)) {
                            dbgs() << ">> no errblock for function with name: " << FnName << '\n';
                            continue;
                        }
                        dbgs() << ">> found errchecks for: " << FnName << "\n";

                        std::map<const ErrCheckInfo *, Instruction *> ECICheckInstPairs =
                            getECICheckInstPairs(F);

                        // at this point we have the location of the ErrCheck
                        // just log it for testing...
                        // _logCheckInstructions(F, ECICheckInstPairs);

                        // find the location of the errors
                        std::map<const ErrCheckInfo *, BasicBlock *> ECIErrLocBBPairs =
                            getECIErrLocBBPairs(ECICheckInstPairs, F);

                        dbgs() << ">> ErrCheckErrLocBBPairs.size: " << ECIErrLocBBPairs.size()
                               << '\n';

                        edited |= instrumentInstructions(ECICheckInstPairs, ECIErrLocBBPairs);
                    }
                }
            }
            return edited;
        }

        bool fifuzzMode(Module &M) {
            bool edited = false;
            for (Function &F : M) {
                // does the function have a body?
                if (!F.isDeclaration()) {
                    std::string FnName = F.getName().str();
                    dbgs() << "[+] " << FnName << '\n';

                    if (IgnoredFunctions.find(FnName) != IgnoredFunctions.end()) {
                        dbgs() << ">> ignoring function: " << FnName
                               << " due to IgnoredFunctions list\n";
                        continue;
                    }

                    // early return if we dont have any errblock for a function with this
                    // name
                    if (!EPInfo.hasErrPointInfo(FnName)) {
                        dbgs() << ">> no errpoints for function with name: " << FnName << '\n';
                        continue;
                    }
                    dbgs() << ">> found errpoints for: " << FnName << "\n";

                    std::map<const ErrPointInfo *, Instruction *> EPIInstPairs = getEPIInstPairs(F);

                    // at this point we have the location of the ErrCheck
                    // just log it for testing...
                    // _logCheckInstructions(F, ECICheckInstPairs);

                    // // find the location of the errors
                    // std::map<const ErrCheckInfo *, BasicBlock *> ECIErrLocBBPairs =
                    //     getECIErrLocBBPairs(ECICheckInstPairs, F);

                    // dbgs() << ">> ErrCheckErrLocBBPairs.size: " << ECIErrLocBBPairs.size() <<
                    // '\n';

                    edited |= instrumentInstructions(EPIInstPairs);
                }
            }
            return edited;
        }

        bool runOnModule(Module &M) override {
            dbgs() << "[~] running on module: " << M.getModuleIdentifier() << "\n";

            // IR changed in this run?
            bool edited = false;

            // process based on the mode (normal/fifuzz)
            // assert(OptMode == Fifuzz);
            if (OptMode == Mode::Normal) {
                dbgs() << ">> runOnModule(): in normal mode\n";
                edited = normalMode(M);
            } else if (OptMode == Mode::Fifuzz) {
                dbgs() << ">> runOnModule(): in fifuzz mode\n";
                edited = fifuzzMode(M);
            } else {
                errs() << "[!] Unknown mode: " << OptMode << "\n";
                exit(EXIT_FAILURE);
            }

            // add the constructor
            if (!NoCtor) {
                edited |= checkAndAddCtor(M);
                edited |= checkAndAddDtor(M);
            }

            dbgs() << ">> edited: " << edited << '\n';
            dbgs().flush();

            // note that this final counter is 1 more than the last bit idx
            // that was instrumented. So this coutner can be used directly in the
            // next opt call
            outs() << "final counter : " << counter << '\n';
            outs().flush();

            return edited;
        }

        bool doInitialization(Module &M) override {
            dbgs() << ">> Inside doInitialization\n";
            dbgs() << ">> Mode: " << OptMode << "\n";
            if (OptMode == Mode::Normal) {
                dbgs() << ">> parsing json in normal mode\n";
                if (!EGInfo.parseErrBlocksJson(ProjectErrblocksJson)) {
                    errs() << "[!] Failed to read provided error json file:" << ProjectErrblocksJson
                           << "\n";
                    exit(EXIT_FAILURE);
                }
            } else if (OptMode == Mode::Fifuzz) {
                dbgs() << ">> parsing json in fifuzz mode\n";
                if (!EPInfo.parseErrBlocksJson(ProjectErrblocksJson)) {
                    errs() << "[!] Failed to read provided error json file:" << ProjectErrblocksJson
                           << "\n";
                    exit(EXIT_FAILURE);
                }
            } else {
                errs() << "[!] unknown mode: " << OptMode << "\n";
                exit(EXIT_FAILURE);
            }

            if (StartCounter) {
                counter = StartCounter;
                errs() << ">>   counter set to " << counter << '\n';
            }

            errs() << ">>   NoCtor set to " << NoCtor << '\n';
            errs() << ">>   DumbMode set to " << DumbMode << '\n';

            // read the list of functions to ignore form the FnIgnoreList
            if (!FnIgnoreList.empty()) {
                initIgnoredFunctionsList(FnIgnoreList);
            }

            InstrHelper = new InstrumentationHelper(&M);
            return true;
        }

      private:
        void initIgnoredFunctionsList(std::string FnIgnoreList) {
            std::ifstream IgnoreListFile(FnIgnoreList);
            if (!IgnoreListFile) {
                errs() << "[!] Failed to read provided ignore list file:" << FnIgnoreList << "\n";
                exit(1);
            } else {
                std::string line;
                while (std::getline(IgnoreListFile, line)) {
                    IgnoredFunctions.insert(line);
                }
                dbgs() << "[+] read " << IgnoredFunctions.size()
                       << " functions from FnIgnoreList\n";
                dbgs().flush();
            }
        }

        // returns <inner, outer, default> counts
        std::tuple<uint32_t, uint32_t, uint32_t>
        getLevelCounts(const std::vector<const ErrCheckInfo *> &ECIs) {
            uint32_t InnerCount = 0;
            uint32_t OuterCount = 0;
            uint32_t DefaultCount = 0;

            for (const ErrCheckInfo *ECI : ECIs) {
                if (ECI->Level == LEVEL_INNER_STR) {
                    InnerCount++;
                } else if (ECI->Level == LEVEL_OUTER_STR) {
                    OuterCount++;
                } else if (ECI->Level == LEVEL_DEFAULT_STR) {
                    DefaultCount++;
                } else {
                    // TODO: create a proper Exception class for our project
                    throw "Unknown Level string: " + ECI->Level;
                }
            }

            return {InnerCount, OuterCount, DefaultCount};
        }

        const std::vector<const ErrCheckInfo *>
        getErrChecksByLevel(std::string level, const std::vector<const ErrCheckInfo *> &ECIs) {
            std::vector<const ErrCheckInfo *> Filtered;

            for (const ErrCheckInfo *ECI : ECIs) {
                if (ECI->Level == level) {
                    Filtered.push_back(ECI);
                }
            }

            return Filtered;
        }

        /// which branch would lead to the error location?
        enum BranchWithErrLoc { TruePath, FalsePath };

        BranchWithErrLoc getBranchWithErrLoc(BranchInst *BI, BasicBlock *TargetBB) {
            // traverse the "true" path
            if (isReachableFrom(BI->getSuccessor(0), TargetBB)) {
                dbgs() << ">>   found in true successors path\n";
                return BranchWithErrLoc::TruePath;

            } else {
                dbgs() << ">>   found in false successors path\n";
                return BranchWithErrLoc::FalsePath;
            }
        }

        bool instrumentBranchInst(BranchInst *BI, const std::vector<const ErrCheckInfo *> &ECIs,
                                  std::map<const ErrCheckInfo *, BasicBlock *> &ECIErrLocBBPairs) {
            bool edited = false;

            // since this is a error check, it should always be a conditional branch
            // instruction
            assert(BI->isConditional());

            uint32_t InnerCount;
            uint32_t OuterCount;
            uint32_t DefaultCount;
            std::tie(InnerCount, OuterCount, DefaultCount) = getLevelCounts(ECIs);

            // now that we have the inner/outer/default counts, we can apply our rules
            // for instrumentation:
            //
            // | InnerCount | OuterCount |    Decision                      |
            // |------------|------------|----------------------------------|
            // | =1         | -          | Based on Inner                   |
            // | >1         | -          | No Instrumentation               |
            // | =0         | =1         | Based on Outer                   |
            // | =0         | >1         | if mixed branches, skip it.      |
            // |            |            | Else as per all True / all False |
            if (InnerCount == 1) {
                // based on "inner"
                dbgs() << ">>   instrumenting based on InnerCount = 1\n";
                const ErrCheckInfo *ECIInner = getErrChecksByLevel(LEVEL_INNER_STR, ECIs)[0];
                BasicBlock *TargetBB = ECIErrLocBBPairs[ECIInner];
                BranchWithErrLoc WhichBr = getBranchWithErrLoc(BI, TargetBB);
                instrumentForBranch(BI, WhichBr, ECIInner->HeuristicID, *ECIInner);

            } else if (InnerCount > 1) {
                // do nothing
                dbgs() << ">>   skipping as InnerCount > 1\n";

            } else if (InnerCount == 0 && OuterCount == 1) {
                // based on "outer"
                dbgs() << ">>   instrumenting based on InnerCount = 0 && OuterCount = 1\n";
                const ErrCheckInfo *ECIOuter = getErrChecksByLevel(LEVEL_OUTER_STR, ECIs)[0];
                BasicBlock *TargetBB = ECIErrLocBBPairs[ECIOuter];
                BranchWithErrLoc WhichBr = getBranchWithErrLoc(BI, TargetBB);
                instrumentForBranch(BI, WhichBr, ECIOuter->HeuristicID, *ECIOuter);

            } else if (InnerCount == 0 && OuterCount > 1) {
                // if mixed branches, skip it.
                // Else as per all true / all false condition
                dbgs() << ">>   instrumenting based on InnerCount = 0 && OuterCount > 1\n";

                uint32_t TruePathCount = 0;
                uint32_t FalsePathCount = 0;

                const std::vector<const ErrCheckInfo *> OuterECIs =
                    getErrChecksByLevel(LEVEL_OUTER_STR, ECIs);

                for (const ErrCheckInfo *ECI : OuterECIs) {
                    BasicBlock *TargetBB = ECIErrLocBBPairs[ECI];
                    BranchWithErrLoc WhichBr = getBranchWithErrLoc(BI, TargetBB);
                    if (WhichBr == BranchWithErrLoc::TruePath) {
                        TruePathCount++;
                    } else {
                        FalsePathCount++;
                    }
                }

                if (TruePathCount == 0 || FalsePathCount == 0) {
                    // all inner or all outer

                    BasicBlock *TargetBB = ECIErrLocBBPairs[ECIs[0]]; // pick any ECI
                    BranchWithErrLoc WhichBr = getBranchWithErrLoc(BI, TargetBB);

                    // its possible that we have muliple Checks, in which case
                    // we would just use H00 if there are mixed heuristics
                    std::string Heuristic = ECIs[0]->HeuristicID;
                    for (uint32_t i = 0; i < ECIs.size(); i++) {
                        if (ECIs[i]->HeuristicID != Heuristic) {
                            Heuristic = "H00"; // mixed heuristics
                            break;
                        }
                    }
                    instrumentForBranch(BI, WhichBr, Heuristic, *ECIs[0]);

                } else {
                    dbgs() << ">>   skipping due to mixed path\n";
                }

            } else {
                // this would happen when
                // inner == 0 && outer == 0 && default >= 1
                // instrument it normally
                dbgs() << ">>   instrumenting based on InnerCount = 0 && OuterCount = 0 && "
                          "DefaultCount >= 1\n";

                BasicBlock *TargetBB = ECIErrLocBBPairs[ECIs[0]]; // pick any ECI
                BranchWithErrLoc WhichBr = getBranchWithErrLoc(BI, TargetBB);

                // its possible that we have muliple Checks, in which case
                // we would just use H00 if there are mixed heuristics
                std::string Heuristic = ECIs[0]->HeuristicID;
                for (uint32_t i = 0; i < ECIs.size(); i++) {
                    if (ECIs[i]->HeuristicID != Heuristic) {
                        Heuristic = "H00"; // mixed heuristics
                        break;
                    }
                }
                instrumentForBranch(BI, WhichBr, Heuristic, *ECIs[0]);
            }

            return edited;
        }

        bool instrumentErrPointInst(CallInst *CI, heuristicid hid, LEVEL level) {
            // TODO: shank: here
            bool edited = false;
            // the broad steps are as below:
            // - do the friggin instrumentation, splitting basicblocks and adding edges

            BasicBlock *CurrBB = CI->getParent();

            // instrument it!
            IRBuilder<> builder(&(*CI->getIterator()));

            // errs() << "=========================\n";
            // CI->dump();

            // errs() << ">>>> before:\n";
            // CurrBB->getParent()->dump();
            // errs() << "------------------------\n";

            // the tmp register that shall be used as a placeholder for the value to be put
            // in place as a result of call instr
            Type *typ = CI->getType();
            Value *faultValue = getFaultValue(typ, CI->getContext());
            if (!faultValue) {
                // likely this is some false entry, so we skip it
                errs() << "returning " << edited << " to skip this one\n";
                return edited;
            }

            Value *tmp = builder.CreateAlloca(typ, nullptr, "tmp");
            Value *CIPlaceholder = builder.CreateLoad(typ, tmp, "tmpholder");
            // errs() << "CI->getType(): ";
            // CI->getType()->dump();
            // errs() << "FinalTmp->getType(): ";
            // CIPlaceholder->getType()->dump();
            CI->replaceAllUsesWith(CIPlaceholder);

            // call to get_bit
            Value *bit = InstrHelper->createCallToGetBit(hid, builder, counter, level);
            Value *tobool = InstrHelper->createBitToBool(bit, builder);

            // split the block (false block)
            BasicBlock *NewFalseBB = CurrBB->splitBasicBlock(CI, "new.false");

            // move one instruction in the NewFalseBB and create another split
            // this would mean that the original "errpoint" would remain in the NewFalseBB and rest
            // of the code would move to the newly created MergeBB
            // we name this as NewTrueBB as we will use this as the TrueBB later (after fixing
            // links)
            auto errPtInst = NewFalseBB->getFirstInsertionPt();
            BasicBlock *NewTrueBB =
                NewFalseBB->splitBasicBlock(errPtInst->getNextNode(), "new.true");
            BasicBlock *MergeBB =
                NewTrueBB->splitBasicBlock(NewTrueBB->getFirstInsertionPt(), "merge");

            // replace the unconditional branch at the end of CurrBB with a conditional one
            // the condition would be "%tobool"
            auto *CurrBBTermI = dyn_cast<BranchInst>(CurrBB->getTerminator());
            IRBuilder<> CurrBBBuilder(CurrBBTermI);
            CurrBBBuilder.CreateCondBr(tobool, NewTrueBB, NewFalseBB);
            CurrBBTermI->eraseFromParent();
            NewFalseBB->getTerminator()->replaceSuccessorWith(NewTrueBB, MergeBB);

            // now add the required load/store instructions
            // true block (inject fault) : fault value -> %tmp
            IRBuilder<> NewTrueBBBuilder(&(*NewTrueBB->getFirstInsertionPt()));
            NewTrueBBBuilder.CreateStore(faultValue, tmp);
            // false block (normal case) : actual value (CI) -> %tmp
            auto afterOriginal = NewFalseBB->getFirstInsertionPt()->getIterator();
            afterOriginal++;
            IRBuilder<> NewFalseBBBuilder(&*afterOriginal);
            NewFalseBBBuilder.CreateStore(CI, tmp);
            // merge block : replace all uses of CI with %tmp
            IRBuilder<> MergeBBBuilder(&(*MergeBB->getFirstInsertionPt()));
            Value *FinalTmp = MergeBBBuilder.CreateLoad(typ, tmp, "tmp.final");
            CIPlaceholder->replaceAllUsesWith(FinalTmp);

            // errs() << ">>>> after:\n";
            // CurrBB->getParent()->dump();

            // Verify the function
            if (verifyFunction(*CI->getFunction(), &errs())) {
                errs() << "Function verification failed: " << CI->getFunction()->getName() << "\n";
                exit(EXIT_FAILURE);
            } else {
                errs() << "Function verification successful!\n";
            }

            return edited;
        }

        Value *getFaultValue(Type *typ, LLVMContext &Ctx) {
            if (typ->isPointerTy()) {
                return Constant::getNullValue(typ);
            } else if (typ->isIntegerTy()) {
                return getConstMinusOne(typ, Ctx);
            } else {
                errs() << "unknown type for fault (neither pointer, not integer)!\n";
                typ->dump();
                return nullptr;
                // exit(EXIT_FAILURE);
            }
        }

        bool instrumentSwitchInst(SwitchInst *SI, const std::vector<const ErrCheckInfo *> &ECIs,
                                  std::map<const ErrCheckInfo *, BasicBlock *> &ECIErrLocBBPairs) {
            bool edited = false;

            // the broad steps are as below:
            // - get all the case values to be instrumented for
            // - do the friggin instrumentation, splitting basicblocks and adding edges

            // collect the target BBs for this switch instruction
            std::set<std::pair<const ErrCheckInfo *, BasicBlock *>> TargetBBs;
            for (const ErrCheckInfo *ECI : ECIs) {
                TargetBBs.insert({ECI, ECIErrLocBBPairs[ECI]});
            }

            // collect the case values to be used for instrumentation
            std::vector<std::tuple<ConstantInt *, heuristicid, LEVEL>> CaseValues =
                getCaseValuesToInstrument(SI, TargetBBs);

            // instrument it!
            if (!CaseValues.empty()) {
                dbgs() << ">>   found in SwitchInst cases\n";

                dbgs() << ">>   Instrumented SwitchInst: " << ECIs[0]->checkLocString()
                       << " with values:\n";
                splitAndInstrumentForCases(SI, CaseValues);

                edited |= true;
            }

            return edited;
        }

        bool instrumentInstructions(std::map<const ErrPointInfo *, Instruction *> &EPIInstPairs) {
            bool edited = false;

            // one ErrPointInfo should have one Instruction associated with it
            std::map<const ErrPointInfo *, unsigned int> counts;
            for (auto &Entry : EPIInstPairs) {
                if (counts.find(Entry.first) != counts.end()) {
                    errs() << "[!] more than one associated instruction found for a errpoint, "
                              "please investigate!\n";
                    errs() << Entry.first->pointLocString() << "\n";
                    exit(1);
                } else {
                    counts.insert({Entry.first, 1});
                }
            }

            // finally the instrumentation part...
            for (auto &EPIInstPair : EPIInstPairs) {
                const ErrPointInfo *EPI = EPIInstPair.first;
                Instruction *I = EPIInstPair.second;
                auto *CI = dyn_cast_or_null<CallInst>(I);
                if (!CI) {
                    errs() << "[!] skipping because instruction is not a CallInst, please "
                              "investigate!\n";
                    continue;
                }
                // assert(CI);

                // NOTE: we are using LEVEL::INNER since the errlib might be invoked with the
                // inner-only flag and we still want to fire these
                errs() << "working on ErrPoint: " << EPI->toJsonString() << "\n";
                edited |=
                    instrumentErrPointInst(CI, HeuristicNumber[EPI->HeuristicID], LEVEL::INNER);
            }

            return edited;
        }

        bool
        instrumentInstructions(std::map<const ErrCheckInfo *, Instruction *> &ECICheckInstPairs,
                               std::map<const ErrCheckInfo *, BasicBlock *> &ECIErrLocBBPairs) {
            bool edited = false;

            // since a single Check Instruction can have multiple ErrCheckInfo associated with
            // it, we create the reverese map of ECICheckInstPairs, i.e. a map of
            // CheckInst -> [ErrCheckInfo]
            // this will make it easier later to determine way in which a particular CheckInst
            // should be instrumented
            std::map<Instruction *, std::vector<const ErrCheckInfo *>> CheckInstECIsPairs;
            for (auto &Entry : ECICheckInstPairs) {
                CheckInstECIsPairs[Entry.second].push_back(Entry.first);
            }

            for (auto &CInstECIPair : CheckInstECIsPairs) {
                Instruction *CheckInst = CInstECIPair.first;

                dbgs() << ">> handling check: " << CInstECIPair.second[0]->checkLocString() << '\n';

                // CheckInst can be either a BranchInst or a SwitchInst
                if (auto *BI = dyn_cast_or_null<BranchInst>(CheckInst)) {
                    edited |= instrumentBranchInst(BI, CInstECIPair.second, ECIErrLocBBPairs);

                } else if (auto *SI = dyn_cast_or_null<SwitchInst>(CheckInst)) {
                    edited |= instrumentSwitchInst(SI, CInstECIPair.second, ECIErrLocBBPairs);

                } else {
                    llvm::errs() << "[!] Unexpected CheckInst!";
                }
            }

            return edited;
        }

        /// this function adds the constructor that is to be called for initializing the count of
        /// error masks
        bool checkAndAddCtor(Module &M) {
            bool edited = false;

            auto CtorFnCallee = M.getOrInsertFunction(
                "FuzzERRCtor", FunctionType::get(Type::getVoidTy(M.getContext()), false));
            auto *CtorFn = dyn_cast<Function>(CtorFnCallee.getCallee());

            if (CtorFn->isDeclaration()) {
                CtorFn->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
                BasicBlock *CtorBB = BasicBlock::Create(M.getContext(), "", CtorFn);
                ReturnInst::Create(M.getContext(), CtorBB);

                // - get the init_valid_mask_count() fn
                // - create the call
                IRBuilder<> IRB(CtorFn->getEntryBlock().getTerminator());
                Function *InitValidBitsFn = InstrHelper->getInitValidBitCountFn();
                Constant *counterArg = ConstantInt::get(Type::getInt32Ty(M.getContext()), counter);
                std::vector<Value *> args{counterArg};
                IRB.CreateCall(InitValidBitsFn, args);

                // add it to the ctors
                appendToUsed(M, {CtorFn});
                // appendToGlobalCtors(M, CtorFn, 1);
                appendToGlobalCtors(M, CtorFn, 65535);

                dbgs() << "[~] final count: " << std::to_string(counter) << '\n';

                std::string ModuleName = M.getName().str();
                dbgs() << "[~] ctor added " << ModuleName << " : " << M.getModuleIdentifier()
                       << "\n";

                edited = true;

            } else {
                dbgs() << "[~] ctor already added, skipping creating the body again\n";
            }

            return edited;
        }

        /// this function adds the destructor that is to be called for saving the
        /// /// get_bit() call count (if running in DRY_RUN_MODE)
        bool checkAndAddDtor(Module &M) {
            bool edited = false;

            auto DtorFnCallee = M.getOrInsertFunction(
                "FuzzERRDtor", FunctionType::get(Type::getVoidTy(M.getContext()), false));
            auto *DtorFn = dyn_cast<Function>(DtorFnCallee.getCallee());

            if (DtorFn->isDeclaration()) {
                DtorFn->addAttribute(AttributeList::FunctionIndex, Attribute::NoUnwind);
                BasicBlock *CtorBB = BasicBlock::Create(M.getContext(), "", DtorFn);
                ReturnInst::Create(M.getContext(), CtorBB);

                // - get the save_total_get_bit_call_count() fn
                // - create the call
                IRBuilder<> IRB(DtorFn->getEntryBlock().getTerminator());
                Function *SaveTotalGetBitCallCountFn = InstrHelper->getSaveTotalGetBitCallCountFn();
                // Constant *counterArg = ConstantInt::get(Type::getInt32Ty(M.getContext()),
                // counter); std::vector<Value *> args{counterArg};
                IRB.CreateCall(SaveTotalGetBitCallCountFn);

                // add it to the dtors
                appendToUsed(M, {DtorFn});
                // appendToGlobalCtors(M, CtorFn, 1);
                appendToGlobalDtors(M, DtorFn, 65535);

                std::string ModuleName = M.getName().str();
                dbgs() << "[~] dtor added " << ModuleName << " : " << M.getModuleIdentifier()
                       << "\n";

                edited = true;

            } else {
                dbgs() << "[~] dtor already added, skipping creating the body again\n";
            }

            return edited;
        }

        void splitAndInstrumentForCases(
            SwitchInst *SI,
            const std::vector<std::tuple<ConstantInt *, heuristicid, LEVEL>> &CaseValues) {
            // the target IR is something like this:
            //
            // %tmp = alloca i32, align 4
            // %switchVal = alloca i32, align 4
            // store i32 %a, i32* %tmp, align 4, !dbg !21
            // %call = call i32 @get_bit(i32 1), !dbg !22
            // %tobool = icmp ne i32 %call, 0, !dbg !22
            // br i1 %tobool, label %if.then, label %if.end, !dbg !24
            //
            // if.then:                                          ; preds = %entry
            // store i32 1, i32* %tmp, align 4, !dbg !24
            // br label %if.end, !dbg !26
            //
            // if.end4:                                          ; preds = %if.then3,
            // %if.end %2 = load i32, i32* %tmp, align 4, !dbg !35 store i32 %2, i32*
            // %switchVal, align 4, !dbg !34 %3 = load i32, i32* %switchVal, align 4,
            // !dbg !36 switch i32 %3, label %sw.default [

            IRBuilder<> builder(&(*SI->getIterator()));

            // INITIAL SETUP

            // add the instruction for storing the value of exiting condition to %tmp
            // (along with the required alloc)
            Value *cond = SI->getCondition();
            Type *typ = cond->getType();
            Value *tmp = builder.CreateAlloca(typ, nullptr, "tmp");

            // %a -> %tmp
            builder.CreateStore(cond, tmp);

            // %switchVal which will finally replace existing condition for SwitchInst
            Value *switchVal = builder.CreateAlloca(typ, nullptr, "switchVal");

            // NOW FOR EACH CASE VALUE...
            BasicBlock *CurrSwitchBB = SI->getParent();
            for (auto &CV : CaseValues) {
                ConstantInt *CI;
                heuristicid hnum;
                LEVEL level;
                std::tie(CI, hnum, level) = CV;
                CurrSwitchBB = instrumentForCaseValue(CurrSwitchBB, SI, CI, tmp, hnum, level);

                dbgs() << ">>   (" << std::to_string(counter - 1)
                       << ", value:" << std::to_string(CI->getSExtValue()) << ")\n";
            }

            // finally set the final value to the condition of the switch inst
            IRBuilder<> newBuilder(CurrSwitchBB->getTerminator());
            Value *FinalTmp = newBuilder.CreateLoad(typ, tmp, "tmp.final");
            SI->setCondition(FinalTmp);
        }

        BasicBlock *instrumentForCaseValue(BasicBlock *CurrSwitchBB, SwitchInst *SI,
                                           ConstantInt *CI, Value *tmp, heuristicid hid,
                                           LEVEL level) {
            IRBuilder<> builder(&(*SI->getIterator()));

            // call get_bit(<id>)
            Value *bit = InstrHelper->createCallToGetBit(hid, builder, counter, level);

            // %tobool = icmp ne i32 %call, 0, !dbg !22
            Value *tobool = InstrHelper->createBitToBool(bit, builder);

            // finally the splits!
            BasicBlock *NewBB = CurrSwitchBB->splitBasicBlock(SI, "new.true");
            BasicBlock *NewSwitchBB = NewBB->splitBasicBlock(SI, "new");
            CurrSwitchBB->getTerminator()->replaceSuccessorWith(NewBB, NewSwitchBB);

            // replace terminator of CurrBB with conditional branch to
            // the NewBB and SwitchBB
            auto *TermI = dyn_cast<BranchInst>(CurrSwitchBB->getTerminator());
            IRBuilder<> CurrBBBuilder(TermI);
            CurrBBBuilder.CreateCondBr(tobool, NewBB, NewSwitchBB);
            TermI->eraseFromParent();

            // in newBB, set the value of %tmp
            // store i32 1, i32* %tmp, align 4, !dbg !24
            IRBuilder<> NewBBBuilder(NewBB->getTerminator());
            NewBBBuilder.CreateStore(CI, tmp);

            return NewSwitchBB;
        }

        std::vector<std::tuple<ConstantInt *, heuristicid, LEVEL>> getCaseValuesToInstrument(
            SwitchInst *SI,
            const std::set<std::pair<const ErrCheckInfo *, BasicBlock *>> &TargetBBs) {

            std::vector<std::tuple<ConstantInt *, heuristicid, LEVEL>> Values;

            // check other cases
            for (auto it = SI->case_begin(), end = SI->case_end(); it != end; it++) {
                BasicBlock *BB = (*it).getCaseSuccessor();
                for (auto &TargetBB : TargetBBs) {
                    if (isReachableFrom(BB, TargetBB.second)) {
                        heuristicid hnum = HeuristicNumber[TargetBB.first->HeuristicID];
                        LEVEL level = LevelFromStr[TargetBB.first->Level];
                        Values.push_back({it->getCaseValue(), hnum, level});
                        break;
                    }
                }
            }

            // check default case
            auto DefaultCase = SI->case_default();
            BasicBlock *BB = DefaultCase->getCaseSuccessor();
            for (auto &TargetBB : TargetBBs) {
                if (isReachableFrom(BB, TargetBB.second)) {
                    // now that we need to instrument default case as well
                    // the simplest thing to do it to just use a value that
                    // is higher than the max values of all cases
                    int64_t maxCaseValue = INT64_MIN;
                    for (auto it = SI->case_begin(), end = SI->case_end(); it != end; it++) {
                        maxCaseValue = std::max(maxCaseValue, (*it).getCaseValue()->getSExtValue());
                    }

                    // this value would make the default case execute
                    // TODO: can this ever be not sufficient?
                    int64_t defaultValueInt = maxCaseValue + 1;
                    Type *typ = SI->getCondition()->getType();
                    auto *defaultValue =
                        dyn_cast<ConstantInt>(ConstantInt::get(typ, defaultValueInt));
                    heuristicid hnum = HeuristicNumber[TargetBB.first->HeuristicID];
                    LEVEL level = LevelFromStr[TargetBB.first->Level];
                    Values.push_back({defaultValue, hnum, level});
                    break;
                }
            }

            return Values;
        }

        void instrumentBranchInstH06(BranchInst *BI, BranchWithErrLoc WhichBr, heuristicid hid,
                                     const ErrCheckInfo &ECI) {
            // currently H06 is only catching != NULL checks, so WhichBr should
            // only be True Branch. Still put in an assert so that we can
            // catch any change in semantics made later to our heuristic
            // assert(WhichBr == BranchWithErrLoc::TruePath);

            if (WhichBr == BranchWithErrLoc::TruePath) {
                dbgs() << ">>   Instrumented BranchInst: (TruePath | Or with bit | "
                       << ECI.checkLocString() << '\n';
            } else {
                dbgs() << ">>   Instrumented BranchInst: (FalsePath | And with !bit | "
                       << ECI.checkLocString() << '\n';
            }

            auto *CmpI = dyn_cast<CmpInst>(BI->getCondition());

            // this comparision should always have 2 operands (x != NULL)
            assert(CmpI->getNumOperands() == 2);

            // find the non-null operand
            // to do so, first locate the ptr that is used in the cmp instruction
            // and then get the operand from the ptr
            Value *PtrVal = nullptr;
            if (auto *ConstOp1 = dyn_cast<Constant>(CmpI->getOperand(0))) {
                if (ConstOp1->isNullValue()) {
                    PtrVal = CmpI->getOperand(1);
                }
            } else if (auto *ConstOp2 = dyn_cast<Constant>(CmpI->getOperand(1))) {
                if (ConstOp2->isNullValue()) {
                    PtrVal = CmpI->getOperand(0);
                }
            } else {
                // should not have happened!
                throw "unreachable!";
            }

            Value *Op = nullptr;
            if (auto *LI = dyn_cast<LoadInst>(PtrVal)) {
                // single operand to a load instruction
                Op = LI->getOperand(0);
            }

            // reference to the current BB
            BasicBlock *CurrBranchBB = BI->getParent();

            // store existing value of the non-null operand
            IRBuilder<> builder(&(*CmpI->getIterator()));
            Type *typ = PtrVal->getType();

            // call get_bit(<id>)
            Value *bit =
                InstrHelper->createCallToGetBit(hid, builder, counter, LevelFromStr[ECI.Level]);

            // %tobool = icmp ne i32 %call, 0, !dbg !22
            Value *tobool = InstrHelper->createBitToBool(bit, builder);

            // finally the splits!
            BasicBlock *NewBB = CurrBranchBB->splitBasicBlock(CmpI, "new.true");
            BasicBlock *NewBranchBB = NewBB->splitBasicBlock(CmpI, "new");
            CurrBranchBB->getTerminator()->replaceSuccessorWith(NewBB, NewBranchBB);

            // replace terminator of CurrBB with conditional branch to
            // the NewBB and SwitchBB
            auto *TermI = dyn_cast<BranchInst>(CurrBranchBB->getTerminator());
            IRBuilder<> CurrBBBuilder(TermI);
            CurrBBBuilder.CreateCondBr(tobool, NewBB, NewBranchBB);
            TermI->eraseFromParent();

            // in newBB, set the value of Op to NULL
            IRBuilder<> NewBBBuilder(NewBB->getTerminator());
            NewBBBuilder.CreateStore(Constant::getNullValue(typ), Op);

            // in the BB which now contains the cmp, load the value of x again
            IRBuilder<> NewBranchBBBuilder(&(*NewBranchBB->getFirstInsertionPt()));
            Value *FinalOp = NewBranchBBBuilder.CreateLoad(typ, Op, "Op.final");
            CmpI->replaceUsesOfWith(PtrVal, FinalOp);
        }

        /// instrument the given BranchInst in dumbMode
        void instrumentForBranchInDumbMode(BranchInst *BI, const BranchWithErrLoc WhichBr) {
            const std::string HeuristicID = "H10";

            // we need to instrument so as to add instructions in line
            // with the following IR statements
            //
            // <id> can be set using a global counter in the pass itself
            //
            // %6 = call i32 @get_bit(i32 %5)
            // %8 = trunc i32 %6 to i1
            // %9 = or i1 %8, %3
            // br i1 %9, label %10, label %12

            IRBuilder<> builder(&(*BI->getIterator()));

            // %7 = call i32 @get_bit(i32 <id>)
            int HID = HeuristicNumber[HeuristicID];
            CallInst *getBitInst =
                InstrHelper->createCallToGetBit(HID, builder, counter, LevelFromStr["Inner"]);

            // %8 = trunc i32 %7 to i1
            Value *bit = builder.CreateTrunc(getBitInst, Type::getInt1Ty(BI->getContext()));

            Value *newCond = nullptr;

            // %9 = or i1 %8, %6
            newCond = builder.CreateOr(bit, BI->getCondition());

            dbgs() << ">>   Instrumented BranchInst: (TruePath | Or with bit | DumbMode)\n";

            // br i1 %9, label %10, label %12
            BI->setCondition(newCond);
        }

        /// instruments the given BranchInst
        void instrumentForBranch(BranchInst *BI, const BranchWithErrLoc WhichBr,
                                 const std::string &HeuristicID, const ErrCheckInfo &ECI) {
            // the branch instruction for H06 is to be instrumented differntly
            // than other heuristics....
            if (HeuristicID == "H06") {
                // dont instrument H06 for now
                // instrumentBranchInstH06(BI, WhichBr, HeuristicNumber[HeuristicID], ECI);
                return;
            }

            // we need to instrument so as to add instructions in line
            // with the following IR statements
            //
            // <id> can be set using a global counter in the pass itself
            //
            // %6 = call i32 @get_bit(i32 %5)
            // %8 = trunc i32 %6 to i1
            // %9 = or i1 %8, %3
            // br i1 %9, label %10, label %12

            IRBuilder<> builder(&(*BI->getIterator()));

            // %7 = call i32 @get_bit(i32 <id>)
            int HID = HeuristicNumber[HeuristicID];
            CallInst *getBitInst =
                InstrHelper->createCallToGetBit(HID, builder, counter, LevelFromStr[ECI.Level]);

            // %8 = trunc i32 %7 to i1
            Value *bit = builder.CreateTrunc(getBitInst, Type::getInt1Ty(BI->getContext()));

            Value *newCond = nullptr;
            if (WhichBr == BranchWithErrLoc::TruePath) {
                // %9 = or i1 %8, %6
                newCond = builder.CreateOr(bit, BI->getCondition());

                dbgs() << ">>   Instrumented BranchInst: (TruePath | Or with bit | "
                       << ECI.checkLocString() << '\n';
            } else {
                Value *bit_negated =
                    builder.CreateXor(bit, getConstOne(bit->getType(), BI->getContext()));
                newCond = builder.CreateAnd(bit_negated, BI->getCondition());

                dbgs() << ">>   Instrumented BranchInst: (FalsePath | And with !bit | "
                       << ECI.checkLocString() << '\n';
            }

            // br i1 %9, label %10, label %12
            BI->setCondition(newCond);
        }

        std::set<const ErrPointInfo *> getInterestingErrPoints(Function &F) {
            std::string FnName = F.getName().str();

            // checks having the same name as this function
            const std::vector<ErrPointInfo> &ErrPoints = EPInfo.getErrorPointInfo(FnName);

            // the filterd checks that pertain to this file only
            std::string FileName = getFileName(F);
            dbgs() << ">> Function FileName: " << FileName << '\n';

            // in libzstd, for some reason there are patterns in filename like './/'
            // replace them with a single /
            CleanFileName(FileName);
            std::string CanonicalFileName = getCanonicalFileName(FileName);
            dbgs() << ">> Function FileName: " << FileName << '\n';
            dbgs() << ">> Function FileName (canonical): " << CanonicalFileName << '\n';

            std::set<const ErrPointInfo *> InterestingErrPoints;
            for (auto &ErrPointInfo : ErrPoints) {
                if (ErrPointInfo.File == CanonicalFileName) {
                    InterestingErrPoints.insert(&ErrPointInfo);
                }
            }

            return InterestingErrPoints;
        }

        /// Interesting Checks are the checks which
        /// - have the same function name
        /// - belong to the file containing this Funciton
        std::set<const ErrCheckInfo *> getInterestingChecks(Function &F) {
            std::string FnName = F.getName().str();

            // checks having the same name as this function
            const std::vector<ErrCheckInfo> &Checks = EGInfo.getErrorCheckInfo(FnName);

            // the filterd checks that pertain to this file only
            std::string FileName = getFileName(F);
            dbgs() << ">> Function FileName: " << FileName << '\n';

            // in libzstd, for some reason there are patterns in filename like './/'
            // replace them with a single /
            CleanFileName(FileName);
            std::string CanonicalFileName = getCanonicalFileName(FileName);
            dbgs() << ">> Function FileName: " << FileName << '\n';
            dbgs() << ">> Function FileName (canonical): " << CanonicalFileName << '\n';

            std::set<const ErrCheckInfo *> InterestingChecks;
            for (auto &CheckInfo : Checks) {
                if (CheckInfo.File == CanonicalFileName) {
                    InterestingChecks.insert(&CheckInfo);
                }
            }

            return InterestingChecks;
        }

        /// InterestingCallInstructions are those instructions which
        /// - are a "call" instruction
        /// - are associated with a line in the interestingLineNos
        std::set<Instruction *>
        getInterestingCallInstructions(Function &F, std::set<uint32_t> &interestingLineNos) {
            std::set<Instruction *> InterestingInstructions;
            for (auto &BB : F) {
                for (auto &Inst : BB) {
                    // we only care about call
                    if (CallInst *CI = dyn_cast_or_null<CallInst>(&Inst)) {
                        // does it have metadata?
                        if (Inst.hasMetadata()) {
                            DebugLoc DLoc = Inst.getDebugLoc();
                            // valid debug location?
                            if (DLoc) {
                                uint32_t line = DLoc.getLine();
                                if (interestingLineNos.find(line) != interestingLineNos.end()) {
                                    // a branch instruction at an intersting line no, add it!
                                    InterestingInstructions.insert(&Inst);
                                }
                            }
                        }
                    }
                }
            }

            return InterestingInstructions;
        }

        /// InterestingBranchInstructions are those instructions which
        /// - are a "branch" instruction (either BranchInst or SwitchInst)
        /// - are associated with a line in the interestingLineNos
        std::set<Instruction *>
        getInterestingBranchInstructions(Function &F, std::set<uint32_t> &interestingLineNos) {
            std::set<Instruction *> InterestingInstructions;
            for (auto &BB : F) {
                for (auto &Inst : BB) {
                    // we only care about branch (if/while) or switch instructions
                    auto *BI = dyn_cast_or_null<BranchInst>(&Inst);
                    auto *SI = dyn_cast_or_null<SwitchInst>(&Inst);
                    if (SI || (BI && BI->isConditional())) {
                        // does it have metadata?
                        if (Inst.hasMetadata()) {
                            DebugLoc DLoc = Inst.getDebugLoc();
                            // valid debug location?
                            if (DLoc) {
                                uint32_t line = DLoc.getLine();
                                if (interestingLineNos.find(line) != interestingLineNos.end()) {
                                    // a branch instruction at an intersting line no, add it!
                                    InterestingInstructions.insert(&Inst);
                                }
                            }
                        }
                    }
                }
            }

            return InterestingInstructions;
        }

        /// return the pairs of (ErrPointInfo, corresponding IR Instruction)
        std::map<const ErrPointInfo *, Instruction *> getEPIInstPairs(Function &F) {
            // HOW THIS WORKS:
            //
            // iterate over the instructions within this function
            // - collect the call instructions and their respective location infos
            // - for each err point insturction, find the closest call instruction
            //
            // the instruction having the next closest column is considered as the
            // "closest" instruction
            std::set<const ErrPointInfo *> InterestingErrPoints = getInterestingErrPoints(F);
            dbgs() << ">> found " << InterestingErrPoints.size() << " interesting errpoints for "
                   << F.getName().str() << '\n';

            // source line numbers that contain the checks
            std::set<uint32_t> interestingLineNos;
            for (auto ErrPoint : InterestingErrPoints) {
                interestingLineNos.insert(ErrPoint->LineNo);
            }

            // collect the interesting call instructions
            std::set<Instruction *> InterestingInstructions =
                getInterestingCallInstructions(F, interestingLineNos);

            std::map<const ErrPointInfo *, Instruction *> pairs;

            for (const ErrPointInfo *EPI : InterestingErrPoints) {
                Instruction *I = nullptr;
                uint32_t mindiff = INT32_MAX;
                for (Instruction *ToCheckInst : InterestingInstructions) {
                    DebugLoc DLoc = ToCheckInst->getDebugLoc();
                    // same line no
                    if (EPI->LineNo == DLoc.getLine()) {
                        int32_t diff = DLoc.getCol() - EPI->ColNo;
                        if (diff >= 0 && diff < mindiff) {
                            // new best (closest column)!
                            I = ToCheckInst;
                            mindiff = diff;
                        }
                    }
                }

                if (I == nullptr) {
                    // this should not have happened, log it and investigate
                    errs() << "[!] Unable to find matching call instruction for this "
                              "ErrPointInfo (please investigate) : "
                           << EPI->toJsonString() << '\n';
                    continue;
                }

                pairs[EPI] = I;
            }

            return pairs;
        }

        /// return the pairs of (ErrCheckInfo, corresponding Check IR Instruction)
        std::map<const ErrCheckInfo *, Instruction *> getECICheckInstPairs(Function &F) {
            // HOW THIS WORKS:
            //
            // iterate over the instructions within this function
            // - collect the branch instructions and their respective location infos
            // - for each check, find the closest branch instruction
            //
            // the instruction having the next closest column is considered as the
            // "closest" instruction

            std::set<const ErrCheckInfo *> InterestingChecks = getInterestingChecks(F);
            dbgs() << ">> found " << InterestingChecks.size() << " interesting checks for "
                   << F.getName().str() << '\n';

            // source line numbers that contain the checks
            std::set<uint32_t> interestingLineNos;
            for (auto CheckInfo : InterestingChecks) {
                interestingLineNos.insert(CheckInfo->LineNo);
            }

            // collect the interesting branch instructions
            std::set<Instruction *> InterestingInstructions =
                getInterestingBranchInstructions(F, interestingLineNos);

            std::map<const ErrCheckInfo *, Instruction *> pairs;

            for (const ErrCheckInfo *ECI : InterestingChecks) {
                Instruction *I = nullptr;
                uint32_t mindiff = INT32_MAX;
                for (Instruction *ToCheckInst : InterestingInstructions) {
                    DebugLoc DLoc = ToCheckInst->getDebugLoc();
                    // same line no
                    if (ECI->LineNo == DLoc.getLine()) {
                        int32_t diff = DLoc.getCol() - ECI->ColNo;
                        if (diff >= 0 && diff < mindiff) {
                            // new best (closest column)!
                            I = ToCheckInst;
                            mindiff = diff;
                        }
                    }
                }

                if (I == nullptr) {
                    // this should not have happened, log it and investigate
                    errs() << "[!] Unable to find matching check instruction for this "
                              "ErrCheckInfo (please investigate) : "
                           << ECI->toJsonString() << '\n';
                    continue;
                }

                pairs[ECI] = I;
            }

            return pairs;
        }

        /// return the pairs of (ErrCheckInfo, corresponding Err IR Instruction)
        std::map<const ErrCheckInfo *, BasicBlock *>
        getECIErrLocBBPairs(std::map<const ErrCheckInfo *, Instruction *> &CheckInstructions,
                            Function &F) {
            // this can be broken into two steps
            // 1. [x] find the instruction corresponding to the error location
            // 2. [x] from the check location, try both true and false paths
            //      if the err inst is found on the true path, we need to instrument
            //      with OR if the err inst is found on the false path, we need to
            //      instrument with AND

            std::map<const ErrCheckInfo *, BasicBlock *> pairs;

            // for each error guard instruction
            for (auto &Elem : CheckInstructions) {
                const ErrCheckInfo *ECI = Elem.first;
                Instruction *CheckInst = Elem.second;

                uint32_t errLineNo = ECI->ErrLocLineNo;
                uint32_t errColNo = ECI->ErrLocColNo;

                uint32_t mindiff = INT32_MAX;
                Instruction *ClosestMatch = nullptr;
                BasicBlock *MatchingBB = nullptr;
                bool matchFound = false;

                // iterate over each basic block in the function
                for (auto &BB : F) {
                    // iterate over each instruction in each BB
                    // and locate the closest matching instruction for the
                    // error location
                    for (auto &Inst : BB) {
                        // does it have metadata?
                        if (Inst.hasMetadata()) {
                            DebugLoc DLoc = Inst.getDebugLoc();
                            // valid debug location?
                            if (DLoc) {
                                uint32_t instLineNo = DLoc.getLine();
                                // line no match?
                                if (instLineNo == errLineNo) {
                                    uint32_t instColNo = DLoc.getCol();
                                    int32_t diff = errColNo - instColNo;
                                    if (diff >= 0 && diff < mindiff) {
                                        // new best (closest column)!
                                        ClosestMatch = &Inst;
                                        MatchingBB = &BB;
                                        mindiff = diff;
                                        if (mindiff == 0) {
                                            matchFound = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (matchFound) {
                        break;
                    }
                }

                // at this point we should have a matching instruction and the associated
                // basic block
                if (ClosestMatch == nullptr) {
                    // we were unable to find the instruction mapping to the error location
                    // this would have to be investigated, so log it for now
                    errs() << "[!] Unable to find matching error instruction for this "
                              "ErrCheckInfo (please investigate) : "
                           << ECI->toJsonString() << '\n';
                    continue;
                }

                // DebugLoc DLoc = ClosestMatch->getDebugLoc();
                // dbgs() << ">> matching error location: File: " << getFileName(F)
                //        << ", line:" << errLineNo << ", col:" << errColNo
                //        << " | error ir instruction loc: " << DLoc.getLine() << ":" <<
                //        DLoc.getCol()
                //        << '\n';

                pairs[ECI] = MatchingBB;
            }

            return pairs;
        }

        std::string getCanonicalFileName(std::string &s) {
            boost::filesystem::path p = boost::filesystem::weakly_canonical(s);
            dbgs() << ">>   canonical path string: " << p.string() << '\n';
            return p.string();
        }

        /// replaces /.// with / in input strings
        void CleanFileName(std::string &s) {
            size_t idx = 0;
            while (true) {
                idx = s.find("/.//");
                if (idx == std::string::npos)
                    break;
                s.replace(idx, 4, "/");
            }
        }

        void
        _logCheckInstructions(Function &F,
                              std::map<const ErrCheckInfo *, Instruction *> &CheckInstructions) {
            for (auto &Elem : CheckInstructions) {

                DebugLoc DLoc = Elem.second->getDebugLoc();
                assert(DLoc);
                dbgs() << ">> matching check info: File: " << getFileName(F)
                       << ", line:" << Elem.first->LineNo << ", col:" << Elem.first->ColNo
                       << " | ir instruction loc: " << DLoc.getLine() << ":" << DLoc.getCol()
                       << '\n';
            }
        }
    };

} // namespace

char InstrumentErrPass::ID = 0;

static RegisterPass<InstrumentErrPass> X("instrumentErr", "Instrument Error Checks", false, false);
