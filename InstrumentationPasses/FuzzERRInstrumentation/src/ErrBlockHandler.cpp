//
// Created by machiry on 4/19/22.
//

#include "ErrBlockHandler.h"
#include <assert.h>
#include <fstream>
#include <llvm/Support/Debug.h>
#include <llvm/Support/raw_os_ostream.h>

#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;

using namespace llvm;

bool ErrPointsInfo::parseErrBlocksJson(const std::string &JsonFilePath) {
    // read the json file so that we have the information
    json j;
    bool RetVal = false;
    std::string json_str;
    std::ifstream json_file(JsonFilePath, std::ifstream::binary);
    if (json_file.is_open()) {
        dbgs() << ">> parsing: " << JsonFilePath << '\n';
        json_file >> j;
        dbgs() << ">> root elements count: " << j.size() << '\n';

        // if this is not a project json, it will have root element of
        // "ErrGuardingConditions"
        if (j.is_object()) {
            j = j["ErrPoints"];
        }

        // process and store the info into a HashMap for faster lookups
        for (auto &item : j) {
            // get the name first
            std::string Name = item["FunctionInfo"]["Name"];
            for (auto &cond : item["ErrConditions"]) {
                ErrPointInfo NewObj(cond["File"], cond["LineNo"], cond["ColNo"], cond["Heuristic"]);
                ErrPoints[Name].push_back(NewObj);
            }
        }
        RetVal = true;

    } else {
        errs() << "[!] " << JsonFilePath << " is not a valid file\n";
    }

    return RetVal;
}

bool ErrGuardsInfo::parseErrBlocksJson(const std::string &JsonFilePath) {
    // read the json file so that we have the information
    json j;
    bool RetVal = false;
    std::string json_str;
    std::ifstream json_file(JsonFilePath, std::ifstream::binary);
    if (json_file.is_open()) {
        dbgs() << ">> parsing: " << JsonFilePath << '\n';
        json_file >> j;
        dbgs() << ">> root elements count: " << j.size() << '\n';

        // if this is not a project json, it will have root element of
        // "ErrGuardingConditions"
        if (j.is_object()) {
            j = j["ErrGuardingConditions"];
        }

        // process and store the info into a HashMap for faster lookups
        for (auto &item : j) {
            // get the name first
            std::string Name = item["FunctionInfo"]["Name"];
            for (auto &cond : item["ErrConditions"]) {
                ErrCheckInfo NewObj(cond["File"], cond["LineNo"], cond["ColNo"], cond["Heuristic"],
                                    cond["Level"], cond["ErrorLoc"]["LineNo"],
                                    cond["ErrorLoc"]["ColNo"]);
                FunctionGuards[Name].push_back(NewObj);
            }
        }
        RetVal = true;

    } else {
        errs() << "[!] " << JsonFilePath << " is not a valid file\n";
    }

    return RetVal;
}

bool ErrGuardsInfo::hasErrCheckInfo(const std::string &FuncName) {
    return FunctionGuards.find(FuncName) != FunctionGuards.end();
}

bool ErrPointsInfo::hasErrPointInfo(const std::string &FuncName) {
    return ErrPoints.find(FuncName) != ErrPoints.end();
}

const std::vector<ErrCheckInfo> &ErrGuardsInfo::getErrorCheckInfo(const std::string &FuncName) {
    assert(hasErrCheckInfo(FuncName) && "No Error Check Info present.");
    return FunctionGuards[FuncName];
}

const std::vector<ErrPointInfo> &ErrPointsInfo::getErrorPointInfo(const std::string &FuncName) {
    assert(hasErrPointInfo(FuncName) && "No Error Check Info present.");
    return ErrPoints[FuncName];
}
