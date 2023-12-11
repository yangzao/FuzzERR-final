//
// Created by machiry on 4/19/22.
//

#ifndef FUZZERR_ERRBLOCKINFO_H
#define FUZZERR_ERRBLOCKINFO_H

#include <map>
#include <set>
#include <stdint.h>
#include <string>
#include <vector>

struct ErrPointInfo {
    std::string File;
    uint32_t LineNo;
    uint32_t ColNo;
    std::string HeuristicID;

    ErrPointInfo(const std::string &file, uint32_t lineno, uint32_t colno,
                 const std::string &heuristicid)
        : File(file), LineNo(lineno), ColNo(colno), HeuristicID(heuristicid) {}

    std::string toJsonString() const {
        std::string RetVal = "{\"File\": \"" + File + "\",";
        RetVal += "\"LineNo\":" + std::to_string(LineNo) + ",";
        RetVal += "\"ColNo\":" + std::to_string(ColNo) + ",";
        RetVal += "\"HeuristicID\":\"" + HeuristicID + "\",}";
        return RetVal;
    }

    std::string pointLocString() const {
        std::string RetVal =
            "(" + File + " | " + std::to_string(LineNo) + ":" + std::to_string(ColNo) + ")";
        return RetVal;
    }
};

/// Struct to hold the data read from errblocks.json file for easier
/// interfacing
struct ErrCheckInfo {
    std::string File;
    uint32_t LineNo;
    uint32_t ColNo;
    std::string HeuristicID;
    std::string Level;
    uint32_t ErrLocLineNo;
    uint32_t ErrLocColNo;

    ErrCheckInfo(const std::string &file, uint32_t lineno, uint32_t colno,
                 const std::string &heuristicid, const std::string &level, uint32_t errLocLineNo,
                 uint32_t errLocColNo)
        : File(file), LineNo(lineno), ColNo(colno), HeuristicID(heuristicid), Level(level),
          ErrLocLineNo(errLocLineNo), ErrLocColNo(errLocColNo) {}

    std::string toJsonString() const {
        std::string RetVal = "{\"File\": \"" + File + "\",";
        RetVal += "\"LineNo\":" + std::to_string(LineNo) + ",";
        RetVal += "\"ColNo\":" + std::to_string(ColNo) + ",";
        RetVal += "\"HeuristicID\":\"" + HeuristicID + "\",";
        RetVal += "\"Level\":\"" + Level + "\",";
        RetVal += "\"ErrLocLineNo\":" + std::to_string(ErrLocLineNo) + ",";
        RetVal += "\"ErrLocColNo\":" + std::to_string(ErrLocColNo) + "}";
        return RetVal;
    }

    std::string checkLocString() const {
        std::string RetVal =
            "(" + File + " | " + std::to_string(LineNo) + ":" + std::to_string(ColNo) + ")";
        return RetVal;
    }
};

class ErrGuardsInfo {
  public:
    ErrGuardsInfo() = default;
    virtual ~ErrGuardsInfo() { FunctionGuards.clear(); }

    bool parseErrBlocksJson(const std::string &JsonFilePath);

    bool hasErrCheckInfo(const std::string &FuncName);

    const std::vector<ErrCheckInfo> &getErrorCheckInfo(const std::string &FuncName);

  private:
    /// since we are just grouping by function names, its possible that
    /// the 'checks' contain entries belonging to different files
    std::map<std::string, std::vector<ErrCheckInfo>> FunctionGuards;
};

class ErrPointsInfo {
  public:
    ErrPointsInfo() = default;
    virtual ~ErrPointsInfo() { ErrPoints.clear(); }

    bool parseErrBlocksJson(const std::string &JsonFilePath);

    bool hasErrPointInfo(const std::string &FuncName);

    const std::vector<ErrPointInfo> &getErrorPointInfo(const std::string &FuncName);

  private:
    /// since we are just grouping by function names, its possible that
    /// the 'checks' contain entries belonging to different files
    std::map<std::string, std::vector<ErrPointInfo>> ErrPoints;
};

#endif // FUZZERR_ERRBLOCKINFO_H
