//
// Created by shank on 4/25/22.
//

#ifndef FUZZERR_ERRCHECKLEVELINFO_H
#define FUZZERR_ERRCHECKLEVELINFO_H

#include <map>
#include <string>

enum LEVEL { INNER = 0, OUTER, DEFAULT };

const std::string LEVEL_INNER_STR = "Inner";
const std::string LEVEL_OUTER_STR = "Outer";
const std::string LEVEL_DEFAULT_STR = "Default";

extern std::map<LEVEL, std::string> LevelStr;
extern std::map<std::string, LEVEL> LevelFromStr;

#endif // FUZZERR_ERRCHECKLEVELINFO_H
