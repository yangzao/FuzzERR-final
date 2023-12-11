//
// Created by shank on 4/25/22.
//

#include "ErrCheckLevelInfo.h"

std::map<std::string, LEVEL> LevelFromStr = {
    {LEVEL_INNER_STR, LEVEL::INNER},
    {LEVEL_OUTER_STR, LEVEL::OUTER},
    {LEVEL_DEFAULT_STR, LEVEL::DEFAULT},
};

std::map<LEVEL, std::string> LevelStr = {
    {LEVEL::INNER, LEVEL_INNER_STR},
    {LEVEL::OUTER, LEVEL_OUTER_STR},
    {LEVEL::DEFAULT, LEVEL_DEFAULT_STR},
};
