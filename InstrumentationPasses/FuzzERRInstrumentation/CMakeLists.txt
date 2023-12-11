add_library(
  InstrumentErr MODULE
  src/InstrumentErr.cpp src/ErrBlockHandler.cpp src/InstrumentationHelper.cpp
  src/HeuristicInfo.cpp src/ErrCheckLevelInfo.cpp)
include_directories(include ../Utils/include)
target_compile_features(InstrumentErr PRIVATE cxx_range_for cxx_auto_type)

set_target_properties(InstrumentErr PROPERTIES COMPILE_FLAGS "-g")

# JSON
include(FetchContent)
FetchContent_Declare(
  json
  URL https://github.com/nlohmann/json/releases/download/v3.10.5/json.tar.xz)
FetchContent_MakeAvailable(json)
# target_link_libraries(InstrumentErr PRIVATE nlohmann_json::nlohmann_json
# Utils)

# boost
find_package(Boost REQUIRED COMPONENTS filesystem)
# target_link_libraries(InstrumentErr Boost::filesystem)

target_link_libraries(InstrumentErr PRIVATE nlohmann_json::nlohmann_json Utils
                                            Boost::filesystem)
