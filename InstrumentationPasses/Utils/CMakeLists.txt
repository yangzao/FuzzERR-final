add_library(Utils STATIC include/Utils.h src/Utils.cpp include/LLVMHelpers.h
                         src/LLVMHelpers.cpp src/MetadataHelpers.cpp)
set_property(TARGET Utils PROPERTY POSITION_INDEPENDENT_CODE ON)

include_directories(include/)

