cmake_minimum_required(VERSION 3.4.3)

project(fuzzerr)

if(POLICY CMP0074)
    cmake_policy(SET CMP0074 OLD)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_CXX_STANDARD 14)
if(CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_FLAGS "-std=c++14 -D__GLIBCXX_USE_CXX11_ABI=0 -O0 -fno-rtti")
else()
    set(CMAKE_CXX_FLAGS "-std=c++14 -D__GLIBCXX_USE_CXX11_ABI=0 -O3 -fno-rtti")
endif()

find_package(LLVM REQUIRED CONFIG)
list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")
include(AddLLVM)
add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

message(STATUS "${CMAKE_MODULE_PATH} ${CMAKE_ROOT}")
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
message(STATUS "LLVM_DEFINITIONS = ${LLVM_DEFINITIONS}")
message(STATUS "LLVM_INCLUDE_DIRS = ${LLVM_INCLUDE_DIRS}")
message(STATUS "LLVM_LIBRARY_DIRS = ${LLVM_LIBRARY_DIRS}")

# # Use the same C++ standard as LLVM does set(CMAKE_CXX_STANDARD 14 CACHE
# STRING "")

# # LLVM is normally built without RTTI. Be consistent with that. if(NOT
# LLVM_ENABLE_RTTI) set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-rtti") endif()

add_subdirectory(Utils)
add_subdirectory(FuzzERRInstrumentation)
