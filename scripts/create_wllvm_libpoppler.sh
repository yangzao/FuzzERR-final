#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/AblationStudy/F_FIP/libpoppler")
# LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/poppler-poppler-22.10.0/poppler-poppler-22.10.0")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/poppler-poppler-22.02.0/poppler-poppler-22.02.0")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    mkdir -p build
    cd build
    export LLVM_COMPILER=clang
    rm -rf ./*
    CC=wllvm CXX=wllvm++ cmake .. -GNinja -DCMAKE_INSTALL_PREFIX=../installed -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" -DCMAKE_BUILD_TYPE=debug -DENABLE_BOOST=OFF
    cmake --build . --target install
    cd ..
    
    # copy over the shared library here
    cp installed/lib/libpoppler.so.118.0.0 "$LIB_INSTR_DIR/libpoppler.so"
    cp installed/lib/libpoppler-glib.so.8.23.0 "$LIB_INSTR_DIR/libpoppler-glib.so"

)
