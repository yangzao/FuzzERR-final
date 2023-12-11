#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libfreetype")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/freetype_2.11.1+dfsg.orig/freetype-2.11.1")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    ./configure CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" --prefix=$(pwd)/installed --disable-static --enable-shared
    make -j$(nproc)
    make install
    
    # copy over the shared library here
    cp installed/lib/libfreetype.so.6.18.1 "$LIB_INSTR_DIR/libfreetype.so"
    
    # copy over the version script
    cp objs/.libs/libfreetype.ver "$LIB_INSTR_DIR"
)
