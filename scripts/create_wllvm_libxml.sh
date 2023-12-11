#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/AblationStudy/F_FIP/libxml2")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libxml2_2.9.13+dfsg.orig/libxml2-2.9.13")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    [[ -f Makefile ]] && make distclean
    mkdir -p installed
    ! rm -rf installed/*
    export LLVM_COMPILER=clang
    ./configure CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" --disable-static --enable-shared --prefix=$(pwd)/installed
    # sed 's/PTR/void */' -i util/cairo-trace/lookup-symbol.c
    make -j$(nproc)
    make install
    
    # copy over the shared libraries here
    cp installed/lib/libxml2.so.2.9.13 "$LIB_INSTR_DIR/libxml2.so"
    cp libxml2.syms "$LIB_INSTR_DIR"
)
