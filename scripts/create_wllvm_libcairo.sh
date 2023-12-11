#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/AblationStudy/F_FIP/libcairo")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/cairo_1.16.0.orig/cairo-1.16.0")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    [[ -f Makefile ]] && make distclean
    mkdir -p installed
    ! rm -rf installed/*
    export LLVM_COMPILER=clang
    ./configure CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" --disable-static --prefix=$(pwd)/installed
    sed 's/PTR/void */' -i util/cairo-trace/lookup-symbol.c
    make -j$(nproc)
    make install
    
    # copy over the shared libraries here
    cp installed/lib/libcairo.so.2.11600.0 "$LIB_INSTR_DIR/libcairo.so"
    cp installed/lib/libcairo-gobject.so.2.11600.0 "$LIB_INSTR_DIR/libcairo-gobject.so"
)
