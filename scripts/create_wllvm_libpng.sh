#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libpng")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libpng1.6_1.6.37.orig/libpng-1.6.37")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    ./configure CC=wllvm CFLAGS="-g -O0" --prefix=$(pwd)/installed --enable-shared --disable-static
    make -j$(nproc)
    make install
    
    # copy over the shared library here
    cp installed/lib/libpng16.so.16.37.0 "$LIB_INSTR_DIR/libpng.so"

    # copy over the version script
    cp libpng.vers "$LIB_INSTR_DIR"
)
