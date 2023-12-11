#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libzstd")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libzstd_1.4.8+dfsg.orig/zstd-1.4.8")


(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make clean
    # ./configure CC=wllvm CFLAGS="-g -O0" --prefix=$(pwd)/installed --enable-shared --disable-static
    CC=wllvm CFLAGS="-g -O0" CXX=wllvm++ CXXFLAGS="-g -O0" make -j$(nproc)
    make install DESTDIR=$(pwd)/installed
    
    # copy over the shared library here
    cp installed/usr/local/lib/libzstd.so.1.4.8 "$LIB_INSTR_DIR/libzstd.so"
)
