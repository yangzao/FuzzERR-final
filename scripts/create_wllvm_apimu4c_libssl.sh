#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/APIMU4C/libssl")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/openssl-1-1-pre8_patched_apimu4c/openssl-1-1-pre8_patched")


(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./config no-asm no-idea --debug -v --prefix="$LIB_SRC_DIR"/installed
    mkdir -p installed
    ! rm -rf installed/*

    make clean
    CC=wllvm CFLAGS="-g -O0" make -j$(nproc)
    make install
    
    # copy over the shared libraries here
    cp "$LIB_SRC_DIR"/installed/lib/libssl.so.1.1 "$LIB_INSTR_DIR/libssl.so"
    cp "$LIB_SRC_DIR"/libssl.map "$LIB_INSTR_DIR/libssl.map"
    cp "$LIB_SRC_DIR"/installed/lib/libcrypto.so.1.1 "$LIB_INSTR_DIR/../libcrypto/libcrypto.so"
    cp "$LIB_SRC_DIR"/libcrypto.map "$LIB_INSTR_DIR/../libcrypto/libcrypto.map"
)
