#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR_SSL=$(realpath "$BASE_DIR/experiments/APIMU4C/openssl_dataset/libssl")
LIB_INSTR_DIR_CRYPTO=$(realpath "$BASE_DIR/experiments/APIMU4C/openssl_dataset/libcrypto")
LIB_SRC_DIR=$(realpath "/workdisk/shank/FuzzERR_stuff/detecterr_input/openssl-1-1-pre8_patched_cmdline/openssl-1-1-pre8_patched_cmdline")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" ./config no-asm no-idea no-threads --debug -v --prefix="$LIB_SRC_DIR"/installed
    mkdir -p installed
    ! rm -rf installed/*

    make clean
    CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" make -j$(nproc)
    make install
    
    # copy over the shared libraries here
    cp "$LIB_SRC_DIR"/installed/lib/libssl.so.1.1 "$LIB_INSTR_DIR_SSL/libssl.so"
    cp "$LIB_SRC_DIR"/installed/lib/libcrypto.so.1.1 "$LIB_INSTR_DIR_SSL/libcrypto.so.1.1"
    cp "$LIB_SRC_DIR"/libssl.map "$LIB_INSTR_DIR_SSL/libssl.map"
    cp "$LIB_SRC_DIR"/installed/lib/libssl.so.1.1 "$LIB_INSTR_DIR_CRYPTO/libssl.so.1.1"
    cp "$LIB_SRC_DIR"/installed/lib/libcrypto.so.1.1 "$LIB_INSTR_DIR_CRYPTO/libcrypto.so"
    cp "$LIB_SRC_DIR"/libcrypto.map "$LIB_INSTR_DIR_CRYPTO/libcrypto.map"
)
