#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libssl")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/openssl-3.0.2")


(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" debian/rules clean
    # mkdir -p installed
    # ! rm -rf installed/*

    DEB_BUILD_OPTIONS="debug nostrip noopt nodoc nocheck parallel=$(nproc)" \
        CC=wllvm CXX=wllvm++ CFLAGS="-g -O0" CXXFLAGS="-g -O0" debian/rules build -j$(nproc)

    # make -j$(nproc)
    # make install
    
    # copy over the shared libraries here
    cp "$LIB_SRC_DIR"/build_shared/libssl.so.3 "$LIB_INSTR_DIR/libssl.so"
    cp "$LIB_SRC_DIR"/build_shared/libssl.ld "$LIB_INSTR_DIR/libssl.ld"
    cp "$LIB_SRC_DIR"/build_shared/libcrypto.so.3 "$LIB_INSTR_DIR/../libcrypto/libcrypto.so"
    cp "$LIB_SRC_DIR"/build_shared/libcrypto.ld "$LIB_INSTR_DIR/libcrypto.ld"
)
