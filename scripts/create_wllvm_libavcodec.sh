#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libavcodec")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/ffmpeg_4.4.2.orig/ffmpeg-4.4.2")

(
    # generate the shared library
    cd "$LIB_SRC_DIR"
    [[ -f Makefile ]] && make distclean
    mkdir -p installed
    rm -rf installed/*
    export LLVM_COMPILER=clang
    ./configure --prefix=$(pwd)/installed --cc=wllvm --cxx=wllvm++ --extra-cflags="-g -O0" --extra-cxxflags="-g -O0" --enable-shared --disable-doc --disable-stripping --disable-static --disable-stripping --disable-asm --disable-inline-asm --disable-x86asm --disable-programs --disable-optimizations
    make -j$(nproc)
    make install
    
    # copy over the shared library here
    cp installed/lib/libavcodec.so.58.134.100 "$LIB_INSTR_DIR/libavcodec.so"
    cp libavcodec/libavcodec.ver "$LIB_INSTR_DIR/libavcodec.ver"
)
