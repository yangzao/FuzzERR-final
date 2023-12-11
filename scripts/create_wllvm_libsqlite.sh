#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libsqlite")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/sqlite3_3.37.2.orig/sqlite3-3.37.2")

(
    cd "$LIB_SRC_DIR"
    export LLVM_COMPILER=clang
    [[ -f Makefile ]] && make distclean
    ./configure CC=wllvm CFLAGS="-g -O0" --prefix=$(pwd)/installed --enable-shared --disable-static
    make -j$(nproc)
    ! make install
    
    # copy over the shared library here
    cp installed/lib/libsqlite3.so.0.8.6 "$LIB_INSTR_DIR/libsqlite3.so"
)
