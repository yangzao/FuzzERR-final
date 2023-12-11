#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

export BIN_AFL_CLANG_FAST=$HOME/code/research/FuzzERR_AFLplusplus/afl-clang-fast
export BIN_AFL_CLANG_FASTPP=$HOME/code/research/FuzzERR_AFLplusplus/afl-clang-fast++

# import utility functions
. $(dirname "$0")/utils.sh

BASE_DIR=$HOME/code/research/FuzzERR

# libelf related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libsqlite")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/sqlite3_3.37.2.orig/sqlite3-3.37.2")

# ======================================
# create instrumented libsqlite3.so
# ======================================
echo_header "create instrumented libsqlite3.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libsqlite3.so" \
		-Wl,-soname -Wl,libsqlite3.so.0 \
		-lbacktrace \
		-lz \
		-lm
)

# ======================================
# make symlinks to instrumented libjsqlite3.so in current directory
# ======================================
echo_header "create symlinks to libsqlite3.so"
(
	cd $LIB_INSTR_DIR
	create_symlink libsqlite3.so.0 libsqlite3.so.final.so
	create_symlink libsqlite3.so.0.8.6 libsqlite3.so.final.so
)
