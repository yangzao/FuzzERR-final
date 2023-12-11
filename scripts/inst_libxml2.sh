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
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libxml2")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libxml2_2.9.13+dfsg.orig/libxml2-2.9.13")

# ======================================
# create instrumented libxml2.so
# ======================================
echo_header "create instrumented libxml2.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libxml2.so" \
		-Wl,-soname,libxml2.so.2 \
		-Wl,--version-script="$LIB_SRC_DIR/libxml2.syms" \
		-lbacktrace \
		-lz \
		-llzma \
		-lm
)

# ======================================
# make symlinks to instrumented libxml2 in current directory
# ======================================
echo_header "create symlink libxml2.so.2"
(
	cd $LIB_INSTR_DIR
	create_symlink libxml2.so.2 libxml2.so.final.so
	create_symlink libxml2.so.2.9.13 libxml2.so.final.so
)
