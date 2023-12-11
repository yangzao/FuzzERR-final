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

# libzstd related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libzstd")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libzstd_1.4.8+dfsg.orig/zstd-1.4.8")

# ======================================
# create instrumented libzstd.so
# ======================================
echo_header "create instrumented libzstd.so"
(
	cd $BASE_DIR
	# $BASE_DIR/experiments/libzstd/huf_decompress_amd64.o
	scripts/inst_so.sh "$LIB_INSTR_DIR/libzstd.so" \
		-lbacktrace
)

# ======================================
# make symlinks to instrumented libzstd in current directory
# ======================================
echo_header "create symlink libzstd.so.1"
(
	cd $LIB_INSTR_DIR
	create_symlink libzstd.so.1 libzstd.so.final.so
	create_symlink libzstd.so.1.4.8 libzstd.so.final.so
)
