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

# libpng related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libpng")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libpng1.6_1.6.37.orig/libpng-1.6.37")

# ======================================
# create instrumented libpng.so
# ======================================
echo_header "create instrumented libpng.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libpng.so" \
		-Wl,-soname,libpng16.so.16 \
		-Wl,--version-script="$LIB_SRC_DIR/libpng.vers" \
		-lbacktrace \
		-lz \
		-lm

	cd $LIB_INSTR_DIR
	create_symlink libpng16.so libpng.so.final.so
	create_symlink libpng16.so.16 libpng.so.final.so
	create_symlink libpng16.so.16.37.0 libpng.so.final.so
)
