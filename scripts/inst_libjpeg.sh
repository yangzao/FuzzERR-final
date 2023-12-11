#!/bin/bash

set -e
set -u
set -x
set -o pipefail
# export PS4='[ $LINENO ]: '

export BIN_AFL_CLANG_FAST=$HOME/code/research/FuzzERR_AFLplusplus/afl-clang-fast
export BIN_AFL_CLANG_FASTPP=$HOME/code/research/FuzzERR_AFLplusplus/afl-clang-fast++

# import utility functions
. $(dirname "$0")/utils.sh

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libjpeg")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libjpeg-turbo_2.1.2.orig/libjpeg-turbo-2.1.2")

# ======================================
# create instrumented libjpeg.so
# ======================================
echo_header "create instrumented libjpeg.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libjpeg.so" -Wl,--version-script="$LIB_INSTR_DIR"/libjpeg.map -Wl,-soname,libjpeg.so.8 \
		-lbacktrace
)

# ======================================
# make symlinks to instrumented libjpeg.so in current directory
# ======================================
echo_header "create symlink libjpeg.so.8"
(
	cd $LIB_INSTR_DIR
	create_symlink libjpeg.so.8 libjpeg.so.final.so
)
