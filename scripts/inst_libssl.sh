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
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libssl")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/openssl-3.0.2")

# ======================================
# create instrumented libssl.so
# ======================================
echo_header "create instrumented libssl.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libssl.so" \
		-Wl,-znodelete -Wl,-Bsymbolic -Wl,-soname=libssl.so.3 \
		-Wl,--version-script="$LIB_INSTR_DIR"/libssl.ld \
		-lbacktrace \
		-liberty \
		-lcrypto
)

# ======================================
# make symlinks to instrumented libssl.so.3 in current directory
# ======================================
echo_header "create symlink libssl.so.3"
(
	cd $LIB_INSTR_DIR
	create_symlink libssl.so.3 libssl.so.final.so
)
