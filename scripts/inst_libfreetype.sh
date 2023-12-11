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
LIB_INSTR_DIR=$(realpath -m "$BASE_DIR/experiments/libfreetype")
LIB_SRC_DIR=$(realpath -m "$BASE_DIR/../detecterr_input/freetype_2.11.1+dfsg.orig/freetype-2.11.1")

# ======================================
# create instrumented libfreetype.so
# ======================================
echo_header "create instrumented libfreetype.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libfreetype.so" -Wl,--version-script="$LIB_INSTR_DIR"/libfreetype.ver -Wl,-soname,libfreetype.so.6 \
		-lbz2 \
		-liberty \
		-lbacktrace \
		-lbrotlicommon \
		-lbrotlidec \
		-lglib-2.0 \
		-lgraphite2 \
		-lharfbuzz \
		-lm \
		-lpcre \
		-lpng16 \
		-lz
)

# ======================================
# make symlinks to instrumented libfreetype.so in current directory
# ======================================
echo_header "create symlink libfreetype.so.6"
(
	cd $LIB_INSTR_DIR
	create_symlink libfreetype.so.6 libfreetype.so.final.so
	create_symlink libfreetype.so.6.18.1 libfreetype.so.final.so
)
