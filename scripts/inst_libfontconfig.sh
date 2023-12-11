#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

# import utility functions
. $(dirname "$0")/utils.sh

BASE_DIR=$HOME/code/research/FuzzERR

# libcairo related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libfontconfig")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/fontconfig-2.14.1/fontconfig-2.14.1")

# ======================================
# create instrumented libfontconfig.so
# ======================================
echo_header "create instrumented libfontconfig.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libfontconfig.so" \
		-Wl,-soname,libfontconfig.so.1

	cd $LIB_INSTR_DIR
	create_symlink libcairo.so.1 libcairo.so.final.so
	create_symlink libcairo.so.1.12 libcairo.so.final.so
	create_symlink libcairo.so.1.12.0 libcairo.so.final.so
)
