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

# libcairo related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libcairo")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/cairo_1.16.0.orig/cairo-1.16.0")

# ======================================
# create instrumented libcairo.so
# ======================================
echo_header "create instrumented libcairo.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libcairo.so" \
		-Wl,-soname,libcairo.so.2 \
		-lbacktrace \
		-lpixman-1 \
		-lfontconfig \
		-lfreetype \
		-lpng16 \
		-lxcb-shm \
		-lxcb \
		-lxcb-render \
		-lXrender \
		-lX11 \
		-lXext \
		-lz \
		-lm \
		-lexpat \
		-luuid \
		-lbrotlidec \
		-lXau \
		-lXdmcp \
		-lbrotlicommon \
		-lbsd \
		-lmd

	cd $LIB_INSTR_DIR
	create_symlink libcairo.so.2 libcairo.so.final.so
	create_symlink libcairo.so.2.11600.0 libcairo.so.final.so
)

echo_header "create instrumented libcairo-gobject.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libcairo-gobject.so" \
		-Wl,-soname,libcairo-gobject.so.2 \
		-lbacktrace \
		-lcairo \
		-lpixman-1 \
		-lfontconfig \
		-lfreetype \
		-lpng16 \
		-lxcb-shm \
		-lxcb \
		-lxcb-render \
		-lXrender \
		-lX11 \
		-lXext \
		-lz \
		-lgobject-2.0 \
		-lglib-2.0 \
		-lm \
		-lc \
		-lexpat \
		-luuid \
		-lbrotlidec \
		-lXau \
		-lXdmcp \
		-lffi \
		-lpcre \
		-lbrotlicommon \
		-lbsd \
		-lmd

	cd $LIB_INSTR_DIR
	create_symlink libcairo-gobject.so.2 libcairo-gobject.so.final.so
	create_symlink libcairo-gobject.so.2.11600.0 libcairo-gobject.so.final.so
)
