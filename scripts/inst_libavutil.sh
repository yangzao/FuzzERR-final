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

# lib related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libavutil")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/ffmpeg_4.4.2.orig/ffmpeg-4.4.2")

# ======================================
# create instrumented libavutil.so
# ======================================
echo_header "create instrumented libavutil.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libavutil.so" \
		-Wl,-soname,libavutil.so.56 \
		-Wl,-Bsymbolic \
		-Wl,--version-script,"$LIB_INSTR_DIR"/libavutil.ver \
		-lbacktrace \
		-lva-drm \
		-lva \
		-lva-x11 \
		-lvdpau \
		-lX11 \
		-lm \
		-ldrm \
		-lXext \
		-lXfixes \
		-lxcb \
		-lXau \
		-lXdmcp \
		-lbsd \
		-lmd
)

# ======================================
# make symlinks to instrumented libavutil.so in current directory
# ======================================
echo_header "create symlinks to libavutil.so"
(
	cd $LIB_INSTR_DIR
	create_symlink libavutil.so.56 libavutil.so.final.so
	create_symlink libavutil.so.56.70.100 libavutil.so.final.so
)
