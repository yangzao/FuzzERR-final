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
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libavcodec")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/ffmpeg_4.4.2.orig/ffmpeg-4.4.2")

# ======================================
# create instrumented libavcodec.so
# ======================================
echo_header "create instrumented libavcodec.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libavcodec.so" -Wl,-soname,libavcodec.so.58 -Wl,-Bsymbolic -Wl,--version-script,"$LIB_INSTR_DIR"/libavcodec.ver \
		-liberty \
		-lbacktrace \
		-lswresample \
		-lavutil \
		-lm \
		-llzma \
		-lz \
		-lva \
		-lsoxr \
		-lva-drm \
		-lva-x11 \
		-lvdpau \
		-lX11 \
		-ldrm \
		-lmfx \
		-lOpenCL \
		-lgomp \
		-lXext \
		-lXfixes \
		-lxcb \
		-lstdc++ \
		-lgcc_s \
		-lXau \
		-lXdmcp \
		-lbsd \
		-lmd
)

# ======================================
# make symlinks to instrumented libavcodec.so in current directory
# ======================================
echo_header "create symlinks to libavcodec.so"
(
	cd $LIB_INSTR_DIR
	create_symlink libavcodec.so.58 libavcodec.so.final.so
	create_symlink libavcodec.so.58.134 libavcodec.so.final.so
	create_symlink libavcodec.so.58.134.100 libavcodec.so.final.so
)
