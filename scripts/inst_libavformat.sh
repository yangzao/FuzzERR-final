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
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libavformat")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/ffmpeg_4.4.2.orig/ffmpeg-4.4.2")

# ======================================
# create instrumented libavformat.so
# ======================================
echo_header "create instrumented libavformat.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libavformat.so" -Wl,-soname,libavformat.so.58 -Wl,-Bsymbolic -Wl,--version-script,"$LIB_INSTR_DIR"/libavformat.ver \
		-lbacktrace \
		-lavcodec \
		-lavutil \
		-lm \
		-lbz2 \
		-lz \
		-lc \
		-lswresample \
		-lvpx \
		-lwebpmux \
		-lwebp \
		-llzma \
		-ldav1d \
		-lrsvg-2 \
		-lgobject-2.0 \
		-lglib-2.0 \
		-lcairo \
		-lzvbi \
		-lsnappy \
		-laom \
		-lcodec2 \
		-lgsm \
		-lmp3lame \
		-lopenjp2 \
		-lopus \
		-lshine \
		-lspeex \
		-ltheoraenc \
		-ltheoradec \
		-ltwolame \
		-lvorbis \
		-lvorbisenc \
		-lx264 \
		-lx265 \
		-lxvidcore \
		-lva \
		-lmfx \
		-lva-drm \
		-lva-x11 \
		-lvdpau \
		-lX11 \
		-ldrm \
		-lOpenCL \
		-lsoxr \
		-lcairo-gobject \
		-lgdk_pixbuf-2.0 \
		-lgio-2.0 \
		-lxml2 \
		-lpangocairo-1.0 \
		-lpango-1.0 \
		-lgcc_s \
		-lffi \
		-lpcre \
		-lpixman-1 \
		-lfontconfig \
		-lfreetype \
		-lpng16 \
		-lxcb-shm \
		-lxcb \
		-lxcb-render \
		-lXrender \
		-lXext \
		-lstdc++ \
		-logg \
		-lnuma \
		-lpthread \
		-lXfixes \
		-lgomp \
		-lgmodule-2.0 \
		-ljpeg \
		-lmount \
		-lselinux \
		-licuuc \
		-lpangoft2-1.0 \
		-lharfbuzz \
		-lfribidi \
		-lthai \
		-lexpat \
		-luuid \
		-lbrotlidec \
		-lXau \
		-lXdmcp \
		-lblkid \
		-lpcre2-8 \
		-licudata \
		-lgraphite2 \
		-ldatrie \
		-lbrotlicommon \
		-lbsd \
		-lmd
)

# ======================================
# make symlinks to instrumented libavformat.so in current directory
# ======================================
echo_header "create symlinks to libavformat.so"
(
	cd $LIB_INSTR_DIR
	create_symlink libavformat.so.58 libavformat.so.final.so
	create_symlink libavformat.so.58.76 libavformat.so.final.so
	create_symlink libavformat.so.58.76.100 libavformat.so.final.so
)
