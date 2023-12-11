#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

# import utility functions
. $(dirname "$0")/utils.sh

# check that one argument is provided
if [ $# -ne 1 ]; then
	echo "Usage: $0 <lib>"
	exit 1
fi

lib=$1
libboost_lib_name="libboost_$lib.so"
echo_header "working on $libboost_lib_name"

BASE_DIR=$HOME/code/research/FuzzERR

# generate errblocks.json and also the wllvm so
echo_header "create errblocks.json and also the wllvm so"
(
	cd experiments/libboost
	./util_build_wllvm_so_lib.sh $lib
)

# libboost related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libboost")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/boost_1_80_0/boost_1_80_0")

linker_flags=
case $lib in
filesystem)
	linker_flags="-l:libboost_atomic.so.1.80.0 -lm -lgcc"
	;;
chrono)
	linker_flags="-stdlib=libc++ -lm -lgcc"
	;;
esac

# # dependent binaries related
# IMAGEMAGICK_SRC_DIR=$(realpath "$BASE_DIR/experiments/libpng/imagemagick_src")
# IMAGEMAGICK_INSTALL_DIR=$(realpath "$BASE_DIR/experiments/libpng/imagemagick_install")
# IMAGEMAGICK_BIN="$IMAGEMAGICK_INSTALL_DIR/bin/magick"

# TESTPNG_SRC_DIR=$(realpath "$BASE_DIR/../tmp/libpng-1.6.35")

# ======================================
# create instrumented libraries
# ======================================
echo_header "create instrumented library: $libboost_lib_name"
(
	cd $BASE_DIR

	version="1.80.0"

	# create the instrumented library
	scripts/inst_so.sh "$LIB_INSTR_DIR"/"$libboost_lib_name" -Wl,-soname,"$libboost_lib_name"."$version" "$linker_flags"

	# create the symlink
	cd $LIB_INSTR_DIR
	create_symlink "$libboost_lib_name"."$version" "$libboost_lib_name".final.so
)
