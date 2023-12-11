#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/AblationStudy/F_FIP/libjpeg")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/libjpeg-turbo_2.1.2.orig/libjpeg-turbo-2.1.2")

(
	# generate the shared library
	cd "$LIB_SRC_DIR"
	mkdir -p build
	cd build
	rm -rf ./*
	mkdir -p ../installed
	rm -rf ../installed/*
	export LLVM_COMPILER=clang
	cmake .. -GNinja -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_INSTALL_PREFIX=../installed -DCMAKE_C_COMPILER=wllvm -DCMAKE_CXX_COMPILER=wllvm++ -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" -DCMAKE_BUILD_TYPE=debug -DWITH_JPEG8=ON -DENABLE_STATIC=False -DWITH_SIMD=OFF
	cmake --build . --target install
	cd ..

	# copy over the shared library here
	cp installed/lib/libjpeg.so.8.2.2 "$LIB_INSTR_DIR/libjpeg.so"
)
