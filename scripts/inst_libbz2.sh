#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

# import utility functions
. $(dirname "$0")/utils.sh

BASE_DIR=$HOME/code/research/FuzzERR

# libbz2 related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libbz2")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/bzip2-bzip2-1.0.8/bzip2-bzip1-1.0.8")

# dependent binaries related
# 1. file
FILE_SRC_DIR=$(realpath "$BASE_DIR/../fuzzerr_program_sources/file_src")
FILE_INSTALL_DIR=$(realpath "$BASE_DIR/experiments/libbz2/file_install")
FILE_BIN="$FILE_INSTALL_DIR/bin/file"

# ======================================
# create instrumented libbz2.so
# ======================================
echo_header "create instrumented libbz2.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libbz2.so" -Wl,-soname -Wl,libbz2.so.1.0
)

# ======================================
# make symlinks to instrumented libbz2 in current directory
# ======================================
echo_header "create symlink libbz2.so.1.0"
(
	cd $LIB_INSTR_DIR
	create_symlink libbz2.so.1.0 libbz2.so.final.so
)
