#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

function errexit() {
	echo "error in >> $STAGE"
	exit 1
}

function echo_header() {
	set +x
	echo "********************************************"
	echo "*** $1"
	echo "********************************************"
	set -x
}

BASE_DIR=$HOME/code/research/FuzzERR

# libncurses related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libncurses")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/ncurses-6.3/ncurses-6.3")

# dependent binaries related
# 1. htop
HTOP_SRC_DIR=$(realpath "$BASE_DIR/../fuzzerr_program_sources/htop_src")
HTOP_INSTALL_DIR=$(realpath "$BASE_DIR/experiments/libncurses/htop_install")
HTOP_BIN="$HTOP_INSTALL_DIR/bin/htop"

# ======================================
# create instrumented libncursesw.so
# ======================================
echo_header "create instrumented libncursesw.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libncursesw.so" -Wl,-soname,libncursesw.so.6.3,-stats,-lc -ldl
)

# ======================================
# make symlinks to instrumented libncursesw in current directory
# ======================================
echo_header "create symlink libncursesw.so.6.3"
(

	cd "$LIB_INSTR_DIR"
	if ! [[ -f ./libncursesw.so.6 ]]; then
		ln -s ./libncursesw.so.final.so ./libncursesw.so.6
	fi
	if ! [[ -f ./libncursesw.so.6.3 ]]; then
		ln -s ./libncursesw.so.final.so ./libncursesw.so.6.3
	fi
)
