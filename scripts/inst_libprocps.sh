#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '

# import utility functions
. $(dirname "$0")/utils.sh

BASE_DIR=$HOME/code/research/FuzzERR

# lib related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libprocps")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/procps-v4.0.1rc1/procps-v4.0.1rc1")

# 1. procps (ps, kill, w, etc.)
PROCPS_SRC_DIR=$(realpath "$BASE_DIR/../fuzzerr_program_sources/procps_src")
PROCPS_INSTALL_DIR=$(realpath $LIB_INSTR_DIR/procps_install)
PROCPS_W_BIN=$PROCPS_INSTALL_DIR/bin/w
PROCPS_FREE_BIN=$PROCPS_INSTALL_DIR/bin/free
PROCPS_PS_BIN=$PROCPS_INSTALL_DIR/bin/ps
PROCPS_TOP_BIN=$PROCPS_INSTALL_DIR/bin/top
PROCPS_VMSTAT_BIN=$PROCPS_INSTALL_DIR/bin/vmstat

# ======================================
# create instrumented libproc2.so
# ======================================
echo_header "create instrumented libproc2.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libproc2.so" -Wl,--version-script,"$LIB_SRC_DIR/library/libproc2.sym"
)

# ======================================
# make symlinks to instrumented lib in current directory
# ======================================
echo_header "create symlinks to libproc2.so"
(
	cd $LIB_INSTR_DIR
	create_symlink libproc2.so.0 libproc2.so.final.so
)
