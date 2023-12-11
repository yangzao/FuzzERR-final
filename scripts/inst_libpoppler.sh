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

# libpng related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libpoppler")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/poppler-poppler-22.02.0/poppler-poppler-22.02.0")

# ======================================
# create instrumented libpoppler.so
# ======================================
echo_header "create instrumented libpoppler.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libpoppler.so" \
		-Wl,-soname,libpoppler.so.118 \
		-lbacktrace \
		-lfreetype \
		-lfontconfig \
		-ljpeg \
		-lz \
		-lcurl \
		-lopenjp2 \
		-llcms2 \
		-lpng16 \
		-ltiff \
		-lm \
		-lstdc++ \
		-lgcc_s \
		-liberty

	cd $LIB_INSTR_DIR
	create_symlink libpoppler.so.118 libpoppler.so.final.so
	create_symlink libpoppler.so.118.0 libpoppler.so.final.so
	create_symlink libpoppler.so.118.0.0 libpoppler.so.final.so

	# also create a copy of this instrumented lib in another folder
	# so that if a program depends on both libpoppler-glib
	# and libpoppler, we can selectively use one instrumetned lib
	# as we cannot use two instrumented lib simultaneously
	mkdir -p "$LIB_INSTR_DIR/instrumented_libpoppler"
	cd "$LIB_INSTR_DIR/instrumented_libpoppler"
	create_symlink libpoppler.so.118 ../libpoppler.so.final.so
	create_symlink libpoppler.so.118.0 ../libpoppler.so.final.so
	create_symlink libpoppler.so.118.0.0 ../libpoppler.so.final.so
)

# ======================================
# create instrumented libpoppler-glib.so
# ======================================
echo_header "create instrumented libpoppler-glib.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libpoppler-glib.so" \
		-Wl,-soname,libpoppler-glib.so.8 \
		-lbacktrace \
		-lpoppler \
		-lcairo \
		-lfreetype \
		-lgio-2.0 \
		-lgobject-2.0 \
		-lglib-2.0 \
		-lstdc++ \
		-lm \
		-lgcc_s \
		-liberty

	cd $LIB_INSTR_DIR
	create_symlink libpoppler-glib.so.8 libpoppler-glib.so.final.so
	create_symlink libpoppler-glib.so.8.23 libpoppler-glib.so.final.so
	create_symlink libpoppler-glib.so.8.23.0 libpoppler-glib.so.final.so

	# also create a copy of this instrumented lib in another folder
	# so that if a program depends on both libpoppler-glib
	# and libpoppler, we can selectively use one instrumetned lib
	# as we cannot use two instrumented lib simultaneously
	mkdir -p "$LIB_INSTR_DIR/instrumented_libpoppler_glib"
	cd "$LIB_INSTR_DIR/instrumented_libpoppler_glib"
	create_symlink libpoppler-glib.so.8 ../libpoppler-glib.so.final.so
	create_symlink libpoppler-glib.so.8.23 ../libpoppler-glib.so.final.so
	create_symlink libpoppler-glib.so.8.23.0 ../libpoppler-glib.so.final.so
)
