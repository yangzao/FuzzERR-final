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

# libelf related
LIB_INSTR_DIR=$(realpath "$BASE_DIR/experiments/libelf")
LIB_SRC_DIR=$(realpath "$BASE_DIR/../detecterr_input/elfutils_0.187.orig/elfutils-0.187")

# ======================================
# create instrumented libelf.so
# ======================================
echo_header "create instrumented libelf.so"
(
	cd $BASE_DIR
	scripts/inst_so.sh "$LIB_INSTR_DIR/libelf.so" \
		-Wl,--soname,libelf.so.1 \
		-Wl,--build-id -Wl,--version-script,"$LIB_INSTR_DIR/libelf.map",--no-undefined \
		-lbacktrace \
		-lz
)

# ======================================
# make symlinks to instrumented libelf in current directory
# ======================================
echo_header "create symlink libelf.so.1"
(
	cd $LIB_INSTR_DIR
	create_symlink libelf.so.1 libelf.so.final.so
)

# # ======================================
# # build dependent binaries that would use this instrumetned libelf
# # ======================================
# # 1. elfutils (readelf, objdump, addr2line, nm etc)
# ELFUTILS_SRC_DIR=$(realpath "$BASE_DIR/../fuzzerr_program_sources/elfutils_src")
# ELFUTILS_INSTALL_DIR=$(realpath "$LIB_INSTR_DIR"/elfutils_install)
# ELFUTILS_NM_BIN="$ELFUTILS_INSTALL_DIR"/bin/eu-nm
# ELFUTILS_STRINGS_BIN="$ELFUTILS_INSTALL_DIR"/bin/eu-strings
# ELFUTILS_OBJDUMP_BIN="$ELFUTILS_INSTALL_DIR"/bin/eu-objdump
# (
#     echo_header "build elfutils with afl and asan"
#
#     cd $ELFUTILS_SRC_DIR/elfutils-0.187
#
#     # remove any existing configuration so that we can start with a clean slate
#     if [[ -f ./Makefile ]]; then
#         make distclean
#     fi
#
#     # configure
#     CFLAGS="-g -O0 -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-const-variable -Wno-unused-but-set-parameter"
#     CXXFLAGS="-g -O0 -Wno-gnu-variable-sized-type-not-at-end -Wno-unused-const-variable -Wno-unused-but-set-parameter"
#     ./configure CC=$BIN_AFL_CLANG_FAST CXX=$BIN_AFL_CLANG_FASTPP CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" --disable-debuginfod --prefix="$ELFUTILS_INSTALL_DIR"
#
#     # replace afl-clang-fast with clang for libs
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' lib/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' backends/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libcpu/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libdwfl/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libdwelf/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libasm/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' debuginfod/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libelf/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libebl/Makefile
#     sed -i 's#/home/shank/code/research/FuzzERR_AFLplusplus/afl-clang-fast#clang#g' libdw/Makefile
#
#     # build and install
#     AFL_USE_ASAN=1 AFL_DONT_OPTIMIZE=1 make -j$(nproc)
#     make install
#
#     # patch the binaries
#     patchelf --force-rpath --add-rpath $LIB_INSTR_DIR $ELFUTILS_NM_BIN
#     printf "[*] patched 'eu-nm' is at $ELFUTILS_NM_BIN\n"
#     patchelf --force-rpath --add-rpath $LIB_INSTR_DIR $ELFUTILS_STRINGS_BIN
#     printf "[*] patched 'eu-strings' is at $ELFUTILS_STRINGS_BIN\n"
#     patchelf --force-rpath --add-rpath $LIB_INSTR_DIR $ELFUTILS_OBJDUMP_BIN
#     printf "[*] patched 'eu-objdump' is at $ELFUTILS_OBJDUMP_BIN\n"
# )
