#!/bin/bash

set -e
set -u
set -x
set -o pipefail
export PS4='[ $LINENO ]: '


function errexit(){
    echo "error in >> $STAGE"
    exit 1
}


BASE_DIR="/home/shank/code/research/FuzzERR"
SO_FILENAME="$(basename /"$1/")"


echo "[~] this script assumes that the $SO_FILENAME file has been created using wllvm"


echo ">> working on instrumenting $1"


STAGE="ensure that the required $1.errblocks.json file is already available"
echo ">> $STAGE"
[ -f $1.errblocks.json ] || errexit


STAGE="generating bitcode file"
echo ">> $STAGE"
extract-bc $1 || errexit


STAGE="disassembling bitcode file"
echo ">> $STAGE"
llvm-dis $1.bc || errexit


STAGE="recompiling the instrumentation pass"
echo ">> $STAGE"
(   
    mkdir -p build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=DEBUG ../InstrumentationPasses && \
    cmake --build . && \
    cd ..
) || errexit


STAGE="instrumenting bitcode file"
echo ">> $STAGE"
# log filename -> inst_so__libpng.so.log
LOG_FILE="$(basename /"$0/")__$SO_FILENAME.log"
opt -load build/FuzzERRInstrumentation/libInstrumentErr.so \
    -enable-new-pm=0 \
    -instrumentErr \
    -errblocks=$1.errblocks.json $1.bc \
    -o $1.inst.bc \
    >"$LOG_FILE" 2>&1 \
    || errexit


STAGE="disassembling instrumented bitcode file"
echo ">> $STAGE"
llvm-dis $1.inst.bc || errexit


STAGE="compiling error injection library"
echo ">> $STAGE"
(cd ErrLib && \
    make clean && \
    CC=$(which clang) make && \
    cd ..) \
    || errexit


STAGE="linking instrumented bitcode file with error injection library"
echo ">> $STAGE"
llvm-link ErrLib/build/errlib/err.bc $1.inst.bc -o $1.final.bc || errexit


STAGE="disassembling final bitcode file"
echo ">> $STAGE"
llvm-dis $1.final.bc || errexit


STAGE="recreating $SO_FILENAME file from the final instrumented file"
echo ">> $STAGE"
if [[ $# -ge 1 ]]; then
    all_args=("$@")
    all_except_first_arg="${all_args[@]:1}"
    $CC -v -shared -g -O0 -fpic $1.final.bc -o $1.final.so $all_except_first_arg || errexit
else
    $CC -v -shared -g -O0 -fpic $1.final.bc -o $1.final.so || errexit
fi
