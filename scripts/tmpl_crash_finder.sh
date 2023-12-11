#! /bin/bash

# env vars
export FUZZERR_DEBUG=1
export FUZZERR_ONLY_INNER=1
export FUZZERR_ENABLE_BACKTRACE=1
export FUZZERR_AFL_MAP={{fuzzerr_afl_map}}
export FUZZERR_BIN_SRC_PATH=#todo
export FUZZERR_LIB_SRC_PATH=#todo
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1"

# local vars
BIN_CRASH_FINDER=$HOME/code/research/FuzzERR/scripts/fuzzerr/crash_finder.py
BIN_UNDER_TEST=#todo
ARGS={{args}}

(
    cd $HOME/code/research/FuzzERR
    
    # TODO: create any directories required in afl tmpfs
   
    # TODO: patchelf the bin

    # convert the $ARGS to a format suitable for crash-finder (comma separated)
    CONVERTED_ARGS=$(echo $ARGS | sed 's/ /,/g')

    echo -e "\n================================================================\n"
    echo -e "$(tput setaf 3)Running CrashFinder:$(tput sgr 0)\n"

    # crash_finder cmd
    $BIN_CRASH_FINDER \
        --prog_path=$BIN_UNDER_TEST \
        --mask_path=$FUZZERR_AFL_MAP \
        --args=$CONVERTED_ARGS \
        --enable-backtrace

    echo -e "\n================================================================\n"
    echo -e "$(tput setaf 3)Running Binary without injecting faults:$(tput sgr 0)\n"

    # fuzzerr disabled run
    FUZZERR_DISABLE=1 timeout 3s $BIN_UNDER_TEST $ARGS

    echo -e "\n================================================================\n"
    echo -e "$(tput setaf 3)Running Binary with fault injection as per the error mask:$(tput sgr 0)\n"

    # direct run cmd
    $BIN_UNDER_TEST $ARGS
)


