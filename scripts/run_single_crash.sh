#!/bin/bash

# takes a single argument, the path to crashing mask

# ensure one argument provided
if [ $# -ne 1 ]; then
    echo "Usage: $0 <path to crashing mask>"
    exit 1
fi

# ensure argument is a file
if [ ! -f $1 ]; then
    echo "Error: $1 is not a file"
    exit 1
fi

error_mask=$(realpath $1)
fuzzing_cmd_file="$error_mask"_fuzzing_cmd
fuzzing_cmd_file=$(realpath $fuzzing_cmd_file)

# ensure fuzzing command file exists
if [ ! -f $fuzzing_cmd_file ]; then
    echo "Error: $fuzzing_cmd_file does not exist"
    exit 1
fi

# extract args from the fuzzing_cmd_file
args=$(cat $fuzzing_cmd_file | awk 'BEGIN {FS=" -- "};{print $2}' | cut -d' ' -f 2- | sd -s "/home/shank" $HOME)

export FUZZERR_DEBUG=1
export FUZZERR_ONLY_INNER=1
export FUZZERR_ENABLE_BACKTRACE=1
export FUZZERR_AFL_MAP=$error_mask 
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1"

# binary is the first item in args
binary=$(echo $args | cut -d' ' -f 1)

# run the binary with the rest of the args
# set rest_args to be the rest of the args
rest_args=$(echo $args | cut -d' ' -f 2-)
ltrace -c $binary $rest_args
