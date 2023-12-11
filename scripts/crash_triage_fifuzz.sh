#!/bin/bash

# set -e
# set -u
# set -x
# export PS4='[ $LINENO ]: '

BASE_DIR=$HOME/code/research/FuzzERR

# requires 1 argument (the path to the directory for the program)
# ensure 1 argument is provided
# if not, print usage and exit
if [ $# -ne 1 ]; then
    echo "Usage: $0 <path to fifuzz program directory>"
    exit 1
fi
prog_dir=$1

# convert prog_dir to absolute path
prog_dir=$(readlink -f $prog_dir)

# ensure the program directory exists
# if not, print error and exit
if [ ! -d $prog_dir ]; then
    echo "Error: $prog_dir does not exist"
    exit 1
fi

afl_output_dir=$prog_dir/output
crashes_dir=$afl_output_dir/default/crashes
if [ ! -d $crashes_dir ]; then
    echo "Error: $crashes_dir does not exist"
    exit 1
fi

# print the message that we are starting to triage the crashes from the crashes_dir (in yellow)
echo -e "\033[1;33mTriaging crashes from\033[0m $crashes_dir"

# print the number of crashes in the crashes_dir
# if there are no crashes, exit
num_crashes=$(ls $crashes_dir | rg --invert-match readme | wc -l)
echo -e "\033[1;33mNumber of crashes:\033[0m $num_crashes"
if [ $num_crashes -eq 0 ]; then
    echo "No crashes to triage"
    exit 0
fi

# create directories for intersting crashes and false crashes
interesting_api_missuse_crashes_dir=$crashes_dir/../crashes_interesting_api_misuse
interesting_crashes_dir=$crashes_dir/../crashes_interesting
false_crashes_dir=$crashes_dir/../crashes_false
mkdir -p $interesting_api_missuse_crashes_dir
mkdir -p $interesting_crashes_dir
mkdir -p $false_crashes_dir

# extract the cmd used to run the program from the readme file
cmd=$(cat $crashes_dir/README.txt  | awk 'BEGIN {FS=" -- "};{print $2}' | rg -N .)

# calculate the number of bytes of error mask
prog_name=$(basename $prog_dir)
# numbits=$(cat $BASE_DIR/scripts/inst_fifuzz_$prog_name.sh | rg "^COUNTER=\d+$" | awk -F= '{print $2}')
numbits=7278
echo "numbits: $numbits"
remainder=$((numbits % 8))
if [ $remainder -ne 0 ]; then
    numbits=$((numbits + 8 - remainder))
fi
numbytes=$((numbits / 8))
# we want it to be a multiple fo 4 (sizeof uint32_t, for the errlib)
remainder=$((numbytes % 4))
if [ $remainder -ne 0 ]; then
    numbytes=$((numbytes + 4 - remainder))
fi
echo "numbytes: $numbytes"

# set the path to FUZZERR_AFL_MAP file
export FUZZERR_AFL_MAP=$prog_dir/fuzzerr_afl_map

# path to current input file
curr_input=$prog_dir/curr_input

# addditional env vars
export FUZZERR_DEBUG=1
export FUZZERR_ENABLE_BACKTRACE=1
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1"

# for each crash in the crashes_dir
for crash in $crashes_dir/*; do
    # skip the readme file
    if [ $crash == $crashes_dir/README.txt ]; then
        continue
    fi

    echo "#########################################################"
    # run the crash through the program
    echo -e "\033[1;33mTriaging crash\033[0m $crash"

    # copy the first numbytes bytes of the crash to the FUZZERR_AFL_MAP file
    head -c $numbytes $crash > $FUZZERR_AFL_MAP

    # copy the rest of the bytes to the curr_input file
    tail -c +$((numbytes + 1)) $crash > $curr_input

    # sanity check
    # print sizes of FUZZERR_AFL_MAP and curr_input and the crash
    echo "FUZZERR_AFL_MAP size: $(stat -c %s $FUZZERR_AFL_MAP)"
    echo "curr_input size: $(stat -c %s $curr_input)"
    echo "crash size: $(stat -c %s $crash)"

    # create a copy of cmd with @@ replace with curr_input
    curr_cmd=$(echo $cmd | sed "s#@@#$curr_input#g")

    # run cmd_curr_input
    echo "cmd: $cmd"
    echo "curr_cmd: $curr_cmd"
    $curr_cmd

    # while true loop
    while true; do
        echo "---------------------------------------------------------"
        # ask the user if they want to continue
        read -p "Continue? [n (next) | i (interesting general) | a (interesting api-misuse) f (false) | d (delete) | q (quit) | s (system)] " choice
        case $choice in
            n ) break;;

            i ) # move the crash to the interesting_crashes_dir
                echo -e "\033[1;33mMoving this crash to\033[0m $interesting_crashes_dir"
                mv $crash $interesting_crashes_dir
                break;;

            a ) # move the crash to the interesting_api_missuse_crashes_dir
                echo -e "\033[1;33mMoving this crash to\033[0m $interesting_api_missuse_crashes_dir"
                mv $crash $interesting_api_missuse_crashes_dir
                break;;

            f ) # move the crash to the false_crashes_dir
                echo -e "\033[1;33mMoving this crash to\033[0m $false_crashes_dir"
                mv $crash $false_crashes_dir
                break;;

            d ) # ask the user if they are sure
                read -p "Are you sure you want to delete this crash? [y/n] " choice
                case $choice in
                    y ) # delete the crash
                        echo "*********************************************************"
                        echo -e "\033[1;33mdeleting crash:\033[0m $crash"
                        rm $crash
                        echo "*********************************************************"
                        break;;

                    n ) break;;
                esac;;

            q ) exit;;

            s ) echo -e "\033[1;33mRunning the cmd with uninstrumented binary:\033[0m"
                echo "curr_cmd: $curr_cmd"
                # create a copy of cmd and replace the first path with the basename of that path
                system_binary=$(echo $curr_cmd | cut -d ' ' -f1 | xargs basename)
                echo "system_binary: $system_binary"
                # replace the first group of characters in cmd with cmd_basename
                cmd_system_binary=$(echo $curr_cmd | sed "s#^[/a-zA-Z0-9_-]\+ #$system_binary #")
                echo "cmd_system_binary: $cmd_system_binary"
                $cmd_system_binary
                ;;

            * ) echo "Please answer 'n' / 'k' / 'q'";;
        esac
    done
done

