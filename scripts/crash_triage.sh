#!/bin/bash

# =============================================================================
# NOTE [IMPORTANT]
# before running this script, you must set up the crash_finder_template_script
# for this target.
# =============================================================================


# ensure that we have 1 argument
if [ $# -lt 2 ]; then
    echo "Usage: $0 <saved_crashes_dir> <crash_finder_template_script>"
    exit 1
fi
saved_crashes_dir=$1
crash_finder_template_script=$2

# if we have a third argument, use it as the error_mask_file
if [ $# -eq 3 ]; then
    error_mask_file=$3
else
    error_mask_file=""
fi

# ensure that the saved_crashes_dir exists
# and that it is a directory
if [ ! -d $saved_crashes_dir ]; then
    echo "Error: $saved_crashes_dir is not a directory"
    exit 1
fi

# ensure that the crash_finder_template_script exists
# and that it is a file
if [ ! -f $crash_finder_template_script ]; then
    echo "Error: $crash_finder_template_script is not a file"
    exit 1
fi

# create a directory to store the interesting crashes
interesting_crashes_dir=$saved_crashes_dir/../saved_crashes_interesting
mkdir -p $interesting_crashes_dir
interesting_crashes_dir=$(realpath $interesting_crashes_dir)

# create a directory to store the false crashes
false_crashes_dir=$saved_crashes_dir/../saved_crashes_false
mkdir -p $false_crashes_dir
false_crashes_dir=$(realpath $false_crashes_dir)

# get the path to the crash_finder_log_dir
crash_finder_log_dir=$saved_crashes_dir/../crash_finder_logs
if [ -d $crash_finder_log_dir ]; then
    crash_finder_log_dir=$(realpath $crash_finder_log_dir)
else
    echo "$(tput setaf 3)Warning:$(tput sgr 0) $crash_finder_log_dir does not exist"
    crash_finder_log_dir=""
fi

# create a copy of the crash_finder_template_script
cp $crash_finder_template_script "$crash_finder_template_script"_wip
wip_script="$crash_finder_template_script"_wip


# iterate over all the crashes in the saved_crashes_dir
for crash in $(ls $saved_crashes_dir); do
    # get the crash path
    crash_path=$saved_crashes_dir/$crash
    crash_path=$(realpath $crash_path)

    # if the path ends with "_fuzzing_cmd", skip it
    if [[ $crash_path == *_fuzzing_cmd ]]; then
        continue
    fi

    # if we have an error_mask_file, check if the crash name matches the error_mask_file
    # if it does not match, skip it
    if [ ! -z $error_mask_file ]; then
        # check if crash name matches the error_mask_file
        if [ ! "$crash" = "$error_mask_file" ]; then
            echo "$(tput setaf 3)Warning:$(tput sgr 0) $crash does not match $error_mask_file, skipping it"
            continue
        fi
    fi

    # get the fuzzing_cmd file
    fuzzing_cmd_file="$crash_path"_fuzzing_cmd

    # print the separator
    echo -e "\n####################################################################\n"
    echo -e "$(tput setaf 3)PROCESSING CRASH:$(tput sgr 0)"

    # print them for now
    echo "$(tput setaf 3)crash_path:$(tput sgr 0) $crash_path"
    echo -e "$(tput setaf 3)fuzzing_cmd_file:$(tput sgr 0) $fuzzing_cmd_file\n"

    # print matching crash_finder_logs files
    if [ ! -z $crash_finder_log_dir ]; then
        echo -e "$(tput setaf 3)matching crash_finder_logs:$(tput sgr 0)"
        time ls $crash_finder_log_dir \
            | xargs -n1 -I{} -P32 \
                bash -c "diff -s $crash_path $crash_finder_log_dir/{} | rg identical" 2>/dev/null \
            | awk '{print $4}' \
            | sed -e "s/\.mask/.log/"
        echo ""
    fi

    # extract the args from the fuzzing_cmd_file
    args=$(cat $fuzzing_cmd_file | awk 'BEGIN {FS=" -- "};{print $2}' | cut -d' ' -f 2- | sd -s "/home/shank" $HOME)

    # replace the FUZZERR_AFL_MAP env var in the wip_script
    # with the crash_path
    sed -i "s|export FUZZERR_AFL_MAP=.*|export FUZZERR_AFL_MAP=$crash_path|" $wip_script

    # replace the ARGS env var in the wip_script with the args
    sed -i "s|^ARGS=.*|ARGS=\"$args\"|" $wip_script

    # run the wip_script
    bash $wip_script

    # print the crash path again
    echo -e "$(tput setaf 3)PROCESSING CRASH:$(tput sgr 0)"

    # print them for now
    echo "$(tput setaf 3)crash_path:$(tput sgr 0) $crash_path"
    echo -e "$(tput setaf 3)fuzzing_cmd_file:$(tput sgr 0) $fuzzing_cmd_file\n"

    # while true loop
    while true; do
        echo "---------------------------------------------------------"
        # ask the user if they want to continue
        read -p "Continue? [n (next) | i (interesting) | f (false) | d (delete) | q (quit)] " choice
        case $choice in
            n ) break;;

            i ) # move the crash to the interesting_crashes_dir
                echo "moving this crash and fuzzing_cmd to $interesting_crashes_dir"
                mv $crash_path $interesting_crashes_dir
                mv $fuzzing_cmd_file $interesting_crashes_dir
                break;;

            f ) # move the crash to the false_crashes_dir
                echo "moving this crash and fuzzing_cmd to $false_crashes_dir"
                mv $crash_path $false_crashes_dir
                mv $fuzzing_cmd_file $false_crashes_dir
                break;;

            d ) # ask the user if they are sure
                read -p "Are you sure you want to delete this crash? [y/n] " choice
                case $choice in
                    y ) # delete the crash
                        echo "*********************************************************"
                        echo "deleting crash_path: $crash_path"
                        rm $crash_path
                        echo "deleting fuzzing_cmd_file: $fuzzing_cmd_file"
                        rm $fuzzing_cmd_file
                        echo "*********************************************************"
                        break;;

                    n ) break;;
                esac;;

            q ) exit;;

            * ) echo "Please answer 'n' / 'k' / 'q'";;
        esac
    done
    echo -e "---------------------------------------------------------\n"
done

