#! /bin/bash

# find all diretories named "fuzzerr_logs" nested inside the current directory
# and delete all files inside them
for d in $(find $1 -name fuzzerr_logs); do
    echo ">>>> processing: $d"
    ! (
        ls -t $d \
        | rg --ignore-case --invert-match state \
        | rg --ignore-case --invert-match lock \
        | rg --ignore-case --invert-match current \
        | tail -n +1 \
        | xargs -n1 -I# rm $d/#
    )
done
