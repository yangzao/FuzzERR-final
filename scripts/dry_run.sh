#! /bin/bash

# set -e
# set -u
# set -x
# set -o pipefail
# export PS4='[ $LINENO ]: '

# ensure that atleast 1 argument is passed
if [ $# -lt 1 ]; then
    echo "Usage: $0 <binary> [<args>]"
    exit 1
fi

binary=$1
# ensure that the binary exists and is executable
if [ ! -x $binary ]; then
    echo "Error: $binary is not executable"
    exit 1
fi

asan_opts="ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:handle_abort=1",
fuzzer_base_opts="FUZZERR_DEBUG=1 FUZZERR_ONLY_INNER=1 FUZZERR_DISABLE=1 FUZZERR_DRY_RUN=1"

# if the FUZZERR_TIMEOUT_IN_SEC environment variable is set, then use it
if [ -n "${FUZZERR_TIMEOUT_IN_SEC:-}" ]; then
    timeout_in_sec=$FUZZERR_TIMEOUT_IN_SEC
else
    timeout_in_sec=10
fi
fuzzer_more_opts="FUZZERR_DRY_RUN_RESULT=dry_run_result FUZZERR_TIMEOUT_IN_SEC=$timeout_in_sec"

cmd="$asan_opts $fuzzer_base_opts $fuzzer_more_opts $binary ${@:2}"
bash -c "$cmd"
