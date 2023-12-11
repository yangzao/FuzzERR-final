#! /usr/bin/env python

import subprocess
import sys
import os
import shutil
from utils import (
    get_configured_logger,
    ensure_aslr_is_disabled,
)
from crash_deduplicate import (
    _get_minimization_info,
    _get_program_path,
    _get_program_args,
    CRASH_MINIMIZER_PATH,
)

log = get_configured_logger("force_minimization")


def minimize_error_mask(
    error_mask: str, prog_path: str, args: str, iterations=30
) -> None:
    """
    Minimizes the given error mask by removing all bits that do not change the
    error mask's value.

    Args:
        error_mask (str): Path to the error mask to be minimized
    """
    # construct the crash_minimizer_cmd
    crash_minimizer_cmd = (
        "FUZZERR_ONLY_INNER=1 "
        "FUZZERR_ENABLE_BACKTRACE=1 "
        f"FUZZERR_AFL_MAP={error_mask} "
        f"{CRASH_MINIMIZER_PATH} "
        f"--mask_path={error_mask} "
        f"--prog_path={prog_path} "
        f"--args={args} "
        f"--iterations={iterations} "
        "2>&1"
    )

    log.info(f"crash_minimizer cmd: {crash_minimizer_cmd}")

    # run the crash_minimizer command
    try:
        result = subprocess.run(
            crash_minimizer_cmd,
            shell=True,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        # result = subprocess.check_output(
        #     crash_minimizer_cmd,
        #     shell=True,
        #     text=True,
        # )

    except subprocess.CalledProcessError as e:
        log.error(f"Error: {e}")
        return None
        # exit(1)

    except subprocess.TimeoutExpired as e:
        log.error(f"Error: {e}")
        return None
        # exit(1)

    else:
        log.info(f"result: {result.stdout}")
        issue_strings = ["base run did not crash"]
        for s in issue_strings:
            if s in result.stdout:
                log.error(
                    f'exiting crash_deduplication because: "{s}" for command: "{crash_minimizer_cmd}"'
                )
                return None
                # exit(1)

        if result:
            # get minimization stat from stdout
            print(_get_minimization_info(result.stdout))

            # replace the original error mask with the minimized one
            minimized_error_mask = f"{error_mask}_minimized"
            log.info(f"replacing {error_mask} with {minimized_error_mask}")
            shutil.copy2(minimized_error_mask, error_mask)
            log.info(f"removing {minimized_error_mask}")
            os.remove(minimized_error_mask)


def main() -> None:
    """
    Args:
        error_mask (str): Path to the error mask to be force minimized
    """
    # ensure that we have 1 argument
    if len(sys.argv) < 2:
        log.error("Usage: %s <error_mask> [<iterations>]" % sys.argv[0])
        sys.exit(1)

    error_mask = os.path.abspath(sys.argv[1])

    # ensure that the error mask exists
    if not os.path.exists(error_mask):
        log.error("Error mask %s does not exist" % error_mask)
        sys.exit(1)

    # if we have a second argument use it as the number of iterations
    iterations = 50
    if len(sys.argv) == 3:
        iterations = int(sys.argv[2])

    # locate the fuzzing_cmd file corresponding to the error mask
    fuzzing_cmd_file = f"{error_mask}_fuzzing_cmd"
    prog_path = _get_program_path(fuzzing_cmd_file)
    args = _get_program_args(fuzzing_cmd_file)
    args = args.replace(" ", ",")

    # minimize the error mask
    minimize_error_mask(error_mask, prog_path, args, iterations)


if __name__ == "__main__":
    ensure_aslr_is_disabled(log)
    main()
