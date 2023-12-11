#! /usr/bin/env python

# run as:
# scripts/crash_minimizer.py -p experiments/libcmusl/test/hello_malloc.c.afl.out -m (pwd)/.fuzzerr_mask

import argparse
import os
import random
import shutil
import subprocess
import sys
from enum import Enum
from typing import Literal, overload, cast

from utils import (
    is_valid_file,
    trimmed_output,
    get_configured_logger,
    ensure_aslr_is_disabled,
    _get_asan_stacktrace,
    _get_effective_ids,
)

# the name of the binary being fuzzed
PROG_NAME: str = ""

MINIMIZED_ERROR_MASK_FILE: str = ""
MINIMIZED_ERROR_MASK_FILE_BACKUP: str = ""

# set logging level
log = get_configured_logger("crash_minimizer")

# parameters. Default values. Will get updated during running.
starting_reduction_rate = 0.5
s = 0.05 # cooling schedule


class BaseRunResult(Enum):
    CRASH = 0  # the dry run crashed
    NO_CRASH = 1  # the dry run did not crash
    TIMEOUT = 2  # the dry run timed out


class ExitCode(Enum):
    INVALID_ARGS = 1


def _parse_and_validate_arguments(
    parser: argparse.ArgumentParser,
) -> argparse.Namespace:
    args = parser.parse_args()

    if not args.prog_path:
        log.error("Error: Path to the program to run is invalid.")
        log.error("Provided argument: {} is not a file.".format(args.prog_path))
        sys.exit(ExitCode.INVALID_ARGS.value)

    if not args.mask_path:
        log.error("Error: Path to the error mask is invalid.")
        log.error("Provided argument: {} is not a file.".format(args.mask_path))
        sys.exit(ExitCode.INVALID_ARGS.value)

    if args.args:
        args.args = list(args.args.replace(" ", "").split(","))

    if not args.stats_file:
        log.warning("No stats file provided, stats wont be saved")
    else:
        log.info(f"Stats file provided, stats will be saved to {args.stats_file}")

    global starting_reduction_rate
    starting_reduction_rate = args.c
    global s
    s = args.s

    # save the binary name
    global PROG_NAME
    PROG_NAME = os.path.basename(args.prog_path)

    return args


def _setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        __file__,
        description="Tool to detect if a given crash occurs in a library or in the program",
    )

    parser.add_argument(
        "-p",
        "--prog_path",
        dest="prog_path",
        type=str,
        help="path to the binary to be run",
    )

    parser.add_argument(
        "-m",
        "--mask_path",
        dest="mask_path",
        type=str,
        help="path to the error mask file",
    )

    parser.add_argument(
        "--args",
        dest="args",
        type=str,
        help="comma separated list of arguments to the binary",
    )

    parser.add_argument(
        "--stats_file",
        dest="stats_file",
        type=str,
        help="path to the file to which the crash_minimizer stats are to be saved",
    )

    parser.add_argument(
        "--for_deduplication",
        dest="for_deduplication",
        action=argparse.BooleanOptionalAction,
    )

    parser.add_argument(
        "--iterations",
        dest="iterations",
        type=int,
        default=10,
        help="maximum number of iterations to run the minimizer for",
    )

    parser.add_argument(
        "--c",
        dest="c",
        type=float,
        default=0.5,
        help="Starting reduction rate",
    )

    parser.add_argument(
        "--s",
        dest="s",
        type=float,
        default=0.05,
        help="Cooling schedule",
    )

    # ensure that FUZZERR_AFL_MAP env var is set
    fuzzerr_afl_map = os.getenv("FUZZERR_AFL_MAP")
    if not fuzzerr_afl_map:
        log.error("FUZZERR_AFL_MAP env var not set, exiting.")
        sys.exit(ExitCode.INVALID_ARGS.value)

    global MINIMIZED_ERROR_MASK_FILE
    MINIMIZED_ERROR_MASK_FILE = fuzzerr_afl_map + "_minimized"
    log.info(f"Minimized error mask file: {MINIMIZED_ERROR_MASK_FILE}")

    global MINIMIZED_ERROR_MASK_FILE_BACKUP
    MINIMIZED_ERROR_MASK_FILE_BACKUP = MINIMIZED_ERROR_MASK_FILE + ".bak"

    return parser


@overload
def run_cmd(
    command,
    env=None,
    cwd=None,
    verbose=False,
    timeout=1 * 60,
    trim=False,
    error_msg="",
    raise_timeout=False,
) -> tuple[str, str, subprocess.CompletedProcess]:
    ...


@overload
def run_cmd(
    command,
    env=None,
    cwd=None,
    verbose=False,
    timeout=1 * 60,
    trim=False,
    error_msg="",
    raise_timeout=False,
) -> tuple[Literal[""], Literal[""], None]:
    ...


def run_cmd(
    command,
    env=None,
    cwd=None,
    verbose=False,
    timeout=1 * 60,
    trim=False,
    error_msg="",
    raise_timeout=False,
):
    try:
        log.debug(f"Running command : {command}\n with {cwd} and {env}")
        result = subprocess.run(
            command,
            env=env,
            shell=True,
            cwd=cwd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if verbose:
            log.debug(f"STDOUT has {trimmed_output(result.stdout.decode('latin-1'))}")
            log.debug(f"STDERR has {trimmed_output(result.stderr.decode('latin-1'))}")
        if trim:
            return (
                trimmed_output(result.stdout.decode("latin-1")),
                trimmed_output(result.stderr.decode("latin-1")),
                result,
            )
        else:
            return (
                result.stdout.decode("latin-1"),
                result.stderr.decode("latin-1"),
                result,
            )

    except subprocess.TimeoutExpired as e:
        log.warning(
            f"The {error_msg} Command Timed out", extra={"cmd": command, "error": e}
        )
        if raise_timeout:
            raise TimeoutError(f"The {error_msg} Command Timed out")
        return "", "", None

    except Exception as e:
        log.exception(f"{error_msg} failed", extra={"cmd": command, "error": e})


def _create_cmd(binary: str, args: list[str]) -> list[str]:
    cmd_lst = ["FUZZERR_ONLY_INNER=1"]
    cmd_lst.append("FUZZERR_DEBUG=1")
    cmd_lst.append("FUZZERR_ENABLE_BACKTRACE=1")
    cmd_lst.append("FUZZERR_CRASH_MINIMIZER_RUN=1")
    cmd_lst.append(
        "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1"
    )
    cmd_lst.append(f"FUZZERR_AFL_MAP={MINIMIZED_ERROR_MASK_FILE}")
    cmd_lst.append(binary)
    if args:
        cmd_lst.extend(args)
    return cmd_lst


def _read_current_error_mask() -> bytearray:
    with open(MINIMIZED_ERROR_MASK_FILE, "rb") as f:
        mask = f.read()
        return bytearray(mask)


def _write_updated_mask(mask: bytearray):
    with open(MINIMIZED_ERROR_MASK_FILE, "wb") as f:
        f.write(mask)


def is_set(idx: int, mask: bytearray) -> bool:
    elem_idx = idx // 8
    bit_idx = idx % 8
    relevant_bit = (mask[elem_idx] & (1 << bit_idx)) >> bit_idx
    return relevant_bit == 1


def is_unset(idx: int, mask: bytearray) -> bool:
    return not is_set(idx, mask)


def unset_bit(idx: int, mask: bytearray):
    elem_idx = idx // 8
    bit_idx = idx % 8
    mask[elem_idx] &= ~(1 << bit_idx)


def set_bit(idx: int, mask: bytearray):
    elem_idx = idx // 8
    bit_idx = idx % 8
    mask[elem_idx] |= 1 << bit_idx


def count_effective_set_bits(
    mask: bytearray, effective_ids: list[int]
) -> tuple[int, list[int]]:
    count = 0
    set_bits = []
    for idx in effective_ids:
        if is_set(idx, mask):
            count += 1
            set_bits.append(idx)
    return (count, set_bits)


def _get_effective_ids_that_are_set(
    mask: bytearray, effective_ids: list[int]
) -> list[int]:
    set_bits = []
    for idx in effective_ids:
        if is_set(idx, mask):
            set_bits.append(idx)
    return set_bits


def _zero_mask_after_idx(idx: int):
    mask = _read_current_error_mask()

    num_bits = len(mask) * 8
    for i in range(idx + 1, num_bits):
        unset_bit(i, mask)

    _write_updated_mask(mask)


def remove_existing_error_mask_files():
    if is_valid_file(MINIMIZED_ERROR_MASK_FILE):
        os.remove(MINIMIZED_ERROR_MASK_FILE)
    if is_valid_file(MINIMIZED_ERROR_MASK_FILE_BACKUP):
        os.remove(MINIMIZED_ERROR_MASK_FILE_BACKUP)
    log.debug(">>>> removed existing masks")


def base_run(cmd: str) -> tuple[BaseRunResult, list[int], list[str]]:
    """
    Run the binary with the given args and error mask (from global var).

    Returns:
        BaseRunResult: the result of the base run
        list[int]: the effective ids that were set in the mask
        list[str]: the asan stack trace lines
    """
    log.info(f"doing base_run to get effective_ids and asan_stacktrace with cmd: {cmd}")
    try:
        if os.getenv("FUZZERR_TIMEOUT_IN_SEC"):
            fuzzerr_timeout_in_sec = int(cast(str, os.getenv("FUZZERR_TIMEOUT_IN_SEC")))
            stdout, stderr, result = run_cmd(
                cmd,
                verbose=True,
                timeout=2 * fuzzerr_timeout_in_sec,
                error_msg="crash_miniminzer binary run",
                raise_timeout=False,
            )
        else:
            stdout, stderr, result = run_cmd(
                cmd,
                verbose=True,
                timeout=1 * 60,
                error_msg="crash_miniminzer binary run",
                raise_timeout=True,
            )

        log.info(f"result.returncode: {result.returncode}")
        log.info("stdout (begin) >>>>>>")
        log.info(f"{stdout}")
        log.info("stdout (end) <<<<<<")
        log.info("stderr (begin) >>>>>>")
        log.info(f"{stderr}")
        log.info("stderr (end) <<<<<<")

        # if the input error_mask does not crash the binary, then just return
        if result.returncode == 0:
            log.warning(
                "[!] input error_mask does not crash the binary, returning [Please Investigate]"
            )
            log.warning("[!] returning now so that we can continue fuzzing...")
            return (BaseRunResult.NO_CRASH, [], [])

        effective_ids = _get_effective_ids(stdout)
        asan_stacktrace = _get_asan_stacktrace(stderr, log)

        # in case the run did not crash
        if not asan_stacktrace:
            return (BaseRunResult.NO_CRASH, effective_ids, [])

        return (BaseRunResult.CRASH, effective_ids, asan_stacktrace)

    except TimeoutError:
        # crash_miniminzer run timed out...
        # we save the mask for later investigation and put in a message
        # that this is something that is to be investigated
        log.warning(
            "[!] crash_minimizer binary run timed out, i.e. likely didnt crash [PLEASE INVESTIGATE]"
        )
        # save_error_mask_for_investigation(
        # MINIMIZED_ERROR_MASK_FILE, PROG_NAME, log)
        log.warning("[!] returning now so that we can continue fuzzing...")
        return (BaseRunResult.TIMEOUT, [], [])


def remove_backup_mask():
    if is_valid_file(MINIMIZED_ERROR_MASK_FILE_BACKUP):
        os.remove(MINIMIZED_ERROR_MASK_FILE_BACKUP)


# Interation |----------------- Bits ----------------| Result | Decision (Reduce/Increase)
# ----------------------------------------------------------------------------------------
# 1          |b1 b2 ...............................bn| Crash  | Reduce
# 2          |b_2_1 b_2_2 ......................b_2_n| Crash  | Reduce
# 3          | ......................................| NoCrash| Increase
# ...
# ...
# ...
# Z

# Reduce (Bits, x (0-1) : reductio rate):
# If the bit is not set -> 0
# If the bit is set -> set the bit with probability 50%

# Increase (x (0-1)) @ iteration K:
# Get the bits from previous iteration (k-1)
# Reduce (Bits_(k-1), x - 10%)




def minimizer(
    binary: str,
    error_mask: str,
    args: list[str],
    stats_file: str | None = None,
    max_minimized_executions: int = 10,
) -> None:
    """
    Minimizes the error_mask that still causes a crash in the binary with the
    given inputs

    Args:
        binary (str): path to binary(asan'ed)
        error_mask (str): path to error_mask file
        args (list[str]): list of arguments to the binary
        stats_file (str): path to stats file [optional]
        max_minimized_executions (int): number of iterations to perform for minimization (default 20)

    Returns:
        None
    """
    # clear out the previous files if any
    remove_existing_error_mask_files()

    # put in the new files
    shutil.copy2(error_mask, MINIMIZED_ERROR_MASK_FILE)
    shutil.copy2(MINIMIZED_ERROR_MASK_FILE, MINIMIZED_ERROR_MASK_FILE_BACKUP)
    assert is_valid_file(MINIMIZED_ERROR_MASK_FILE)

    cmd_lst = _create_cmd(binary=binary, args=args)
    cmd = subprocess.list2cmdline(cmd_lst)

    # dry run to get the max_effective_idx
    (result, effective_ids, asan_stacktrace) = base_run(cmd)

    # if the dry run didnt succeed, then we just return
    if result != BaseRunResult.CRASH:
        log.error(
            "base run did not crash, returning for now to continue [Please Investigate]"
        )
        remove_backup_mask()
        return

    log.info(f"effective_ids: {effective_ids}")
    log.info("asan_stacktrace: {}".format("\n" + "\n".join(asan_stacktrace)))

    if not effective_ids:
        log.warning(f"no effective_ids: false crash (atleast for us)...")
        remove_backup_mask()
        return

    if len(effective_ids) == 1:
        log.info(f"only 1 effective_ids: cant really miniminze that...")
        msg = f"Original count: 1, Final count: 1, Executions required: 0"
        log.info(msg)
        remove_backup_mask()
        return

    # set to store the effective id combinations that we have already tried
    # so that we dont try them again
    seen_effective_ids: set[tuple[int, ...]] = set()
    seen_effective_ids.add(tuple(effective_ids))

    # zero out all bit after the last effective bit so that they dont lead
    # to crashes
    _zero_mask_after_idx(effective_ids[-1])
    mask = _read_current_error_mask()
    log.info(
        f"set effective bits in the zeroed mask: {count_effective_set_bits(mask, effective_ids)}"
    )
    shutil.copy2(MINIMIZED_ERROR_MASK_FILE, MINIMIZED_ERROR_MASK_FILE_BACKUP)

    reduction_rate = starting_reduction_rate  # 50%

    original_effective_ids = effective_ids.copy()
    original_asan_stacktrace = asan_stacktrace.copy()

    # the number of times we actually ran with the reduced error mask
    execution_cnt = 0

    # max possible effective ids combinations
    max_effective_ids_combinations = 2 ** len(effective_ids)

    for iter_cnt in range(100):
        # if we have already tried the max number of executions, then we break out
        if execution_cnt >= max_minimized_executions:
            log.info(
                f"already tried max number of executions: {max_minimized_executions}, breaking out of loop"
            )
            break

        # if we have already seen all the combinations, then break out
        if len(seen_effective_ids) == max_effective_ids_combinations - 1:
            log.info(
                f"seen all possible effective_ids combinations, breaking out of loop. [executions: {execution_cnt}]"
            )
            break

        log.info(f"iter_cnt: {iter_cnt}")
        # read the contents of the error mask file (as it might have been updated)
        mask = _read_current_error_mask()
        # log.info(f"mask: {mask}")

        # unset relevant bits with probability = reduction rate
        for idx in original_effective_ids:
            if is_set(idx, mask):
                if random.random() < reduction_rate:
                    unset_bit(idx, mask)

        # get the updated effective bits
        effective_ids = _get_effective_ids_that_are_set(mask, original_effective_ids)
        log.info(f"effective_ids: {effective_ids}")

        if not effective_ids:
            log.info("no effective_ids, skipping")
            continue

        if tuple(effective_ids) in seen_effective_ids:
            log.info("skipping as we have already seen this combination")
            continue

        # new combination, add it to our seen set
        seen_effective_ids.add(tuple(effective_ids))

        # write the updated mask to file
        _write_updated_mask(mask)
        log.info(
            f"updated mask: set bits: {count_effective_set_bits(mask, effective_ids)}"
        )

        # increase the execution_cnt
        execution_cnt += 1

        # now run the binary and see if it crashes
        try:
            if os.getenv("FUZZERR_TIMEOUT_IN_SEC"):
                fuzzerr_timeout_in_sec = int(
                    cast(str, os.getenv("FUZZERR_TIMEOUT_IN_SEC"))
                )
                stdout, stderr, result = run_cmd(
                    cmd,
                    verbose=True,
                    timeout=2 * fuzzerr_timeout_in_sec,
                    error_msg="crash_miniminzer binary run",
                    raise_timeout=True,
                )
            else:
                stdout, stderr, result = run_cmd(
                    cmd,
                    verbose=True,
                    timeout=1 * 20,
                    error_msg="crash_miniminzer binary run",
                    raise_timeout=True,
                )

            if result.returncode != 0:
                log.info("minimized mask crashes")
                # if it crashes, compare the stacktrace with the original one
                asan_stacktrace = _get_asan_stacktrace(stderr, log)
                if asan_stacktrace == original_asan_stacktrace:
                    log.info("same stacktrace, keeping the minimized mask")
                    shutil.copy2(
                        MINIMIZED_ERROR_MASK_FILE, MINIMIZED_ERROR_MASK_FILE_BACKUP
                    )
                    if len(effective_ids) == 1:
                        log.info("only 1 effective_ids, cant minimize further")
                        break
                    log.info("resetting the reduction rate...")
                    reduction_rate = starting_reduction_rate  # 50%
                else:
                    log.info("different stacktrace, reverting")
                    log.info(
                        "asan_stacktrace: {}".format("\n" + "\n".join(asan_stacktrace))
                    )
                    # revert to previous error mask and decrease the reduction rate
                    shutil.copy2(
                        MINIMIZED_ERROR_MASK_FILE_BACKUP, MINIMIZED_ERROR_MASK_FILE
                    )
                    reduction_rate = max(s, reduction_rate - s)
                    log.info(f"update reduction_reate: {reduction_rate}")

            else:
                log.info("minimized mask doesnt crash")
                # revert to previous error mask and decrease the reduction rate
                shutil.copy2(
                    MINIMIZED_ERROR_MASK_FILE_BACKUP, MINIMIZED_ERROR_MASK_FILE
                )
                reduction_rate = max(s, reduction_rate - s)
                log.info(f"update reduction_reate: {reduction_rate}")

        except TimeoutError:
            # if we timeout, we assume that the binary didnt crash
            log.info("minimized mask doesnt crash")
            # if it doesnt crash,
            # revert to previous error mask and decrease the reduction rate
            shutil.copy2(MINIMIZED_ERROR_MASK_FILE_BACKUP, MINIMIZED_ERROR_MASK_FILE)
            reduction_rate = max(s, reduction_rate - s)
            log.info(f"update reduction_reate: {reduction_rate}")

    # log the minimization stats at the end of the stats_file
    mask = _read_current_error_mask()
    effective_ids = _get_effective_ids_that_are_set(mask, original_effective_ids)
    msg = f"Original count: {len(original_effective_ids)}, Final count: {len(effective_ids)}, Executions required: {execution_cnt}"
    log.info(msg)
    if stats_file:
        with open(stats_file, "a") as f:
            f.write(f"{msg}\n")

    # remove the backup file
    remove_backup_mask()


def main() -> None:
    """
    Args:
        --prog_path (str): path to the binary to be run
        --mask_path (str): starting error mask which is to be minimized
        --args (str): comma-separated list of arguments to the binary
        --stats_file (str): path to the crash_minimizer stats file [optional]
        --for_deduplication : flag to indicate that the minimizer has been invoked for deduplication
        --iterations (Optional[int]): max number of executions of the binary to be done during minimization

    Please note that the FUZZERR_AFL_MAP environment variable must be set to the
    the path of the afl map file.

    For example a binary that would normally be invoked as:

        my_binary input1 input2

    The way crash_minimizer.py should be called for the above binary is:

        crash_minimizer.py --prog_path=my_binary --mask_path=<err_mask> --args=input1,input2 --stats_file=<stats_file>
    """
    parser = _setup_parser()
    args = _parse_and_validate_arguments(parser)
    log.info(f"args: {args}")

    if args.for_deduplication:
        minimizer(
            binary=args.prog_path,
            error_mask=args.mask_path,
            args=args.args,
            stats_file=args.stats_file,
            max_minimized_executions=30,
        )
    else:
        minimizer(
            binary=args.prog_path,
            error_mask=args.mask_path,
            args=args.args,
            stats_file=args.stats_file,
            max_minimized_executions=args.iterations,
        )


if __name__ == "__main__":
    ensure_aslr_is_disabled(log)
    main()
