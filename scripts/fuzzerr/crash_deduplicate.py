#! /usr/bin/env python

import argparse
from utils import (
    get_configured_logger,
    mkdir_p,
    clean_file_names,
    ensure_aslr_is_disabled,
    _get_asan_stacktrace,
    _get_injected_mask_ids,
    kill_residuals,
)
import pprint
import sys
from collections import defaultdict
import os
import subprocess
import re
import shutil
from multiprocessing import Pool


log = get_configured_logger("crash_deduplicate")

LONG_RUNNING_TIMEOUT_IN_SEC = 15
NUM_POOL_PROCS = 20


# the path of the binary that was fuzzed
BIN_PATH = None

# are we working on a long running program
LONG_RUNNING = False


CRASH_MINIMIZER_PATH = "$HOME/code/research/FuzzERR/scripts/fuzzerr/crash_minimizer.py"

minimizer_stat_regex = re.compile(
    r"Original count: \d+, Final count: \d+, Executions required: \d+"
)

hyper_args = {}


def _setup_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        __file__,
        description="Tool to minimize and deduplicate crashes",
    )

    parser.add_argument(
        "--saved_crashes_dir",
        dest="saved_crashes_dir",
        type=str,
        help="path to the saved crashes directory",
    )

    parser.add_argument(
        "--long_running",
        dest="long_running",
        type=bool,
        default=False,
        help="whether to run the minimizer in long running mode",
    )

    parser.add_argument(
        "--c",
        dest="c",
        type=float,
        default=0.5,
        help="Reduction rate",
    )

    parser.add_argument(
        "--s",
        dest="s",
        type=float,
        default=0.05,
        help="Cooling schedule",
    )

    parser.add_argument(
        "--t",
        dest="t",
        type=int,
        default=10,
        help="Iterations",
    )

    return parser


def _parse_and_validate_arguments(
    parser: argparse.ArgumentParser,
) -> argparse.Namespace:
    args = parser.parse_args()

    if not args.saved_crashes_dir:
        log.error("Error: saved_crashes_dir is required")
        sys.exit(1)

    if not os.path.isdir(args.saved_crashes_dir):
        log.error(f"Error: {args.saved_crashes_dir} is not a directory")
        sys.exit(1)

    args.saved_crashes_dir = os.path.abspath(args.saved_crashes_dir)

    if args.long_running:
        log.info("Running in long running mode")
        global LONG_RUNNING
        LONG_RUNNING = True

    if not args.c or not args.s or not args.t:
        log.error("Hyper parameters missing")
        sys.exit(1)

    global hyper_args
    hyper_args["c"] = args.c
    hyper_args["s"] = args.s
    hyper_args["t"] = args.t

    print(hyper_args)

    return args


def _get_program_path(fuzzing_cmd_file) -> str:
    cmd = (
        f"cat {fuzzing_cmd_file} "
        "| awk 'BEGIN {{FS=\" -- \"}};{{print $2}}' "
        "| cut -d' ' -f 1"
    )
    # log.info(f"cmd: {cmd}")
    prog = subprocess.check_output(
        cmd, shell=True, stderr=subprocess.STDOUT, text=True
    ).strip()
    # log.info(f"prog: {prog}")
    return prog


def _get_program_args(fuzzing_cmd_file) -> str:
    cmd = (
        f"cat {fuzzing_cmd_file} "
        "| awk 'BEGIN {{FS=\" -- \"}};{{print $2}}' "
        "| cut -d' ' -f 2- | sd -s /home/shank $HOME"
    )
    # log.info(f"cmd: {cmd}")
    args = subprocess.check_output(
        cmd, shell=True, stderr=subprocess.STDOUT, text=True
    ).strip()
    # log.info(f"args: {args}")
    return args


def _get_minimization_info(result: str) -> str | None:
    # get the line matching the minimizer_stat_regex
    for line in result.splitlines()[::-1]:
        match = minimizer_stat_regex.search(line)
        if match:
            return match.group(0)


def _do_minimize_one(idx: int, mask_file_path: str, prog: str, args: str) -> str | None:
    # construct the crash_minimizer command
    global hyper_args
    crash_minimizer_cmd = (
        f"FUZZERR_ONLY_INNER=1 "
        f"FUZZERR_AFL_MAP={mask_file_path} "
        f"{CRASH_MINIMIZER_PATH} "
        f"--mask_path={mask_file_path} "
        f"--prog_path={prog} "
        f"--args={args} "
        f"--iterations={hyper_args['t']} "
        f"--c={hyper_args['c']} "
        f"--s={hyper_args['s']} "
        # f"--for_deduplication "
        "2>&1"
    )

    if LONG_RUNNING:
        crash_minimizer_cmd = (
            f"FUZZERR_TIMEOUT_IN_SEC={LONG_RUNNING_TIMEOUT_IN_SEC} "
            + crash_minimizer_cmd
        )

    log.info(f"crash_minimizer_cmd: {crash_minimizer_cmd}")

    # run the crash_minimizer command
    try:
        # result = subprocess.run(
        #     crash_minimizer_cmd,
        #     shell=True,
        #     text=True,
        # )
        result = subprocess.check_output(
            crash_minimizer_cmd,
            shell=True,
            text=True,
        )

    except subprocess.CalledProcessError as e:
        log.error(f"Error: {e}")
        log.error(f"[idx:{idx}] Output: {e.output}")
        return None
        # exit(1)

    except subprocess.TimeoutExpired as e:
        log.error(f"Error: {e}")
        log.error(f"[idx:{idx}] Output: {e.output}")
        return None
        # exit(1)

    else:
        log.info(f"result: {result}")
        issue_strings = ["base run did not crash"]
        for s in issue_strings:
            if s in result:
                log.error(
                    f'[idx:{idx}] exiting crash_deduplication because: "{s}" for command: "{crash_minimizer_cmd}"'
                )
                return None
                # exit(1)

        # get minimization stat from stdout
        return _get_minimization_info(result)


def minimize_one(
    idx: int,
    mask_file_path: str,
) -> str | None:
    # construct the crash_minimizer command...

    # first, get the fuzzing command
    fuzzing_cmd_file = f"{mask_file_path}_fuzzing_cmd"

    # extract the binary from the fuzzing cmd file
    prog = _get_program_path(fuzzing_cmd_file)

    # extract the args from the fuzzing cmd file
    args = _get_program_args(fuzzing_cmd_file)
    args = args.replace(" ", ",")

    # escape <
    args = args.replace("<", "\\<")

    # minimize
    return _do_minimize_one(idx, mask_file_path, prog, args)


def minimize_saved_crashes(
    saved_crashes_dir: str, saved_crashes_minimized_dir: str
) -> None:
    """Minimize each saved crash.

    Args:
        saved_crashes_dir (str): Path to the saved crashes directory.
        saved_crashes_minimized_dir (str): Path to the minimized crashes directory.
    """
    mkdir_p(saved_crashes_minimized_dir)

    # remove any previously minimized crashes
    cmd = f"ls {saved_crashes_dir} | rg --invert-match '_fuzzing_cmd' | rg '_minimized' | xargs -I# rm {saved_crashes_dir}/#"
    log.info(f"removing any previously minimized crashes: {cmd}")
    result = subprocess.call(cmd, shell=True, text=True)

    # get the list of saved crashes
    cmd = f"ls {saved_crashes_dir} | rg --invert-match '_fuzzing_cmd' | rg --invert-match '_minimized'"
    log.info(f"cmd: {cmd}")
    result = subprocess.check_output(
        cmd, shell=True, stderr=subprocess.STDOUT, text=True
    )
    error_masks = [x.strip() for x in result.splitlines()]
    # log.info(f"error_masks: {pprint.pformat(error_masks)}")

    # minimize each saved crash
    # for m in error_masks[50:52]:
    # for m in error_masks:
    #     log.info("=" * 80)
    #     log.info(f"minimizing crash: {m}")
    #     log.info("=" * 80)
    #     m = error_masks[0]
    #     m_path = os.path.join(saved_crashes_dir, m)
    #     minimization_stat = minimize_one(m_path)
    #     log.info(f"minimization_stat: {minimization_stat}")
    with Pool(NUM_POOL_PROCS) as pool:
        error_masks_abspaths = [os.path.join(saved_crashes_dir, m) for m in error_masks]
        results = pool.starmap(minimize_one, enumerate(error_masks_abspaths))
        log.info(
            f"final minimization stats: {pprint.pformat(list(zip(error_masks, results)))}"
        )
        parent_dir = os.path.dirname(saved_crashes_dir)
        with open(
            os.path.join(parent_dir, "crash_minimization_stats.txt"),
            "w",
        ) as f:
            f.write(pprint.pformat(list(zip(error_masks, results))))


def move_minimized_crashes(
    saved_crashes_dir: str, saved_crashes_minimized_dir: str
) -> None:
    """Move minimized crashes to a new directory.

    Args:
        saved_crashes_dir (str): Path to the saved crashes directory.
        saved_crashes_minimized_dir (str): Path to the minimized crashes directory.
    """
    # remove any leftover backups
    log.info(f"removing any leftover backups...")
    cmd = f"rm -rf {saved_crashes_dir}/*.bak"
    subprocess.check_call(cmd, shell=True, text=True)

    # clear out the minimized crashes directory
    cmd = f"rm -rf {saved_crashes_minimized_dir}/*"
    subprocess.check_call(cmd, shell=True, text=True)

    cmd = f"ls {saved_crashes_dir} | rg --invert-match bak | rg '_minimized'"
    minimized_masks = subprocess.check_output(cmd, shell=True, text=True).splitlines()
    # log.info(f"minimized_masks: {pprint.pformat(minimized_masks)}")

    # ensure that we have a fuzzing_cmd file for each minimized crash
    for m in minimized_masks:
        m_path = os.path.join(saved_crashes_dir, m)
        fuzzing_cmd_file = f"{m_path}_fuzzing_cmd".replace("_minimized", "")
        if not os.path.exists(fuzzing_cmd_file):
            log.error(f"missing fuzzing_cmd_file: {fuzzing_cmd_file}")
            exit(1)

    # move each minimized crash to the minimized crashes directory
    log.info(f"moving each minimized crash to the minimized crashes directory...")
    cmd = f"mv {saved_crashes_dir}/*_minimized {saved_crashes_minimized_dir}"
    subprocess.check_call(cmd, shell=True, text=True)

    # copy each relevant fuzzing_cmd file to the minimized crashes directory
    log.info(
        f"copying each relevant fuzzing_cmd file to the minimized crashes directory..."
    )
    for m in minimized_masks:
        m_path = os.path.join(saved_crashes_dir, m)
        fuzzing_cmd_file = f"{m_path}_fuzzing_cmd".replace("_minimized", "")
        shutil.copy(fuzzing_cmd_file, saved_crashes_minimized_dir)


def _collect_idx_and_backtrace(
    idx: int, error_mask: str
) -> tuple[tuple[int], tuple[str]] | None:
    """Collect the idx and backtrace from the error mask.

    Args:
        error_mask (str): Path to the error mask.

    Returns:
        tuple[list[int], list[str]] | None: The idx and backtrace.
    """
    fuzzing_cmd_file = f"{error_mask}_fuzzing_cmd".replace("_minimized", "")

    # construct the command to run the binary with the error mask
    cmd = (
        "FUZZERR_DEBUG=1 "
        "FUZZERR_ONLY_INNER=1 "
        "FUZZERR_ENABLE_BACKTRACE=1 "
        f"FUZZERR_AFL_MAP={error_mask} "
        'ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1" '
    )

    if LONG_RUNNING:
        cmd += f"FUZZERR_TIMEOUT_IN_SEC={LONG_RUNNING_TIMEOUT_IN_SEC} "

    prog = _get_program_path(fuzzing_cmd_file)
    args = _get_program_args(fuzzing_cmd_file)

    cmd += f"{prog} {args} "

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=60,
        )
        if result.returncode == 0:
            log.error(
                f"[idx:{idx}] cmd did not fail as expected, will be skipped [error_mask:{error_mask}]"
            )
            log.error(f"[idx:{idx}] cmd: {cmd}")
            return None

        injected_mask_ids = _get_injected_mask_ids(result.stdout)
        asan_stacktrace = _get_asan_stacktrace(result.stderr, log)

        result = (tuple(injected_mask_ids), tuple(asan_stacktrace))
        return result

    except subprocess.TimeoutExpired:
        log.error(
            f"[idx:{idx}] cmd timed out, will be skipped [error_mask:{error_mask}]"
        )
        log.error(f"[idx:{idx}] cmd: {cmd}")
        return None


def deduplicate_minimized_crashes(
    saved_crashes_minimized_dir: str, saved_crashes_deduplicated_dir: str
) -> None:
    """Deduplicate minimized crashes.

    Args:
        saved_crashes_minimized_dir (str): Path to the minimized crashes directory.
        saved_crashes_deduplicated_dir (str): Path to the deduplicated crashes directory.
    """
    mkdir_p(saved_crashes_deduplicated_dir)

    log.info(f"saved_crashes_minimized_dir: {saved_crashes_minimized_dir}")
    log.info(f"saved_crashes_deduplicated_dir: {saved_crashes_deduplicated_dir}")

    # clear out the directory
    cmd = f"rm -rf {saved_crashes_deduplicated_dir}/*"
    subprocess.check_call(cmd, shell=True, text=True)

    # for each error_mask in the minimized crashes directory
    # run the program with the error_mask and backtrace enabled
    # collect the idx of the FIPs that are hit and the ASAN backtrace for each error_mask
    # construct a dict of {((idx1, idx2, ...), backtrace): [error_mask1, error_mask2, ...]}
    # for each key in the dict, move the first error_mask files to the deduplicated crashes directory

    # get the list of minimized crashes
    cmd = f"ls {saved_crashes_minimized_dir} | rg --invert-match '_fuzzing_cmd'"
    error_masks = subprocess.check_output(cmd, shell=True, text=True).splitlines()
    # log.info(f"error_masks: {pprint.pformat(error_masks)}")

    with Pool(NUM_POOL_PROCS) as pool:
        # collect idx and backtrace for each error mask
        error_masks_abspaths = [
            os.path.join(saved_crashes_minimized_dir, m) for m in error_masks
        ]
        log.info(f"error_masks_abspaths[0]: {error_masks_abspaths[0]}")
        result = pool.starmap(
            _collect_idx_and_backtrace, list(enumerate(error_masks_abspaths))
        )
        # log.info(f"result: {pprint.pformat(result)}")

        assert len(result) == len(error_masks_abspaths)

        # # older algorithm:
        # # now create the crash grouping based on the (idx, backtrace) tuple
        # crash_groups = defaultdict(list)
        # for i, idx_stacktrace in enumerate(result):
        #     if idx_stacktrace is None:
        #         continue
        #     crash_groups[idx_stacktrace].append(error_masks_abspaths[i])
        # # log.info(f"crash_groups: {pprint.pformat(crash_groups)}")

        # newer algorithm:
        # now create the crash grouping based on the backtrace alone
        crash_groups: defaultdict[
            tuple[str], list[tuple[tuple[int], str]]
        ] = defaultdict(list)
        for i, idx_stacktrace in enumerate(result):
            if idx_stacktrace is None:
                continue
            idx, stacktrace = idx_stacktrace
            crash_groups[stacktrace].append((idx, error_masks_abspaths[i]))
        # sort the groups internally by the length of the idx tuple
        for k in crash_groups:
            crash_groups[k] = sorted(crash_groups[k], key=lambda x: len(x[0]))

        # log them out...
        log.info(f"crash_groups: number of groups: {len(crash_groups)}")
        log.info(
            f"crash_groups: injected_mask_ids count: {pprint.pformat(sorted(len(k[0]) for k in crash_groups.keys()))}"
        )
        log.info(
            f"crash_groups: group sizes: {pprint.pformat(sorted(map(len, crash_groups.values())))}"
        )

        # move the first error mask from each group to the deduplicated crashes directory
        # for (i, k) in enumerate(crash_groups):
        for (i, k) in enumerate(crash_groups):
            print(f">>> crash_group: {i}")
            error_mask_path = crash_groups[k][0][1]
            # log.info(f"error_mask_path: {error_mask_path}")
            error_mask_orig_name = os.path.basename(
                re.sub(r"_minimized$", "", error_mask_path)
            )
            # log.info(f"error_mask_orig_name: {error_mask_orig_name}")
            log.info(f"copying {error_mask_path} to {saved_crashes_deduplicated_dir}")
            shutil.copy2(
                error_mask_path,
                os.path.join(saved_crashes_deduplicated_dir, error_mask_orig_name),
            )
            fuzzing_cmd_file = os.path.join(
                saved_crashes_minimized_dir, f"{error_mask_orig_name}_fuzzing_cmd"
            )
            log.info(f"copying {fuzzing_cmd_file} to {saved_crashes_deduplicated_dir}")
            shutil.copy2(fuzzing_cmd_file, saved_crashes_deduplicated_dir)


def get_bin_path(saved_crashes_dir: str) -> str | None:
    # get a file ending in _fuzzing_cmd from the saved_crashes_dir
    for f in os.listdir(saved_crashes_dir):
        if f.endswith("_fuzzing_cmd"):
            fpath = os.path.join(saved_crashes_dir, f)
            with open(fpath, "r") as fuzzing_cmd_file:
                fuzzing_cmd = fuzzing_cmd_file.read().strip()
                parts = fuzzing_cmd.split(" -- ")
                interesting = parts[1]
                parts = interesting.split(" ")
                return parts[0]
    return None


def main() -> None:
    """Main function.

    Args:
        saved_crashes_dir (str): Path to the saved crashes directory.
    """
    parser = _setup_parser()
    args = _parse_and_validate_arguments(parser)
    log.info(f"args: {args}")

    clean_file_names(args.saved_crashes_dir)

    parent_dir = os.path.dirname(args.saved_crashes_dir)
    saved_crashes_dir_name = os.path.basename(args.saved_crashes_dir)

    # minimize each saved crash
    saved_crashes_minimized_dir = os.path.join(
        parent_dir, f"{saved_crashes_dir_name}_minimized"
    )
    minimize_saved_crashes(
        saved_crashes_dir=args.saved_crashes_dir,
        saved_crashes_minimized_dir=saved_crashes_minimized_dir,
    )

    # kill residuals :|
    bin_path = get_bin_path(args.saved_crashes_dir)
    if not bin_path:
        log.error("could not find bin_path, [Please Investigate]")
        exit(1)
    kill_residuals(bin_path, log)

    # move minimized crashes to a new directory
    move_minimized_crashes(
        saved_crashes_dir=args.saved_crashes_dir,
        saved_crashes_minimized_dir=saved_crashes_minimized_dir,
    )

    # deduplicate minimized crashes (and move deduplicated crashes to a final directory)
    saved_crashes_deduplicated_dir = os.path.join(
        parent_dir, f"{saved_crashes_dir_name}_deduplicated"
    )
    deduplicate_minimized_crashes(
        saved_crashes_minimized_dir=saved_crashes_minimized_dir,
        saved_crashes_deduplicated_dir=saved_crashes_deduplicated_dir,
    )
    kill_residuals(bin_path, log)


if __name__ == "__main__":
    ensure_aslr_is_disabled(log)
    main()
