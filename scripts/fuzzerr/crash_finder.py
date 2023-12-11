#! /usr/bin/env python3

"""
Exit Codes (see class ExitCode below):
    IMPOSSIBLE = 0
    INVALID_ARGS = 1
    SRC_PATH_NOT_PROVIDED = 2
    CRASH_IN_PROGRAM = 3
    CRASH_IN_LIBRARY = 4
    SRC_PATH_NOT_IN_BACKTRACE = 5
"""

from typing import TypedDict, cast
import argparse
import os
import pprint
import re
import subprocess
import sys
import shutil
from enum import Enum
from typing import Optional
from utils import (
    trimmed_output,
    is_valid_filename,
    get_file_name_from_path,
    get_encoded_file,
    encode_string,
    get_current_fn_name,
    get_configured_logger,
    get_timestamp,
    SEPARATOR,
    asanregex,
)


# the name of the binary being fuzzed
PROG_NAME: str = ""

# set logging level
log = get_configured_logger("crash_finder")


# crashregex = re.compile(r"(.*?) at ([A-Za-z0-9_\- //\.]+?):(\d+)")
regexes = [
    re.compile(x)
    for x in [
        r"([a-zA-Z0-9]+\-param\-overflow)",
        r"([a-zA-Z0-9]+\-param\-overlap)",
        r"(param-overflow)",
    ]
]
backtrace_regex = re.compile(r">>>> (.*?):(\d+)")


class CrashInfoDict(TypedDict):
    crash_func: str
    crash_line: int
    crash_filename: str
    crash_filename_path: str
    crash_input: str
    crash_log: str
    bug_type: str
    cmd: str | None


class CrashLocation(Enum):
    PROGRAM = 0
    LIBRARY = 1


class CrashLocationDecisionReason(Enum):
    BIN_SRC_PATH_IN_CRASH_LOCATION = 0
    CRASH_SRC_LINE_DIFFERENT_FROM_GET_BIT_SRC_LINE = 1


class ExitCode(Enum):
    IMPOSSIBLE = 0
    INVALID_ARGS = 1
    SRC_PATH_NOT_PROVIDED = 2
    CRASH_IN_PROGRAM = 3
    CRASH_IN_LIBRARY = 4
    SRC_PATH_NOT_IN_BACKTRACE = 5


class TimeoutError(Exception):
    pass


def run_cmd(
    command,
    env=None,
    cwd=None,
    verbose=False,
    timeout=1 * 60,
    trim=False,
    error_msg="",
    raise_timeout=False,
) -> tuple[str, str]:
    try:
        log.debug(f"Running command : {command}\n with {cwd} and {env}")
        out = subprocess.run(
            command,
            env=env,
            shell=True,
            cwd=cwd,
            timeout=timeout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if verbose:
            log.debug(f"STDOUT has {trimmed_output(out.stdout.decode('latin-1'))}")
            log.debug(f"STDERR has {trimmed_output(out.stderr.decode('latin-1'))}")
        if trim:
            return trimmed_output(out.stdout.decode("latin-1")), trimmed_output(
                out.stderr.decode("latin-1")
            )
        else:
            return out.stdout.decode("latin-1"), out.stderr.decode("latin-1")

    except subprocess.TimeoutExpired as e:
        log.error(
            f"The {error_msg} Command Timed out", extra={"cmd": command, "error": e}
        )
        if raise_timeout:
            raise TimeoutError(f"The {error_msg} Command Timed out")
        return "", ""

    except Exception as e:
        log.exception(f"{error_msg} failed", extra={"cmd": command, "error": e})
        return "", ""


def get_asan_bug_type(asan_log) -> str:
    bug_types = [
        "heap-buffer-overflow",
        "stack-overflow",
        "heap-use-after-free",
        "stack-buffer-underflow",
        "initialization-order-fiasco",
        "stack-buffer-overflow",
        "stack-use-after-return",
        "use-after-poison",
        "container-overflow",
        "stack-use-after-scope",
        "global-buffer-overflow",
        "intra-object-overflow",
        "dynamic-stack-buffer-overflow",
        "unknown-crash",
        "allocator is out of memory",
        "specified RSS limit exceeded",
        "invalid alignment",
        "pvalloc parameters overflow",
        "reallocarray parameters overflow",
        "alloc parameters overflow",
        "attempting free on address which was not malloc()-ed",
    ]
    for bug_type in bug_types:
        if bug_type in asan_log:
            return bug_type

    for regex_type in regexes:
        matchobj = regex_type.search(asan_log)
        if matchobj:
            return matchobj.group(1)
    return "UNKNOWN"


def parse_asan_crash(crash_log: str, crash_error_mask: str) -> Optional[CrashInfoDict]:
    # log.info(f"{get_current_fn_name()} >>>")

    if crash_log is None or len(crash_log) == 0:
        log.info("asan crash_log is empty! so binary has not crashed")
        return None

    if "AddressSanitizer" not in crash_log:
        log.warning("ASAN crash header not present in logs! [Please Investigate]")
        return None

    for line in crash_log.split("\n"):
        match = asanregex.search(line)
        if match:
            crashfunc = match.group(1)
            filename = match.group(2)
            if not is_valid_filename(filename.strip()):
                log.info(f">> invalid filename: {filename.strip()}, skipping")
                continue
            return {
                "crash_func": crashfunc,
                "crash_line": int(match.group(3)),
                "crash_filename": get_file_name_from_path(filename),
                "crash_filename_path": filename,
                "crash_input": get_encoded_file(crash_error_mask),
                "crash_log": encode_string(crash_log, log),
                "bug_type": get_asan_bug_type(crash_log),
                "cmd": None,
            }
    return None


def _get_crash_info(
    binary: str, error_mask: str, args: list[str], enable_backtrace: bool
) -> tuple[Optional[CrashInfoDict], str, str]:
    """
    Checks for crashes with given binary when run using the given error_mask
    and inputs

    Args:
        binary (str): path to binary (asan'ed)
        error_mask (str): path to error_mask file
        args (list[str]): list of arguments to the binary

    Returns:
        tuple[Optional[CrashInfo], str]: tuple of dict containing crash information or None in case it cannot parse the
        crash information, and the stdout and stderr (for further analysis)
    """
    # log.info(f"trying to find the crash location for the following:")
    # log.info(
    #     f">> binary:{binary}, error_mask:{error_mask}, args:{pprint.pformat(args)}]"
    # )
    # log.info(f"binary_realpath: {os.path.realpath(binary)}")

    asan_stdout, asan_stderr = "", ""
    try:
        cmd_lst = []

        cmd_lst.append("FUZZERR_ONLY_INNER=1")

        if enable_backtrace:
            cmd_lst.append("FUZZERR_ENABLE_BACKTRACE=1")

        cmd_lst.append(
            "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=1:handle_abort=1"
        )
        cmd_lst.append(f"FUZZERR_AFL_MAP={error_mask}")
        cmd_lst.append(f"{binary}")

        # add args to the command (if there are any)
        if args:
            cmd_lst.extend(args)

        cmd = subprocess.list2cmdline(cmd_lst)

        log.info(f"cmd: {cmd}")

        if os.getenv("FUZZERR_TIMEOUT_IN_SEC"):
            fuzzerr_timeout_in_sec = int(cast(str, os.getenv("FUZZERR_TIMEOUT_IN_SEC")))
            if enable_backtrace:
                fuzzerr_timeout_in_sec *= 2
            asan_stdout, asan_stderr = run_cmd(
                cmd,
                verbose=True,
                timeout=fuzzerr_timeout_in_sec,
                error_msg="ASAN binary run",
                raise_timeout=False,
            )
        else:
            asan_stdout, asan_stderr = run_cmd(
                cmd,
                verbose=True,
                timeout=1 * 60,
                error_msg="ASAN binary run",
                raise_timeout=True,
            )

    except TimeoutError:
        log.warning("Timeout error while running the binary")
        return None, asan_stdout, asan_stderr

    # log.info(f"asan_stdout: {asan_stdout}")
    # log.info(f"asan_stderr: \n{asan_stderr}")

    crash = parse_asan_crash(crash_log=asan_stderr, crash_error_mask=error_mask)

    # add cmd to crash dict
    if crash:
        crash["cmd"] = cmd

    # log.info(f">> crash: {pprint.pformat(crash)}")
    return (crash, asan_stdout, asan_stderr)


def _get_src_line_for_crash(src_path: str, logtxt: str) -> int | None:
    # iterate over the lines
    # starting at line that contains "AddressSanitizer:", until we encounter an empty line
    # match against asan regex and see if the file is under src_path
    # return the corresponding line number (match 3) for the last such match

    class State(Enum):
        NOT_IN_BACKTRACE = 0
        IN_BACKTRACE = 1

    state = State.NOT_IN_BACKTRACE
    result = None

    for line in logtxt.split("\n"):
        if "AddressSanitizer:" in line:
            state = State.IN_BACKTRACE
            continue

        elif state == State.IN_BACKTRACE:
            # # empty line => end of backtrace, return the result
            # if line.strip() == "":
            #     return result

            # non-empty line => check if it matches the asan regex
            match = asanregex.search(line)
            if match:
                filename = match.group(2)
                if not is_valid_filename(filename.strip()):
                    log.info(f">> invalid filename: {filename.strip()}, skipping")
                    continue
                if src_path in filename:
                    result = int(match.group(3))
                    return result

    return result


def _get_src_line_for_last_get_bit(src_path: str, logtxt: str) -> int | None:
    # iterate over the lines
    # maintain the last src_path matching line number

    class State(Enum):
        NOT_IN_BACKTRACE = 0
        IN_BACKTRACE = 1

    BACKTRACE_START_MARKER = "BACKTRACE START >>"
    BACKTRACE_END_MARKER = "BACKTRACE END >>"

    state = State.NOT_IN_BACKTRACE
    skip_till_next_backtrace = False
    result = None

    for line in logtxt.split("\n"):
        if BACKTRACE_START_MARKER in line:
            skip_till_next_backtrace = False
            state = State.IN_BACKTRACE

        elif BACKTRACE_END_MARKER in line:
            state = State.NOT_IN_BACKTRACE

        elif state == State.IN_BACKTRACE and not skip_till_next_backtrace:
            match = backtrace_regex.search(line)
            if match:
                if src_path in match.group(1):
                    result = int(match.group(2))
                    skip_till_next_backtrace = True

    return result


def save_crash_finder_log(
    binary: str,
    error_mask: str,
    cmd: str,
    asan_stdout: str,
    asan_stderr: str,
    reason: CrashLocationDecisionReason,
) -> None:
    """
    Saves the crash finder logs to a file in the folder specified by
    CRASH_FINDER_LOG_DIR env var.

    The file name is <binary_name>_<mask_file_name>_<timestamp>_<self_pid>

    Please note that afl-fuzz takes the final decision regarding whether a crash
    is unique or not. So during triaging, there might be many logs created by
    crash_finder that pertain to crashes that afl decided to throw away.
    However we are storing this here in the hope that this could help in cases
    where, during triaging, crash_finder says that the crash is in library but
    the crash was saved so the crash should have been in the program.

    Args:
        binary (str): path to the binary
        error_mask (str): path to error_mask file
        cmd (str): command that was run, based on which crash finder took the decision

    Returns:
        None
    """
    crash_finder_log_dir = os.getenv("CRASH_FINDER_LOG_DIR")
    if crash_finder_log_dir:
        binary_name = os.path.basename(binary)
        mask_name = os.path.basename(error_mask)
        timestamp = get_timestamp()
        pid = os.getpid()

        log_file_name = f"{binary_name}_{mask_name}_{timestamp}_{pid}.log"
        log.info(f">> saving crash finder log to: {log_file_name}")
        log_file_path = os.path.join(crash_finder_log_dir, log_file_name)
        with open(log_file_path, "w") as f:
            f.write(f"cmd: {cmd}")
            f.write(f"\n{SEPARATOR}\n")
            f.write(f"decision reason: {reason.name}")
            f.write(f"\n{SEPARATOR}\n")
            f.write(f"asan_stdout >>>>")
            f.write(f"{asan_stdout}")
            f.write(f"\n{SEPARATOR}\n")
            f.write(f"asan_stderr >>>>")
            f.write(f"{asan_stderr}")

        mask_file_name = f"{binary_name}_{mask_name}_{timestamp}_{pid}.mask"
        log.info(f">> saving error mask to: {mask_file_name}")
        mask_file_path = os.path.join(crash_finder_log_dir, mask_file_name)
        shutil.copy2(error_mask, mask_file_path)

    else:
        log.info(
            ">> CRASH_FINDER_LOG_DIR env var not set, skipping saving crash finder log"
        )


def check_crash_location(
    binary: str,
    error_mask: str,
    args: list[str],
    bin_src_path: str,
    lib_src_path: str,
    enable_backtrace: bool,
) -> CrashLocation | None:
    """
    Checks for crashes with given binary when run using the given error_mask
    and inputs

    Args:
        binary(str): path to binary(asan'ed)
        error_mask(str): path to error_mask file
        args(list[str]): list of arguments to the binary
        bin_src_path(str): path of the src directory
        lib_src_path(str): path of the lib directory
        enable_backtrace (bool): enable backtrace

    Returns:
        CrashLocation | None: the location of the crash
    """
    crash, asan_stdout, asan_stderr = _get_crash_info(
        binary, error_mask, args, enable_backtrace
    )

    if not enable_backtrace:
        if crash is not None:
            log.info(f"Successfully extracted details from asan!")
            # log.info(f"crash: {crash}")

            log.info(
                f"crash location: {crash['crash_func']}: {crash['crash_filename_path']}:{crash['crash_line']}"
            )

            # on the basis of the crash location, return the CrashLocation.
            # we need to be conservative here and check for bin_src_path since
            # we do not have the backtraces enabled and our only guide is the
            # asan_stderr
            if bin_src_path in crash["crash_filename_path"]:
                assert crash["cmd"] is not None
                # save_crash_finder_log(
                #     binary,
                #     error_mask,
                #     crash["cmd"],
                #     asan_stdout,
                #     asan_stderr,
                #     CrashLocationDecisionReason.BIN_SRC_PATH_IN_CRASH_LOCATION,
                # )
                log.info("asan_stdout (begin) >>>>>>")
                log.info(f"{asan_stdout}")
                log.info("asan_stdout (end) <<<<<<")
                log.info("asan_stderr (begin) >>>>>>")
                log.info(f"{asan_stderr}")
                log.info("asan_stderr (end) <<<<<<")
                return CrashLocation.PROGRAM
            else:
                return CrashLocation.LIBRARY

        else:
            # crash is None
            log.warning(
                "unable to extract details from asan, assuming the crash location to be the library!"
            )
            # log.warning("asan_stdout (begin) >>>>>>")
            # log.warning(f"{asan_stdout}")
            # log.warning("asan_stdout (end) <<<<<<")
            # log.warning("asan_stderr (begin) >>>>>>")
            # log.warning(f"{asan_stderr}")
            # log.warning("asan_stderr (end) <<<<<<")
            return None

    else:
        # backtrace is enabled to we need to compare the last src locations in get_bit backtrace
        # and in the asan crash
        # - extract the lib location from asan stderr
        # - extract the lib location from stdout
        # - if they are different, then CRASH_IN_PROGRAM
        # - else CRASH_IN_LIBRARY

        if not crash:
            # crash is None, meaning that either there was a TimeoutError or the
            # binary did not crash or ASAN header was not found in the stderr.
            # we can just log this info that we are ignoring this case since
            # we are not sure if the binary crashed or not
            log.warning("ignoring as crash details were not extracted from asan")
            return None

        log.info(
            f"crash location: {crash['crash_func']}: {crash['crash_filename_path']}:{crash['crash_line']}"
        )

        # get the 'last' locations for the lib_src_path in the asan stderr and
        # in the stdout
        crash_src_line = _get_src_line_for_crash(bin_src_path, asan_stderr)
        get_bit_src_line = _get_src_line_for_last_get_bit(bin_src_path, asan_stdout)

        # if we couldn't find the bin_src_path in the get_bit() backtraces,
        # then there is something really wrong with the binary and we need to
        # investigate this.
        if not get_bit_src_line:
            log.error(
                "BIN_SRC_PATH not found in get_bit() backtraces! [Please Investigate]"
            )
            log.error(f"BIN_SRC_PATH: {bin_src_path}")
            log.error("asan_stdout (begin) >>>>>>")
            log.error(f"{asan_stdout}")
            log.error("asan_stdout (end) <<<<<<")
            exit(ExitCode.SRC_PATH_NOT_IN_BACKTRACE.value)

        if not crash_src_line:
            log.error("BIN_SRC_PATH not found in asan output! [Please Investigate]")
            log.error(f"BIN_SRC_PATH: {bin_src_path}")
            log.error("asan_stderr (begin) >>>>>>")
            log.error(f"{asan_stderr}")
            log.error("asan_stderr (end) <<<<<<")
            # # if the first line after the ASAN header has __interceptor_free, then skip this
            # # this is related to some issue in openssl tests where they register interceptors
            # # that are invoked when the libcrypto tries to free memory. And these wont have the
            # # src path in the backtrace
            # for line in asan_stderr.splitlines():
            #     if "in __interceptor_free" in line:
            #         log.warning(
            #             "ignoring this crash since it is related to __interceptor_free"
            #         )
            #         exit(ExitCode.CRASH_IN_LIBRARY.value)
            exit(ExitCode.SRC_PATH_NOT_IN_BACKTRACE.value)

        log.info(f"crash_src_line: {crash_src_line}")
        log.info(f"get_bit_src_line: {get_bit_src_line}")

        if crash_src_line == get_bit_src_line:
            log.info("crash location: LIBRARY")
            return CrashLocation.LIBRARY
        else:
            assert crash["cmd"] is not None
            # save_crash_finder_log(
            #     binary,
            #     error_mask,
            #     crash["cmd"],
            #     asan_stdout,
            #     asan_stderr,
            #     CrashLocationDecisionReason.CRASH_SRC_LINE_DIFFERENT_FROM_GET_BIT_SRC_LINE,
            # )
            log.info("asan_stdout (begin) >>>>>>")
            log.info(f"{asan_stdout}")
            log.info("asan_stdout (end) <<<<<<")
            log.info("asan_stderr (begin) >>>>>>")
            log.info(f"{asan_stderr}")
            log.info("asan_stderr (end) <<<<<<")
            log.info("crash location: PROGRAM")
            return CrashLocation.PROGRAM


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
        "--enable-backtrace",
        dest="enable_backtrace",
        action=argparse.BooleanOptionalAction,
        help="enable backtacke",
    )

    return parser


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

    # save the binary name
    global PROG_NAME
    PROG_NAME = os.path.basename(args.prog_path)

    return args


def _get_lib_src_path() -> str:
    """
    Tries to get the source path from environment variable(`FUZZERR_LIB_SRC_PATH`). If this
    environment variable is not set, it exits the program with the appropriate error code
    """
    src_path = os.getenv("FUZZERR_LIB_SRC_PATH")
    if not src_path:
        log.error("FUZZERR_LIB_SRC_PATH not set, exiting now")
        exit(ExitCode.SRC_PATH_NOT_PROVIDED.value)
    return src_path


def _get_bin_src_path() -> str:
    """
    Tries to get the source path from environment variable(`FUZZERR_BIN_SRC_PATH`). If this
    environment variable is not set, it exits the program with the appropriate error code
    """
    src_path = os.getenv("FUZZERR_BIN_SRC_PATH")
    if not src_path:
        log.error("FUZZERR_BIN_SRC_PATH not set, exiting now")
        exit(ExitCode.SRC_PATH_NOT_PROVIDED.value)
    return src_path


def main() -> None:
    """
    Args:
        --prog_path(str): path to the binary to be run
        --mask_path(str): path to the error mask file
        --args(str): comma separated list of arguments to the binary
        --enable-backtrace: flag to enable backtrace

    For example a binary that would normally be invoked as:

        my_binary input1 input2

    The way crash_finder.py should be called for the above binary is:

        FUZZERR_LIB_SRC_PATH=<lib_src_path> FUZZERR_BIN_SRC_PATH=<bin_src_path> crash_finder.py --prog_path=my_binary --mask_path=<err_mask> --args=input1,input2 --enable-backtrace
    """
    parser = _setup_parser()
    args = _parse_and_validate_arguments(parser)
    # log.info(f"args: {args}")

    bin_src_path = _get_bin_src_path()
    lib_src_path = _get_lib_src_path()
    log.info(f"bin_src_path: {bin_src_path}")
    log.info(f"lib_src_path: {lib_src_path}")

    crash_location = check_crash_location(
        binary=args.prog_path,
        error_mask=args.mask_path,
        args=args.args,
        bin_src_path=bin_src_path,
        lib_src_path=lib_src_path,
        enable_backtrace=args.enable_backtrace,
    )

    if not crash_location:
        log.error(
            (
                "[!] check_crash_location returned None, PLEASE INVESTIGATE the above logs. "
                "Ignoring this case by assuming the location to be in LIBRARY"
            )
        )
        log.info(f"{ExitCode.CRASH_IN_LIBRARY.name}")
        exit(ExitCode.CRASH_IN_LIBRARY.value)

    elif crash_location == CrashLocation.PROGRAM:
        log.info(f"{ExitCode.CRASH_IN_PROGRAM.name}")
        exit(ExitCode.CRASH_IN_PROGRAM.value)

    elif crash_location == CrashLocation.LIBRARY:
        log.info(f"{ExitCode.CRASH_IN_LIBRARY.name}")
        exit(ExitCode.CRASH_IN_LIBRARY.value)


if __name__ == "__main__":
    main()
