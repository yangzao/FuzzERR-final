#! /usr/bin/env python3

import json
import time
from enum import Enum
import subprocess
import os
import pprint
import sys
from utils import (
    mkdir_p,
    run_cmd_with_realtime_output,
    get_configured_logger,
    clean_file_names,
    ensure_aslr_is_disabled,
    kill_residuals,
)
import shutil
import threading
from typing import Optional
from copy import deepcopy
import signal
import multiprocessing
import shlex
from logging import Logger


def handle_sigint(sig, frame):
    while len(multiprocessing.active_children()) > 0:
        # get all active child processes
        active = multiprocessing.active_children()
        print(f"found {len(active)} active children")
        for child in active:
            print(f"terminating {child}")
            child.terminate()
    exit(1)


signal.signal(signal.SIGINT, handle_sigint)


# set logging level
log = get_configured_logger("fuzz_bin")


# number of usable cpus
NUM_CPUS = len(os.sched_getaffinity(0))
# NUM_CPUS = 32  # use half the cores


class FuzzResult(Enum):
    OK = 0
    ERROR = 1


BASE_CONFIG = {
    "DEBUG": 0,
    "AFL_FUZZ_BIN": "/home/shank/code/research/FuzzERR_AFLplusplus/afl-fuzz",
    # "AFL_TIMEOUT_MSECS": 10000,  # 10 seconds
    "BIN_ARGS": "",
    "TOTAL_FUZZ_TIME_MINS": 6 * 60,  # 6 hours
    "FUZZ_TIME_PER_INPUT_ARG_MINS": 15,  # 15 minutes
    "MIN_FUZZ_TIME_PER_INPUT_ARG_MINS": 15,  # 15 minutes
    # "FUZZERR_TIMEOUT_IN_SEC": 1,  # we dont really care about hangs as of
    # now so use this and skip it
    "LOG_DESTINATION": "MULTILOG",  # MULTILOG, STDOUT
    "RANDOM_FAULT_INJECTION": 0,
    "FUZZERR_DISABLE_CRASH_FINDER": 0,
    "RESUME_FUZZING": 0,
}


def create_zero_map(config: dict) -> None:
    zero_file = os.path.join(config["AFL_INPUT_DIR"], "zero")
    cmd_lst = [
        "afl_create_zero_map.sh",
        zero_file,
    ]
    cmd = subprocess.list2cmdline(cmd_lst)
    # report_if_crashes(run_cmd(cmd))
    run_cmd_with_realtime_output(cmd)


def construct_config(fuzz_config: dict, parallelize: bool = False) -> dict:
    # create copy of base_config dict
    config = BASE_CONFIG.copy()
    config["PARALLELIZE"] = parallelize

    # merge with fuzz_config
    config.update(fuzz_config)

    # add specific configuration
    # BIN_NAME
    # BASE_AFL_DIR
    # AFL_INPUT_DIR
    # AFL_OUTPUT_DIR
    # AFL_TMPDIR
    # AFL_MAP_FILE

    if "BIN_NAME" not in config:
        config["BIN_NAME"] = os.path.basename(config["BIN_TO_FUZZ"])

    if "BASE_AFL_DIR" not in config:
        config["BASE_AFL_DIR"] = mkdir_p(
            os.path.join(config["LIB_INSTR_DIR"], f"{config['BIN_NAME']}_afl")
        )
    else:
        mkdir_p(config["BASE_AFL_DIR"])

    if "AFL_INPUT_DIR" not in config:
        config["AFL_INPUT_DIR"] = mkdir_p(
            os.path.join(config["BASE_AFL_DIR"], "afl_input")
        )
    else:
        mkdir_p(config["AFL_INPUT_DIR"])

    if "AFL_OUTPUT_DIR" not in config:
        config["AFL_OUTPUT_DIR"] = mkdir_p(
            os.path.join(config["BASE_AFL_DIR"], "afl_output")
        )
    else:
        mkdir_p(config["AFL_OUTPUT_DIR"])

    config["CRASH_FINDER_LOG_DIR"] = mkdir_p(
        os.path.join(config["BASE_AFL_DIR"], "crash_finder_logs")
    )

    if "AFL_TMPDIR" not in config:
        tmpdir = f"/tmp/afl-ramdisk/{config['BIN_NAME']}/tmpdir"
        shutil.rmtree(tmpdir, ignore_errors=True)
        config["AFL_TMPDIR"] = mkdir_p(tmpdir)
    else:
        mkdir_p(config["AFL_TMPDIR"])

    if "AFL_MAP_FILE" not in config:
        config["AFL_MAP_FILE"] = f"/tmp/afl-ramdisk/{config['BIN_NAME']}/afl.map"

    return config


class FuzzerKind(Enum):
    DEFAULT = 0
    MAIN = 1
    SECONDARY = 2


def create_fuzz_cmd(
    config: dict,
    dry_run_get_bit_call_count: int,
    main_or_secondary: FuzzerKind = FuzzerKind.DEFAULT,
    secondary_num: Optional[int] = None,
    reduce_fuzz_time_secs: int = 0,
) -> str:
    # base options
    cmd_lst = [
        "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:handle_abort=1",
        # "AFL_CHILD_DEBUG=0",
        # FUZZERR_ENABLE_BACKTRACE=1
        "AFL_SHUFFLE_QUEUE=1",
        "AFL_SYNC_TIME=6",  # sync every 6 minutes
        "AFL_DISABLE_TRIM=1",
        "FUZZERR_ONLY_INNER=1",
    ]

    # # custom python mutator
    # cmd_lst.extend(
    #     [
    #         f"PYTHONPATH={os.getenv('HOME')}/code/research/FuzzERR/scripts",
    #         "AFL_PYTHON_MODULE=fuzzerr_custom_mutator",
    #         "AFL_CUSTOM_MUTATOR_ONLY=1",
    #     ]
    # )

    if "RANDOM_FAULT_INJECTION" in config and config["RANDOM_FAULT_INJECTION"] == 1:
        cmd_lst.extend(
            [
                f"PYTHONPATH={os.getenv('HOME')}/code/research/FuzzERR/scripts",
                "AFL_PYTHON_MODULE=fuzzerr_mutator_random",
                "AFL_CUSTOM_MUTATOR_ONLY=1",
            ]
        )

    if (
        "FUZZERR_DISABLE_CRASH_FINDER" in config
        and config["FUZZERR_DISABLE_CRASH_FINDER"] == 1
    ):
        cmd_lst.append("FUZZERR_DISABLE_CRASH_FINDER=1")

    # disable startup calibration for long running programs
    if (
        "DISABLE_STARTUP_CALIBRATION" in config
        and config["DISABLE_STARTUP_CALIBRATION"] == True
    ):
        cmd_lst.append("AFL_NO_STARTUP_CALIBRATION=1")
    else:
        cmd_lst.append("AFL_FAST_CAL=1")

    if config["DEBUG"] == 1 or config["DEBUG"] == 2:
        cmd_lst.extend(
            [
                "AFL_DEBUG=1",
            ]
        )
        if config["DEBUG"] == 1:
            cmd_lst.append("FUZZERR_DEBUG=1")
        elif config["DEBUG"] == 2:
            cmd_lst.append("FUZZERR_DEBUG=2")

    # only useful for long running programs like pdf readers (ref. apvlv)
    if "FUZZERR_TIMEOUT_IN_SEC" in config:
        cmd_lst.append(f"FUZZERR_TIMEOUT_IN_SEC={config['FUZZERR_TIMEOUT_IN_SEC']}")

    # AFL_UI is required only if we are not in debug mode and we are runnining in
    # non-parallelized mode
    if not (config["DEBUG"] == 0 and main_or_secondary == FuzzerKind.DEFAULT):
        cmd_lst.append("AFL_NO_UI=1")

    # if we are creating the command for either a MAIN or SECONDARY fuzzer,
    # set the name of the AFL_MAP_FILE accordingly so that things dont go south
    # for this, we can duplicate the config object and set the AFL_MAP_FILE
    # so that we dont mess up with the original object
    if (
        main_or_secondary == FuzzerKind.MAIN
        or main_or_secondary == FuzzerKind.SECONDARY
    ):
        config = deepcopy(config)
        if main_or_secondary == FuzzerKind.MAIN:
            config["AFL_MAP_FILE"] += "_M"
        else:
            config["AFL_MAP_FILE"] += f"_S{secondary_num}"

    # additional options from config
    cmd_lst.extend(
        [
            f"AFL_TMPDIR={config['AFL_TMPDIR']}",
            f"FUZZERR_AFL_MAP={config['AFL_MAP_FILE']}",
            f"FUZZERR_BIN_SRC_PATH={config['BIN_SRC_DIR']}",
            f"FUZZERR_LIB_SRC_PATH={config['LIB_SRC_DIR']}",
            f"CRASH_FINDER_LOG_DIR={config['CRASH_FINDER_LOG_DIR']}",
            f"{config['AFL_FUZZ_BIN']}",
            "-i",
            f'{"-" if config["RESUME_FUZZING"] else config["AFL_INPUT_DIR"]}',
            "-o",
            f"{config['AFL_CURR_OUTPUT_DIR']}",
            "-f",
            f"{config['AFL_MAP_FILE']}",
        ]
    )

    if "AFL_TIMEOUT_MSECS" in config:
        cmd_lst.extend(["-t", f"{config['AFL_TIMEOUT_MSECS']}"])

    # time to fuzz in seconds
    ttf = max(
        20, config["FUZZ_TIME_PER_INPUT_ARG_MINS"] * 60 - (reduce_fuzz_time_secs + 1)
    )
    cmd_lst.extend(["-V", f"{ttf}"])

    # fuzzer_name
    fuzzerr_folder_name = "default"
    # in case of main fuzzer
    if main_or_secondary == FuzzerKind.MAIN:
        fuzzerr_folder_name = "fuzzer_M"
        cmd_lst.extend(["-M", fuzzerr_folder_name])

    # or secondary fuzzer
    elif main_or_secondary == FuzzerKind.SECONDARY:
        assert (
            secondary_num is not None
        ), "secondary_num needs to be provided to name the secondary fuzzer"
        fuzzerr_folder_name = f"fuzzer_S{secondary_num}"
        cmd_lst.extend(["-S", fuzzerr_folder_name])

    # limit sizes of input generated by afl
    min_afl_input_size = int(dry_run_get_bit_call_count * 1 // 8) + 1
    max_afl_input_size = int(dry_run_get_bit_call_count * 1.20 // 8) + 1
    cmd_lst.extend(["-g", f"{min_afl_input_size}", "-G", f"{max_afl_input_size}"])

    cmd_lst.extend(
        [
            "--",
            f"{config['BIN_TO_FUZZ']}",
        ]
    )

    # add bin args
    bin_args = config["BIN_ARGS"]
    # need an output file?
    if "{{output}}" in bin_args:
        if main_or_secondary == FuzzerKind.MAIN:
            bin_args = bin_args.replace(
                "{{output}}", os.path.join(config["AFL_TMPDIR"], f"outfile_M")
            )
        elif main_or_secondary == FuzzerKind.SECONDARY:
            bin_args = bin_args.replace(
                "{{output}}",
                os.path.join(config["AFL_TMPDIR"], f"outfile_S{secondary_num}"),
            )
        else:
            bin_args = bin_args.replace(
                "{{output}}", os.path.join(config["AFL_TMPDIR"], f"outfile")
            )
    # need an output dir?
    if "{{outputd}}" in bin_args:
        output_dir = os.path.join(config["AFL_TMPDIR"], f"outdir")
        if main_or_secondary == FuzzerKind.MAIN:
            output_dir = os.path.join(config["AFL_TMPDIR"], "outdir_M")
        elif main_or_secondary == FuzzerKind.SECONDARY:
            output_dir = os.path.join(config["AFL_TMPDIR"], f"outdir_S{secondary_num}")
        mkdir_p(output_dir)
        bin_args = bin_args.replace("{{outputd}}", output_dir)

    cmd_lst.extend(bin_args.split())

    # log destination?
    if config["LOG_DESTINATION"] == "MULTILOG":
        multilog_dest = mkdir_p(
            f'{config["AFL_CURR_OUTPUT_DIR"]}/{fuzzerr_folder_name}/fuzzerr_logs'
        )
        # s5242880 => 5*1024*1024 bytes per file = 5242880 bytes
        # n10 => 10 files for rotation
        cmd_lst.extend(shlex.split(f"2>&1 | multilog s5242880 n15 {multilog_dest}"))

    return subprocess.list2cmdline(cmd_lst)


def create_dry_run_cmd(config: dict, dry_run_result_file: str) -> str:
    # base options
    cmd_lst = [
        "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0:handle_abort=1",
        "FUZZERR_ONLY_INNER=1",
    ]

    if config["DEBUG"] == 1 or config["DEBUG"] == 2:
        cmd_lst.extend(
            [
                "AFL_DEBUG=1",
                "AFL_NO_UI=1",
            ]
        )
        if config["DEBUG"] == 1:
            cmd_lst.append("FUZZERR_DEBUG=1")
        elif config["DEBUG"] == 2:
            cmd_lst.append("FUZZERR_DEBUG=2")

    if "FUZZERR_TIMEOUT_IN_SEC" in config:
        cmd_lst.append(
            f"FUZZERR_TIMEOUT_IN_SEC={config['FUZZERR_TIMEOUT_IN_SEC']}",
        )

    cmd_lst.extend(
        [
            "FUZZERR_DISABLE=1",  # disable error injection
            "FUZZERR_DRY_RUN=1",  # dry run
            f"FUZZERR_DRY_RUN_RESULT={dry_run_result_file}",  # dry run result file
            f"FUZZERR_BIN_SRC_PATH={config['BIN_SRC_DIR']}",
            f"FUZZERR_LIB_SRC_PATH={config['LIB_SRC_DIR']}",
            f"{config['BIN_TO_FUZZ']}",
        ]
    )

    # output file required?
    bin_args = config["BIN_ARGS"]
    if "{{output}}" in bin_args:
        bin_args = bin_args.replace(
            "{{output}}", os.path.join(config["AFL_TMPDIR"], "outfile")
        )
    # need an output dir?
    if "{{outputd}}" in bin_args:
        bin_args = bin_args.replace(
            "{{outputd}}", os.path.join(config["AFL_TMPDIR"], f"outdir")
        )
    cmd_lst.extend(bin_args.split())

    return subprocess.list2cmdline(cmd_lst)


def validate_required_fields(config: dict) -> None:
    required_fields = [
        "AFL_FUZZ_BIN",
        "AFL_INPUT_DIR",
        "AFL_MAP_FILE",
        "AFL_OUTPUT_DIR",
        "AFL_CURR_OUTPUT_DIR",
        # "AFL_TIMEOUT_MSECS",
        "AFL_TMPDIR",
        "BASE_AFL_DIR",
        "BIN_ARGS",
        "BIN_NAME",
        "BIN_SRC_DIR",
        "BIN_TO_FUZZ",
        "LIB_INSTR_DIR",
        "LIB_SRC_DIR",
        "FUZZ_TIME_PER_INPUT_ARG_MINS",
    ]
    for field in required_fields:
        if field not in config:
            raise Exception(f"Required field {field} not in config")

    if "{{input}}" in config["BIN_ARGS"] or "{{input_name}}" in config["BIN_ARGS"]:
        raise Exception(
            "{{input}} not allowed in BIN_ARGS, provide an BIN_INPUT_DIR directory containing input files"
        )


def get_fuzzing_cmd_from_readme(fp: str) -> str:
    # read the creash file
    # fuzzing cmd is the 3rd line in the file
    with open(fp) as f:
        lines = [line.strip() for line in f.readlines()]
        return lines[2]


def save_crashes(config: dict) -> None:
    # in case of parallel fuzzing, we would have multiple directories
    # in the output directory, each having the name of their respective
    # fuzzing worker (which is not relevant)
    # we just need to iterate over these and collect these crashes
    crashes_dirs = []

    # parallel fuzzing
    for d in os.listdir(config["AFL_CURR_OUTPUT_DIR"]):
        crashes_dirs.append(
            os.path.join(config["AFL_CURR_OUTPUT_DIR"], os.path.join(d, "crashes"))
        )

    # saved crashes dir
    saved_crashes_dir = os.path.join(config["BASE_AFL_DIR"], "saved_crashes")
    mkdir_p(saved_crashes_dir)

    for crashes_dir in crashes_dirs:
        if os.path.exists(crashes_dir):
            if "README.txt" in os.listdir(crashes_dir):
                # get the fuzzing cmd from README.txt
                fuzz_cmd = get_fuzzing_cmd_from_readme(
                    os.path.join(crashes_dir, "README.txt")
                )

                # now save the crashes and the fuzzing cmd
                for f in os.listdir(crashes_dir):
                    if f == "README.txt":
                        continue
                    # copy the crashing mask
                    fp = os.path.join(crashes_dir, f)
                    saved_fp = os.path.join(saved_crashes_dir, f)
                    shutil.copy2(fp, saved_fp)
                    log.info(f"saved crash file: {f}")

                    # create the file to store the fuzzing cmd
                    cmd_fn = f"{f}_fuzzing_cmd"
                    cmd_fp = os.path.join(saved_crashes_dir, cmd_fn)
                    with open(cmd_fp, "w") as cmd_file:
                        cmd_file.write(fuzz_cmd)
                    log.info(
                        f"saved fuzzing cmd for the crash to file: {os.path.basename(cmd_fp)}"
                    )


def _fuzz(fuzz_cmd: str, config: dict):
    run_cmd_with_realtime_output(
        fuzz_cmd,
        timeout=(config["FUZZ_TIME_PER_INPUT_ARG_MINS"] + 10) * 60,
        log=log,
    )


def dry_run(config: dict) -> int:
    """
    returns the calls to get_bit() done in a dry_run (with fuzzerr_disabled)
    """
    log.info(f"[+] performing dry_run to get the number of calls to get_bit()")
    dry_run_result_file = os.path.join(config["AFL_TMPDIR"], "dry_run_result")
    fuzz_cmd = create_dry_run_cmd(config, dry_run_result_file)
    log.info(f"[+] dry_run cmd: {fuzz_cmd}")

    run_cmd_with_realtime_output(fuzz_cmd, log=log)

    # open the dry_run_result file and read the integer
    with open(dry_run_result_file) as f:
        dry_run_result = int(f.read().strip())

    return dry_run_result


def fuzz(config: dict) -> FuzzResult:
    """
    runs the fuzzer and saves the crashes (optionally running on all cores).
    """
    # validate required fields in config
    validate_required_fields(config)

    # - if we have to parallelize this,
    #   - we construct multiple fuzz_cmds
    #     one for the master and the rest for slaves
    #   - we also need to take care to decrease the times for the slave fuzzers
    #     so that they time out before the master

    # do a dry run of the file to collect the number of calls to get_bit()
    try:
        dry_run_get_bit_call_count = dry_run(config)
    except Exception as e:
        log.error(
            "[!] dry_run with the input failed, this input will be skipped [PLEASE DELETE THIS INPUT].",
            e,
            stack_info=True,
            exc_info=True,
        )
        return FuzzResult.ERROR

    log.info(
        f"[+] number of calls to get_bit() in dry run: {dry_run_get_bit_call_count}"
    )

    if config["PARALLELIZE"]:
        if "NUM_CPUS" in config:
            global NUM_CPUS
            NUM_CPUS = config["NUM_CPUS"]

        log.info(f"[+] fuzzing parallely on {NUM_CPUS - 2} cores")
        # use NUM_CORES - 2

        # 1 -> master
        fuzz_cmd = create_fuzz_cmd(
            config,
            dry_run_get_bit_call_count=dry_run_get_bit_call_count,
            main_or_secondary=FuzzerKind.MAIN,
        )
        log.info(f"[*] starting main worker: {fuzz_cmd}")
        threading.Timer(0.0, _fuzz, [fuzz_cmd, config]).start()
        time.sleep(2)

        # (NUM_CORES - 2) - 1 -> slaves
        delay = 2
        for i in range(NUM_CPUS - 2 - 1):
            fuzz_cmd = create_fuzz_cmd(
                config,
                dry_run_get_bit_call_count=dry_run_get_bit_call_count,
                main_or_secondary=FuzzerKind.SECONDARY,
                secondary_num=i + 1,
                reduce_fuzz_time_secs=delay,
            )
            time.sleep(0.5)
            log.info(f"[*] starting secondary worker ({i+1}): {fuzz_cmd}")
            threading.Timer(0.0, _fuzz, [fuzz_cmd, config]).start()
            delay += 1

        # wait for the fuzzers to finish
        while threading.active_count() > 1:
            time.sleep(10)
            log.info(f">>>>> Active Threads: {threading.active_count()}")
            try:
                subprocess.check_call(["afl-whatsup", "-s", config["AFL_OUTPUT_DIR"]])
            except:
                pass

    else:
        # SINGLE PROCESS
        fuzz_cmd = create_fuzz_cmd(
            config, dry_run_get_bit_call_count=dry_run_get_bit_call_count
        )
        log.info(f"[*] fuzzing with command: {fuzz_cmd}")
        run_cmd_with_realtime_output(
            fuzz_cmd, timeout=(config["FUZZ_TIME_PER_INPUT_ARG_MINS"] + 2) * 60, log=log
        )

    # wait some time to let the fuzzers finish
    time.sleep(5)

    # at this point, kill all the processes for the binary being fuzzed,
    # except this one (the one containing fuzz_bin.py in its name)
    kill_residuals(config["BIN_TO_FUZZ"], log)

    save_crashes(config)

    return FuzzResult.OK


def delete_files_from_previous_run(config: dict) -> None:
    # AFL_OUTPUT_DIR
    log.info(f"[+] deleting [AFL_OUTPUT_DIR]")
    shutil.rmtree(config["AFL_OUTPUT_DIR"])
    mkdir_p(config["AFL_OUTPUT_DIR"])

    # Crash Finder Logs
    crash_finder_logs_dir = os.path.join(config["BASE_AFL_DIR"], "crash_finder_logs")
    log.info("[*] deleting [crash_finder_logs_dir]")
    shutil.rmtree(crash_finder_logs_dir, ignore_errors=True)

    # Saved Crashes
    saved_crashes_dir = os.path.join(config["BASE_AFL_DIR"], "saved_crashes")
    log.info("[*] deleting [saved_crashes_dir]")
    shutil.rmtree(saved_crashes_dir, ignore_errors=True)

    # Saved Crashes Minimized
    saved_crashes_minimized_dir = os.path.join(
        config["BASE_AFL_DIR"], "saved_crashes_minimized"
    )
    log.info("[*] deleting [saved_crashes_minimized_dir]")
    shutil.rmtree(saved_crashes_minimized_dir, ignore_errors=True)

    # Saved Crashes Minimized Deduplicated
    saved_crashes_min_dedup_dir = os.path.join(
        config["BASE_AFL_DIR"], "saved_crashes_minimized_dedup"
    )
    log.info("[*] deleting [saved_crashes_minimized_deduplicated_dir]")
    shutil.rmtree(saved_crashes_min_dedup_dir, ignore_errors=True)


def main() -> None:
    ensure_aslr_is_disabled(log)

    if len(sys.argv) < 2:
        print("[!] usage: fuzz_bin.py <fuzz_config.json>")
        exit(1)

    # parallelize?
    parallelize = False
    if len(sys.argv) >= 3:
        parallelize = sys.argv[2] == "-p"

    # note the start time
    start_time = time.monotonic()

    # read the json config specified in the first argument
    with open(sys.argv[1], "r") as fuzz_config_file:
        fuzz_config = json.load(fuzz_config_file)
        log.info("fuzz_config:")
        log.info(f"{pprint.pformat(fuzz_config)}")

        # construct the config
        config = construct_config(fuzz_config, parallelize)

        # if AFL_OUTPUT_DIR is not empty, ask the user if it should be deleted
        if (
            os.path.exists(config["AFL_OUTPUT_DIR"])
            and len(os.listdir(config["AFL_OUTPUT_DIR"])) > 0
        ):
            log.info(
                f"[!] [AFL_OUTPUT_DIR] is not empty, do you want to delete it and other related files? [y/n]"
            )
            if input() == "y":
                delete_files_from_previous_run(config)
                config["RESUME_FUZZING"] = False
            else:
                log.info("[*] continuing with the existing directory...")
                config["RESUME_FUZZING"] = True

        if not config["RESUME_FUZZING"]:
            # run setup commands, if any
            if "SETUP_CMDS" in config:
                for cmd in config["SETUP_CMDS"]:
                    log.info(f"[*] running setup cmd: {cmd}")
                    run_cmd_with_realtime_output(cmd, log=log)

            # create zero map file as initial input
            create_zero_map(config)

        # BIN_ARGS_LIST is always required
        assert "BIN_ARGS_LIST" in config, "BIN_ARGS_LIST not found in config"

        # clean the names of the inputs, if applicable
        if "BIN_INPUT_DIR" in config:
            clean_file_names(config["BIN_INPUT_DIR"])

        # log the final config being used
        log.info("fuzzing with final config:")
        log.info(f"{pprint.pformat(config)}")

        num_input_combinations_to_fuzz = (
            config["TOTAL_FUZZ_TIME_MINS"] // config["FUZZ_TIME_PER_INPUT_ARG_MINS"]
        )
        log.info(
            f"[*] number of input combinations to fuzz (based on total time limit): {num_input_combinations_to_fuzz}"
        )

        num_input_combinations_fuzzed = 0
        for (i, bin_args) in enumerate(config["BIN_ARGS_LIST"]):
            log.info(
                f"[+] num_input_combinations_fuzzed: {num_input_combinations_fuzzed}"
            )
            if num_input_combinations_fuzzed >= num_input_combinations_to_fuzz:
                break

            if "BIN_INPUT_DIR" in config:
                for f in os.listdir(config["BIN_INPUT_DIR"]):
                    log.info(
                        f"[+] num_input_combinations_fuzzed: {num_input_combinations_fuzzed}"
                    )
                    if num_input_combinations_fuzzed >= num_input_combinations_to_fuzz:
                        break

                    # replace {{input}} with input file
                    config["BIN_ARGS"] = bin_args.replace(
                        "{{input}}", os.path.join(config["BIN_INPUT_DIR"], f)
                    )
                    # replace {{input_name}} with input filename (and not the path)
                    config["BIN_ARGS"] = config["BIN_ARGS"].replace(
                        "{{input_name}}",
                        os.path.basename(os.path.join(config["BIN_INPUT_DIR"], f)),
                    )
                    # set the directory that afl should use as the output directory
                    config["AFL_CURR_OUTPUT_DIR"] = os.path.join(
                        config["AFL_OUTPUT_DIR"], f"{f}__{i}"
                    )
                    # fuzz
                    res = fuzz(config)
                    if res == FuzzResult.OK:
                        num_input_combinations_fuzzed += 1

            else:
                # no BIN_INPUT_DIR
                config["BIN_ARGS"] = bin_args
                # set the directory that afl should use as the output directory
                config["AFL_CURR_OUTPUT_DIR"] = os.path.join(
                    config["AFL_OUTPUT_DIR"], f"no_input__{i}"
                )
                # fuzz
                res = fuzz(config)
                if res == FuzzResult.OK:
                    num_input_combinations_fuzzed += 1

        # run teardown commands, if any
        if "TEARDOWN_CMDS" in config:
            for cmd in config["TEARDOWN_CMDS"]:
                log.info(f"[*] running teardown cmd: {cmd}")
                run_cmd_with_realtime_output(cmd, log=log)

        log.info("[+] done fuzzing!!")
        log.info(f"[+] num_input_combinations_fuzzed: {num_input_combinations_fuzzed}")
        log.info(
            f"[+] total time spent fuzzing: {( time.monotonic() - start_time ) // 60} minutes"
        )


if __name__ == "__main__":
    main()
