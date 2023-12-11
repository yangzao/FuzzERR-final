from datetime import datetime
import subprocess
import os
import inspect
import shutil
import logging
import psutil
from logging import Logger
import base64
import signal
import binascii
from typing import Optional
import sys
import re
from colorlog import ColoredFormatter


ERROR_MASK_TO_INVESTIGATE_DIR = (
    "/home/shank/code/research/FuzzERR/TODO/crash_minimizer_investigate/"
)

SEPARATOR = "=" * 80

asanregex = re.compile(r"#\d+ .*? in (.*?) (.*?):(\d+)")
get_bit_regex = re.compile(
    r"get_bit\(\): returning 1 .*? \(effective idx (\d+)\), mask_id (\d+)"
)


def path_exists(path):
    return os.path.exists(path)


def is_file(path):
    return os.path.isfile(path)


def get_file_name_from_path(path):
    dir_path, filename = os.path.split(path)
    return filename if filename else os.path.basename(dir_path)


def get_file_size(path):
    return os.path.getsize(path)


def is_dir(path):
    return os.path.isdir(path)


def get_encoded_file(filename) -> str:
    if is_valid_file(filename):
        data = open(filename, "rb").read()
        return base64.b64encode(data).decode("latin-1")
    return ""


def is_valid_file(path):
    return path_exists(path) and is_file(path) and get_file_size(path) != 0


def is_valid_filename(filename):
    if filename == "??":
        return False
    if os.path.basename(filename) == "helper.c":
        return False
    if filename.startswith("/build"):
        # library files
        return False
    if "compiler-rt" in filename:
        return False
    if "llvm10" in filename:
        return False
    return True


def get_timestamp() -> str:
    """
    returns a timestamp in format 'yyyymmddhhmmss_<milisecond>'
    """
    d = datetime.now()
    return datetime.strftime(d, "%Y%m%d%H%M%S_%f")


def get_current_fn_name() -> str:
    return inspect.stack()[1][3]


def save_error_mask_for_investigation(
    mask_file: str, prog_name: str, log: Logger
) -> str:
    # name of file to which the mask will be saved
    ts = get_timestamp()
    saved_error_mask_file = os.path.join(
        ERROR_MASK_TO_INVESTIGATE_DIR, ts + "_" + prog_name
    )

    # save the file
    shutil.copy2(mask_file, saved_error_mask_file)
    log.warning(
        f"[!] error mask named {saved_error_mask_file} copied to {ERROR_MASK_TO_INVESTIGATE_DIR}"
    )

    return saved_error_mask_file


def trimmed_output(output):
    if isinstance(output, str):
        # if the length is greater than 2000, trim it and return the last 2000 characters
        if len(output) > 4000:
            return output[-4000:]
        return output
    else:
        return output


def decode_string(data, log: Logger):
    """
    base64 decode a string or bytes
    """
    if isinstance(data, str):
        data = data.encode("latin-1")
    try:
        return base64.b64decode(data).decode("latin-1")
    except binascii.Error as e:
        log.exception("Error decoding string: {0}".format(e))
        if isinstance(data, str):
            return data
        else:
            return data.decode("latin-1")


def encode_string(data, log: Logger):
    """
    base64 encode a string or bytes
    """
    if isinstance(data, str):
        data = data.encode("latin-1")
    try:
        return base64.b64encode(data).decode("latin-1")
    except binascii.Error as e:
        log.exception("Error encoding string: {0}".format(e))
        if isinstance(data, str):
            return data
        else:
            return data.decode("latin-1")


def mkdir_p(path: str) -> str:
    """
    creates a directory if it does not exist
    """
    if not os.path.exists(path):
        os.makedirs(path)
    return path


def run_cmd(
    command,
    env=None,
    cwd=None,
    verbose=False,
    timeout=1 * 60,  # in seconds
    trim=False,
    error_msg="",
    raise_timeout=False,
    log=None,
) -> Optional[tuple[str, str, subprocess.CompletedProcess]]:
    try:
        if log:
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
        if verbose and log:
            log.debug(f"STDOUT has {trimmed_output(out.stdout.decode('latin-1'))}")
            log.debug(f"STDERR has {trimmed_output(out.stderr.decode('latin-1'))}")
        if trim:
            return (
                trimmed_output(out.stdout.decode("latin-1")),
                trimmed_output(out.stderr.decode("latin-1")),
                out,
            )
        else:
            return out.stdout.decode("latin-1"), out.stderr.decode("latin-1"), out

    except subprocess.TimeoutExpired as e:
        if log:
            log.error(
                f"The {error_msg} Command Timed out", extra={"cmd": command, "error": e}
            )
        if raise_timeout:
            raise TimeoutError(f"The {error_msg} Command Timed out")
        return None

    except Exception as e:
        if log:
            log.exception(f"{error_msg} failed", extra={"cmd": command, "error": e})
        return None


def run_cmd_with_realtime_output(
    cmd: str, timeout=1 * 60, log: Logger | None = None  # in seconds
) -> None:
    p = subprocess.Popen(
        cmd,
        shell=True,
        stdout=sys.stdout,
        stderr=sys.stderr,
        bufsize=0,
        start_new_session=True,
    )
    try:
        returncode = p.wait(timeout=timeout)
        if returncode != 0:
            if log:
                log.exception(
                    f"Command {cmd} failed with return code {returncode}",
                    exc_info=True,
                    stack_info=True,
                )
                log.error(f"stderr: {p.stderr}")
            raise Exception(f"Command {cmd} failed with returncode {returncode}")

    except subprocess.TimeoutExpired:
        if log:
            log.exception(f"The Command Timed out", stack_info=True)
        if log:
            log.warning(f"Process id is: {p.pid}")
            log.warning(f"Killing process group {os.getpgid(p.pid)}")
            log.warning(f"PID of fuzz_bin is {os.getpid()}")
            log.warning(f"PGID of fuzz_bin is {os.getpgid(os.getpid())}")
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        # try:
        #     proc = psutil.Process(p.pid)
        # except psutil.NoSuchProcess:
        #     return
        # else:
        #     for child in proc.children(recursive=True):
        #         if log:
        #             log.warning(f"Killing child process {child.pid}")
        #         child.terminate()
        #     proc.terminate()
        #     proc.wait()


def get_configured_logger(name: str, level: int = logging.INFO) -> Logger:
    log = logging.getLogger(name)
    log.setLevel(level)
    stream_h = logging.StreamHandler()
    formatter = ColoredFormatter(
        "%(log_color)s%(asctime)-s %(name)s [%(levelname)s] %(reset)s%(message)s",
        datefmt=None,
        reset=True,
        log_colors={
            "DEBUG": "purple",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red",
        },
    )
    stream_h.setFormatter(formatter)
    log.addHandler(stream_h)
    return log


def clean_file_names(dir: str) -> None:
    # iterate over all files in the input directory
    for file in os.listdir(dir):
        # replace , with _ in the filename
        new_name = file.replace(",", "_")
        if new_name != file:
            os.rename(
                os.path.join(dir, file),
                os.path.join(dir, new_name),
            )


def ensure_aslr_is_disabled(log: Logger) -> None:
    """
    ensures that ASLR is disabled
    """
    log.info("[+] checking if ASLR is disabled")
    # check if ASLR is disabled
    aslr_status = subprocess.check_output(
        ["cat", "/proc/sys/kernel/randomize_va_space"]
    ).strip()
    if aslr_status == b"0":
        log.info("[+] ASLR is disabled")
    else:
        log.error("[!] ASLR is enabled, please disable it and try again")
        exit(1)


def _get_asan_stacktrace(stderr_log: str, log: Logger) -> list[str]:
    result = []

    # starts at a line containing "AddressSanitizer:"
    # ends with the first blank line

    NOT_IN_STACKTRACE = 0
    IN_STACKTRACE = 1
    state = NOT_IN_STACKTRACE

    for line in stderr_log.split("\n"):
        if state == NOT_IN_STACKTRACE:
            if " AddressSanitizer:" in line:
                state = IN_STACKTRACE
            continue
        elif state == IN_STACKTRACE:
            if line == "":
                break
            if not asanregex.search(line):
                continue
            result.append(line)

    if not result:
        log.warning("Could not find ASAN stacktrace in stderr log [Please Investigate]")

    return result


def _get_effective_ids(log: str) -> list[int]:
    # the lines containing idx are of the form:
    # get_bit(): returning 1 for current_idx 27 (effective idx 27), mask_id 408, having hid 4
    result = []
    for line in log.split("\n"):
        match = get_bit_regex.search(line)
        if match:
            result.append(int(match.group(1)))
    return result


def _get_injected_mask_ids(log: str) -> list[int]:
    result = []
    for line in log.split("\n"):
        match = get_bit_regex.search(line)
        if match:
            result.append(int(match.group(2)))
    result = list(sorted(list(set(result))))
    return result


def kill_residuals(bin_path: str, log: Logger) -> None:
    # kill any residual processes for the binary being fuzzed
    ignore_lst = [
        "fuzz_bin.py",
        "crash_deduplicate.py",
        "crash_minimizer.py",
        "crash_finder.py",
    ]

    log.info(f"Killing any residual processes for {bin_path}")
    cmd = f"pgrep -f {bin_path}"
    log.info(f"running cmd: {cmd}")
    pids = []
    try:
        pids = (
            subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, text=True
            )
            .strip()
            .splitlines()
        )
    except subprocess.CalledProcessError as e:
        log.error(f"cmd {cmd} failed with error: {e}")
        log.error(f"cmd output: {e.output}")

    for pid in pids:
        # get the command line for the pid
        cmd = f"ps -p {pid} --no-headers -fww -o cmd="
        try:
            full_cmd = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.STDOUT, text=True
            ).strip()
            log.info(f"full_cmd: {full_cmd}")
            if any(x in full_cmd for x in ignore_lst):
                log.info(f"ignoring {full_cmd}")
                continue
            log.info(f"Killing pid: {pid}")
            cmd = f"kill -KILL {pid}"
            subprocess.check_call(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            log.error(f"cmd {cmd} failed with error: {e}")
            log.error(f"cmd output: {e.output}")
    log.info(f"Killing residuals done")
