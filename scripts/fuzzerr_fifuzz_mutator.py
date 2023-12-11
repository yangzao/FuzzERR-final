#!/usr/bin/env python
# encoding: utf-8

import random
import os
from sre_constants import FAILURE, SUCCESS
import sys


def init(seed):
    """
    Called once when AFLFuzz starts up. Used to seed our RNG.

    @type seed: int
    @param seed: A 32-bit random value
    """
    random.seed(seed)


def deinit():
    pass


def fuzz(buf, add_buf, max_size):
    """
    Called per fuzzing iteration.

    @type buf: bytearray
    @param buf: The buffer that should be mutated.

    @type add_buf: bytearray
    @param add_buf: A second buffer that can be used as mutation source.

    @type max_size: int
    @param max_size: Maximum size of the mutated output. The mutation must not
        produce data larger than max_size.

    @rtype: bytearray
    @return: A new bytearray containing the mutated data
    """
    debug_mode = os.getenv("FUZZERR_DEBUG")
    if debug_mode and debug_mode == "1":
        print(f"(fuzz) afl buf len: {len(buf)}", file=sys.stderr)

    # number of bytes for error mask
    # read the size from the env var: FUZZERR_ERROR_MASK_NBITS
    error_mask_nbits = os.getenv("FUZZERR_ERROR_MASK_NBITS")
    if error_mask_nbits is None:
        raise Exception("FUZZERR_ERROR_MASK_NBITS env var is not set")
    nbits = int(error_mask_nbits.strip())
    if nbits % 8 == 0:
        nbytes = nbits // 8
    else:
        nbytes = nbits // 8 + 1

    # next we round nbytes to the neares multiple of 4 (sizeof uint32_t)
    if nbytes % 4 != 0:
        nbytes = nbytes + 4 - (nbytes % 4)

    # in case the inputs is not of sufficient size, just return it, so that it can be discarded in
    # post_process
    if len(buf) <= nbytes:
        if debug_mode and debug_mode == "1":
            print(
                f"(fuzz) lenght of buf ({len(buf)}) was less than nbytes ({nbytes}), hence skipping",
                file=sys.stderr,
            )
        return None
    return buf


# Uncomment and implement the following methods if you want to use a custom
# trimming algorithm. See also the documentation for a better API description.

# def init_trim(buf):
#     '''
#     Called per trimming iteration.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be trimmed.
#
#     @rtype: int
#     @return: The maximum number of trimming steps.
#     '''
#     global ...
#
#     # Initialize global variables
#
#     # Figure out how many trimming steps are possible.
#     # If this is not possible for your trimming, you can
#     # return 1 instead and always return 0 in post_trim
#     # until you are done (then you return 1).
#
#     return steps
#
# def trim():
#     '''
#     Called per trimming iteration.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the trimmed data.
#     '''
#     global ...
#
#     # Implement the actual trimming here
#
#     return bytearray(...)
#
# def post_trim(success):
#     '''
#     Called after each trimming operation.
#
#     @type success: bool
#     @param success: Indicates if the last trim operation was successful.
#
#     @rtype: int
#     @return: The next trim index (0 to max number of steps) where max
#              number of steps indicates the trimming is done.
#     '''
#     global ...
#
#     if not success:
#         # Restore last known successful input, determine next index
#     else:
#         # Just determine the next index, based on what was successfully
#         # removed in the last step
#
#     return next_index


def post_process(buf) -> bytearray | str:
    """
    Called just before the execution to write the test case in the format
    expected by the target

    @type buf: bytearray
    @param buf: The buffer containing the test case to be executed

    @rtype: bytearray
    @return: The buffer containing the test case after
    """
    debug_mode = os.getenv("FUZZERR_DEBUG")
    if debug_mode and debug_mode == "1":
        print(f"afl buf len: {len(buf)}", file=sys.stderr)

    fuzzerr_afl_map_file = os.getenv("FUZZERR_AFL_MAP")
    if fuzzerr_afl_map_file is None:
        raise Exception("FUZZERR_AFL_MAP env var is not set")

    # number of bytes for error mask
    # read the size from the env var: FUZZERR_ERROR_MASK_NBITS
    error_mask_nbits = os.getenv("FUZZERR_ERROR_MASK_NBITS")
    if error_mask_nbits is None:
        raise Exception("FUZZERR_ERROR_MASK_NBITS env var is not set")
    nbits = int(error_mask_nbits.strip())
    if nbits % 8 == 0:
        nbytes = nbits // 8
    else:
        nbytes = nbits // 8 + 1

    # next we round nbytes to the neares multiple of 4 (sizeof uint32_t)
    if nbytes % 4 != 0:
        nbytes = nbytes + 4 - (nbytes % 4)

    # in case the inputs is not of sufficient size, just return it, so that it can be discarded in
    # post_process
    if len(buf) <= nbytes:
        with open(fuzzerr_afl_map_file, "wb") as f:
            f.write(b"\x00" * nbytes)
            if debug_mode and debug_mode == "1":
                print("setting 0 bytes in error mask", file=sys.stderr)

        if debug_mode and debug_mode == "1":
            print(
                f"(post_process) length of buf ({len(buf)}) was less than nbytes ({nbytes}), hence skipping",
                file=sys.stderr,
            )
        return bytearray(b"\x00")

    # tmp - if we have a non-zero mask, print and exit
    if any(b for b in buf[:nbytes]):
        if debug_mode and debug_mode == "1":
            print(f">>>> non-zero error mask! map", file=sys.stderr)
            print(f">>>> map: {buf[:nbytes]}", file=sys.stderr)

    try:
        with open(fuzzerr_afl_map_file, "wb") as f:
            f.write(buf[:nbytes])
            if debug_mode and debug_mode == "1":
                print(f"map: {buf[:nbytes]}", file=sys.stderr)
    except IOError:
        raise Exception(
            f"unable to write error mask to FUZZERR_AFL_MAP file ({fuzzerr_afl_map_file})"
        )

    return buf[nbytes:]


# def havoc_mutation(buf, max_size):
#     '''
#     Perform a single custom mutation on a given input.
#
#     @type buf: bytearray
#     @param buf: The buffer that should be mutated.
#
#     @type max_size: int
#     @param max_size: Maximum size of the mutated output. The mutation must not
#         produce data larger than max_size.
#
#     @rtype: bytearray
#     @return: A new bytearray containing the mutated data
#     '''
#     return mutated_buf
#
# def havoc_mutation_probability():
#     '''
#     Called for each `havoc_mutation`. Return the probability (in percentage)
#     that `havoc_mutation` is called in havoc. Be default it is 6%.
#
#     @rtype: int
#     @return: The probability (0-100)
#     '''
#     return prob
#
# def queue_get(filename):
#     '''
#     Called at the beginning of each fuzz iteration to determine whether the
#     test case should be fuzzed
#
#     @type filename: str
#     @param filename: File name of the test case in the current queue entry
#
#     @rtype: bool
#     @return: Return True if the custom mutator decides to fuzz the test case,
#         and False otherwise
#     '''
#     return True
#
# def queue_new_entry(filename_new_queue, filename_orig_queue):
#     '''
#     Called after adding a new test case to the queue
#
#     @type filename_new_queue: str
#     @param filename_new_queue: File name of the new queue entry
#
#     @type filename_orig_queue: str
#     @param filename_orig_queue: File name of the original queue entry
#     '''
#     pass
