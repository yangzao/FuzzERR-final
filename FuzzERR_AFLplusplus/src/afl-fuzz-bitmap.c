/*
   american fuzzy lop++ - bitmap related routines
   ----------------------------------------------

   Originally written by Michal Zalewski

   Now maintained by Marc Heuse <mh@mh-sec.de>,
                        Heiko Eißfeldt <heiko.eissfeldt@hexco.de> and
                        Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2016, 2017 Google Inc. All rights reserved.
   Copyright 2019-2022 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */

#include "afl-fuzz.h"
#include "debug.h"
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#if !defined NAME_MAX
  #define NAME_MAX _XOPEN_NAME_MAX
#endif


// @shank
static u32 crash_finder_filtered_cnt = 0;
static u32 crash_finder_keeping_cnt = 0;

// @shank
// This function saves the crash_finder_filterd_cnt to
// 'afl->out_dir/crash_finder_counts'.
// first line is crash_finder_filtered_cnt
// second line is crash_finder_keeping_cnt
void save_crash_finder_stats(afl_state_t *afl) {
    FILE *f = NULL;
    u8    fn[PATH_MAX];
    snprintf(fn, PATH_MAX, "%s/crash_finder_stats", afl->out_dir);
    f = create_ffile(fn);

    fprintf(f, "crash_finder_filtered_cnt: %u\n", crash_finder_filtered_cnt);
    fprintf(f, "crash_finder_keeping_cnt: %u\n", crash_finder_keeping_cnt);

    fclose(f);
}

/* Write bitmap to file. The bitmap is useful mostly for the secret
   -B option, to focus a separate fuzzing session on a particular
   interesting input without rediscovering all the others. */

void write_bitmap(afl_state_t *afl) {

  u8  fname[PATH_MAX];
  s32 fd;

  if (!afl->bitmap_changed) { return; }
  afl->bitmap_changed = 0;

  snprintf(fname, PATH_MAX, "%s/fuzz_bitmap", afl->out_dir);
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, DEFAULT_PERMISSION);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_write(fd, afl->virgin_bits, afl->fsrv.map_size, fname);

  close(fd);

}

/* Count the number of bits set in the provided bitmap. Used for the status
   screen several times every second, does not have to be fast. */

u32 count_bits(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This gets called on the inverse, virgin bitmap; optimize for sparse
       data. */

    if (likely(v == 0xffffffff)) {

      ret += 32;
      continue;

    }

    v -= ((v >> 1) & 0x55555555);
    v = (v & 0x33333333) + ((v >> 2) & 0x33333333);
    ret += (((v + (v >> 4)) & 0xF0F0F0F) * 0x01010101) >> 24;

  }

  return ret;

}

/* Count the number of bytes set in the bitmap. Called fairly sporadically,
   mostly to update the status screen or calibrate and examine confirmed
   new paths. */

u32 count_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    if (likely(!v)) { continue; }
    if (v & 0x000000ffU) { ++ret; }
    if (v & 0x0000ff00U) { ++ret; }
    if (v & 0x00ff0000U) { ++ret; }
    if (v & 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Count the number of non-255 bytes set in the bitmap. Used strictly for the
   status screen, several calls per second or so. */

u32 count_non_255_bytes(afl_state_t *afl, u8 *mem) {

  u32 *ptr = (u32 *)mem;
  u32  i = ((afl->fsrv.real_map_size + 3) >> 2);
  u32  ret = 0;

  while (i--) {

    u32 v = *(ptr++);

    /* This is called on the virgin bitmap, so optimize for the most likely
       case. */

    if (likely(v == 0xffffffffU)) { continue; }
    if ((v & 0x000000ffU) != 0x000000ffU) { ++ret; }
    if ((v & 0x0000ff00U) != 0x0000ff00U) { ++ret; }
    if ((v & 0x00ff0000U) != 0x00ff0000U) { ++ret; }
    if ((v & 0xff000000U) != 0xff000000U) { ++ret; }

  }

  return ret;

}

/* Destructively simplify trace by eliminating hit count information
   and replacing it with 0x80 or 0x01 depending on whether the tuple
   is hit or not. Called on every new crash or timeout, should be
   reasonably fast. */
const u8 simplify_lookup[256] = {

    [0] = 1, [1 ... 255] = 128

};

/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

const u8 count_class_lookup8[256] = {

    [0] = 0,
    [1] = 1,
    [2] = 2,
    [3] = 4,
    [4 ... 7] = 8,
    [8 ... 15] = 16,
    [16 ... 31] = 32,
    [32 ... 127] = 64,
    [128 ... 255] = 128

};

u16 count_class_lookup16[65536];

void init_count_class16(void) {

  u32 b1, b2;

  for (b1 = 0; b1 < 256; b1++) {

    for (b2 = 0; b2 < 256; b2++) {

      count_class_lookup16[(b1 << 8) + b2] =
          (count_class_lookup8[b1] << 8) | count_class_lookup8[b2];

    }

  }

}

/* Import coverage processing routines. */

#ifdef WORD_SIZE_64
  #include "coverage-64.h"
#else
  #include "coverage-32.h"
#endif

/* Check if the current execution path brings anything new to the table.
   Update virgin bits to reflect the finds. Returns 1 if the only change is
   the hit-count for a particular tuple; 2 if there are new tuples seen.
   Updates the map, so subsequent calls will always return 0.

   This function is called after every exec() on a fairly large buffer, so
   it needs to be fast. We do this in 32-bit and 64-bit flavors. */

inline u8 has_new_bits(afl_state_t *afl, u8 *virgin_map) {

#ifdef WORD_SIZE_64

  u64 *current = (u64 *)afl->fsrv.trace_bits;
  u64 *virgin = (u64 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 7) >> 3);

#else

  u32 *current = (u32 *)afl->fsrv.trace_bits;
  u32 *virgin = (u32 *)virgin_map;

  u32 i = ((afl->fsrv.real_map_size + 3) >> 2);

#endif                                                     /* ^WORD_SIZE_64 */

  u8 ret = 0;
  while (i--) {

    if (unlikely(*current)) discover_word(&ret, current, virgin);

    current++;
    virgin++;

  }

  if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
    afl->bitmap_changed = 1;

  return ret;

}

/* A combination of classify_counts and has_new_bits. If 0 is returned, then the
 * trace bits are kept as-is. Otherwise, the trace bits are overwritten with
 * classified values.
 *
 * This accelerates the processing: in most cases, no interesting behavior
 * happen, and the trace bits will be discarded soon. This function optimizes
 * for such cases: one-pass scan on trace bits without modifying anything. Only
 * on rare cases it fall backs to the slow path: classify_counts() first, then
 * return has_new_bits(). */

inline u8 has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return has_new_bits(afl, virgin_map);

}

/* Compact trace bytes into a smaller bitmap. We effectively just drop the
   count information here. This is called only sporadically, for some
   new paths. */

void minimize_bits(afl_state_t *afl, u8 *dst, u8 *src) {

  u32 i = 0;

  while (i < afl->fsrv.map_size) {

    if (*(src++)) { dst[i >> 3] |= 1 << (i & 7); }
    ++i;

  }

}

#ifndef SIMPLE_FILES

/* Construct a file name for a new test case, capturing the operation
   that led to its discovery. Returns a ptr to afl->describe_op_buf_256. */

u8 *describe_op(afl_state_t *afl, u8 new_bits, size_t max_description_len) {

  u8 is_timeout = 0;

  if (new_bits & 0xf0) {

    new_bits -= 0x80;
    is_timeout = 1;

  }

  size_t real_max_len =
      MIN(max_description_len, sizeof(afl->describe_op_buf_256));
  u8 *ret = afl->describe_op_buf_256;

  if (unlikely(afl->syncing_party)) {

    sprintf(ret, "sync:%s,src:%06u", afl->syncing_party, afl->syncing_case);

  } else {

    sprintf(ret, "src:%06u", afl->current_entry);

    if (afl->splicing_with >= 0) {

      sprintf(ret + strlen(ret), "+%06d", afl->splicing_with);

    }

    sprintf(ret + strlen(ret), ",time:%llu,execs:%llu",
            get_cur_time() + afl->prev_run_time - afl->start_time,
            afl->fsrv.total_execs);

    if (afl->current_custom_fuzz &&
        afl->current_custom_fuzz->afl_custom_describe) {

      /* We are currently in a custom mutator that supports afl_custom_describe,
       * use it! */

      size_t len_current = strlen(ret);
      ret[len_current++] = ',';
      ret[len_current] = '\0';

      ssize_t size_left = real_max_len - len_current - strlen(",+cov") - 2;
      if (is_timeout) { size_left -= strlen(",+tout"); }
      if (unlikely(size_left <= 0)) FATAL("filename got too long");

      const char *custom_description =
          afl->current_custom_fuzz->afl_custom_describe(
              afl->current_custom_fuzz->data, size_left);
      if (!custom_description || !custom_description[0]) {

        DEBUGF("Error getting a description from afl_custom_describe");
        /* Take the stage name as description fallback */
        sprintf(ret + len_current, "op:%s", afl->stage_short);

      } else {

        /* We got a proper custom description, use it */
        strncat(ret + len_current, custom_description, size_left);

      }

    } else {

      /* Normal testcase descriptions start here */
      sprintf(ret + strlen(ret), ",op:%s", afl->stage_short);

      if (afl->stage_cur_byte >= 0) {

        sprintf(ret + strlen(ret), ",pos:%d", afl->stage_cur_byte);

        if (afl->stage_val_type != STAGE_VAL_NONE) {

          sprintf(ret + strlen(ret), ",val:%s%+d",
                  (afl->stage_val_type == STAGE_VAL_BE) ? "be:" : "",
                  afl->stage_cur_val);

        }

      } else {

        sprintf(ret + strlen(ret), ",rep:%d", afl->stage_cur_val);

      }

    }

  }

  if (is_timeout) { strcat(ret, ",+tout"); }

  if (new_bits == 2) { strcat(ret, ",+cov"); }

  if (unlikely(strlen(ret) >= max_description_len))
    FATAL("describe string is too long");

  return ret;

}

#endif                                                     /* !SIMPLE_FILES */

/* Write a message accompanying the crash directory :-) */

void write_crash_readme(afl_state_t *afl) {

  u8    fn[PATH_MAX];
  s32   fd;
  FILE *f;

  u8 val_buf[STRINGIFY_VAL_SIZE_MAX];

  sprintf(fn, "%s/crashes/README.txt", afl->out_dir);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);

  /* Do not die on errors here - that would be impolite. */

  if (unlikely(fd < 0)) { return; }

  f = fdopen(fd, "w");

  if (unlikely(!f)) {

    close(fd);
    return;

  }

  fprintf(
      f,
      "Command line used to find this crash:\n\n"

      "%s\n\n"

      "If you can't reproduce a bug outside of afl-fuzz, be sure to set the "
      "same\n"
      "memory limit. The limit used for this fuzzing session was %s.\n\n"

      "Need a tool to minimize test cases before investigating the crashes or "
      "sending\n"
      "them to a vendor? Check out the afl-tmin that comes with the fuzzer!\n\n"

      "Found any cool bugs in open-source tools using afl-fuzz? If yes, please "
      "post\n"
      "to https://github.com/AFLplusplus/AFLplusplus/issues/286 once the "
      "issues\n"
      " are fixed :)\n\n",

      afl->orig_cmdline,
      stringify_mem_size(val_buf, sizeof(val_buf),
                         afl->fsrv.mem_limit << 20));      /* ignore errors */

  fclose(f);

}

/// @shank
/// TODO: shank: later: this should be read from some environment variable
static const char *CRASH_FINDER_PATH = "$HOME/code/research/FuzzERR/scripts/fuzzerr/crash_finder.py";
static const char *CRASH_MINIMIZER_PATH = "$HOME/code/research/FuzzERR/scripts/fuzzerr/crash_minimizer.py";
static char *MINIMIZED_ERROR_MASK_FILE = NULL;
static char *MINIMIZER_STATS_FILE = NULL;

/// @shank
enum CrashFinderEC{
    CrashFinderEC_IMPOSSIBLE = 0,
    CrashFinderEC_INVALID_ARGS,
    CrashFinderEC_SRC_PATH_NOT_PROVIDED,
    CrashFinderEC_CRASH_IN_PROGRAM,
    CrashFinderEC_CRASH_IN_LIBRARY,
    CrashFinderEC_SRC_PATH_NOT_IN_BACKTRACE
};


/// @shank
/// crash_minimizer --prog_path=<prog_path>> --mask_path=<error_mask> --args=<input1>,<input2>..
char *_create_crash_minimizer_cmd(afl_state_t *afl){
    // if(afl->debug){ printf(">>>> %s(): afl->argv: %s\n", __func__, *afl->argv); }
    int argc = 0;
    while(afl->argv[argc]){
        argc++;
    }

    char *prog_bin = afl->argv[0];
    char *error_mask_file = afl->fsrv.out_file;
    assert(error_mask_file != NULL);
    assert(MINIMIZER_STATS_FILE != NULL);

    // calculate the length of the malloced chunk for this cmd
    size_t cmd_len = 0;
    cmd_len += strlen(CRASH_MINIMIZER_PATH) + 1;
    cmd_len += strlen("--prog_path=");
    cmd_len += strlen(prog_bin) + 1;
    cmd_len += strlen("--mask_path=");
    cmd_len += strlen(error_mask_file) + 1;
    cmd_len += strlen("--args=");
    for (int i = 1; i < argc; i++){
        cmd_len += strlen(afl->argv[i]) + 1;
    }
    cmd_len += strlen("--stats_file=");
    cmd_len += strlen(MINIMIZER_STATS_FILE) + 1;
    if(!afl->debug){
        // suppress stdout and stderr
        cmd_len += strlen(">/dev/null 2>/dev/null") + 1;
    }
    // if(afl->debug){ printf(">>>> %s(): cmd_len: %zu\n", __func__, cmd_len);}

    // construct the cmd string and return
    char *cmd = (char *)calloc(cmd_len, sizeof(char));
    if(cmd == NULL){
        FATAL("%s(): unable to allocate buffer for crash_minimizer command", __func__);
    }
    cmd = strcat(cmd, CRASH_MINIMIZER_PATH);;
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--prog_path=");
    cmd = strcat(cmd, prog_bin);
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--mask_path=");
    cmd = strcat(cmd, error_mask_file);
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--args=");
    for (int i = 1; i < argc; i++){
        cmd = strcat(cmd, afl->argv[i]);
        if(i != argc-1){
            cmd = strcat(cmd, ",");
        }
    }
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--stats_file=");
    cmd = strcat(cmd, MINIMIZER_STATS_FILE);
    if(!afl->debug){
        // suppress stdout and stderr
        cmd = strcat(cmd, " >/dev/null 2>/dev/null");
    }

    if(afl->debug){
        // printf(">>>> %s(): final cmd length: %zu\n", __func__, strlen(cmd));
        printf(">>>> %s(): cmd: %s\n", __func__, cmd);
    }

    return cmd;
}


/// create the command line for the crash_finder.py
/// using the infomation available in `afl`
///
/// crash_finder.py --prog_path=<bin> --mask_path=<error_mask> --args=<input1>,<input2>..
///
/// FUZZERR_BIN_SRC_PATH should have already been set inside environment variable
///
/// NOTE: the (char *) returned by this function should be freed by the caller
/// @shank
char *_create_crash_finder_cmd(afl_state_t *afl, bool enable_backtrace, const u8* custom_error_mask_file){
    // required:
    // [x] binary : afl->argv[0]
    // [x] args if any : afl->argv[1]...
    // [x] error mask : afl->fsrv.out_file

    // if(afl->debug){
    //     printf(">>>> %s(): afl->argv: %s\n", __func__, *afl->argv);
    //     printf(">>>> %s(): afl->fsrv->target_path: %s\n", __func__, afl->fsrv.target_path);
    // }

    int argc = 0;
    while(afl->argv[argc]){
        argc++;
    }

    char *prog_bin = afl->fsrv.target_path;
    const char *error_mask_file = NULL;
    if(custom_error_mask_file){
        error_mask_file = custom_error_mask_file;
    } else {
        error_mask_file = afl->fsrv.out_file;
    }
    assert(error_mask_file != NULL);

    // calculate the length of the malloced chunk for this cmd
    size_t cmd_len = 0;
    cmd_len += strlen(CRASH_FINDER_PATH) + 1;
    cmd_len += strlen("--prog_path=");
    cmd_len += strlen(prog_bin) + 1;
    cmd_len += strlen("--mask_path=");
    cmd_len += strlen(error_mask_file) + 1;
    cmd_len += strlen("--args=");
    for (int i = 1; i < argc; i++){
        cmd_len += strlen(afl->argv[i]) + 1;
    }
    if(enable_backtrace){
        cmd_len += strlen("--enable-backtrace") + 1;
    }
    if(!afl->debug){
        // suppress stdout and stderr
        cmd_len += strlen(">/dev/null 2>/dev/null") + 1;
    }
    // if(afl->debug){ printf(">>>> %s(): cmd_len: %zu\n", __func__, cmd_len); }

    // construct the cmd string and return
    char *cmd = (char *)calloc(cmd_len + 1, sizeof(char));
    if(cmd == NULL){
        FATAL("_create_crash_finder_cmd(): unable to allocate buffer for crash_finder command");
    }
    cmd = strcat(cmd, CRASH_FINDER_PATH);;
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--prog_path=");
    cmd = strcat(cmd, prog_bin);
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--mask_path=");
    cmd = strcat(cmd, error_mask_file);
    cmd = strcat(cmd, " ");
    cmd = strcat(cmd, "--args=");
    for (int i = 1; i < argc; i++){
        cmd = strcat(cmd, afl->argv[i]);
        if(i != argc-1){
            cmd = strcat(cmd, ",");
        }
    }
    if(enable_backtrace){
        cmd = strcat(cmd, " ");
        cmd = strcat(cmd, "--enable-backtrace");
    }
    if(!afl->debug){
        // suppress stdout and stderr
        cmd = strcat(cmd, " >/dev/null 2>/dev/null");
    }

    if(afl->debug){
        // printf(">>>> %s(): final cmd length: %zu\n", __func__, strlen(cmd));
        printf(">>>> %s(): cmd: %s\n", __func__, cmd);
    }

    return cmd;
}


/// @shank
/// custom_error_mask -> minimized error mask to run the crash_finder with
///
/// returns: u8: exit code of the crash_finder
u8 run_crash_finder(afl_state_t *afl, bool enable_backtrace, const char *custom_error_mask){
    char *crash_finder_cmd = _create_crash_finder_cmd(afl, enable_backtrace, custom_error_mask);
    int status = system(crash_finder_cmd);
    free(crash_finder_cmd);
    status /= 256;
    // if(afl->debug){ printf(">>>> %s(): crash_finder exit code status: %d\n", __func__, status); }
    return status;
}


/// @shank
///
/// returns: u8*: path to the minimized error mask file
/// this would be: /tmp/fuzzerr_minimized_error_mask
const char *run_crash_minimizer(afl_state_t *afl){
    // - create the command line for crash minimizer
    char *crash_minimizer_cmd = _create_crash_minimizer_cmd(afl);
    int status = system(crash_minimizer_cmd);
    free(crash_minimizer_cmd);

    status /= 256;
    if(afl->debug) { printf(">>>> %s(): crash_minimizer exit code status: %d\n", __func__, status); }
    if(status == 0){
        // - if the crash_minimizer exits successfully, then $FUZZERR_AFL_MAP_minimized
        // would be the minimized mask
        return MINIMIZED_ERROR_MASK_FILE;
    }else{
        // - if the crash_minimizer doesnt exit successfully, return NULL
        return NULL;
    }
}


// @shank
/// uses crash_finder with minimized error mask to decide whether the error was in library or in the
/// program
/// returns 1 if the crash is to be saved (crash was in program) and 0 if its to be discarded (crash
/// was in library)
u8 decide_via_crash_finder_with_minimized_mask(afl_state_t *afl, const char *minimized_error_mask){
    //      - run crash_finder with backtrace_enabled using this minimized mask
    u8 status = run_crash_finder(afl, true, minimized_error_mask);

    switch(status){
        case CrashFinderEC_IMPOSSIBLE:
            WARNF("CrashFinder with minimized mask (exit code: %d) - unexpected exit [discarding the mask]\n", status);
            return 0;

        case CrashFinderEC_INVALID_ARGS:
            FATAL("CrashFinder with minimized mask (exit code: %d) - invalid args\n", status);

        case CrashFinderEC_SRC_PATH_NOT_PROVIDED:
            FATAL("CrashFinder with minimized mask (exit code: %d) - SRC_PATH not provided\n", status);

        case CrashFinderEC_CRASH_IN_PROGRAM:
            // - if crash is in program, handle it as the case above
            if(afl->debug){
                SAYF("CrashFinder with minimized mask (exit code: %d) - crash in program [recommending to keep the mask]\n", status);
            }
            return 1;

        case CrashFinderEC_CRASH_IN_LIBRARY:
            // - if crash is in program, handle it as the case above
            if(afl->debug){
                SAYF("CrashFinder with minimized mask (exit code: %d) - crash in library [discarding the mask]\n", status);
            }
            return 0;

        case CrashFinderEC_SRC_PATH_NOT_IN_BACKTRACE:
            FATAL("CrashFinder (exit code: %d) - SRC_PATH_NOT_IN_BACKTRACE\n", status);

        default:
            WARNF("unknown CrashFinder exit code (with minimized mask): %d [discarding the mask]\n", status);
            return 0;
    }
}

// @shank
/// uses crash_finder with backtrace enabled to decide whether the error was in library or in the
/// program
/// returns 1 if the crash is to be saved (crash was in program) and 0 if its to be discarded (crash
/// was in library)
u8 decide_via_crash_finder_with_backtrace(afl_state_t *afl){
    u8 status = run_crash_finder(afl, true, NULL);

    switch (status) {
        case CrashFinderEC_IMPOSSIBLE:
            FATAL("CrashFinder with backtrace (exit code: %d) - unexpected exit (PLEASE INVESTIGATE)\n", status);

        case CrashFinderEC_INVALID_ARGS:
            FATAL("CrashFinder with backtrace (exit code: %d) - invalid args\n", status);

        case CrashFinderEC_SRC_PATH_NOT_PROVIDED:
            FATAL("CrashFinder with backtrace (exit code: %d) - SRC_PATH not provided\n", status);

        case CrashFinderEC_CRASH_IN_PROGRAM:
            if(afl->debug){
                SAYF("CrashFinder with backtrace (exit code: %d) - crash in program [recommending to keep the mask]\n", status);
            }
            return 1;

        case CrashFinderEC_CRASH_IN_LIBRARY:
            if(afl->debug){
                SAYF("CrashFinder with backtrace (exit code: %d) - crash in library\n", status);
            }
            return 0;

        case CrashFinderEC_SRC_PATH_NOT_IN_BACKTRACE:
            FATAL("CrashFinder (exit code: %d) - SRC_PATH_NOT_IN_BACKTRACE\n", status);

        default:
            WARNF("unknown CrashFinder exit code (with backtrace): %d\n", status);
            return 0;
    }
}

// @shank
/// uses crash_finder to take the call on whether the error was in library or in the program
/// returns 1 if the crash is to be saved and 0 if its to be discarded
u8 decide_via_crash_finder(afl_state_t *afl){
    if(afl->debug){
        printf(">>>> %s(): run_crash_finder without backtrace\n", __func__);
        fflush(stdout);
    }

    // set MINIMIZED_ERROR_MASK_FILE path, if required
    // this is only required to be set once, since this will remain the same
    // for a particular run of afl-fuzz
    if(!MINIMIZED_ERROR_MASK_FILE){
        // ensure that we have the FUZZERR_AFL_MAP env var set
        char *fuzzerr_afl_map = getenv("FUZZERR_AFL_MAP");
        if(!fuzzerr_afl_map){
            FATAL("[!] FUZZERR_AFL_MAP env var not set");
        }
        // allocate buffer for MINIMIZED_ERROR_MASK_FILE
        MINIMIZED_ERROR_MASK_FILE = calloc(strlen(fuzzerr_afl_map) + strlen("_minimized") + 1, sizeof(char));
        strcat(MINIMIZED_ERROR_MASK_FILE, fuzzerr_afl_map);
        strcat(MINIMIZED_ERROR_MASK_FILE, "_minimized");
        if(afl->debug){
            printf(">>>> %s(): MINIMIZED_ERROR_MASK_FILE path is: %s\n", __func__, MINIMIZED_ERROR_MASK_FILE);
            fflush(stdout);
        }
    }

    // set MINIMIZER_STATS_FILE path, if required
    // this is only required to be set once, since this will remain the same
    // for a particular run of afl-fuzz
    if(!MINIMIZER_STATS_FILE){
        // allocate buffer for MINIMIZER_STATS_FILE
        uint32_t char_count = strlen(afl->out_dir) + 1 + strlen("crash_minimizer_stats") + 1;
        MINIMIZER_STATS_FILE = calloc(char_count, sizeof(char));
        snprintf(MINIMIZER_STATS_FILE, char_count, "%s/crash_minimizer_stats", afl->out_dir);
        if(afl->debug){
            printf(">>>> %s(): MINIMIZER_STATS_FILE path is: %s\n", __func__, MINIMIZER_STATS_FILE);
            fflush(stdout);
        }
    }


    // crash_finder without backtrace
    u8 status = run_crash_finder(afl, false, NULL);

    // if(afl->debug){
    //     printf(">>>> %s(): run_crash_finder status: %d\n", __func__, status);
    //     fflush(stdout);
    // }

    //     take action, based on the exit code
    //
    // fuzzerr > crash_finder.py
    // Exit Codes (see class ExitCode below):
    //     IMPOSSIBLE = 0 -> log warning about unexpected exit code, keep input
    //     INVALID_ARGS = 1 -> abort!
    //     SRC_PATH_NOT_PROVIDED = 2 -> abort!
    //     CRASH_IN_PROGRAM = 3  -> log info about crash in program, keep input
    //     CRASH_IN_LIBRARY = 4 -> phase II
    //     default -> log warning about unknown exit code, keep input
    switch(status){
        case CrashFinderEC_IMPOSSIBLE:
            FATAL("CrashFinder (exit code: %d) - unexpected exit (PLEASE INVESTIGATE)\n", status);

        case CrashFinderEC_INVALID_ARGS:
            FATAL("CrashFinder (exit code: %d) - invalid args\n", status);

        case CrashFinderEC_SRC_PATH_NOT_PROVIDED:
            FATAL("CrashFinder (exit code: %d) - SRC_PATH not provided\n", status);

        case CrashFinderEC_CRASH_IN_PROGRAM:
            if(afl->debug){
                SAYF("CrashFinder (exit code: %d) - crash in program [recommending to keep the mask]\n", status);
            }
            return 1;

        case CrashFinderEC_CRASH_IN_LIBRARY:
            if(afl->debug){
                SAYF("CrashFinder (exit code: %d) - crash in library\n", status);
            }
            // since the crash was in library, do the following:
            // - run with backtrace enabled and check the return code
            // - if crash is in program, handle it as the case above
            // - if crash is again in library,
            //      - invoke crash minimizer to minimize the error_mask
            //      - run crash_finder with backtrace_enabled using this minimized mask
            //      - take the final call based on the result

            if(afl->debug){
                printf(">>>> %s(): running crash_finder again with backtrace, as crash was in library\n", __func__);
                fflush(stdout);
            }

            // - run with backtrace enabled and check the return code
            // result will be 1 if crash was in program
            // and 0 if crash was in library
            u8 result = decide_via_crash_finder_with_backtrace(afl);

            if (result == 1){
                // crash in program, keep it
                return 1;

            }else {
                // crash in library
                // use crash_minimizer and further steps...

                if(afl->debug){
                    printf(">>>> %s(): running crash_minimizer\n", __func__);
                    fflush(stdout);
                }

                // - if crash is again in library,
                //      - invoke crash minimizer to minimize the error_mask
                //      - run crash_finder with backtrace_enabled using this minimized mask
                //      - take the final call based on the result

                //      - invoke crash minimizer to minimize the error_mask
                const char *minimized_error_mask = run_crash_minimizer(afl);
                if (!minimized_error_mask){
                    WARNF("decide_via_crash_finder(): unable to get the minimized_error_mask (PLEASE INSPECT) [discarding the mask]\n");
                    return 0;
                }

                if(afl->debug){
                    printf(">>>> %s(): running crash_finder with minimzed error mask\n", __func__);
                    fflush(stdout);
                }

                result = decide_via_crash_finder_with_minimized_mask(afl, minimized_error_mask);
                return result;
            }

        case CrashFinderEC_SRC_PATH_NOT_IN_BACKTRACE:
            FATAL("CrashFinder (exit code: %d) - SRC_PATH_NOT_IN_BACKTRACE\n", status);

        default:
            WARNF("unknown CrashFinder exit code: %d [discarding the mask]\n", status);
            return 0;
    }
}


/* Check if the result of an execve() during routine fuzzing is interesting,
   save or queue the input test case for further analysis if so. Returns 1 if
   entry is saved, 0 otherwise. */

u8 __attribute__((hot))
save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {
    if(afl->debug && fault == 2){
        printf(">>>> %s(): fault: %d\n", __func__, fault);
    }

  if (unlikely(len == 0)) { return 0; }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, is_timeout = 0;
  s32 fd;
  u64 cksum = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF)
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  if (likely(fault == afl->crash_mode)) {
        // if(afl->debug){ printf(">>>> %s() > fault == afl->crash_mode\n", __func__); }

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */

    new_bits = has_new_bits_unclassified(afl, afl->virgin_bits);

    if (likely(!new_bits)) {

      if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
      return 0;

    }

    classified = new_bits;

  save_to_queue:

#ifndef SIMPLE_FILES

    queue_fn =
        alloc_printf("%s/queue/id:%06u,%s", afl->out_dir, afl->queued_items,
                     describe_op(afl, new_bits + is_timeout,
                                 NAME_MAX - strlen("id:000000,")));

#else

    queue_fn =
        alloc_printf("%s/queue/id_%06u", afl->out_dir, afl->queued_items);

#endif                                                    /* ^!SIMPLE_FILES */
    fd = open(queue_fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", queue_fn); }
    ck_write(fd, mem, len, queue_fn);
    close(fd);
    add_to_queue(afl, queue_fn, len, 0);

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    /* AFLFast schedule? update the new queue entry */
    if (cksum) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* due to classify counts we have to recalculate the checksum */
    afl->queue_top->exec_cksum =
        hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    // @shank
    if(afl->debug){
        printf(">>>> %s(): calling calibrate_case() >>>>\n", __func__);
        fflush(stdout);
    }

    res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);

    // @shank
    if(afl->debug){
        printf(">>>> %s(): done with calibrate_case() <<<<\n", __func__);
        fflush(stdout);
    }

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8  new_fault;
        u32 tmp_len = write_to_testcase(afl, &mem, len, 0);

        if (likely(tmp_len)) {

          len = tmp_len;

        } else {

          len = write_to_testcase(afl, &mem, len, 1);

        }

        new_fault = fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s", afl->out_dir,
               afl->saved_hangs,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,")));

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu", afl->out_dir,
               afl->saved_hangs);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

        // @shank
        // NOTE: shank: we can run CrashFinder here and if the crash is
        // occuring in library, just return 'keeping' (0)
        //
        // if CRASH_FINDER_DISABLE is set, then we don't run crashfinder
        char *crash_finder_disable = getenv("FUZZERR_DISABLE_CRASH_FINDER");
        if(!(crash_finder_disable && crash_finder_disable[0] == '1')){
            keeping = decide_via_crash_finder(afl);
            if (keeping == 1){
                crash_finder_keeping_cnt++;

                if(afl->debug){
                    printf(">>>> %s(): crash_finder decided to keep crash\n", __func__);
                    fflush(stdout);
                }

            } else {
                // crash_finder said that this is not interesting, so skip it
                crash_finder_filtered_cnt++;
                // return 0;
            }
            save_crash_finder_stats(afl);
        } else {
            if(afl->debug){
                SAYF(">>>> %s(): crash_finder disabled\n", __func__);
            }
        }


      if (likely(!afl->non_instrumented_mode)) {

        if (!classified) { classify_counts(&afl->fsrv); }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

    // @shank
    // if we reach here with keeping==0, then crash_finder decided to skip this crash
    // so we should return now, and not save it
    if(!(crash_finder_disable && crash_finder_disable[0] == '1')){
        if(keeping == 0){
            return keeping;
        }
    }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")));

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal);

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;

    // @shank
    if(afl->debug){
        printf(">>>> %s(): afl saved the crash (afl->saved_crashes: %llu) to file: %s\n", __func__, afl->saved_crashes, fn);
        fflush(stdout);
    }

#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
  if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn); }
  ck_write(fd, mem, len, fn);
  close(fd);

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string, 0x1000);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

    if(afl->debug){
        printf(">>>> %s() > returning keeping=%d\n", __func__, keeping);
        fflush(stdout);
    }
  return keeping;

}

