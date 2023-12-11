#define _GNU_SOURCE
#include <dlfcn.h>

#ifndef ERRLIB_COMMON_H
#define ERRLIB_COMMON_H

#include "../../include/errlib/err.h"
#include <signal.h>
#include <stdbool.h>

// https://stackoverflow.com/a/45238104/947472
/* --- PRINTF_BYTE_TO_BINARY macro's --- */
#define BYTE_TO_BINARY_PATTERN "%c%c%c%c%c%c%c%c"
#define BYTE_TO_BINARY(byte)                                                                       \
    (byte & 0x80 ? '1' : '0'), (byte & 0x40 ? '1' : '0'), (byte & 0x20 ? '1' : '0'),               \
        (byte & 0x10 ? '1' : '0'), (byte & 0x08 ? '1' : '0'), (byte & 0x04 ? '1' : '0'),           \
        (byte & 0x02 ? '1' : '0'), (byte & 0x01 ? '1' : '0')
/* --- end macros --- */

#define MASK_ARR_LEN 8192
#define MAX_LINE_LENGTH 20

extern size_t VALID_MASK_COUNT;
extern uint32_t INPUT_NUM_COUNT; // should be = (VALID_MASK_COUNT / 32)

// debug mode?
extern bool DEBUG_MODE;

// dry run mode?
extern bool DRY_RUN_MODE;
// dry run mode: total get_bit() calls
extern size_t TOTAL_GET_BIT_CALL_COUNT;
// dry run mode: path to save get_bit() call count
extern char *fuzzerr_dry_run_result_path;

// save backtrace?
extern bool ENABLE_BACKTRACE;

// only inner?
extern bool ONLY_INNER;

extern uint32_t ERROR_MASK[MASK_ARR_LEN];

// the index which would be used to return the current value of the
// get_bit()
extern size_t CURRENT_IDX;
extern size_t EFFECTIVE_CURRENT_IDX;
extern size_t MAX_CURRENT_IDX;

// disable idx
#define MAX_DISABLED_IDS 100
extern uint32_t DISABLED_IDS[MAX_DISABLED_IDS];
extern size_t VALID_DISABLED_IDS_COUNT;

// disable heuristics
#define MAX_DISABLED_HEURISTICS 100
extern uint32_t DISABLED_HEURISTICS[MAX_DISABLED_HEURISTICS];
extern size_t VALID_DISABLED_HEURISTICS_COUNT;

/// has the error mask been initialized?
extern bool is_mask_initialized;

/// flag to avoid going in an infinite loop
extern bool in_get_bit;

/// flag to avoid going in an infinite loop in destructor
extern bool in_dtor;

/// flag to indicate that we are already in a backtrace
extern bool in_save_backtrace;

/// flag to indicate that the injection has been disabled temporarily
extern volatile bool disabled;

/// first lib fn to be called
#define MAX_FN_NAME_LEN 100
extern char lib_fn_name[MAX_FN_NAME_LEN];

/// initialize the error mask
void init_error_mask();

/// get the bit at the current idx from the ERROR_MASK
int get_bit_at_current_idx();

/// save the backtrace
void save_backtrace();

/// install signal handler for comparing backtrace
void install_signal_handler();

/// signal handler for SIGALRM
void fuzzerr_sigalrm_handler(int signum);

static uint8_t alternate_stack[8192];

#endif /* ERRLIB_COMMON_H */
