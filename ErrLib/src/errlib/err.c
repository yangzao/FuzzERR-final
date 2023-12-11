#include "../../include/errlib/err.h"
#include "common.h"
#include <assert.h>
#include <stdio.h>

/// flag to avoid executing get_bit if the constructor itself hasn't run yet
bool ctor_executed = false;

/// will be called from the library constructor so as to record the number of
/// valid mask counts required. This information shall be used later on to
/// initilize the error mask
void init_valid_mask_count(uint32_t count) {
    VALID_MASK_COUNT = count;

    if (VALID_MASK_COUNT % 32 == 0) {
        INPUT_NUM_COUNT = VALID_MASK_COUNT / 32;
    } else {
        INPUT_NUM_COUNT = VALID_MASK_COUNT / 32 + 1;
    }

    char *fuzzerr_debug = getenv("FUZZERR_DEBUG");
    if (fuzzerr_debug) {
        DEBUG_MODE = true;
        printf(">> DEBUG MODE ON\n");
        fflush(stdout);
    }

    char *fuzzerr_dry_run = getenv("FUZZERR_DRY_RUN");
    if (fuzzerr_dry_run && fuzzerr_dry_run[0] == '1') {
        DRY_RUN_MODE = true;
        printf(">> DRY RUN MODE ON\n");
        fflush(stdout);

        // check that FUZZERR_DRY_RUN_RESULT is set
        fuzzerr_dry_run_result_path = getenv("FUZZERR_DRY_RUN_RESULT");
        if (!fuzzerr_dry_run_result_path) {
            printf(">> ERROR: FUZZERR_DRY_RUN_RESULT is not set\n");
            fflush(stdout);
            exit(EXIT_FAILURE);
        }
    }

    // set the signal handler so that the program ends in a limited time
    char *fuzzerr_crash_minimizer_run = getenv("FUZZERR_CRASH_MINIMIZER_RUN");
    char *fuzzerr_crash_finder_run = getenv("FUZZERR_CRASH_FINDER_RUN");
    if ((fuzzerr_crash_minimizer_run && fuzzerr_crash_minimizer_run[0] == '1') ||
        (fuzzerr_crash_finder_run && fuzzerr_crash_finder_run[0] == '1') ||
        (fuzzerr_dry_run && fuzzerr_dry_run[0] == '1')) {

        char *fuzzerr_timeout_in_sec = getenv("FUZZERR_TIMEOUT_IN_SEC");
        if (fuzzerr_timeout_in_sec != NULL) {
            // install the signal handler for SIGALRM
            struct sigaction sa;
            sa.sa_handler = fuzzerr_sigalrm_handler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = 0;
            if (sigaction(SIGALRM, &sa, NULL) == -1) {
                perror("sigaction");
                exit(1);
            }

            printf(">> Set SIGALRM handler and timer for TIMEOUT: %s seconds\n",
                   fuzzerr_timeout_in_sec);
            fflush(stdout);

            // set the alarm
            alarm(atoi(fuzzerr_timeout_in_sec));

        } else {
            printf(">> FUZZERR_TIMEOUT_IN_SEC is not set, wont force exit the program\n");
            fflush(stdout);
        }
    }

    char *fuzzerr_enable_backtrace = getenv("FUZZERR_ENABLE_BACKTRACE");
    if (fuzzerr_enable_backtrace) {
        ENABLE_BACKTRACE = true;
    }

    char *fuzzerr_signal_handler = getenv("FUZZERR_SIGNAL_HANDLER");
    if (fuzzerr_signal_handler) {
        install_signal_handler();
    }

    if (DEBUG_MODE) {
        printf("initialized valid mask count...\n");
    }

    if (DEBUG_MODE) {
        printf("VALID_MASK_COUNT as per FIP: %zu\n", VALID_MASK_COUNT);
        printf("INPUT_NUM_COUNT as per FIP: %d\n", INPUT_NUM_COUNT);
    }

    ctor_executed = true;
}

/// will be called from the library destructor so as to record the number of actual
/// get_bit() calls made. This information shall be used later on for creating the
/// error mask during fuzzing
/// NOTE: this function is only useful if FUZZERR_DRY_RUN env variable is set
void save_total_get_bit_call_count() {
    if (!DRY_RUN_MODE) {
        return;
    }

    in_dtor = true;

    if (DEBUG_MODE) {
        printf("saving total get_bit call count: %zu\n", TOTAL_GET_BIT_CALL_COUNT);
        fflush(stdout);
    }

    FILE *fp = fopen(fuzzerr_dry_run_result_path, "w");
    if (!fp) {
        printf(">> ERROR: could not open file %s for writing\n", fuzzerr_dry_run_result_path);
        fflush(stdout);
        exit(EXIT_FAILURE);
    }
    fprintf(fp, "%zu", TOTAL_GET_BIT_CALL_COUNT);
    fclose(fp);

    in_dtor = false;
}

/// returns the corresponding bit from the ERROR_MASK
int fuzzerr_get_bit(int flag_id, enum Heuristic hid, enum Level level) {
    // early return in case the constructor has not been run yet
    if (!ctor_executed) {
        return 0;
    }

    // early return in case we are in the destructor
    if (in_dtor) {
        return 0;
    }

    // early return in case we already are in get_bit() before the current call
    if (in_get_bit) {
        return 0;
    }

    // early return if disabled flag is set
    if (disabled) {
        return 0;
    }

    // early return if in backtrace
    if (in_save_backtrace) {
        return 0;
    }

    // flag that we are in get_bit() now
    in_get_bit = true;

    // initialize the error mask in case its not initialized yet
    if (!is_mask_initialized) {
        init_error_mask();
    }

    // printf("inside get_bit(): flag_id=%d\n", flag_id);

    // flush stdout so that the different calls dont appear interleaved
    fflush(stdout);

    // verify that the user isnt asking beyong the valid index
    // assert(flag_id < VALID_MASK_COUNT);

    // get the bit at the current idx from the ERROR_MASK
    int val = get_bit_at_current_idx();

    // increment the total get_bit() call count
    TOTAL_GET_BIT_CALL_COUNT++;

    // bypass non-inner checks (outer/default)
    if (ONLY_INNER && level != Inner) {
        val = 0;
        // if (DEBUG_MODE) {
        //     // printf("get_bit(): bypassing as level is not inner\n");
        //     printf("get_bit(): returning %d for current_idx %zu (effective idx %zu), mask_id %d,
        //     "
        //            "having hid %d (%s) [bypassing as level is not inner]\n",
        //            val, (CURRENT_IDX - 1), (EFFECTIVE_CURRENT_IDX - 1), flag_id, hid,
        //            lib_fn_name);
        //     fflush(stdout);
        // }
    }

    // bypass disabled ids
    for (uint32_t i = 0; i < VALID_DISABLED_IDS_COUNT; i++) {
        if (DISABLED_IDS[i] == CURRENT_IDX - 1) {
            if (DEBUG_MODE) {
                printf("get_bit(): bypassing as current_idx %lu is disabled\n", CURRENT_IDX - 1);
            }
            val = 0;
            break;
        }
    }

    // bypass disabled heuristics
    for (uint32_t i = 0; i < VALID_DISABLED_HEURISTICS_COUNT; i++) {
        if (DISABLED_HEURISTICS[i] == hid) {
            if (DEBUG_MODE) {
                printf("get_bit(): bypassing as heuristic %d is disabled\n", hid);
            }
            val = 0;
            break;
        }
    }

    // if we are returning 1, and ENABLE_BACKTRACE is set, save the backtrace
    if (val == 1 && ENABLE_BACKTRACE) {
        save_backtrace();
    }

    // flush stdout so that the different calls dont appear interleaved
    fflush(stdout);

    if ((DEBUG_MODE || ENABLE_BACKTRACE) && val == 1) {
        // use CURRENT_IDX-1 while printing because the idx would have been increased
        // as a result of call to get_bit_at_current_idx()
        printf("get_bit(): returning %d for current_idx %zu (effective idx %zu), mask_id %d, "
               "having hid %d (%s)\n",
               val, (CURRENT_IDX - 1), (EFFECTIVE_CURRENT_IDX - 1), flag_id, hid, lib_fn_name);
        fflush(stdout);
    }

    // flag that we are not in get_bit() anymore
    in_get_bit = false;

    return val;
}
