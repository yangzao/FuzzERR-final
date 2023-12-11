#include "common.h"
#include "demangle.h"
#include <assert.h>
#include <backtrace.h>
#include <bits/types/sigset_t.h>
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define ANSI_RESET_ALL "\x1b[0m"
#define ANSI_COLOR_BLACK "\x1b[30m"
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\x1b[33m"
#define ANSI_COLOR_BLUE "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN "\x1b[36m"
#define ANSI_COLOR_WHITE "\x1b[37m"
#define ANSI_STYLE_BOLD "\x1b[1m"
#define ANSI_STYLE_ITALIC "\x1b[3m"
#define ANSI_STYLE_UNDERLINE "\x1b[4m"

bool DEBUG_MODE = false;
bool ENABLE_BACKTRACE = false;
bool ONLY_INNER = false;
size_t VALID_MASK_COUNT;
uint32_t INPUT_NUM_COUNT; // should be = (VALID_MASK_COUNT / 32)
uint32_t ERROR_MASK[MASK_ARR_LEN];
uint32_t DISABLED_IDS[MAX_DISABLED_IDS];
size_t VALID_DISABLED_IDS_COUNT;
uint32_t DISABLED_HEURISTICS[MAX_DISABLED_HEURISTICS];
size_t VALID_DISABLED_HEURISTICS_COUNT;
bool is_mask_initialized = false;
char lib_fn_name[MAX_FN_NAME_LEN] = {0};

bool DRY_RUN_MODE = false;
size_t TOTAL_GET_BIT_CALL_COUNT = 0;
char *fuzzerr_dry_run_result_path = NULL;

static struct backtrace_state *bt_state = NULL;

/// flag to indicate that the injection has been disabled temporarily
volatile bool disabled = false;

size_t CURRENT_IDX = 0;
size_t EFFECTIVE_CURRENT_IDX = 0;

// the max idx after which the mask should rotate
// this should be initialized as per the actual INTEGERS initialized in the ERROR_MASK
size_t MAX_CURRENT_IDX = MASK_ARR_LEN * sizeof(uint32_t) * 8;

/// flag to avoid going in an infinite loop
bool in_get_bit = false;

/// flag to avoid going in an infinite loop in destructor
bool in_dtor = false;

/// maximum number of backtrace lines
const size_t MAX_BACKTRACE_LINES = 128;

/// flag to indicate that we are already saving a backtrace
bool in_save_backtrace = false;

// files to which the current run related information will be saved
char *FUZZERR_MASK_FILE = ".fuzzerr_mask";
char *FUZZERR_DISABLED_IDS_FILE = ".fuzzerr_disabled_ids";
char *FUZZERR_DISABLED_HEURISTICS_FILE = ".fuzzerr_disabled_heuristics";

void print_int_as_bits(uint32_t i) {
    printf(BYTE_TO_BINARY_PATTERN ",", BYTE_TO_BINARY(i >> 24));
    printf(BYTE_TO_BINARY_PATTERN ",", BYTE_TO_BINARY(i >> 16));
    printf(BYTE_TO_BINARY_PATTERN ",", BYTE_TO_BINARY(i >> 8));
    printf(BYTE_TO_BINARY_PATTERN "", BYTE_TO_BINARY(i));
}

void fuzzerr_disable() {
    disabled = true;

    char *msg = ">>>> fuzzerr_disable(): disabling fuzzerr...\n";
    size_t len = strlen(msg);
    write(STDOUT_FILENO, msg, len);
}

void fuzzerr_enable() {
    char *msg = ">>>> fuzzerr_enable(): enabling fuzzerr...\n";
    size_t len = strlen(msg);
    write(STDOUT_FILENO, msg, len);

    disabled = false;
}

void init_to_zero() {
    for (uint32_t i = 0; i < INPUT_NUM_COUNT; i++) {
        ERROR_MASK[i] = 0;
    }
    MAX_CURRENT_IDX = INPUT_NUM_COUNT * sizeof(uint32_t) * 8;
}

void init_from_random() {
    srandom(time(NULL));
    for (uint32_t i = 0; i < INPUT_NUM_COUNT; i++) {
        ERROR_MASK[i] = random();
    }
    MAX_CURRENT_IDX = INPUT_NUM_COUNT * sizeof(uint32_t) * 8;
}

FILE *open_file_or_exit(const char *file_name, char *mode) {
    FILE *file = fopen(file_name, mode);
    if (!file) {
        perror(file_name);
        exit(1);
    }
    return file;
}

int open_file_or_exit_fd(const char *file_path, int flags) {
    int fd = open(file_path, flags);
    if (fd < 0) {
        perror(file_path);
        exit(1);
    }
    return fd;
}

/// returns the file size (in bytes)
/// takes the opened filedescriptor as the argument
size_t get_filesize(int fd) {
    struct stat statbuf;
    int result = fstat(fd, &statbuf);
    if (result < 0) {
        perror("unable to get the size of file");
        exit(1);
    }
    return statbuf.st_size;
}

void init_error_mask_from_file(const char *file_name) {
    // printf(">> loading error mask from %s\n", file_name);

    // open and mmap the file
    int fd = open_file_or_exit_fd(file_name, O_RDONLY);
    size_t file_size = get_filesize(fd);
    printf(">> afl generated input file_size: %zu\n", file_size);
    char *ptr = (char *)mmap(NULL, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ptr == MAP_FAILED) {
        perror(">> unable to mmap the file");
        close(fd);
        exit(1);
    }
    close(fd);

    // printf(">> mmaped file and closed fd\n");

    // read the bits and initialize the mask
    //
    // this has been modified to read-in the complete file (subject to the size of the ERROR_MASK)
    // and not just till "valid idx"
    size_t curr = 0; // the current position in the mmaped file
    size_t numbers_initialized = 0;
    for (size_t idx = 0; idx < MASK_ARR_LEN; idx++) {
        if (curr + sizeof(uint32_t) <= file_size) { // copy 4 bytes (uint32_t)
            memcpy(&ERROR_MASK[idx], ptr + curr, sizeof(uint32_t));
            curr += sizeof(uint32_t);
            numbers_initialized += 1;
            // printf(">> initialized number %zu\n", idx);
            if (numbers_initialized == MASK_ARR_LEN) { // whole ERROR_MASK was initialized
                printf(">> [!] initialized whole of ERROR_MASK, this is not normal. [Please "
                       "investigate]\n");
                printf(">> [!] curr: %zu, file_size: %zu, numbers_initialized: %zu\n", curr,
                       file_size, numbers_initialized);
                break;
            }
        } else {
            break;
        }
    }

    if (numbers_initialized < MASK_ARR_LEN) {
        // Its possible that we didnt read in the full error mask.
        // For example, consider that we had 22 bytes of error mask, the code above would have read
        // 20 bytes (4bytes per i32 * 5), but would have left the last 2 bytes.
        // So we should create another number and consume these bytes.
        // note: the code below is mostly a hacky solution
        size_t remaining = file_size - numbers_initialized * sizeof(uint32_t);
        switch (remaining) {
        case 0:
            // nothing to do
            break;
        case 1:
        case 2:
        case 3:
            memcpy(&ERROR_MASK[numbers_initialized], ptr + curr, remaining);
            numbers_initialized++;
            break;
        default:
            fprintf(stderr, "(%s) should be unreachable (but got remaining=%zu)!\n", __func__,
                    remaining);
            fprintf(stderr, "(%s) file_size: %zu, numbers_initialized: %zu\n", __func__, file_size,
                    numbers_initialized);
            exit(EXIT_FAILURE);
        }
    }

    // unmap the file
    munmap(ptr, file_size);

    // printf(">> numbers initialized from afl generated input: %zu\n", numbers_initialized);

    // // this shouldn't happen but still, in case the input mask is smaller than what is required
    // for
    // // covering all valid idx, we will initialize the rest of the mask with zeroes
    // if (numbers_initialized < INPUT_NUM_COUNT) {
    //     printf("[!] (numbers_initialized :%zu) not enough input bits were provided, the rest
    //     would "
    //            "be initialized to 0. [Please investigate]\n",
    //            numbers_initialized);
    //     for(size_t idx = numbers_initialized; idx < INPUT_NUM_COUNT; idx++){
    //         ERROR_MASK[idx] = 0;
    //     }
    // }

    // based on the bits initialized from afl input, we will set the MAX_CURRENT_IDX
    // uint32_t valid_nums = numbers_initialized > INPUT_NUM_COUNT ? numbers_initialized:
    // INPUT_NUM_COUNT;
    MAX_CURRENT_IDX = numbers_initialized * sizeof(uint32_t) * 8;
    printf(">> (%s) MAX_CURRENT_IDX set to : %zu\n", __func__, MAX_CURRENT_IDX);
}

void init_disabled_ids_from_file(const char *file_name) {
    printf("loading disabled ids from %s\n", FUZZERR_DISABLED_IDS_FILE);
    char line[MAX_LINE_LENGTH] = {0};
    FILE *file = fopen(file_name, "r");

    if (!file) {
        printf("%s not found, skipping loading disabled ids\n", FUZZERR_DISABLED_IDS_FILE);
        return;
    }

    uint32_t idx = 0;
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        DISABLED_IDS[idx] = strtol(line, NULL, 10);
        VALID_DISABLED_IDS_COUNT++;
        idx++;
    }
    fclose(file);
}

void init_disabled_heuristics_from_file(const char *file_name) {
    printf("loading disabled heuristics from %s\n", FUZZERR_DISABLED_HEURISTICS_FILE);
    char line[MAX_LINE_LENGTH] = {0};
    FILE *file = fopen(file_name, "r");

    if (!file) {
        printf("%s not found, skipping loading disabled heuristics\n",
               FUZZERR_DISABLED_HEURISTICS_FILE);
        return;
    }

    uint32_t idx = 0;
    while (fgets(line, MAX_LINE_LENGTH, file)) {
        DISABLED_HEURISTICS[idx] = strtol(line, NULL, 10);
        VALID_DISABLED_HEURISTICS_COUNT++;
        idx++;
    }
    fclose(file);
}

void init_from_stdin() {
    for (uint32_t idx = 0; idx < INPUT_NUM_COUNT; idx++) {
        scanf("%d", &ERROR_MASK[idx]);
    }
    MAX_CURRENT_IDX = INPUT_NUM_COUNT * sizeof(uint32_t) * 8;
}

void parse_disable_heuristics(char *disable_heuristics) {
    printf("disabling heuristics: %s\n", disable_heuristics);

    char *p = strtok(disable_heuristics, ",");
    uint32_t hid;
    for (uint32_t i = VALID_DISABLED_HEURISTICS_COUNT; i < MAX_DISABLED_HEURISTICS; i++) {
        if (p == NULL) {
            break;
        }
        hid = atoi(p);

        bool already_present = false;
        for (uint32_t j = 0; j < VALID_DISABLED_HEURISTICS_COUNT; j++) {
            if (hid == DISABLED_HEURISTICS[j]) {
                already_present = true;
            }
        }

        if (!already_present) {
            DISABLED_HEURISTICS[i] = hid;
            VALID_DISABLED_HEURISTICS_COUNT = i + 1;
        }

        p = strtok(NULL, ",");
    }
}

void parse_disable_ids(char *disable_ids) {
    printf("disabling ids: %s\n", disable_ids);

    char *p = strtok(disable_ids, ",");
    uint32_t id;
    VALID_DISABLED_IDS_COUNT = 0;
    for (uint32_t i = 0; i < MAX_DISABLED_IDS; i++) {
        if (p == NULL) {
            break;
        }
        id = atoi(p);
        printf(">> id: %d\n", id);

        bool already_present = false;
        for (uint32_t j = 0; j < VALID_DISABLED_IDS_COUNT; j++) {
            if (id == DISABLED_IDS[j]) {
                already_present = true;
            }
        }

        if (!already_present) {
            // printf("storing id:%d as DISABLED_IDS[%d]\n", id, i);
            DISABLED_IDS[i] = id;
            VALID_DISABLED_IDS_COUNT = i + 1;
            printf(">> disabling id: %d\n", id);
            // print disabled_ids[i]
            printf(">> disabled_ids[%d]: %d\n", i, DISABLED_IDS[i]);
        }

        p = strtok(NULL, ",");
    }

    // print all disabled ids
    printf(">> (parse_disable_ids) VALID_DISABLED_IDS_COUNT: %zu\n", VALID_DISABLED_IDS_COUNT);
    printf(">> (parse_disable_ids) disabled ids: ");
    for (uint32_t i = 0; i < VALID_DISABLED_IDS_COUNT; i++) {
        printf("%d, ", DISABLED_IDS[i]);
    }
    printf("\n");
}

void save_error_mask() {
    printf(">> saving error mask to %s\n", FUZZERR_MASK_FILE);

    // open and mmap the file
    int fd = open_file_or_exit_fd(FUZZERR_MASK_FILE, O_RDWR | O_CREAT | O_TRUNC);

    // write the bytes
    uint32_t valid_nums = MAX_CURRENT_IDX / (sizeof(uint32_t) * 8);
    for (uint32_t i = 0; i < valid_nums; i++) {
        write(fd, &ERROR_MASK[i], sizeof(uint32_t));
    }
    close(fd);

    printf("current error mask saved to %s\n", FUZZERR_MASK_FILE);
}

void save_disabled_ids() {
    FILE *file = open_file_or_exit(FUZZERR_DISABLED_IDS_FILE, "w");
    for (uint32_t i = 0; i < VALID_DISABLED_IDS_COUNT; i++) {
        fprintf(file, "%u\n", DISABLED_IDS[i]);
    }
    fclose(file);
    printf("current disabled ids saved to %s\n", FUZZERR_DISABLED_IDS_FILE);
}

void save_disabled_heuristics() {
    FILE *file = open_file_or_exit(FUZZERR_DISABLED_HEURISTICS_FILE, "w");
    for (uint32_t i = 0; i < VALID_DISABLED_HEURISTICS_COUNT; i++) {
        fprintf(file, "%u\n", DISABLED_HEURISTICS[i]);
    }
    fclose(file);
    printf("current disabled ids saved to %s\n", FUZZERR_DISABLED_HEURISTICS_FILE);
}

/// save the parameters for this run, for replaying later, if required
/// - error mask
/// - disabled ids
/// - disabled heuristics
void save_params() {
    save_error_mask();
    save_disabled_ids();
    save_disabled_heuristics();
}

void load_last_params() {
    init_error_mask_from_file(FUZZERR_MASK_FILE);
    init_disabled_ids_from_file(FUZZERR_DISABLED_IDS_FILE);
    init_disabled_heuristics_from_file(FUZZERR_DISABLED_HEURISTICS_FILE);
}

void load_from_afl_map(char *afl_map_file) { init_error_mask_from_file(afl_map_file); }

void init_error_mask() {
    fflush(stdout);
    printf("initializing error mask...\n");
    fprintf(stderr, "initializing error mask...\n");

    // init current_idx to 0
    CURRENT_IDX = 0;

    // TODO: we now have enough flags that they are bound to get mixed
    // Enforce some checks to make them exclusive

    // read the bits based on certain environment variables:
    // FUZZERR_AFL_MAP : are we working with afl??
    // FUZZERR_REPLAY : should we reload the parameters used for last run?
    // FUZZERR_RANDOM_INPUT : initialize with random bits (DEFAULT) (bool)
    // FUZZERR_STANDARD_INPUT : read from stdin (bool)
    // FUZZERR_FILE_INPUT : read from a file (set filename as env var)
    // FUZZERR_DISABLED : disable all (just set everything to 0)
    char *fuzzerr_standard_input = getenv("FUZZERR_STANDARD_INPUT");
    char *fuzzerr_file_input = getenv("FUZZERR_FILE_INPUT");
    char *fuzzerr_disable = getenv("FUZZERR_DISABLE");
    char *fuzzerr_afl_map = getenv("FUZZERR_AFL_MAP");
    char *fuzzerr_replay = getenv("FUZZERR_REPLAY");

    if (fuzzerr_disable) {
        printf("disabling error masks...\n");
        init_to_zero();
        printf("initialized error masks to zero.\n");

    } else if (fuzzerr_afl_map) {
        // printf("reading error masks from afl map file...\n");
        load_from_afl_map(fuzzerr_afl_map);
        // printf("initialized error masks from afl map file.\n");

    } else if (fuzzerr_replay) {
        printf("reading error masks from last saved params...\n");
        load_last_params();
        printf("initialized error masks from last saved params.\n");

    } else if (fuzzerr_standard_input) {
        printf("reading error masks from stdin...\n");
        init_from_stdin();
        printf("initialized error masks from stdin.\n");

    } else if (fuzzerr_file_input) {
        printf("reading error masks from file: %s...\n", fuzzerr_file_input);
        init_error_mask_from_file(fuzzerr_file_input);
        printf("initialized error masks from file.\n");

    } else {
        // default to random
        printf("initializing error masks randomly...\n");
        init_from_random();
        printf("initialized error masks randomly.\n");
    }

    // set the flag to indicate that the error mask has been initialized
    is_mask_initialized = true;

    // should only inner errors be triggered?
    char *fuzzerr_only_inner = getenv("FUZZERR_ONLY_INNER");
    if (fuzzerr_only_inner) {
        ONLY_INNER = true;
    }

    // disable certain mask ids
    char *fuzzerr_disable_ids = getenv("FUZZERR_DISABLE_IDS");
    if (fuzzerr_disable_ids) {
        parse_disable_ids(fuzzerr_disable_ids);
        if (DEBUG_MODE) {
            printf(">> disabled ids: ");
            for (uint32_t i = 0; i < VALID_DISABLED_IDS_COUNT; i++) {
                printf("%u ", DISABLED_IDS[i]);
            }
            printf("\n");
        }
    }

    // disable certain heuristics
    char *fuzzerr_disable_heuristics = getenv("FUZZERR_DISABLE_HEURISTICS");
    if (fuzzerr_disable_heuristics) {
        parse_disable_heuristics(fuzzerr_disable_heuristics);
    }

    // print output for debugging?
    if (DEBUG_MODE) {
        fflush(stdout);
        uint32_t valid_nums = MAX_CURRENT_IDX / (sizeof(uint32_t) * 8);

        // print error mask only if the suitable env var is set
        char *fuzzerr_print_error_mask = getenv("FUZZERR_PRINT_ERROR_MASK");
        if (fuzzerr_print_error_mask && fuzzerr_print_error_mask[0] == '1') {
            printf("ERROR_MASK(s):\n");
            printf(">> MAX_CURRENT_IDX: %zu\n", MAX_CURRENT_IDX);
            printf(">> valid_nums: %u\n", valid_nums);
            for (size_t i = 0; i < valid_nums; i++) {
                print_int_as_bits(ERROR_MASK[i]);
                if (i % 2 == 1 || i == valid_nums - 1) {
                    printf("\n");
                } else {
                    printf(" ");
                }
                fflush(stdout);
            }
        }
    }

    // save the parameters for this run for replaying later, if required
    // - error mask
    // - disabled ids
    // - disabled heuristics
    char *fuzzerr_save_params = getenv("FUZZERR_SAVE_PARAMS");
    if (fuzzerr_save_params) {
        save_params();
    }

    // tmp: @shank: try using libbactrace
    bt_state = backtrace_create_state(NULL, 1, NULL, NULL);
    if (!bt_state) {
        printf("[!] backtrace_create_state failed, exiting!\n");
        exit(1);
    }
}

int get_bit_at_current_idx() {
    // get the bit at the current_idx from the error_masks
    int idx = EFFECTIVE_CURRENT_IDX / (sizeof(uint32_t) * 8);
    int pos = EFFECTIVE_CURRENT_IDX % (sizeof(uint32_t) * 8);
    int mask = 0x1 << pos;
    int val = (ERROR_MASK[idx] & mask) >> pos;

    // increase CURRENT_IDX and EFFECTIVE_CURRENT_IDX
    CURRENT_IDX++;
    EFFECTIVE_CURRENT_IDX = CURRENT_IDX % MAX_CURRENT_IDX;

    return val;
}

// // last backtrace_lines
// // TODO: shank: backtrace_lines should be freed in a destructor function at last
// char **backtrace_lines = NULL;
// int backtrace_lines_cnt = 0;
// const int MAX_BACKTRACE_LINE = 100;

// void clear_previous_backtrace_lines() {
//     if (DEBUG_MODE && ENABLE_BACKTRACE) {
//         printf("- clearing previous backtrace_lines...");
//     }
//     for (int i = 0; i < backtrace_lines_cnt; i++) {
//         if (backtrace_lines[i]) {
//             free(backtrace_lines[i]);
//         }
//     }
//     backtrace_lines_cnt = 0;
//     if (DEBUG_MODE && ENABLE_BACKTRACE) {
//         printf("done\n");
//     }
// }

// void check_cnt(uint64_t val, uint64_t max_allowed, char *msg) {
//     if (val > max_allowed) {
//         if (DEBUG_MODE) {
//             write(STDOUT_FILENO, msg, strlen(msg));
//             exit(EXIT_FAILURE);
//         }
//     }
// }

/// execute addr2line and return -1 if it fails else return 0
/// the output is saved in the buffer passed as argument
int addr2line(char *addr2line_cmd, char *addr2line_out, int MAX_OUTPUT_SZ) {
    FILE *fp = popen(addr2line_cmd, "r");
    if (fp == NULL) {
        if (DEBUG_MODE) {
            printf("> unable to call addr2line, skipping...\n");
        }
        if (addr2line_out) {
            free(addr2line_out);
        }
        return -1;
    }

    char *result = fgets(addr2line_out, MAX_OUTPUT_SZ, fp);
    pclose(fp);
    if (result == NULL) {
        if (DEBUG_MODE) {
            printf("> unable to read the result of addr2line, skipping...\n");
        }
        if (addr2line_out) {
            free(addr2line_out);
        }
        return -1;
    }

    // all good, just replace the end character, in case of a newline
    int len = strlen(addr2line_out);
    if (addr2line_out[len - 1] == '\n') {
        addr2line_out[len - 1] = '\0';
    }

    // signifies success
    return 0;
}

// // idx: index into backtrace_lines
// // line: a line from backtrace_symbols
// void set_backtrace_line(int idx, char *line, void *addr) {
//     // void set_backtrace_line(int idx, char *line, bool set_lib_fn_name) {
//     // line is in the format:
//     // test/hello_malloc.c.out() [0x41889f]

//     const uint64_t MAX_PATH_SZ = 512;
//     char addr2line_cmd[1024] = {0};

//     // get the exe_name
//     char exe_name[MAX_PATH_SZ] = {0};
//     char *end = strchr(line, '(');
//     assert(end != NULL); // shouldn't be possible
//     uint64_t cnt = end - line;
//     check_cnt(cnt, MAX_PATH_SZ - 1, "exe_name longer than (MAX_PATH_SZ - 1), exiting!");
//     memcpy(exe_name, line, cnt);
//     exe_name[cnt] = '\0';
//     // printf(">>>> exe_name: %s\n", exe_name);

//     // get the address
//     // char addr[20] = {0};
//     // char *start = strchr(line, '[');
//     // assert(start != NULL); // shouldn't be possible
//     // start++;               // move to the next char
//     // end = strchr(line, ']');
//     // assert(end != NULL); // shouldn't be possible
//     // cnt = end - start;
//     // check_cnt(cnt, 20 - 1, "addr longer than (20-1), exiting!");
//     // // printf(">>>> cnt: %d\n", cnt);
//     // memcpy(addr, start, cnt);
//     // addr[cnt] = '\0';
//     // // printf(">>>> addr: %s\n", addr);

//     // construct the command
//     char *ADDR2LINE_FMT = "llvm-addr2line --demangle --functions --pretty-print --exe=\"%.512s\"
//     %p"; sprintf(addr2line_cmd, ADDR2LINE_FMT, exe_name, addr); printf(">> addr2line_cmd: %s\n",
//     addr2line_cmd);
//     // printf(">>>> %s\n", line);

//     // now execute the cmd and get the return line
//     char *addr2line_out = (char *)calloc(MAX_PATH_SZ, sizeof(char *));
//     if (addr2line_out == NULL) {
//         if (DEBUG_MODE) {
//             printf("> call to calloc failed while creating addrline, skipping...\n");
//         }
//         backtrace_lines[idx] = strdup(line);
//         return;
//     }

//     int res = addr2line(addr2line_cmd, addr2line_out, MAX_PATH_SZ);
//     if (res == -1) {
//         // failed in addr2line
//         backtrace_lines[idx] = strdup(line);
//         return;
//     }

//     if (addr2line_out[0] == '?' || addr2line_out[0] == ':' || strstr(addr2line_out, "??:")) {
//         // printf("> addr2line output not useful: %s\n", addr2line_out);
//         // printf("> addr2line cmd was: %s\n", addr2line_cmd);

//         // if addr2line cannot resolve location, it returns "??:.."
//         // try seeing if this is a shared library address and information obtained
//         // using dladdr would help

//         Dl_info dlinfo;
//         if (dladdr(addr, &dlinfo) == 0) {
//             if (DEBUG_MODE) {
//                 printf("> unable to map address %lu to a shared library\n", (unsigned long)addr);
//             }
//             // we use the original line in that case
//             backtrace_lines[idx] = strdup(line);
//             return;
//         }

//         const char *fname = dlinfo.dli_fname;
//         intptr_t offset = (char *)addr - (char *)dlinfo.dli_fbase;
//         // printf("> fname: %s\n", fname);
//         // printf("> offset: %ld\n", offset);

//         // make another addr2line call but this time
//         memset(addr2line_cmd, 0, sizeof(addr2line_cmd));
//         memset(addr2line_out, 0, MAX_PATH_SZ * sizeof(char *));
//         char *ADDR2LINE_FMT = "llvm-addr2line --demangle --functions --pretty-print
//         --exe=\"%.512s\" 0x%012x"; sprintf(addr2line_cmd, ADDR2LINE_FMT, fname, offset);

//         int res = addr2line(addr2line_cmd, addr2line_out, MAX_PATH_SZ);
//         if (res == -1) {
//             // failed in addr2line
//             backtrace_lines[idx] = strdup(line);
//             return;
//         }
//         if (addr2line_out[0] == '?' || addr2line_out[0] == ':' || strstr(addr2line_out, "??:")) {
//             // printf("> addr2line output not useful again: %s\n", addr2line_out);
//             // printf("> addr2line cmd was: %s\n", addr2line_cmd);
//             backtrace_lines[idx] = strdup(line);
//             return;
//         }
//     }

//     // we were successful in getting the addr2line output (either the first time or the second),
//     use
//     // it
//     backtrace_lines[idx] = addr2line_out;
// }

// /// saves the first library function that was called from our src code
// /// iterates over the saved backtrace for this functionality
// void save_first_lib_fn() {
//     // ensure that we have the FUZZERR_LIB_SRC_PATH env variable set
//     const char *fuzzerr_lib_src_path = getenv("FUZZERR_LIB_SRC_PATH");
//     if (!fuzzerr_lib_src_path) {
//         printf("[!] FUZZERR_LIB_SRC_PATH env var not set, wont save first library function.\n");
//         return;
//     }

//     // skip the first 2 lines as they were skipped while saving the backtrace
//     for (int i = 2; i < backtrace_lines_cnt; i++) {
//         if (strstr(backtrace_lines[i], fuzzerr_lib_src_path)) {
//             // the backtrace should be of the form "<fn_name> at <file:line>"

//             // get the function name
//             char *end = strchr(backtrace_lines[i], ' ');
//             if (!end) {
//                 // we couldnt find the space charater, just skip this
//                 continue;
//             }
//             uint64_t cnt = end - backtrace_lines[i];
//             check_cnt(cnt, MAX_FN_NAME_LEN - 1,
//                       "function anem longer than (MAX_FN_NAME_LEN - 1), exiting!");

//             // clear out the previous fn_name
//             memset(lib_fn_name, 0, MAX_FN_NAME_LEN);
//             // save lib_fn_name
//             strncpy(lib_fn_name, backtrace_lines[i], cnt);
//             // printf("> saved lib_fn_name: %s\n", lib_fn_name);
//         }
//     }
// }

int try_dladdr(uintptr_t addr, char *addr2line_out, int MAX_OUTPUT_SZ) {
    Dl_info dlinfo;
    if (dladdr((const void *)addr, &dlinfo) == 0) {
        return -1;
    }

    const char *fname = dlinfo.dli_fname;
    intptr_t offset = (char *)addr - (char *)dlinfo.dli_fbase;
    // printf("> fname: %s\n", fname);
    // printf("> offset: %ld\n", offset);

    // make another addr2line call but this time
    char addr2line_cmd[1024];
    char *ADDR2LINE_FMT =
        "llvm-addr2line --demangle --functions --pretty-print --exe=\"%.512s\" 0x%012x";
    snprintf(addr2line_cmd, 1024, ADDR2LINE_FMT, fname, offset);
    // printf("> addr2line cmd: %s\n", addr2line_cmd);

    int res = addr2line(addr2line_cmd, addr2line_out, 4096);
    if (res == -1) {
        // failed in addr2line
        return -1;
    }
    if (addr2line_out[0] == '?' || addr2line_out[0] == ':' || strstr(addr2line_out, "??:")) {
        // printf("> addr2line output not useful again: %s\n", addr2line_out);
        // printf("> addr2line cmd was: %s\n", addr2line_cmd);
        memset(addr2line_out, 0, MAX_OUTPUT_SZ);
        snprintf(addr2line_out, MAX_OUTPUT_SZ, "%s", fname);
        return 0;
    }

    return 0;
}

// tmp: @shank: trying libbacktrace
static int backtrace_full_cb(void *data, uintptr_t pc, const char *filename, int lineno,
                             const char *function) {

    char file_name[512] = {0};
    char addr2line_out[4096] = {0};
    if (filename) {
        // if filename starts with /, then it is an absolute path and we can use it as is
        // otherwise, we fall back to addr2line to get the file name
        snprintf(file_name, 512, "%s", filename);

        if (filename[0] == '/') {
            snprintf(file_name, 512, "%s", filename);
        } else {
            // try using addr2line to get the full filename
            char addr2line_cmd[1024];
            char *ADDR2LINE_FMT =
                "llvm-addr2line --demangle --functions --pretty-print --exe=\"%.512s\" 0x%012x";
            snprintf(addr2line_cmd, 1024, ADDR2LINE_FMT, program_invocation_name, pc);

            // char *addr2line_out = (char *)calloc(4096, sizeof(char *));
            // if (addr2line_out == NULL) {
            //  if (DEBUG_MODE) {
            //      printf("> call to calloc failed while creating addrline, skipping...\n");
            //  }
            //  snprintf(file_name, 512, "%s", filename);
            // }

            int res = addr2line(addr2line_cmd, addr2line_out, 4096);
            if (res == -1) {
                // failed in addr2line
                snprintf(file_name, 512, "%s", filename);

            } else if (addr2line_out[0] == '?' || addr2line_out[0] == ':' ||
                       strstr(addr2line_out, "??:")) {
                snprintf(file_name, 512, "%s", filename);
                // // printf("> addr2line output not useful: %s\n", addr2line_out);
                // // printf("> addr2line cmd was: %s
                // memset(addr2line_out, 0, 4096);
                // printf("> trying dl_ddr #1\n");
                // fflush(stdout);
                // res = try_dladdr(pc, addr2line_out, 4096);
                // if (res == -1){
                //     snprintf(file_name, 512, "%s", filename);
                // } else {
                //     // at this point we (hopefully) have the full file name in addr2line_out
                //     printf(">>>> %p in %s\n", (void*)pc, addr2line_out);
                //     return 0;
                // }
            } else {
                // at this point we (hopefully) have the full file name in addr2line_out
                printf(">>>> %p in %s\n", (void *)pc, addr2line_out);
                return 0;
            }
        }

    } else {
        memset(addr2line_out, 0, 4096);
        // printf("> trying dl_ddr #2\n");
        // fflush(stdout);
        int res = try_dladdr(pc, addr2line_out, 4096);
        if (res == -1) {
            snprintf(file_name, 512, "%s", "??");
        } else {
            // at this point we (hopefully) have the full file name in addr2line_out
            printf(">>>> %p in %s\n", (void *)pc, addr2line_out);
            return 0;
        }
    }

    char function_name[MAX_FN_NAME_LEN];
    if (function) {
        snprintf(function_name, MAX_FN_NAME_LEN, "%s", function);
    } else {
        snprintf(function_name, MAX_FN_NAME_LEN, "%s", "?");
    }

    char msg[1024];
    int status = -1;
    char *demangledName = cplus_demangle(function_name, DMGL_PARAMS | DMGL_ANSI);
    if (demangledName != NULL)
        printf(">>>> %p in %s at %s:%d\n", (void *)pc, demangledName, file_name, lineno);
    else
        printf(">>>> %p in %s at %s:%d\n", (void *)pc, function_name, file_name, lineno);
    free(demangledName);
    return 0;
}

void save_backtrace() {
    // return early, if we are already inside another save_backtrace()
    if (in_save_backtrace) {
        return;
    }

    // mark that we are executing a backtrace
    in_save_backtrace = true;

    // tmp: @shank: try using libbactrace
    // struct backtrace_state *bt_state = backtrace_create_state(NULL, 1, NULL, NULL);
    // if (!bt_state) {
    //     printf("[!] backtrace_create_state failed, exiting!\n");
    //     exit(1);
    // }
    if (ENABLE_BACKTRACE) {
        // printf(">> LIBBACKTRACE start:\n");
        printf(ANSI_STYLE_BOLD ANSI_COLOR_GREEN "BACKTRACE START >>" ANSI_RESET_ALL "\n");
        backtrace_full(bt_state, 1, backtrace_full_cb, NULL, NULL);
        // printf(">> LIBBACKTRACE end:\n");
        printf(ANSI_STYLE_BOLD ANSI_COLOR_GREEN "BACKTRACE END >>" ANSI_RESET_ALL "\n");
        fflush(stdout);
    }

    // // TODO: shank: replace printf() with write() in all parts of this code

    // void *backtrace_buf[MAX_BACKTRACE_LINES];
    // char **backtrace_strings;

    // int trace_cnt = backtrace(backtrace_buf, MAX_BACKTRACE_LINES);
    // if (ENABLE_BACKTRACE && DEBUG_MODE) {
    //     printf("> backtrace() returned %d addresses\n", trace_cnt);
    //     for(int i = 0; i < trace_cnt; i++) {
    //         printf("> backtrace_buf[%d]: %p\n", i, backtrace_buf[i]);
    //     }
    // }

    // backtrace_strings = backtrace_symbols(backtrace_buf, trace_cnt);
    // if (backtrace_strings == NULL) {
    //     perror("backtrace_symbols");
    //     exit(EXIT_FAILURE);
    // }

    // if (backtrace_lines != NULL) {
    //     clear_previous_backtrace_lines();
    // } else {
    //     backtrace_lines = (char **)calloc(MAX_BACKTRACE_LINE, sizeof(char *));
    //     if (backtrace_lines == NULL) {
    //         if (DEBUG_MODE) {
    //             printf("> call to calloc failed while creating backtrace_lines, skipping...\n");
    //         }
    //         free(backtrace_strings);
    //         return;
    //     }
    // }
    // backtrace_lines_cnt = trace_cnt;

    // // skip the first 2 since they are our own backtrace functions
    // for (int i = 2; i < trace_cnt; i++) {
    //     // printf(">> %s\n", backtrace_strings[i]);
    //     set_backtrace_line(i, backtrace_strings[i], backtrace_buf[i]);
    // }

    // // tmp: print saved backtrace
    // if (ENABLE_BACKTRACE) {
    //     printf(ANSI_STYLE_BOLD ANSI_COLOR_GREEN "BACKTRACE START >>" ANSI_RESET_ALL "\n");
    //     for (int i = 2; i < backtrace_lines_cnt; i++) {
    //         printf(">>>> %s\n", backtrace_lines[i]);
    //     }
    //     printf(ANSI_STYLE_BOLD ANSI_COLOR_GREEN "BACKTRACE END >>" ANSI_RESET_ALL "\n");
    // }

    // save_first_lib_fn();

    // free(backtrace_strings);

    // mark that we are done saving the current backtrace
    in_save_backtrace = false;

    fflush(stdout);
}

void signal_handler(int signum, siginfo_t *siginfo, void *context) {
    // disable fuzzerr since we are in the handler
    fuzzerr_disable();

    int old_errno = errno;

    switch (signum) {
    case SIGSEGV:
        fputs("BINARY CRASHED!\n", stderr);
        fputs("Caught SIGSEGV: Segmentation Fault\n", stderr);
        break;
    case SIGINT:
        fputs("BINARY CRASHED!\n", stderr);
        fputs("Caught SIGINT: Interactive attention signal, (usually ctrl+c)\n", stderr);
        break;
    case SIGFPE:
        fputs("BINARY CRASHED!\n", stderr);
        switch (siginfo->si_code) {
        case FPE_INTDIV:
            fputs("Caught SIGFPE: (integer divide by zero)\n", stderr);
            break;
        case FPE_INTOVF:
            fputs("Caught SIGFPE: (integer overflow)\n", stderr);
            break;
        case FPE_FLTDIV:
            fputs("Caught SIGFPE: (floating-point divide by zero)\n", stderr);
            break;
        case FPE_FLTOVF:
            fputs("Caught SIGFPE: (floating-point overflow)\n", stderr);
            break;
        case FPE_FLTUND:
            fputs("Caught SIGFPE: (floating-point underflow)\n", stderr);
            break;
        case FPE_FLTRES:
            fputs("Caught SIGFPE: (floating-point inexact result)\n", stderr);
            break;
        case FPE_FLTINV:
            fputs("Caught SIGFPE: (floating-point invalid operation)\n", stderr);
            break;
        case FPE_FLTSUB:
            fputs("Caught SIGFPE: (subscript out of range)\n", stderr);
            break;
        default:
            fputs("Caught SIGFPE: Arithmetic Exception\n", stderr);
            break;
        }
    case SIGILL:
        fputs("BINARY CRASHED!\n", stderr);
        switch (siginfo->si_code) {
        case ILL_ILLOPC:
            fputs("Caught SIGILL: (illegal opcode)\n", stderr);
            break;
        case ILL_ILLOPN:
            fputs("Caught SIGILL: (illegal operand)\n", stderr);
            break;
        case ILL_ILLADR:
            fputs("Caught SIGILL: (illegal addressing mode)\n", stderr);
            break;
        case ILL_ILLTRP:
            fputs("Caught SIGILL: (illegal trap)\n", stderr);
            break;
        case ILL_PRVOPC:
            fputs("Caught SIGILL: (privileged opcode)\n", stderr);
            break;
        case ILL_PRVREG:
            fputs("Caught SIGILL: (privileged register)\n", stderr);
            break;
        case ILL_COPROC:
            fputs("Caught SIGILL: (coprocessor error)\n", stderr);
            break;
        case ILL_BADSTK:
            fputs("Caught SIGILL: (internal stack error)\n", stderr);
            break;
        default:
            fputs("Caught SIGILL: Illegal Instruction\n", stderr);
            break;
        }
        break;
    case SIGTERM:
        fputs("BINARY CRASHED!\n", stderr);
        fputs("Caught SIGTERM: a termination request was sent to the program\n", stderr);
        break;
    case SIGABRT:
        fputs("BINARY CRASHED!\n", stderr);
        fputs("Caught SIGABRT: usually caused by an abort() or assert()\n", stderr);
        break;
    default:
        break;
    }

    sigset_t mask_all, mask_prev;
    if (sigfillset(&mask_all) < 0) {
        char *msg = "error setting mask, exiting\n";
        int len = strlen(msg);
        write(STDERR_FILENO, msg, len);
        exit(EXIT_FAILURE);
    };

    sigprocmask(SIG_BLOCK, &mask_all, &mask_prev);
    save_backtrace();
    sigprocmask(SIG_SETMASK, &mask_prev, NULL);

    // restore errno, though it doesnt really matter here...
    errno = old_errno;

    exit(EXIT_FAILURE);
}

typedef void (*sa_sigaction_handler)(int, siginfo_t *, void *);

void install_signal_handler() {
    printf(">>>> installing signal handler...\n");

    // setup alternate stack
    {
        stack_t ss = {};
        ss.ss_sp = (void *)alternate_stack;
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;

        if (sigaltstack(&ss, NULL) != 0) {
            err(1, "sigaltstack");
        }
    }

    // register handlers
    struct sigaction sa;
    sa.sa_sigaction = (sa_sigaction_handler)signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;

    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        err(1, "sigaction");
    }
    if (sigaction(SIGFPE, &sa, NULL) != 0) {
        err(1, "sigaction");
    }
    if (sigaction(SIGINT, &sa, NULL) != 0) {
        err(1, "sigaction");
    }
    if (sigaction(SIGILL, &sa, NULL) != 0) {
        err(1, "sigaction");
    }
    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        err(1, "sigaction");
    }
    if (sigaction(SIGABRT, &sa, NULL) != 0) {
        err(1, "sigaction");
    }

    printf(">>>> installed signal handler\n");
}

// @shank
// sigalrm handler
void fuzzerr_sigalrm_handler(int signum) {
    save_total_get_bit_call_count();

    printf(">>>> from errlib fuzzerr_sigalrm_handler.. killing self, bye!\n");
    fflush(stdout);

    kill(getpid(), SIGTERM);

    // we exit the process
    // _exit(EXIT_SUCCESS);
}
