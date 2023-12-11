#ifndef ERRLIB_ERR_H
#define ERRLIB_ERR_H

#include <stdint.h>
#include <stdlib.h>

// TODO: DISCUSS: note regarding heuristic ids
// since now we are instrumenting multiple conditions into one error check
// (refer the decision table used in instrumenting branch instructions)
// we need to have a way to communicate that this get_bit() might have been
// called due to any of of the possible reasons.
// For now, we are using H00 as a marker for this but this would better be
// handled by using some sort of a bit mapping.
enum Heuristic {
    H00 = 0, // signifies multiple heuristics
    H01,     // not used
    H02,
    H03,
    H04,
    H05,
    H06,
    H07,
    H08,
    H09,
    H10,
    H11,
};

enum Level { Inner = 0, Outer, Default };

/// will be called from the library constructor so as to record the number of
/// valid mask counts required. This information shall be used later on to
/// initilize the error mask
extern void init_valid_mask_count(uint32_t count);

/// will be called from the library destructor so as to record the number of actual
/// get_bit() calls made. This information shall be used later on for creating the
/// error mask during fuzzing
/// NOTE: this function is only useful if FUZZERR_DRY_RUN env variable is set
extern void save_total_get_bit_call_count();

/// returns the corresponding bit from the ERROR_MASK
extern int fuzzerr_get_bit(int x, enum Heuristic hid, enum Level level);

#endif /* ERRLIB_ERR_H */
