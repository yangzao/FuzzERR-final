#include <stdio.h>

void my_afl_ctor() __attribute__((constructor(65534)));

void my_afl_ctor() {
    printf("this is from afl constructor: before __AFL_INIT()\n");
    __AFL_INIT();
    printf("this is from afl constructor: after __AFL_INIT()\n");
}
