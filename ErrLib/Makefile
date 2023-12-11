BUILD_DIR=build
INCLUDES=-I include/
CFLAGS=-g -O0
LDFLAGS=-liberty
BCFLAGS=-fpic

# the main rule to generate the bitcode err.bc
bc: $(BUILD_DIR)/errlib/err.bc

%.ll: %.c
	$(CC) $(CFLAGS) $(BCFLAGS) $(INCLUDES) -c -emit-llvm -S $^ -o $@ $(LDFLAGS)

$(BUILD_DIR)/errlib/err.bc: src/errlib/err.ll src/errlib/common.ll
	mkdir -p $(BUILD_DIR)/errlib
	llvm-link -o $@ $^


.PHONY: clean
clean:
	rm -rf src/errlib/*.o
	rm -rf src/errlib/*.bc
	rm -rf $(BUILD_DIR)/*

