# The FuzzERR tool (to instrument libraries)

This repository contains the source code for FuzzERR, a tool that takes as input the shared library generated using `wllvm` (so that it includes the whole program llvm bitcode for the library) and the errorblocks.json file for this library generated using `DetectERR` and produces the instrumented library shared object file. This tool is a part of our research paper accepted at AsiaCCS-2024, titled "Fuzzing API Error Handling Behaviors using Coverage Guided Fault Injection".

This repository contains the llvm opt pass for this instrumentation. This repository also included the source code for the `Errlib` which makes it easier to control the exact fault injection point.

## Build

The following instructions are for Ubuntu 22.04.

**Packages from `apt`**

```
sudo apt install -y python3.10 multilog bear patchelf
```

**llvm**

```
wget https://apt.llvm.org/llvm.sh
chmod +x llvm.sh
sudo ./llvm.sh 13 all
```

**Cargo packages**

```
# install rust (and cargo) using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# reload your shell so that cargo bin path is added to your PATH, and then:
cargo install fd sd
```

**Others**

- Install [libbacktrace](https://github.com/ianlancetaylor/libbacktrace) as per the instructions in their repository.

**Python Packages (pip)**

```
pip install colorlog wllvm
```

## How do I go about fuzzing a program with a library??

The following are the steps involved in fuzzing a program with a given library.

1. Get the potential fault injection points for the library (`errblocks.json` file).
    - To obtain this, run [DetectERR](https://github.com/purs3lab/DetectERR-final) on the library source code.
2. Get the json compilation database (`compile_commands.json`) for the library.
3. Build the library using `wllvm`, with debug info.
4. Build the FuzzERR LLVM Instrumentation Pass in `InstrumentationPasses` directory (only required once).
5. Get the LLVM bitcode for the library.
    - Extract the whole library bitcode from the generated shared library in step above, using `extract-bc` from `wllvm` project.
6. Instrument the library bitcode.
    - Run the instrumentation pass on the extracted bitcode from step 4.
7. Link the instrumented bitcode with Errlib to generate the final instrumented library.
    - First build ErrLib (from `ErrLib` directory in this repository)
    - Then link the ErrLib with the instrumented bitcode using `llvm-link`.
8. Build the program to fuzz (with debug info).
9. Use `patchelf` to modify the RPath in the program binary to use the instrumented library created above.
10. Fuzz the program (with the modified RPath from step 9) using the modified `afl-fuzz` from [FuzzERR_AFLPlusPlus](https://github.com/purs3lab/FuzzERR_AFLPlusPlus-final).

## Example:

The example below uses [jpegoptim](https://github.com/tjko/jpegoptim) as the program to be fuzzed and [libjpeg](https://github.com/libjpeg-turbo/libjpeg-turbo) as the library which would be instrumented for fault injection.

- (Step 1). Download and extract the source code for libjpeg-turbo. Use `detecterr` to generate the compilation database. Refer to DetectERR repo for details about its usage.

- (Steps 2,3). Refer to the `scripts/create_wllvm_libjpeg.sh` script to compile libjpeg with wllvm. NOTE: Update the `BASE_DIR`, `LIB_SRC_DIR` and `LIB_INSTR_DIR` paths as per your setup.
    - `BASE_DIR` : the path to this repo.
    - `LIB_SRC_DIR` : the path to source code for libjpeg
    - `LIB_INSTR_DIR` : the path where the libjpeg library, compiled using wllvm, should be moved to.
    - This script generates the compilation database as well (step 2), using the inbuilt support in cmake. For libraries using other build system, `bear` can be used to generate the compilation database.

- (Step 4,5,6,7). Refer to the `scripts/inst_libjpeg.sh` script that generates the instrumented `libjpeg.so` shared library from the `libjpeg.so` file generated in the step above. Internally it uses the helper script `script/inst_so.sh` which actually takes care of steps 4, 5, 6 and 7. The `BASE_DIR`, `LIB_SRC_DIR` and `LIB_INSTR_DIR` are same as the step above.

- (Step 8,9). Download and extract the source code for jpegoptim. Build it using the `afl-clang-fast`/`afl-clang-fast++` binaries from FuzzERR_AFLPlusPlus. Finally, using `patchelf`, add an RPath to the generated jpegoptim binary so that it would use the instrumented library generate above (step 9). 
    - The `scripts/inst_libjpeg.sh` script also contains the code for the steps described above (refer ????).

- (Step 10). The `scripts/fuzzerr/fuzz_bin.py` script functions as a harness to fuzz the given binary. It uses a json config that contains the parameters for the fuzzing campaign. The json config for jpegoptim is provided at [fuzz_jpegoptim.json](experiments/libjpeg/fuzz_jpegoptim.json). To run the process:

    ```bash
    # single process
    ./scripts/fuzzerr/fuzz_bin.py experiments/libjpeg/fuzz_jpegoptim.json

    # OR to use multiple processes in parallel
    ./scripts/fuzzerr/fuzz_bin.py experiments/libjpeg/fuzz_jpegoptim.json -p
    ```

    The parameters of the fuzzing config file are explained below:

    1. `SETUP_CMDS` : list of commands to run before the fuzzing campaign (for example, to setup a particular folder structure).
    2. `LIB_INSTR_DIR`, `LIB_SRC_DIR` : same as explained above.
    3. `BIN_SRC_DIR` : path to the directory containing the sources for the program being fuzzed.
    4. `BIN_TO_FUZZ` : path to the final binary to fuzz (jpegoptim).
    5. `BIN_INPUT_DIR` : path to the directory containing initial seed inputs for fuzzing.
    6. `BIN_ARGS_LIST` : list of invocations for the program being fuzzed. The following special variables are available for use in these commands.
        a. `{{input}}` : the input file path
        b. `{{output}}` : the output file path
        c. `{{outputd}}` : the path to a temporary output directory where this program will put its output files
        For example the line `-d {{outputd}} -o {{input}}` in `BIN_ARGS_LIST` means that jpegoptim will be run using the command `jpegoptim -d /path/to/tmp_output_dir -o /path/to/one/seed_input`, and then the fuzzer (afl++) would inject faults in libjpeg, while being guided by feedback.
    7. `DEBUG` : Whether to print the output (for debugging purposes) (NOTE: this produces a *lot* of output and is really useful only when running without the `-p` flag i.e. in single process)
    8. `TOTAL_FUZZ_TIME_MINS` : total time in minutes for which this program should be fuzzed
    9. `FUZZ_TIME_PER_INPUT_ARG_MINS` : time in minutes for which one particular input should be used for one particular invocation of the command arguments listed in `BIN_ARGS_LIST` (explained above).
    10. `AFL_TIMEOUT_MSECS` : time delay, in miliseconds, which afl++ should treat as a timeout (useful for slow binaries)
    11. `FUZZERR_TIMEOUT_IN_SEC` : timeout to be used internally by FuzzERR while doing crash-minimization/filtering.
    12. `LOG_DESTINATION` : "MULTILOG"/"STDOUT" -- whether to save output to log files (MULTILOG) or just print on screen (STDOUT).
