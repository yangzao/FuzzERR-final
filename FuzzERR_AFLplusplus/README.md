# Fuzzerr_AFLPlusPlus

This repository contains the modified version of AFL++ to be used with [FuzzERR](https://github.com/purs3lab/FuzzERR-final). This tool is a part of our research paper detailing FuzzERR, accepted at AsiaCCS-2024, titled "Fuzzing API Error Handling Behaviors using Coverage Guided Fault Injection".

## Building and Installing

```bash
# build
make clean
CC=clang CXX=clang++ make source-only -j$(nproc) STATIC=1 NO_NYX=1

# install
make install DESTDIR=/path/to/aflpp_install_dir
```
