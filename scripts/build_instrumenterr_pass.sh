#! /bin/bash

set -x
set -e
set -u
set -o pipefail

mkdir -p build && \
cd build && \
cmake -DCMAKE_BUILD_TYPE=DEBUG ../InstrumentationPasses && \
cmake --build . && \
cd ..
