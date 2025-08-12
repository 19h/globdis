#!/bin/bash

echo "Building Linux ELF version with clang..."

# Check if clang++ is installed
if ! command -v clang++ &> /dev/null; then
    echo "Warning: clang++ not found, falling back to g++"
    CXX_COMPILER="g++"
else
    CXX_COMPILER="clang++"
fi

echo "Using compiler: $CXX_COMPILER"

mkdir -p build-linux
cd build-linux

# Configure with the chosen compiler to build native Linux ELF
cmake .. -DCMAKE_CXX_COMPILER=$CXX_COMPILER
make

echo "Built Linux ELF executable: GlobalCallAnalyzer"
