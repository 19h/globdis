#!/bin/bash

echo "Building Windows PE version..."

# Check if MinGW-w64 is installed
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: MinGW-w64 cross-compiler not found."
    echo "Install it with: sudo apt-get install gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64"
    exit 1
fi

mkdir -p build-windows
cd build-windows

# Use MinGW toolchain to cross-compile to Windows PE format
cmake .. -DCMAKE_TOOLCHAIN_FILE=../mingw-w64-toolchain.cmake -DFORCE_WINDOWS_BUILD=ON
make

echo "Built Windows PE executable: GlobalCallAnalyzer.exe"
