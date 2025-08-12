#!/bin/bash

echo "Building both Windows PE and Linux ELF versions..."
echo "=================================================="

# Build Linux ELF version
echo
echo "1. Building Linux ELF version..."
./build-linux.sh

if [ $? -eq 0 ]; then
    echo "✓ Linux ELF version built successfully"
else
    echo "✗ Linux ELF version build failed"
    exit 1
fi

# Build Windows PE version
echo
echo "2. Building Windows PE version..."
./build.sh

if [ $? -eq 0 ]; then
    echo "✓ Windows PE version built successfully"
else
    echo "✗ Windows PE version build failed"
    exit 1
fi

echo
echo "=================================================="
echo "Build summary:"
echo "  Linux ELF:    ./build-linux/GlobalCallAnalyzer"
echo "  Windows PE:   ./build-windows/GlobalCallAnalyzer.exe"
echo 
echo "Both executables can analyze PE files!"
echo "The Linux version uses POSIX file mapping."
echo "The Windows version uses Windows file mapping APIs."
