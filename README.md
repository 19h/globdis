# Global Call Analyzer

Build instructions and project information.

## Overview

Global Call Analyzer is a tool for analyzing function calls in binary files.

## Prerequisites

- CMake 3.10 or higher
- C++ compiler with C++17 support
- Ninja build system (optional but recommended)

## Building

1. Create a build directory:
   ```bash
   mkdir build
   cd build
   ```

2. Configure the project:
   ```bash
   cmake ..
   ```

   Or with Ninja:
   ```bash
   cmake -G Ninja ..
   ```

3. Build the project:
   ```bash
   cmake --build .
   ```

## Usage

After building, run the analyzer:
```bash
./build/global_call_analyzer <binary_file>
```

## License

[Add license information here]
