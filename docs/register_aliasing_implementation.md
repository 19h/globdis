# Register Aliasing Implementation for Derived Pointers

## Overview
This implementation extends the GlobalCallAnalyzer to track register aliasing for derived pointers. The system now maintains associations between registers and their source globals with offsets, even as pointers are copied between registers or modified through arithmetic operations.

## Key Features Implemented

### 1. Register-to-Register Copying
- When a MOV instruction copies a pointer from one register to another, the tracking information is preserved
- The destination register inherits the source global and offset information
- Example: `mov rbx, rax` - if rax contains a tracked pointer, rbx will now also be tracked

### 2. Pointer Arithmetic Tracking
- ADD/SUB instructions with immediate values update the accumulated offset
- LEA instructions that compute effective addresses are handled specially
- Example: `add rax, 8` - adds 8 to the accumulated offset for the pointer in rax

### 3. Register Clearing
- When a register is overwritten with a non-pointer value, its tracking is cleared
- This prevents false positives from stale tracking data
- Example: `xor rax, rax` - clears any pointer tracking for rax

### 4. Sub-register Support
- The system correctly handles sub-registers (e.g., eax, ax, al are all part of rax)
- Uses GetFullRegister() to map any sub-register to its full 64-bit version
- Prevents tracking conflicts between different parts of the same register

## Implementation Details

### Data Structure
```cpp
struct DereferencedPointer {
    uint64_t source_global_va{};     // Global variable the pointer was loaded from
    int64_t source_offset{};         // Offset within the global (signed)
    ZydisRegister loaded_register{}; // Register containing the pointer
    size_t instruction_index{};      // Where the load occurred
    size_t nesting_level = 1;        // Depth of dereference
    int64_t accumulated_offset{};    // Total offset from arithmetic
};
```

### Key Functions
1. **GetFullRegister()**: Maps any sub-register to its full 64-bit version
2. **RegistersOverlap()**: Checks if two registers share the same physical register
3. **ProcessInstruction()**: Enhanced to handle register aliasing in three steps:
   - Step 1: Handle register-to-register moves
   - Step 2: Handle pointer arithmetic
   - Step 3: Clear tracking for overwritten registers

### Integration
The register_pointer_map is maintained across all instructions in the Analyze() method, allowing tracking to persist throughout the analysis of the entire .text section.

## Testing
A test program (test_register_aliasing.cpp) demonstrates various aliasing scenarios:
1. Basic register copying
2. Pointer arithmetic with char* casts
3. LEA-based offset calculations
4. Register clearing with nullptr assignment
5. Multi-level aliasing chains

## Future Enhancements
- Support for more complex arithmetic patterns (e.g., scaled index addressing)
- Tracking through function calls (with calling convention awareness)
- Integration with the nested access tracking for multi-level pointer dereferences
