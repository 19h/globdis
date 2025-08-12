#include <iostream>

// Global variables with explicit patterns
volatile int g_counter = 0;
void (*g_func_ptr)() = nullptr;
int g_array[100] = {0};

// Global vtable-like structure
struct VTable {
    void (*func1)();
    void (*func2)();
    void (*func3)();
};

void test_func1() { g_counter++; }
void test_func2() { g_counter += 2; }
void test_func3() { g_counter += 3; }

VTable g_vtable = { test_func1, test_func2, test_func3 };
VTable* g_vtable_ptr = &g_vtable;

// Function that uses globals in ways the analyzer should detect
void test_global_access() {
    // Direct global load and store
    int temp = g_counter;      // load from global
    g_counter = temp + 1;      // store to global

    // Array access
    g_array[0] = 42;           // store to global array
    int val = g_array[1];      // load from global array

    // Function pointer call through global
    if (g_func_ptr != nullptr) {
        g_func_ptr();          // call through global pointer
    }

    // Virtual call pattern through global vtable
    g_vtable_ptr->func1();     // virtual call [reg+0]
    g_vtable_ptr->func2();     // virtual call [reg+8]
    g_vtable_ptr->func3();     // virtual call [reg+16]
}

// Another function with different access patterns
#ifdef _WIN32
__declspec(noinline)
#else
__attribute__((noinline))
#endif
void complex_global_pattern() {
    // Load global address into register then use it multiple times
    VTable* local_ptr = g_vtable_ptr;

    // Multiple accesses through the same base
    local_ptr->func1();
    local_ptr->func2();

    // Offset access pattern
    int* array_ptr = g_array;
    array_ptr[10] = 100;
    array_ptr[20] = 200;
    array_ptr[30] = 300;
}

int main() {
    std::cout << "Test program for GlobalCallAnalyzer\n";

    // Set up function pointer
    g_func_ptr = test_func1;

    // Call test functions
    test_global_access();
    complex_global_pattern();

    std::cout << "Final counter value: " << g_counter << "\n";
    return 0;
}
