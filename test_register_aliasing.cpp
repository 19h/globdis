#include <cstdint>
#include <iostream>

// Global struct to test derived pointer tracking
struct TestStruct {
    int field1;
    int field2;
    void* ptr_field;
    double double_field;
    char buffer[16];
};

TestStruct g_test_struct = {42, 100, nullptr, 3.14, "Hello"};
TestStruct* g_struct_ptr = &g_test_struct;

void test_register_aliasing() {
    // Test 1: Basic register-to-register copy
    TestStruct* p1 = g_struct_ptr;
    TestStruct* p2 = p1;  // This should track p2 as an alias of p1
    
    // Access through aliased pointer
    int val1 = p2->field1;
    int val2 = p2->field2;
    
    // Test 2: Pointer arithmetic
    char* char_ptr = (char*)g_struct_ptr;
    char_ptr += 8;  // This should track offset adjustment
    void* ptr_val = *(void**)char_ptr;  // Access ptr_field
    
    // Test 3: LEA instruction for offset calculation
    int* field2_ptr = &g_struct_ptr->field2;  // LEA will be used here
    int field2_val = *field2_ptr;
    
    // Test 4: Register overwrite (should clear tracking)
    TestStruct* p3 = g_struct_ptr;
    p3 = nullptr;  // This should clear tracking for p3
    
    // Test 5: Complex aliasing chain
    TestStruct* p4 = g_struct_ptr;
    TestStruct* p5 = p4;
    TestStruct* p6 = p5;
    double d = p6->double_field;  // Access through multiple aliases
    
    std::cout << "Test values: " << val1 << ", " << val2 << ", " 
              << field2_val << ", " << d << std::endl;
}

int main() {
    test_register_aliasing();
    return 0;
}
