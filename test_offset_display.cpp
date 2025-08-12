#include <iostream>
#include <cstdint>
#include <iomanip>

// Test how our offset display logic works
void test_offset_display(int64_t offset) {
    if (offset < 0) {
        std::cout << "  [-0x" << std::hex << -offset << "]" << std::endl;
    } else {
        std::cout << "  [+0x" << std::hex << offset << "]" << std::endl;
    }
}

int main() {
    std::cout << "Testing offset display logic:" << std::endl;
    
    // Test positive offsets
    test_offset_display(0);
    test_offset_display(8);
    test_offset_display(0x100);
    
    // Test negative offsets
    test_offset_display(-8);
    test_offset_display(-0x10);
    test_offset_display(-0x100);
    
    // Test the specific case from the issue
    int64_t problematic_offset = -8;
    std::cout << "\nProblematic offset -8:" << std::endl;
    std::cout << "  As uint64_t: 0x" << std::hex << static_cast<uint64_t>(problematic_offset) << std::endl;
    std::cout << "  As int64_t: " << std::dec << problematic_offset << std::endl;
    test_offset_display(problematic_offset);
    
    return 0;
}
