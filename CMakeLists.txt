cmake_minimum_required(VERSION 3.17)
project(GlobalCallAnalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(external/zydis)

include_directories(include external/zydis/include)

# Main executable - choose version based on build type
if(CMAKE_SYSTEM_NAME STREQUAL "Windows" OR FORCE_WINDOWS_BUILD)
    # Windows PE version (cross-compiled or native)
    add_executable(GlobalCallAnalyzer src/main.cpp src/GlobalCallAnalyzer.cpp)
    # Link Windows libraries when cross-compiling
    if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
        target_link_libraries(GlobalCallAnalyzer PRIVATE kernel32 psapi)
    endif()
else()
    # Linux ELF version (native)
    add_executable(GlobalCallAnalyzer src/main_linux.cpp src/GlobalCallAnalyzer.cpp)
endif()

# Common settings
target_compile_definitions(GlobalCallAnalyzer PRIVATE GCA_ENABLE_PAR=0)
target_link_libraries(GlobalCallAnalyzer PRIVATE Zydis::Zydis)

# Add the test program executable
add_executable(TestProgram src/test_program.cpp)

