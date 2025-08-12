cmake_minimum_required(VERSION 3.17)
project(GlobalCallAnalyzer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(external/zydis)

include_directories(include external/zydis/include)

add_executable(GlobalCallAnalyzer src/main.cpp src/GlobalCallAnalyzer.cpp)
target_link_libraries(GlobalCallAnalyzer PRIVATE Zydis::Zydis)

# Add the test program executable
add_executable(TestProgram src/test_program.cpp)

