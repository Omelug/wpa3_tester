cmake_minimum_required(VERSION 4.0)
project(wpa3_tester)

set(CMAKE_CXX_STANDARD 20)

# libraries
find_package(yaml-cpp REQUIRED)

add_executable(wpa3_tester main.cpp)

target_link_libraries(wpa3_tester PRIVATE yaml-cpp)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib/external)

