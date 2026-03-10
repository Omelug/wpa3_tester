# Manual tests - for runtime verification by testers
# These tests require manual inspection of results

file(GLOB MANUAL_TEST_CORE_SOURCES
        "${CMAKE_CURRENT_SOURCE_DIR}/manual_test_core/*.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/manual_test_core/*.h"
)

message(STATUS "MANUAL_TEST_CORE_SOURCES sources: ${MANUAL_TEST_CORE_SOURCES}")
add_library(manual_test_core STATIC ${MANUAL_TEST_CORE_SOURCES})
target_link_libraries(manual_test_core PUBLIC wpa3_core tins)

# Manual test executables
add_executable(test_list_external_entities "./list_external_entities.cpp")
target_link_libraries(test_list_external_entities PRIVATE manual_test_core)

set_target_properties(test_list_external_entities PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/bin/manual_tests"
)
