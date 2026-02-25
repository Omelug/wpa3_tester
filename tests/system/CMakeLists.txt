# system tests
add_executable(run_system_tests test_process_manager.cpp)
target_link_libraries(run_system_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME SystemTests COMMAND run_system_tests)
