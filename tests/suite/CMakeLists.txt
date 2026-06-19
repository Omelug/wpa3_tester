add_executable(run_result_helper_tests test_result_helper.cpp)
target_link_libraries(run_result_helper_tests PRIVATE
        wpa3_suite
        wpa3_core
        doctest_headers
)
add_test(NAME ResultHelperTests COMMAND run_result_helper_tests)