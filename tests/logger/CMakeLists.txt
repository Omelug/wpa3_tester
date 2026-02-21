# logger tests
add_executable(run_logger_tests test_log_time.cpp)
target_link_libraries(run_logger_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME LoggerTests COMMAND run_logger_tests)
