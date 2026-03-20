# logger time tests
add_executable(run_logger_time_tests test_log_time.cpp)
target_link_libraries(run_logger_time_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME LoggerTimeTests COMMAND run_logger_time_tests)

# logger tests
add_executable(run_logger_tests test_log.cpp)
target_link_libraries(run_logger_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME LoggerTests COMMAND run_logger_tests)

# error message tests
add_executable(run_error_message_tests test_error_messages.cpp)
target_link_libraries(run_error_message_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME ErrorMessageTests COMMAND run_error_message_tests)

