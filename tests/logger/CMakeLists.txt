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

# report guard tests
add_executable(run_report_guard_tests test_report_guard.cpp)
target_link_libraries(run_report_guard_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME ReportGuardTests COMMAND run_report_guard_tests)

# html guard tests
add_executable(run_html_guard_tests test_html_guard.cpp)
target_include_directories(run_html_guard_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/result_overview/include
)
target_link_libraries(run_html_guard_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME HtmlGuardTests COMMAND run_html_guard_tests)

