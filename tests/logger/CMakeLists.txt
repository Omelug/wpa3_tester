add_doctest_exe(run_logger_time_tests SOURCES test_log_time.cpp TEST_NAME LoggerTimeTests)
add_doctest_exe(run_logger_tests SOURCES test_log.cpp TEST_NAME LoggerTests)
add_doctest_exe(run_error_message_tests SOURCES test_error_messages.cpp TEST_NAME ErrorMessageTests)
add_doctest_exe(run_report_guard_tests SOURCES test_report_guard.cpp TEST_NAME ReportGuardTests)

add_doctest_exe(run_html_guard_tests SOURCES test_html_guard.cpp TEST_NAME HtmlGuardTests)
target_include_directories(run_html_guard_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../result_overview/include
)

add_doctest_exe(run_devices_tests SOURCES test_devices.cpp TEST_NAME DevicesTests LIBS test_helpers)
