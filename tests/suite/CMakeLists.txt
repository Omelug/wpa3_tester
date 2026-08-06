
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/../test_data DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_result_helper_tests SOURCES test_result_helper.cpp TEST_NAME ResultHelperTests LIBS wpa3_suite)
add_doctest_exe(run_entry_parse_tests SOURCES test_entry_parse.cpp TEST_NAME EntryParseTests LIBS test_helpers)
