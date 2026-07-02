add_doctest_exe(run_parse_acm_response_tests SOURCES test_parse_acm_response.cpp TEST_NAME ParseACMResponseTests LIBS test_helpers tins)

# Copy test data file to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ACM_commit_test.pcapng
        ${CMAKE_CURRENT_BINARY_DIR}/ACM_commit_test.pcapng
        COPYONLY)
