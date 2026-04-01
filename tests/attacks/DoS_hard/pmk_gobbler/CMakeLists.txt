# pmk_gobbler attack tests
add_executable(run_parse_acm_response_tests test_parse_acm_response.cpp)

target_link_libraries(run_parse_acm_response_tests PRIVATE
        wpa3_core
        doctest_headers
        tins
)

# Copy test data file to build directory
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ACM_commit_test.pcapng 
               ${CMAKE_CURRENT_BINARY_DIR}/ACM_commit_test.pcapng 
               COPYONLY)

add_test(NAME ParseACMResponseTests COMMAND run_parse_acm_response_tests)
