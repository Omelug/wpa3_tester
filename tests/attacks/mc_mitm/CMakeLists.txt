# mc_mitm attack tests
add_executable(run_mc_mitm_tests test_mc_mitm.cpp)

target_link_libraries(run_mc_mitm_tests PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

set(TEST_DATA_FILES
        beacon_test.pcapng
        probe_res.pcapng
)

# TODO better than configure_file
foreach (data_file ${TEST_DATA_FILES})
    add_custom_command(
            TARGET run_mc_mitm_tests POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/${data_file}
            ${CMAKE_CURRENT_BINARY_DIR}/${data_file}
            COMMENT "Copying ${data_file} to build directory"
    )
endforeach ()

add_test(NAME McMitmTests COMMAND run_mc_mitm_tests)
