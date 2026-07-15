# DoS_hard attack tests
add_subdirectory(pmk_gobbler)

file(COPY cookie_guzzler/test_sae_commit.pcapng DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

add_doctest_exe(run_sae_helpers SOURCES test_sae_helper.cpp TEST_NAME SAE_helpers LIBS test_helpers tins)
target_compile_definitions(run_sae_helpers PRIVATE TEST_DATA_DIR=".")
