# DoS_hard attack tests
add_subdirectory(pmk_gobbler)

add_doctest_exe(run_sae_helpers SOURCES test_sae_helper.cpp TEST_NAME SAE_helpers LIBS test_helpers tins)
