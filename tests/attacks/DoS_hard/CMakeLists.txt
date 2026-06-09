# DoS_hard attack tests
add_subdirectory(cookie_guzzler)
add_subdirectory(pmk_gobbler)
#add_subdirectory(memory_omnivore)

# sae_helpers
add_executable(run_sae_helpers ./test_sae_helper.cpp)

target_link_libraries(run_sae_helpers PRIVATE
        test_helpers
        wpa3_core
        doctest_headers
        tins
)

add_test(NAME SAE_helpers COMMAND run_sae_helpers)
