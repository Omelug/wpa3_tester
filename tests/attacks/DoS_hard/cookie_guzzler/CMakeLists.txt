# cookie_guzzler attack tests
add_executable(run_cookie_guzzler_tests test_cookie_guzzler_frame.cpp)

target_link_libraries(run_cookie_guzzler_tests PRIVATE
        wpa3_core
        doctest_headers
        tins
)

add_test(NAME CookieGuzzlerFrameTests COMMAND run_cookie_guzzler_tests)

# SAE callback tests
add_executable(run_sae_callback_tests test_dos_helpers.cpp)

target_link_libraries(run_sae_callback_tests PRIVATE
        wpa3_core
        doctest_headers
        tins
)

add_test(NAME CallbackTests COMMAND run_sae_callback_tests)
