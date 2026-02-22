# hostapd helper tests
add_executable(run_hostapd_tests test_hostapd_helper.cpp)

target_link_libraries(run_hostapd_tests PRIVATE
        wpa3_core
        doctest_headers
)

add_test(NAME HostapdHelperTests COMMAND run_hostapd_tests)

