# hw_cap_tests
add_executable(hw_cap_tests test_hw_capabilities.cpp)
target_link_libraries(hw_cap_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME HWCapabilitiesTests COMMAND hw_cap_tests)

# system tests
add_executable(run_system_tests test_process_manager.cpp)
target_link_libraries(run_system_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME SystemTests COMMAND run_system_tests)

# injection check manual test
add_executable(run_injection_check_test test_injection_check.cpp)
target_link_libraries(run_injection_check_test PRIVATE
        wpa3_core
        doctest_headers
)

#if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
#    find_program(SETCAP_EXE setcap)
#    if(SETCAP_EXE)
#        add_custom_command(TARGET run_injection_check_test POST_BUILD
#                COMMAND sudo ${SETCAP_EXE} cap_net_raw,cap_net_admin=eip ${CMAKE_BINARY_DIR}/tests/system/run_injection_check_test
#        )
#    endif()
#endif()

add_test(NAME InjectionCheckTest COMMAND ${CMAKE_BINARY_DIR}/tests/system/run_injection_check_test)

#get_target_property(TEST_PATH run_injection_check_test LOCATION)
#message(STATUS "Cesta k testu (LOCATION): ${TEST_PATH}")

#add_test(NAME InjectionCheckTest COMMAND sudo $<TARGET_FILE:run_injection_check_test>)