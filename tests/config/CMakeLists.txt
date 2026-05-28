# config tests
add_executable(run_config_tests test_actor_config.cpp test_global_config.cpp test_run_config.cpp)
target_link_libraries(run_config_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME ConfigTests COMMAND run_config_tests)

# Actor_Config_sim setup_actor tests
add_executable(run_sim_setup_tests test_actor_config_sim_setup.cpp)
target_link_libraries(run_sim_setup_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME SimSetupTests COMMAND run_sim_setup_tests)

# RunStatus utility functions tests
add_executable(run_runstatus_utils_tests test_run_status_utils.cpp)

target_link_libraries(run_runstatus_utils_tests PRIVATE
        wpa3_core
        doctest_headers
        yaml-cpp
)

add_test(NAME RunStatusUtilsTests COMMAND run_runstatus_utils_tests)

