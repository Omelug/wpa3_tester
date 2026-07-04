add_doctest_exe(run_config_tests
        SOURCES test_actor_config.cpp test_global_config.cpp test_run_config.cpp
        TEST_NAME ConfigTests
)
add_doctest_exe(run_sim_setup_tests SOURCES test_actor_config_sim_setup.cpp TEST_NAME SimSetupTests)
add_doctest_exe(run_runstatus_utils_tests SOURCES test_run_status_utils.cpp TEST_NAME RunStatusUtilsTests LIBS yaml-cpp)
