# config tests
add_executable(run_config_tests test_actor_config.cpp test_global_config.cpp)
target_link_libraries(run_config_tests PRIVATE
        wpa3_core
        doctest_headers
)
add_test(NAME ConfigTests COMMAND run_config_tests)

