# bl0ck attack tests
add_executable(run_bl0ck_tests test_bl0ck_frame.cpp)

target_link_libraries(run_bl0ck_tests PRIVATE
        wpa3_core
        doctest_headers
        tins
)

add_test(NAME Bl0ckFrameTests COMMAND run_bl0ck_tests)

