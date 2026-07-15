if(NOT ENABLE_ASAN)
    return()
endif()

if(CMAKE_CROSSCOMPILING)
    message(FATAL_ERROR "ENABLE_ASAN is not supported for cross-compilation")
endif()

message(STATUS "ASan/LSan enabled — clean rebuild needed when toggling this option")

add_compile_options(-fsanitize=address,leak -fno-omit-frame-pointer -g)
add_link_options(-fsanitize=address,leak)

# Known benign leaks from third-party libraries (one-time global init that is
# never freed by design — not a bug, just a common C library pattern).
set(_LSAN_SUPP "${CMAKE_BINARY_DIR}/lsan.supp")
file(WRITE "${_LSAN_SUPP}"
"# OpenSSL one-time global init
leak:CRYPTO_
leak:EVP_
# libnl socket/cache internals
leak:nl_socket_alloc
leak:nlmsg_alloc
# yaml-cpp global state
leak:YAML::
")

add_custom_target(leak-check
    COMMAND sudo -E env
        LSAN_OPTIONS=suppressions=${_LSAN_SUPP}:print_suppressions=0
        ASAN_OPTIONS=detect_leaks=1:halt_on_error=0:print_stats=1
        ${CMAKE_CTEST_COMMAND}
            --test-dir ${CMAKE_BINARY_DIR}
            --output-on-failure

    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL
    COMMENT "Running tests under AddressSanitizer + LeakSanitizer"
)
