set(_RELEASE_BUILD_DIR "${CMAKE_BINARY_DIR}/release-build")

add_custom_target(release
    COMMAND ${CMAKE_COMMAND}
        -S ${CMAKE_SOURCE_DIR}
        -B ${_RELEASE_BUILD_DIR}
        -DCMAKE_BUILD_TYPE=Release
        "-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -flto=auto"
        "-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -flto=auto"
        "-DCMAKE_EXE_LINKER_FLAGS=-flto=auto -Wl,--strip-all"
        -DENABLE_ASAN=OFF
        -DENABLE_COVERAGE=OFF
        "-DFETCHCONTENT_BASE_DIR=${CMAKE_BINARY_DIR}"
    COMMAND ${CMAKE_COMMAND} --build ${_RELEASE_BUILD_DIR}
        --target wpa3_tester
        --parallel
    VERBATIM
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    USES_TERMINAL
    COMMENT "Release binary → ${_RELEASE_BUILD_DIR}/bin/wpa3_tester"
)
