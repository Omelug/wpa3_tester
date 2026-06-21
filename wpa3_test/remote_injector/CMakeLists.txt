cmake_minimum_required(VERSION 3.20)
project(remote_injector C)

execute_process(COMMAND uname -m OUTPUT_VARIABLE HOST_ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)

# Host-arch binary
add_executable(remote_injector_${HOST_ARCH} main.c)
set_target_properties(remote_injector_${HOST_ARCH} PROPERTIES
    C_STANDARD 17
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Cross-compilation targets via musl.cc prebuilt toolchains.
# Usage: cmake --build . --target remote_injector_mips   (or aarch64, armv7l, ...)
set(MUSL_TOOLCHAIN_DIR "$ENV{HOME}/.musl-cross")

set(CROSS_TARGETS
    mips     mips-linux-musl
    mipsel   mipsel-linux-musl
    aarch64  aarch64-linux-musl
    armv7l   arm-linux-musleabihf
)

list(LENGTH CROSS_TARGETS _len)
math(EXPR _last "${_len} - 1")

foreach(_i RANGE 0 ${_last} 2)
    math(EXPR _j "${_i} + 1")
    list(GET CROSS_TARGETS ${_i} _arch)
    list(GET CROSS_TARGETS ${_j} _triple)

    if(NOT _arch STREQUAL HOST_ARCH)
        set(_gcc "${MUSL_TOOLCHAIN_DIR}/${_triple}-cross/bin/${_triple}-gcc")
        set(_out "${CMAKE_BINARY_DIR}/bin/remote_injector_${_arch}")

        add_custom_target(remote_injector_${_arch}
            COMMAND ${CMAKE_COMMAND} -E echo "Cross-compiling for ${_arch} using ${_gcc}"
            COMMAND ${_gcc} -O2 -static -o ${_out}
                    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
            COMMENT "Building remote_injector_${_arch}"
            VERBATIM
        )
    endif()
endforeach()

# Helper target: download all musl cross toolchains and build all arch variants
add_custom_target(remote_injector_all_arch
    COMMAND ${CMAKE_COMMAND} -E make_directory ${MUSL_TOOLCHAIN_DIR}
    COMMAND ${CMAKE_COMMAND} -E echo "Downloading musl cross toolchains..."
    COMMAND bash -c [=[
        set -e
        BASE="https://musl.cc"
        DIR="]=] + "${MUSL_TOOLCHAIN_DIR}" + [=["
        for triple in mips-linux-musl mipsel-linux-musl aarch64-linux-musl arm-linux-musleabihf; do
            tarball="${triple}-cross.tgz"
            if [ ! -d "${DIR}/${triple}-cross" ]; then
                echo "Downloading ${tarball}..."
                curl -L "${BASE}/${tarball}" | tar xz -C "${DIR}"
            fi
        done
    ]=]
    COMMENT "Downloading musl toolchains to ${MUSL_TOOLCHAIN_DIR}"
    VERBATIM
)
add_dependencies(remote_injector_all_arch
    remote_injector_mips remote_injector_mipsel remote_injector_aarch64 remote_injector_armv7l
)
