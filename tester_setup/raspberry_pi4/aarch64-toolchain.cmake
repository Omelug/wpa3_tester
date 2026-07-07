set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# clang is a native cross-compiler — gcc-aarch64-linux-gnu provides crt/libgcc
set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER_TARGET   aarch64-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-gnu)

# Tell clang where to find crtbeginS.o / libgcc from the GCC cross-toolchain.
# --sysroot would otherwise hide /usr from clang's search.
set(CMAKE_C_FLAGS_INIT   "--gcc-toolchain=/usr")
set(CMAKE_CXX_FLAGS_INIT "--gcc-toolchain=/usr")

# lld as cross-linker
set(CMAKE_EXE_LINKER_FLAGS_INIT    "-fuse-ld=lld")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "-fuse-ld=lld")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "-fuse-ld=lld")

# CMAKE_SYSROOT is passed from the command line by make sysroot/deploy-cross
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # run host tools (cmake, ninja)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)    # libs only from sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
