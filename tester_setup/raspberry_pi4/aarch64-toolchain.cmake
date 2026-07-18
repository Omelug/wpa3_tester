set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_C_COMPILER   clang)
set(CMAKE_CXX_COMPILER clang++)
set(CMAKE_C_COMPILER_TARGET   aarch64-linux-gnu)
set(CMAKE_CXX_COMPILER_TARGET aarch64-linux-gnu)

# Tell clang where to find crtbeginS.o / libgcc from the GCC cross-toolchain.
# --sysroot would otherwise hide /usr from clang's search.
set(CMAKE_C_FLAGS_INIT   "--gcc-toolchain=/usr -ffile-prefix-map=${CMAKE_SOURCE_DIR}/=./")
set(CMAKE_CXX_FLAGS_INIT "--gcc-toolchain=/usr -ffile-prefix-map=${CMAKE_SOURCE_DIR}/=./")

# prefer mold (faster), fall back to lld
find_program(MOLD_EXE mold NO_CMAKE_FIND_ROOT_PATH)
if(MOLD_EXE)
    set(_LD "-fuse-ld=mold")
else()
    set(_LD "-fuse-ld=lld")
endif()
set(CMAKE_EXE_LINKER_FLAGS_INIT    "${_LD} -static-libstdc++ -static-libgcc")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_LD}")
set(CMAKE_MODULE_LINKER_FLAGS_INIT "${_LD}")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # run host tools (cmake, ninja)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)    # libs only from sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
