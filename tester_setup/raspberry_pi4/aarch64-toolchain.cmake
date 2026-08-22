set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
set(CMAKE_LIBRARY_ARCHITECTURE aarch64-linux-gnu)   # makes find_package search lib/aarch64-linux-gnu/cmake/

# Use the aarch64 cross gcc/g++ directly — avoids clang cc-wrapper issues on NixOS
# PATH sources:
#   NixOS cross shell : aarch64-unknown-linux-gnu-{gcc,g++}  (crossPkgs.buildPackages.gcc)
#   Debian/Kali       : aarch64-linux-gnu-{gcc,g++}          (gcc-aarch64-linux-gnu)
find_program(CMAKE_C_COMPILER
    NAMES aarch64-linux-gnu-gcc aarch64-unknown-linux-gnu-gcc
    DOC "aarch64 C cross-compiler" REQUIRED)
find_program(CMAKE_CXX_COMPILER
    NAMES aarch64-linux-gnu-g++ aarch64-unknown-linux-gnu-g++
    DOC "aarch64 C++ cross-compiler" REQUIRED)

# prefer mold (faster), fall back to lld — both are multiarch
find_program(MOLD_EXE mold NO_CMAKE_FIND_ROOT_PATH)
if(MOLD_EXE)
    set(_LD "-fuse-ld=mold")
else()
    set(_LD "-fuse-ld=lld")
endif()
# FORCE so these survive re-configure with stale CMakeCache
set(CMAKE_EXE_LINKER_FLAGS    "${_LD} -static-libstdc++ -static-libgcc -Wl,--dynamic-linker=/lib/ld-linux-aarch64.so.1" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "${_LD}" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "${_LD}" CACHE STRING "" FORCE)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)   # run host tools (cmake, ninja)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)    # libs only from sysroot
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
