set(CMAKE_POLICY_DEFAULT_CMP0000 OLD)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
set(CMAKE_POLICY_DEFAULT_CMP0167 NEW)

set_property(GLOBAL PROPERTY ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)
set(CMAKE_WARN_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_ERROR_DEPRECATED OFF CACHE BOOL "" FORCE)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set_property(GLOBAL PROPERTY JOB_POOLS link_job_pool=2)
set(CMAKE_JOB_POOL_LINK link_job_pool)

# NixOS: Use system packages instead of FetchContent
# When using Nix, all dependencies are provided by the environment
# We use find_package and pkg-config for system libraries

find_package(PkgConfig REQUIRED)

# NixOS: dbus-1.pc has libsystemd as a transitive dep; add system profile pkgconfig so the probe doesn't warn
if(EXISTS "/run/current-system/sw/lib/pkgconfig")
    set(ENV{PKG_CONFIG_PATH} "/run/current-system/sw/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
endif()

# Ensure we can find packages in Nix store
list(APPEND CMAKE_PREFIX_PATH ${CMAKE_INSTALL_PREFIX})

# Set common options for all dependencies
set(YAML_CPP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(YAML_CPP_BUILD_CONTRIB OFF CACHE BOOL "" FORCE)

set(DISABLE_DBUS ON CACHE BOOL "" FORCE)
set(DISABLE_RDMA ON CACHE BOOL "" FORCE)
set(PCAP_SUPPORT_RDMASNIFF 0 CACHE BOOL "" FORCE)
set(DISABLE_DAG ON CACHE BOOL "" FORCE)
set(DISABLE_SEPTEL ON CACHE BOOL "" FORCE)
set(DISABLE_SNF ON CACHE BOOL "" FORCE)
set(DISABLE_TC ON CACHE BOOL "" FORCE)
set(ENABLE_PROFILING OFF CACHE BOOL "" FORCE)

set(ARGPARSE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(ARGPARSE_BUILD_SAMPLES OFF CACHE BOOL "" FORCE)
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(JSON_VALIDATOR_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_TESTS OFF CACHE BOOL "" FORCE)
set(DOCTEST_WITH_MAIN_IN_STATIC_LIB OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(PCAP_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_CXX11 ON CACHE BOOL "" FORCE)
set(LIBTINS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_ACK_TRACKER ON CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_WPA2 ON CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_DOT11 ON CACHE BOOL "" FORCE)
set(LIBTINS_ENABLE_PCAP ON CACHE BOOL "" FORCE)
set(WITH_DBUS OFF CACHE BOOL "" FORCE)
set(REPROC_STATIC ON CACHE BOOL "" FORCE)
set(REPROC_CXX ON CACHE BOOL "" FORCE)
set(REPROC++ ON CACHE BOOL "" FORCE)
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

# Header-only libraries - find in Nix store
find_path(BOOST_PFR_INCLUDE_DIR NAMES boost/pfr.hpp
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(BOOST_PFR_INCLUDE_DIR)
    message(STATUS "Found boost_pfr headers at ${BOOST_PFR_INCLUDE_DIR}")
    include_directories(${BOOST_PFR_INCLUDE_DIR})
else()
    message(WARNING "boost_pfr not found, may need to install via Nix")
endif()

find_path(ARGPARSE_INCLUDE_DIR NAMES argparse.hpp
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(ARGPARSE_INCLUDE_DIR)
    message(STATUS "Found argparse headers at ${ARGPARSE_INCLUDE_DIR}")
    include_directories(${ARGPARSE_INCLUDE_DIR})
    add_library(argparse::argparse INTERFACE IMPORTED)
    set_target_properties(argparse::argparse PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${ARGPARSE_INCLUDE_DIR}"
    )
else()
    message(WARNING "argparse not found")
endif()

find_path(NLOHMANN_JSON_INCLUDE_DIR NAMES nlohmann/json.hpp
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(NLOHMANN_JSON_INCLUDE_DIR)
    message(STATUS "Found nlohmann/json headers at ${NLOHMANN_JSON_INCLUDE_DIR}")
    include_directories(${NLOHMANN_JSON_INCLUDE_DIR})
    add_library(nlohmann_json::nlohmann_json INTERFACE IMPORTED)
    set_target_properties(nlohmann_json::nlohmann_json PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${NLOHMANN_JSON_INCLUDE_DIR}"
    )
else()
    message(WARNING "nlohmann/json not found, may need to install via Nix")
endif()

find_path(JSON_SCHEMA_VALIDATOR_INCLUDE_DIR NAMES json-schema-validator/validator.hpp
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(JSON_SCHEMA_VALIDATOR_INCLUDE_DIR)
    message(STATUS "Found json-schema-validator headers at ${JSON_SCHEMA_VALIDATOR_INCLUDE_DIR}")
    include_directories(${JSON_SCHEMA_VALIDATOR_INCLUDE_DIR})
    add_library(nlohmann_json_schema_validator INTERFACE IMPORTED)
    set_target_properties(nlohmann_json_schema_validator PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${JSON_SCHEMA_VALIDATOR_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES nlohmann_json::nlohmann_json
    )
else()
    message(WARNING "json-schema-validator not found")
endif()

find_path(DOCTEST_INCLUDE_DIR NAMES doctest/doctest.h
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(DOCTEST_INCLUDE_DIR)
    message(STATUS "Found doctest headers at ${DOCTEST_INCLUDE_DIR}")
    include_directories(${DOCTEST_INCLUDE_DIR})
    add_library(doctest_headers INTERFACE IMPORTED)
    set_target_properties(doctest_headers PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${DOCTEST_INCLUDE_DIR}"
    )
    add_library(doctest INTERFACE IMPORTED)
    set_target_properties(doctest PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${DOCTEST_INCLUDE_DIR}"
    )
else()
    message(WARNING "doctest not found, may need to install via Nix")
endif()

# System libraries with pkg-config
pkg_check_modules(SYSTEM_PCAP libpcap)
if (SYSTEM_PCAP_FOUND)
    message(STATUS "Using system libpcap ${SYSTEM_PCAP_VERSION}")
    add_library(pcap_imported SHARED IMPORTED GLOBAL)
    set_target_properties(pcap_imported PROPERTIES
            IMPORTED_LOCATION ${SYSTEM_PCAP_LINK_LIBRARIES}
            INTERFACE_INCLUDE_DIRECTORIES "${SYSTEM_PCAP_INCLUDE_DIRS}"
    )
    set(PCAP_INCLUDE_DIR "${SYSTEM_PCAP_INCLUDE_DIRS}" CACHE PATH "" FORCE)
    set(PCAP_LIBRARY "${SYSTEM_PCAP_LINK_LIBRARIES}" CACHE FILEPATH "" FORCE)
    set(PCAP_FOUND TRUE CACHE BOOL "" FORCE)
    set(PCAP_LINKS_SOLO TRUE CACHE BOOL "" FORCE)
    include_directories(${SYSTEM_PCAP_INCLUDE_DIRS})
else ()
    message(FATAL_ERROR "libpcap not found via pkg-config")
endif ()

# libtins
pkg_check_modules(LIBTINS QUIET libtins)
if(LIBTINS_FOUND)
    message(STATUS "Using system libtins via pkg-config")
    add_library(tins_lib INTERFACE IMPORTED GLOBAL)
    set_target_properties(tins_lib PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${LIBTINS_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${LIBTINS_LIBRARIES}"
    )
    include_directories(${LIBTINS_INCLUDE_DIRS})
else()
    find_library(TINS_LIBRARY NAMES tins
        PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_INSTALL_PREFIX}/lib /usr/lib /usr/lib64
    )
    find_path(TINS_INCLUDE_DIR NAMES tins/tins.h
        PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
    )
    if(TINS_LIBRARY AND TINS_INCLUDE_DIR)
        message(STATUS "Found libtins: ${TINS_LIBRARY}")
        add_library(tins_lib STATIC IMPORTED GLOBAL)
        set_target_properties(tins_lib PROPERTIES
                IMPORTED_LOCATION ${TINS_LIBRARY}
                INTERFACE_INCLUDE_DIRECTORIES "${TINS_INCLUDE_DIR}"
        )
        set(LIBTINS_FOUND TRUE CACHE BOOL "" FORCE)
        include_directories(${TINS_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "libtins not found")
    endif()
endif()

# reproc++
find_path(REPROC_INCLUDE_DIR NAMES reproc++/reproc.hpp
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
find_library(REPROC_LIBRARY NAMES reproc
    PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_INSTALL_PREFIX}/lib /usr/lib /usr/lib64
)
if(REPROC_INCLUDE_DIR)
    message(STATUS "Found reproc++ headers at ${REPROC_INCLUDE_DIR}")
    include_directories(${REPROC_INCLUDE_DIR})
    add_library(reproc_lib INTERFACE)
    target_include_directories(reproc_lib SYSTEM INTERFACE ${REPROC_INCLUDE_DIR})
    if(REPROC_LIBRARY)
        message(STATUS "Found reproc library at ${REPROC_LIBRARY}")
        target_link_libraries(reproc_lib INTERFACE ${REPROC_LIBRARY})
    else()
        message(WARNING "reproc library not found, only headers will be available")
    endif()
else()
    message(FATAL_ERROR "reproc++ not found")
endif()

# linux_headers_wifi - download the header file
find_path(LINUX_NL80211_INCLUDE_DIR NAMES linux/nl80211.h
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(NOT LINUX_NL80211_INCLUDE_DIR)
    message(STATUS "Downloading linux/nl80211.h")
    file(DOWNLOAD https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/nl80211.h
        ${CMAKE_BINARY_DIR}/nl80211.h
    )
    set(LINUX_NL80211_INCLUDE_DIR ${CMAKE_BINARY_DIR})
    file(WRITE ${CMAKE_BINARY_DIR}/linux/nl80211.h "#include \"nl80211.h\"\n")
endif()
include_directories(${LINUX_NL80211_INCLUDE_DIR})

# radiotap
find_path(RADIOTAP_INCLUDE_DIR NAMES radiotap/radiotap.h
    PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
)
if(NOT RADIOTAP_INCLUDE_DIR)
    message(STATUS "Using bundled radiotap")
    file(DOWNLOAD https://raw.githubusercontent.com/radiotap/radiotap-library/master/radiotap.c
        ${CMAKE_BINARY_DIR}/radiotap.c
    )
    file(DOWNLOAD https://raw.githubusercontent.com/radiotap/radiotap-library/master/radiotap.h
        ${CMAKE_BINARY_DIR}/radiotap.h
    )
    set(RADIOTAP_INCLUDE_DIR ${CMAKE_BINARY_DIR})
    set(RADIOTAP_SOURCE_DIR ${CMAKE_BINARY_DIR})
else()
    find_path(RADIOTAP_SOURCE_DIR NAMES radiotap/radiotap.c
        PATHS ${CMAKE_PREFIX_PATH} ${CMAKE_INSTALL_PREFIX}
    )
    if(NOT RADIOTAP_SOURCE_DIR)
        set(RADIOTAP_SOURCE_DIR ${RADIOTAP_INCLUDE_DIR}/..)
    endif()
endif()

add_library(radiotap_lib STATIC "${RADIOTAP_SOURCE_DIR}/radiotap.c")
target_include_directories(radiotap_lib PUBLIC ${RADIOTAP_INCLUDE_DIR})
set_source_files_properties("${RADIOTAP_SOURCE_DIR}/radiotap.c" PROPERTIES
        SKIP_PRECOMPILE_HEADERS ON
        COMPILE_OPTIONS "-Wno-address-of-packed-member"
)

# yaml-cpp
pkg_check_modules(YAML_CPP QUIET yaml-cpp)
if(YAML_CPP_FOUND)
    message(STATUS "Using system yaml-cpp via pkg-config")
    add_library(yaml-cpp_lib INTERFACE IMPORTED GLOBAL)
    set_target_properties(yaml-cpp_lib PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${YAML_CPP_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES "${YAML_CPP_LIBRARIES}"
    )
    include_directories(${YAML_CPP_INCLUDE_DIRS})
else()
    find_library(YAML_CPP_LIBRARY NAMES yaml-cpp
        PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_INSTALL_PREFIX}/lib /usr/lib /usr/lib64
    )
    find_path(YAML_CPP_INCLUDE_DIR NAMES yaml-cpp/yaml.h
        PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
    )
    if(YAML_CPP_LIBRARY AND YAML_CPP_INCLUDE_DIR)
        message(STATUS "Found yaml-cpp: ${YAML_CPP_LIBRARY}")
        add_library(yaml-cpp_lib STATIC IMPORTED GLOBAL)
        set_target_properties(yaml-cpp_lib PROPERTIES
                IMPORTED_LOCATION ${YAML_CPP_LIBRARY}
                INTERFACE_INCLUDE_DIRECTORIES "${YAML_CPP_INCLUDE_DIR}"
        )
        include_directories(${YAML_CPP_INCLUDE_DIR})
    else()
        message(FATAL_ERROR "yaml-cpp not found")
    endif()
endif()

# libssh
pkg_check_modules(LIBSSH libssh)
if (NOT LIBSSH_FOUND)
    find_library(LIBSSH_LIBRARY NAMES ssh
        PATHS ${CMAKE_PREFIX_PATH}/lib ${CMAKE_INSTALL_PREFIX}/lib /usr/lib /usr/lib64
    )
    find_path(LIBSSH_INCLUDE_DIR NAMES libssh/sftp.h
        PATHS ${CMAKE_PREFIX_PATH}/include ${CMAKE_INSTALL_PREFIX}/include /usr/include
    )
    if(LIBSSH_LIBRARY AND LIBSSH_INCLUDE_DIR)
        message(STATUS "Found libssh: ${LIBSSH_LIBRARY}")
        add_library(libssh_imported SHARED IMPORTED GLOBAL)
        set_target_properties(libssh_imported PROPERTIES
                IMPORTED_LOCATION ${LIBSSH_LIBRARY}
                INTERFACE_INCLUDE_DIRECTORIES "${LIBSSH_INCLUDE_DIR}"
        )
        include_directories(${LIBSSH_INCLUDE_DIR})
        list(APPEND CMAKE_BUILD_RPATH ${LIBSSH_LIBRARY_DIRS})
    else()
        message(FATAL_ERROR "libssh not found")
    endif()
else()
    list(APPEND CMAKE_BUILD_RPATH ${LIBSSH_LIBRARY_DIRS})
endif()

# Ensure RPATH includes Nix store paths
pkg_check_modules(LIBNL REQUIRED libnl-3.0 libnl-genl-3.0)
list(APPEND CMAKE_BUILD_RPATH ${LIBNL_LIBRARY_DIRS})

# Add Nix store to RPATH
list(APPEND CMAKE_BUILD_RPATH ${CMAKE_INSTALL_PREFIX}/lib)
