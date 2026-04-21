find_package(PkgConfig REQUIRED)
set(REQUIRED_PACKAGES
        "libpcap"
        "openssl"
        "libnl-3.0"
        "libnl-genl-3.0"
        "yaml-cpp"
        "libtins"
)

foreach(pkg ${REQUIRED_PACKAGES})
    pkg_check_modules(${pkg}_PKG REQUIRED ${pkg})
endforeach()

macro(glob_src VAR DIR)
    file(GLOB_RECURSE ${VAR} CONFIGURE_DEPENDS "${DIR}/*.cpp")
endmacro()
glob_src(SYSTEM_SRC     "src/system")
glob_src(LOGGER_SRC     "src/logger")
glob_src(CONFIG_SRC     "src/config")
glob_src(OBSERVER_SRC   "src/observer")
glob_src(SCAN_SRC       "src/scan")
glob_src(EX_PROG_SRC    "src/ex_program")
glob_src(SETUP_SRC      "src/setup")
glob_src(SUITE_SRC      "src/suite")

glob_src(ATT_BY_target_SRC "src/attacks/by_target")
glob_src(ATT_COMP_SRC   "src/attacks/components")
glob_src(DOS_HARD_SRC   "src/attacks/DoS_hard")
glob_src(DOS_SOFT_SRC   "src/attacks/DoS_soft")
glob_src(ENTERPRISE_SRC "src/attacks/Enterprise")
glob_src(MC_MITM_SRC    "src/attacks/mc_mitm")
#file(GLOB ATTACKS_SRC CONFIGURE_DEPENDS  "src/attacks/attacks.cpp")

macro(wpa3_library NAME)
    add_library(${NAME} STATIC ${ARGN})
    target_link_libraries(${NAME} PUBLIC wpa3_deps)
endmacro()

wpa3_library(wpa3_system     ${SYSTEM_SRC})
wpa3_library(wpa3_logger     ${LOGGER_SRC})
wpa3_library(wpa3_config     ${CONFIG_SRC})
wpa3_library(wpa3_observer   ${OBSERVER_SRC})
wpa3_library(wpa3_scan       ${SCAN_SRC})
wpa3_library(wpa3_ex_program ${EX_PROG_SRC})
wpa3_library(wpa3_setup      ${SETUP_SRC})
wpa3_library(wpa3_suite      ${SUITE_SRC})
# attacks
wpa3_library(wpa3_by_target ${ATT_BY_target_SRC})
wpa3_library(wpa3_components ${ATT_COMP_SRC})
wpa3_library(wpa3_dos_hard   ${DOS_HARD_SRC})
wpa3_library(wpa3_dos_soft   ${DOS_SOFT_SRC})
wpa3_library(wpa3_enterprise ${ENTERPRISE_SRC})
wpa3_library(wpa3_mc_mitm    ${MC_MITM_SRC})

add_library(wpa3_core INTERFACE)
#add_library(wpa3_core STATIC )
#target_link_libraries(wpa3_core PUBLIC wpa3_deps)