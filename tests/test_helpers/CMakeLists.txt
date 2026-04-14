file(GLOB HELPERS_SOURCES "./*.cpp")

add_library(test_helpers STATIC ${HELPERS_SOURCES})

target_include_directories(test_helpers PUBLIC .)

target_link_libraries(test_helpers PUBLIC
        wpa3_deps
        tins
)