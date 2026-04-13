# Awk scripts (separated for debugging)

file(GLOB AWK_FILES "${CMAKE_CURRENT_SOURCE_DIR}/awk_scripts/*.awk")
foreach(SOURCE_FILE ${AWK_FILES})
    get_filename_component(FILE_NAME ${SOURCE_FILE} NAME_WE)
    set(HEADER_FILE "${CMAKE_CURRENT_BINARY_DIR}/awk_scripts/generated_${FILE_NAME}.h")
    file(READ ${SOURCE_FILE} AWK_CONTENTS)
    set(VAR_NAME "AWK_SCRIPT_${FILE_NAME}")
    set(HEADER_CODE
            "#pragma once

static const char* ${VAR_NAME} = R\"awk(
${AWK_CONTENTS}
)awk\"\;
"
    )
    file(WRITE ${HEADER_FILE} ${HEADER_CODE})
endforeach()