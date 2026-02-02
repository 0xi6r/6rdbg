cmake_minimum_required(VERSION 3.14)
project(6rdbg C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform detection
if(WIN32)
    set(PLATFORM_WINDOWS TRUE)
    add_definitions(-DPLATFORM_WINDOWS=1)
else()
    set(PLATFORM_WINDOWS FALSE)
    add_definitions(-DPLATFORM_WINDOWS=0)
endif()

# Architecture detection
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    add_definitions(-DTARGET_X64=1)
else()
    add_definitions(-DTARGET_X64=0)
endif()

# Source files
set(COMMON_SOURCES
    src/disasm.c
    src/command_parser.c
    src/ui_common.c
)

if(WIN32)
    set(PLATFORM_SOURCES
        src/debugger_platform.c
        src/ui_platform.c
    )
    
    set(PLATFORM_LIBS
        dbghelp
        psapi
    )
    
    set(OUTPUT_NAME "6rdbg.exe")
else()
    set(PLATFORM_SOURCES
        src/debugger_platform.c
        src/ui_platform.c
    )
    
    set(PLATFORM_LIBS
        ncursesw
    )
    
    set(OUTPUT_NAME "6rdbg")
endif()

# All sources
set(SOURCES
    src/main.c
    src/debugger_platform.c
    src/ui_platform.c
    src/ui_common.c
    src/disasm.c
    src/command_parser.c
)

# Create executable
add_executable(${OUTPUT_NAME} ${SOURCES})

# Include directories
target_include_directories(${OUTPUT_NAME} PRIVATE src)

# Link libraries
if(WIN32)
    target_link_libraries(${OUTPUT_NAME} ${PLATFORM_LIBS})
    
    # Set Windows subsystem
    set_target_properties(${OUTPUT_NAME} PROPERTIES
        WIN32_EXECUTABLE FALSE
    )
else()
    target_link_libraries(${OUTPUT_NAME} ${PLATFORM_LIBS} pthread)
    
    # Set install rpath for ncurses
    set_target_properties(${OUTPUT_NAME} PROPERTIES
        INSTALL_RPATH "$ORIGIN"
    )
endif()

# Compiler-specific options
if(MSVC)
    target_compile_options(${OUTPUT_NAME} PRIVATE
        /W4
        /D_CRT_SECURE_NO_WARNINGS
    )
else()
    target_compile_options(${OUTPUT_NAME} PRIVATE
        -Wall
        -Wextra
        -Wno-unused-parameter
        -Wno-unused-function
    )
    
    # Debug flags
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        target_compile_options(${OUTPUT_NAME} PRIVATE -g -O0)
    else()
        target_compile_options(${OUTPUT_NAME} PRIVATE -O2)
    endif()
endif()

# Install target
install(TARGETS ${OUTPUT_NAME} DESTINATION bin)

# Print configuration info
message(STATUS "Building 6rdbg for: ${CMAKE_SYSTEM_NAME}")
message(STATUS "Architecture: ${CMAKE_SYSTEM_PROCESSOR}")
message(STATUS "Target: ${OUTPUT_NAME}")
message(STATUS "Platform libraries: ${PLATFORM_LIBS}")