cmake_minimum_required(VERSION 3.2)
project(portscanner)
include_directories(include)

add_compile_options(
        -Wall
        -Wextra
        -Wpedantic
        -Wparentheses
        -Wunused
        -Wformat=2
        -fstrict-overflow
        -Wstrict-prototypes
        -Wold-style-definition
        -Wmissing-prototypes
        -Wwrite-strings
        -Wfloat-equal
        -Wshadow
)

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 6.1)
    add_compile_options(
        -Wduplicated-cond
        -Wnull-dereference
        -Wlogical-op
    )
endif()

if(CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 7.1)
    add_compile_options(
        -Wduplicated-branches
        -Walloc-zero
    )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options(-Werror -pedantic-errors)
endif()


add_library(portscanner SHARED
        src/packet.c
        src/portscan.c
        src/route.c
        src/probe_recv.c
        src/probe_send.c
        src/bpf.c
)
set_target_properties(portscanner PROPERTIES PUBLIC_HEADER "include/portscan.h")

add_executable(portscanner_cli
        cli/main.c
)

target_link_libraries(portscanner_cli portscanner)
install(TARGETS portscanner portscanner_cli
	LIBRARY       DESTINATION lib
	RUNTIME       DESTINATION bin
	PUBLIC_HEADER DESTINATION include
)
