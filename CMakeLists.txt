cmake_minimum_required(VERSION 3.2)
project(portscanner)
include_directories(include)

add_library(portscanner SHARED
        src/packet.c
        src/portscan.c
        src/route.c
        src/probe_recv.c
        src/probe_send.c
)

add_executable(portscanner_cli
        cli/main.c
)

target_link_libraries(portscanner_cli portscanner)
