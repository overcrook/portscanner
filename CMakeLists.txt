cmake_minimum_required(VERSION 3.2)
project(portscanner)
include_directories(include)

add_library(portscanner SHARED
        src/portscan.c
        src/route.c
)
