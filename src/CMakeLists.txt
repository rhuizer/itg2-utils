cmake_minimum_required(VERSION 2.6)
project(itg2-utils)

set(SOURCES itg2-file.c itg2-file.h getput.h)
add_library(itg2-utils ${SOURCES})

add_executable(itg2-decrypt itg2-decrypt.c)
target_link_libraries(itg2-decrypt itg2-utils crypto)
