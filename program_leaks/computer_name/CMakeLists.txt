cmake_minimum_required(VERSION 3.16)
project(poc)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(poc
        avleak.c
        avleak.h
        poc.rc
        poc.c)
