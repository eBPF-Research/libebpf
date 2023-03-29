cmake_minimum_required(VERSION 3.10)
project(HelloWorld C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

add_executable(HelloWorld hello.c)

# set the -static flag for static linking
set_target_properties(HelloWorld PROPERTIES LINK_FLAGS "-static")
