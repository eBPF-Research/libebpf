cmake_minimum_required(VERSION 3.15)

#
# Project details
#

project(
  vm-exten
  LANGUAGES C
)

verbose_message("extensions for vm")

set(SRC_FILE
  src/relo.c
)

if(${CMAKE_PROJECT_NAME}_BUILD_EXECUTABLE)
  add_executable(vm-exten ${SRC_FILE})
  set(${CMAKE_PROJECT_NAME}_EXTEN_LIB ${CMAKE_PROJECT_NAME}_LIB)
else()
  add_library(${CMAKE_PROJECT_NAME} ${SRC_FILE})
  set(${CMAKE_PROJECT_NAME}_EXTEN_LIB ${CMAKE_PROJECT_NAME})
endif()

# set the -static flag for static linking
set_target_properties(vm-exten PROPERTIES LINK_FLAGS "-static")

target_link_libraries(
  vm-exten
  PUBLIC
    ${${CMAKE_PROJECT_NAME}_EXTEN_LIB}
)

verbose_message("Finished adding unit tests for ${CMAKE_PROJECT_NAME}.")
