cmake_minimum_required(VERSION 3.10)

project(
  portforware
  VERSION 1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(
  pfw STATIC
  ${PROJECT_SOURCE_DIR}/src/pfwlib.cpp ${PROJECT_SOURCE_DIR}/src/pefile.cpp
  ${PROJECT_SOURCE_DIR}/src/stringutils.cpp
  ${PROJECT_SOURCE_DIR}/src/hooking.cpp)

target_include_directories(pfw PUBLIC ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(pfw PRIVATE ntdll user32)

add_definitions(-DWIN32_LEAN_AND_MEAN)
