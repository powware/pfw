cmake_minimum_required(VERSION 3.10)

project(
  pfw
  VERSION 1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(
  pfw STATIC
  ${PROJECT_SOURCE_DIR}/src/pfwlib.cpp ${PROJECT_SOURCE_DIR}/src/pefile.cpp
  ${PROJECT_SOURCE_DIR}/src/stringutils.cpp
  ${PROJECT_SOURCE_DIR}/src/hooking.cpp)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set_target_properties(pfw PROPERTIES OUTPUT_NAME "pfw64")
else()
  set_target_properties(pfw PROPERTIES OUTPUT_NAME "pfw32")
endif()

set_target_properties(
  pfw PROPERTIES ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/Debug"
                 ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/Release")

target_include_directories(
  pfw PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
             $<INSTALL_INTERFACE:include>)

target_link_libraries(pfw PRIVATE ntdll user32)

add_definitions(-DWIN32_LEAN_AND_MEAN)

install(
  TARGETS pfw
  EXPORT pfwTargets
  ARCHIVE DESTINATION lib)

install(DIRECTORY include/ DESTINATION include)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/pfwConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

install(
  EXPORT pfwTargets
  FILE pfwTargets.cmake
  NAMESPACE pfw::
  DESTINATION lib/cmake/pfw)

configure_file(pfwConfig.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/pfwConfig.cmake"
               @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pfwConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/pfwConfigVersion.cmake"
        DESTINATION lib/cmake/pfw)
