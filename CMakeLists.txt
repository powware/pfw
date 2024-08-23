cmake_minimum_required(VERSION 3.10)

project(
  pfw
  VERSION 1.0
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_library(pfw INTERFACE)

target_include_directories(
  pfw INTERFACE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                $<INSTALL_INTERFACE:include>)

target_link_libraries(pfw INTERFACE ntdll user32)

target_compile_definitions(pfw INTERFACE -DWIN32_LEAN_AND_MEAN -DUNICODE
                                         -D_UNICODE)

install(
  TARGETS pfw
  EXPORT pfwTargets
  INCLUDES
  DESTINATION include)

install(DIRECTORY include/ DESTINATION include)

install(
  EXPORT pfwTargets
  FILE pfwTargets.cmake
  NAMESPACE pfw::
  DESTINATION lib/cmake/pfw)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/pfwConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion ARCH_INDEPENDENT)

configure_file(pfwConfig.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/pfwConfig.cmake"
               @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/pfwConfig.cmake"
              "${CMAKE_CURRENT_BINARY_DIR}/pfwConfigVersion.cmake"
        DESTINATION lib/cmake/pfw)
