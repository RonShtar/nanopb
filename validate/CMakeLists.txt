# nanopb + validation, built and installed the way nanopb is. CMake 3.14 or newer.
#
#   cmake -S validate -B build -DCMAKE_INSTALL_PREFIX=/where
#   cmake --build build
#   cmake --install build
#
# This builds nanopb itself from the repository root, with nanopb's CMakeLists.txt
# unchanged, and adds the validation runtime (validate/runtime/pb_validate.c):
#
# NANOPB_VALIDATE_IN_NANOPB_LIBRARY=ON (default)
#   pb_validate.c is compiled into nanopb's own library: libprotobuf-nanopb.a holds
#   pb_common, pb_encode, pb_decode and pb_validate. pb_validate.h and
#   pb_filter_macros.h are installed next to pb.h. Use it as nanopb:
#
#     find_package(nanopb REQUIRED)
#     target_link_libraries(app nanopb::protobuf-nanopb-static)
#
#   (With CMake 3.19+ the same is possible from nanopb's own build:
#    cmake -S . -DCMAKE_PROJECT_INCLUDE=validate/extra/nanopb_validate_hook.cmake)
#
# NANOPB_VALIDATE_IN_NANOPB_LIBRARY=OFF
#   a separate libprotobuf-nanopb-validate next to nanopb's library:
#
#     find_package(nanopb-validate REQUIRED)       # also finds nanopb
#     target_link_libraries(app nanopb::protobuf-nanopb-validate)
#
# NANOPB_VALIDATE_WITH_NANOPB=OFF
#   use an already installed nanopb (find_package(nanopb)) and build only the separate
#   validation library (its installed .a cannot be changed from here).
#
# Settings that must match everywhere, carried to your project by find_package:
#   -DNANOPB_VALIDATE_FIELD_32BIT=ON      PB_FIELD_32BIT for the library and its users
#   -DNANOPB_VALIDATE_DEFINES="A;B=1"     any others (PB_VALIDATE_MAX_VIOLATIONS=32, ...)
#
# nanopb's own options (nanopb_BUILD_GENERATOR, BUILD_SHARED_LIBS, ...) work as
# usual. protoc must be found, as for nanopb.

cmake_minimum_required(VERSION 3.14.0)

project(nanopb_validate VERSION 1.0.0 LANGUAGES C)

option(NANOPB_VALIDATE_WITH_NANOPB "Build and install nanopb from the repository root too" ON)
option(NANOPB_VALIDATE_IN_NANOPB_LIBRARY
    "Compile pb_validate.c into nanopb's libprotobuf-nanopb (ON) or a separate libprotobuf-nanopb-validate (OFF)" ON)

include(GNUInstallDirs)

get_filename_component(_nanopb_root "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
include(${CMAKE_CURRENT_SOURCE_DIR}/extra/nanopb_validate_attach.cmake)

if(NANOPB_VALIDATE_WITH_NANOPB)
    add_subdirectory(${_nanopb_root} nanopb)
    if(NANOPB_VALIDATE_IN_NANOPB_LIBRARY)
        # nanopb's targets exist now: add pb_validate.c to them (nanopb's files unchanged).
        nanopb_validate_attach()
        return()
    endif()
    if(TARGET protobuf-nanopb)
        set(_nanopb_runtime protobuf-nanopb)
    elseif(TARGET protobuf-nanopb-static)
        set(_nanopb_runtime protobuf-nanopb-static)
    else()
        message(FATAL_ERROR "nanopb built no runtime library (nanopb_BUILD_RUNTIME is OFF?)")
    endif()
    # nanopb's pb_*.c need the same settings (PB_FIELD_32BIT changes its descriptors).
    foreach(_target protobuf-nanopb protobuf-nanopb-static)
        if(TARGET ${_target})
            nanopb_validate_apply_definitions(${_target})
        endif()
    endforeach()
else()
    nanopb_validate_definitions(_defs)
    if(_defs)
        message(STATUS "nanopb_validate: the installed nanopb must have been built with ${_defs} too")
    endif()
    find_package(nanopb REQUIRED)
    if(TARGET nanopb::protobuf-nanopb)
        set(_nanopb_runtime nanopb::protobuf-nanopb)
    else()
        set(_nanopb_runtime nanopb::protobuf-nanopb-static)
    endif()
endif()

# A separate validation library.
set(NANOPB_VALIDATE_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/nanopb-validate")

add_library(protobuf-nanopb-validate
    runtime/pb_validate.h
    runtime/pb_filter_macros.h
    runtime/pb_validate.c)
set_target_properties(protobuf-nanopb-validate PROPERTIES C_STANDARD 99)
if(BUILD_SHARED_LIBS)
    set_target_properties(protobuf-nanopb-validate PROPERTIES SOVERSION 0)
endif()
target_link_libraries(protobuf-nanopb-validate PUBLIC ${_nanopb_runtime})
target_include_directories(protobuf-nanopb-validate PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/runtime>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/nanopb>)
if(NOT NANOPB_VALIDATE_WITH_NANOPB)
    nanopb_validate_apply_definitions(protobuf-nanopb-validate)
else()
    nanopb_validate_apply_optimize(protobuf-nanopb-validate)   # definitions come from nanopb's target
endif()
add_library(nanopb::protobuf-nanopb-validate ALIAS protobuf-nanopb-validate)

install(TARGETS protobuf-nanopb-validate EXPORT nanopb-validate-targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

# Next to nanopb's pb.h, so one include directory serves both.
install(FILES runtime/pb_validate.h runtime/pb_filter_macros.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nanopb)

configure_file(extra/nanopb-validate-config.cmake.in nanopb-validate-config.cmake @ONLY)
configure_file(extra/nanopb-validate-config-version.cmake.in nanopb-validate-config-version.cmake @ONLY)

install(EXPORT nanopb-validate-targets
    DESTINATION ${NANOPB_VALIDATE_CMAKEDIR}
    NAMESPACE nanopb::)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/nanopb-validate-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/nanopb-validate-config-version.cmake
    DESTINATION ${NANOPB_VALIDATE_CMAKEDIR})

# The generator tool (python -m nanopb_validate ...) is not installed here: run it
# from the checkout, or install it into Wireshark with `wireshark install`.
