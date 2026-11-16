# nanopb + validation, built and installed the way nanopb is.
#
#   cmake -S validate -B build -DCMAKE_INSTALL_PREFIX=/where
#   cmake --build build
#   cmake --install build
#
# This builds nanopb itself (the repository root, untouched: libprotobuf-nanopb
# and pb.h, pb_common.h, pb_encode.h, pb_decode.h) and adds what nanopb's own
# CMakeLists does not know about:
#
#   libprotobuf-nanopb-validate.a   pb_validate.c, the validation runtime
#   <prefix>/include/nanopb/pb_validate.h, pb_filter_macros.h   (next to pb.h)
#   <prefix>/lib/cmake/nanopb-validate/   find_package(nanopb-validate)
#
# Use it:
#
#   find_package(nanopb-validate REQUIRED)       # also finds nanopb
#   target_link_libraries(app nanopb::protobuf-nanopb-validate)
#
# and the generated code (python -m nanopb_validate gen ...) compiles with
# #include <pb_validate.h>. The validate library links the nanopb runtime
# publicly, so the generated packet filters (pb_decode) link too.
#
# Options:
#   NANOPB_VALIDATE_WITH_NANOPB  ON (default): build and install nanopb from the
#                                repository root too. OFF: use an installed
#                                nanopb (find_package(nanopb)) and add only
#                                the validation runtime.
# nanopb's own options (nanopb_BUILD_GENERATOR, BUILD_SHARED_LIBS, ...) work as
# usual. protoc must be found, as for nanopb.

cmake_minimum_required(VERSION 3.14.0)

project(nanopb_validate VERSION 1.0.0 LANGUAGES C)

option(NANOPB_VALIDATE_WITH_NANOPB "Build and install nanopb from the repository root too" ON)

include(GNUInstallDirs)

get_filename_component(_nanopb_root "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)

if(NANOPB_VALIDATE_WITH_NANOPB)
    add_subdirectory(${_nanopb_root} nanopb)
    if(TARGET protobuf-nanopb)
        set(_nanopb_runtime protobuf-nanopb)
    elseif(TARGET protobuf-nanopb-static)
        set(_nanopb_runtime protobuf-nanopb-static)
    else()
        message(FATAL_ERROR "nanopb built no runtime library (nanopb_BUILD_RUNTIME is OFF?)")
    endif()
else()
    find_package(nanopb REQUIRED)
    if(TARGET nanopb::protobuf-nanopb)
        set(_nanopb_runtime nanopb::protobuf-nanopb)
    else()
        set(_nanopb_runtime nanopb::protobuf-nanopb-static)
    endif()
endif()

if(NOT DEFINED CMAKE_INSTALL_CMAKEDIR)
    set(CMAKE_INSTALL_CMAKEDIR "${CMAKE_INSTALL_LIBDIR}/cmake/nanopb")
endif()
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
