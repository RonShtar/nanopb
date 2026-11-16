# Put the validation runtime into nanopb's own library, without changing nanopb.
#
#   cmake -S . -B build -DCMAKE_PROJECT_INCLUDE=validate/extra/nanopb_validate_hook.cmake
#   cmake --build build
#   cmake --install build
#
# nanopb's CMakeLists.txt is used as it is. CMake runs this file right after its
# project() call; the work is deferred to the end of nanopb's directory, when its
# library targets exist, and then
#
#   * validate/runtime/pb_validate.c is added to libprotobuf-nanopb (static and/or
#     shared, whichever nanopb builds), so pb_validate.o is part of the same .a;
#   * pb_validate.h and pb_filter_macros.h are installed next to pb.h
#     (<prefix>/include/nanopb), and found in the build tree through the target.
#
# A project that already does find_package(nanopb) and links nanopb::protobuf-nanopb-static
# gets validation with no other change. Upgrading nanopb stays a plain merge: this
# file and everything it adds live in validate/.
#
# Needs CMake 3.19 (cmake_language(DEFER)). Relative paths are taken from the
# directory you run cmake in; an absolute path always works.

if(NOT PROJECT_NAME STREQUAL "nanopb")
    return()
endif()

get_property(_nanopb_validate_hooked GLOBAL PROPERTY NANOPB_VALIDATE_HOOKED)
if(_nanopb_validate_hooked)
    return()
endif()
set_property(GLOBAL PROPERTY NANOPB_VALIDATE_HOOKED TRUE)

if(CMAKE_VERSION VERSION_LESS 3.19)
    message(FATAL_ERROR "nanopb_validate_hook.cmake needs CMake 3.19 or newer (this is ${CMAKE_VERSION}); "
        "use cmake -S validate instead: it needs only 3.14.")
endif()

get_filename_component(NANOPB_VALIDATE_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../runtime" ABSOLUTE)
get_filename_component(NANOPB_VALIDATE_NANOPB_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)   # where pb.h is

function(_nanopb_validate_attach)
    set(_attached FALSE)
    foreach(_target protobuf-nanopb protobuf-nanopb-static)
        if(TARGET ${_target})
            target_sources(${_target} PRIVATE
                ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_validate.c
                ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_validate.h
                ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_filter_macros.h)
            # pb_validate.h includes pb.h, which sits in nanopb's root folder.
            target_include_directories(${_target} PRIVATE ${NANOPB_VALIDATE_NANOPB_DIR})
            # In the build tree, other targets see pb_validate.h through the library.
            target_include_directories(${_target} INTERFACE
                $<BUILD_INTERFACE:${NANOPB_VALIDATE_RUNTIME_DIR}>)
            set(_attached TRUE)
        endif()
    endforeach()
    if(NOT _attached)
        message(WARNING "nanopb_validate_hook: nanopb built no runtime library "
            "(nanopb_BUILD_RUNTIME is OFF?); pb_validate was not added")
        return()
    endif()
    include(GNUInstallDirs)
    install(FILES
        ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_validate.h
        ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_filter_macros.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nanopb)
endfunction()

cmake_language(DEFER CALL _nanopb_validate_attach)
