# nanopb_validate_attach(): put validate/runtime/pb_validate.c into nanopb's own library.
#
# Call it after nanopb's CMakeLists.txt has created its targets: from
# validate/CMakeLists.txt after add_subdirectory(<nanopb>) (CMake 3.14+), or from
# nanopb_validate_hook.cmake at the end of nanopb's directory (CMake 3.19+).
#
#   * pb_validate.c is added to libprotobuf-nanopb (static and/or shared, whichever
#     nanopb builds), so pb_validate.o is a member of the same .a;
#   * pb_validate.h and pb_filter_macros.h are installed next to pb.h
#     (<prefix>/include/nanopb) and are visible in the build tree through the target.
#
# Only nanopb's targets are changed, never its files.

# Build settings that must be the same in the library and in every file using it
# (PB_FIELD_32BIT, PB_VALIDATE_MAX_*, PB_VALIDATE_DEBUG, ...). They are PUBLIC
# definitions of the library: nanopb's pb_*.c and pb_validate.c are compiled with them,
# and a project linking nanopb::protobuf-nanopb(-static) from find_package(nanopb)
# gets them too, so it needs no target_compile_definitions of its own.
#
#   -DNANOPB_VALIDATE_FIELD_32BIT=ON                         PB_FIELD_32BIT
#   -DNANOPB_VALIDATE_DEFINES="PB_VALIDATE_MAX_VIOLATIONS=32;PB_VALIDATE_DEBUG"
option(NANOPB_VALIDATE_FIELD_32BIT "Define PB_FIELD_32BIT for the library and every project using it" OFF)
set(NANOPB_VALIDATE_DEFINES "" CACHE STRING
    "Definitions (;-separated, NAME or NAME=VALUE) for the library and every project using it")

function(nanopb_validate_definitions out)
    set(_defs ${NANOPB_VALIDATE_DEFINES})
    if(NANOPB_VALIDATE_FIELD_32BIT AND NOT "PB_FIELD_32BIT" IN_LIST _defs)
        list(APPEND _defs PB_FIELD_32BIT)
    endif()
    set(${out} ${_defs} PARENT_SCOPE)
endfunction()

# One optimization level for the whole runtime, whatever CMAKE_BUILD_TYPE says
# (Release defaults to -O3, Debug to none):
#
#   -DNANOPB_VALIDATE_OPTIMIZE=O2       nanopb's pb_*.c and pb_validate.c at -O2 (MSVC: /O2)
#
# It is added after the build type's flags, so it wins (the last -O counts); -g of a
# Debug build stays. PRIVATE: projects linking the library keep their own level (the
# generated code has `gen --optimize O2` for that).
set(NANOPB_VALIDATE_OPTIMIZE "" CACHE STRING
    "Optimization level for nanopb's runtime and pb_validate.c in every build type (O0, O1, O2, O3, Os; empty: the build type's)")

function(nanopb_validate_optimize_flag out)
    set(_level "${NANOPB_VALIDATE_OPTIMIZE}")
    string(REGEX REPLACE "^[-/]" "" _level "${_level}")
    if(_level STREQUAL "")
        set(${out} "" PARENT_SCOPE)
        return()
    endif()
    if(NOT _level MATCHES "^O([0-3]|s|z|fast|g)$")
        message(FATAL_ERROR "NANOPB_VALIDATE_OPTIMIZE=${NANOPB_VALIDATE_OPTIMIZE}: give O0, O1, O2, O3, Os, Oz or Og")
    endif()
    if(MSVC)
        if(_level MATCHES "^O[0g]$")
            set(_level "Od")
        elseif(_level MATCHES "^O[sz]$")
            set(_level "O1")
        elseif(_level MATCHES "^O(3|fast)$")
            set(_level "O2")
        endif()
        set(${out} "/${_level}" PARENT_SCOPE)
    else()
        set(${out} "-${_level}" PARENT_SCOPE)
    endif()
endfunction()

# Adds the settings to `target` as PUBLIC definitions (exported with the target), and
# NANOPB_VALIDATE_OPTIMIZE as a PRIVATE compile option.
function(nanopb_validate_apply_definitions target)
    nanopb_validate_definitions(_defs)
    if(_defs)
        target_compile_definitions(${target} PUBLIC ${_defs})
        message(STATUS "nanopb_validate: ${target} and its users are compiled with: ${_defs}")
    endif()
    nanopb_validate_apply_optimize(${target})
endfunction()

function(nanopb_validate_apply_optimize target)
    nanopb_validate_optimize_flag(_opt)
    if(_opt)
        target_compile_options(${target} PRIVATE ${_opt})
        message(STATUS "nanopb_validate: ${target} is compiled with ${_opt} in every build type")
    endif()
endfunction()

get_filename_component(NANOPB_VALIDATE_RUNTIME_DIR "${CMAKE_CURRENT_LIST_DIR}/../runtime" ABSOLUTE)
get_filename_component(NANOPB_VALIDATE_NANOPB_DIR "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)   # where pb.h is

function(nanopb_validate_attach)
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
            nanopb_validate_apply_definitions(${_target})
            set(_attached TRUE)
        endif()
    endforeach()
    if(NOT _attached)
        message(WARNING "nanopb_validate: nanopb built no runtime library "
            "(nanopb_BUILD_RUNTIME is OFF?); pb_validate was not added")
        return()
    endif()
    include(GNUInstallDirs)
    install(FILES
        ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_validate.h
        ${NANOPB_VALIDATE_RUNTIME_DIR}/pb_filter_macros.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/nanopb)
endfunction()
