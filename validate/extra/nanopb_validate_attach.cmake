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
