# Put the validation runtime into nanopb's own library, without changing nanopb.
# CMake 3.19 or newer. With an older CMake use the same thing as a project:
#
#   cmake -S validate -B build          (CMake 3.14+, same result; see validate/CMakeLists.txt)
#
# With CMake 3.19+ nanopb's own build can be used, with one extra flag:
#
#   cmake -S . -B build -DCMAKE_PROJECT_INCLUDE=validate/extra/nanopb_validate_hook.cmake
#   cmake --build build
#   cmake --install build
#
# CMake runs this file right after nanopb's project() call; the work is deferred to the
# end of nanopb's directory, when its library targets exist, and then
# nanopb_validate_attach() (nanopb_validate_attach.cmake) adds pb_validate.c to
# libprotobuf-nanopb, so pb_validate.o is part of the same .a, and installs
# pb_validate.h and pb_filter_macros.h next to pb.h. nanopb's CMakeLists.txt is used as
# it is, so upgrading nanopb stays a plain merge.

if(NOT PROJECT_NAME STREQUAL "nanopb")
    return()
endif()

get_property(_nanopb_validate_hooked GLOBAL PROPERTY NANOPB_VALIDATE_HOOKED)
if(_nanopb_validate_hooked)
    return()
endif()
set_property(GLOBAL PROPERTY NANOPB_VALIDATE_HOOKED TRUE)

if(CMAKE_VERSION VERSION_LESS 3.19)
    message(FATAL_ERROR "nanopb_validate_hook.cmake needs CMake 3.19 or newer (this is ${CMAKE_VERSION}). "
        "Same result with CMake 3.14+: cmake -S validate -B build (pb_validate.c goes into "
        "nanopb's libprotobuf-nanopb.a the same way).")
endif()

include(${CMAKE_CURRENT_LIST_DIR}/nanopb_validate_attach.cmake)
cmake_language(DEFER CALL nanopb_validate_attach)
