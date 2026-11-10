# CMake support for nanopb validation, next to nanopb's own FindNanopb.cmake.
#
#   list(APPEND CMAKE_MODULE_PATH ${NANOPB_DIR}/extra)
#   find_package(Nanopb REQUIRED)                         # nanopb, unchanged
#   include(${NANOPB_DIR}/validate/extra/NanopbValidate.cmake)
#
#   nanopb_validate_generate(SRCS HDRS foo.proto bar.proto
#                            [OPTIONS --filter pkg.Envelope])
#   add_executable(app main.c ${SRCS} ${HDRS})
#   target_link_libraries(app nanopb_validate)
#
# nanopb_validate_generate() writes <name>.pb.c/.h and <name>_validate.c/.h
# for each .proto into the current binary directory, in one protoc run per
# file (python -m nanopb_validate gen). Link the generated sources with the
# nanopb runtime (pb_encode.c, pb_decode.c, pb_common.c, e.g. from
# NANOPB_SRCS) and the nanopb_validate library defined here.

get_filename_component(NANOPB_VALIDATE_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
get_filename_component(_nanopb_root "${NANOPB_VALIDATE_DIR}/.." ABSOLUTE)

find_package(Python3 REQUIRED COMPONENTS Interpreter)

if(NOT TARGET nanopb_validate)
  add_library(nanopb_validate STATIC ${NANOPB_VALIDATE_DIR}/runtime/pb_validate.c)
  target_include_directories(nanopb_validate PUBLIC ${NANOPB_VALIDATE_DIR}/runtime ${_nanopb_root})
  set_target_properties(nanopb_validate PROPERTIES C_STANDARD 99)
endif()

function(nanopb_validate_generate SRCS HDRS)
  cmake_parse_arguments(ARG "" "" "OPTIONS" ${ARGN})
  set(srcs)
  set(hdrs)
  foreach(proto ${ARG_UNPARSED_ARGUMENTS})
    get_filename_component(abs "${proto}" ABSOLUTE)
    get_filename_component(dir "${abs}" DIRECTORY)
    get_filename_component(name "${abs}" NAME_WE)
    set(out "${CMAKE_CURRENT_BINARY_DIR}")
    set(outputs "${out}/${name}.pb.c" "${out}/${name}.pb.h" "${out}/${name}_validate.c" "${out}/${name}_validate.h")
    add_custom_command(
      OUTPUT ${outputs}
      COMMAND ${Python3_EXECUTABLE} ${NANOPB_VALIDATE_DIR}/nanopb_validate gen
              -I ${dir} -D ${out} ${ARG_OPTIONS} ${abs}
      DEPENDS ${abs}
      WORKING_DIRECTORY ${dir}
      COMMENT "nanopb + validation: ${proto}"
      VERBATIM)
    list(APPEND srcs "${out}/${name}.pb.c" "${out}/${name}_validate.c")
    list(APPEND hdrs "${out}/${name}.pb.h" "${out}/${name}_validate.h")
  endforeach()
  set_source_files_properties(${srcs} ${hdrs} PROPERTIES GENERATED TRUE)
  set(${SRCS} ${srcs} PARENT_SCOPE)
  set(${HDRS} ${hdrs} PARENT_SCOPE)
endfunction()
