# Building nanopb + pb_validate for a target, everything at -O2

Step-by-step, with what to check after each step. It follows the FirePillar layout
(`libs/libsrc/fp-nanopb` as a submodule, a cross toolchain file, `libs/lib/<type>` and
`libs/include` as install targets); change the paths for another project. Each step is
written so you can follow it yourself or paste it to an agent.

What is compiled at `-O2` and how:

| Code | Built by | -O2 from |
|---|---|---|
| `pb_common.c`, `pb_encode.c`, `pb_decode.c` | nanopb's own CMake target | `-DNANOPB_VALIDATE_OPTIMIZE=O2` |
| `pb_validate.c` (in the same `.a`) | the same target (`cmake -S validate`) | `-DNANOPB_VALIDATE_OPTIMIZE=O2` |
| generated `<p>.pb.c`, `<p>_validate.c` | your project | `gen --optimize O2` (`#pragma GCC optimize`) and/or your project's flags |

`NANOPB_VALIDATE_OPTIMIZE` is added after the build type's flags, so it holds in Release
(CMake's `-O3` is overridden) and in Debug (`-g -O2`: still debuggable, but at full speed).

## Steps

1. In `libs/libsrc/fp-nanopb`, make sure it is on master and up to date with origin/master,
   and that it is this version: `validate/extra/nanopb_validate_attach.cmake` contains
   `NANOPB_VALIDATE_OPTIMIZE`. If it does not, bring the new version in first. From the
   offline package:
   `git fetch <package>/nanopb-offline.bundle validate/buf-append && git merge --ff-only FETCH_HEAD`.
   If that is not a fast-forward, stop and show me the output.
   Do not edit pb.h. `PB_FIELD_32BIT` comes from `-DNANOPB_VALIDATE_FIELD_32BIT=ON`. If an
   earlier commit already enabled it in pb.h, leave that as it is: it is the same value.
   Show me `git status` and `git log -1 --oneline`.

2. Build and install twice, Release then Debug, each from a fresh build folder. Use
   `cmake -S validate` (it works with CMake 3.14+, 3.18 included; it builds nanopb from its
   unchanged root and puts pb_validate.c into nanopb's own .a):

       cd libs/libsrc/fp-nanopb
       rm -rf build
       cmake -S validate -B build \
         -DCMAKE_TOOLCHAIN_FILE=D:/dev/FirePillar/libs/lib/bamam_toolchain.cmake \
         -DCMAKE_BUILD_TYPE=<Release|Debug> -Dnanopb_BUILD_GENERATOR=OFF \
         -DNANOPB_VALIDATE_FIELD_32BIT=ON \
         -DNANOPB_VALIDATE_DEFINES="PB_BUFFER_ONLY;PB_NO_ERRMSG" \
         -DNANOPB_VALIDATE_OPTIMIZE=O2 2>&1 | tee configure-<type>.log
       cmake --build build --verbose 2>&1 | tee build-<type>.log
       cmake --install build
       rm -rf build

   Keep `configure-<type>.log` and `build-<type>.log` (outside the build folder) for step 3.
   Report where `cmake --install` put each .h and .a file.

3. Verify, for Release and for Debug:
   - The configure log has both lines:

         nanopb_validate: protobuf-nanopb-static and its users are compiled with: PB_BUFFER_ONLY;PB_NO_ERRMSG;PB_FIELD_32BIT
         nanopb_validate: protobuf-nanopb-static is compiled with -O2 in every build type

   - Every runtime file was compiled at -O2. The last -O on each compile line counts:

         grep -E ' -c [^ ]*pb_(common|encode|decode|validate)\.c' build-<type>.log | while read -r l; do
           echo "$(echo "$l" | grep -oE 'pb_[a-z]+\.c$') $(echo "$l" | grep -oE ' -O[0-3sgz]' | tail -1)"; done

     Expected: exactly four lines, `pb_common.c -O2`, `pb_encode.c -O2`, `pb_decode.c -O2`,
     `pb_validate.c -O2`. Release lines also show the toolchain's `-O3` before it, and Debug
     lines show `-g`.
   - One library holds all four (`libprotobuf-nanopb.a` in Release, `libprotobuf-nanopbd.a` in Debug):

         arm-altera-eabi-ar t libs/lib/Release/libprotobuf-nanopb.a
         arm-altera-eabi-ar t libs/lib/Debug/libprotobuf-nanopbd.a

     Expected: pb_common, pb_encode, pb_decode and pb_validate objects. Both files have new timestamps.
   - It is the 32-bit build: `arm-altera-eabi-nm <file.a> | grep _f32` finds symbols, and
     `arm-altera-eabi-nm <file.a> | grep _f16` finds none.
   - `libs/include/nanopb/` holds pb.h, pb_encode.h, pb_decode.h, pb_common.h, pb_validate.h and
     pb_filter_macros.h. The installed pb.h is identical to the submodule's pb.h:
     `diff libs/include/nanopb/pb.h libs/libsrc/fp-nanopb/pb.h` prints nothing.
   - The code-generation flags recorded in each .a:

         arm-altera-eabi-readelf -p .GCC.command.line <file.a> 2>/dev/null | sed -n 's/.*\]  *//p' | grep -E '^-(m|f|O|g)' | sort -u

     The section exists only when the toolchain compiles with `-frecord-gcc-switches`. If it does
     not exist, say so; don't treat it as a failure. If it exists, `-O2` must be in the list.

4. Generate the C for the protocols, also at -O2. If they use protovalidate, convert them
   first (README "Preparing a protos directory from protovalidate"):

       python validate/tools/buf_to_validate.py <protos> --out <protos_nanopb>
       python -m nanopb_validate check <protos_nanopb>
       python -m nanopb_validate gen <protos_nanopb> --out <generated> --optimize O2

   Run these from `libs/libsrc/fp-nanopb/validate`. `check` must end with 0 error(s). Every
   generated .c must contain `#pragma GCC optimize ("O2")`:

       grep -L 'pragma GCC optimize ("O2")' <generated>/*/*.c

   Expected: no file listed. In FirePillar's CMake, also set the generated files to -O2 if
   the target's flags would override the pragma (e.g. explicit `-O0` per file):

       set_source_files_properties(<p>.pb.c <p>_validate.c PROPERTIES COMPILE_OPTIONS -O2)

   FirePillar must be compiled with the same defines as the library:
   `-DPB_FIELD_32BIT -DPB_BUFFER_ONLY -DPB_NO_ERRMSG`. You get them automatically with
   `find_package(nanopb)` and `nanopb::protobuf-nanopb-static`. A mismatch does not link
   ("undefined reference to pb_violations_record_..._f16"): it never corrupts memory.

5. Add or update a line in `libs/VERSION.txt`:

       fp-nanopb <short commit> - pb_validate in libprotobuf-nanopb, -O2 (Release and Debug), PB_FIELD_32BIT

6. If the submodule got new commits in step 1, they are already committed there. In the
   parent repo, stage `libs/libsrc/fp-nanopb`, `libs/include`, `libs/lib` and
   `libs/VERSION.txt`, and commit:
   "fp-nanopb: pb_validate at -O2, rebuild Debug and Release".

## Rules

- Do NOT push anything (neither the submodule nor the parent repo). Stop after the commits and
  tell me what to push, in which order (submodule first, then parent).
- Do not modify any other submodule (mbedtls, jansson, fp-libxml).
- Do not edit nanopb's files (pb.h, pb_*.c, CMakeLists.txt). Every switch goes on the cmake
  command line.
- If any step fails or the output differs from what is described here (different file names,
  install paths, flags other than -O2 in step 3, missing tools), stop and show me the output
  instead of working around it.

At the end, give me a short summary: the submodule commit hash, the installed files, the
verification results (configure lines, the four -O2 lines per build type, ar/nm/readelf),
and the commands I need to run to push.

## Without the target toolchain (to try it on a PC)

The same configure line without `-DCMAKE_TOOLCHAIN_FILE`, plus on Windows without gcc the zig
shims from [testing.md](testing.md). `tests/py/test_cmake_install.py` runs this check
(`test_optimize_level_for_every_build_type`): Release and Debug, every runtime file at -O2.
