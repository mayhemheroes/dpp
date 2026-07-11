#!/usr/bin/env bash
#
# dpp/mayhem/build.sh — build brainboxdotcc/DPP's Discord event-payload JSON parser as a
# sanitized libFuzzer target (+ a standalone reproducer), and build a self-contained golden
# oracle for mayhem/test.sh.
#
# Fuzzed surface: attacker-controlled bytes -> nlohmann::json::parse -> DPP's
# json_interface<T>::fill_from_json (message/user/guild/channel/embed). The harness lives in
# mayhem/harnesses/dpp_json_fuzzer.cpp. We compile the DPP library ITSELF with $SANITIZER_FLAGS
# so the parser code (not just the harness) is instrumented.
#
# Voice support is DISABLED (-DBUILD_VOICE_SUPPORT=OFF): it pulls in libopus + the bundled mlspp
# (DAVE E2EE) tree and is irrelevant to the JSON parse surface. That drops the dep set to just
# OpenSSL + zlib (installed by mayhem/Dockerfile).
#
# Build contract from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/$OUT/
# STANDALONE_FUZZ_MAIN. $OUT defaults to /mayhem.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${SRC:=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
: "${OUT:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS SRC OUT

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
INC="-I$SRC/include"

# DPP needs C++17, threads, and OpenSSL/zlib at link time. -fsanitize=fuzzer-no-link lets the
# library object files carry coverage instrumentation without pulling in libFuzzer's main().
CXX_SAN="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"

# ── 1) Build the DPP STATIC library WITH sanitizers (instruments the JSON parser) ─────────────
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"

cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DBUILD_SHARED_LIBS=OFF \
  -DBUILD_VOICE_SUPPORT=OFF \
  -DDPP_BUILD_TEST=OFF \
  -DDPP_NO_VCPKG=ON \
  -DDPP_NO_CONAN=ON \
  -DRUN_LDCONFIG=OFF \
  -DDPP_INSTALL=OFF \
  -DCMAKE_C_COMPILER="$CC" \
  -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  -DCMAKE_CXX_FLAGS="$CXX_SAN $DEBUG_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" \
  -DCMAKE_SHARED_LINKER_FLAGS="$SANITIZER_FLAGS"

cmake --build "$BUILD" --target dpp -j "$MAYHEM_JOBS"

LIBDPP="$(find "$BUILD" -name 'libdpp.a' | head -1)"
[ -n "$LIBDPP" ] || { echo "ERROR: libdpp.a not found after build" >&2; exit 1; }
echo "built static lib: $LIBDPP"

# DPP system deps (voice off → no opus): OpenSSL + zlib + pthread.
SYSLIBS="-lssl -lcrypto -lz -lpthread -ldl"

# ── 2) libFuzzer target -> $OUT/dpp_json_fuzzer ───────────────────────────────────────────────
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/dpp_json_fuzzer.cpp" \
    $LIB_FUZZING_ENGINE "$LIBDPP" $SYSLIBS \
    -o "$OUT/dpp_json_fuzzer"

# ── 3) standalone reproducer (no libFuzzer runtime) -> $OUT/dpp_json_fuzzer-standalone ─────────
$CXX -std=c++17 $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
    "$HARNESS_DIR/dpp_json_fuzzer.cpp" "$HARNESS_DIR/standalone_main.cpp" \
    "$LIBDPP" $SYSLIBS \
    -o "$OUT/dpp_json_fuzzer-standalone"

echo "built dpp_json_fuzzer (+ standalone)"

# ── 4) Self-contained golden oracle for test.sh: a tiny program that parses a KNOWN Discord
#       MESSAGE_CREATE JSON via dpp::message::fill_from_json and ASSERTS the extracted fields,
#       and asserts that malformed JSON is rejected. Built with NORMAL flags so test.sh is an
#       honest PATCH oracle (no sanitizer noise). Compiled against the SAME library sources but
#       a clean (un-sanitized) static lib so the test binary is self-contained. ────────────────
TESTBUILD="$SRC/mayhem-tests"
rm -rf "$TESTBUILD"; mkdir -p "$TESTBUILD"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$TESTBUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    -DBUILD_VOICE_SUPPORT=OFF \
    -DDPP_BUILD_TEST=OFF \
    -DDPP_NO_VCPKG=ON -DDPP_NO_CONAN=ON -DRUN_LDCONFIG=OFF -DDPP_INSTALL=OFF \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$TESTBUILD" --target dpp -j "$MAYHEM_JOBS"
LIBDPP_CLEAN="$(find "$TESTBUILD" -name 'libdpp.a' | head -1)"
[ -n "$LIBDPP_CLEAN" ] || { echo "ERROR: clean libdpp.a not found" >&2; exit 1; }

$CXX -std=c++17 -O2 $INC \
    "$HARNESS_DIR/oracle.cpp" "$LIBDPP_CLEAN" $SYSLIBS \
    -o "$OUT/dpp_oracle"
echo "built dpp_oracle (golden parse oracle)"

echo "build.sh complete:"
ls -la "$OUT/dpp_json_fuzzer" "$OUT/dpp_json_fuzzer-standalone" "$OUT/dpp_oracle" 2>&1 || true
