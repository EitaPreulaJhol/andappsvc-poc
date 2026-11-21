#!/usr/bin/env bash
# Cross-build check with mingw-w64 (handy on Linux CI; use CMake + MSVC on Windows).
#
#   ./build.sh              dynamic C/C++ runtime (libstdc++-6.dll, libgcc_s_*.dll)
#   ./build.sh --static     fully static runtime: the binaries only import system DLLs
#   ./build.sh --clean      remove ./build first
#
# --static adds -static -static-libgcc -static-libstdc++ so no mingw runtime
# DLLs have to be shipped next to the exe/dll (the Windows import list then only
# contains KERNEL32/ADVAPI32/msvcrt... and PSAPI).
set -euo pipefail
cd "$(dirname "$0")"

CXX=${CXX:-x86_64-w64-mingw32-g++}
OUT=${OUT:-build}
STATIC=0

usage() {
  cat <<'EOF'
usage: ./build.sh [options]

  --static    link the C/C++ runtime statically (-static -static-libgcc
              -static-libstdc++); the binaries only import ADVAPI32, KERNEL32
              and msvcrt, so no mingw runtime DLLs have to be shipped
  --dynamic   default: dynamic runtime (libstdc++-6.dll, libgcc_s_seh-1.dll)
  --clean     remove ./build first
EOF
}

for arg in "$@"; do
  case "$arg" in
    --static|-static) STATIC=1 ;;
    --dynamic|-dynamic) STATIC=0 ;;
    --clean) rm -rf "$OUT" ;;
    --help|-h) usage; exit 0 ;;
    *) echo "error: unknown option '$arg'" >&2; usage >&2; exit 2 ;;
  esac
done

mkdir -p "$OUT"

FLAGS=(-std=c++17 -O2 -Wall -Wextra -DUNICODE -D_UNICODE -DWIN32_LEAN_AND_MEAN -DNOMINMAX
       -Iinclude -Isrc)
CORE=(src/driver_image.cpp src/auth.cpp)
WIN=(src/andappsvc.cpp src/selfprotect.cpp src/win_util.cpp src/inject.cpp
     src/driver_install.cpp)

# Link-time runtime selection.
if [ "$STATIC" = 1 ]; then
  RUNTIME=(-static -static-libgcc -static-libstdc++)
  MODE="static"
else
  RUNTIME=()
  MODE="dynamic"
fi
echo "runtime: $MODE"

echo "[1/4] andappsvc.rc (embedded driver + manifest + version info)"
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
"$WINDRES" -I res -i res/andappsvc.rc -O coff -o "$OUT/andappsvc.res.o"

echo "[2/4] andappsvc_client.exe"
"$CXX" "${FLAGS[@]}" -municode "${RUNTIME[@]}" "${CORE[@]}" "${WIN[@]}" src/main.cpp \
       "$OUT/andappsvc.res.o" -o "$OUT/andappsvc_client.exe" -lpsapi -ladvapi32

echo "[3/4] andappsvc_payload.dll"
"$CXX" "${FLAGS[@]}" -shared "${RUNTIME[@]}" -static-libgcc -static-libstdc++ \
       "${CORE[@]}" "${WIN[@]}" payload/dllmain.cpp \
       -o "$OUT/andappsvc_payload.dll" -lpsapi -ladvapi32

echo "[4/4] auth_vectors (host build, verifies the hash chain)"
HOSTCXX=${HOSTCXX:-g++}
"$HOSTCXX" -std=c++17 -O2 -Iinclude -Isrc \
           tests/auth_vectors.cpp src/auth.cpp src/driver_image.cpp -o "$OUT/auth_vectors"

echo
echo "done -> $OUT ($MODE runtime)"
if command -v x86_64-w64-mingw32-objdump >/dev/null 2>&1; then
  for binary in "$OUT/andappsvc_client.exe" "$OUT/andappsvc_payload.dll"; do
    echo "imports of $(basename "$binary"):"
    x86_64-w64-mingw32-objdump -p "$binary" | awk '/DLL Name/{print "  " $3}' | sort -u
  done
fi
