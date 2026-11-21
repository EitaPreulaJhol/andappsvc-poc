cmake_minimum_required(VERSION 3.20)
# CMP0091: select the MSVC runtime through CMAKE_MSVC_RUNTIME_LIBRARY (needed for
# the static-runtime option below).
cmake_policy(SET CMP0091 NEW)
project(andappsvc_client LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT WIN32)
  message(FATAL_ERROR "The client targets Windows (the driver is a Windows kernel module).")
endif()

# Static C/C++ runtime: nothing but ADVAPI32/KERNEL32/msvcrt is imported, so the
# exe and the payload DLL can be dropped on a machine without the toolchain.
#   cmake -S . -B build -A x64 -DANDAPPSVC_STATIC_RUNTIME=OFF   (opt out)
option(ANDAPPSVC_STATIC_RUNTIME "Link the C/C++ runtime statically" ON)
if(ANDAPPSVC_STATIC_RUNTIME)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
  if(MINGW)
    add_link_options(-static -static-libgcc -static-libstdc++)
  endif()
  message(STATUS "andappsvc: static C/C++ runtime")
else()
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
  message(STATUS "andappsvc: dynamic C/C++ runtime")
endif()

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
if(MSVC)
  add_compile_options(/W4 /permissive-)
else()
  add_compile_options(-Wall -Wextra)
endif()

# rc.exe / windres both need the directory of andappsvc2_64.sys on their include
# path (the .rc references it by name).
if(MSVC)
  set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} /I \"${CMAKE_CURRENT_SOURCE_DIR}/res\"")
else()
  set(CMAKE_RC_FLAGS "${CMAKE_RC_FLAGS} -I \"${CMAKE_CURRENT_SOURCE_DIR}/res\"")
endif()

# Portable core (no Windows API): PE reader + authentication hash chain.
add_library(andappsvc_core STATIC
  src/driver_image.cpp
  src/auth.cpp
)
target_include_directories(andappsvc_core PUBLIC include src)

# Windows client library.
add_library(andappsvc_client_lib STATIC
  src/andappsvc.cpp
  src/selfprotect.cpp
  src/win_util.cpp
  src/inject.cpp
  src/driver_install.cpp
)
target_link_libraries(andappsvc_client_lib PUBLIC andappsvc_core psapi advapi32)
target_include_directories(andappsvc_client_lib PUBLIC include src)

# Console front end.  res/andappsvc.rc embeds the driver (RCDATA #101), the
# requireAdministrator manifest and the version info.
add_executable(andappsvc_client src/main.cpp res/andappsvc.rc)
target_include_directories(andappsvc_client PRIVATE res)
if(MINGW)
  # the entry point is wmain() -> needs the unicode startup object
  target_compile_options(andappsvc_client PRIVATE -municode)
  target_link_options(andappsvc_client PRIVATE -municode)
endif()
target_link_libraries(andappsvc_client PRIVATE andappsvc_client_lib)

# Injected payload.
add_library(andappsvc_payload SHARED payload/dllmain.cpp)
target_link_libraries(andappsvc_payload PRIVATE andappsvc_client_lib)
set_target_properties(andappsvc_payload PROPERTIES OUTPUT_NAME "andappsvc_payload"
                      PREFIX "" SUFFIX ".dll")

# Host-side verification of the hash chain against vectors from the IDB.
add_executable(auth_vectors tests/auth_vectors.cpp)
target_link_libraries(auth_vectors PRIVATE andappsvc_core)
