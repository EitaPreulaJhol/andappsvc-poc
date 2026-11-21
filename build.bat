@echo off
rem Build with Visual Studio (x64 Native Tools command prompt) or via CMake.
rem
rem   build.bat             dynamic C/C++ runtime (/MD)
rem   build.bat --static    static C/C++ runtime  (/MT, self-contained binaries)
rem   build.bat --clean     remove build\ first
setlocal

set RTFLAG=/MD
set RUNTIME=dynamic
if /I "%~1"=="--static" (set RTFLAG=/MT& set RUNTIME=static)
if /I "%~1"=="-static"  (set RTFLAG=/MT& set RUNTIME=static)
if /I "%~1"=="static"   (set RTFLAG=/MT& set RUNTIME=static)
if /I "%~1"=="--dynamic" (set RTFLAG=/MD& set RUNTIME=dynamic)
if /I "%~1"=="--clean"   if exist build rmdir /s /q build
echo runtime: %RUNTIME% (%RTFLAG%)

where cl >nul 2>nul
if errorlevel 1 (
  echo Building with CMake...
  if /I "%RUNTIME%"=="static" (
    cmake -S . -B build -A x64 -DANDAPPSVC_STATIC_RUNTIME=ON
  ) else (
    cmake -S . -B build -A x64 -DANDAPPSVC_STATIC_RUNTIME=OFF
  )
  if errorlevel 1 goto :fail
  cmake --build build --config Release
  if errorlevel 1 goto :fail
  echo.
  echo Output: build\Release\andappsvc_client.exe / andappsvc_payload.dll / auth_vectors.exe
  goto :eof
)

if not exist build mkdir build
echo [1/4] andappsvc.rc (embedded driver + manifest + version info)
rc /nologo /I res /fo build\andappsvc.res res\andappsvc.rc
if errorlevel 1 goto :fail

echo [2/4] andappsvc_client.exe
cl /nologo /std:c++17 /EHsc /O2 /W4 %RTFLAG% /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
   /Iinclude /Isrc ^
   src\driver_image.cpp src\auth.cpp src\andappsvc.cpp src\selfprotect.cpp ^
   src\win_util.cpp src\inject.cpp src\driver_install.cpp src\main.cpp ^
   build\andappsvc.res ^
   /Fe:build\andappsvc_client.exe /Fo:build\ /link psapi.lib advapi32.lib
if errorlevel 1 goto :fail

echo [3/4] andappsvc_payload.dll
cl /nologo /std:c++17 /EHsc /O2 /W4 %RTFLAG% /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /DNOMINMAX ^
   /Iinclude /Isrc /LD ^
   src\driver_image.cpp src\auth.cpp src\andappsvc.cpp src\selfprotect.cpp ^
   src\win_util.cpp src\inject.cpp src\driver_install.cpp payload\dllmain.cpp ^
   /Fe:build\andappsvc_payload.dll /Fo:build\ /link psapi.lib advapi32.lib
if errorlevel 1 goto :fail

echo [4/4] auth_vectors.exe
cl /nologo /std:c++17 /EHsc /O2 /W4 /Iinclude /Isrc ^
   tests\auth_vectors.cpp src\auth.cpp src\driver_image.cpp ^
   /Fe:build\auth_vectors.exe /Fo:build\
if errorlevel 1 goto :fail

echo.
echo Output in build\ — run:  build\auth_vectors.exe andappsvc2_64.sys
goto :eof

:fail
echo build failed
exit /b 1
