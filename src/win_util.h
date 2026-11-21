#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

namespace andappsvc {

std::wstring Win32ErrorMessage(DWORD error);
std::string ToUtf8(const std::wstring& wide);
std::wstring ToWide(const std::string& utf8);

// NT path of the calling process image ("\\Device\\HarddiskVolume3\\...\\x.exe"),
// i.e. exactly what ZwQueryInformationProcess(ProcessImageFileName) returns and
// what the driver compares against g_ProtectedImageName.
bool GetOwnNtImagePath(std::wstring* nt_path, std::wstring* error);

// NT path of an arbitrary process (needs PROCESS_QUERY_LIMITED_INFORMATION).
bool GetProcessNtImagePath(HANDLE process, std::wstring* nt_path, std::wstring* error);

// Converts an NT path to a Win32 path when possible:
//   "\??\C:\..."               -> "C:\..."
//   "\SystemRoot\..."          -> "%SystemRoot%\..."
//   "\Device\HarddiskVolume3\.." -> "C:\..." (via QueryDosDevice)
std::wstring NtPathToWin32Path(const std::wstring& nt_path);

// Finds the on-disk file of a loaded kernel module by its runtime image base.
// Prefers PSAPI (EnumDeviceDrivers) and falls back to
// NtQuerySystemInformation(SystemModuleInformation).
std::wstring FindLoadedModulePath(uint64_t image_base);

// Resolves the andappsvc2_64.sys file to use for the hash chain:
//   1. explicit override, 2. %ANDAPPSVC_DRIVER_IMAGE%,
//   3. the loaded module matching `image_base`, 4. %SystemRoot%\System32\drivers\andappsvc2_64.sys
std::wstring ResolveDriverImagePath(const std::wstring& override_path, uint64_t image_base);

// UTF-8 text helpers (the payload policy/log files are UTF-8 so non-ASCII image
// paths survive the trip through the injected DLL).
bool WriteTextFileUtf8(const std::wstring& path, const std::wstring& text, std::wstring* error);
bool AppendTextFileUtf8(const std::wstring& path, const std::wstring& text);
bool ReadTextFileUtf8(const std::wstring& path, std::wstring* text);

}  // namespace andappsvc
