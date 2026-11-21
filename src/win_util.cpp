#include "win_util.h"

#include <psapi.h>

#include <cstdio>
#include <cwchar>

namespace andappsvc {
namespace {

// ---------------------------------------------------------------- ntdll bits
// Declared locally so we do not depend on a specific WDK/SDK header version.
using NtQueryInformationProcessFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQuerySystemInformationFn = LONG(WINAPI*)(ULONG, PVOID, ULONG, PULONG);

constexpr ULONG kNtProcessImageFileName = 27;  // PROCESSINFOCLASS: ProcessImageFileName
constexpr ULONG kNtSystemModuleInformation = 11;
constexpr LONG kStatusInfoLengthMismatch = static_cast<LONG>(0xC0000004);

struct NtUnicodeString {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
};

struct SystemModuleEntry {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
};

struct SystemModuleInformation {
  ULONG Count;
  SystemModuleEntry Modules[1];
};

NtQueryInformationProcessFn GetNtQueryInformationProcess() {
  static NtQueryInformationProcessFn fn = [] {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtQueryInformationProcessFn>(reinterpret_cast<void*>(
                       GetProcAddress(ntdll, "NtQueryInformationProcess")))
                 : nullptr;
  }();
  return fn;
}

NtQuerySystemInformationFn GetNtQuerySystemInformation() {
  static NtQuerySystemInformationFn fn = [] {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<NtQuerySystemInformationFn>(reinterpret_cast<void*>(
                       GetProcAddress(ntdll, "NtQuerySystemInformation")))
                 : nullptr;
  }();
  return fn;
}

bool QueryImageName(HANDLE process, std::wstring* out, std::wstring* error) {
  auto nt_query = GetNtQueryInformationProcess();
  if (nt_query == nullptr) {
    if (error) *error = L"NtQueryInformationProcess is unavailable";
    return false;
  }
  std::vector<uint8_t> buffer(0x1000);
  for (int attempt = 0; attempt < 4; ++attempt) {
    ULONG length = 0;
    const LONG status = nt_query(process, kNtProcessImageFileName, buffer.data(),
                                 static_cast<ULONG>(buffer.size()), &length);
    if (status == kStatusInfoLengthMismatch || length > buffer.size()) {
      buffer.resize(buffer.size() * 2 + length);
      continue;
    }
    if (status < 0) {
      if (error) *error = L"NtQueryInformationProcess(ProcessImageFileName) failed: 0x" +
                          std::to_wstring(static_cast<uint32_t>(status));
      return false;
    }
    const auto* us = reinterpret_cast<const NtUnicodeString*>(buffer.data());
    if (us->Buffer == nullptr || us->Length == 0) {
      if (error) *error = L"ProcessImageFileName returned an empty path";
      return false;
    }
    *out = std::wstring(us->Buffer, us->Length / sizeof(wchar_t));
    return true;
  }
  if (error) *error = L"ProcessImageFileName buffer too small";
  return false;
}

}  // namespace

std::wstring Win32ErrorMessage(DWORD error) {
  wchar_t* text = nullptr;
  const DWORD len = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&text), 0,
      nullptr);
  std::wstring result;
  if (len != 0 && text != nullptr) {
    result.assign(text, len);
    while (!result.empty() && (result.back() == L'\r' || result.back() == L'\n')) result.pop_back();
    LocalFree(text);
  }
  if (result.empty()) result = L"error " + std::to_wstring(error);
  return result;
}

std::string ToUtf8(const std::wstring& wide) {
  if (wide.empty()) return {};
  const int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()),
                                      nullptr, 0, nullptr, nullptr);
  std::string out(static_cast<size_t>(len), '\0');
  WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), out.data(), len,
                      nullptr, nullptr);
  return out;
}

std::wstring ToWide(const std::string& utf8) {
  if (utf8.empty()) return {};
  const int len = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()),
                                      nullptr, 0);
  std::wstring out(static_cast<size_t>(len), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), static_cast<int>(utf8.size()), out.data(), len);
  return out;
}

bool GetOwnNtImagePath(std::wstring* nt_path, std::wstring* error) {
  if (!QueryImageName(GetCurrentProcess(), nt_path, error)) return false;

  // Cross-check with the Win32 path when possible; a mismatch means the NT
  // conversion is unavailable, which is fine - the driver wants the NT form.
  wchar_t exe[MAX_PATH * 4] = {};
  if (GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe)) != 0) {
    // Nothing to do: NtQueryInformationProcess already gave us the canonical
    // path.  Kept for debuggers.
  }
  return true;
}

bool GetProcessNtImagePath(HANDLE process, std::wstring* nt_path, std::wstring* error) {
  return QueryImageName(process, nt_path, error);
}

std::wstring NtPathToWin32Path(const std::wstring& nt_path) {
  if (nt_path.empty()) return nt_path;

  // \??\C:\... or \??\UNC\...
  if (nt_path.rfind(L"\\??\\", 0) == 0) {
    std::wstring rest = nt_path.substr(4);
    if (rest.rfind(L"UNC\\", 0) == 0) return L"\\\\" + rest.substr(4);
    return rest;
  }
  // \SystemRoot\System32\drivers\x.sys
  if (nt_path.rfind(L"\\SystemRoot\\", 0) == 0) {
    wchar_t win_dir[MAX_PATH] = {};
    const UINT n = GetWindowsDirectoryW(win_dir, ARRAYSIZE(win_dir));
    if (n != 0) return std::wstring(win_dir) + nt_path.substr(11);
    return nt_path;
  }
  // \Device\HarddiskVolumeN\... -> <drive>:\...
  if (nt_path.rfind(L"\\Device\\", 0) == 0) {
    wchar_t drives[512] = {};
    const DWORD n = GetLogicalDriveStringsW(ARRAYSIZE(drives) - 1, drives);
    if (n != 0) {
      for (const wchar_t* drive = drives; *drive; drive += wcslen(drive) + 1) {
        wchar_t target[1024] = {};
        if (QueryDosDeviceW(drive, target, ARRAYSIZE(target)) == 0) continue;
        const size_t len = wcslen(target);
        if (len < 8) continue;
        if (_wcsnicmp(nt_path.c_str(), target, len) == 0 && nt_path.size() > len &&
            nt_path[len] == L'\\') {
          // drive already carries the trailing backslash ("C:\")
          return std::wstring(drive) + nt_path.substr(len + 1);
        }
      }
    }
  }
  return nt_path;
}

std::wstring FindLoadedModulePath(uint64_t image_base) {
  // 1) PSAPI
  DWORD needed = 0;
  EnumDeviceDrivers(nullptr, 0, &needed);
  if (needed != 0) {
    std::vector<LPVOID> bases(needed / sizeof(LPVOID) + 1);
    if (EnumDeviceDrivers(bases.data(), static_cast<DWORD>(bases.size() * sizeof(LPVOID)), &needed)) {
      const size_t count = needed / sizeof(LPVOID);
      for (size_t i = 0; i < count; ++i) {
        if (reinterpret_cast<uint64_t>(bases[i]) != image_base) continue;
        wchar_t file[MAX_PATH] = {};
        if (GetDeviceDriverFileNameW(bases[i], file, ARRAYSIZE(file)) != 0) {
          return NtPathToWin32Path(file);
        }
      }
    }
  }

  // 2) SystemModuleInformation
  auto nt_query = GetNtQuerySystemInformation();
  if (nt_query != nullptr) {
    std::vector<uint8_t> buffer(0x10000);
    for (int attempt = 0; attempt < 6; ++attempt) {
      ULONG length = 0;
      const LONG status = nt_query(kNtSystemModuleInformation, buffer.data(),
                                   static_cast<ULONG>(buffer.size()), &length);
      if (status == kStatusInfoLengthMismatch || length > buffer.size()) {
        buffer.resize(buffer.size() * 2);
        continue;
      }
      if (status < 0) break;
      const auto* info = reinterpret_cast<const SystemModuleInformation*>(buffer.data());
      for (ULONG i = 0; i < info->Count; ++i) {
        const SystemModuleEntry& module = info->Modules[i];
        if (reinterpret_cast<uint64_t>(module.ImageBase) != image_base) continue;
        const char* name = reinterpret_cast<const char*>(module.FullPathName);
        std::wstring wide;
        const int chars = MultiByteToWideChar(CP_ACP, 0, name, -1, nullptr, 0);
        if (chars > 0) {
          wide.resize(static_cast<size_t>(chars));
          MultiByteToWideChar(CP_ACP, 0, name, -1, wide.data(), chars);
          if (!wide.empty() && wide.back() == L'\0') wide.pop_back();
        }
        return NtPathToWin32Path(wide);
      }
      break;
    }
  }
  return {};
}

std::wstring ResolveDriverImagePath(const std::wstring& override_path, uint64_t image_base) {
  if (!override_path.empty()) return override_path;

  wchar_t env[MAX_PATH * 2] = {};
  if (GetEnvironmentVariableW(L"ANDAPPSVC_DRIVER_IMAGE", env, ARRAYSIZE(env)) != 0) {
    return env;
  }

  const std::wstring loaded = FindLoadedModulePath(image_base);
  if (!loaded.empty()) return loaded;

  wchar_t system_root[MAX_PATH] = {};
  const UINT n = GetWindowsDirectoryW(system_root, ARRAYSIZE(system_root));
  if (n != 0) return std::wstring(system_root) + L"\\System32\\drivers\\andappsvc2_64.sys";
  return L"C:\\Windows\\System32\\drivers\\andappsvc2_64.sys";
}

bool WriteTextFileUtf8(const std::wstring& path, const std::wstring& text, std::wstring* error) {
  FILE* file = _wfopen(path.c_str(), L"wb");
  if (file == nullptr) {
    if (error) *error = L"cannot write '" + path + L"'";
    return false;
  }
  const std::string utf8 = ToUtf8(text);
  const size_t written = utf8.empty() ? 0 : std::fwrite(utf8.data(), 1, utf8.size(), file);
  std::fclose(file);
  if (written != utf8.size()) {
    if (error) *error = L"short write to '" + path + L"'";
    return false;
  }
  return true;
}

bool AppendTextFileUtf8(const std::wstring& path, const std::wstring& text) {
  FILE* file = _wfopen(path.c_str(), L"ab");
  if (file == nullptr) return false;
  const std::string utf8 = ToUtf8(text);
  const size_t written = utf8.empty() ? 0 : std::fwrite(utf8.data(), 1, utf8.size(), file);
  std::fclose(file);
  return written == utf8.size();
}

bool ReadTextFileUtf8(const std::wstring& path, std::wstring* text) {
  FILE* file = _wfopen(path.c_str(), L"rb");
  if (file == nullptr) return false;
  std::string bytes;
  char buffer[4096];
  size_t got = 0;
  while ((got = std::fread(buffer, 1, sizeof(buffer), file)) != 0) bytes.append(buffer, got);
  std::fclose(file);
  *text = ToWide(bytes);
  return true;
}

}  // namespace andappsvc
