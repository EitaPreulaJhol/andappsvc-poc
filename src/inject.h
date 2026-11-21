#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "selfprotect.h"

namespace andappsvc {

struct LaunchedProcess {
  HANDLE process = nullptr;
  HANDLE thread = nullptr;
  DWORD pid = 0;

  void Close();
};

bool IsElevated();

// Loads `dll_path` (absolute, existing file) into the target process by
// CreateRemoteThread(LoadLibraryW).  Returns the remote module base in
// `module_base` when requested.
bool InjectLibrary(HANDLE process, const std::wstring& dll_path, uint64_t* module_base,
                   std::wstring* error);

bool LaunchSuspended(const std::wstring& command_line, LaunchedProcess* launched,
                     std::wstring* error);

// The payload reads "<dll directory>\andappsvc_policy.ini".  This writes it.
bool WritePayloadPolicy(const std::wstring& path, const ProtectOptions& options,
                        const std::wstring& log_path, std::wstring* error);

// "<dll directory>" of a module already loaded in this process.
std::wstring ModuleDirectory(HMODULE module);

}  // namespace andappsvc
