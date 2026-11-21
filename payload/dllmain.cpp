// andappsvc_payload.dll — runs the protection sequence *inside* the target
// process.
//
// The driver protects the process that owns the session (ObPreOperationCallback
// looks the handle target's PID up in g_ProcessTable and only enforces the
// policy for entries with Monitored != 0, which is only set by IOCTL 0xAA023800
// issued by that very process).  Protecting a foreign process therefore means
// executing this sequence in its context.
//
// The policy is read from "andappsvc_policy.ini" next to this DLL (written by
// andappsvc_client.exe before injection):
//
//   image=<NT image path>      ; default: this process image
//   trusted=1,2,3              ; max 5
//   blacklist=4,5              ; max 3
//   expected_parent=1234
//   enable=1
//   log=C:\path\to\log.txt
//
// On load a worker thread performs the sequence and then keeps the session alive
// (the driver drops the protection on IRP_MJ_CLEANUP when the handle closes) and
// appends every handle-access record to the log file.
#include <windows.h>

#include <cstdio>
#include <cwchar>
#include <string>
#include <vector>

#include "andappsvc.h"
#include "inject.h"
#include "selfprotect.h"
#include "win_util.h"

namespace {

using namespace andappsvc;

HMODULE g_module = nullptr;
CRITICAL_SECTION g_log_lock;

std::wstring g_log_path;

void LogLine(const std::wstring& text) {
  // Always go to the debugger, and to the log file when configured.
  OutputDebugStringW((L"[andappsvc_payload] " + text + L"\n").c_str());
  if (g_log_path.empty()) return;
  EnterCriticalSection(&g_log_lock);
  SYSTEMTIME st;
  GetLocalTime(&st);
  wchar_t stamp[64];
  std::swprintf(stamp, ARRAYSIZE(stamp), L"%04u-%02u-%02u %02u:%02u:%02u  ", st.wYear, st.wMonth,
                st.wDay, st.wHour, st.wMinute, st.wSecond);
  AppendTextFileUtf8(g_log_path, std::wstring(stamp) + text + L"\n");
  LeaveCriticalSection(&g_log_lock);
}

// Reads "key=value" from a UTF-8 policy file (the file is small: read it once).
std::wstring ReadIniValue(const std::wstring& path, const wchar_t* key) {
  std::wstring content;
  if (!ReadTextFileUtf8(path, &content)) return {};
  const size_t key_len = wcslen(key);
  size_t position = 0;
  while (position < content.size()) {
    size_t end = content.find(L'\n', position);
    if (end == std::wstring::npos) end = content.size();
    std::wstring line = content.substr(position, end - position);
    position = end + 1;
    while (!line.empty() && (line.back() == L'\r' || line.back() == L' ')) line.pop_back();
    if (line.size() <= key_len + 1) continue;
    if (_wcsnicmp(line.c_str(), key, key_len) != 0 || line[key_len] != L'=') continue;
    return line.substr(key_len + 1);
  }
  return {};
}

void ParsePidList(const std::wstring& text, std::vector<uint32_t>* out) {
  out->clear();
  size_t start = 0;
  while (start < text.size()) {
    size_t comma = text.find(L',', start);
    if (comma == std::wstring::npos) comma = text.size();
    const std::wstring piece = text.substr(start, comma - start);
    if (!piece.empty()) {
      const unsigned long value = wcstoul(piece.c_str(), nullptr, 0);
      if (value != 0) out->push_back(static_cast<uint32_t>(value));
    }
    start = comma + 1;
  }
}

DWORD WINAPI WorkerThread(void* parameter) {
  (void)parameter;
  wchar_t module_path[MAX_PATH * 4] = {};
  GetModuleFileNameW(g_module, module_path, ARRAYSIZE(module_path));
  std::wstring directory = ModuleDirectory(g_module);
  const std::wstring ini_path = directory.empty() ? L"" : directory + L"\\andappsvc_policy.ini";

  ProtectOptions options;
  std::wstring log_path;
  if (!ini_path.empty() && GetFileAttributesW(ini_path.c_str()) != INVALID_FILE_ATTRIBUTES) {
    options.nt_image_path = ReadIniValue(ini_path, L"image");
    ParsePidList(ReadIniValue(ini_path, L"trusted"), &options.trusted_pids);
    ParsePidList(ReadIniValue(ini_path, L"blacklist"), &options.blacklist_pids);
    const std::wstring parent = ReadIniValue(ini_path, L"expected_parent");
    if (!parent.empty()) options.expected_parent_pid = static_cast<uint32_t>(wcstoul(parent.c_str(), nullptr, 0));
    const std::wstring enable = ReadIniValue(ini_path, L"enable");
    if (!enable.empty()) options.enable = wcstoul(enable.c_str(), nullptr, 0) != 0;
    log_path = ReadIniValue(ini_path, L"log");
    const std::wstring driver = ReadIniValue(ini_path, L"driver_image");
    if (!driver.empty()) options.driver_image_path = driver;
  }
  g_log_path = log_path;
  LogLine(L"payload loaded into pid " + std::to_wstring(GetCurrentProcessId()) +
          L" from " + module_path);

  Protector protector;
  std::wstring error;
  if (!protector.Start(options, &error)) {
    LogLine(L"protection FAILED: " + error);
    return 1;
  }
  wchar_t token_text[16];
  std::swprintf(token_text, ARRAYSIZE(token_text), L"0x%08X", protector.token());
  LogLine(L"authenticated (token " + std::wstring(token_text) + L"), protecting " +
          protector.nt_image_path() + L", driver " + protector.driver_image_path() +
          L", enforcement " + (protector.protection_enabled() ? L"on" : L"off"));

  // Keep the handle (session) alive forever; the driver unregisters the Ob
  // callbacks as soon as the session table empties.
  for (;;) {
    Sleep(1000);
    std::vector<AccessLogRecord> records;
    std::wstring poll_error;
    if (protector.Poll(&records, &poll_error)) {
      for (const AccessLogRecord& record : records) {
        LogLine(L"handle access: " + DescribeAccessLogRecord(record));
      }
    } else {
      LogLine(L"poll failed: " + poll_error);
    }
  }
  return 0;
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved) {
  (void)reserved;
  if (reason == DLL_PROCESS_ATTACH) {
    g_module = module;
    InitializeCriticalSection(&g_log_lock);
    DisableThreadLibraryCalls(module);
    HANDLE thread = CreateThread(nullptr, 0, WorkerThread, nullptr, 0, nullptr);
    if (thread != nullptr) CloseHandle(thread);
  }
  return TRUE;
}
