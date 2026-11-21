// andappsvc_client.exe — command line front end for andappsvc2_64.sys.
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <string>
#include <vector>

#include "andappsvc.h"
#include "auth.h"
#include "driver_image.h"
#include "driver_install.h"
#include "inject.h"
#include "selfprotect.h"
#include "win_util.h"

namespace {

using namespace andappsvc;

struct Options {
  std::wstring command;
  std::wstring driver_image;
  std::wstring image;
  std::vector<uint32_t> trusted;
  std::vector<uint32_t> blacklist;
  uint32_t expected_parent = 0;
  bool enable = true;
  bool verbose = false;
  int log_interval_ms = 2000;
  int duration_sec = 0;
  bool once = false;
  uint32_t hash_rva = 0;
  uint32_t hash_size = 0;
  bool has_hash_range = false;
  DWORD target_pid = 0;
  std::wstring dll_path;
  std::wstring log_path;
  std::wstring exe_path;
  std::wstring child_args;
  std::wstring base;
  std::wstring pid_hash;
  // Driver bootstrap (embedded RCDATA payload).
  bool install_driver = true;
  bool service_autostart = false;
  bool remove_image = false;
  std::wstring driver_install_path;
  std::wstring service_name;
};

std::wstring Usage() {
  return L"andappsvc_client.exe — client for andappsvc2_64.sys\n"
         L"\n"
         L"usage: andappsvc_client.exe <command> [options]\n"
         L"\n"
         L"commands:\n"
         L"  info                     protocol version + level-0 information leaks\n"
         L"  token                    compute the authentication token for this process\n"
         L"  self                     protect this process and keep the session open\n"
         L"  protect --pid <n>        inject the payload DLL into a running process\n"
         L"  launch --exe <path> [-- <args>]\n"
         L"                           start suspended, inject the payload, resume\n"
         L"  uninstall                stop and delete the kernel service\n"
         L"\n"
         L"On every launch the embedded andappsvc2_64.sys (RCDATA #101) is deployed to\n"
         L"%SystemRoot%\\System32\\drivers and started through the service control manager,\n"
         L"unless --no-install is given.\n"
         L"\n"
         L"options:\n"
         L"  --driver-image <path>    andappsvc2_64.sys used for the hash chain\n"
         L"                           (default: the loaded module matched by image base)\n"
         L"  --image <nt-path>        NT image path to protect\n"
         L"                           (default: the calling process image)\n"
         L"  --trusted <a,b,...>      trusted PIDs, never blocked (max 5)\n"
         L"  --blacklist <a,b,...>    parent PIDs whose children are never blocked (max 3)\n"
         L"  --expected-parent <pid>  expected parent PID for svchost.exe\n"
         L"  --no-enable              install the policy but leave enforcement off\n"
         L"  --log-interval <ms>      access-log polling interval (default 2000)\n"
         L"  --duration <sec>         stop after N seconds (default 0 = forever)\n"
         L"  --hash-range <rva:size>  level-1 diagnostic: hash a driver .text range\n"
         L"  --once                   run the level-1 diagnostics and exit\n"
         L"  --pid <n>                target process for 'protect'\n"
         L"  --dll <path>             payload DLL (default: beside this exe)\n"
         L"  --log <path>             payload log file\n"
         L"  --base <hex>             override the driver image base ('token')\n"
         L"  --pid-hash <hex>         override the PID hash ('token')\n"
         L"  --no-install             do not deploy/start the embedded driver\n"
         L"  --driver-path <path>     where to deploy the embedded .sys\n"
         L"  --service-autostart      register the kernel service as SERVICE_AUTO_START\n"
         L"  --service-name <name>    kernel service name (default: andappsvc2)\n"
         L"  --remove-file            'uninstall': also delete the deployed .sys\n"
         L"  --verbose\n"
         L"  --help\n";
}

bool ParseU32List(const std::wstring& text, std::vector<uint32_t>* out) {
  out->clear();
  size_t start = 0;
  while (start <= text.size()) {
    const size_t comma = text.find(L',', start);
    const std::wstring piece = text.substr(start, comma == std::wstring::npos ? std::wstring::npos
                                                                              : comma - start);
    if (!piece.empty()) {
      wchar_t* end = nullptr;
      const unsigned long value = wcstoul(piece.c_str(), &end, 0);
      if (end == piece.c_str() || *end != L'\0') return false;
      out->push_back(static_cast<uint32_t>(value));
    }
    if (comma == std::wstring::npos) break;
    start = comma + 1;
  }
  return true;
}

bool ParseArgs(int argc, wchar_t** argv, Options* options, std::wstring* error) {
  if (argc < 2) {
    *error = L"missing command";
    return false;
  }
  options->command = argv[1];
  bool saw_separator = false;
  for (int i = 2; i < argc; ++i) {
    const std::wstring arg = argv[i];
    if (saw_separator) {
      if (!options->child_args.empty()) options->child_args += L' ';
      options->child_args += arg;
      continue;
    }
    if (arg == L"--") {
      saw_separator = true;
      continue;
    }
    auto value = [&](std::wstring* out) -> bool {
      if (i + 1 >= argc) return false;
      *out = argv[++i];
      return true;
    };
    if (arg == L"--help" || arg == L"-h") {
      *error = L"help";
      return false;
    }
    if (arg == L"--verbose" || arg == L"-v") {
      options->verbose = true;
      continue;
    }
    if (arg == L"--no-enable") {
      options->enable = false;
      continue;
    }
    if (arg == L"--once") {
      options->once = true;
      continue;
    }
    if (arg == L"--no-install") {
      options->install_driver = false;
      continue;
    }
    if (arg == L"--service-autostart") {
      options->service_autostart = true;
      continue;
    }
    if (arg == L"--remove-file") {
      options->remove_image = true;
      continue;
    }
    std::wstring text;
    struct ValueOption {
      const wchar_t* name;
      std::wstring* target;
    };
    const ValueOption value_options[] = {
        {L"--driver-image", &options->driver_image},
        {L"--image", &options->image},
        {L"--log", &options->log_path},
        {L"--dll", &options->dll_path},
        {L"--exe", &options->exe_path},
        {L"--base", &options->base},
        {L"--pid-hash", &options->pid_hash},
        {L"--driver-path", &options->driver_install_path},
        {L"--service-name", &options->service_name},
    };
    bool handled = false;
    for (const ValueOption& option : value_options) {
      if (arg != option.name) continue;
      if (!value(option.target)) {
        *error = arg + L" needs a value";
        return false;
      }
      handled = true;
      break;
    }
    if (handled) continue;

    if (arg == L"--trusted" || arg == L"--blacklist") {
      if (!value(&text)) {
        *error = arg + L" needs a value";
        return false;
      }
      std::vector<uint32_t>* target =
          (arg == L"--trusted") ? &options->trusted : &options->blacklist;
      if (!ParseU32List(text, target)) {
        *error = arg + L": expected a comma separated list of PIDs";
        return false;
      }
      continue;
    }
    if (arg == L"--expected-parent" || arg == L"--pid") {
      if (!value(&text)) {
        *error = arg + L" needs a value";
        return false;
      }
      const uint32_t n = static_cast<uint32_t>(wcstoul(text.c_str(), nullptr, 0));
      if (arg == L"--pid") {
        options->target_pid = n;
      } else {
        options->expected_parent = n;
      }
      continue;
    }
    if (arg == L"--log-interval" || arg == L"--duration") {
      if (!value(&text)) {
        *error = arg + L" needs a value";
        return false;
      }
      const int n = static_cast<int>(wcstol(text.c_str(), nullptr, 0));
      if (arg == L"--log-interval") {
        options->log_interval_ms = n;
      } else {
        options->duration_sec = n;
      }
      continue;
    }
    if (arg == L"--hash-range") {
      if (!value(&text)) {
        *error = L"--hash-range needs rva:size";
        return false;
      }
      const size_t colon = text.find(L':');
      if (colon == std::wstring::npos) {
        *error = L"--hash-range: expected rva:size";
        return false;
      }
      const std::wstring rva = text.substr(0, colon);
      const std::wstring size = text.substr(colon + 1);
      options->hash_rva = static_cast<uint32_t>(wcstoul(rva.c_str(), nullptr, 0));
      options->hash_size = static_cast<uint32_t>(wcstoul(size.c_str(), nullptr, 0));
      options->has_hash_range = true;
      continue;
    }
    *error = L"unknown option: " + arg;
    return false;
  }
  return true;
}

std::wstring Timestamp() {
  SYSTEMTIME st;
  GetLocalTime(&st);
  wchar_t buf[32];
  std::swprintf(buf, ARRAYSIZE(buf), L"%02u:%02u:%02u", st.wHour, st.wMinute, st.wSecond);
  return buf;
}

InstallOptions MakeInstallOptions(const Options& options) {
  InstallOptions install;
  install.target_path = options.driver_install_path;
  install.auto_start = options.service_autostart;
  if (!options.service_name.empty()) install.service_name = options.service_name;
  return install;
}

// Deploys the embedded driver and starts the kernel service when needed.  Every
// command that talks to the device goes through this first.
bool BootstrapDriver(const Options& options) {
  if (!options.install_driver) return true;
  InstallOptions install = MakeInstallOptions(options);
  InstallResult result;
  std::wstring error;
  if (!EnsureDriverLoaded(install, &result, &error)) {
    std::fwprintf(stderr, L"error: cannot start the embedded driver: %ls\n", error.c_str());
    return false;
  }
  const uint32_t embedded = EmbeddedDriverSize();
  if (result.already_loaded) {
    if (options.verbose) std::wprintf(L"driver: already loaded\n");
    return true;
  }
  std::wprintf(L"driver: deployed %ls (%u bytes, embedded payload)\n",
               result.image_path.c_str(), embedded);
  std::wprintf(L"driver: service '%ls' %ls%ls, started\n", install.service_name.c_str(),
               result.service_created ? L"created" : L"reused",
               result.service_updated ? L"/updated" : L"");
  return true;
}

int CommandUninstall(const Options& options) {
  InstallOptions install = MakeInstallOptions(options);
  std::wstring error;
  if (!StopAndRemoveDriver(install, options.remove_image, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  std::wprintf(L"service '%ls' stopped and deleted%ls\n", install.service_name.c_str(),
               options.remove_image ? L", deployed image removed" : L"");
  return 0;
}

int CommandInfo(const Options& options) {
  if (!BootstrapDriver(options)) return 1;
  Client client;
  std::wstring error;
  if (!client.Open(&error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  uint32_t version = 0;
  uint32_t pid_hash = 0;
  uint64_t image_base = 0;
  if (!client.GetProtocolVersion(&version, &error) ||
      !client.GetSessionInfo(&pid_hash, &image_base, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  std::wprintf(L"device          : %ls\n", kDeviceWin32Path);
  std::wprintf(L"protocol        : %u (0x%X)\n", version, version);
  std::wprintf(L"caller pid      : %lu\n", GetCurrentProcessId());
  std::wprintf(L"pid hash        : 0x%08X\n", pid_hash);
  std::wprintf(L"image base      : 0x%llX\n", static_cast<unsigned long long>(image_base));
  const std::wstring resolved = ResolveDriverImagePath(options.driver_image, image_base);
  std::wprintf(L"driver image    : %ls\n", resolved.c_str());
  DriverImage image;
  std::string load_error;
  if (image.Load(ToUtf8(resolved), &load_error)) {
    std::wprintf(L"  sha256        : %ls\n", ToWide(image.Sha256Hex()).c_str());
    std::wprintf(L"  timestamp     : 0x%X\n", image.time_date_stamp());
    const uint32_t token = ComputeAuthToken(image, image_base, GetCurrentProcessId(), pid_hash);
    std::wprintf(L"  auth token    : 0x%08X (would be sent by 0xAA023828)\n", token);
  } else {
    std::wprintf(L"  (cannot read: %ls)\n", ToWide(load_error).c_str());
  }
  return 0;
}

int CommandToken(const Options& options) {
  const bool offline = !options.base.empty() && !options.pid_hash.empty();
  if (!offline && !BootstrapDriver(options)) return 1;
  std::wstring error;
  DriverImage image;
  uint32_t pid_hash = 0;
  uint64_t image_base = 0;
  uint32_t pid = GetCurrentProcessId();

  std::wstring driver_path = options.driver_image;
  if (!options.base.empty()) image_base = wcstoull(options.base.c_str(), nullptr, 0);
  if (!options.pid_hash.empty()) pid_hash = static_cast<uint32_t>(wcstoul(options.pid_hash.c_str(), nullptr, 0));

  Client client;
  if (options.base.empty() || options.pid_hash.empty()) {
    if (!client.Open(&error)) {
      std::fwprintf(stderr, L"error: %ls\n", error.c_str());
      return 1;
    }
    if (!client.GetSessionInfo(&pid_hash, &image_base, &error)) {
      std::fwprintf(stderr, L"error: %ls\n", error.c_str());
      return 1;
    }
  }
  if (driver_path.empty()) driver_path = ResolveDriverImagePath({}, image_base);
  std::string load_error;
  if (!image.Load(ToUtf8(driver_path), &load_error)) {
    std::fwprintf(stderr, L"error: cannot read driver image: %ls\n", ToWide(load_error).c_str());
    return 1;
  }
  const uint32_t token = ComputeAuthToken(image, image_base, pid, pid_hash);
  std::wprintf(L"pid=%lu variant=%u\n", pid, (pid >> 2) & 3);
  std::wprintf(L"pid_hash=0x%08X image_base=0x%llX token=0x%08X\n", pid_hash,
               static_cast<unsigned long long>(image_base), token);
  return 0;
}

int CommandSelf(const Options& options) {
  if (!BootstrapDriver(options)) return 1;
  ProtectOptions protect;
  protect.driver_image_path = options.driver_image;
  protect.nt_image_path = options.image;
  protect.trusted_pids = options.trusted;
  protect.blacklist_pids = options.blacklist;
  protect.expected_parent_pid = options.expected_parent;
  protect.enable = options.enable;

  Protector protector;
  std::wstring error;
  if (!protector.Start(protect, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  std::wprintf(L"session established for pid %lu\n", GetCurrentProcessId());
  std::wprintf(L"  protocol     : %u\n", protector.protocol_version());
  std::wprintf(L"  driver base  : 0x%llX\n", static_cast<unsigned long long>(protector.image_base()));
  std::wprintf(L"  driver file  : %ls\n", protector.driver_image_path().c_str());
  std::wprintf(L"  token        : 0x%08X (accepted)\n", protector.token());
  std::wprintf(L"  protected    : %ls\n", protector.nt_image_path().c_str());
  std::wprintf(L"  enforcement  : %ls\n", protector.protection_enabled() ? L"enabled" : L"disabled");
  std::wprintf(L"  trusted pids : %zu, blacklist: %zu\n", protect.trusted_pids.size(),
               protect.blacklist_pids.size());
  if (!protect.trusted_pids.empty() || !protect.blacklist_pids.empty()) {
    // The driver stores only 5 / 3 slots.
    if (protect.trusted_pids.size() > 5 || protect.blacklist_pids.size() > 3) {
      std::fwprintf(stderr, L"warning: extra PIDs were truncated by the driver\n");
    }
  }

  if (options.has_hash_range) {
    uint32_t hash = 0;
    if (!protector.client().HashDriverRange(options.hash_rva, options.hash_size, &hash, &error)) {
      std::fwprintf(stderr, L"error: %ls\n", error.c_str());
      return 1;
    }
    std::wprintf(L"hash of rva 0x%X+0x%X = 0x%08X\n", options.hash_rva, options.hash_size, hash);
    if (options.once) return 0;
  }
  if (options.once) {
    // Keep the session until we are done printing; the destructor drops it.
    return 0;
  }

  const ULONGLONG start = GetTickCount64();
  std::wprintf(L"protecting - press Ctrl+C to stop\n");
  for (;;) {
    Sleep(static_cast<DWORD>(options.log_interval_ms < 100 ? 100 : options.log_interval_ms));
    std::vector<AccessLogRecord> records;
    std::wstring poll_error;
    if (protector.Poll(&records, &poll_error)) {
      for (const AccessLogRecord& record : records) {
        std::wprintf(L"[%ls] handle access: %ls\n", Timestamp().c_str(),
                     DescribeAccessLogRecord(record).c_str());
      }
    } else {
      std::fwprintf(stderr, L"poll failed: %ls\n", poll_error.c_str());
    }
    if (options.duration_sec > 0 &&
        GetTickCount64() - start >= static_cast<ULONGLONG>(options.duration_sec) * 1000) {
      std::wprintf(L"duration elapsed, closing the session\n");
      break;
    }
  }
  return 0;
}

std::wstring DefaultPayloadPath() {
  wchar_t exe[MAX_PATH * 4] = {};
  if (GetModuleFileNameW(nullptr, exe, ARRAYSIZE(exe)) == 0) return L"andappsvc_payload.dll";
  std::wstring path = exe;
  const size_t slash = path.find_last_of(L'\\');
  if (slash == std::wstring::npos) return L"andappsvc_payload.dll";
  return path.substr(0, slash + 1) + L"andappsvc_payload.dll";
}

std::wstring DefaultPayloadLog(DWORD pid) {
  wchar_t temp[MAX_PATH] = {};
  if (GetTempPathW(ARRAYSIZE(temp), temp) == 0) return L"andappsvc_payload.log";
  return std::wstring(temp) + L"andappsvc_" + std::to_wstring(pid) + L".log";
}

bool PreparePayload(const Options& options, DWORD pid, std::wstring* dll_out,
                    std::wstring* log_out, std::wstring* error) {
  *dll_out = options.dll_path.empty() ? DefaultPayloadPath() : options.dll_path;
  *log_out = options.log_path.empty() ? DefaultPayloadLog(pid) : options.log_path;

  ProtectOptions policy;
  policy.nt_image_path = options.image;
  policy.trusted_pids = options.trusted;
  policy.blacklist_pids = options.blacklist;
  policy.expected_parent_pid = options.expected_parent;
  policy.enable = options.enable;

  std::wstring ini = *dll_out;
  const size_t slash = ini.find_last_of(L'\\');
  if (slash == std::wstring::npos) {
    if (error) *error = L"payload path must be absolute";
    return false;
  }
  ini = ini.substr(0, slash + 1) + L"andappsvc_policy.ini";
  if (!WritePayloadPolicy(ini, policy, *log_out, error)) return false;
  if (options.verbose) std::wprintf(L"policy written to %ls\n", ini.c_str());
  return true;
}

int CommandProtect(const Options& options) {
  if (!BootstrapDriver(options)) return 1;
  if (options.target_pid == 0) {
    std::fwprintf(stderr, L"error: --pid is required\n");
    return 1;
  }
  std::wstring dll, log, error;
  if (!PreparePayload(options, options.target_pid, &dll, &log, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  HANDLE process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION |
                                   PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                               FALSE, options.target_pid);
  if (process == nullptr) {
    std::fwprintf(stderr, L"error: OpenProcess(%lu): %ls\n", options.target_pid,
                  Win32ErrorMessage(GetLastError()).c_str());
    return 1;
  }
  uint64_t module = 0;
  const bool ok = InjectLibrary(process, dll, &module, &error);
  CloseHandle(process);
  if (!ok) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  std::wprintf(L"payload loaded into pid %lu (module base 0x%llX)\n", options.target_pid,
               static_cast<unsigned long long>(module));
  std::wprintf(L"payload log: %ls\n", log.c_str());
  return 0;
}

int CommandLaunch(const Options& options) {
  if (!BootstrapDriver(options)) return 1;
  if (options.exe_path.empty()) {
    std::fwprintf(stderr, L"error: --exe is required\n");
    return 1;
  }
  std::wstring command_line = L"\"" + options.exe_path + L"\"";
  if (!options.child_args.empty()) command_line += L" " + options.child_args;

  LaunchedProcess launched;
  std::wstring error;
  if (!LaunchSuspended(command_line, &launched, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    return 1;
  }
  // The policy (and the default log file name) needs the real PID, so it is
  // written after CreateProcessW but before the payload is mapped in.
  std::wstring dll, log;
  if (!PreparePayload(options, launched.pid, &dll, &log, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    TerminateProcess(launched.process, 1);
    return 1;
  }
  uint64_t module = 0;
  if (!InjectLibrary(launched.process, dll, &module, &error)) {
    std::fwprintf(stderr, L"error: %ls\n", error.c_str());
    TerminateProcess(launched.process, 1);
    return 1;
  }
  if (ResumeThread(launched.thread) == static_cast<DWORD>(-1)) {
    std::fwprintf(stderr, L"error: ResumeThread failed\n");
    TerminateProcess(launched.process, 1);
    return 1;
  }
  std::wprintf(L"launched pid %lu with the payload preloaded\n", launched.pid);
  std::wprintf(L"payload log: %ls\n", log.c_str());
  launched.Close();
  return 0;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  Options options;
  std::wstring error;
  if (!ParseArgs(argc, argv, &options, &error)) {
    if (error == L"help") {
      std::wprintf(L"%ls", Usage().c_str());
      return 0;
    }
    std::fwprintf(stderr, L"error: %ls\n\n%ls", error.c_str(), Usage().c_str());
    return 2;
  }
  if (options.command == L"--help" || options.command == L"help") {
    std::wprintf(L"%ls", Usage().c_str());
    return 0;
  }
  if (!IsElevated()) {
    std::fwprintf(stderr,
                  L"warning: not elevated.  Deploying/starting the driver and the IOCTLs need "
                  L"an administrator token (the embedded manifest requests it; use \"Run as "
                  L"administrator\" when the manifest was stripped).\n");
  }

  if (options.command == L"info") return CommandInfo(options);
  if (options.command == L"token") return CommandToken(options);
  if (options.command == L"self") return CommandSelf(options);
  if (options.command == L"uninstall") return CommandUninstall(options);
  if (options.command == L"protect") return CommandProtect(options);
  if (options.command == L"launch") return CommandLaunch(options);

  std::fwprintf(stderr, L"error: unknown command '%ls'\n\n%ls", options.command.c_str(),
                Usage().c_str());
  return 2;
}
