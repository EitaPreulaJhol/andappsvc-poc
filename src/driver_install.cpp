#include "driver_install.h"

#include <winsvc.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include "andappsvc/proto.h"
#include "win_util.h"

namespace andappsvc {
namespace {

// Not present in every SDK (mingw), 577 == ERROR_INVALID_IMAGE_HASH.
constexpr DWORD kErrorInvalidImageHash = 577;

struct ResourceBlob {
  const uint8_t* data = nullptr;
  uint32_t size = 0;
  HRSRC handle = nullptr;
  HGLOBAL loaded = nullptr;
};

bool LockEmbeddedDriver(ResourceBlob* blob, std::wstring* error) {
  HRSRC resource = FindResourceW(nullptr, MAKEINTRESOURCEW(kDriverResourceId),
                                 MAKEINTRESOURCEW(10) /* RT_RCDATA */);
  if (resource == nullptr) {
    if (error) *error = L"the embedded driver resource (RCDATA #" +
                        std::to_wstring(kDriverResourceId) + L") is missing";
    return false;
  }
  HGLOBAL loaded = LoadResource(nullptr, resource);
  if (loaded == nullptr) {
    if (error) *error = L"LoadResource failed: " + Win32ErrorMessage(GetLastError());
    return false;
  }
  blob->handle = resource;
  blob->loaded = loaded;
  blob->data = static_cast<const uint8_t*>(LockResource(loaded));
  blob->size = SizeofResource(nullptr, resource);
  if (blob->data == nullptr || blob->size == 0) {
    if (error) *error = L"the embedded driver resource is empty";
    return false;
  }
  return true;
}

std::wstring DefaultDriverPath() {
  wchar_t system_root[MAX_PATH] = {};
  if (GetWindowsDirectoryW(system_root, ARRAYSIZE(system_root)) == 0) {
    return L"C:\\Windows\\System32\\drivers\\andappsvc2_64.sys";
  }
  return std::wstring(system_root) + L"\\System32\\drivers\\andappsvc2_64.sys";
}

std::wstring ProgramDataDriverPath() {
  wchar_t program_data[MAX_PATH] = {};
  const DWORD len = GetEnvironmentVariableW(L"ProgramData", program_data, ARRAYSIZE(program_data));
  if (len == 0 || len >= ARRAYSIZE(program_data)) {
    return L"C:\\ProgramData\\andappsvc\\andappsvc2_64.sys";
  }
  return std::wstring(program_data) + L"\\andappsvc\\andappsvc2_64.sys";
}

bool FileEquals(const std::wstring& path, const ResourceBlob& blob) {
  HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr, OPEN_EXISTING, 0, nullptr);
  if (file == INVALID_HANDLE_VALUE) return false;
  LARGE_INTEGER size = {};
  if (!GetFileSizeEx(file, &size) || size.QuadPart != blob.size) {
    CloseHandle(file);
    return false;
  }
  std::vector<uint8_t> buffer(blob.size);
  DWORD read = 0;
  const BOOL ok =
      ReadFile(file, buffer.data(), blob.size, &read, nullptr) && read == blob.size;
  CloseHandle(file);
  return ok && std::memcmp(buffer.data(), blob.data, blob.size) == 0;
}

bool WriteAll(HANDLE file, const uint8_t* data, uint32_t size) {
  uint32_t offset = 0;
  while (offset < size) {
    DWORD written = 0;
    if (!WriteFile(file, data + offset, size - offset, &written, nullptr) || written == 0) {
      return false;
    }
    offset += written;
  }
  return true;
}

bool WriteDriverFile(const std::wstring& path, const ResourceBlob& blob, std::wstring* error) {
  // Make sure the parent directory exists.
  const size_t slash = path.find_last_of(L'\\');
  if (slash != std::wstring::npos) {
    const std::wstring directory = path.substr(0, slash);
    CreateDirectoryW(directory.c_str(), nullptr);  // best effort, may already exist
  }
  HANDLE file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    if (error) {
      *error = L"cannot write '" + path + L"': " + Win32ErrorMessage(GetLastError()) +
               L" (elevation required?)";
    }
    return false;
  }
  const bool ok = WriteAll(file, blob.data, blob.size);
  if (ok) FlushFileBuffers(file);
  CloseHandle(file);
  if (!ok && error) *error = L"short write to '" + path + L"'";
  return ok;
}

bool WaitForDevice(int timeout_ms) {
  const ULONGLONG deadline = GetTickCount64() + static_cast<ULONGLONG>(timeout_ms);
  for (;;) {
    HANDLE device = CreateFileW(kDeviceWin32Path, GENERIC_READ | GENERIC_WRITE,
                                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                                nullptr);
    if (device != INVALID_HANDLE_VALUE) {
      // Opening the device creates a session for this PID; close it again so the
      // real client can open it later.  (IRP_MJ_CLEANUP drops the session.)
      CloseHandle(device);
      return true;
    }
    if (GetLastError() == ERROR_GEN_FAILURE) return true;  // device up, session exists
    if (GetTickCount64() >= deadline) return false;
    Sleep(100);
  }
}

}  // namespace

bool IsDriverLoaded() {
  HANDLE device = CreateFileW(kDeviceWin32Path, GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0,
                              nullptr);
  if (device != INVALID_HANDLE_VALUE) {
    CloseHandle(device);
    return true;
  }
  DWORD error = GetLastError();
  if (error == ERROR_ACCESS_DENIED) {
    device = CreateFileW(kDeviceWin32Path, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                         OPEN_EXISTING, 0, nullptr);
    if (device != INVALID_HANDLE_VALUE) {
      CloseHandle(device);
      return true;
    }
    error = GetLastError();
  }
  // ERROR_GEN_FAILURE == STATUS_UNSUCCESSFUL from IRP_MJ_CREATE, i.e. the device
  // exists but this PID already owns a session (or the 100-entry table is full).
  return error == ERROR_GEN_FAILURE;
}

uint32_t EmbeddedDriverSize() {
  ResourceBlob blob;
  std::wstring ignored;
  return LockEmbeddedDriver(&blob, &ignored) ? blob.size : 0;
}

bool ExtractEmbeddedDriver(const std::wstring& target_path, std::wstring* error) {
  ResourceBlob blob;
  if (!LockEmbeddedDriver(&blob, error)) return false;
  return WriteDriverFile(target_path, blob, error);
}

bool EnsureDriverLoaded(const InstallOptions& options, InstallResult* result, std::wstring* error) {
  InstallResult local{};
  if (result == nullptr) result = &local;

  if (IsDriverLoaded()) {
    result->already_loaded = true;
    return true;
  }

  // ---- 1. deploy the embedded image -------------------------------------
  ResourceBlob blob;
  if (!LockEmbeddedDriver(&blob, error)) return false;

  std::wstring image_path = options.target_path.empty() ? DefaultDriverPath() : options.target_path;
  if (!FileEquals(image_path, blob)) {
    std::wstring write_error;
    if (WriteDriverFile(image_path, blob, &write_error)) {
      result->file_written = true;
    } else if (options.target_path.empty()) {
      // %SystemRoot%\System32\drivers is not writable (or blocked by a filter):
      // fall back to ProgramData, which the SCM accepts as an absolute path.
      const std::wstring fallback = ProgramDataDriverPath();
      if (!WriteDriverFile(fallback, blob, error)) {
        if (error) *error = write_error + L"; fallback failed: " + *error;
        return false;
      }
      image_path = fallback;
      result->file_written = true;
    } else {
      if (error) *error = write_error;
      return false;
    }
  }
  result->image_path = image_path;

  // ---- 2. create/update the kernel service ------------------------------
  // \??\ makes the path an NT object-manager path, which is what the kernel
  // loader expects for a driver image outside SystemRoot\System32.
  const std::wstring binary_path = L"\\??\\" + image_path;
  const DWORD start_type = options.auto_start ? SERVICE_AUTO_START : SERVICE_DEMAND_START;

  SC_HANDLE scm =
      OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
  if (scm == nullptr) {
    const DWORD err = GetLastError();
    if (error) {
      *error = L"OpenSCManager failed: " + Win32ErrorMessage(err) +
               (err == ERROR_ACCESS_DENIED ? L" (run elevated)" : L"");
    }
    return false;
  }

  SC_HANDLE service = CreateServiceW(
      scm, options.service_name.c_str(), options.display_name.c_str(),
      SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | DELETE,
      SERVICE_KERNEL_DRIVER, start_type, SERVICE_ERROR_NORMAL, binary_path.c_str(), nullptr, nullptr,
      nullptr, nullptr, nullptr);

  if (service != nullptr) {
    result->service_created = true;
  } else {
    const DWORD create_error = GetLastError();
    if (create_error != ERROR_SERVICE_EXISTS && create_error != ERROR_ACCESS_DENIED) {
      if (error) *error = L"CreateService failed: " + Win32ErrorMessage(create_error);
      CloseServiceHandle(scm);
      return false;
    }
    if (create_error == ERROR_ACCESS_DENIED) {
      if (error) *error = L"CreateService failed: access denied (run elevated)";
      CloseServiceHandle(scm);
      return false;
    }
    // The service exists: make sure it points at our freshly deployed image and
    // that it is not disabled.
    service = OpenServiceW(scm, options.service_name.c_str(),
                           SERVICE_START | SERVICE_STOP | SERVICE_QUERY_STATUS |
                               SERVICE_CHANGE_CONFIG | DELETE);
    if (service == nullptr) {
      if (error) *error = L"OpenService failed: " + Win32ErrorMessage(GetLastError());
      CloseServiceHandle(scm);
      return false;
    }
    if (ChangeServiceConfigW(service, SERVICE_NO_CHANGE, start_type, SERVICE_NO_CHANGE,
                             binary_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                             nullptr)) {
      result->service_updated = true;
    }
  }
  CloseServiceHandle(scm);

  // ---- 3. start it -------------------------------------------------------
  if (!StartServiceW(service, 0, nullptr)) {
    const DWORD start_error = GetLastError();
    if (start_error == ERROR_SERVICE_ALREADY_RUNNING) {
      result->service_started = true;
    } else if (start_error == ERROR_SERVICE_DISABLED) {
      // Re-enable a service somebody disabled and retry once.
      if (!ChangeServiceConfigW(service, SERVICE_NO_CHANGE, start_type, SERVICE_NO_CHANGE,
                                binary_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr,
                                nullptr) ||
          !StartServiceW(service, 0, nullptr)) {
        if (error) {
          *error = L"StartService failed: " + Win32ErrorMessage(start_error) +
                   L" (the driver image must be signed; check the System event log for "
                   L"code integrity / signature errors)";
        }
        CloseServiceHandle(service);
        return false;
      }
      result->service_started = true;
    } else {
      // 577 = ERROR_IMAGE_NOT_SIGNED-ish (invalid image hash), 1275 = driver blocked
      if (error) {
        *error = L"StartService failed: " + Win32ErrorMessage(start_error) +
                 L" (Win32 " + std::to_wstring(start_error) + L")" +
                 (start_error == kErrorInvalidImageHash
                      ? L" - signature rejected by the kernel"
                      : L"");
      }
      CloseServiceHandle(service);
      return false;
    }
  } else {
    result->service_started = true;
  }

  // Confirm the SCM reports the driver as running (it may take a moment).
  SERVICE_STATUS status = {};
  for (int i = 0; i < 50; ++i) {
    if (!QueryServiceStatus(service, &status)) break;
    if (status.dwCurrentState == SERVICE_RUNNING) break;
    if (status.dwCurrentState == SERVICE_STOPPED) {
      if (error) {
        *error = L"the driver service stopped immediately (Win32 " +
                 std::to_wstring(status.dwWin32ExitCode) + L") - check the System event log";
      }
      CloseServiceHandle(service);
      return false;
    }
    Sleep(100);
  }
  CloseServiceHandle(service);

  // ---- 4. wait for \Device\Htsysm49BE01 --------------------------------
  if (!WaitForDevice(5000)) {
    if (error) *error = L"the driver reported a successful start but the device did not appear";
    return false;
  }
  return true;
}

bool StopAndRemoveDriver(const InstallOptions& options, bool remove_image, std::wstring* error) {
  SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
  if (scm == nullptr) {
    if (error) *error = L"OpenSCManager failed: " + Win32ErrorMessage(GetLastError());
    return false;
  }
  SC_HANDLE service = OpenServiceW(scm, options.service_name.c_str(),
                                   SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
  if (service == nullptr) {
    const DWORD err = GetLastError();
    CloseServiceHandle(scm);
    if (err == ERROR_SERVICE_DOES_NOT_EXIST) return true;  // nothing to do
    if (error) *error = L"OpenService failed: " + Win32ErrorMessage(err);
    return false;
  }

  bool ok = true;
  SERVICE_STATUS status = {};
  if (!ControlService(service, SERVICE_CONTROL_STOP, &status)) {
    const DWORD err = GetLastError();
    if (err != ERROR_SERVICE_NOT_ACTIVE) {
      ok = false;
      if (error) *error = L"ControlService(STOP) failed: " + Win32ErrorMessage(err);
    }
  } else {
    // Give the driver a moment to run its unload path.
    for (int i = 0; i < 30; ++i) {
      if (!QueryServiceStatus(service, &status) || status.dwCurrentState == SERVICE_STOPPED) break;
      Sleep(100);
    }
  }

  if (!DeleteService(service)) {
    const DWORD err = GetLastError();
    if (err != ERROR_SERVICE_MARKED_FOR_DELETE) {
      ok = false;
      if (error) *error = L"DeleteService failed: " + Win32ErrorMessage(err);
    }
  }
  CloseServiceHandle(service);
  CloseServiceHandle(scm);

  if (ok && remove_image) {
    // Only delete a file that is byte-identical to the embedded payload.
    ResourceBlob blob;
    std::wstring ignored;
    const std::wstring candidates[] = {options.target_path.empty() ? DefaultDriverPath()
                                                                   : options.target_path,
                                       ProgramDataDriverPath()};
    for (const std::wstring& path : candidates) {
      if (path.empty()) continue;
      if (!LockEmbeddedDriver(&blob, &ignored)) break;
      if (!FileEquals(path, blob)) continue;
      if (!DeleteFileW(path.c_str())) {
        // Pending delete on reboot is fine.
        MoveFileExW(path.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
      }
    }
  }
  return ok;
}

}  // namespace andappsvc
