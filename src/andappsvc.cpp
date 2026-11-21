#include "andappsvc.h"

#include <winternl.h>

#include <cstdio>
#include <cstring>

#include "auth.h"
#include "win_util.h"

namespace andappsvc {
namespace {

// The driver requires InputBufferLength >= 0x208 for the protected image name
// (CmdSetProtectedImageName), i.e. 260 wchars.
constexpr size_t kProtectedImageBufferBytes = 0x208;

std::wstring Hex32(uint32_t v) {
  wchar_t buf[16];
  std::swprintf(buf, ARRAYSIZE(buf), L"0x%08X", v);
  return buf;
}

// Hints for the statuses the driver actually returns (NTSTATUS mapped by
// kernel32 when DeviceIoControl fails).
std::wstring StatusHint(DWORD error) {
  switch (error) {
    case ERROR_GEN_FAILURE:  // 0xC0000001 STATUS_UNSUCCESSFUL
      return L" [STATUS_UNSUCCESSFUL: session lost/level 2, unknown IOCTL or wrong buffer size]";
    case ERROR_INVALID_PARAMETER:  // 0xC000000D
      return L" [STATUS_INVALID_PARAMETER: the IOCTL expects a different buffer length]";
    case ERROR_MORE_DATA:  // 0xC0000023 STATUS_BUFFER_TOO_SMALL
      return L" [STATUS_BUFFER_TOO_SMALL]";
    case ERROR_INVALID_FUNCTION:  // 0xC0000010 STATUS_INVALID_DEVICE_REQUEST
      return L" [STATUS_INVALID_DEVICE_REQUEST]";
    default:
      return {};
  }
}

}  // namespace

bool SendIoctl(HANDLE device, uint32_t code, const void* in, uint32_t in_length, void* out,
               uint32_t out_length, std::wstring* error) {
  DWORD returned = 0;
  SetLastError(ERROR_SUCCESS);
  const BOOL ok = DeviceIoControl(device, code, const_cast<void*>(in), in_length, out, out_length,
                                  &returned, nullptr);
  if (!ok) {
    const DWORD err = GetLastError();
    if (error) {
      *error = L"IOCTL 0x" + Hex32(code).substr(2) + L" failed: " + Win32ErrorMessage(err) +
               L" (Win32 " + std::to_wstring(err) + L")" + StatusHint(err);
    }
    return false;
  }
  return true;
}

Client::~Client() { Close(); }

void Client::Close() {
  if (handle_ != INVALID_HANDLE_VALUE) {
    // Closing the handle triggers IRP_MJ_CLEANUP, which drops the session
    // (and the Ob callbacks once the session table becomes empty).
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
  }
}

bool Client::Open(std::wstring* error) {
  if (is_open()) return true;
  const wchar_t* paths[] = {
      kDeviceWin32Path,                          // \\.\Htsysm49BE01
      L"\\\\?\\GLOBALROOT\\Device\\Htsysm49BE01",  // NT namespace form
  };
  // The IOCTLs are FILE_ANY_ACCESS, so even a handle with no access rights is
  // enough to talk to the driver.  Prefer read/write, fall back to "query only"
  // so a restrictive device DACL does not get in the way.
  const DWORD access_modes[] = {GENERIC_READ | GENERIC_WRITE, 0};
  DWORD last_error = 0;
  for (const wchar_t* path : paths) {
    for (DWORD access : access_modes) {
      HANDLE h = CreateFileW(path, access, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                             OPEN_EXISTING, 0, nullptr);
      if (h != INVALID_HANDLE_VALUE) {
        handle_ = h;
        return true;
      }
      last_error = GetLastError();
      if (last_error != ERROR_ACCESS_DENIED) break;  // a retry with 0 will not help
    }
  }
  if (error) {
    *error = L"cannot open " + std::wstring(kDeviceWin32Path) + L": " +
             Win32ErrorMessage(last_error) + L" (Win32 " + std::to_wstring(last_error) + L")";
    if (last_error == ERROR_FILE_NOT_FOUND || last_error == ERROR_PATH_NOT_FOUND) {
      *error += L" - is andappsvc2_64.sys loaded?";
    } else if (last_error == ERROR_ACCESS_DENIED) {
      *error += L" - the device ACL normally requires elevation (SYSTEM/Administrators)";
    } else if (last_error == ERROR_GEN_FAILURE) {
      *error += L" - STATUS_UNSUCCESSFUL from IRP_MJ_CREATE: this process already owns a "
                L"session (one per PID) or the 100-entry table is full";
    }
  }
  return false;
}

bool Client::Ioctl(uint32_t code, const void* in, uint32_t in_length, void* out,
                   uint32_t out_length, std::wstring* error) {
  if (!is_open()) {
    if (error) *error = L"device is not open";
    return false;
  }
  return SendIoctl(handle_, code, in, in_length, out, out_length, error);
}

bool Client::GetProtocolVersion(uint32_t* version, std::wstring* error) {
  uint32_t value = 0;
  if (!Ioctl(kCmdGetProtocolVersion, nullptr, 0, &value, sizeof(value), error)) return false;
  *version = value;
  return true;
}

bool Client::GetSessionInfo(uint32_t* pid_hash, uint64_t* image_base, std::wstring* error) {
  // CmdGetSessionInfo writes 16 bytes: ULONG pid_hash, ULONG64 image_base.
  // (The second qword is written as a full 64-bit value by GetDriverImageBase().)
  uint64_t buffer[2] = {};
  if (!Ioctl(kCmdGetSessionInfo, nullptr, 0, buffer, sizeof(buffer), error)) return false;
  *pid_hash = static_cast<uint32_t>(buffer[0]);
  *image_base = buffer[1];
  return true;
}

bool Client::Authenticate(const DriverImage& image, uint64_t image_base, uint32_t pid_hash,
                          uint32_t* token, std::wstring* error) {
  const uint32_t pid = GetCurrentProcessId();
  const uint32_t value = ComputeAuthToken(image, image_base, pid, pid_hash);
  if (value == 0 && !image.loaded()) {
    if (error) *error = L"driver image is not loaded";
    return false;
  }
  // CmdGetProcessIdHash requires InputBufferLength == 4 and OutputBufferLength == 0.
  // A wrong token sets CommandLevel = 2 permanently for this session, so the
  // token must be computed from the *file of the loaded driver*.
  if (!Ioctl(kCmdAuthenticate, &value, sizeof(value), nullptr, 0, error)) return false;
  if (token) *token = value;
  return true;
}

bool Client::IsAuthenticated(std::wstring* error) {
  std::vector<AccessLogRecord> ignored;
  std::wstring local_error;
  if (ReadAccessLog(&ignored, &local_error)) return true;
  if (error) {
    *error = L"session is not at command level 1 (authentication failed or rejected): " +
             local_error;
  }
  return false;
}

bool Client::SetProtectedImage(const std::wstring& nt_image_path, std::wstring* error) {
  if (nt_image_path.empty()) {
    if (error) *error = L"empty protected image path";
    return false;
  }
  if (nt_image_path.size() * sizeof(wchar_t) >= kProtectedImageBufferBytes) {
    if (error) *error = L"protected image path is too long for the driver (max 259 wchars)";
    return false;
  }
  // InputBufferLength must be >= 0x208; the driver copies 260 wchars out of the
  // system buffer with StrCopySafe(wImageName, 0x104, ...).
  std::vector<uint8_t> buffer(kProtectedImageBufferBytes, 0);
  std::memcpy(buffer.data(), nt_image_path.c_str(),
              nt_image_path.size() * sizeof(wchar_t));
  return Ioctl(kCmdSetProtectedImage, buffer.data(), static_cast<uint32_t>(buffer.size()), nullptr,
               0, error);
}

bool Client::SetProtectionEnabled(bool enable, std::wstring* error) {
  return Ioctl(enable ? kCmdEnableProtection : kCmdDisableProtection, nullptr, 0, nullptr, 0,
               error);
}

bool Client::SetTrustedPids(const std::vector<uint32_t>& pids, std::wstring* error) {
  uint32_t buffer[5] = {};
  for (size_t i = 0; i < pids.size() && i < 5; ++i) buffer[i] = pids[i];
  return Ioctl(kCmdSetTrustedPids, buffer, sizeof(buffer), nullptr, 0, error);
}

bool Client::SetInheritedPidBlacklist(const std::vector<uint32_t>& pids, std::wstring* error) {
  uint32_t buffer[3] = {};
  for (size_t i = 0; i < pids.size() && i < 3; ++i) buffer[i] = pids[i];
  return Ioctl(kCmdSetParentBlacklist, buffer, sizeof(buffer), nullptr, 0, error);
}

bool Client::SetExpectedParentPid(uint32_t pid, std::wstring* error) {
  return Ioctl(kCmdSetExpectedParent, &pid, sizeof(pid), nullptr, 0, error);
}

bool Client::ReadAccessLog(std::vector<AccessLogRecord>* records, std::wstring* error) {
  uint32_t slots[12] = {};
  if (!Ioctl(kCmdGetAccessLog, nullptr, 0, slots, sizeof(slots), error)) return false;
  if (records) {
    records->clear();
    for (int i = 0; i < 12; ++i) {
      const uint32_t value = slots[i];
      if (value == 0) continue;
      AccessLogRecord record;
      record.pid = value & 0x1FFFFFFFu;
      record.protection_was_disabled = (value & kGrantProtectionWasOff) != 0;
      record.table_full = (i == 0) && ((value & kGrantTableFull) != 0);
      record.last_denied = (value & kLastDeniedMarker) != 0;
      records->push_back(record);
    }
  }
  return true;
}

bool Client::GetKernelReturnAddress(uint64_t* address, std::wstring* error) {
  uint64_t value = 0;
  if (!Ioctl(kCmdGetReturnAddress, nullptr, 0, &value, sizeof(value), error)) return false;
  *address = value;
  return true;
}

bool Client::HashDriverRange(uint32_t rva, uint32_t size, uint32_t* hash, std::wstring* error) {
  const uint32_t input[2] = {rva, size};
  uint32_t value = 0;
  if (!Ioctl(kCmdHashDriverRange, input, sizeof(input), &value, sizeof(value), error)) return false;
  *hash = value;
  return true;
}

}  // namespace andappsvc
