// User-mode client for andappsvc2_64.sys.
//
// Wraps the reconstructed IOCTL interface (see include/andappsvc/proto.h) and
// the authentication hash chain (auth.cpp).
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

#include "andappsvc/proto.h"
#include "driver_image.h"

namespace andappsvc {

struct AccessLogRecord {
  uint32_t pid = 0;
  bool protection_was_disabled = false;  // bit 31 of the slot
  bool table_full = false;               // bit 29 of slot 0
  bool last_denied = false;              // bit 30 (LastDeniedPid entry)
};

class Client {
 public:
  Client() = default;
  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  // Opens \\.\Htsysm49BE01 and thereby creates the caller's session.
  // One session per PID: a second open from the same process fails.
  bool Open(std::wstring* error);
  void Close();
  bool is_open() const { return handle_ != INVALID_HANDLE_VALUE; }

  // ---- level 0 -----------------------------------------------------------
  bool GetProtocolVersion(uint32_t* version, std::wstring* error);
  // Returns HashProcessId() for the caller plus the runtime image base.
  bool GetSessionInfo(uint32_t* pid_hash, uint64_t* image_base, std::wstring* error);
  // Sends the token computed by ComputeAuthToken(); promotes the session to
  // level 1 on a match and *permanently* rejects it (level 2) on a mismatch.
  bool Authenticate(const DriverImage& image, uint64_t image_base, uint32_t pid_hash,
                    uint32_t* token, std::wstring* error);
  // Probes a level-1-only command.  The session level is not readable directly,
  // so this is how a client confirms that authentication succeeded.
  bool IsAuthenticated(std::wstring* error);

  // ---- level 1 -----------------------------------------------------------
  // g_ProtectedImageName := nt_image_path (NT form, e.g. \Device\HarddiskVolume3\...).
  // Also marks the caller's entry Monitored/ProtectionEnabled and installs the
  // Ob callbacks (first successful call wins).
  bool SetProtectedImage(const std::wstring& nt_image_path, std::wstring* error);
  bool SetProtectionEnabled(bool enable, std::wstring* error);
  bool SetTrustedPids(const std::vector<uint32_t>& pids, std::wstring* error);
  bool SetInheritedPidBlacklist(const std::vector<uint32_t>& pids, std::wstring* error);
  bool SetExpectedParentPid(uint32_t pid, std::wstring* error);
  bool ReadAccessLog(std::vector<AccessLogRecord>* records, std::wstring* error);
  // Leaks the kernel return address of IrpMjDeviceControl (nt!IopfCallDriver-ish).
  bool GetKernelReturnAddress(uint64_t* address, std::wstring* error);
  // Hashes a driver .text range: input {rva, size}, output = 32-bit hash.
  bool HashDriverRange(uint32_t rva, uint32_t size, uint32_t* hash, std::wstring* error);

 private:
  bool Ioctl(uint32_t code, const void* in, uint32_t in_length, void* out, uint32_t out_length,
             std::wstring* error);

  HANDLE handle_ = INVALID_HANDLE_VALUE;
};

// Sends an IOCTL and reports the Win32/NTSTATUS error text on failure.
bool SendIoctl(HANDLE device, uint32_t code, const void* in, uint32_t in_length, void* out,
               uint32_t out_length, std::wstring* error);

}  // namespace andappsvc
