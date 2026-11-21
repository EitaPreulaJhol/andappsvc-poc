#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "andappsvc.h"

namespace andappsvc {

struct ProtectOptions {
  // Optional override of the on-disk driver image used for the hash chain.
  std::wstring driver_image_path;
  // NT path stored in g_ProtectedImageName.  Empty = the caller's own image.
  std::wstring nt_image_path;
  std::vector<uint32_t> trusted_pids;    // IOCTL 0xAA02380C (max 5)
  std::vector<uint32_t> blacklist_pids;  // IOCTL 0xAA023810 (max 3)
  uint32_t expected_parent_pid = 0;      // IOCTL 0xAA023814
  bool enable = true;                    // IOCTL 0xAA023808 / 0xAA023804
};

// Owns one driver session and keeps it (and therefore the protection) alive.
// Must be destroyed only when protection is no longer needed: the driver drops
// the session on IRP_MJ_CLEANUP and unregisters the Ob callbacks once the
// session table becomes empty.
class Protector {
 public:
  Protector() = default;
  ~Protector();
  Protector(const Protector&) = delete;
  Protector& operator=(const Protector&) = delete;

  bool Start(const ProtectOptions& options, std::wstring* error);
  void Stop();
  bool running() const { return running_; }

  // Drains (and clears) the driver-side access log of this session.
  bool Poll(std::vector<AccessLogRecord>* records, std::wstring* error);

  const std::wstring& driver_image_path() const { return driver_image_path_; }
  const std::wstring& nt_image_path() const { return nt_image_path_; }
  uint64_t image_base() const { return image_base_; }
  uint32_t pid_hash() const { return pid_hash_; }
  uint32_t token() const { return token_; }
  uint32_t protocol_version() const { return protocol_version_; }
  bool protection_enabled() const { return protection_enabled_; }

  Client& client() { return client_; }

 private:
  Client client_;
  std::wstring driver_image_path_;
  std::wstring nt_image_path_;
  uint64_t image_base_ = 0;
  uint32_t pid_hash_ = 0;
  uint32_t token_ = 0;
  uint32_t protocol_version_ = 0;
  bool protection_enabled_ = false;
  bool running_ = false;
};

// Human readable one-line description of an access-log record.
std::wstring DescribeAccessLogRecord(const AccessLogRecord& record);

}  // namespace andappsvc
