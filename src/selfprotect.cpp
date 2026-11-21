#include "selfprotect.h"

#include <cstdio>

#include "auth.h"
#include "driver_image.h"
#include "win_util.h"

namespace andappsvc {

Protector::~Protector() { Stop(); }

bool Protector::Start(const ProtectOptions& options, std::wstring* error) {
  if (running_) {
    if (error) *error = L"protector is already running";
    return false;
  }

  // 1. Session: IRP_MJ_CREATE inserts this PID into g_ProcessTable.
  if (!client_.Open(error)) return false;

  // 2. Level-0 handshake.
  if (!client_.GetProtocolVersion(&protocol_version_, error)) {
    client_.Close();
    return false;
  }
  if (!client_.GetSessionInfo(&pid_hash_, &image_base_, error)) {
    client_.Close();
    return false;
  }

  // 3. Reproduce the authentication token from the driver image.
  //    The token is a function of the *runtime* image base, so it can only be
  //    computed after 0xAA023824 leaked it.
  driver_image_path_ = ResolveDriverImagePath(options.driver_image_path, image_base_);
  DriverImage image;
  std::string load_error;
  if (!image.Load(ToUtf8(driver_image_path_), &load_error)) {
    if (error) {
      *error = L"cannot read the driver image '" + driver_image_path_ + L"' (" +
               ToWide(load_error) + L"). Use --driver-image to point at the .sys file.";
    }
    client_.Close();
    return false;
  }

  if (!client_.Authenticate(image, image_base_, pid_hash_, &token_, error)) {
    client_.Close();
    return false;
  }
  // A wrong token leaves the session permanently rejected (CommandLevel 2) and
  // the driver fails every further command, so verify before touching policy.
  if (!client_.IsAuthenticated(error)) {
    client_.Close();
    return false;
  }

  // 4. Policy.  All setters act on the *caller's* PROC_TRACK_ENTRY.
  if (!client_.SetTrustedPids(options.trusted_pids, error) ||
      !client_.SetInheritedPidBlacklist(options.blacklist_pids, error)) {
    client_.Close();
    return false;
  }
  if (options.expected_parent_pid != 0 &&
      !client_.SetExpectedParentPid(options.expected_parent_pid, error)) {
    client_.Close();
    return false;
  }

  nt_image_path_ = options.nt_image_path;
  if (nt_image_path_.empty()) {
    if (!GetOwnNtImagePath(&nt_image_path_, error)) {
      client_.Close();
      return false;
    }
  }

  // 5. Store g_ProtectedImageName and install the Ob callbacks.  This also sets
  //    Monitored = ProtectionEnabled = 1 for this session.
  if (!client_.SetProtectedImage(nt_image_path_, error)) {
    client_.Close();
    return false;
  }

  // 6. The registration path enabled protection unconditionally; honour
  //    --no-enable by clearing the flag again.
  protection_enabled_ = options.enable;
  if (!client_.SetProtectionEnabled(options.enable, error)) {
    client_.Close();
    return false;
  }

  running_ = true;
  return true;
}

void Protector::Stop() {
  if (!running_ && !client_.is_open()) return;
  // Closing the handle is what drops the session (IRP_MJ_CLEANUP).
  client_.Close();
  running_ = false;
  protection_enabled_ = false;
}

bool Protector::Poll(std::vector<AccessLogRecord>* records, std::wstring* error) {
  if (!running_) {
    if (error) *error = L"protector is not running";
    return false;
  }
  return client_.ReadAccessLog(records, error);
}

std::wstring DescribeAccessLogRecord(const AccessLogRecord& record) {
  std::wstring text = L"pid " + std::to_wstring(record.pid);
  if (record.last_denied) text += L" [access stripped]";
  if (record.protection_was_disabled) text += L" [seen while protection was disabled]";
  if (record.table_full) text += L" [access log was full]";
  return text;
}

}  // namespace andappsvc
