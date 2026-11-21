// Self-installation of the embedded andappsvc2_64.sys.
//
// The driver is carried inside the executable as an RCDATA resource (see
// res/andappsvc.rc) and is deployed + started automatically when the client
// launches:
//
//   FindResource(IDR_DRIVER_PAYLOAD)
//     -> %SystemRoot%/System32/drivers/andappsvc2_64.sys
//        (fallback: %ProgramData%/andappsvc/andappsvc2_64.sys)
//   CreateService(SERVICE_KERNEL_DRIVER, "\??\<path>")
//   StartService -> DriverEntry runs and creates the device objects
//     \Device\Htsysm49BE01 and \DosDevices\Htsysm49BE01.
//
// The driver image is Microsoft WHQL signed ("Microsoft Windows Hardware
// Compatibility Publisher"), so it loads with Secure Boot and driver signature
// enforcement enabled.  A file that differs from the embedded payload is
// replaced before the service is (re)started.
#pragma once

#include <windows.h>

#include <cstdint>
#include <string>

namespace andappsvc {

// Must match IDR_DRIVER_PAYLOAD in res/andappsvc.rc.
constexpr int kDriverResourceId = 101;

struct InstallOptions {
  std::wstring service_name = L"andappsvc2";
  std::wstring display_name = L"andappsvc2 process protection driver";
  // Explicit image path; empty = %SystemRoot%\System32\drivers\andappsvc2_64.sys
  std::wstring target_path;
  // Register the service with SERVICE_AUTO_START instead of SERVICE_DEMAND_START.
  bool auto_start = false;
};

struct InstallResult {
  std::wstring image_path;
  bool already_loaded = false;   // the device was usable before we did anything
  bool file_written = false;     // the embedded driver was (re)written
  bool service_created = false;  // CreateService succeeded
  bool service_updated = false;  // ChangeServiceConfig fixed an existing service
  bool service_started = false;  // StartService returned success/already-running
};

// True when \\.\Htsysm49BE01 can be opened (the driver is loaded and a session
// could be created - note that opening it also consumes the caller's session).
bool IsDriverLoaded();

// Extracts the embedded driver and makes sure the device is available.
// Idempotent: if the driver is already running this is a no-op.
bool EnsureDriverLoaded(const InstallOptions& options, InstallResult* result, std::wstring* error);

// Stops the service and deletes it.  With `remove_image` the deployed .sys is
// deleted as well (only when its bytes match the embedded payload).
bool StopAndRemoveDriver(const InstallOptions& options, bool remove_image, std::wstring* error);

// Writes the RCDATA payload to `target_path` (creating directories as needed).
bool ExtractEmbeddedDriver(const std::wstring& target_path, std::wstring* error);

// Size in bytes of the embedded payload (0 when the resource is missing).
uint32_t EmbeddedDriverSize();

}  // namespace andappsvc
