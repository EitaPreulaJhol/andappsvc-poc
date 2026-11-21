#pragma once

#include <cstdint>

#include "driver_image.h"

namespace andappsvc {

// Reproduces the token required by IOCTL 0xAA023828 for the calling process.
//
//  image       - the on-disk andappsvc2_64.sys (same build as the loaded driver)
//  image_base  - the driver's *runtime* image base, obtained from IOCTL 0xAA023824
//  process_id  - the calling process id (PsGetCurrentProcessId() inside the driver)
//  pid_hash    - the first ULONG64 returned by IOCTL 0xAA023824
//
// Returns 0 only if the image failed to load (callers should pre-validate).
uint32_t ComputeAuthToken(const DriverImage& image, uint64_t image_base, uint32_t process_id,
                          uint32_t pid_hash);

}  // namespace andappsvc
