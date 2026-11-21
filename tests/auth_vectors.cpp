// Validates the ported hash chain against vectors produced by an independent
// Python model of the driver's assembly (see re/analysis.md, auth.cpp).
//
//   usage: auth_vectors <path-to-andappsvc2_64.sys>
#include <cstdio>
#include <cstring>

#include "auth.h"
#include "driver_image.h"

namespace {

struct Vector {
  uint64_t image_base;
  uint32_t pid;
  uint32_t pid_hash;
  uint32_t token;
};

// Generated from the IDB (see re/client_testvectors.txt).
constexpr Vector kVectors[] = {
    {0x0000000140000000ULL, 1234, 0xA7689732, 0x19131D4E},
    {0x0000000140000000ULL, 4321, 0x865D0491, 0x1DB8AC2C},
    {0x0000000140000000ULL, 6172, 0x8179E75C, 0xF826A679},
    {0x0000000140000000ULL, 8064, 0xD3794780, 0x13C4927E},
    {0x0000000140000000ULL, 4660, 0x09D329F4, 0x103C38CD},
    {0x0000000140000000ULL, 703696, 0x0B5ADBD0, 0x7D16B6F6},
    {0x0000000140001000ULL, 1234, 0xA7689732, 0x19137D4E},
    {0x0000000140001000ULL, 4321, 0x865D0491, 0x1DB8CC2C},
    {0x0000000140001000ULL, 6172, 0x8179E75C, 0xF826C679},
    {0x0000000140001000ULL, 8064, 0xD3794780, 0x13C4F27E},
    {0x0000000140001000ULL, 4660, 0x09D329F4, 0x103C58CD},
    {0x0000000140001000ULL, 703696, 0x0B5ADBD0, 0x7D16D6F6},
    {0x0000000152340000ULL, 1234, 0xA7689732, 0x19131D4E},
    {0x0000000152340000ULL, 4321, 0x865D0491, 0x1DB8AC2C},
    {0x0000000152340000ULL, 6172, 0x8179E75C, 0xF826A679},
    {0x0000000152340000ULL, 8064, 0xD3794780, 0x13C4927E},
    {0x0000000152340000ULL, 4660, 0x09D329F4, 0x103C38CD},
    {0x0000000152340000ULL, 703696, 0x0B5ADBD0, 0x7D16B6F6},
};

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    std::fprintf(stderr, "usage: %s <andappsvc2_64.sys>\n", argv[0]);
    return 2;
  }
  andappsvc::DriverImage image;
  std::string error;
  if (!image.Load(argv[1], &error)) {
    std::fprintf(stderr, "failed to load image: %s\n", error.c_str());
    return 2;
  }
  std::printf("image: preferred_base=0x%llX size=0x%X timestamp=0x%X sha256=%s\n",
              static_cast<unsigned long long>(image.preferred_base()), image.size_of_image(),
              image.time_date_stamp(), image.Sha256Hex().c_str());

  int failures = 0;
  for (const Vector& v : kVectors) {
    const uint32_t got =
        andappsvc::ComputeAuthToken(image, v.image_base, v.pid, v.pid_hash);
    const bool ok = got == v.token;
    if (!ok) ++failures;
    std::printf("%s base=0x%llX pid=%u pidhash=0x%08X expect=0x%08X got=0x%08X\n",
                ok ? "PASS" : "FAIL", static_cast<unsigned long long>(v.image_base), v.pid,
                v.pid_hash, v.token, got);
  }
  std::printf("%d/%zu vectors passed\n", static_cast<int>(sizeof(kVectors) / sizeof(kVectors[0])) - failures,
              sizeof(kVectors) / sizeof(kVectors[0]));
  return failures == 0 ? 0 : 1;
}
