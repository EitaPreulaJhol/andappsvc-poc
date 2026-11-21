#include "driver_image.h"

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

namespace andappsvc {
namespace {

constexpr uint16_t kDosMagic = 0x5A4D;      // "MZ"
constexpr uint32_t kNtSignature = 0x00004550;  // "PE\0\0"
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kOptionalMagicPe32Plus = 0x20B;

inline uint16_t Rd16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
inline uint32_t Rd32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
         (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t Rd64(const uint8_t* p) {
  return static_cast<uint64_t>(Rd32(p)) | (static_cast<uint64_t>(Rd32(p + 4)) << 32);
}

// ------------------------------------------------------------------ SHA-256
struct Sha256 {
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  uint64_t length = 0;
  uint8_t buf[64] = {};
  size_t fill = 0;
  uint32_t w[64] = {};

  static uint32_t Rotr(uint32_t v, int n) { return (v >> n) | (v << (32 - n)); }

  void Block(const uint8_t* p) {
    static const uint32_t k[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
    for (int i = 0; i < 16; ++i) {
      // SHA-256 consumes the block as big-endian dwords.
      const uint8_t* q = p + 4 * i;
      w[i] = (static_cast<uint32_t>(q[0]) << 24) | (static_cast<uint32_t>(q[1]) << 16) |
             (static_cast<uint32_t>(q[2]) << 8) | static_cast<uint32_t>(q[3]);
    }
    for (int i = 16; i < 64; ++i) {
      const uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
      const uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int i = 0; i < 64; ++i) {
      const uint32_t s1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t t1 = hh + s1 + ch + k[i] + w[i];
      const uint32_t s0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t t2 = s0 + maj;
      hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
  }

  void Update(const uint8_t* p, size_t n) {
    length += n;
    while (n--) {
      buf[fill++] = *p++;
      if (fill == 64) { Block(buf); fill = 0; }
    }
  }

  std::string Final() {
    const uint64_t bits = length * 8;
    const uint8_t pad0 = 0x80, pad1 = 0;
    Update(&pad0, 1);
    while (fill != 56) Update(&pad1, 1);
    uint8_t len[8];
    for (int i = 0; i < 8; ++i) len[i] = static_cast<uint8_t>(bits >> (56 - 8 * i));
    Update(len, 8);
    char out[65];
    for (int i = 0; i < 8; ++i) std::snprintf(out + 8 * i, 9, "%08x", h[i]);
    return std::string(out, 64);
  }
};

}  // namespace

bool DriverImage::ReadFileData(const std::string& path, std::string* error) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (error) *error = "cannot open '" + path + "'";
    return false;
  }
  file_.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
  if (file_.size() < 0x200) {
    if (error) *error = "'" + path + "' is too small to be a PE image";
    return false;
  }
  return true;
}

bool DriverImage::Load(const std::string& path, std::string* error) {
  file_.clear();
  sections_.clear();
  if (!ReadFileData(path, error)) return false;

  const uint8_t* p = file_.data();
  if (Rd16(p) != kDosMagic) {
    if (error) *error = "missing MZ header";
    return false;
  }
  const uint32_t e_lfanew = Rd32(p + 0x3C);
  if (e_lfanew + 0x108 > file_.size()) {
    if (error) *error = "truncated PE headers";
    return false;
  }
  const uint8_t* nt = p + e_lfanew;
  if (Rd32(nt) != kNtSignature) {
    if (error) *error = "missing PE signature";
    return false;
  }
  const uint8_t* file_header = nt + 4;
  const uint16_t machine = Rd16(file_header + 0);
  const uint16_t section_count = Rd16(file_header + 2);
  time_date_stamp_ = Rd32(file_header + 4);
  const uint16_t optional_size = Rd16(file_header + 16);
  const uint8_t* opt = file_header + 20;
  if (Rd16(opt) != kOptionalMagicPe32Plus) {
    if (error) *error = "not a PE32+ image";
    return false;
  }
  preferred_base_ = Rd64(opt + 24);
  size_of_image_ = Rd32(opt + 56);
  size_of_headers_ = Rd32(opt + 60);
  const uint32_t size_of_headers_from_opt = size_of_headers_;

  const uint8_t* sec = opt + optional_size;
  if (static_cast<size_t>(sec - p) + static_cast<size_t>(section_count) * 40 > file_.size()) {
    if (error) *error = "truncated section table";
    return false;
  }
  for (uint16_t i = 0; i < section_count; ++i, sec += 40) {
    Section s{};
    s.virtual_size = Rd32(sec + 8);
    s.virtual_address = Rd32(sec + 12);
    s.raw_size = Rd32(sec + 16);
    s.raw_offset = Rd32(sec + 20);
    if (s.virtual_size == 0) s.virtual_size = s.raw_size;
    if (s.virtual_address == 0) continue;
    sections_.push_back(s);
  }
  if (sections_.empty()) {
    if (error) *error = "no sections";
    return false;
  }
  (void)machine;
  (void)size_of_headers_from_opt;
  return true;
}

const DriverImage::Section* DriverImage::FindSection(uint32_t rva) const {
  for (const Section& s : sections_) {
    if (rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size) return &s;
  }
  return nullptr;
}

bool DriverImage::ReadRva(uint32_t rva, void* out, size_t len) const {
  if (len == 0) return true;
  auto* dst = static_cast<uint8_t*>(out);
  // Anything inside the headers is mapped 1:1.
  if (rva < size_of_headers_ && rva + len <= size_of_headers_) {
    if (rva + len > file_.size()) return false;
    std::memcpy(dst, file_.data() + rva, len);
    return true;
  }
  const Section* s = FindSection(rva);
  if (s == nullptr) return false;
  const uint32_t delta = rva - s->virtual_address;
  if (delta >= s->raw_size) {
    // zero-filled tail of the section
    std::memset(dst, 0, len);
    return delta + len <= s->virtual_size;
  }
  if (delta + len > s->raw_size) return false;
  const size_t off = static_cast<size_t>(s->raw_offset) + delta;
  if (off + len > file_.size()) return false;
  std::memcpy(dst, file_.data() + off, len);
  return true;
}

uint8_t DriverImage::ReadU8(uint32_t rva) const {
  uint8_t v = 0;
  return ReadRva(rva, &v, 1) ? v : 0;
}

uint32_t DriverImage::ReadU32(uint32_t rva) const {
  uint32_t v = 0;
  return ReadRva(rva, &v, 4) ? v : 0;
}

std::string DriverImage::Sha256Hex() const {
  Sha256 sha;
  if (!file_.empty()) sha.Update(file_.data(), file_.size());
  return sha.Final();
}

}  // namespace andappsvc
