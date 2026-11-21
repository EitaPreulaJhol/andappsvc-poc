// Reimplementation of the driver's authentication hash chain.
//
// Chain (all offsets are RVAs inside andappsvc2_64.sys, image base B):
//
//   pid_hash  = 0xAA023824 response   (= 16 x MixHashStep(g_HashSeed ^ pid, 0))
//   token     = HashBuffer[((pid >> 2) & 3)](2, 0, &pid_hash, 4)
//
// HashBuffer_x(depth, seed, data, len)        (0x1400035F0 + 0x170 * x)
//   result  = 0
//   For the two buffers {[(retaddr & ~3) - 256, 512], [data, len]}:
//       n     = size >> 2 (dword count)
//       acc   = n
//       rotA  = rotB = ((n ^ (size >> 12)) & 0xF)
//       for each dword w: acc += ror(w, rotB) + rol(w, rotA); rotB/rotA wrap at 29/23
//       if (n > 1) acc ^= (uint32)buffer_pointer     // only the .text window
//       result ^= acc
//   if (depth) result ^= HashBuffer_[(seed ^ result) & 3](depth - 1, result, NULL, 0)
//   v = MixHashStep(K1, TRUE) ^ K2                       // purely address derived
//   repeat 3x: v ^= MixHash[v & 0xF](v)
//   return result ^ v
//
// MixHashStep(v, TRUE)      (0x1400030F8)
//   builds a bitmask from every 3-bit window of v, then twice:
//   r ^= MixTable_16..31[r & 0xF](r, retaddr)
//
// MixHash_i(v)              (0x140002500 + 0x70 * i)
//   v ^= init; 5 rounds: x = (round == special) ? v ^ round_xor : v;
//                        v = x ^ MixTable_00..31[x & 0x1F](x, retaddr)
//   return v ^ final
//
// MixTable_j(v, retaddr)    (0x1400031F0 + 0x10 * j)
//   return (uint32)retaddr ^ (v & 0xFF) ^ *(uint8 *)(retaddr + kMixTableDisp[j])
//
// `retaddr` is always the runtime address of the instruction following the
// indirect call inside the *caller* (a fixed RVA + B), so the whole chain only
// needs B and the driver's code bytes, which the caller supplies through
// DriverImage.
#include "auth.h"

#include "andappsvc/proto.h"

namespace andappsvc {
namespace {

inline uint32_t ror32(uint32_t v, int n) {
  n &= 31;
  return n ? ((v >> n) | (v << (32 - n))) : v;
}
inline uint32_t rol32(uint32_t v, int n) {
  n &= 31;
  return n ? ((v << n) | (v >> (32 - n))) : v;
}

struct Hasher {
  const DriverImage& image;
  uint64_t base;

  uint32_t MixTable(int index, uint32_t value, uint32_t ret_rva) const {
    const uint32_t disp = static_cast<uint32_t>(static_cast<int64_t>(ret_rva) + kMixTableDisp[index]);
    const uint32_t ret = static_cast<uint32_t>(base + ret_rva);
    return ret ^ (value & 0xFFu) ^ image.ReadU8(disp);
  }

  uint32_t MixHashStep(uint32_t v, bool with_table) const {
    uint32_t r = 0;
    const uint32_t x1 = (v >> 31) | (2u * (v & 3u));
    if (x1 - 1u <= 3u) r |= 1u;
    const uint32_t x2 = (v >> 30) | (4u * (v & 1u));
    if (x2 - 1u <= 3u) r |= 0x80000000u;
    uint32_t sh = v;
    for (int bit = 1; bit < 31; ++bit) {
      if ((sh & 7u) - 1u <= 3u) r |= (1u << bit);
      sh >>= 1;
    }
    if (with_table) {
      r ^= MixTable(16 + (r & 0xF), r, kMixHashStepCallRet[0]);
      r ^= MixTable(16 + (r & 0xF), r, kMixHashStepCallRet[1]);
    }
    return r;
  }

  uint32_t MixHash(int index, uint32_t v) const {
    const uint32_t* p = kMixHashParams[index];
    v ^= p[0];
    for (uint32_t round = 0; round < 5; ++round) {
      const uint32_t x = (round == p[2]) ? (v ^ p[1]) : v;
      v = x ^ MixTable(x & 0x1F, x, kMixHashCallRet[index]);
    }
    return v ^ p[3];
  }

  // Accumulates one buffer.  `rva` is the image RVA of the bytes to hash unless
  // `data` is non-null, in which case those `len` bytes are used instead.
  uint32_t Window(uint32_t rva, uint32_t size, const uint8_t* data = nullptr, uint32_t len = 0) const {
    const uint32_t n = size >> 2;
    uint32_t acc = n;
    int rot_a = static_cast<int>((n ^ (size >> 12)) & 0xF);
    int rot_b = rot_a;
    for (uint32_t i = 0; i < n; ++i) {
      uint32_t w;
      if (data != nullptr) {
        w = 0;
        for (int k = 3; k >= 0; --k) {
          const uint32_t idx = 4 * i + static_cast<uint32_t>(k);
          w = (w << 8) | (idx < len ? data[idx] : 0u);
        }
      } else {
        w = image.ReadU32(rva + 4 * i);
      }
      acc += ror32(w, rot_b) + rol32(w, rot_a);
      rot_b = (rot_b + 1 < 29) ? rot_b + 1 : 0;
      rot_a = (rot_a + 1 < 23) ? rot_a + 1 : 0;
    }
    if (n > 1) acc ^= static_cast<uint32_t>(base + rva);
    return acc;
  }

  uint32_t HashBuffer(int variant, int depth, uint32_t seed, const uint8_t* data, uint32_t len,
                      uint32_t ret_rva) const {
    uint32_t result = 0;
    // The driver hashes the 512 bytes of its own .text that precede the call
    // site: (retaddr & ~3) - 256.
    const uint32_t window_rva = static_cast<uint32_t>((ret_rva & ~3u) - 256u);
    result ^= Window(window_rva, 512);
    if (data != nullptr) result ^= Window(0, len, data, len);
    if (depth != 0) {
      const int child = static_cast<int>((seed ^ result) & 3u);
      result ^= HashBuffer(child, depth - 1, result, nullptr, 0, kHasherRecursiveCallRet[variant]);
    }
    uint32_t v = MixHashStep(kHasherKeys[variant][0], true) ^ kHasherKeys[variant][1];
    for (int i = 0; i < 3; ++i) v ^= MixHash(static_cast<int>(v & 0xF), v);
    return result ^ v;
  }
};

}  // namespace

uint32_t ComputeAuthToken(const DriverImage& image, uint64_t image_base, uint32_t process_id,
                          uint32_t pid_hash) {
  if (!image.loaded()) return 0;
  const Hasher hasher{image, image_base};
  const int variant = static_cast<int>((process_id >> 2) & 3u);
  const uint8_t payload[4] = {static_cast<uint8_t>(pid_hash), static_cast<uint8_t>(pid_hash >> 8),
                              static_cast<uint8_t>(pid_hash >> 16),
                              static_cast<uint8_t>(pid_hash >> 24)};
  return hasher.HashBuffer(variant, 2, 0, payload, 4, kOuterHasherCallRet);
}

}  // namespace andappsvc
