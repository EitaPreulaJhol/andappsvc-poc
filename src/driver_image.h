// Minimal PE image reader used to fetch the driver's .text bytes for the
// authentication hash. Portable (no Windows API) so it can be unit-tested on any
// host OS against the .sys file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace andappsvc {

class DriverImage {
 public:
  // Loads and validates a PE32+ image (the driver).  `path` is UTF-8.
  bool Load(const std::string& path, std::string* error);

  bool loaded() const { return !sections_.empty(); }
  const std::vector<uint8_t>& file() const { return file_; }
  uint64_t preferred_base() const { return preferred_base_; }
  uint32_t size_of_image() const { return size_of_image_; }
  uint32_t time_date_stamp() const { return time_date_stamp_; }

  // Reads `len` bytes at image RVA `rva`.  Returns false when the range is not
  // backed by file data.
  bool ReadRva(uint32_t rva, void* out, size_t len) const;
  uint8_t ReadU8(uint32_t rva) const;
  uint32_t ReadU32(uint32_t rva) const;

  // SHA-256 of the whole file, useful to pin the expected driver build.
  std::string Sha256Hex() const;

 private:
  struct Section {
    uint32_t virtual_address;
    uint32_t virtual_size;
    uint32_t raw_offset;
    uint32_t raw_size;
  };

  bool ReadFileData(const std::string& path, std::string* error);
  const Section* FindSection(uint32_t rva) const;

  std::vector<uint8_t> file_;
  std::vector<Section> sections_;
  uint64_t preferred_base_ = 0;
  uint32_t size_of_image_ = 0;
  uint32_t size_of_headers_ = 0;
  uint32_t time_date_stamp_ = 0;
};

}  // namespace andappsvc
