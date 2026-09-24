#include "util.hpp"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <unistd.h>

namespace cg {

std::string Trim(std::string s) {
  auto notspace = [](unsigned char c) { return !std::isspace(c); };
  s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
  s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
  return s;
}

std::string ToLower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

int64_t UnixNow() {
  return static_cast<int64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count());
}

std::string UtcNowIso8601() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

std::string FormatIso8601Utc(int year, int month, int day, int hour, int minute, int second) {
  // Device stamps are wall-clock without TZ. Treat as UTC for API contract (ISO-8601 Z).
  // Org can reinterpret on server if needed.
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ", year, month, day, hour,
                minute, second);
  return buf;
}

std::string HexEncode(const unsigned char* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.resize(len * 2);
  for (size_t i = 0; i < len; ++i) {
    out[i * 2] = kHex[(data[i] >> 4) & 0xF];
    out[i * 2 + 1] = kHex[data[i] & 0xF];
  }
  return out;
}

std::string HmacSha256Hex(const std::string& key, const std::string& message) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int md_len = 0;
  HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
       reinterpret_cast<const unsigned char*>(message.data()), message.size(), md, &md_len);
  return HexEncode(md, md_len);
}

std::string NewUuidV4() {
  unsigned char b[16];
  if (RAND_bytes(b, sizeof(b)) != 1) {
    // Fallback: time-based pseudo
    auto now = UnixNow();
    for (int i = 0; i < 16; ++i) b[i] = static_cast<unsigned char>((now >> (i % 8)) ^ (i * 17));
  }
  b[6] = (b[6] & 0x0F) | 0x40;
  b[8] = (b[8] & 0x3F) | 0x80;
  char buf[37];
  std::snprintf(buf, sizeof(buf),
                "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", b[0], b[1],
                b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
                b[14], b[15]);
  return buf;
}

std::string Hostname() {
  char buf[256];
  if (gethostname(buf, sizeof(buf)) != 0) return "unknown";
  buf[sizeof(buf) - 1] = '\0';
  return buf;
}

bool EnsureDir(const std::string& path, std::string& err) {
  std::error_code ec;
  std::filesystem::create_directories(path, ec);
  if (ec) {
    err = "mkdir " + path + ": " + ec.message();
    return false;
  }
  return true;
}

}  // namespace cg
