#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cg {

std::string Trim(std::string s);
std::string ToLower(std::string s);
std::string UtcNowIso8601();
std::string FormatIso8601Utc(int year, int month, int day, int hour, int minute, int second);
std::string NewUuidV4();
std::string HexEncode(const unsigned char* data, size_t len);
std::string HmacSha256Hex(const std::string& key, const std::string& message);
std::string Hostname();
bool EnsureDir(const std::string& path, std::string& err);
int64_t UnixNow();

}  // namespace cg
