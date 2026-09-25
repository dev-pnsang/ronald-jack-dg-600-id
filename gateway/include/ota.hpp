#pragma once

#include <string>

#include "config.hpp"
#include "device_identity.hpp"
#include "http_client.hpp"
#include "store.hpp"

namespace cg {

struct OtaCheckInfo {
  bool update = false;
  std::string job_id;
  std::string package_version;
  std::string package_name;
  std::string download_url;
  std::string checksum_sha256;
};

// Run one OTA cycle: check → download → verify → install → report.
// once=true: single run then return; once=false: loop on schedule slots.
int RunOtaService(Config cfg, bool once);

bool OtaCheck(const Config& cfg, const HttpClient& http, const Credential& cred, OtaCheckInfo& out,
              std::string& err);
bool OtaReport(const Config& cfg, const HttpClient& http, const Credential& cred,
               const std::string& job_id, const std::string& status, int progress_pct,
               const std::string& error_code, const std::string& error_message,
               const std::string& installed_version, std::string& err);

}  // namespace cg
