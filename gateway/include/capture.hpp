#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "config.hpp"
#include "device_identity.hpp"
#include "http_client.hpp"

namespace cg {

// Local copies under data_dir/capture so a bad parse can be extracted again.
// After a successful upload, the local file is removed once it is 7 days old
// and has not grown since that upload.
void SetCaptureDir(const std::string& data_dir);
void AppendOpsCapture(const std::string& level, const std::string& component, const std::string& code,
                      const std::string& message, const std::string& fields_json);
void AppendRawCapture(const std::string& label, const std::vector<uint8_t>& bytes);
void FlushCaptureArchives(const Config& cfg, const HttpClient& http, const Credential& cred,
                         bool force = false);

}  // namespace cg
