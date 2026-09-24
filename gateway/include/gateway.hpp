#pragma once

#include "config.hpp"

namespace cg {

int RunGateway(const Config& cfg);
int RunEnroll(const Config& cfg, const std::string& pairing_code);
// Import rotated secrets from JSON file, ACK with new credential, persist.
// JSON keys: auth_secret, signing_secret; optional device_id, organization_id, credential_id, scopes.
int RunAckRotate(const Config& cfg, const std::string& secrets_json_path);

}  // namespace cg
