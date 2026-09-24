#pragma once

#include <string>

#include "config.hpp"
#include "http_client.hpp"

namespace cg {

struct Credential {
  std::string device_id;
  std::string organization_id;
  std::string auth_secret;     // cp_dev_...
  std::string signing_secret;  // cp_dsig_...
  std::string credential_id;
  std::string scopes_json;
};

struct SignedResult {
  bool ok = false;
  long status = 0;
  std::string body;
  std::string error;
};

// Enroll with pairing code (public, no HMAC). Secrets returned once.
bool EnrollDevice(const Config& cfg, const HttpClient& http, const std::string& pairing_code,
                  Credential& out, std::string& err);

// HMAC-signed request: Authorization Bearer + timestamp + nonce + signature.
SignedResult SignedRequest(const Config& cfg, const HttpClient& http, const Credential& cred,
                           const std::string& method, const std::string& path,
                           const std::string& raw_body);

// ACK after admin rotate — call with NEW credential.
SignedResult AckCredential(const Config& cfg, const HttpClient& http, const Credential& new_cred);

}  // namespace cg
