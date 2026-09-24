#include "device_identity.hpp"

#include <nlohmann/json.hpp>

#include "util.hpp"

namespace cg {

bool EnrollDevice(const Config& cfg, const HttpClient& http, const std::string& pairing_code,
                  Credential& out, std::string& err) {
  nlohmann::json body = {
      {"pairing_code", pairing_code},
      {"client_info",
       {{"agent", cfg.agent_name},
        {"version", cfg.agent_version},
        {"hostname", Hostname()},
        {"device_role", "checkin_gateway"},
        {"terminal_model", "Ronald Jack DG-600-ID"}}},
  };
  std::string raw = body.dump();  // compact
  std::string url = cfg.base_url + "/device-identity/enroll";
  auto resp = http.Request("POST", url, raw, {{"Content-Type", "application/json"}});
  if (!resp.error.empty()) {
    err = resp.error;
    return false;
  }
  if (resp.status != 201) {
    err = "enroll HTTP " + std::to_string(resp.status) + ": " + resp.body;
    return false;
  }
  try {
    auto j = nlohmann::json::parse(resp.body);
    if (!j.value("success", false)) {
      err = "enroll success=false: " + resp.body;
      return false;
    }
    auto d = j.at("data");
    out.device_id = d.value("device_id", "");
    out.organization_id = d.value("organization_id", "");
    out.auth_secret = d.at("auth_secret").get<std::string>();
    out.signing_secret = d.at("signing_secret").get<std::string>();
    out.credential_id = d.value("credential_id", "");
    if (d.contains("scopes")) out.scopes_json = d["scopes"].dump();
    return true;
  } catch (const std::exception& ex) {
    err = std::string("enroll parse: ") + ex.what();
    return false;
  }
}

SignedResult SignedRequest(const Config& cfg, const HttpClient& http, const Credential& cred,
                           const std::string& method, const std::string& path,
                           const std::string& raw_body) {
  SignedResult r;
  if (cred.auth_secret.empty() || cred.signing_secret.empty()) {
    r.error = "missing credentials";
    return r;
  }
  std::string ts = std::to_string(UnixNow());
  std::string nonce = NewUuidV4();
  std::string msg = ts + "." + nonce + "." + raw_body;
  std::string sig = HmacSha256Hex(cred.signing_secret, msg);

  std::map<std::string, std::string> headers = {
      {"Authorization", "Bearer " + cred.auth_secret},
      {"Content-Type", "application/json"},
      {"X-CommaDesk-Timestamp", ts},
      {"X-CommaDesk-Nonce", nonce},
      {"X-CommaDesk-Signature", "sha256=" + sig},
  };
  std::string url = cfg.base_url + path;
  auto resp = http.Request(method, url, raw_body, headers);
  r.status = resp.status;
  r.body = resp.body;
  if (!resp.error.empty()) {
    r.error = resp.error;
    return r;
  }
  r.ok = (resp.status >= 200 && resp.status < 300);
  if (!r.ok) r.error = "HTTP " + std::to_string(resp.status);
  return r;
}

SignedResult AckCredential(const Config& cfg, const HttpClient& http, const Credential& new_cred) {
  return SignedRequest(cfg, http, new_cred, "POST", "/device-identity/credentials/ack", "{}");
}

}  // namespace cg
