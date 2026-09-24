#include "ingest.hpp"

#include <cstdio>
#include <string>

#include <nlohmann/json.hpp>

namespace cg {
namespace {

std::string SanitizeUtf8Local(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  const unsigned char* p = reinterpret_cast<const unsigned char*>(s.data());
  size_t i = 0, n = s.size();
  while (i < n) {
    unsigned char c = p[i];
    if (c <= 0x7F) {
      out.push_back(static_cast<char>(c));
      ++i;
      continue;
    }
    size_t need = 0;
    if ((c & 0xE0) == 0xC0)
      need = 2;
    else if ((c & 0xF0) == 0xE0)
      need = 3;
    else if ((c & 0xF8) == 0xF0)
      need = 4;
    else {
      out.push_back('?');
      ++i;
      continue;
    }
    if (i + need > n) {
      out.push_back('?');
      ++i;
      continue;
    }
    bool ok = true;
    for (size_t j = 1; j < need; ++j) {
      if ((p[i + j] & 0xC0) != 0x80) {
        ok = false;
        break;
      }
    }
    if (!ok) {
      out.push_back('?');
      ++i;
      continue;
    }
    out.append(s, i, need);
    i += need;
  }
  return out;
}

}  // namespace

std::string BuildIngestBody(const AttendanceEvent& ev, const DeviceInfo& device,
                            const Config& cfg) {
  nlohmann::json j;
  j["attendance_code"] = SanitizeUtf8Local(ev.user_id);
  j["timestamp"] = SanitizeUtf8Local(ev.timestamp_iso);

  if (cfg.ingest_minimal) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  }

  j["employee_code"] = SanitizeUtf8Local(ev.user_id);
  j["device_user_id"] = SanitizeUtf8Local(ev.user_id);
  if (!ev.user_name.empty()) j["user_name"] = SanitizeUtf8Local(ev.user_name);
  j["verify_mode"] = ev.verify_mode;
  j["verify_mode_text"] = VerifyModeText(ev.verify_mode);
  j["inout_mode"] = ev.inout_mode;
  j["inout_mode_text"] = InOutModeText(ev.inout_mode);
  j["work_code"] = ev.work_code;
  j["received_at"] =
      SanitizeUtf8Local(ev.received_at_iso.empty() ? ev.timestamp_iso : ev.received_at_iso);
  j["from_live"] = ev.from_live;

  nlohmann::json device_j;
  device_j["ip"] = SanitizeUtf8Local(device.ip.empty() ? cfg.device_ip : device.ip);
  device_j["port"] = device.port ? device.port : cfg.device_port;
  device_j["serial"] = SanitizeUtf8Local(device.serial);
  device_j["firmware"] = SanitizeUtf8Local(device.firmware);
  device_j["platform"] = SanitizeUtf8Local(device.platform);
  device_j["model"] = "Ronald Jack DG-600-ID";
  j["device"] = device_j;

  nlohmann::json agent_j;
  agent_j["name"] = SanitizeUtf8Local(cfg.agent_name);
  agent_j["version"] = SanitizeUtf8Local(cfg.agent_version);
  agent_j["role"] = "checkin_gateway";
  j["source_agent"] = agent_j;

  try {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  } catch (const std::exception& ex) {
    nlohmann::json minimal;
    minimal["attendance_code"] = SanitizeUtf8Local(ev.user_id);
    minimal["timestamp"] = SanitizeUtf8Local(ev.timestamp_iso);
    std::fprintf(stderr, "[ingest] dump fallback: %s\n", ex.what());
    return minimal.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
  }
}

SignedResult PostDeviceIngest(const Config& cfg, const HttpClient& http, const Credential& cred,
                              const std::string& raw_body) {
  return SignedRequest(cfg, http, cred, "POST", "/checkin/device-ingest", raw_body);
}

}  // namespace cg
