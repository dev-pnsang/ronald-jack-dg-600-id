#include "ingest.hpp"

#include <nlohmann/json.hpp>

namespace cg {

std::string BuildIngestBody(const AttendanceEvent& ev, const DeviceInfo& device,
                            const Config& cfg) {
  // Contract fields from device-ingest.md + all available punch/device extras.
  // Server may ignore unknown fields; required identity field is always attendance_code.
  nlohmann::json j;
  j["attendance_code"] = ev.user_id;
  j["employee_code"] = ev.user_id;  // also send local ID; server resolve order handles both
  j["timestamp"] = ev.timestamp_iso;

  j["device_user_id"] = ev.user_id;
  if (!ev.user_name.empty()) j["user_name"] = ev.user_name;
  j["verify_mode"] = ev.verify_mode;
  j["verify_mode_text"] = VerifyModeText(ev.verify_mode);
  j["inout_mode"] = ev.inout_mode;
  j["inout_mode_text"] = InOutModeText(ev.inout_mode);
  j["work_code"] = ev.work_code;
  j["received_at"] = ev.received_at_iso.empty() ? ev.timestamp_iso : ev.received_at_iso;
  j["from_live"] = ev.from_live;

  j["device"] = {
      {"ip", device.ip.empty() ? cfg.device_ip : device.ip},
      {"port", device.port ? device.port : cfg.device_port},
      {"serial", device.serial},
      {"firmware", device.firmware},
      {"platform", device.platform},
      {"model", "Ronald Jack DG-600-ID"},
  };

  j["source_agent"] = {
      {"name", cfg.agent_name},
      {"version", cfg.agent_version},
      {"role", "checkin_gateway"},
  };

  // Compact JSON — HMAC must cover exact bytes sent.
  return j.dump();
}

SignedResult PostDeviceIngest(const Config& cfg, const HttpClient& http, const Credential& cred,
                              const std::string& raw_body) {
  return SignedRequest(cfg, http, cred, "POST", "/checkin/device-ingest", raw_body);
}

}  // namespace cg
