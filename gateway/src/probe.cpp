#include "probe.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <thread>

#include <nlohmann/json.hpp>

#include "log.hpp"
#include "util.hpp"
#include "zk_device.hpp"

namespace cg {
namespace {

std::atomic<bool> g_listen_running{true};

void OnListenSignal(int) { g_listen_running = false; }

std::string LocalNowIso() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d", tm.tm_year + 1900,
                tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
  return buf;
}

std::string FormatDuration(int64_t abs_sec) {
  if (abs_sec < 0) abs_sec = -abs_sec;
  int h = static_cast<int>(abs_sec / 3600);
  int m = static_cast<int>((abs_sec % 3600) / 60);
  int s = static_cast<int>(abs_sec % 60);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", h, m, s);
  return buf;
}

std::string SanitizeUtf8(const std::string& s) {
  // Keep ASCII printable; replace other bytes with '?' so nlohmann::json never throws.
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    if (c >= 32 && c < 127) out.push_back(static_cast<char>(c));
    else if (c == '\t' || c == '\n' || c == '\r') out.push_back(static_cast<char>(c));
    else out.push_back('?');
  }
  return out;
}

bool WriteText(const std::string& path, const std::string& content, std::string& err) {
  std::ofstream out(path);
  if (!out) {
    err = "cannot write " + path;
    return false;
  }
  out << content;
  return true;
}

bool WriteJson(const std::string& path, const nlohmann::json& j, std::string& err) {
  return WriteText(path, j.dump(2) + "\n", err);
}

bool WriteBinary(const std::string& path, const std::vector<uint8_t>& bytes, std::string& err) {
  std::ofstream out(path, std::ios::binary);
  if (!out) {
    err = "cannot write " + path;
    return false;
  }
  if (!bytes.empty()) out.write(reinterpret_cast<const char*>(bytes.data()),
                                static_cast<std::streamsize>(bytes.size()));
  return true;
}

void AppendLog(std::ofstream& log, const std::string& line) {
  log << "[" << LocalNowIso() << "] " << line << "\n";
  log.flush();
  LogInfo(line);
}

nlohmann::json EventToJson(const AttendanceEvent& ev, const Config& cfg) {
  nlohmann::json event = {
      {"user_id", SanitizeUtf8(ev.user_id)},
      {"user_name", SanitizeUtf8(ev.user_name)},
      {"timestamp", ev.timestamp_iso},
      {"year", ev.year},
      {"month", ev.month},
      {"day", ev.day},
      {"hour", ev.hour},
      {"minute", ev.minute},
      {"second", ev.second},
      {"verify_mode", ev.verify_mode},
      {"verify_mode_text", VerifyModeText(ev.verify_mode)},
      {"inout_mode", ev.inout_mode},
      {"inout_mode_text", InOutModeText(ev.inout_mode)},
      {"work_code", ev.work_code},
      {"from_live", ev.from_live},
      {"raw_cmd", ev.raw_cmd},
  };
  return {
      {"received_at", ev.received_at_iso.empty() ? UtcNowIso8601() : ev.received_at_iso},
      {"device", {{"host", cfg.device_ip}, {"port", cfg.device_port}}},
      {"event", event},
      {"raw", {{"hex", ev.raw_hex}, {"cmd", ev.raw_cmd}}},
  };
}

const char* kDeviceOptionKeys[] = {
    "~SerialNumber",
    "~DeviceName",
    "DeviceName",
    "~OEMVendor",
    "~Platform",
    "~ProductCode",
    "FirmVer",
    "~ZKFPVersion",
    "~SSR",
    "~PIN2Width",
    "~ExtendFmt",
    "~IsOnlyRFMachine",
    "~MaxFingerCount",
    "~MaxAttLogCount",
    "~MaxUserCount",
    "~MAC",
    "MAC",
    "~IPAddress",
    "IPAddress",
    "~NETMASK",
    "NETMASK",
    "~GATEIPAddress",
    "~DHCP",
    "~ProductTime",
    "~BuildInfo",
    "BuildInfo",
    "~DeviceName",
    "WorkCode",
    "~CompatOldFirmware",
    "~FaceFunOn",
    "FaceFunOn",
    "~FingerFunOn",
    "FingerFunOn",
};

}  // namespace

bool SaveDeviceEndpoint(const std::string& config_path, const std::string& host, int port,
                        std::string& err) {
  if (config_path.empty()) {
    err = "empty config path";
    return false;
  }
  std::ifstream in(config_path);
  std::vector<std::string> lines;
  bool have_ip = false;
  bool have_port = false;
  if (in) {
    std::string line;
    while (std::getline(in, line)) {
      auto trimmed = Trim(line);
      if (!trimmed.empty() && trimmed[0] != '#' && trimmed[0] != ';') {
        auto eq = trimmed.find('=');
        if (eq != std::string::npos) {
          auto key = Trim(trimmed.substr(0, eq));
          if (key == "device_ip") {
            lines.push_back("device_ip=" + host);
            have_ip = true;
            continue;
          }
          if (key == "device_port") {
            lines.push_back("device_port=" + std::to_string(port));
            have_port = true;
            continue;
          }
        }
      }
      lines.push_back(line);
    }
  }
  if (!have_ip) lines.push_back("device_ip=" + host);
  if (!have_port) lines.push_back("device_port=" + std::to_string(port));

  std::ofstream out(config_path);
  if (!out) {
    err = "cannot write config: " + config_path;
    return false;
  }
  for (size_t i = 0; i < lines.size(); ++i) {
    out << lines[i];
    if (i + 1 < lines.size() || (!lines.empty() && !lines.back().empty())) out << "\n";
  }
  return true;
}

int RunConnectTest(const Config& cfg) {
  LogInfo("Protocol/library: " + std::string(ZkDevice::ProtocolName()));
  LogInfo("Device address: " + cfg.device_ip + ":" + std::to_string(cfg.device_port));
  ZkDevice device;
  std::string err;
  if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                      err)) {
    LogError("Connection failed: " + err);
    return 2;
  }
  DeviceInfo info;
  if (device.ReadDeviceInfo(info, err)) {
    LogInfo("Device serial=" + info.serial + " firmware=" + info.firmware +
            " time=" + info.device_time_local);
  } else {
    LogWarning("Connected but ReadDeviceInfo: " + err);
  }
  device.Disconnect();
  LogInfo("Connection success");
  return 0;
}

int RunDiscover(const Config& cfg, const std::string& result_dir) {
  std::string err;
  if (!EnsureDir(result_dir, err)) {
    LogError(err);
    return 1;
  }
  if (!EnsureDir(result_dir + "/raw", err)) {
    LogError(err);
    return 1;
  }

  std::ofstream dlog(result_dir + "/discovery.log", std::ios::app);
  AppendLog(dlog, "Discovery start host=" + cfg.device_ip + " port=" +
                      std::to_string(cfg.device_port) + " protocol=" + ZkDevice::ProtocolName());

  ZkDevice device;
  if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                      err)) {
    AppendLog(dlog, "Connection failed: " + err);
    nlohmann::json fail = {{"status", "FAILED"},
                           {"error", err},
                           {"device", {{"host", cfg.device_ip}, {"port", cfg.device_port}}},
                           {"protocol", ZkDevice::ProtocolName()}};
    WriteJson(result_dir + "/connection.json", fail, err);
    return 2;
  }
  AppendLog(dlog, "Connection success: " + cfg.device_ip + ":" + std::to_string(cfg.device_port));
  WriteJson(result_dir + "/connection.json",
            {{"status", "ok"},
             {"device", {{"host", cfg.device_ip}, {"port", cfg.device_port}}},
             {"protocol", ZkDevice::ProtocolName()},
             {"connected_at", LocalNowIso()}},
            err);

  nlohmann::json capabilities = nlohmann::json::array();
  auto add_cap = [&](const std::string& name, const std::string& status, const std::string& detail) {
    capabilities.push_back({{"name", name}, {"status", status}, {"detail", detail}});
  };

  // --- Device options ---
  nlohmann::json options = nlohmann::json::array();
  nlohmann::json device_info = {{"host", cfg.device_ip},
                                {"port", cfg.device_port},
                                {"protocol", ZkDevice::ProtocolName()}};
  for (const char* key : kDeviceOptionKeys) {
    auto r = device.ProbeOption(key);
    options.push_back({{"key", r.key},
                       {"status", r.status},
                       {"value", r.value},
                       {"raw_hex", r.raw_hex},
                       {"reply_cmd", r.reply_cmd},
                       {"error", r.error}});
    AppendLog(dlog, std::string("option ") + key + " => " + r.status +
                        (r.value.empty() ? "" : (" value=" + r.value)) +
                        (r.error.empty() ? "" : (" err=" + r.error)));
    if (r.status == "ok") {
      device_info[r.key] = r.value;
      if (std::string(key) == "~SerialNumber") device_info["serial_number"] = r.value;
      if (std::string(key) == "~DeviceName" || std::string(key) == "DeviceName")
        device_info["device_name"] = r.value;
      if (std::string(key) == "FirmVer") device_info["firmware"] = r.value;
      if (std::string(key) == "~OEMVendor" || std::string(key) == "~Platform")
        device_info["platform"] = r.value;
      if (std::string(key) == "~MAC" || std::string(key) == "MAC") device_info["mac"] = r.value;
    }
    add_cap(std::string("CMD_DEVICE:") + key, r.status, r.error.empty() ? r.value : r.error);
  }
  WriteJson(result_dir + "/device-options.json", options, err);
  WriteJson(result_dir + "/raw/device-options.json", options, err);

  // --- Time ---
  DeviceTime dt;
  nlohmann::json time_j;
  if (device.GetTime(dt, err)) {
    time_j = {{"status", "ok"},
              {"device_time_local", dt.iso_local},
              {"encoded", dt.encoded},
              {"raw_hex", dt.raw_hex},
              {"parts",
               {{"year", dt.year},
                {"month", dt.month},
                {"day", dt.day},
                {"hour", dt.hour},
                {"minute", dt.minute},
                {"second", dt.second}}}};
    device_info["device_time_local"] = dt.iso_local;
    AppendLog(dlog, "device time: " + dt.iso_local);
    add_cap("CMD_GET_TIME", "ok", dt.iso_local);
  } else {
    time_j = {{"status", "FAILED"}, {"error", err}};
    AppendLog(dlog, "GET_TIME FAILED: " + err);
    add_cap("CMD_GET_TIME", "FAILED", err);
  }
  WriteJson(result_dir + "/device-time.json", time_j, err);

  // --- Free sizes / status counters ---
  DeviceInfo sizes_info;
  RawBlob sizes_raw;
  nlohmann::json sizes_j;
  if (device.ReadFreeSizes(sizes_info, sizes_raw, err)) {
    sizes_j = {{"status", sizes_raw.status},
               {"user_count", sizes_info.user_count},
               {"finger_count", sizes_info.finger_count},
               {"log_count", sizes_info.log_count},
               {"reply_cmd", sizes_raw.reply_cmd},
               {"raw_hex", sizes_raw.hex()},
               {"raw_len", sizes_raw.bytes.size()}};
    device_info["user_count"] = sizes_info.user_count;
    device_info["finger_count"] = sizes_info.finger_count;
    device_info["log_count"] = sizes_info.log_count;
    WriteBinary(result_dir + "/raw/free-sizes.bin", sizes_raw.bytes, err);
    WriteText(result_dir + "/raw/free-sizes.hex", sizes_raw.hex() + "\n", err);
    AppendLog(dlog, "free sizes users=" + std::to_string(sizes_info.user_count) +
                        " fingers=" + std::to_string(sizes_info.finger_count) +
                        " logs=" + std::to_string(sizes_info.log_count));
    add_cap("CMD_GET_FREE_SIZES", "ok", "len=" + std::to_string(sizes_raw.bytes.size()));
  } else {
    sizes_j = {{"status", "FAILED"}, {"error", err}, {"raw_hex", sizes_raw.hex()}};
    AppendLog(dlog, "GET_FREE_SIZES FAILED: " + err);
    add_cap("CMD_GET_FREE_SIZES", "FAILED", err);
  }
  WriteJson(result_dir + "/device-status.json", sizes_j, err);

  WriteJson(result_dir + "/device-info.json", device_info, err);

  // Fresh session before bulk downloads — long option probing can leave the link sticky.
  device.Disconnect();
  if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                      err)) {
    AppendLog(dlog, "Reconnect before users FAILED: " + err);
    WriteJson(result_dir + "/capabilities.json",
              {{"protocol", ZkDevice::ProtocolName()},
               {"device", {{"host", cfg.device_ip}, {"port", cfg.device_port}}},
               {"discovered_at", LocalNowIso()},
               {"capabilities", capabilities}},
              err);
    return 3;
  }

  // --- Users ---
  std::vector<UserRecord> users;
  RawBlob users_raw;
  nlohmann::json users_j;
  if (device.ReadUsersRaw(users, users_raw, err)) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& u : users) {
      arr.push_back({{"user_id", SanitizeUtf8(u.user_id)},
                     {"uid", u.uid},
                     {"name", SanitizeUtf8(u.name)},
                     {"name_raw_hex", HexEncode(reinterpret_cast<const unsigned char*>(u.name.data()),
                                                u.name.size())},
                     {"privilege", u.privilege},
                     {"privilege_text", PrivilegeText(u.privilege)},
                     {"enabled", u.enabled},
                     {"password_present", !u.password.empty()},
                     {"card", u.card},
                     {"raw_hex", u.raw_hex}});
    }
    users_j = {{"status", "ok"},
               {"count", users.size()},
               {"raw_len", users_raw.bytes.size()},
               {"raw_hex_preview", users_raw.hex().substr(0, 512)},
               {"users", arr}};
    WriteBinary(result_dir + "/raw/users.bin", users_raw.bytes, err);
    WriteText(result_dir + "/raw/users.hex", users_raw.hex() + "\n", err);
    AppendLog(dlog, "users read: " + std::to_string(users.size()));
    add_cap("CMD_USERTEMP_RRQ", "ok", "users=" + std::to_string(users.size()));
  } else {
    users_j = {{"status", "FAILED"}, {"error", err}};
    AppendLog(dlog, "ReadUsers FAILED: " + err);
    add_cap("CMD_USERTEMP_RRQ", "FAILED", err);
  }
  WriteJson(result_dir + "/users.json", users_j, err);

  // Fresh session before attendance + live smoke test
  device.Disconnect();
  if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                      err)) {
    AppendLog(dlog, "Reconnect before attendance FAILED: " + err);
  }

  // --- Fingerprint templates metadata (attempt) ---
  RawBlob fp_raw;
  std::vector<uint8_t> fp_req = {0x01};  // templates flag used by some firmwares
  nlohmann::json fp_j;
  // Reuse private path via ReadUsersRaw-style: try CMD_USERTEMP_RRQ flag 1
  // Expose through a temporary connect-level probe: use ReadUsersRaw only for flag 5.
  // For fingerprints, try Fetch via reconnecting Enable+command by probing ReadAttendance style.
  // Simpler: mark as attempted through option keys; try raw command via ReadUsers with note.
  {
    // Soft probe: if FingerFunOn empty and no sizes finger_count → NOT_SUPPORTED for template dump
    bool finger_on = false;
    for (const auto& o : options) {
      if (o.value("key", "") == "~FingerFunOn" || o.value("key", "") == "FingerFunOn") {
        if (o.value("status", "") == "ok") finger_on = true;
      }
    }
    if (sizes_info.finger_count > 0 || finger_on) {
      fp_j = {{"status", "NOT_SUPPORTED"},
              {"detail",
               "Fingerprint templates bulk dump not implemented safely in this agent; "
               "device reports finger-related counters/options. See device-status.json / "
               "device-options.json. No fake template data."},
              {"finger_count_from_sizes", sizes_info.finger_count}};
      add_cap("fingerprint_templates", "NOT_SUPPORTED", "bulk dump not implemented");
    } else {
      fp_j = {{"status", "NOT_SUPPORTED"},
              {"detail", "No finger counters/options returned by device"}};
      add_cap("fingerprint_templates", "NOT_SUPPORTED", "no finger data exposed");
    }
    (void)fp_raw;
    (void)fp_req;
  }
  WriteJson(result_dir + "/fingerprint-metadata.json", fp_j, err);

  // --- Attendance ---
  std::vector<AttendanceEvent> logs;
  RawBlob att_raw;
  nlohmann::json att_j;
  if (device.ReadAttendanceLogsRaw(logs, att_raw, err)) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& ev : logs) {
      arr.push_back({{"user_id", SanitizeUtf8(ev.user_id)},
                     {"user_name", SanitizeUtf8(ev.user_name)},
                     {"timestamp", ev.timestamp_iso},
                     {"verify_mode", ev.verify_mode},
                     {"verify_mode_text", VerifyModeText(ev.verify_mode)},
                     {"inout_mode", ev.inout_mode},
                     {"inout_mode_text", InOutModeText(ev.inout_mode)},
                     {"work_code", ev.work_code},
                     {"raw_hex", ev.raw_hex}});
    }
    att_j = {{"status", "ok"},
             {"count", logs.size()},
             {"raw_len", att_raw.bytes.size()},
             {"raw_hex_preview", att_raw.hex().substr(0, 512)},
             {"records", arr}};
    WriteBinary(result_dir + "/raw/attendance.bin", att_raw.bytes, err);
    WriteText(result_dir + "/raw/attendance.hex", att_raw.hex() + "\n", err);
    AppendLog(dlog, "attendance records: " + std::to_string(logs.size()));
    add_cap("CMD_ATTLOG_RRQ", "ok", "records=" + std::to_string(logs.size()));
  } else {
    att_j = {{"status", "FAILED"}, {"error", err}};
    AppendLog(dlog, "ReadAttendance FAILED: " + err);
    add_cap("CMD_ATTLOG_RRQ", "FAILED", err);
  }
  WriteJson(result_dir + "/attendance-records.json", att_j, err);

  // --- Live capture capability smoke (start+stop, no long listen) ---
  nlohmann::json live_j;
  if (device.StartLiveCapture(err)) {
    live_j = {{"status", "ok"}, {"detail", "RegEvent ACK_OK"}};
    add_cap("CMD_REG_EVENT", "ok", "RegEvent mask=0xFFFF");
    device.StopLiveCapture();
    AppendLog(dlog, "live capture start/stop OK");
  } else {
    live_j = {{"status", "FAILED"}, {"error", err}};
    add_cap("CMD_REG_EVENT", "FAILED", err);
    AppendLog(dlog, "live capture FAILED: " + err);
  }
  WriteJson(result_dir + "/live-capture-capability.json", live_j, err);

  WriteJson(result_dir + "/capabilities.json",
            {{"protocol", ZkDevice::ProtocolName()},
             {"device", {{"host", cfg.device_ip}, {"port", cfg.device_port}}},
             {"discovered_at", LocalNowIso()},
             {"capabilities", capabilities}},
            err);

  AppendLog(dlog, "Discovery complete. Results in " + result_dir);
  device.Disconnect();
  return 0;
}

int RunSyncTime(const Config& cfg, const std::string& result_dir) {
  std::string err;
  if (!EnsureDir(result_dir, err)) {
    LogError(err);
    return 1;
  }

  std::ofstream dlog(result_dir + "/time-sync.log", std::ios::app);
  ZkDevice device;
  if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                      err)) {
    AppendLog(dlog, "Connection failed: " + err);
    return 2;
  }

  DeviceTime before;
  if (!device.GetTime(before, err)) {
    AppendLog(dlog, "GET_TIME before FAILED: " + err);
    return 3;
  }

  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_r(&now, &local);
  char server_buf[64];
  std::snprintf(server_buf, sizeof(server_buf), "%04d-%02d-%02d %02d:%02d:%02d",
                local.tm_year + 1900, local.tm_mon + 1, local.tm_mday, local.tm_hour, local.tm_min,
                local.tm_sec);
  char device_buf[64];
  std::snprintf(device_buf, sizeof(device_buf), "%04d-%02d-%02d %02d:%02d:%02d", before.year,
                before.month, before.day, before.hour, before.minute, before.second);

  std::tm device_tm{};
  device_tm.tm_year = before.year - 1900;
  device_tm.tm_mon = before.month - 1;
  device_tm.tm_mday = before.day;
  device_tm.tm_hour = before.hour;
  device_tm.tm_min = before.minute;
  device_tm.tm_sec = before.second;
  device_tm.tm_isdst = -1;
  std::time_t device_epoch = std::mktime(&device_tm);
  int64_t diff = static_cast<int64_t>(now) - static_cast<int64_t>(device_epoch);
  int64_t abs_diff = diff >= 0 ? diff : -diff;

  AppendLog(dlog, std::string("Server time: ") + server_buf);
  AppendLog(dlog, std::string("Device time: ") + device_buf);
  AppendLog(dlog, "Difference: " + FormatDuration(abs_diff) +
                      (diff >= 0 ? " (device behind)" : " (device ahead)"));

  if (!device.SetTime(local.tm_year + 1900, local.tm_mon + 1, local.tm_mday, local.tm_hour,
                      local.tm_min, local.tm_sec, err)) {
    AppendLog(dlog, "SET_TIME FAILED: " + err);
    WriteJson(result_dir + "/time-sync.json",
              {{"status", "FAILED"},
               {"error", err},
               {"server_time", server_buf},
               {"device_time_before", device_buf},
               {"difference_seconds", diff}},
              err);
    return 4;
  }
  AppendLog(dlog, "SET_TIME applied to server local time");

  // Brief settle
  std::this_thread::sleep_for(std::chrono::milliseconds(300));

  DeviceTime after;
  if (!device.GetTime(after, err)) {
    AppendLog(dlog, "GET_TIME after FAILED: " + err);
    return 5;
  }
  char after_buf[64];
  std::snprintf(after_buf, sizeof(after_buf), "%04d-%02d-%02d %02d:%02d:%02d", after.year,
                after.month, after.day, after.hour, after.minute, after.second);
  AppendLog(dlog, std::string("Device time after sync: ") + after_buf);

  bool verified = (after.year == local.tm_year + 1900 && after.month == local.tm_mon + 1 &&
                   after.day == local.tm_mday && after.hour == local.tm_hour &&
                   std::abs(after.minute - local.tm_min) <= 1);

  nlohmann::json result = {{"status", verified ? "ok" : "VERIFY_MISMATCH"},
                           {"server_time", server_buf},
                           {"device_time_before", device_buf},
                           {"device_time_after", after_buf},
                           {"difference_before_seconds", diff},
                           {"difference_before_hhmmss", FormatDuration(abs_diff)},
                           {"verified", verified},
                           {"raw_before_hex", before.raw_hex},
                           {"raw_after_hex", after.raw_hex}};
  WriteJson(result_dir + "/time-sync.json", result, err);
  AppendLog(dlog, verified ? "Time sync verified OK" : "Time sync VERIFY_MISMATCH");
  device.Disconnect();
  return verified ? 0 : 6;
}

int RunListen(const Config& cfg, const std::string& result_dir) {
  std::string err;
  if (!EnsureDir(result_dir, err)) {
    LogError(err);
    return 1;
  }

  g_listen_running = true;
  std::signal(SIGINT, OnListenSignal);
  std::signal(SIGTERM, OnListenSignal);

  std::ofstream event_log(result_dir + "/attendance-events.log", std::ios::app);
  std::ofstream event_jsonl(result_dir + "/attendance-events.jsonl", std::ios::app);
  std::ofstream service_log(result_dir + "/listen-service.log", std::ios::app);

  AppendLog(service_log, "Listen service starting host=" + cfg.device_ip + ":" +
                             std::to_string(cfg.device_port) + " protocol=" +
                             ZkDevice::ProtocolName());

  ZkDevice device;
  std::set<std::string> recent_keys;
  std::map<std::string, std::string> name_by_id;
  // Prefer previously discovered users.json for name enrichment — avoid USERTEMP bulk on the
  // live session (this firmware often stops ACKing RegEvent after bulk until power-cycle-ish settle).
  {
    std::ifstream uin(result_dir + "/users.json");
    if (uin) {
      try {
        auto uj = nlohmann::json::parse(uin);
        for (const auto& u : uj.value("users", nlohmann::json::array())) {
          name_by_id[u.value("user_id", "")] = SanitizeUtf8(u.value("name", ""));
        }
        AppendLog(service_log, "Loaded " + std::to_string(name_by_id.size()) +
                                   " names from users.json");
      } catch (const std::exception& ex) {
        AppendLog(service_log, std::string("WARNING users.json parse: ") + ex.what());
      }
    }
  }
  auto dedupe_key = [](const AttendanceEvent& ev) {
    return ev.user_id + "|" + ev.timestamp_iso + "|" + std::to_string(ev.verify_mode) + "|" +
           std::to_string(ev.inout_mode) + "|" + std::to_string(ev.work_code);
  };

  while (g_listen_running) {
    if (!device.IsConnected()) {
      AppendLog(service_log, "Reconnect attempt to " + cfg.device_ip + ":" +
                                 std::to_string(cfg.device_port));
      if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                          err)) {
        AppendLog(service_log, "Connection failed: " + err);
        std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
        continue;
      }
      if (!device.StartLiveCapture(err)) {
        AppendLog(service_log, "StartLiveCapture failed: " + err);
        device.Disconnect();
        std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
        continue;
      }
      AppendLog(service_log, "Realtime listener armed — waiting for punches");
    }

    bool ok = device.PollLive(
        [&](const AttendanceEvent& ev) {
          AttendanceEvent enriched = ev;
          if (enriched.user_name.empty()) {
            auto it = name_by_id.find(enriched.user_id);
            if (it != name_by_id.end()) enriched.user_name = it->second;
          }
          auto key = dedupe_key(enriched);
          if (recent_keys.count(key)) {
            LogDebug("duplicate event suppressed: " + key);
            return;
          }
          recent_keys.insert(key);
          if (recent_keys.size() > 5000) recent_keys.clear();

          auto j = EventToJson(enriched, cfg);
          std::string line = j.dump();
          event_jsonl << line << "\n";
          event_jsonl.flush();

          std::ostringstream oss;
          oss << "Attendance event received user_id=" << enriched.user_id
              << " name=" << enriched.user_name << " ts=" << enriched.timestamp_iso
              << " verify=" << VerifyModeText(enriched.verify_mode)
              << " inout=" << InOutModeText(enriched.inout_mode)
              << " work_code=" << enriched.work_code << " raw_hex=" << enriched.raw_hex;
          event_log << "[" << LocalNowIso() << "] " << oss.str() << "\n";
          event_log.flush();
          LogInfo(oss.str());
        },
        1000, err);

    if (!ok) {
      AppendLog(service_log, "Device disconnected — will reconnect");
      device.Disconnect();
      std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
    }
  }

  AppendLog(service_log, "Listen service stopping");
  device.Disconnect();
  return 0;
}

}  // namespace cg
