#include "config.hpp"

#include <fstream>
#include <map>
#include <vector>

#include "util.hpp"

namespace cg {

bool ParseBool(const std::string& val, bool default_value) {
  auto v = ToLower(Trim(val));
  if (v.empty()) return default_value;
  if (v == "1" || v == "true" || v == "yes" || v == "on") return true;
  if (v == "0" || v == "false" || v == "no" || v == "off") return false;
  return default_value;
}

bool LoadConfig(const std::string& path, Config& out, std::string& err) {
  if (path.empty()) {
    err = "empty config path";
    return false;
  }
  std::ifstream in(path);
  if (!in) {
    err = "cannot open config: " + path;
    return false;
  }
  out.config_path = path;
  std::string line;
  while (std::getline(in, line)) {
    line = Trim(line);
    if (line.empty() || line[0] == '#' || line[0] == ';') continue;
    auto eq = line.find('=');
    if (eq == std::string::npos) continue;
    auto key = Trim(line.substr(0, eq));
    auto val = Trim(line.substr(eq + 1));
    if (!val.empty() && ((val.front() == '"' && val.back() == '"') ||
                         (val.front() == '\'' && val.back() == '\''))) {
      val = val.substr(1, val.size() - 2);
    }
    try {
      if (key == "device_ip") out.device_ip = val;
      else if (key == "device_port") out.device_port = std::stoi(val);
      else if (key == "device_password") out.device_password = std::stoi(val);
      else if (key == "device_timeout_sec") out.device_timeout_sec = std::stoi(val);
      else if (key == "base_url") {
        while (!val.empty() && val.back() == '/') val.pop_back();
        out.base_url = val;
      } else if (key == "data_dir") out.data_dir = val;
      else if (key == "agent_name") out.agent_name = val;
      else if (key == "agent_version") out.agent_version = val;
      else if (key == "live_listen") out.live_listen = ParseBool(val, true);
      else if (key == "poll_fallback") out.poll_fallback = ParseBool(val, true);
      else if (key == "discover_terminals") out.discover_terminals = ParseBool(val, true);
      else if (key == "catalog_refresh_sec") out.catalog_refresh_sec = std::stoi(val);
      else if (key == "attlog_sync_times") out.attlog_sync_times = val;
      else if (key == "users_sync_times") out.users_sync_times = val;
      else if (key == "bootstrap_refresh_sec") out.bootstrap_refresh_sec = std::stoi(val);
      else if (key == "poll_interval_sec") out.poll_interval_sec = std::stoi(val);
      else if (key == "ingest_minimal") out.ingest_minimal = ParseBool(val, false);
      else if (key == "reconnect_delay_sec") out.reconnect_delay_sec = std::stoi(val);
      else if (key == "outbox_retry_sec") out.outbox_retry_sec = std::stoi(val);
      else if (key == "outbox_max_attempts") out.outbox_max_attempts = std::stoi(val);
      else if (key == "outbox_retention_days") out.outbox_retention_days = std::stoi(val);
      else if (key == "http_timeout_sec") out.http_timeout_sec = std::stoi(val);
      else if (key == "device_tz_offset_min") out.device_tz_offset_min = std::stoi(val);
      else if (key == "punch_max_age_sec") out.punch_max_age_sec = std::stoi(val);
      else if (key == "punch_min_year") out.punch_min_year = std::stoi(val);
    } catch (const std::exception& ex) {
      err = "bad config value for " + key + ": " + ex.what();
      return false;
    }
  }
  return true;
}


bool UpsertConfigKeys(const std::string& path,
                      const std::vector<std::pair<std::string, std::string>>& kv,
                      std::string& err) {
  if (path.empty()) {
    err = "empty config path";
    return false;
  }
  std::map<std::string, std::string> want;
  for (const auto& p : kv) want[p.first] = p.second;

  std::ifstream in(path);
  std::vector<std::string> lines;
  std::map<std::string, bool> seen;
  if (in) {
    std::string line;
    while (std::getline(in, line)) {
      auto trimmed = Trim(line);
      if (!trimmed.empty() && trimmed[0] != '#' && trimmed[0] != ';') {
        auto eq = trimmed.find('=');
        if (eq != std::string::npos) {
          auto key = Trim(trimmed.substr(0, eq));
          auto it = want.find(key);
          if (it != want.end()) {
            lines.push_back(key + "=" + it->second);
            seen[key] = true;
            continue;
          }
        }
      }
      lines.push_back(line);
    }
  }
  for (const auto& p : kv) {
    if (!seen[p.first]) lines.push_back(p.first + "=" + p.second);
  }

  std::ofstream out(path);
  if (!out) {
    err = "cannot write config: " + path;
    return false;
  }
  for (size_t i = 0; i < lines.size(); ++i) {
    out << lines[i] << "\n";
  }
  return true;
}

}  // namespace cg
