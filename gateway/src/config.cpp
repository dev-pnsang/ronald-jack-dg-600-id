#include "config.hpp"

#include <fstream>
#include <sstream>

#include "util.hpp"

namespace cg {

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
  int lineno = 0;
  while (std::getline(in, line)) {
    ++lineno;
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
    else if (key == "live_listen") {
      auto v = ToLower(val);
      out.live_listen = !(v == "0" || v == "false" || v == "no" || v == "off");
    } else if (key == "reconnect_delay_sec") out.reconnect_delay_sec = std::stoi(val);
    else if (key == "outbox_retry_sec") out.outbox_retry_sec = std::stoi(val);
    else if (key == "http_timeout_sec") out.http_timeout_sec = std::stoi(val);
  }
  return true;
}

}  // namespace cg
