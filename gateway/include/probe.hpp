#pragma once

#include <string>

#include "config.hpp"

namespace cg {

// Persist device_ip / device_port into the config file (other keys preserved).
bool SaveDeviceEndpoint(const std::string& config_path, const std::string& host, int port,
                        std::string& err);

// Connect/disconnect smoke test; logs protocol + address. Returns 0 on success.
int RunConnectTest(const Config& cfg);

// Full read-only discovery against the configured ZK device. Writes JSON + raw under result_dir.
int RunDiscover(const Config& cfg, const std::string& result_dir);

// Compare server vs device time, set device clock to server local time, verify.
int RunSyncTime(const Config& cfg, const std::string& result_dir);

// Realtime attendance listener (no CommaDesk enroll required). Keeps running until SIGINT/SIGTERM.
int RunListen(const Config& cfg, const std::string& result_dir);

}  // namespace cg
