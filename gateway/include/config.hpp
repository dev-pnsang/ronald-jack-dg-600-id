#pragma once

#include <cstdint>
#include <string>

namespace cg {

struct Config {
  // Ronald Jack DG-600-ID (LAN connectivity only — not CommaDesk auth)
  std::string device_ip = "192.168.1.201";
  int device_port = 4370;
  int device_password = 0;
  int device_timeout_sec = 10;

  // CommaDesk
  std::string base_url = "https://localhost:8080/api/v1";  // no trailing slash

  // Local state
  std::string data_dir = "/var/lib/checkin-gateway";
  std::string config_path;

  // Agent identity metadata (sent in enroll client_info + ingest extras)
  std::string agent_name = "checkin-gateway";
  std::string agent_version = "1.0.0";

  // Behavior
  bool live_listen = true;
  bool poll_fallback = true;       // also pull recent ATTLOG when live is quiet
  int poll_interval_sec = 30;
  bool ingest_minimal = false;     // only attendance_code + timestamp
  int reconnect_delay_sec = 5;
  int outbox_retry_sec = 15;
  int outbox_max_attempts = 50;
  int outbox_retention_days = 14;  // prune seen + dead outbox older than this
  int http_timeout_sec = 30;
};

// Load key=value config file. Missing keys keep defaults.
// Returns false on I/O error (path set but unreadable).
bool LoadConfig(const std::string& path, Config& out, std::string& err);

bool ParseBool(const std::string& val, bool default_value = false);

}  // namespace cg
