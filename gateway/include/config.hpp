#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

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
  bool poll_fallback = false;
  /** Pull org attendance_devices (with IP) from CommaDesk and poll each. */
  bool discover_terminals = true;
  int catalog_refresh_sec = 300;      // refresh terminal list only (no ATTLOG)
  int poll_interval_sec = 43200;     // unused — ATTLOG at 00:00 & 12:00 only
  bool ingest_minimal = false;     // only attendance_code + timestamp
  // Device wall-clock TZ offset east of UTC in minutes (420 = Asia/Ho_Chi_Minh)
  int device_tz_offset_min = 420;
  // Drop punches older than this (vs gateway local clock)
  int punch_max_age_sec = 300;
  // Reject device years below this (clock not synced)
  int punch_min_year = 2020;
  int reconnect_delay_sec = 5;
  int outbox_retry_sec = 15;
  int outbox_max_attempts = 50;
  int outbox_retention_days = 14;  // prune seen + dead outbox older than this
  int http_timeout_sec = 90;
};

// Load key=value config file. Missing keys keep defaults.
// Returns false on I/O error (path set but unreadable).
bool LoadConfig(const std::string& path, Config& out, std::string& err);

bool ParseBool(const std::string& val, bool default_value = false);

// Upsert key=value lines in a config file (preserves comments/order).
bool UpsertConfigKeys(const std::string& path,
                      const std::vector<std::pair<std::string, std::string>>& kv,
                      std::string& err);

}  // namespace cg
