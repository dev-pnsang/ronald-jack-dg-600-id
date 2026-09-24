#include "gateway.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <thread>

#include <nlohmann/json.hpp>
#include <sys/stat.h>

#include "device_identity.hpp"
#include "http_client.hpp"
#include "ingest.hpp"
#include "store.hpp"
#include "util.hpp"
#include "zk_device.hpp"

namespace cg {
namespace {

std::atomic<bool> g_running{true};

void OnSignal(int) { g_running = false; }

std::string DedupeKey(const AttendanceEvent& ev) {
  return ev.user_id + "|" + ev.timestamp_iso + "|" + std::to_string(ev.inout_mode) + "|" +
         std::to_string(ev.verify_mode) + "|" + std::to_string(ev.work_code);
}

bool LooksLikeInvalidBody(const SignedResult& r) {
  if (r.status != 400) return false;
  return r.body.find("INVALID_BODY") != std::string::npos;
}

bool IsRecentPunch(const AttendanceEvent& ev, int max_age_sec) {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  gmtime_r(&now, &tmb);
  auto days = [](int y, int m, int d) -> int64_t {
    if (m < 3) {
      y -= 1;
      m += 12;
    }
    return 365LL * y + y / 4 - y / 100 + y / 400 + (153 * (m - 3) + 2) / 5 + d;
  };
  int64_t punch_sec = days(ev.year, ev.month, ev.day) * 86400LL + ev.hour * 3600LL +
                      ev.minute * 60LL + ev.second;
  int64_t now_sec = days(tmb.tm_year + 1900, tmb.tm_mon + 1, tmb.tm_mday) * 86400LL +
                    tmb.tm_hour * 3600LL + tmb.tm_min * 60LL + tmb.tm_sec;
  int64_t delta = now_sec - punch_sec;
  if (delta < 0) delta = -delta;
  return delta <= max_age_sec;
}

void EnqueuePunch(Store& store, const Config& cfg, const DeviceInfo& info, const AttendanceEvent& ev) {
  auto body = BuildIngestBody(ev, info, cfg);
  auto key = DedupeKey(ev);
  std::string e2;
  if (!store.Enqueue(key, body, e2)) {
    std::fprintf(stderr, "[outbox] enqueue failed: %s\n", e2.c_str());
    return;
  }
  std::fprintf(stderr, "[punch] user=%s ts=%s verify=%d inout=%d live=%d\n", ev.user_id.c_str(),
               ev.timestamp_iso.c_str(), ev.verify_mode, ev.inout_mode, ev.from_live ? 1 : 0);
}

void FlushOutbox(Config& cfg, Store& store, const HttpClient& http, const Credential& cred) {
  auto due = store.DueOutbox(20, UnixNow(), cfg.outbox_max_attempts);
  for (const auto& item : due) {
    if (!g_running) break;
    auto r = PostDeviceIngest(cfg, http, cred, item.body_json);
    std::string err;

    // If full payload rejected, rewrite this item to minimal contract fields once.
    if (!r.ok && LooksLikeInvalidBody(r) && !cfg.ingest_minimal) {
      try {
        auto j = nlohmann::json::parse(item.body_json);
        nlohmann::json minimal;
        minimal["attendance_code"] = j.value("attendance_code", j.value("device_user_id", ""));
        minimal["timestamp"] = j.value("timestamp", "");
        std::string raw = minimal.dump();
        std::fprintf(stderr,
                     "[ingest] INVALID_BODY — retrying id=%lld with minimal body; "
                     "set ingest_minimal=true to make permanent\n",
                     static_cast<long long>(item.id));
        r = PostDeviceIngest(cfg, http, cred, raw);
        if (r.ok && r.status == 201) {
          // Replace stored body so future retries stay minimal for this punch.
          store.MarkOutboxOk(item.id, err);
          // Re-mark seen already done; also flip config suggestion only via log.
          std::fprintf(stderr, "[ingest] ok id=%lld status=%ld (minimal)\n",
                       static_cast<long long>(item.id), r.status);
          continue;
        }
      } catch (...) {
        // fall through to normal fail path
      }
    }

    if (r.ok && r.status == 201) {
      store.MarkOutboxOk(item.id, err);
      std::fprintf(stderr, "[ingest] ok id=%lld status=%ld\n", static_cast<long long>(item.id),
                   r.status);
    } else {
      std::string detail = r.error;
      if (!r.body.empty()) detail += " " + r.body.substr(0, 200);
      int next_attempts = item.attempts + 1;
      if (next_attempts >= cfg.outbox_max_attempts) {
        store.AbandonOutbox(item.id, "max attempts: " + detail, err);
        std::fprintf(stderr, "[ingest] abandon id=%lld after %d attempts: %s\n",
                     static_cast<long long>(item.id), next_attempts, detail.c_str());
      } else {
        int64_t next = UnixNow() + cfg.outbox_retry_sec;
        store.MarkOutboxFail(item.id, detail, next, err);
        std::fprintf(stderr, "[ingest] fail id=%lld attempt=%d: %s\n",
                     static_cast<long long>(item.id), next_attempts, detail.c_str());
      }
    }
  }
}

void MaybePrune(Store& store, const Config& cfg) {
  if (cfg.outbox_retention_days <= 0) return;
  std::string err;
  int64_t cutoff = UnixNow() - static_cast<int64_t>(cfg.outbox_retention_days) * 24 * 3600;
  int n = store.Prune(cutoff, err);
  if (n > 0) std::fprintf(stderr, "[store] pruned %d old rows\n", n);
}

void HardenDataDir(const Config& cfg) {
  ::chmod(cfg.data_dir.c_str(), 0700);
  std::string db = cfg.data_dir + "/state.db";
  ::chmod(db.c_str(), 0600);
  if (!cfg.config_path.empty()) ::chmod(cfg.config_path.c_str(), 0640);
}

}  // namespace

int RunEnroll(const Config& cfg, const std::string& pairing_code) {
  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  HardenDataDir(cfg);
  Store store;
  if (!store.Open(cfg.data_dir + "/state.db", err)) {
    std::fprintf(stderr, "store: %s\n", err.c_str());
    return 1;
  }
  HttpClient http(cfg.http_timeout_sec);
  Credential cred;
  if (!EnrollDevice(cfg, http, pairing_code, cred, err)) {
    std::fprintf(stderr, "enroll failed: %s\n", err.c_str());
    return 1;
  }
  if (!store.SaveCredential(cred, err)) {
    std::fprintf(stderr, "save credential: %s\n", err.c_str());
    return 1;
  }
  HardenDataDir(cfg);
  std::fprintf(stdout, "Enrolled OK.\n");
  std::fprintf(stdout, "  device_id: %s\n", cred.device_id.c_str());
  std::fprintf(stdout, "  organization_id: %s\n", cred.organization_id.c_str());
  std::fprintf(stdout, "  credential_id: %s\n", cred.credential_id.c_str());
  std::fprintf(stdout, "  scopes: %s\n", cred.scopes_json.c_str());
  std::fprintf(stdout, "Secrets stored in %s/state.db (do not commit / log).\n",
               cfg.data_dir.c_str());
  return 0;
}

int RunAckRotate(const Config& cfg, const std::string& secrets_json_path) {
  std::string err;
  std::ifstream in(secrets_json_path);
  if (!in) {
    std::fprintf(stderr, "cannot open secrets file: %s\n", secrets_json_path.c_str());
    return 1;
  }
  nlohmann::json j;
  try {
    in >> j;
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "invalid JSON: %s\n", ex.what());
    return 1;
  }

  Credential neu;
  try {
    neu.auth_secret = j.at("auth_secret").get<std::string>();
    neu.signing_secret = j.at("signing_secret").get<std::string>();
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "secrets JSON must include auth_secret + signing_secret: %s\n",
                 ex.what());
    return 1;
  }
  neu.device_id = j.value("device_id", "");
  neu.organization_id = j.value("organization_id", "");
  neu.credential_id = j.value("credential_id", "");
  if (j.contains("scopes")) neu.scopes_json = j["scopes"].dump();

  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  Store store;
  if (!store.Open(cfg.data_dir + "/state.db", err)) {
    std::fprintf(stderr, "store: %s\n", err.c_str());
    return 1;
  }
  // Preserve device_id if file omitted them
  Credential old;
  if (store.LoadCredential(old, err)) {
    if (neu.device_id.empty()) neu.device_id = old.device_id;
    if (neu.organization_id.empty()) neu.organization_id = old.organization_id;
  }

  HttpClient http(cfg.http_timeout_sec);
  auto ack = AckCredential(cfg, http, neu);
  if (!ack.ok) {
    std::fprintf(stderr, "ACK failed: %s %s\n", ack.error.c_str(), ack.body.substr(0, 300).c_str());
    return 1;
  }
  if (!store.SaveCredential(neu, err)) {
    std::fprintf(stderr, "save new credential: %s\n", err.c_str());
    return 1;
  }
  HardenDataDir(cfg);
  std::fprintf(stdout, "Rotate ACK OK. New secrets stored. Old credential revoked server-side.\n");
  return 0;
}

int RunGateway(const Config& cfg_in) {
  Config cfg = cfg_in;
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  HardenDataDir(cfg);
  Store store;
  if (!store.Open(cfg.data_dir + "/state.db", err)) {
    std::fprintf(stderr, "store: %s\n", err.c_str());
    return 1;
  }
  Credential cred;
  if (!store.LoadCredential(cred, err)) {
    std::fprintf(stderr, "Not enrolled: %s\n", err.c_str());
    std::fprintf(stderr, "Run: checkin-gateway --config <path> --enroll <pairing_code>\n");
    return 2;
  }

  HttpClient http(cfg.http_timeout_sec);
  ZkDevice device;
  DeviceInfo info;
  info.ip = cfg.device_ip;
  info.port = cfg.device_port;

  int64_t last_poll = 0;
  int64_t last_prune = 0;

  std::fprintf(stderr,
               "[gateway] start agent=%s version=%s base_url=%s device=%s:%d "
               "ingest_minimal=%d poll_fallback=%d\n",
               cfg.agent_name.c_str(), cfg.agent_version.c_str(), cfg.base_url.c_str(),
               cfg.device_ip.c_str(), cfg.device_port, cfg.ingest_minimal ? 1 : 0,
               cfg.poll_fallback ? 1 : 0);

  while (g_running) {
    if (!device.IsConnected()) {
      std::fprintf(stderr, "[zk] connecting %s:%d ...\n", cfg.device_ip.c_str(), cfg.device_port);
      if (!device.Connect(cfg.device_ip, cfg.device_port, cfg.device_password, cfg.device_timeout_sec,
                          err)) {
        std::fprintf(stderr, "[zk] connect failed: %s\n", err.c_str());
        FlushOutbox(cfg, store, http, cred);
        std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
        continue;
      }
      if (device.ReadDeviceInfo(info, err)) {
        std::fprintf(stderr, "[zk] connected serial=%s firmware=%s\n", info.serial.c_str(),
                     info.firmware.c_str());
      }
      std::vector<UserRecord> users;
      if (device.ReadUsers(users, err)) {
        std::fprintf(stderr, "[zk] users cached: %zu\n", users.size());
      }
      if (cfg.live_listen) {
        if (!device.StartLiveCapture(err)) {
          std::fprintf(stderr, "[zk] StartLiveCapture failed: %s\n", err.c_str());
          device.Disconnect();
          std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
          continue;
        }
        std::fprintf(stderr, "[zk] live listen ON\n");
      }
      // Bootstrap poll once after connect so we catch punches missed during downtime.
      last_poll = 0;
    }

    if (cfg.live_listen) {
      bool ok = device.PollLive(
          [&](const AttendanceEvent& ev) { EnqueuePunch(store, cfg, info, ev); }, 500, err);
      if (!ok) {
        std::fprintf(stderr, "[zk] poll error: %s — reconnecting\n", err.c_str());
        device.Disconnect();
        std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
        continue;
      }
    } else {
      std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    int64_t now = UnixNow();
    if (cfg.poll_fallback && device.IsConnected() &&
        (last_poll == 0 || now - last_poll >= cfg.poll_interval_sec)) {
      last_poll = now;
      std::vector<AttendanceEvent> logs;
      if (device.ReadAttendanceLogs(logs, err)) {
        // Only recent punches — avoid replaying full history every interval.
        // Live path remains primary; this covers missed RT events after reconnect.
        constexpr int kRecentSec = 5 * 60;
        int recent = 0;
        for (auto& ev : logs) {
          if (!IsRecentPunch(ev, kRecentSec)) continue;
          EnqueuePunch(store, cfg, info, ev);
          if (++recent >= 50) break;
        }
        if (recent > 0)
          std::fprintf(stderr, "[zk] poll_fallback enqueued %d recent logs\n", recent);
      } else {
        std::fprintf(stderr, "[zk] ReadAttendanceLogs: %s\n", err.c_str());
      }
    }

    FlushOutbox(cfg, store, http, cred);

    if (now - last_prune > 3600) {
      last_prune = now;
      MaybePrune(store, cfg);
    }
  }

  device.Disconnect();
  std::fprintf(stderr, "[gateway] stopped\n");
  return 0;
}

}  // namespace cg
