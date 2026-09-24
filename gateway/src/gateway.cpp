#include "gateway.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <thread>

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

void FlushOutbox(const Config& cfg, Store& store, const HttpClient& http, const Credential& cred) {
  auto due = store.DueOutbox(20, UnixNow());
  for (const auto& item : due) {
    if (!g_running) break;
    auto r = PostDeviceIngest(cfg, http, cred, item.body_json);
    std::string err;
    if (r.ok && r.status == 201) {
      store.MarkOutboxOk(item.id, err);
      std::fprintf(stderr, "[ingest] ok id=%lld status=%ld\n", static_cast<long long>(item.id),
                   r.status);
    } else {
      std::string detail = r.error;
      if (!r.body.empty()) detail += " " + r.body.substr(0, 200);
      int64_t next = UnixNow() + cfg.outbox_retry_sec;
      store.MarkOutboxFail(item.id, detail, next, err);
      std::fprintf(stderr, "[ingest] fail id=%lld: %s\n", static_cast<long long>(item.id),
                   detail.c_str());
      // Do not log secrets; body already sent.
    }
  }
}

}  // namespace

int RunEnroll(const Config& cfg, const std::string& pairing_code) {
  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
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
  std::fprintf(stdout, "Enrolled OK.\n");
  std::fprintf(stdout, "  device_id: %s\n", cred.device_id.c_str());
  std::fprintf(stdout, "  organization_id: %s\n", cred.organization_id.c_str());
  std::fprintf(stdout, "  credential_id: %s\n", cred.credential_id.c_str());
  std::fprintf(stdout, "  scopes: %s\n", cred.scopes_json.c_str());
  std::fprintf(stdout, "Secrets stored in %s/state.db (do not commit).\n", cfg.data_dir.c_str());
  return 0;
}

int RunGateway(const Config& cfg) {
  std::signal(SIGINT, OnSignal);
  std::signal(SIGTERM, OnSignal);

  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
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

  std::fprintf(stderr, "[gateway] start agent=%s version=%s base_url=%s device=%s:%d\n",
               cfg.agent_name.c_str(), cfg.agent_version.c_str(), cfg.base_url.c_str(),
               cfg.device_ip.c_str(), cfg.device_port);

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
        std::fprintf(stderr, "[zk] live listen ON — punches will be ingested\n");
      }
    }

    // Live poll
    bool ok = device.PollLive(
        [&](const AttendanceEvent& ev) {
          auto body = BuildIngestBody(ev, info, cfg);
          auto key = DedupeKey(ev);
          std::string e2;
          if (!store.Enqueue(key, body, e2)) {
            std::fprintf(stderr, "[outbox] enqueue failed: %s\n", e2.c_str());
            return;
          }
          std::fprintf(stderr, "[punch] user=%s ts=%s verify=%d inout=%d\n", ev.user_id.c_str(),
                       ev.timestamp_iso.c_str(), ev.verify_mode, ev.inout_mode);
        },
        500, err);

    if (!ok) {
      std::fprintf(stderr, "[zk] poll error: %s — reconnecting\n", err.c_str());
      device.Disconnect();
      std::this_thread::sleep_for(std::chrono::seconds(cfg.reconnect_delay_sec));
    }

    FlushOutbox(cfg, store, http, cred);
  }

  device.Disconnect();
  std::fprintf(stderr, "[gateway] stopped\n");
  return 0;
}

}  // namespace cg
