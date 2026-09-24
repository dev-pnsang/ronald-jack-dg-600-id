#include "gateway.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <thread>
#include <vector>

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
  localtime_r(&now, &tmb);
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


std::string FingerprintEvents(const std::vector<AttendanceEvent>& logs) {
  std::vector<std::string> keys;
  keys.reserve(logs.size());
  for (const auto& ev : logs) keys.push_back(DedupeKey(ev));
  std::sort(keys.begin(), keys.end());
  uint64_t h = 5381;
  for (const auto& k : keys) {
    for (unsigned char c : k) h = ((h << 5) + h) + c;
  }
  return std::to_string(keys.size()) + ":" + std::to_string(h);
}

std::string FingerprintUsers(const std::vector<UserRecord>& users) {
  std::vector<std::string> keys;
  keys.reserve(users.size());
  for (const auto& u : users) {
    keys.push_back(u.user_id + "|" + u.name + "|" + std::to_string(u.privilege) + "|" +
                    (u.enabled ? "1" : "0"));
  }
  std::sort(keys.begin(), keys.end());
  uint64_t h = 5381;
  for (const auto& k : keys) {
    for (unsigned char c : k) h = ((h << 5) + h) + c;
  }
  return std::to_string(keys.size()) + ":" + std::to_string(h);
}

std::string SanitizeUtf8Users(const std::string& s) {
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

void SyncMachineUsersCatalog(Config& cfg, Store& store, const HttpClient& http, const Credential& cred,
                             const std::string& terminal_id, const std::string& terminal_ip,
                             const std::vector<UserRecord>& users) {
  if (users.empty()) {
    std::fprintf(stderr, "[users] %s empty catalog (skip)\n", terminal_ip.c_str());
    return;
  }
  std::string fp = FingerprintUsers(users);
  std::string fp_key = "users_fp:" + (terminal_id.empty() ? terminal_ip : terminal_id);
  std::string prev_fp;
  std::string meta_err;
  store.GetMeta(fp_key, prev_fp, meta_err);
  if (!prev_fp.empty() && prev_fp == fp) {
    std::fprintf(stderr, "[users] %s unchanged fp=%s (skip PUT)\n", terminal_ip.c_str(), fp.c_str());
    return;
  }
  nlohmann::json body;
  body["terminal_ip"] = terminal_ip;
  nlohmann::json arr = nlohmann::json::array();
  for (const auto& u : users) {
    if (u.user_id.empty()) continue;
    nlohmann::json row;
    row["user_id"] = SanitizeUtf8Users(u.user_id);
    if (!u.name.empty()) row["name"] = SanitizeUtf8Users(u.name);
    row["privilege"] = u.privilege;
    row["enabled"] = u.enabled;
    arr.push_back(std::move(row));
  }
  body["users"] = std::move(arr);
  auto r = SignedRequest(cfg, http, cred, "PUT", "/checkin/machine-users", body.dump());
  if (!r.ok) {
    std::fprintf(stderr, "[users] PUT fail %s: %s %s\n", terminal_ip.c_str(), r.error.c_str(),
                 r.body.substr(0, 200).c_str());
    return;
  }
  store.SetMeta(fp_key, fp, meta_err);
  std::fprintf(stderr, "[users] synced %zu from %s fp=%s\n", users.size(), terminal_ip.c_str(),
               fp.c_str());
}


// Fire only in the first 90 seconds of local 00:00 and 12:00 (once per slot key).
std::string CurrentAttlogSyncSlot() {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  localtime_r(&now, &tmb);
  if (tmb.tm_hour != 0 && tmb.tm_hour != 12) return "";
  if (tmb.tm_min != 0) return "";
  if (tmb.tm_sec > 90) return "";
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d-%02d", tmb.tm_year + 1900, tmb.tm_mon + 1,
                tmb.tm_mday, tmb.tm_hour);
  return buf;
}

bool PunchOnOrAfter(const AttendanceEvent& ev, const std::string& ymd) {
  if (ymd.empty() || ymd.size() < 10) return true;
  int y = 0, m = 0, d = 0;
  if (std::sscanf(ymd.c_str(), "%d-%d-%d", &y, &m, &d) != 3) return true;
  if (ev.year != y) return ev.year > y;
  if (ev.month != m) return ev.month > m;
  return ev.day >= d;
}

void EnqueuePunch(Store& store, const Config& cfg, const DeviceInfo& info, const AttendanceEvent& ev) {
  AttendanceEvent punch = ev;
  if (punch.year < cfg.punch_min_year) {
    std::time_t now = std::time(nullptr);
    std::tm tmb{};
    localtime_r(&now, &tmb);
    punch.year = tmb.tm_year + 1900;
    punch.month = tmb.tm_mon + 1;
    punch.day = tmb.tm_mday;
    punch.hour = tmb.tm_hour;
    punch.minute = tmb.tm_min;
    punch.second = tmb.tm_sec;
    punch.timestamp_iso = FormatIso8601Offset(punch.year, punch.month, punch.day, punch.hour,
                                              punch.minute, punch.second, cfg.device_tz_offset_min);
    std::fprintf(stderr,
                 "[punch] bad device clock (%s) — using gateway time %s user=%s\n",
                 ev.timestamp_iso.c_str(), punch.timestamp_iso.c_str(), punch.user_id.c_str());
  }
  std::string body;
  try {
    body = BuildIngestBody(punch, info, cfg);
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "[punch] skip bad body user=%s: %s\n", punch.user_id.c_str(), ex.what());
    return;
  }
  auto key = DedupeKey(punch);
  std::string e2;
  if (!store.Enqueue(key, body, e2)) {
    std::fprintf(stderr, "[outbox] enqueue failed: %s\n", e2.c_str());
    return;
  }
  std::fprintf(stderr, "[punch] user=%s ts=%s verify=%d inout=%d live=%d\n", punch.user_id.c_str(),
               punch.timestamp_iso.c_str(), punch.verify_mode, punch.inout_mode,
               punch.from_live ? 1 : 0);
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

  struct TerminalTarget {
    std::string id;
    std::string name;
    std::string ip;
    int port = 4370;
    std::string usage_started_on;  // YYYY-MM-DD inclusive
  };

  auto parse_catalog = [&](const std::string& body, std::vector<TerminalTarget>& out) {
    out.clear();
    try {
      auto j = nlohmann::json::parse(body);
      auto data = j.contains("data") ? j["data"] : j;
      if (!data.is_array()) return;
      for (const auto& row : data) {
        TerminalTarget t;
        t.id = row.value("id", "");
        t.name = row.value("name", "");
        t.ip = row.value("ip_address", "");
        t.port = row.value("port", 4370);
        t.usage_started_on = row.value("usage_started_on", "");
        if (t.ip.empty()) continue;
        if (t.port <= 0) t.port = 4370;
        out.push_back(t);
      }
    } catch (const std::exception& ex) {
      std::fprintf(stderr, "[catalog] parse error: %s\n", ex.what());
    }
  };

  auto refresh_catalog = [&](std::vector<TerminalTarget>& terminals) {
    if (!cfg.discover_terminals) {
      terminals.clear();
      if (!cfg.device_ip.empty()) {
        terminals.push_back(
            TerminalTarget{"local", "config", cfg.device_ip, cfg.device_port, ""});
      }
      return;
    }
    auto r = SignedRequest(cfg, http, cred, "GET", "/checkin/terminals", "");
    if (r.ok) {
      parse_catalog(r.body, terminals);
      std::fprintf(stderr, "[catalog] %zu terminal(s) from server\n", terminals.size());
    } else {
      std::fprintf(stderr, "[catalog] fetch fail: %s %s\n", r.error.c_str(),
                   r.body.substr(0, 160).c_str());
    }
    if (terminals.empty() && !cfg.device_ip.empty()) {
      terminals.push_back(
          TerminalTarget{"local", "config-fallback", cfg.device_ip, cfg.device_port, ""});
      std::fprintf(stderr, "[catalog] empty — fallback device_ip=%s:%d\n", cfg.device_ip.c_str(),
                   cfg.device_port);
    }
  };

  std::vector<TerminalTarget> terminals;
  refresh_catalog(terminals);

  {
    std::string tip = cfg.device_ip;
    int tport = cfg.device_port;
    if (!terminals.empty()) {
      tip = terminals[0].ip;
      tport = terminals[0].port;
    }
    nlohmann::json hb = {
        {"lan_ip", PrimaryLanIPv4()},
        {"terminal_ip", tip},
        {"terminal_port", tport},
        {"hostname", Hostname()},
        {"agent_name", cfg.agent_name},
        {"agent_version", cfg.agent_version},
        {"terminal_model", "Ronald Jack DG-600-ID"},
    };
    std::string raw = hb.dump();
    auto hr = SignedRequest(cfg, http, cred, "PUT", "/device-identity/heartbeat", raw);
    if (hr.ok) {
      std::fprintf(stderr, "[heartbeat] ok status=%ld lan_ip=%s terminal_ip=%s\n", hr.status,
                   hb.value("lan_ip", "").c_str(), tip.c_str());
    } else {
      std::fprintf(stderr, "[heartbeat] fail: %s %s\n", hr.error.c_str(),
                   hr.body.substr(0, 200).c_str());
    }
  }

  std::fprintf(stderr,
               "[gateway] start agent=%s version=%s base_url=%s discover=%d terminals=%zu "
               "attlog_sync=00:00+12:00 ingest_minimal=%d\n",
               cfg.agent_name.c_str(), cfg.agent_version.c_str(), cfg.base_url.c_str(),
               cfg.discover_terminals ? 1 : 0, terminals.size(), cfg.ingest_minimal ? 1 : 0);

  int64_t last_catalog = UnixNow();
  int64_t last_prune = 0;
  int64_t last_heartbeat = UnixNow();
  std::string last_sync_slot;
  {
    std::string meta_err;
    store.GetMeta("attlog_last_sync_slot", last_sync_slot, meta_err);
  }
  // Never sync on startup — only at local 00:00 and 12:00.

  auto sync_terminal_attlog = [&](const TerminalTarget& t) {
    ZkDevice device;
    DeviceInfo info;
    info.ip = t.ip;
    info.port = t.port;
    device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
    std::string local_err;
    std::fprintf(stderr, "[attlog] sync %s (%s) %s:%d from=%s\n", t.name.c_str(), t.id.c_str(),
                 t.ip.c_str(), t.port,
                 t.usage_started_on.empty() ? "(today/all)" : t.usage_started_on.c_str());
    if (!device.Connect(t.ip, t.port, cfg.device_password, cfg.device_timeout_sec, local_err)) {
      std::fprintf(stderr, "[attlog] connect fail %s: %s\n", t.ip.c_str(), local_err.c_str());
      return;
    }
    device.ReadDeviceInfo(info, local_err);
    std::vector<AttendanceEvent> logs;
    if (!device.ReadAttendanceLogs(logs, local_err)) {
      std::fprintf(stderr, "[attlog] ReadAttendanceLogs %s: %s\n", t.ip.c_str(), local_err.c_str());
      // Still try ReadUsers in same session if ATTLOG failed mid-way.
    }
    std::vector<UserRecord> users;
    if (!device.ReadUsers(users, local_err)) {
      std::fprintf(stderr, "[users] ReadUsers %s: %s\n", t.ip.c_str(), local_err.c_str());
      users.clear();
    }
    device.Disconnect();

    // Push USERTEMP catalog (independent of ATTLOG fingerprint skip).
    SyncMachineUsersCatalog(cfg, store, http, cred, t.id, t.ip, users);

    std::string since = t.usage_started_on;
    if (since.empty()) {
      std::time_t tn = std::time(nullptr);
      std::tm tmb{};
      localtime_r(&tn, &tmb);
      char buf[16];
      std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tmb.tm_year + 1900, tmb.tm_mon + 1,
                    tmb.tm_mday);
      since = buf;
    }

    std::vector<AttendanceEvent> filtered;
    filtered.reserve(logs.size());
    for (auto& ev : logs) {
      if (ev.year < cfg.punch_min_year) continue;
      if (!PunchOnOrAfter(ev, since)) continue;
      filtered.push_back(std::move(ev));
    }

    std::string fp = FingerprintEvents(filtered);
    std::string fp_key = "attlog_fp:" + (t.id.empty() ? t.ip : t.id);
    std::string prev_fp;
    std::string meta_err;
    store.GetMeta(fp_key, prev_fp, meta_err);
    if (!prev_fp.empty() && prev_fp == fp) {
      std::fprintf(stderr, "[attlog] %s unchanged fp=%s (skip ingest)\n", t.ip.c_str(), fp.c_str());
      return;
    }

    int enq = 0;
    for (auto& ev : filtered) {
      ev.from_live = false;
      EnqueuePunch(store, cfg, info, ev);
      ++enq;
    }
    store.SetMeta(fp_key, fp, meta_err);
    std::fprintf(stderr, "[attlog] %s filtered=%zu/%zu enqueued=%d fp=%s\n", t.ip.c_str(),
                 filtered.size(), logs.size(), enq, fp.c_str());
  };

  while (g_running) {
    int64_t now = UnixNow();
    if (cfg.discover_terminals &&
        (now - last_catalog >= std::max(60, cfg.catalog_refresh_sec))) {
      last_catalog = now;
      refresh_catalog(terminals);
    }

    if (now - last_heartbeat >= 300) {
      last_heartbeat = now;
      std::string tip = terminals.empty() ? cfg.device_ip : terminals[0].ip;
      int tport = terminals.empty() ? cfg.device_port : terminals[0].port;
      nlohmann::json hb = {
          {"lan_ip", PrimaryLanIPv4()},
          {"terminal_ip", tip},
          {"terminal_port", tport},
          {"hostname", Hostname()},
          {"agent_name", cfg.agent_name},
          {"agent_version", cfg.agent_version},
      };
      auto hr = SignedRequest(cfg, http, cred, "PUT", "/device-identity/heartbeat", hb.dump());
      if (!hr.ok) {
        std::fprintf(stderr, "[heartbeat] fail: %s\n", hr.error.c_str());
      }
    }

    std::string slot = CurrentAttlogSyncSlot();
    if (!slot.empty() && slot != last_sync_slot && !terminals.empty()) {
      std::fprintf(stderr, "[attlog] scheduled sync slot=%s terminals=%zu\n", slot.c_str(),
                   terminals.size());
      for (const auto& t : terminals) {
        if (!g_running) break;
        sync_terminal_attlog(t);
        FlushOutbox(cfg, store, http, cred);
      }
      last_sync_slot = slot;
      std::string meta_err;
      store.SetMeta("attlog_last_sync_slot", last_sync_slot, meta_err);
    }

    FlushOutbox(cfg, store, http, cred);
    now = UnixNow();
    if (now - last_prune > 3600) {
      last_prune = now;
      MaybePrune(store, cfg);
    }
    // Idle loop — no live listen / no frequent ATTLOG (locks ZK panel).
    for (int i = 0; i < 30 && g_running; ++i) {
      FlushOutbox(cfg, store, http, cred);
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }

  std::fprintf(stderr, "[gateway] stopped\n");
  return 0;
}

}  // namespace cg
