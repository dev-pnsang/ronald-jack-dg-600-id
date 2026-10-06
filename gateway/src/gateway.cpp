#include "gateway.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <sstream>
#include <ctime>
#include <fstream>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>

#include "capture.hpp"
#include "device_identity.hpp"
#include "http_client.hpp"
#include "ingest.hpp"
#include "store.hpp"
#include "util.hpp"
#include "zk_device.hpp"

namespace cg {
namespace {

std::atomic<bool> g_running{true};
std::atomic<bool> g_ingest_run{true};

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

// Ship short Vietnamese ops messages to CommaDesk Device Monitor (POST /device-ops/logs).
// Keep codes stable (English snake_case); put human text in `message`.
void OpsLog(Store& store, const char* level, const char* component, const char* code,
            const std::string& message, const nlohmann::json& fields = nlohmann::json::object()) {
  std::string oe;
  store.EnqueueOpsLog(level, component, code, message, fields.dump(), oe);
  AppendOpsCapture(level ? level : "", component ? component : "", code ? code : "", message, fields.dump());
}

bool SyncMachineUsersCatalog(Config& cfg, Store& store, const HttpClient& http, const Credential& cred,
                             const std::string& terminal_id, const std::string& terminal_ip,
                             const std::vector<UserRecord>& users, bool force = false) {
  if (users.empty()) {
    std::fprintf(stderr, "[users] %s empty catalog (skip)\n", terminal_ip.c_str());
    OpsLog(store, "warn", "users", "users_empty",
           "Máy chấm công không có user id để đồng bộ",
           {{"terminal_ip", terminal_ip}, {"terminal_id", terminal_id}});
    return false;
  }
  std::string fp = FingerprintUsers(users);
  std::string fp_key = "users_fp:" + (terminal_id.empty() ? terminal_ip : terminal_id);
  std::string prev_fp;
  std::string meta_err;
  store.GetMeta(fp_key, prev_fp, meta_err);
  if (!force && !prev_fp.empty() && prev_fp == fp) {
    std::fprintf(stderr, "[users] %s unchanged fp=%s (skip PUT)\n", terminal_ip.c_str(), fp.c_str());
    OpsLog(store, "info", "users", "users_unchanged",
           "Danh sách user id không đổi — bỏ qua gửi lên server",
           {{"terminal_ip", terminal_ip}, {"terminal_id", terminal_id}, {"fp", fp},
            {"count", users.size()}});
    return true;
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
  const size_t user_n = body["users"].size();
  std::string raw = body.dump();
  std::fprintf(stderr, "[users] PUT /checkin/machine-users terminal_ip=%s count=%zu bytes=%zu%s\n",
               terminal_ip.c_str(), user_n, raw.size(), force ? " (force)" : "");
  auto r = SignedRequest(cfg, http, cred, "PUT", "/checkin/machine-users", raw);
  if (!r.ok) {
    std::fprintf(stderr, "[users] PUT fail %s: %s %s\n", terminal_ip.c_str(), r.error.c_str(),
                 r.body.substr(0, 400).c_str());
    OpsLog(store, "error", "users", "users_put_fail",
           "Gửi danh sách user id lên server thất bại",
           {{"terminal_ip", terminal_ip},
            {"terminal_id", terminal_id},
            {"count", user_n},
            {"detail", (r.error + " " + r.body.substr(0, 120)).substr(0, 160)}});
    return false;
  }
  store.SetMeta(fp_key, fp, meta_err);
  std::fprintf(stderr, "[users] synced %zu from %s fp=%s status=%ld body=%s\n", user_n,
               terminal_ip.c_str(), fp.c_str(), r.status, r.body.substr(0, 200).c_str());
  OpsLog(store, "info", "users", "users_put_ok",
         "Đã gửi danh sách user id lên server thành công",
         {{"terminal_ip", terminal_ip},
          {"terminal_id", terminal_id},
          {"count", user_n},
          {"force", force},
          {"http_status", r.status}});
  return true;
}


// Local calendar day. day_offset -1 is yesterday. mktime normalizes month edges.
std::string LocalYmd(int day_offset) {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  localtime_r(&now, &tmb);
  tmb.tm_mday += day_offset;
  tmb.tm_isdst = -1;
  std::mktime(&tmb);
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tmb.tm_year + 1900, tmb.tm_mon + 1, tmb.tm_mday);
  return buf;
}

// 1 minute, then 5 minutes, then 15 minutes.
int64_t BackoffDelaySec(int step) {
  if (step <= 0) return 60;
  if (step == 1) return 300;
  return 900;
}

// Latest configured HH:MM that has already started today. Empty before the first slot.
// The key stays due until a read succeeds, including after the old 90-second window.
std::string LatestPassedSyncSlot(const std::string& times_csv) {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  localtime_r(&now, &tmb);
  std::string csv = times_csv.empty() ? "00:00,12:00" : times_csv;
  std::stringstream ss(csv);
  std::string part;
  std::string best;
  int best_mins = -1;
  const int now_mins = tmb.tm_hour * 60 + tmb.tm_min;
  while (std::getline(ss, part, ',')) {
    int h = -1, m = -1;
    if (std::sscanf(part.c_str(), "%d:%d", &h, &m) != 2) continue;
    if (h < 0 || h > 23 || m < 0 || m > 59) continue;
    const int target = h * 60 + m;
    if (now_mins < target || target < best_mins) continue;
    best_mins = target;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d-%02d%02d", tmb.tm_year + 1900, tmb.tm_mon + 1,
                  tmb.tm_mday, h, m);
    best = buf;
  }
  return best;
}

// Fire in the first ~90s of each configured HH:MM slot (once per slot key).
std::string CurrentAttlogSyncSlot(const std::string& times_csv) {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  localtime_r(&now, &tmb);
  std::string csv = times_csv.empty() ? "00:00,12:00" : times_csv;
  std::stringstream ss(csv);
  std::string part;
  while (std::getline(ss, part, ',')) {
    int h = -1, m = -1;
    if (std::sscanf(part.c_str(), "%d:%d", &h, &m) != 2) continue;
    if (h < 0 || h > 23 || m < 0 || m > 59) continue;
    if (tmb.tm_hour != h) continue;
    int mins = tmb.tm_min * 60 + tmb.tm_sec;
    int target = m * 60;
    if (mins < target || mins > target + 90) continue;
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d-%02d%02d", tmb.tm_year + 1900, tmb.tm_mon + 1,
                  tmb.tm_mday, h, m);
    return buf;
  }
  return "";
}

void ApplyDeviceBootstrap(Config& cfg, Store& store, HttpClient& http, Credential& cred) {
  auto r = SignedRequest(cfg, http, cred, "GET", "/device-identity/bootstrap", "");
  if (!r.ok) {
    std::fprintf(stderr, "[bootstrap] fail: %s %s\n", r.error.c_str(),
                 r.body.substr(0, 160).c_str());
    OpsLog(store, "warn", "bootstrap", "bootstrap_fail",
           "Không lấy được cấu hình bootstrap từ server",
           {{"detail", (r.error + " " + r.body.substr(0, 120)).substr(0, 160)}});
    return;
  }
  try {
    auto j = nlohmann::json::parse(r.body);
    auto d = j.at("data");
    if (d.contains("discover_terminals")) {
      cfg.discover_terminals = d.value("discover_terminals", cfg.discover_terminals);
    }
    if (d.contains("catalog_refresh_sec")) {
      int v = d.value("catalog_refresh_sec", cfg.catalog_refresh_sec);
      if (v >= 60) cfg.catalog_refresh_sec = v;
    }
    if (d.contains("attlog_sync_times") && d["attlog_sync_times"].is_array()) {
      std::string csv;
      for (const auto& t : d["attlog_sync_times"]) {
        if (!t.is_string()) continue;
        if (!csv.empty()) csv += ",";
        csv += t.get<std::string>();
      }
      if (!csv.empty()) cfg.attlog_sync_times = csv;
    }
    if (d.contains("users_sync_times") && d["users_sync_times"].is_array()) {
      std::string csv;
      for (const auto& t : d["users_sync_times"]) {
        if (!t.is_string()) continue;
        if (!csv.empty()) csv += ",";
        csv += t.get<std::string>();
      }
      if (!csv.empty()) cfg.users_sync_times = csv;
    }
    std::string e2;
    store.SetMeta("bootstrap_channel_mode",
                  d.value("checkin_channel_mode", std::string("both")), e2);
    store.SetMeta("attlog_sync_times", cfg.attlog_sync_times, e2);
    store.SetMeta("users_sync_times", cfg.users_sync_times, e2);
    std::fprintf(stderr,
                 "[bootstrap] ok discover=%d catalog_sec=%d attlog=%s users=%s channel=%s\n",
                 cfg.discover_terminals ? 1 : 0, cfg.catalog_refresh_sec,
                 cfg.attlog_sync_times.c_str(), cfg.users_sync_times.c_str(),
                 d.value("checkin_channel_mode", std::string("both")).c_str());
    OpsLog(store, "info", "bootstrap", "bootstrap_ok",
           "Đã nhận cấu hình bootstrap từ server",
           {{"discover_terminals", cfg.discover_terminals},
            {"catalog_refresh_sec", cfg.catalog_refresh_sec},
            {"attlog_sync_times", cfg.attlog_sync_times},
            {"users_sync_times", cfg.users_sync_times},
            {"checkin_channel_mode", d.value("checkin_channel_mode", std::string("both"))}});
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "[bootstrap] parse: %s\n", ex.what());
    OpsLog(store, "error", "bootstrap", "bootstrap_parse_fail",
           "Phân tích cấu hình bootstrap thất bại", {{"detail", ex.what()}});
  }
}

bool SensorEnableAllowed(Store& store, const std::map<std::string, bool>& spent, const std::string& ip) {
  auto it = spent.find(ip);
  if (it != spent.end() && it->second) return false;
  std::string raw;
  std::string err;
  if (!store.GetMeta("sensor_enable_at:" + ip, raw, err) || raw.empty()) return true;
  const int64_t at = std::strtoll(raw.c_str(), nullptr, 10);
  if (at <= 0) return true;
  return UnixNow() - at >= 900;
}

void NoteSensorEnable(Store& store, std::map<std::string, bool>& spent, const std::string& ip) {
  spent[ip] = true;
  std::string err;
  store.SetMeta("sensor_enable_at:" + ip, std::to_string(UnixNow()), err);
}

bool PunchAtOrAfterUnix(const AttendanceEvent& ev, int64_t watermark) {
  if (watermark <= 0) return true;
  std::tm tmb{};
  tmb.tm_year = ev.year - 1900;
  tmb.tm_mon = ev.month - 1;
  tmb.tm_mday = ev.day;
  tmb.tm_hour = ev.hour;
  tmb.tm_min = ev.minute;
  tmb.tm_sec = ev.second;
  tmb.tm_isdst = -1;
  const std::time_t punch = std::mktime(&tmb);
  if (punch == static_cast<std::time_t>(-1)) return true;
  return static_cast<int64_t>(punch) >= watermark;
}

// Read the catalog today, or immediately when the device user count changed.
bool UsersCatalogDue(Store& store, const std::string& tid, int user_count) {
  std::string meta_err;
  std::string prev_count;
  std::string prev_fp;
  std::string read_on;
  store.GetMeta("users_count:" + tid, prev_count, meta_err);
  store.GetMeta("users_fp:" + tid, prev_fp, meta_err);
  store.GetMeta("users_read_on:" + tid, read_on, meta_err);
  if (read_on == LocalYmd(0) && !prev_fp.empty() && !prev_count.empty() &&
      prev_count == std::to_string(user_count)) {
    return false;
  }
  return true;
}

bool PunchOnOrAfter(const AttendanceEvent& ev, const std::string& ymd) {
  if (ymd.empty() || ymd.size() < 10) return true;
  int y = 0, m = 0, d = 0;
  if (std::sscanf(ymd.c_str(), "%d-%d-%d", &y, &m, &d) != 3) return true;
  if (ev.year != y) return ev.year > y;
  if (ev.month != m) return ev.month > m;
  return ev.day >= d;
}

int MaxPunchYear() {
  std::time_t now = std::time(nullptr);
  std::tm tmb{};
  localtime_r(&now, &tmb);
  return tmb.tm_year + 1900 + 1;
}

bool PunchYearOk(const AttendanceEvent& ev, int min_year) {
  return ev.year >= min_year && ev.year <= MaxPunchYear();
}

bool UserCatalogComplete(int device_count, const std::vector<UserRecord>& users) {
  if (users.empty()) return false;
  if (device_count > 0 && static_cast<int>(users.size()) + 1 < device_count) return false;
  int named = 0;
  for (const auto& u : users) {
    if (!u.user_id.empty() && !u.name.empty()) ++named;
  }
  return named * 2 >= static_cast<int>(users.size());
}

bool EnqueuePunch(Store& store, const Config& cfg, const DeviceInfo& info, const AttendanceEvent& ev) {
  AttendanceEvent punch = ev;
  if (!PunchYearOk(punch, cfg.punch_min_year)) {
    std::fprintf(stderr, "[punch] drop implausible time %s user=%s\n", punch.timestamp_iso.c_str(),
                 punch.user_id.c_str());
    OpsLog(store, "warn", "gateway", "punch_bad_time",
           "Bỏ qua chấm công vì năm không hợp lệ",
           {{"user", punch.user_id}, {"timestamp", punch.timestamp_iso}});
    return true;
  }
  std::string body;
  try {
    body = BuildIngestBody(punch, info, cfg);
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "[punch] skip bad body user=%s: %s\n", punch.user_id.c_str(), ex.what());
    OpsLog(store, "error", "gateway", "punch_bad_body",
           "Bỏ qua chấm công vì dữ liệu không hợp lệ",
           {{"user", punch.user_id}, {"detail", ex.what()}});
    return false;
  }
  auto key = DedupeKey(punch);
  std::string e2;
  if (!store.Enqueue(key, body, e2)) {
    std::fprintf(stderr, "[outbox] enqueue failed: %s\n", e2.c_str());
    OpsLog(store, "error", "gateway", "outbox_enqueue_fail",
           "Không ghi được chấm công vào hàng đợi gửi",
           {{"user", punch.user_id}, {"detail", e2}});
    return false;
  }
  OpsLog(store, "info", "gateway", "punch", "Đã nhận chấm công từ máy",
         {{"user", punch.user_id},
          {"live", punch.from_live ? 1 : 0},
          {"timestamp", punch.timestamp_iso},
          {"verify_mode", punch.verify_mode},
          {"inout_mode", punch.inout_mode}});
  std::fprintf(stderr, "[punch] user=%s ts=%s verify=%d inout=%d live=%d\n", punch.user_id.c_str(),
               punch.timestamp_iso.c_str(), punch.verify_mode, punch.inout_mode,
               punch.from_live ? 1 : 0);
  return true;
}

bool IngestAccepted(const SignedResult& r) {
  if (r.status == 409) return true;
  return r.status >= 200 && r.status < 300;
}

void FlushOutbox(Config& cfg, Store& store, const HttpClient& http, const Credential& cred,
                  int limit = 20) {
  if (limit < 1) limit = 1;
  auto due = store.DueOutbox(limit, UnixNow(), 0);
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
        OpsLog(store, "warn", "ingest", "ingest_minimal_retry",
               "Server từ chối body đầy đủ — thử gửi tối giản",
               {{"outbox_id", item.id}});
        r = PostDeviceIngest(cfg, http, cred, raw);
        if (IngestAccepted(r)) {
          // Replace stored body so future retries stay minimal for this punch.
          store.MarkOutboxOk(item.id, err);
          // Re-mark seen already done; also flip config suggestion only via log.
          OpsLog(store, "info", "ingest", "ingest_ok",
                 "Server đã chấp nhận chấm công (body tối giản)",
                 {{"outbox_id", item.id}, {"minimal", true}});
          std::fprintf(stderr, "[ingest] ok id=%lld status=%ld (minimal)\n",
                       static_cast<long long>(item.id), r.status);
          continue;
        }
      } catch (...) {
        // fall through to normal fail path
      }
    }

    if (IngestAccepted(r)) {
      store.MarkOutboxOk(item.id, err);
      const bool already = r.status == 409;
      OpsLog(store, "info", "ingest", already ? "ingest_already" : "ingest_ok",
             already ? "Server đã có punch này" : "Server đã chấp nhận chấm công",
             {{"outbox_id", item.id}, {"http_status", r.status}});
      std::fprintf(stderr, "[ingest] ok id=%lld status=%ld\n", static_cast<long long>(item.id),
                   r.status);
    } else {
      std::string detail = r.error;
      if (!r.body.empty()) detail += " " + r.body.substr(0, 200);
      int next_attempts = item.attempts + 1;
      const bool client_error = r.status >= 400 && r.status < 500;
      const bool slow = client_error || next_attempts >= cfg.outbox_max_attempts;
      int64_t next = UnixNow() + (slow ? 900 : cfg.outbox_retry_sec);
      store.MarkOutboxFail(item.id, detail, next, err);
      if (next_attempts == cfg.outbox_max_attempts) {
        OpsLog(store, "error", "ingest", "ingest_kept",
               "Gửi chấm công thất bại nhiều lần. Giữ punch và gửi lại chậm",
               {{"outbox_id", item.id}, {"attempts", next_attempts},
                {"http_status", r.status}, {"detail", detail.substr(0, 160)}});
      } else if (next_attempts == 1 || next_attempts % 5 == 0) {
        OpsLog(store, "warn", "ingest", "ingest_fail", "Gửi chấm công lên server thất bại",
               {{"outbox_id", item.id}, {"attempt", next_attempts}, {"http_status", r.status},
                {"detail", detail.substr(0, 160)}});
      }
      std::fprintf(stderr, "[ingest] keep id=%lld attempt=%d retry_in=%s status=%ld: %s\n",
                   static_cast<long long>(item.id), next_attempts, slow ? "900s" : "fast", r.status,
                   detail.c_str());
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


void FlushOpsLogs(Config& cfg, Store& store, HttpClient& http, Credential& cred) {
  auto items = store.DueOpsLogs(50);
  if (items.empty()) return;
  nlohmann::json entries = nlohmann::json::array();
  std::vector<int64_t> ids;
  for (const auto& it : items) {
    nlohmann::json e = {
        {"ts", it.ts_iso},
        {"level", it.level},
        {"component", it.component},
        {"message", it.message},
    };
    if (!it.code.empty()) e["code"] = it.code;
    if (!it.fields_json.empty()) {
      try { e["fields"] = nlohmann::json::parse(it.fields_json); } catch (...) {}
    }
    entries.push_back(e);
    ids.push_back(it.id);
  }
  nlohmann::json body = {{"entries", entries}};
  auto r = SignedRequest(cfg, http, cred, "POST", "/device-ops/logs", body.dump());
  if (!r.ok) {
    std::fprintf(stderr, "[ops] flush fail: %s %s\n", r.error.c_str(), r.body.substr(0, 160).c_str());
    return;
  }
  std::string e2;
  store.DeleteOpsLogs(ids, e2);
}

void HardenDataDir(const Config& cfg) {
  ::chmod(cfg.data_dir.c_str(), 0700);
  std::string db = cfg.data_dir + "/state.db";
  ::chmod(db.c_str(), 0600);
  if (!cfg.config_path.empty()) ::chmod(cfg.config_path.c_str(), 0640);
}

// When enroll runs as root, hand ownership to the systemd service user so
// checkin-gateway.service (User=checkin-gateway) can open state.db.
void EnsureServiceDataOwnership(const Config& cfg) {
  if (::geteuid() != 0) return;
  struct passwd* pw = ::getpwnam("checkin-gateway");
  if (!pw) return;
  const uid_t uid = pw->pw_uid;
  const gid_t gid = pw->pw_gid;
  ::chown(cfg.data_dir.c_str(), uid, gid);
  const std::string db = cfg.data_dir + "/state.db";
  ::chown(db.c_str(), uid, gid);
  ::chown((db + "-wal").c_str(), uid, gid);
  ::chown((db + "-shm").c_str(), uid, gid);
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
  EnsureServiceDataOwnership(cfg);
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

int RunSyncUsers(const Config& cfg_in) {
  Config cfg = cfg_in;
  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }
  SetCaptureDir(cfg.data_dir);
  Store store;
  if (!store.Open(cfg.data_dir + "/state.db", err)) {
    std::fprintf(stderr, "store: %s\n", err.c_str());
    return 1;
  }
  Credential cred;
  if (!store.LoadCredential(cred, err)) {
    std::fprintf(stderr, "Not enrolled: %s\n", err.c_str());
    return 2;
  }

  HttpClient http(cfg.http_timeout_sec);
  std::string tip = cfg.device_ip;
  int tport = cfg.device_port;
  std::string tid;
  std::string tname = "config";

  if (cfg.discover_terminals) {
    auto r = SignedRequest(cfg, http, cred, "GET", "/checkin/terminals", "");
    if (r.ok) {
      try {
        auto j = nlohmann::json::parse(r.body);
        auto data = j.contains("data") ? j["data"] : j;
        if (data.is_array() && !data.empty()) {
          const auto& row = data[0];
          tip = row.value("ip_address", tip);
          tport = row.value("port", tport);
          tid = row.value("id", "");
          tname = row.value("name", tname);
          if (tport <= 0) tport = 4370;
        }
      } catch (const std::exception& ex) {
        std::fprintf(stderr, "[users] catalog parse: %s — using config device_ip\n", ex.what());
      }
    } else {
      std::fprintf(stderr, "[users] catalog fail: %s — using config device_ip\n", r.error.c_str());
    }
  }

  if (tip.empty()) {
    std::fprintf(stderr, "[users] no terminal IP configured\n");
    return 1;
  }

  std::fprintf(stderr, "[users] reading from %s (%s) %s:%d ...\n", tname.c_str(), tid.c_str(),
               tip.c_str(), tport);
  OpsLog(store, "info", "users", "users_manual_start",
         "Chạy đồng bộ user id thủ công (--sync-users)",
         {{"ip", tip}, {"port", tport}, {"name", tname}});
  ZkDevice device;
  device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
  if (!device.Connect(tip, tport, cfg.device_password, cfg.device_timeout_sec, err,
                      /*allow_sensor_enable=*/false)) {
    std::fprintf(stderr, "[users] connect fail: %s\n", err.c_str());
    OpsLog(store, "warn", "zk", "connect_fail",
           "Không kết nối được máy chấm công khi đồng bộ user id thủ công",
           {{"ip", tip}, {"port", tport}, {"detail", err}, {"phase", "sync_users_cli"}});
    FlushOpsLogs(cfg, store, http, cred);
    FlushCaptureArchives(cfg, http, cred, true);
    return 3;
  }
  std::vector<UserRecord> users;
  if (!device.ReadUsers(users, err)) {
    std::fprintf(stderr, "[users] ReadUsers fail: %s\n", err.c_str());
    OpsLog(store, "warn", "users", "users_read_fail",
           "Đọc danh sách user id từ máy thất bại (thủ công)",
           {{"ip", tip}, {"detail", err}});
    device.Disconnect();
    FlushOpsLogs(cfg, store, http, cred);
    FlushCaptureArchives(cfg, http, cred, true);
    return 4;
  }
  device.Disconnect();

  std::fprintf(stderr, "[users] device returned %zu user(s):\n", users.size());
  for (const auto& u : users) {
    std::fprintf(stderr, "  id=%s name=%s priv=%d enabled=%d\n", u.user_id.c_str(), u.name.c_str(),
                 u.privilege, u.enabled ? 1 : 0);
  }

  if (!SyncMachineUsersCatalog(cfg, store, http, cred, tid, tip, users, /*force=*/true)) {
    FlushOpsLogs(cfg, store, http, cred);
    FlushCaptureArchives(cfg, http, cred, true);
    return 5;
  }
  FlushOpsLogs(cfg, store, http, cred);
  FlushCaptureArchives(cfg, http, cred, true);
  std::fprintf(stdout, "OK synced %zu users from %s to %s/checkin/machine-users\n", users.size(),
               tip.c_str(), cfg.base_url.c_str());
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
  SetCaptureDir(cfg.data_dir);
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
    bool from_server = false;
    if (r.ok) {
      parse_catalog(r.body, terminals);
      from_server = true;
      std::fprintf(stderr, "[catalog] %zu terminal(s) from server\n", terminals.size());
    } else {
      std::fprintf(stderr, "[catalog] fetch fail: %s %s\n", r.error.c_str(),
                   r.body.substr(0, 160).c_str());
      static int64_t last_catalog_fail_ops = 0;
      const int64_t now_cf = UnixNow();
      if (now_cf - last_catalog_fail_ops >= 300) {
        OpsLog(store, "warn", "catalog", "catalog_fetch_fail",
               "Không lấy được danh sách thiết bị chấm công từ server",
               {{"detail", (r.error + " " + r.body.substr(0, 120)).substr(0, 160)}});
        last_catalog_fail_ops = now_cf;
      }
    }

    bool used_fallback = false;
    if (terminals.empty() && !cfg.device_ip.empty()) {
      terminals.push_back(
          TerminalTarget{"local", "config-fallback", cfg.device_ip, cfg.device_port, ""});
      used_fallback = true;
      std::fprintf(stderr, "[catalog] empty — fallback device_ip=%s:%d\n", cfg.device_ip.c_str(),
                   cfg.device_port);
    }

    // Ops notify when catalog changes (not every refresh) — helps verify server/local match.
    if (from_server || used_fallback) {
      std::ostringstream fp_ss;
      fp_ss << (from_server ? "srv:" : "fb:") << terminals.size();
      int matched = 0;
      nlohmann::json list = nlohmann::json::array();
      for (const auto& t : terminals) {
        fp_ss << "|" << t.id << "@" << t.ip << ":" << t.port;
        bool same_cfg = (!cfg.device_ip.empty() && t.ip == cfg.device_ip && t.port == cfg.device_port);
        if (same_cfg) ++matched;
        list.push_back({{"id", t.id},
                        {"name", t.name},
                        {"ip", t.ip},
                        {"port", t.port},
                        {"matches_local_config", same_cfg}});
      }
      fp_ss << "|local=" << cfg.device_ip << ":" << cfg.device_port << "|m=" << matched;
      const std::string fp = fp_ss.str();
      std::string prev_fp;
      std::string meta_err;
      store.GetMeta("ops_catalog_fp", prev_fp, meta_err);
      if (prev_fp != fp) {
        store.SetMeta("ops_catalog_fp", fp, meta_err);
        nlohmann::json fields = {{"count", terminals.size()},
                                 {"local_ip", cfg.device_ip},
                                 {"local_port", cfg.device_port},
                                 {"matched_local_config", matched},
                                 {"terminals", list}};
        if (used_fallback) {
          OpsLog(store, "warn", "catalog", "terminal_fallback",
                 "Server chưa có thiết bị chấm công phù hợp — dùng cấu hình local", fields);
        } else if (matched > 0) {
          OpsLog(store, "info", "catalog", "terminal_matched",
                 "Đã phát hiện thiết bị chấm công trên server trùng cấu hình local (IP/port)",
                 fields);
        } else if (!terminals.empty()) {
          OpsLog(store, "info", "catalog", "terminal_found",
                 "Đã lấy danh sách thiết bị chấm công từ server (khác IP/port cấu hình local)",
                 fields);
        } else {
          OpsLog(store, "warn", "catalog", "terminal_empty",
                 "Server trả về catalog thiết bị chấm công rỗng", fields);
        }
      }
    }
  };

  std::vector<TerminalTarget> terminals;
  refresh_catalog(terminals);
  bool heartbeat_up = false;

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
      heartbeat_up = true;
      std::fprintf(stderr, "[heartbeat] ok status=%ld lan_ip=%s terminal_ip=%s\n", hr.status,
                   hb.value("lan_ip", "").c_str(), tip.c_str());
    } else {
      std::fprintf(stderr, "[heartbeat] fail: %s %s\n", hr.error.c_str(),
                   hr.body.substr(0, 200).c_str());
      OpsLog(store, "warn", "heartbeat", "heartbeat_fail",
             "Heartbeat lên server thất bại",
             {{"detail", (hr.error + " " + hr.body.substr(0, 120)).substr(0, 160)}});
    }
  }

  ApplyDeviceBootstrap(cfg, store, http, cred);

  std::fprintf(stderr,
               "[gateway] start agent=%s version=%s base_url=%s discover=%d terminals=%zu "
               "attlog_sync=%s users_sync=%s live_listen=%d ingest_minimal=%d\n",
               cfg.agent_name.c_str(), cfg.agent_version.c_str(), cfg.base_url.c_str(),
               cfg.discover_terminals ? 1 : 0, terminals.size(), cfg.attlog_sync_times.c_str(),
               cfg.users_sync_times.c_str(), cfg.live_listen ? 1 : 0, cfg.ingest_minimal ? 1 : 0);
  OpsLog(store, "info", "gateway", "gateway_start",
         "Dịch vụ checkin-gateway đã khởi động",
         {{"agent_version", cfg.agent_version},
          {"base_url", cfg.base_url},
          {"terminals", terminals.size()},
          {"attlog_sync_times", cfg.attlog_sync_times},
          {"users_sync_times", cfg.users_sync_times},
          {"live_listen", cfg.live_listen}});
  FlushOpsLogs(cfg, store, http, cred);

  // One Enable per terminal per 15 minutes, and only on a session that is allowed to try.
  // Reconnects pass allow_enable false.
  std::map<std::string, bool> sensor_enable_spent;

  // Sync device wall-clock from gateway local time on every service start (DG-600 often
  // boots at 2000-01-01 after power loss).
  auto sync_terminal_clock = [&](const TerminalTarget& t) {
    std::string local_err;
    ZkDevice device;
    device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
    if (!device.Connect(t.ip, t.port, cfg.device_password, cfg.device_timeout_sec, local_err,
                        /*allow_sensor_enable=*/false)) {
      std::fprintf(stderr, "[time] connect fail %s: %s\n", t.ip.c_str(), local_err.c_str());
      OpsLog(store, "warn", "zk", "connect_fail",
             "Không kết nối được máy chấm công khi đồng bộ giờ",
             {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err},
              {"phase", "sync_time"}});
      return;
    }
    DeviceTime before;
    std::string before_s = "?";
    if (device.GetTime(before, local_err)) {
      before_s = before.iso_local;
    }
    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_r(&now, &local);
    if (!device.SetTime(local.tm_year + 1900, local.tm_mon + 1, local.tm_mday, local.tm_hour,
                        local.tm_min, local.tm_sec, local_err)) {
      std::fprintf(stderr, "[time] SET_TIME fail %s: %s (was %s)\n", t.ip.c_str(),
                   local_err.c_str(), before_s.c_str());
      OpsLog(store, "warn", "zk", "set_time_fail",
             "Kết nối được máy nhưng đồng bộ giờ thất bại",
             {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err},
              {"before", before_s}});
      device.Disconnect();
      return;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    DeviceTime after;
    std::string after_s = "?";
    if (device.GetTime(after, local_err)) after_s = after.iso_local;
    device.Disconnect();
    char server_buf[32];
    std::snprintf(server_buf, sizeof(server_buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                  local.tm_year + 1900, local.tm_mon + 1, local.tm_mday, local.tm_hour,
                  local.tm_min, local.tm_sec);
    std::fprintf(stderr, "[time] synced %s (%s) before=%s after=%s server=%s\n", t.ip.c_str(),
                 t.name.c_str(), before_s.c_str(), after_s.c_str(), server_buf);
    OpsLog(store, "info", "zk", "connect_ok",
           "Đã kết nối máy chấm công và đồng bộ giờ thành công",
           {{"ip", t.ip},
            {"port", t.port},
            {"name", t.name},
            {"before", before_s},
            {"after", after_s},
            {"gateway_time", server_buf},
            {"phase", "sync_time"}});
  };

  for (const auto& t : terminals) {
    if (!g_running) break;
    sync_terminal_clock(t);
  }

  int64_t last_catalog = UnixNow();
  int64_t last_prune = 0;
  int64_t last_heartbeat = UnixNow();
  int64_t last_bootstrap = UnixNow();
  // Live reconnects on its own timer: 1m, then 5m, then 15m. ATTLOG does not start a second loop.
  int live_backoff_step = 0;
  int64_t next_live_attempt = 0;
  bool live_catchup_armed = false;
  std::string last_sync_slot;
  std::string last_users_sync_slot;
  int attlog_backoff_step = 0;
  int64_t next_attlog_attempt = 0;
  std::vector<std::string> attlog_owed;
  {
    std::string meta_err;
    std::string raw_next;
    std::string raw_step;
    store.GetMeta("attlog_last_sync_slot", last_sync_slot, meta_err);
    store.GetMeta("users_last_sync_slot", last_users_sync_slot, meta_err);
    store.GetMeta("attlog_next_attempt", raw_next, meta_err);
    store.GetMeta("attlog_backoff_step", raw_step, meta_err);
    if (!raw_next.empty()) next_attlog_attempt = std::strtoll(raw_next.c_str(), nullptr, 10);
    if (!raw_step.empty()) attlog_backoff_step = std::atoi(raw_step.c_str());
  }
  // Every start reconciles from the last successful read. Live does not replay missed punches.
  bool attlog_catchup_pending = !terminals.empty();

  // Persistent RegEvent session on the primary terminal (realtime punches).
  // Do NOT ReadUsers/ATTLOG on this socket — bulk breaks RegEvent on DG-600 until reconnect.
  ZkDevice live_device;
  live_device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
  DeviceInfo live_info;
  std::string live_ip;
  int live_port = 0;
  bool live_ops_ok = false;
  int64_t last_live_fail_ops = 0;

  auto ensure_live = [&](bool allow_sensor_enable) -> bool {
    if (!cfg.live_listen) return false;
    if (terminals.empty()) {
      std::fprintf(stderr, "[zk] live listen: no terminals\n");
      return false;
    }
    const TerminalTarget& t = terminals[0];
    if (live_device.IsConnected() && live_ip == t.ip && live_port == t.port) return true;

    live_device.Disconnect();
    live_ip = t.ip;
    live_port = t.port;
    live_info = DeviceInfo{};
    live_info.ip = t.ip;
    live_info.port = t.port;

    std::string err;
    std::fprintf(stderr, "[zk] live connecting %s:%d (%s) enable=%d ...\n", t.ip.c_str(), t.port,
                 t.name.c_str(), allow_sensor_enable ? 1 : 0);
    auto log_live_fail = [&](const char* code, const std::string& msg) {
      const int64_t now = UnixNow();
      // State change or at most every 5 minutes while still down.
      if (live_ops_ok || now - last_live_fail_ops >= 300) {
        OpsLog(store, "warn", "zk", code, msg,
               {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", err},
                {"phase", "live_listen"}});
        last_live_fail_ops = now;
      }
      live_ops_ok = false;
    };
    bool enable_attempted = false;
    if (!live_device.Connect(t.ip, t.port, cfg.device_password, cfg.device_timeout_sec, err,
                             allow_sensor_enable, &enable_attempted)) {
      if (allow_sensor_enable && enable_attempted) NoteSensorEnable(store, sensor_enable_spent, t.ip);
      std::fprintf(stderr, "[zk] live connect failed: %s\n", err.c_str());
      log_live_fail("connect_fail", "Không kết nối được máy chấm công (lắng nghe realtime)");
      return false;
    }
    if (allow_sensor_enable) NoteSensorEnable(store, sensor_enable_spent, t.ip);
    live_device.ReadDeviceInfo(live_info, err);
    if (!live_device.StartLiveCapture(err)) {
      std::fprintf(stderr, "[zk] StartLiveCapture failed: %s\n", err.c_str());
      live_device.Disconnect();
      log_live_fail("live_capture_fail",
                    "Kết nối được máy nhưng không bật được lắng nghe realtime");
      return false;
    }
    std::fprintf(stderr, "[zk] live listen ON %s:%d serial=%s\n", t.ip.c_str(), t.port,
                 live_info.serial.c_str());
    if (!live_ops_ok) {
      OpsLog(store, "info", "zk", "connect_ok",
             "Đã kết nối máy chấm công và bật lắng nghe realtime",
             {{"ip", t.ip},
              {"port", t.port},
              {"name", t.name},
              {"serial", live_info.serial},
              {"phase", "live_listen"}});
    }
    live_ops_ok = true;
    return true;
  };

  auto sync_terminal_users = [&](const TerminalTarget& t) {
    std::string local_err;
    const std::string tid = t.id.empty() ? t.ip : t.id;
    std::fprintf(stderr, "[users] sync %s (%s) %s:%d\n", t.name.c_str(), t.id.c_str(), t.ip.c_str(),
                 t.port);

    std::vector<UserRecord> users;
    int user_count = -1;
    bool need_users = true;
    bool skipped_unchanged = false;
    {
      ZkDevice device;
      device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
      if (!device.Connect(t.ip, t.port, cfg.device_password, cfg.device_timeout_sec, local_err,
                          /*allow_sensor_enable=*/false)) {
        std::fprintf(stderr, "[users] connect fail %s: %s\n", t.ip.c_str(), local_err.c_str());
        OpsLog(store, "warn", "zk", "connect_fail",
               "Không kết nối được máy chấm công khi đồng bộ user id",
               {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err},
                {"phase", "users_sync"}});
        return;
      }

      DeviceInfo sizes_info;
      RawBlob sizes_raw;
      if (device.ReadFreeSizes(sizes_info, sizes_raw, local_err)) {
        user_count = sizes_info.user_count;
        if (!UsersCatalogDue(store, tid, user_count)) {
          need_users = false;
          skipped_unchanged = true;
          std::fprintf(stderr, "[users] %s skip ReadUsers (already read today, count=%d)\n",
                       t.ip.c_str(), user_count);
        }
      }

      if (need_users) {
        if (!device.ReadUsers(users, local_err)) {
          std::fprintf(stderr, "[users] ReadUsers %s: %s\n", t.ip.c_str(), local_err.c_str());
          users.clear();
          OpsLog(store, "warn", "users", "users_read_fail",
                 "Đọc danh sách user id từ máy chấm công thất bại",
                 {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err}});
        } else if (user_count < 0) {
          user_count = static_cast<int>(users.size());
        }
      }
      device.Disconnect();
    }

    if (!users.empty() && UserCatalogComplete(user_count, users)) {
      std::string meta_err;
      if (SyncMachineUsersCatalog(cfg, store, http, cred, t.id, t.ip, users)) {
        store.SetMeta("users_count:" + tid, std::to_string(users.size()), meta_err);
        store.SetMeta("users_read_on:" + tid, LocalYmd(0), meta_err);
      }
    } else if (!users.empty()) {
      std::fprintf(stderr, "[users] %s incomplete catalog read=%zu device_count=%d (not uploaded)\n",
                   t.ip.c_str(), users.size(), user_count);
      OpsLog(store, "warn", "users", "users_incomplete",
             "Đọc danh sách nhân viên không đủ so với máy — không ghi đè catalog",
             {{"ip", t.ip}, {"read", users.size()}, {"device_count", user_count}});
    } else if (!skipped_unchanged) {
      OpsLog(store, "warn", "users", "users_empty",
             "Không có user id đọc được từ máy để đồng bộ",
             {{"ip", t.ip}, {"port", t.port}, {"name", t.name}});
    }
  };

  auto sync_terminal_attlog = [&](const TerminalTarget& t, bool also_users) -> bool {
    DeviceInfo info;
    info.ip = t.ip;
    info.port = t.port;
    std::string local_err;
    const std::string tid = t.id.empty() ? t.ip : t.id;
    std::fprintf(stderr, "[attlog] sync %s (%s) %s:%d from=%s users=%d\n", t.name.c_str(),
                 t.id.c_str(), t.ip.c_str(), t.port,
                 "last-success",
                 also_users ? 1 : 0);
    OpsLog(store, "info", "attlog", "attlog_start",
           "Bắt đầu đồng bộ nhật ký chấm công (ATTLOG) từ máy",
           {{"ip", t.ip},
            {"port", t.port},
            {"name", t.name},
            {"also_users", also_users},
            {"usage_started_on", t.usage_started_on}});

    // One TCP session for reads only — disconnect ASAP. No RecoverDevice/Enable after bulk
    // (that path froze the DG-600 panel when Enable timed out).
    std::vector<AttendanceEvent> logs;
    std::vector<UserRecord> users;
    bool users_pulled = false;
    bool attlog_read_ok = false;
    size_t attlog_bytes = 0;
    int user_count = -1;
    int64_t read_started = 0;

    {
      ZkDevice device;
      device.SetTzOffsetMinutes(cfg.device_tz_offset_min);
      if (!device.Connect(t.ip, t.port, cfg.device_password, cfg.device_timeout_sec, local_err,
                          /*allow_sensor_enable=*/false)) {
        std::fprintf(stderr, "[attlog] connect fail %s: %s\n", t.ip.c_str(), local_err.c_str());
        OpsLog(store, "warn", "zk", "connect_fail",
               "Không kết nối được máy chấm công khi đồng bộ ATTLOG",
               {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err},
                {"phase", "attlog_sync"}});
      } else {
        if (!device.ConnectWarning().empty()) {
          OpsLog(store, "warn", "zk", "sensor_state_skipped",
                 "Không đọc được trạng thái cảm biến. Vẫn đọc ATTLOG",
                 {{"ip", t.ip}, {"port", t.port}, {"detail", device.ConnectWarning()}});
        }
        device.ReadDeviceInfo(info, local_err);

        read_started = UnixNow();
        if (!device.ReadAttendanceLogs(logs, local_err)) {
          std::fprintf(stderr, "[attlog] ReadAttendanceLogs %s: %s\n", t.ip.c_str(),
                       local_err.c_str());
          logs.clear();
          OpsLog(store, "warn", "attlog", "attlog_read_fail",
                 "Đọc nhật ký chấm công từ máy thất bại",
                 {{"ip", t.ip}, {"port", t.port}, {"name", t.name}, {"detail", local_err}});
        } else {
          attlog_read_ok = true;
          attlog_bytes = device.LastAttlogBytes();
        }

        if (also_users) {
          bool need_users = true;
          DeviceInfo sizes_info;
          RawBlob sizes_raw;
          if (device.ReadFreeSizes(sizes_info, sizes_raw, local_err)) {
            user_count = sizes_info.user_count;
            if (!UsersCatalogDue(store, tid, user_count)) {
              need_users = false;
              std::fprintf(stderr, "[users] %s skip ReadUsers (already read today, count=%d)\n",
                           t.ip.c_str(), user_count);
            }
          }

          if (need_users) {
            if (!device.ReadUsers(users, local_err)) {
              std::fprintf(stderr, "[users] ReadUsers %s: %s\n", t.ip.c_str(), local_err.c_str());
              users.clear();
            } else {
              users_pulled = true;
              if (user_count < 0) user_count = static_cast<int>(users.size());
            }
          }
        }

        device.Disconnect();
      }
    }

    if (users_pulled && UserCatalogComplete(user_count, users)) {
      std::string meta_err;
      if (SyncMachineUsersCatalog(cfg, store, http, cred, t.id, t.ip, users)) {
        store.SetMeta("users_count:" + tid, std::to_string(users.size()), meta_err);
        store.SetMeta("users_read_on:" + tid, LocalYmd(0), meta_err);
      }
    } else if (users_pulled) {
      std::fprintf(stderr, "[users] %s incomplete catalog read=%zu device_count=%d (not uploaded)\n",
                   t.ip.c_str(), users.size(), user_count);
      OpsLog(store, "warn", "users", "users_incomplete",
             "Đọc danh sách nhân viên không đủ so với máy — không ghi đè catalog",
             {{"ip", t.ip}, {"read", users.size()}, {"device_count", user_count}});
    }

    if (attlog_read_ok && logs.empty() && info.log_count > 0 && attlog_bytes == 0) {
      attlog_read_ok = false;
      std::fprintf(stderr, "[attlog] %s empty read but device log_count=%d (fingerprint kept)\n",
                   t.ip.c_str(), info.log_count);
      OpsLog(store, "warn", "attlog", "attlog_incomplete",
             "Đọc ATTLOG rỗng trong khi máy vẫn còn nhật ký — không ghi đè fingerprint",
             {{"ip", t.ip}, {"port", t.port}, {"log_count", info.log_count}});
    } else if (attlog_read_ok && logs.empty() && attlog_bytes > 0) {
      // The table arrived. Rows were not valid punches. Pulling it again and opening a
      // second session is what took this DG-600 off the LAN.
      std::fprintf(stderr,
                   "[attlog] %s table=%zu bytes has no valid punches (log_count=%d) — not retrying\n",
                   t.ip.c_str(), attlog_bytes, info.log_count);
      OpsLog(store, "warn", "attlog", "attlog_no_valid_punches",
             "Đã đọc hết nhật ký nhưng không có dòng chấm công hợp lệ — không đọc lại ngay",
             {{"ip", t.ip}, {"port", t.port}, {"bytes", attlog_bytes}, {"log_count", info.log_count}});
    }
    if (!attlog_read_ok) return false;

    // Next read overlaps the transfer. The saved mark is 5 minutes before this read started.
    constexpr int64_t kAttlogOverlapSec = 5 * 60;
    std::string wm_raw;
    std::string meta_wm;
    store.GetMeta("attlog_ok_at:" + tid, wm_raw, meta_wm);
    const int64_t watermark = wm_raw.empty() ? 0 : std::strtoll(wm_raw.c_str(), nullptr, 10);
    // No mark yet: do not upload the whole device log. Floor is the later of
    // usage_started_on and the last 3 local days.
    std::string first_floor;
    if (watermark <= 0) {
      first_floor = LocalYmd(-2);
      if (!t.usage_started_on.empty() && t.usage_started_on > first_floor) {
        first_floor = t.usage_started_on;
      }
    }
    auto mark_watermark = [&]() {
      if (read_started <= kAttlogOverlapSec) return;
      std::string e;
      store.SetMeta("attlog_ok_at:" + tid, std::to_string(read_started - kAttlogOverlapSec), e);
    };

    std::vector<AttendanceEvent> filtered;
    filtered.reserve(logs.size());
    for (auto& ev : logs) {
      if (!PunchYearOk(ev, cfg.punch_min_year)) continue;
      if (watermark > 0) {
        if (!PunchAtOrAfterUnix(ev, watermark)) continue;
      } else if (!PunchOnOrAfter(ev, first_floor)) {
        continue;
      }
      filtered.push_back(std::move(ev));
    }
    OpsLog(store, "info", "attlog", "attlog_window",
           watermark > 0 ? "Đối soát ATTLOG từ lần đọc thành công trước"
                         : "Đối soát ATTLOG lần đầu trong cửa sổ gần đây",
           {{"ip", t.ip},
            {"watermark", watermark},
            {"first_floor", first_floor},
            {"usage_started_on", t.usage_started_on},
            {"raw", logs.size()},
            {"kept", filtered.size()}});

    std::string fp = FingerprintEvents(filtered);
    std::string fp_key = "attlog_fp:" + tid;
    std::string prev_fp;
    std::string meta_err;
    store.GetMeta(fp_key, prev_fp, meta_err);
    if (!prev_fp.empty() && prev_fp == fp) {
      bool missing = false;
      for (const auto& ev : filtered) {
        if (!store.SeenDedupe(DedupeKey(ev))) {
          missing = true;
          break;
        }
      }
      if (!missing) {
        std::fprintf(stderr, "[attlog] %s unchanged fp=%s (skip ingest)\n", t.ip.c_str(), fp.c_str());
        OpsLog(store, "info", "attlog", "attlog_unchanged",
               "Nhật ký chấm công không đổi — bỏ qua gửi lên server",
               {{"ip", t.ip}, {"port", t.port}, {"raw", logs.size()}, {"filtered", filtered.size()},
                {"fp", fp}});
        mark_watermark();
        return true;
      }
      std::fprintf(stderr, "[attlog] %s fp unchanged but some punches are not ingested yet\n",
                   t.ip.c_str());
    }

    int enq = 0;
    int already = 0;
    bool enqueue_failed = false;
    for (auto& ev : filtered) {
      ev.from_live = false;
      if (store.SeenDedupe(DedupeKey(ev))) {
        ++already;
        continue;
      }
      if (!EnqueuePunch(store, cfg, info, ev)) enqueue_failed = true;
      else ++enq;
    }
    if (!enqueue_failed) store.SetMeta(fp_key, fp, meta_err);
    std::fprintf(stderr, "[attlog] %s filtered=%zu/%zu enqueued=%d already=%d fp=%s\n",
                 t.ip.c_str(), filtered.size(), logs.size(), enq, already, fp.c_str());
    OpsLog(store, "info", "attlog", "attlog_enqueued",
           "Đã đưa nhật ký chấm công vào hàng đợi gửi lên server",
           {{"ip", t.ip},
            {"port", t.port},
            {"name", t.name},
            {"raw", logs.size()},
            {"filtered", filtered.size()},
            {"enqueued", enq},
            {"already_seen", already},
            {"fp", fp}});

    std::fprintf(stderr, "[attlog] %s kept device ATTLOG after enqueue=%d\n", t.ip.c_str(), enq);
    OpsLog(store, "info", "attlog", "attlog_kept",
           "Giữ nguyên nhật ký chấm công trên máy sau khi đưa vào hàng đợi",
           {{"ip", t.ip}, {"enqueued", enq}});
    if (!enqueue_failed) mark_watermark();
    return !enqueue_failed;
  };

  std::thread ingest_worker([&] {
    HttpClient ingest_http(cfg.http_timeout_sec);
    while (g_ingest_run) {
      FlushOutbox(cfg, store, ingest_http, cred, 5);
      FlushOpsLogs(cfg, store, ingest_http, cred);
      for (int i = 0; i < 10 && g_ingest_run; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
      }
    }
    FlushOutbox(cfg, store, ingest_http, cred, 1);
    FlushOpsLogs(cfg, store, ingest_http, cred);
  });

  while (g_running) {
    int64_t now = UnixNow();
    if (now - last_bootstrap >= std::max(60, cfg.bootstrap_refresh_sec)) {
      last_bootstrap = now;
      ApplyDeviceBootstrap(cfg, store, http, cred);
    }
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
        OpsLog(store, "warn", "heartbeat", "heartbeat_fail",
               "Heartbeat định kỳ lên server thất bại",
               {{"detail", hr.error}, {"terminal_ip", tip}, {"terminal_port", tport}});
        heartbeat_up = false;
      } else if (!heartbeat_up) {
        heartbeat_up = true;
        OpsLog(store, "info", "heartbeat", "heartbeat_ok",
               "Heartbeat lên server thành công sau lỗi",
               {{"terminal_ip", tip}, {"terminal_port", tport}, {"http_status", hr.status}});
      }
    }

    std::string slot = LatestPassedSyncSlot(cfg.attlog_sync_times);
    std::string users_slot = CurrentAttlogSyncSlot(cfg.users_sync_times);
    const bool slot_due = !slot.empty() && slot != last_sync_slot && !terminals.empty();
    const bool attlog_due =
        (slot_due || attlog_catchup_pending) && !terminals.empty() && now >= next_attlog_attempt;
    const bool users_due =
        !users_slot.empty() && users_slot != last_users_sync_slot && !terminals.empty() && !attlog_due;
    // Same HH:MM window: one TCP session does ATTLOG + users (avoids double disconnect on DG-600).
    const bool users_with_attlog = attlog_due && !users_slot.empty() && users_slot == slot &&
                                   users_slot != last_users_sync_slot;

    auto arm_live_backoff = [&](const char* detail) {
      live_device.Disconnect();
      const int64_t wait = BackoffDelaySec(live_backoff_step);
      if (live_backoff_step < 2) ++live_backoff_step;
      next_live_attempt = UnixNow() + wait;
      live_ops_ok = false;
      std::fprintf(stderr, "[zk] live down — reconnect in %llds (%s)\n", static_cast<long long>(wait),
                   detail);
      OpsLog(store, "warn", "zk", "live_backoff",
             "Mất kết nối realtime. Sẽ nối lại sau thời gian chờ",
             {{"ip", live_ip},
              {"port", live_port},
              {"wait_sec", wait},
              {"detail", detail}});
      if (!live_catchup_armed) {
        live_catchup_armed = true;
        attlog_catchup_pending = true;
        if (next_attlog_attempt > UnixNow()) {
          // An ATTLOG failure is already waiting. Do not open a second device session.
        } else {
          next_attlog_attempt = UnixNow();
        }
      }
    };

    if (attlog_due) {
      const bool live_was_up = live_device.IsConnected();
      live_device.Disconnect();
      std::fprintf(stderr, "[attlog] sync slot=%s catchup=%d terminals=%zu users=%d owed=%zu\n",
                   slot.c_str(), attlog_catchup_pending ? 1 : 0, terminals.size(),
                   users_with_attlog ? 1 : 0, attlog_owed.size());
      OpsLog(store, "info", "attlog", "attlog_slot",
             "Đọc ATTLOG hôm qua và hôm nay",
             {{"slot", slot},
              {"terminals", terminals.size()},
              {"catchup", attlog_catchup_pending},
              {"with_users", users_with_attlog}});
      std::vector<std::string> failed;
      int attempted = 0;
      for (const auto& t : terminals) {
        if (!g_running) break;
        const std::string tid = t.id.empty() ? t.ip : t.id;
        if (!attlog_owed.empty() &&
            std::find(attlog_owed.begin(), attlog_owed.end(), tid) == attlog_owed.end()) {
          continue;
        }
        ++attempted;
        if (!sync_terminal_attlog(t, /*also_users=*/users_with_attlog)) failed.push_back(tid);
      }
      std::string meta_err;
      if (attempted == 0) {
        attlog_owed.clear();
      } else if (failed.empty() && g_running) {
        attlog_owed.clear();
        attlog_backoff_step = 0;
        next_attlog_attempt = 0;
        attlog_catchup_pending = false;
        store.SetMeta("attlog_next_attempt", "0", meta_err);
        store.SetMeta("attlog_backoff_step", "0", meta_err);
        if (!slot.empty()) {
          last_sync_slot = slot;
          store.SetMeta("attlog_last_sync_slot", last_sync_slot, meta_err);
        }
        if (users_with_attlog) {
          last_users_sync_slot = users_slot;
          store.SetMeta("users_last_sync_slot", last_users_sync_slot, meta_err);
        }
      } else if (!failed.empty()) {
        attlog_owed = std::move(failed);
        attlog_catchup_pending = true;
        const int64_t wait = BackoffDelaySec(attlog_backoff_step);
        if (attlog_backoff_step < 2) ++attlog_backoff_step;
        next_attlog_attempt = UnixNow() + wait;
        store.SetMeta("attlog_next_attempt", std::to_string(next_attlog_attempt), meta_err);
        store.SetMeta("attlog_backoff_step", std::to_string(attlog_backoff_step), meta_err);
        std::fprintf(stderr, "[attlog] %zu terminal(s) failed — retry in %llds, slot not marked\n",
                     attlog_owed.size(), static_cast<long long>(wait));
        OpsLog(store, "warn", "attlog", "attlog_retry",
               "Đọc ATTLOG chưa xong. Khung giờ chưa được đánh dấu",
               {{"failed", attlog_owed.size()}, {"wait_sec", wait}, {"slot", slot}});
      }
      // A second TCP session in the same second as ATTLOG made this DG-600 stop answering,
      // then drop off the LAN. Leave the device alone before live listen.
      if (live_was_up) next_live_attempt = UnixNow() + 180;
    } else if (users_due) {
      const bool live_was_up = live_device.IsConnected();
      live_device.Disconnect();
      std::fprintf(stderr, "[users] scheduled sync slot=%s terminals=%zu\n", users_slot.c_str(),
                   terminals.size());
      OpsLog(store, "info", "users", "users_slot",
             "Tới khung giờ đồng bộ user id",
             {{"slot", users_slot}, {"terminals", terminals.size()}});
      for (const auto& t : terminals) {
        if (!g_running) break;
        sync_terminal_users(t);
      }
      last_users_sync_slot = users_slot;
      std::string meta_err;
      store.SetMeta("users_last_sync_slot", last_users_sync_slot, meta_err);
      if (live_was_up) next_live_attempt = UnixNow() + 180;
    }

    now = UnixNow();
    if (now - last_prune > 3600) {
      last_prune = now;
      MaybePrune(store, cfg);
    }

    if (cfg.live_listen && !terminals.empty()) {
      const TerminalTarget& primary = terminals[0];
      if (live_device.IsConnected() && (live_ip != primary.ip || live_port != primary.port)) {
        live_device.Disconnect();
        live_backoff_step = 0;
        next_live_attempt = UnixNow();
        live_catchup_armed = false;
      }
      if (!live_device.IsConnected() && now >= next_live_attempt) {
        const bool allow_enable = SensorEnableAllowed(store, sensor_enable_spent, primary.ip);
        if (!ensure_live(allow_enable)) {
          arm_live_backoff("connect");
        } else {
          live_backoff_step = 0;
          next_live_attempt = 0;
          live_catchup_armed = false;
        }
      } else if (live_device.IsConnected()) {
        std::string live_err;
        const bool ok = live_device.PollLive(
            [&](const AttendanceEvent& ev) { EnqueuePunch(store, cfg, live_info, ev); }, 500,
            live_err);
        if (!ok) arm_live_backoff(live_err.c_str());
      }
    }

    FlushCaptureArchives(cfg, http, cred);
    if (!live_device.IsConnected()) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  }

  live_device.Disconnect();
  OpsLog(store, "info", "gateway", "gateway_stop", "Dịch vụ checkin-gateway đang dừng", {});
  g_ingest_run = false;
  if (ingest_worker.joinable()) ingest_worker.join();
  FlushCaptureArchives(cfg, http, cred, true);
  std::fprintf(stderr, "[gateway] stopped\n");
  return 0;
}

}  // namespace cg
