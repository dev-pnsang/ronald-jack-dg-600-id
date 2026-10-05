#include "capture.hpp"

#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>

#include <nlohmann/json.hpp>

#include "util.hpp"

namespace cg {
namespace {

constexpr int64_t kUploadIntervalSec = 60;
constexpr int64_t kDeleteAfterUploadSec = 7 * 24 * 3600;
constexpr int64_t kMaxUploadBytes = 32 * 1024 * 1024;

std::string g_dir;
int64_t g_last_flush = 0;

std::string LocalDay() {
  std::time_t t = std::time(nullptr);
  std::tm tm{};
  localtime_r(&t, &tm);
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
  return buf;
}

std::string Base64(const uint8_t* data, size_t n) {
  static const char* table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string out;
  out.reserve(((n + 2) / 3) * 4);
  for (size_t i = 0; i < n; i += 3) {
    unsigned v = static_cast<unsigned>(data[i]) << 16;
    if (i + 1 < n) v |= static_cast<unsigned>(data[i + 1]) << 8;
    if (i + 2 < n) v |= static_cast<unsigned>(data[i + 2]);
    out.push_back(table[(v >> 18) & 63]);
    out.push_back(table[(v >> 12) & 63]);
    out.push_back(i + 1 < n ? table[(v >> 6) & 63] : '=');
    out.push_back(i + 2 < n ? table[v & 63] : '=');
  }
  return out;
}

std::string OneLine(std::string s) {
  for (char& c : s) {
    if (c == '\n' || c == '\r' || c == '\t') c = ' ';
  }
  return s;
}

bool AppendLine(const std::string& path, const std::string& line) {
  std::ofstream out(path, std::ios::app);
  if (!out) return false;
  out << line << '\n';
  return static_cast<bool>(out);
}

struct UploadMark {
  int64_t at = 0;
  int64_t size = 0;
};

std::string StatePath() { return g_dir + "/upload-state.json"; }

std::map<std::string, UploadMark> LoadMarks() {
  std::map<std::string, UploadMark> marks;
  std::ifstream in(StatePath());
  if (!in) return marks;
  std::stringstream buf;
  buf << in.rdbuf();
  try {
    auto j = nlohmann::json::parse(buf.str());
    for (auto it = j.begin(); it != j.end(); ++it) {
      UploadMark m;
      m.at = it.value().value("at", static_cast<int64_t>(0));
      m.size = it.value().value("size", static_cast<int64_t>(0));
      marks[it.key()] = m;
    }
  } catch (...) {
  }
  return marks;
}

void SaveMarks(const std::map<std::string, UploadMark>& marks) {
  nlohmann::json j = nlohmann::json::object();
  for (const auto& kv : marks) {
    j[kv.first] = {{"at", kv.second.at}, {"size", kv.second.size}};
  }
  std::ofstream out(StatePath(), std::ios::trunc);
  if (out) out << j.dump();
}

bool ParseArchiveName(const std::string& name, std::string& kind, std::string& day) {
  int y = 0, m = 0, d = 0;
  if (std::sscanf(name.c_str(), "ops-%d-%d-%d.log", &y, &m, &d) == 3) {
    kind = "ops";
  } else if (std::sscanf(name.c_str(), "raw-%d-%d-%d.jsonl", &y, &m, &d) == 3) {
    kind = "raw";
  } else {
    return false;
  }
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", y, m, d);
  if (name != (kind + "-" + buf + (kind == "ops" ? ".log" : ".jsonl"))) return false;
  day = buf;
  return true;
}

std::string ReadFile(const std::string& path, int64_t size) {
  std::ifstream in(path, std::ios::binary);
  std::string body(static_cast<size_t>(size), '\0');
  if (size > 0) in.read(body.data(), size);
  if (!in) return {};
  return body;
}

}  // namespace

void SetCaptureDir(const std::string& data_dir) {
  g_dir = data_dir + "/capture";
  std::string err;
  if (!EnsureDir(g_dir, err)) {
    std::fprintf(stderr, "[capture] %s\n", err.c_str());
    g_dir.clear();
    return;
  }
  ::chmod(g_dir.c_str(), 0700);
}

void AppendOpsCapture(const std::string& level, const std::string& component, const std::string& code,
                      const std::string& message, const std::string& fields_json) {
  if (g_dir.empty()) return;
  std::string line = UtcNowIso8601() + "\t" + OneLine(level) + "\t" + OneLine(component) + "\t" +
                     OneLine(code) + "\t" + OneLine(message) + "\t" + OneLine(fields_json);
  if (!AppendLine(g_dir + "/ops-" + LocalDay() + ".log", line)) {
    std::fprintf(stderr, "[capture] append ops failed\n");
  }
}

void AppendRawCapture(const std::string& label, const std::vector<uint8_t>& bytes) {
  if (g_dir.empty() || bytes.empty()) return;
  nlohmann::json row = {
      {"ts", UtcNowIso8601()},
      {"label", label},
      {"bytes", bytes.size()},
      {"body_b64", Base64(bytes.data(), bytes.size())},
  };
  if (!AppendLine(g_dir + "/raw-" + LocalDay() + ".jsonl", row.dump())) {
    std::fprintf(stderr, "[capture] append raw failed\n");
  }
}

void FlushCaptureArchives(const Config& cfg, const HttpClient& http, const Credential& cred, bool force) {
  if (g_dir.empty()) return;
  int64_t now = UnixNow();
  if (!force && g_last_flush != 0 && now - g_last_flush < kUploadIntervalSec) return;
  g_last_flush = now;

  DIR* dir = ::opendir(g_dir.c_str());
  if (!dir) return;
  auto marks = LoadMarks();
  bool dirty = false;
  while (dirent* ent = ::readdir(dir)) {
    std::string name = ent->d_name;
    std::string kind, day;
    if (!ParseArchiveName(name, kind, day)) continue;
    std::string path = g_dir + "/" + name;
    struct stat st{};
    if (::stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) continue;
    int64_t size = static_cast<int64_t>(st.st_size);
    if (size <= 0) continue;
    auto found = marks.find(name);
    if (found != marks.end() && found->second.size == size && found->second.at > 0) {
      if (now - found->second.at >= kDeleteAfterUploadSec) {
        if (::unlink(path.c_str()) == 0) {
          std::fprintf(stderr, "[capture] deleted %s after upload age 7d\n", name.c_str());
          marks.erase(found);
          dirty = true;
        }
      }
      continue;
    }
    if (size > kMaxUploadBytes) {
      std::fprintf(stderr, "[capture] skip upload %s size=%lld over 32MB\n", name.c_str(),
                   static_cast<long long>(size));
      continue;
    }
    std::string body = ReadFile(path, size);
    if (static_cast<int64_t>(body.size()) != size) continue;
    std::string ctype = kind == "raw" ? "application/x-ndjson" : "text/plain";
    std::string req = "/device-ops/log-files?log_date=" + day + "&file_name=" + name + "&kind=" + kind;
    auto r = SignedRequest(cfg, http, cred, "POST", req, body, ctype);
    if (!r.ok) {
      std::fprintf(stderr, "[capture] upload fail %s: %s %s\n", name.c_str(), r.error.c_str(),
                   r.body.substr(0, 160).c_str());
      continue;
    }
    marks[name] = UploadMark{now, size};
    dirty = true;
    std::fprintf(stderr, "[capture] uploaded %s kind=%s bytes=%lld\n", name.c_str(), kind.c_str(),
                 static_cast<long long>(size));
  }
  ::closedir(dir);
  if (dirty) SaveMarks(marks);
}

}  // namespace cg
