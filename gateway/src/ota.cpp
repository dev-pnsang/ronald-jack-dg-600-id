#include "ota.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <sstream>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <sys/stat.h>

#include "util.hpp"

namespace cg {
namespace {

std::atomic<bool> g_ota_running{true};

// Production layout — never touch checkin-ota while installing gateway.
constexpr const char* kGatewayBin = "/usr/bin/checkin-gateway";
constexpr const char* kOtaBin = "/usr/bin/checkin-ota";
constexpr const char* kGatewayService = "checkin-gateway";
constexpr const char* kOtaService = "checkin-ota";

std::string ShellQuote(const std::string& s) {
  std::string out = "'";
  for (char c : s) {
    if (c == '\'')
      out += "'\\''";
    else
      out.push_back(c);
  }
  out.push_back('\'');
  return out;
}

std::string Sha256File(const std::string& path, std::string& err) {
  std::ifstream in(path, std::ios::binary);
  if (!in) {
    err = "cannot open " + path;
    return "";
  }
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  char buf[8192];
  while (in) {
    in.read(buf, sizeof(buf));
    std::streamsize n = in.gcount();
    if (n > 0) SHA256_Update(&ctx, buf, static_cast<size_t>(n));
  }
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_Final(hash, &ctx);
  static const char* hex = "0123456789abcdef";
  std::string out(64, '0');
  for (int i = 0; i < 32; ++i) {
    out[i * 2] = hex[(hash[i] >> 4) & 0xF];
    out[i * 2 + 1] = hex[hash[i] & 0xF];
  }
  return out;
}

bool DownloadUrl(const std::string& url, const std::string& dest, int timeout_sec, std::string& err) {
  std::string cmd = "curl -fsSL --max-time " + std::to_string(std::max(30, timeout_sec)) +
                    " --max-filesize 67108864 -o " + ShellQuote(dest) + " " + ShellQuote(url);
  int rc = std::system(cmd.c_str());
  if (rc != 0) {
    err = "download failed rc=" + std::to_string(rc);
    return false;
  }
  struct stat st {};
  if (::stat(dest.c_str(), &st) != 0 || st.st_size <= 0) {
    err = "download empty";
    return false;
  }
  if (st.st_size > 64LL * 1024 * 1024) {
    err = "download exceeds 64MB";
    return false;
  }
  return true;
}

std::vector<std::pair<int, int>> ParseHHMMList(const std::string& csv) {
  std::vector<std::pair<int, int>> out;
  std::stringstream ss(csv);
  std::string part;
  while (std::getline(ss, part, ',')) {
    int h = -1, m = -1;
    if (std::sscanf(part.c_str(), "%d:%d", &h, &m) == 2 && h >= 0 && h <= 23 && m >= 0 && m <= 59) {
      out.emplace_back(h, m);
    }
  }
  if (out.empty()) {
    out.emplace_back(3, 30);
    out.emplace_back(15, 30);
  }
  return out;
}

bool CurrentOtaSlot(const std::vector<std::pair<int, int>>& slots, std::string& slot) {
  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_r(&now, &local);
  for (const auto& hm : slots) {
    if (local.tm_hour == hm.first && local.tm_min >= hm.second && local.tm_min <= hm.second + 1) {
      char buf[16];
      std::snprintf(buf, sizeof(buf), "%02d:%02d", hm.first, hm.second);
      slot = buf;
      return true;
    }
  }
  slot.clear();
  return false;
}

enum class ArtifactFormat { GzipTar, Deb, Unknown };

ArtifactFormat DetectArtifactFormat(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return ArtifactFormat::Unknown;
  unsigned char mag[8] = {};
  in.read(reinterpret_cast<char*>(mag), 8);
  const auto n = in.gcount();
  if (n >= 2 && mag[0] == 0x1f && mag[1] == 0x8b) return ArtifactFormat::GzipTar;
  if (n >= 8 && mag[0] == '!' && mag[1] == '<' && mag[2] == 'a' && mag[3] == 'r' &&
      mag[4] == 'c' && mag[5] == 'h' && mag[6] == '>' && mag[7] == '\n') {
    return ArtifactFormat::Deb;
  }
  return ArtifactFormat::Unknown;
}

bool RestartGatewayOnly(std::string& err) {
  // Never restart checkin-ota from inside an OTA install cycle.
  std::string cmd = std::string("systemctl restart ") + kGatewayService +
                    " || systemctl start " + kGatewayService;
  if (std::system(cmd.c_str()) != 0) {
    err = "service_start_failed";
    return false;
  }
  return true;
}

bool InstallDeb(const std::string& deb_path, std::string& err) {
  // Unattended OTA: never prompt on TTY. Keep local conf (base_url, device_ip, …).
  std::string cmd =
      "DEBIAN_FRONTEND=noninteractive dpkg --force-confdef --force-confold -i " +
      ShellQuote(deb_path) +
      " || DEBIAN_FRONTEND=noninteractive apt-get -y "
      "-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold -f install";
  if (std::system(cmd.c_str()) != 0) {
    err = "dpkg install failed";
    return false;
  }
  // Package postinst may enable units; ensure gateway is up without killing OTA.
  return RestartGatewayOnly(err);
}

bool AtomicInstallBinary(const std::string& src, const std::string& dest, std::string& err) {
  std::string tmp = std::string(dest) + ".new";
  if (std::system(("install -m 0755 " + ShellQuote(src) + " " + ShellQuote(tmp)).c_str()) != 0) {
    err = "install binary failed: " + dest;
    return false;
  }
  if (std::rename(tmp.c_str(), dest.c_str()) != 0) {
    err = "atomic replace failed: " + dest;
    return false;
  }
  return true;
}

bool InstallTarGz(const std::string& archive, std::string& err, bool* ota_updated) {
  if (ota_updated) *ota_updated = false;
  std::string work = "/var/tmp/checkin-ota/extract";
  std::system(("rm -rf " + work + " && mkdir -p " + work).c_str());
  std::string untar = "tar -xzf " + ShellQuote(archive) + " -C " + ShellQuote(work);
  if (std::system(untar.c_str()) != 0) {
    err = "tar extract failed";
    return false;
  }
  std::string install_sh = work + "/install.sh";
  struct stat st {};
  if (::stat(install_sh.c_str(), &st) == 0) {
    std::string cmd = "chmod +x " + ShellQuote(install_sh) + " && " + ShellQuote(install_sh) + " " +
                      ShellQuote(kGatewayBin) + " " + ShellQuote(kGatewayService);
    if (std::system(cmd.c_str()) != 0) {
      err = "install.sh failed";
      return false;
    }
    return true;
  }
  std::string bin = work + "/checkin-gateway";
  if (::stat(bin.c_str(), &st) != 0) {
    err = "artifact missing checkin-gateway binary";
    return false;
  }
  std::system((std::string("systemctl stop ") + kGatewayService + " || true").c_str());
  if (!AtomicInstallBinary(bin, kGatewayBin, err)) return false;

  std::string ota_src = work + "/checkin-ota";
  if (::stat(ota_src.c_str(), &st) == 0) {
    // Replace OTA binary under our feet (inode stays until we exit); restart after report.
    if (!AtomicInstallBinary(ota_src, kOtaBin, err)) return false;
    if (ota_updated) *ota_updated = true;
  }

  return RestartGatewayOnly(err);
}

bool InstallArtifact(const std::string& archive, std::string& err, bool* ota_updated) {
  const ArtifactFormat fmt = DetectArtifactFormat(archive);
  if (fmt == ArtifactFormat::GzipTar) {
    std::fprintf(stderr, "[ota] artifact format=tar.gz path=%s\n", kGatewayBin);
    return InstallTarGz(archive, err, ota_updated);
  }
  if (fmt == ArtifactFormat::Deb) {
    std::fprintf(stderr, "[ota] artifact format=deb\n");
    return InstallDeb(archive, err);
  }
  err =
      "unsupported artifact (need .tar.gz or .deb; got raw binary/html/other — check download URL)";
  return false;
}

void ApplyBootstrapOtaTimes(Config& cfg, Store& store, HttpClient& http, Credential& cred) {
  (void)cfg;
  std::string err;
  auto r = SignedRequest(cfg, http, cred, "GET", "/device-identity/bootstrap", "");
  if (!r.ok) {
    std::fprintf(stderr, "[ota] bootstrap fail: %s\n", r.error.c_str());
    return;
  }
  try {
    auto j = nlohmann::json::parse(r.body);
    auto d = j.at("data");
    if (d.contains("ota_check_times") && d["ota_check_times"].is_array()) {
      std::string csv;
      for (const auto& t : d["ota_check_times"]) {
        if (!t.is_string()) continue;
        if (!csv.empty()) csv += ",";
        csv += t.get<std::string>();
      }
      if (!csv.empty()) {
        store.SetMeta("ota_check_times", csv, err);
        std::fprintf(stderr, "[ota] bootstrap ota_check_times=%s\n", csv.c_str());
      }
    }
  } catch (const std::exception& ex) {
    std::fprintf(stderr, "[ota] bootstrap parse: %s\n", ex.what());
  }
}

bool RunOneCycle(Config& cfg, Store& store, HttpClient& http, Credential& cred) {
  std::string err;
  OtaCheckInfo info;
  if (!OtaCheck(cfg, http, cred, info, err)) {
    std::fprintf(stderr, "[ota] check fail: %s\n", err.c_str());
    return false;
  }
  if (!info.update) {
    std::fprintf(stderr, "[ota] no update\n");
    return true;
  }
  std::fprintf(stderr, "[ota] update job=%s version=%s\n", info.job_id.c_str(),
               info.package_version.c_str());

  if (!OtaReport(cfg, http, cred, info.job_id, "downloading", 10, "", "", "", err)) {
    std::fprintf(stderr, "[ota] report downloading fail: %s\n", err.c_str());
  }

  std::string dir = "/var/tmp/checkin-ota";
  EnsureDir(dir, err);
  std::string archive = dir + "/package.bin";
  if (!DownloadUrl(info.download_url, archive, cfg.http_timeout_sec, err)) {
    std::string e2;
    OtaReport(cfg, http, cred, info.job_id, "failed", 0, "download_timeout", err, "", e2);
    return false;
  }
  std::string sum = Sha256File(archive, err);
  if (sum.empty() || sum != info.checksum_sha256) {
    std::string msg = sum.empty() ? err : ("expected " + info.checksum_sha256 + " got " + sum);
    std::string e2;
    OtaReport(cfg, http, cred, info.job_id, "failed", 0, "checksum_mismatch", msg, "", e2);
    return false;
  }

  if (!OtaReport(cfg, http, cred, info.job_id, "installing", 70, "", "", "", err)) {
    std::fprintf(stderr, "[ota] report installing fail: %s\n", err.c_str());
  }

  std::string ierr;
  bool ota_updated = false;
  if (!InstallArtifact(archive, ierr, &ota_updated)) {
    std::string e2;
    const char* code = (ierr == "service_start_failed") ? "service_start_failed" : "install_error";
    OtaReport(cfg, http, cred, info.job_id, "failed", 0, code, ierr, "", e2);
    return false;
  }

  if (!OtaReport(cfg, http, cred, info.job_id, "success", 100, "", "", info.package_version, err)) {
    std::fprintf(stderr, "[ota] report success fail: %s\n", err.c_str());
    return false;
  }
  std::fprintf(stderr, "[ota] success installed_version=%s gateway=%s\n",
               info.package_version.c_str(), kGatewayBin);

  if (ota_updated) {
    // Restart ourselves AFTER success report so a bad self-update still reported.
    std::fprintf(stderr, "[ota] scheduling restart of %s (new binary installed)\n", kOtaService);
    std::system(("systemctl restart " + std::string(kOtaService) + " || true").c_str());
  }
  return true;
}

}  // namespace

bool OtaCheck(const Config& cfg, const HttpClient& http, const Credential& cred, OtaCheckInfo& out,
              std::string& err) {
  auto r = SignedRequest(cfg, http, cred, "GET", "/device-ota/check", "");
  if (!r.ok) {
    err = r.error + " " + r.body.substr(0, 200);
    return false;
  }
  try {
    auto j = nlohmann::json::parse(r.body);
    auto d = j.at("data");
    out.update = d.value("update", false);
    if (!out.update) return true;
    out.job_id = d.value("job_id", "");
    out.package_version = d.value("package_version", "");
    out.package_name = d.value("package_name", "");
    out.download_url = d.value("download_url", "");
    out.checksum_sha256 = d.value("checksum_sha256", "");
    if (out.job_id.empty() || out.download_url.empty() || out.checksum_sha256.size() != 64) {
      err = "incomplete check payload";
      return false;
    }
    return true;
  } catch (const std::exception& ex) {
    err = std::string("parse: ") + ex.what();
    return false;
  }
}

bool OtaReport(const Config& cfg, const HttpClient& http, const Credential& cred,
               const std::string& job_id, const std::string& status, int progress_pct,
               const std::string& error_code, const std::string& error_message,
               const std::string& installed_version, std::string& err) {
  nlohmann::json body = {{"job_id", job_id}, {"status", status}, {"progress_pct", progress_pct}};
  if (!error_code.empty()) body["error_code"] = error_code;
  if (!error_message.empty()) body["error_message"] = error_message;
  if (!installed_version.empty()) body["installed_version"] = installed_version;
  auto r = SignedRequest(cfg, http, cred, "POST", "/device-ota/report", body.dump());
  if (!r.ok) {
    err = r.error + " " + r.body.substr(0, 200);
    return false;
  }
  return true;
}

int RunOtaService(Config cfg, bool once) {
  std::string err;
  if (!EnsureDir(cfg.data_dir, err)) {
    std::fprintf(stderr, "[ota] %s\n", err.c_str());
    return 1;
  }
  Store store;
  if (!store.Open(cfg.data_dir + "/state.db", err)) {
    std::fprintf(stderr, "[ota] store: %s\n", err.c_str());
    return 1;
  }
  Credential cred;
  if (!store.LoadCredential(cred, err)) {
    std::fprintf(stderr, "[ota] not enrolled: %s\n", err.c_str());
    return 2;
  }
  HttpClient http(cfg.http_timeout_sec);

  ApplyBootstrapOtaTimes(cfg, store, http, cred);

  if (once) {
    return RunOneCycle(cfg, store, http, cred) ? 0 : 1;
  }

  std::string last_slot;
  store.GetMeta("ota_last_sync_slot", last_slot, err);
  std::string times_csv = "03:30,15:30";
  store.GetMeta("ota_check_times", times_csv, err);
  if (times_csv.empty()) times_csv = "03:30,15:30";
  auto slots = ParseHHMMList(times_csv);

  int64_t last_bootstrap = 0;
  while (g_ota_running) {
    int64_t now = UnixNow();
    if (now - last_bootstrap >= 3600) {
      ApplyBootstrapOtaTimes(cfg, store, http, cred);
      store.GetMeta("ota_check_times", times_csv, err);
      if (times_csv.empty()) times_csv = "03:30,15:30";
      slots = ParseHHMMList(times_csv);
      last_bootstrap = now;
    }
    std::string slot;
    if (CurrentOtaSlot(slots, slot) && slot != last_slot) {
      std::fprintf(stderr, "[ota] scheduled slot=%s\n", slot.c_str());
      RunOneCycle(cfg, store, http, cred);
      last_slot = slot;
      store.SetMeta("ota_last_sync_slot", last_slot, err);
    }
    std::this_thread::sleep_for(std::chrono::seconds(20));
  }
  return 0;
}

}  // namespace cg
