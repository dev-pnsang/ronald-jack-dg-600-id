#include "ota.hpp"
#include <algorithm>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <thread>

#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <sys/stat.h>

#include "util.hpp"

namespace cg {
namespace {

std::atomic<bool> g_ota_running{true};

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

bool CurrentOtaSlot(std::string& slot) {
  std::time_t now = std::time(nullptr);
  std::tm local{};
  localtime_r(&now, &local);
  if (local.tm_hour == 3 && local.tm_min >= 30 && local.tm_min <= 31) {
    slot = "03:30";
    return true;
  }
  if (local.tm_hour == 15 && local.tm_min >= 30 && local.tm_min <= 31) {
    slot = "15:30";
    return true;
  }
  slot.clear();
  return false;
}

bool InstallArtifact(const std::string& archive, const std::string& install_path,
                     const std::string& service_name, std::string& err) {
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
                      ShellQuote(install_path) + " " + ShellQuote(service_name);
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
  std::system(("systemctl stop " + service_name + " || true").c_str());
  std::string tmp = install_path + ".new";
  if (std::system(("install -m 0755 " + ShellQuote(bin) + " " + ShellQuote(tmp)).c_str()) != 0) {
    err = "install binary failed";
    return false;
  }
  if (std::rename(tmp.c_str(), install_path.c_str()) != 0) {
    err = "atomic replace failed";
    return false;
  }
  if (std::system(("systemctl start " + service_name).c_str()) != 0) {
    err = "service_start_failed";
    return false;
  }
  return true;
}

bool RunOneCycle(Config& cfg, Store& store, HttpClient& http, Credential& cred) {
  (void)store;
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
  std::string archive = dir + "/package.tar.gz";
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
  if (!InstallArtifact(archive, "/usr/local/bin/checkin-gateway", "checkin-gateway", ierr)) {
    std::string e2;
    const char* code = (ierr == "service_start_failed") ? "service_start_failed" : "install_error";
    OtaReport(cfg, http, cred, info.job_id, "failed", 0, code, ierr, "", e2);
    return false;
  }

  if (!OtaReport(cfg, http, cred, info.job_id, "success", 100, "", "", info.package_version, err)) {
    std::fprintf(stderr, "[ota] report success fail: %s\n", err.c_str());
    return false;
  }
  std::fprintf(stderr, "[ota] success installed_version=%s\n", info.package_version.c_str());
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

  if (once) {
    return RunOneCycle(cfg, store, http, cred) ? 0 : 1;
  }

  std::string last_slot;
  store.GetMeta("ota_last_sync_slot", last_slot, err);
  while (g_ota_running) {
    std::string slot;
    if (CurrentOtaSlot(slot) && slot != last_slot) {
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
