#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "config.hpp"
#include "gateway.hpp"
#include "log.hpp"
#include "probe.hpp"
#include "store.hpp"
#include "util.hpp"

namespace {

void Usage(const char* argv0) {
  std::fprintf(stderr,
               "Usage:\n"
               "  %s --config <path>\n"
               "      Run checkin gateway (ATTLOG sync 00:00/12:00 + CommaDesk ingest)\n"
               "  %s --config <path> --enroll <pairing_code>\n"
               "  %s --config <path> --ack-rotate <secrets.json>\n"
               "  %s --config <path> --status\n"
               "      Show base_url / device / enrolled (no secrets)\n"
               "\n"
               "Configure (service-callable):\n"
               "  %s --config <path> server set --url <https://host/api/v1>\n"
               "  %s --config <path> device set --host <ip> [--port <port>]\n"
               "\n"
               "Local ZK tools:\n"
               "  %s --config <path> --discover|--sync-time|--sync-users|--listen [--result-dir <dir>]\n"
               "\n"
               "Options: --log-level debug|info|warning|error\n",
               argv0, argv0, argv0, argv0, argv0, argv0, argv0);
}

std::string DefaultResultDir() {
  const char* env = std::getenv("CHECKIN_GATEWAY_RESULT_DIR");
  if (env && *env) return env;
  return "/var/lib/checkin-gateway/results";
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path;
  std::string pairing_code;
  std::string rotate_path;
  std::string result_dir = DefaultResultDir();
  std::string device_host;
  std::string server_url;
  int device_port = 4370;
  bool enroll = false;
  bool ack_rotate = false;
  bool discover = false;
  bool sync_time = false;
  bool sync_users = false;
  bool listen = false;
  bool device_set = false;
  bool server_set = false;
  bool status = false;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else if (std::strcmp(argv[i], "--enroll") == 0 && i + 1 < argc) {
      enroll = true;
      pairing_code = argv[++i];
    } else if (std::strcmp(argv[i], "--ack-rotate") == 0 && i + 1 < argc) {
      ack_rotate = true;
      rotate_path = argv[++i];
    } else if (std::strcmp(argv[i], "--status") == 0) {
      status = true;
    } else if (std::strcmp(argv[i], "--discover") == 0) {
      discover = true;
    } else if (std::strcmp(argv[i], "--sync-time") == 0) {
      sync_time = true;
    } else if (std::strcmp(argv[i], "--sync-users") == 0) {
      sync_users = true;
    } else if (std::strcmp(argv[i], "--listen") == 0) {
      listen = true;
    } else if (std::strcmp(argv[i], "--result-dir") == 0 && i + 1 < argc) {
      result_dir = argv[++i];
    } else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
      std::string lvl = argv[++i];
      if (lvl == "debug") cg::GlobalLogLevel() = cg::LogLevel::Debug;
      else if (lvl == "info") cg::GlobalLogLevel() = cg::LogLevel::Info;
      else if (lvl == "warning") cg::GlobalLogLevel() = cg::LogLevel::Warning;
      else if (lvl == "error") cg::GlobalLogLevel() = cg::LogLevel::Error;
      else {
        std::fprintf(stderr, "Unknown log level: %s\n", lvl.c_str());
        return 1;
      }
    } else if (std::strcmp(argv[i], "server") == 0 && i + 1 < argc &&
               std::strcmp(argv[i + 1], "set") == 0) {
      server_set = true;
      ++i;
      while (i + 1 < argc) {
        if (std::strcmp(argv[i + 1], "--url") == 0 && i + 2 < argc) {
          i += 2;
          server_url = argv[i];
        } else {
          break;
        }
      }
    } else if (std::strcmp(argv[i], "device") == 0 && i + 1 < argc &&
               std::strcmp(argv[i + 1], "set") == 0) {
      device_set = true;
      ++i;
      while (i + 1 < argc) {
        if (std::strcmp(argv[i + 1], "--host") == 0 && i + 2 < argc) {
          i += 2;
          device_host = argv[i];
        } else if (std::strcmp(argv[i + 1], "--port") == 0 && i + 2 < argc) {
          i += 2;
          device_port = std::atoi(argv[i]);
        } else {
          break;
        }
      }
    } else if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0) {
      Usage(argv[0]);
      return 0;
    } else {
      std::fprintf(stderr, "Unknown arg: %s\n", argv[i]);
      Usage(argv[0]);
      return 1;
    }
  }

  if (config_path.empty()) {
    Usage(argv[0]);
    return 1;
  }

  int mode_count = static_cast<int>(enroll) + static_cast<int>(ack_rotate) +
                   static_cast<int>(discover) + static_cast<int>(sync_time) +
                   static_cast<int>(sync_users) + static_cast<int>(listen) +
                   static_cast<int>(device_set) + static_cast<int>(server_set) +
                   static_cast<int>(status);
  if (mode_count > 1) {
    std::fprintf(stderr, "Use only one mode at a time\n");
    return 1;
  }

  if (server_set) {
    if (server_url.empty()) {
      std::fprintf(stderr, "server set requires --url <base_url>\n");
      return 1;
    }
    while (!server_url.empty() && server_url.back() == '/') server_url.pop_back();
    std::string err;
    if (!cg::UpsertConfigKeys(config_path, {{"base_url", server_url}}, err)) {
      cg::LogError(err);
      return 1;
    }
    std::fprintf(stdout, "OK base_url=%s\n", server_url.c_str());
    std::fprintf(stdout, "Restart service: systemctl restart checkin-gateway\n");
    return 0;
  }

  if (device_set) {
    if (device_host.empty() || device_port <= 0) {
      std::fprintf(stderr, "device set requires --host and --port\n");
      return 1;
    }
    std::string err;
    if (!cg::SaveDeviceEndpoint(config_path, device_host, device_port, err)) {
      cg::LogError(err);
      return 1;
    }
    cg::LogInfo("Saved device endpoint " + device_host + ":" + std::to_string(device_port));
    cg::Config cfg;
    if (!cg::LoadConfig(config_path, cfg, err)) {
      cg::LogError(err);
      return 1;
    }
    return cg::RunConnectTest(cfg);
  }

  cg::Config cfg;
  std::string err;
  if (!cg::LoadConfig(config_path, cfg, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
  }

  if (status) {
    bool enrolled = false;
    std::string device_id;
    {
      cg::Store store;
      std::string e2;
      if (store.Open(cfg.data_dir + "/state.db", e2)) {
        cg::Credential cred;
        if (store.LoadCredential(cred, e2)) {
          enrolled = true;
          device_id = cred.device_id;
        }
      }
    }
    std::fprintf(stdout, "config=%s\n", config_path.c_str());
    std::fprintf(stdout, "base_url=%s\n", cfg.base_url.c_str());
    std::fprintf(stdout, "data_dir=%s\n", cfg.data_dir.c_str());
    std::fprintf(stdout, "device_ip=%s\n", cfg.device_ip.c_str());
    std::fprintf(stdout, "device_port=%d\n", cfg.device_port);
    std::fprintf(stdout, "discover_terminals=%s\n", cfg.discover_terminals ? "true" : "false");
    std::fprintf(stdout, "attlog_sync=%s\n",
                 cfg.attlog_sync_times.empty() ? "00:00,12:00" : cfg.attlog_sync_times.c_str());
    std::fprintf(stdout, "users_sync=%s\n",
                 cfg.users_sync_times.empty() ? "00:00,12:00" : cfg.users_sync_times.c_str());
    std::fprintf(stdout, "enrolled=%s\n", enrolled ? "true" : "false");
    if (enrolled) std::fprintf(stdout, "device_id=%s\n", device_id.c_str());
    return 0;
  }

  if (enroll) {
    if (pairing_code.empty()) {
      std::fprintf(stderr, "Missing pairing code\n");
      return 1;
    }
    return cg::RunEnroll(cfg, pairing_code);
  }
  if (ack_rotate) {
    return cg::RunAckRotate(cfg, rotate_path);
  }
  if (discover) {
    return cg::RunDiscover(cfg, result_dir);
  }
  if (sync_time) {
    return cg::RunSyncTime(cfg, result_dir);
  }
  if (sync_users) {
    return cg::RunSyncUsers(cfg);
  }
  if (listen) {
    return cg::RunListen(cfg, result_dir);
  }
  return cg::RunGateway(cfg);
}
