#include <cstdio>
#include <cstring>
#include <string>

#include "config.hpp"
#include "ota.hpp"

int main(int argc, char** argv) {
  std::string config_path = "/root/ronald-jack-dg-600-id/gateway/config/checkin-gateway.conf";
  bool once = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else if (std::strcmp(argv[i], "--once") == 0) {
      once = true;
    } else if (std::strcmp(argv[i], "--help") == 0) {
      std::fprintf(stdout,
                   "Usage: checkin-ota --config <path> [--once]\n"
                   "  Scheduled OTA check at 03:30 and 15:30 local (default).\n"
                   "  --once runs a single check/install cycle then exits.\n");
      return 0;
    }
  }
  cg::Config cfg;
  std::string err;
  if (!cg::LoadConfig(config_path, cfg, err)) {
    std::fprintf(stderr, "config: %s\n", err.c_str());
    return 1;
  }
  cfg.config_path = config_path;
  return cg::RunOtaService(cfg, once);
}
