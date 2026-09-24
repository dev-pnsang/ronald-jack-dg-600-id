#include <cstdio>
#include <cstring>
#include <string>

#include "config.hpp"
#include "gateway.hpp"

namespace {

void Usage(const char* argv0) {
  std::fprintf(stderr,
               "Usage:\n"
               "  %s --config <path>\n"
               "      Run checkin gateway service (live listen + ingest)\n"
               "  %s --config <path> --enroll <pairing_code>\n"
               "      Enroll Device Identity once; store secrets in data_dir\n"
               "  %s --config <path> --ack-rotate <secrets.json>\n"
               "      After admin Rotate: ACK with new secrets and replace local store\n"
               "\n"
               "secrets.json: {\"auth_secret\":\"cp_dev_...\",\"signing_secret\":\"cp_dsig_...\"}\n"
               "Config example: config/checkin-gateway.conf.example\n",
               argv0, argv0, argv0);
}

}  // namespace

int main(int argc, char** argv) {
  std::string config_path;
  std::string pairing_code;
  std::string rotate_path;
  bool enroll = false;
  bool ack_rotate = false;

  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else if (std::strcmp(argv[i], "--enroll") == 0 && i + 1 < argc) {
      enroll = true;
      pairing_code = argv[++i];
    } else if (std::strcmp(argv[i], "--ack-rotate") == 0 && i + 1 < argc) {
      ack_rotate = true;
      rotate_path = argv[++i];
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
  if (enroll && ack_rotate) {
    std::fprintf(stderr, "Use either --enroll or --ack-rotate, not both\n");
    return 1;
  }

  cg::Config cfg;
  std::string err;
  if (!cg::LoadConfig(config_path, cfg, err)) {
    std::fprintf(stderr, "%s\n", err.c_str());
    return 1;
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
  return cg::RunGateway(cfg);
}
