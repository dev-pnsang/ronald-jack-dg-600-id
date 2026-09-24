#pragma once

#include <string>

#include "config.hpp"
#include "device_identity.hpp"
#include "http_client.hpp"
#include "zk_device.hpp"

namespace cg {

// Build device-ingest JSON. Always includes attendance_code (local ID) + timestamp
// plus all available punch/device fields for server-side mapping.
std::string BuildIngestBody(const AttendanceEvent& ev, const DeviceInfo& device,
                            const Config& cfg);

SignedResult PostDeviceIngest(const Config& cfg, const HttpClient& http, const Credential& cred,
                              const std::string& raw_body);

}  // namespace cg
