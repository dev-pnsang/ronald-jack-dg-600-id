#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace cg {

struct DeviceInfo {
  std::string ip;
  int port = 0;
  std::string firmware;
  std::string serial;
  std::string platform;
  std::string device_time_iso;
  int user_count = 0;
  int log_count = 0;
};

struct UserRecord {
  std::string user_id;
  std::string name;
  int privilege = 0;
  bool enabled = true;
};

// Fields mirror Standalone SDK / Dg600Reader AttendanceRecord + extras.
struct AttendanceEvent {
  std::string user_id;       // local ID on machine (enroll number)
  std::string user_name;
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  std::string timestamp_iso; // UTC ISO-8601 derived from device stamp (as wall clock; TZ assumed local→UTC convert optional)
  std::string received_at_iso;
  int verify_mode = 0;
  int inout_mode = 0;
  int work_code = 0;
  bool from_live = true;
};

using AttendanceCallback = std::function<void(const AttendanceEvent&)>;

// ZK TCP client — same protocol family as ZKTeco Standalone SDK (port 4370).
// Windows COM zkemkeeper.dll cannot run on Linux; this speaks the wire protocol directly.
class ZkDevice {
 public:
  ZkDevice();
  ~ZkDevice();

  ZkDevice(const ZkDevice&) = delete;
  ZkDevice& operator=(const ZkDevice&) = delete;

  bool Connect(const std::string& ip, int port, int password, int timeout_sec, std::string& err);
  void Disconnect();
  bool IsConnected() const { return connected_; }

  bool ReadDeviceInfo(DeviceInfo& out, std::string& err);
  bool ReadUsers(std::vector<UserRecord>& out, std::string& err);

  // Register for realtime attendance events (RegEvent / live capture).
  bool StartLiveCapture(std::string& err);
  void StopLiveCapture();

  // Poll socket for live events; invokes cb for each punch. Returns false on fatal I/O.
  bool PollLive(AttendanceCallback cb, int wait_ms, std::string& err);

  const std::string& Ip() const { return ip_; }
  int Port() const { return port_; }
  const DeviceInfo& LastInfo() const { return info_; }

 private:
  bool SendCommand(uint16_t command, const std::vector<uint8_t>& data, std::vector<uint8_t>& reply,
                   uint16_t& reply_cmd, std::string& err, int timeout_ms = 5000);
  bool RecvPacket(std::vector<uint8_t>& payload, uint16_t& command, std::string& err, int timeout_ms);
  bool CreateSocket(std::string& err);
  void CloseSocket();
  bool Handshake(std::string& err);
  bool Authenticate(int password, std::string& err);
  bool EnableDevice(bool enable, std::string& err);
  bool GetString(uint16_t command, const std::string& param, std::string& value, std::string& err);
  bool ParseAttEvent(const std::vector<uint8_t>& data, AttendanceEvent& ev);

  int fd_ = -1;
  bool connected_ = false;
  bool live_ = false;
  uint16_t session_id_ = 0;
  uint16_t reply_id_ = 0;
  std::string ip_;
  int port_ = 4370;
  int password_ = 0;
  int timeout_sec_ = 10;
  DeviceInfo info_;
  std::vector<UserRecord> users_cache_;
};

const char* VerifyModeText(int mode);
const char* InOutModeText(int mode);

}  // namespace cg
