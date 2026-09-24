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
  std::string device_name;
  std::string device_time_iso;
  std::string device_time_local;  // wall-clock as reported by device (no TZ)
  int user_count = 0;
  int log_count = 0;
  int finger_count = 0;
};

struct DeviceOptionResult {
  std::string key;
  std::string status;  // ok | empty | FAILED | NOT_SUPPORTED
  std::string value;
  std::string raw_hex;
  std::string error;
  uint16_t reply_cmd = 0;
};

struct DeviceTime {
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  std::string iso_local;  // YYYY-MM-DDTHH:MM:SS (device wall clock)
  uint32_t encoded = 0;
  std::string raw_hex;
};

struct UserRecord {
  std::string user_id;
  std::string name;
  int privilege = 0;
  bool enabled = true;
  uint16_t uid = 0;
  std::string password;
  uint32_t card = 0;
  std::string raw_hex;  // per-record raw bytes
};

// Fields mirror Standalone SDK / Dg600Reader AttendanceRecord + extras.
struct AttendanceEvent {
  std::string user_id;  // local ID on machine (enroll number)
  std::string user_name;
  int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
  std::string timestamp_iso;  // wall-clock from device stamped as Z for API
  std::string received_at_iso;
  int verify_mode = 0;
  int inout_mode = 0;
  int work_code = 0;
  bool from_live = true;
  std::string raw_hex;
  uint16_t raw_cmd = 0;
};

struct RawBlob {
  std::string label;
  std::string status;  // ok | FAILED | empty
  std::string error;
  uint16_t reply_cmd = 0;
  std::vector<uint8_t> bytes;
  std::string hex() const;
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
  void SetTzOffsetMinutes(int offset_min) { tz_offset_min_ = offset_min; }
  bool IsConnected() const { return connected_; }

  bool ReadDeviceInfo(DeviceInfo& out, std::string& err);
  bool ReadUsers(std::vector<UserRecord>& out, std::string& err);
  // Same as ReadUsers but also returns the raw user table blob.
  bool ReadUsersRaw(std::vector<UserRecord>& out, RawBlob& raw, std::string& err);

  // Pull attendance logs from device (CMD_ATTLOG_RRQ) — used as poll fallback.
  bool ReadAttendanceLogs(std::vector<AttendanceEvent>& out, std::string& err);
  bool ReadAttendanceLogsRaw(std::vector<AttendanceEvent>& out, RawBlob& raw, std::string& err);

  // Re-enable UI after bulk (retry Enable, then hard reconnect). Call after every large pull.
  bool RecoverDevice(std::string& err);
  // Clear attendance buffer on device after successful local enqueue (keeps next pull small).
  bool ClearAttendanceLogs(std::string& err);

  bool GetTime(DeviceTime& out, std::string& err);
  // Set device clock from local wall-clock components (year>=2000).
  bool SetTime(int year, int month, int day, int hour, int minute, int second, std::string& err);

  // Probe CMD_DEVICE option key (e.g. "~SerialNumber"). Never invents values.
  DeviceOptionResult ProbeOption(const std::string& key);

  // CMD_GET_FREE_SIZES (50) — users/fingers/records capacity counters when supported.
  bool ReadFreeSizes(DeviceInfo& info, RawBlob& raw, std::string& err);

  // Register for realtime attendance events (RegEvent / live capture).
  bool StartLiveCapture(std::string& err);
  void StopLiveCapture();

  // Poll socket for live events; invokes cb for each punch. Returns false on fatal I/O.
  bool PollLive(AttendanceCallback cb, int wait_ms, std::string& err);

  const std::string& Ip() const { return ip_; }
  int Port() const { return port_; }
  const DeviceInfo& LastInfo() const { return info_; }
  static const char* ProtocolName() { return "ZKTeco TCP wire protocol (pyzk-compatible)"; }

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
  bool FetchLargeData(uint16_t command, const std::vector<uint8_t>& req, RawBlob& raw,
                      std::string& err);
  // pyzk-style buffered pull (CMD_PREPARE_BUFFER / CMD_READ_BUFFER).
  bool FetchLargeDataBuffered(uint16_t command, int32_t fct, int32_t ext, RawBlob& raw,
                              std::string& err);
  bool FetchLargeDataSmart(uint16_t command, int32_t fct, const std::vector<uint8_t>& legacy_req,
                           RawBlob& raw, std::string& err);

  int tz_offset_min_ = 420;
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
const char* PrivilegeText(int privilege);

uint32_t EncodeZkTime(int year, int month, int day, int hour, int minute, int second);
bool DecodeZkTime(uint32_t t, int& year, int& month, int& day, int& hour, int& minute, int& second);

}  // namespace cg
