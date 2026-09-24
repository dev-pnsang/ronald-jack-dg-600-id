#include "zk_device.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#include <cstring>
#include <map>

#include "util.hpp"

namespace cg {
namespace {

// ZKTeco communication protocol (same family as Standalone SDK / pyzk).
constexpr uint16_t CMD_CONNECT = 1000;
constexpr uint16_t CMD_EXIT = 1001;
constexpr uint16_t CMD_ENABLEDEVICE = 1002;
constexpr uint16_t CMD_DISABLEDEVICE = 1003;
constexpr uint16_t CMD_ACK_OK = 2000;
constexpr uint16_t CMD_ACK_ERROR = 2001;
constexpr uint16_t CMD_ACK_DATA = 2002;
constexpr uint16_t CMD_ACK_UNAUTH = 2005;
constexpr uint16_t CMD_PREPARE_DATA = 1500;
constexpr uint16_t CMD_DATA = 1501;
constexpr uint16_t CMD_FREE_DATA = 1502;
constexpr uint16_t CMD_USERTEMP_RRQ = 9;
constexpr uint16_t CMD_ATTLOG_RRQ = 13;
constexpr uint16_t CMD_DEVICE = 11;
constexpr uint16_t CMD_GET_TIME = 201;
constexpr uint16_t CMD_REG_EVENT = 500;
constexpr uint16_t CMD_ACK_UNAUTH_ALT = 2005;
constexpr uint16_t EF_ATTLOG = 1;

constexpr size_t USHORT_SIZE = 2;
constexpr size_t ULONG_SIZE = 4;

uint16_t ReadU16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0] | (p[1] << 8));
}

uint32_t ReadU32(const uint8_t* p) {
  return static_cast<uint32_t>(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
}

void WriteU16(std::vector<uint8_t>& buf, uint16_t v) {
  buf.push_back(static_cast<uint8_t>(v & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
}

void WriteU32(std::vector<uint8_t>& buf, uint32_t v) {
  buf.push_back(static_cast<uint8_t>(v & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
  buf.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

uint16_t Checksum(const std::vector<uint8_t>& payload) {
  uint32_t chk = 0;
  size_t i = 0;
  for (; i + 1 < payload.size(); i += 2) {
    chk += ReadU16(payload.data() + i);
    chk &= 0xFFFF;
  }
  if (i < payload.size()) {
    chk += payload[i];
    chk &= 0xFFFF;
  }
  chk = (~chk) & 0xFFFF;
  return static_cast<uint16_t>((chk + 1) & 0xFFFF);
}

std::vector<uint8_t> MakePacket(uint16_t command, uint16_t session_id, uint16_t reply_id,
                                const std::vector<uint8_t>& data) {
  std::vector<uint8_t> body;
  WriteU16(body, command);
  WriteU16(body, 0);  // checksum placeholder
  WriteU16(body, session_id);
  WriteU16(body, reply_id);
  body.insert(body.end(), data.begin(), data.end());
  uint16_t chk = Checksum(body);
  body[2] = static_cast<uint8_t>(chk & 0xFF);
  body[3] = static_cast<uint8_t>((chk >> 8) & 0xFF);

  std::vector<uint8_t> packet;
  packet.push_back(0x50);
  packet.push_back(0x50);
  packet.push_back(0x82);
  packet.push_back(0x7D);
  WriteU32(packet, static_cast<uint32_t>(body.size()));
  packet.insert(packet.end(), body.begin(), body.end());
  return packet;
}

bool SetNonBlocking(int fd, bool on) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) return false;
  if (on) flags |= O_NONBLOCK;
  else flags &= ~O_NONBLOCK;
  return fcntl(fd, F_SETFL, flags) == 0;
}

bool WaitReadable(int fd, int timeout_ms) {
  fd_set rfds;
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int rc = select(fd + 1, &rfds, nullptr, nullptr, &tv);
  return rc > 0;
}

bool WaitWritable(int fd, int timeout_ms) {
  fd_set wfds;
  FD_ZERO(&wfds);
  FD_SET(fd, &wfds);
  timeval tv{};
  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;
  int rc = select(fd + 1, nullptr, &wfds, nullptr, &tv);
  return rc > 0;
}

std::string CleanText(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    if (c == 0) break;
    if (c >= 32) out.push_back(static_cast<char>(c));
  }
  return Trim(out);
}

}  // namespace

const char* VerifyModeText(int mode) {
  switch (mode) {
    case 0: return "password";
    case 1: return "fingerprint";
    case 2: return "card";
    case 3: return "fingerprint+password";
    case 4: return "fingerprint+card";
    case 5: return "password+card";
    case 6: return "fingerprint+password+card";
    case 7: return "card+fingerprint";
    case 8: return "face";
    case 9: return "face+fingerprint";
    case 10: return "face+password";
    case 11: return "face+card";
    case 15: return "face+password";
    default: return "unknown";
  }
}

const char* InOutModeText(int mode) {
  switch (mode) {
    case 0: return "in";
    case 1: return "out";
    case 2: return "break_out";
    case 3: return "break_in";
    case 4: return "ot_in";
    case 5: return "ot_out";
    default: return "unknown";
  }
}

ZkDevice::ZkDevice() = default;

ZkDevice::~ZkDevice() { Disconnect(); }

bool ZkDevice::CreateSocket(std::string& err) {
  CloseSocket();
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0) {
    err = std::string("socket: ") + std::strerror(errno);
    return false;
  }
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port_));
  if (inet_pton(AF_INET, ip_.c_str(), &addr.sin_addr) != 1) {
    err = "invalid device IP: " + ip_;
    CloseSocket();
    return false;
  }
  SetNonBlocking(fd_, true);
  int rc = ::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
  if (rc < 0 && errno != EINPROGRESS) {
    err = std::string("connect: ") + std::strerror(errno);
    CloseSocket();
    return false;
  }
  if (!WaitWritable(fd_, timeout_sec_ * 1000)) {
    err = "connect timeout";
    CloseSocket();
    return false;
  }
  int so_error = 0;
  socklen_t len = sizeof(so_error);
  getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_error, &len);
  if (so_error != 0) {
    err = std::string("connect failed: ") + std::strerror(so_error);
    CloseSocket();
    return false;
  }
  SetNonBlocking(fd_, false);
  // Set recv timeout
  timeval tv{};
  tv.tv_sec = timeout_sec_;
  setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
  setsockopt(fd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  return true;
}

void ZkDevice::CloseSocket() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool ZkDevice::RecvPacket(std::vector<uint8_t>& payload, uint16_t& command, std::string& err,
                          int timeout_ms) {
  payload.clear();
  if (fd_ < 0) {
    err = "not connected";
    return false;
  }
  if (!WaitReadable(fd_, timeout_ms)) {
    err = "recv timeout";
    return false;
  }
  uint8_t header[8];
  size_t got = 0;
  while (got < sizeof(header)) {
    ssize_t n = ::recv(fd_, header + got, sizeof(header) - got, 0);
    if (n <= 0) {
      err = "recv header failed";
      return false;
    }
    got += static_cast<size_t>(n);
  }
  if (header[0] != 0x50 || header[1] != 0x50 || header[2] != 0x82 || header[3] != 0x7D) {
    err = "bad packet magic";
    return false;
  }
  uint32_t size = ReadU32(header + 4);
  if (size < 8 || size > 1024 * 1024) {
    err = "bad packet size";
    return false;
  }
  std::vector<uint8_t> body(size);
  got = 0;
  while (got < size) {
    if (!WaitReadable(fd_, timeout_ms)) {
      err = "recv body timeout";
      return false;
    }
    ssize_t n = ::recv(fd_, body.data() + got, size - got, 0);
    if (n <= 0) {
      err = "recv body failed";
      return false;
    }
    got += static_cast<size_t>(n);
  }
  command = ReadU16(body.data());
  session_id_ = ReadU16(body.data() + 4);
  reply_id_ = static_cast<uint16_t>((ReadU16(body.data() + 6) + 1) & 0xFFFF);
  payload.assign(body.begin() + 8, body.end());
  return true;
}

bool ZkDevice::SendCommand(uint16_t command, const std::vector<uint8_t>& data,
                           std::vector<uint8_t>& reply, uint16_t& reply_cmd, std::string& err,
                           int timeout_ms) {
  auto packet = MakePacket(command, session_id_, reply_id_, data);
  size_t sent = 0;
  while (sent < packet.size()) {
    ssize_t n = ::send(fd_, packet.data() + sent, packet.size() - sent, 0);
    if (n <= 0) {
      err = "send failed";
      return false;
    }
    sent += static_cast<size_t>(n);
  }
  if (!RecvPacket(reply, reply_cmd, err, timeout_ms)) return false;
  if (reply_cmd == CMD_ACK_UNAUTH || reply_cmd == CMD_ACK_UNAUTH_ALT) {
    err = "device unauthorized (need comm password?)";
    return false;
  }
  if (reply_cmd == CMD_ACK_ERROR) {
    err = "device returned ACK_ERROR";
    return false;
  }
  return true;
}

bool ZkDevice::Handshake(std::string& err) {
  session_id_ = 0;
  reply_id_ = 0;
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_CONNECT, {}, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK && cmd != CMD_ACK_UNAUTH) {
    // Some firmwares reply ACK_OK; unauth means password required next.
  }
  return true;
}

bool ZkDevice::Authenticate(int password, std::string& err) {
  if (password == 0) return true;
  // CMD_AUTH = 1102 with session-based hash (pyzk make_commkey)
  constexpr uint16_t CMD_AUTH = 1102;
  uint32_t key = static_cast<uint32_t>(password);
  uint32_t session = session_id_;
  // pyzk: make_commkey
  uint32_t k = 0;
  for (int i = 0; i < 32; ++i) {
    if (key & (1u << i)) k = (k << 1) | 1;
    else k = k << 1;
  }
  k += session;
  std::vector<uint8_t> data(4);
  data[0] = static_cast<uint8_t>(k & 0xFF);
  data[1] = static_cast<uint8_t>((k >> 8) & 0xFF);
  data[2] = static_cast<uint8_t>((k >> 16) & 0xFF);
  data[3] = static_cast<uint8_t>((k >> 24) & 0xFF);
  // XOR with 'ZKSO' pattern like pyzk
  static const uint8_t xor_key[4] = {0x5A, 0x4B, 0x53, 0x4F};  // ZKSO
  for (int i = 0; i < 4; ++i) data[i] ^= xor_key[i];
  // Swap bytes per pyzk
  std::swap(data[0], data[2]);
  std::swap(data[1], data[3]);
  for (int i = 0; i < 4; ++i) data[i] = static_cast<uint8_t>((~data[i]) & 0xFF);

  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_AUTH, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK) {
    err = "auth failed";
    return false;
  }
  return true;
}

bool ZkDevice::EnableDevice(bool enable, std::string& err) {
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  return SendCommand(enable ? CMD_ENABLEDEVICE : CMD_DISABLEDEVICE, {}, reply, cmd, err);
}

bool ZkDevice::GetString(uint16_t /*command*/, const std::string& param, std::string& value,
                         std::string& err) {
  // CMD_OPTIONS_RRQ = 11 with "~SerialNumber\0" style via CMD_DEVICE
  std::vector<uint8_t> data(param.begin(), param.end());
  data.push_back(0);
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_DEVICE, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK && cmd != CMD_ACK_DATA) {
    value.clear();
    return true;  // optional fields
  }
  // Reply often "SerialNumber=XXXX\0"
  std::string raw(reply.begin(), reply.end());
  auto eq = raw.find('=');
  if (eq != std::string::npos) value = CleanText(raw.substr(eq + 1));
  else value = CleanText(raw);
  return true;
}

bool ZkDevice::Connect(const std::string& ip, int port, int password, int timeout_sec,
                       std::string& err) {
  Disconnect();
  ip_ = ip;
  port_ = port;
  password_ = password;
  timeout_sec_ = timeout_sec > 0 ? timeout_sec : 10;
  if (!CreateSocket(err)) return false;
  if (!Handshake(err)) {
    CloseSocket();
    return false;
  }
  if (!Authenticate(password, err)) {
    CloseSocket();
    return false;
  }
  EnableDevice(true, err);  // best-effort
  connected_ = true;
  info_.ip = ip_;
  info_.port = port_;
  return true;
}

void ZkDevice::Disconnect() {
  if (connected_ && fd_ >= 0) {
    std::string err;
    StopLiveCapture();
    std::vector<uint8_t> reply;
    uint16_t cmd = 0;
    SendCommand(CMD_EXIT, {}, reply, cmd, err, 2000);
  }
  CloseSocket();
  connected_ = false;
  live_ = false;
}

bool ZkDevice::ReadDeviceInfo(DeviceInfo& out, std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  out = DeviceInfo{};
  out.ip = ip_;
  out.port = port_;
  GetString(CMD_DEVICE, "~SerialNumber", out.serial, err);
  GetString(CMD_DEVICE, "~OEMVendor", out.platform, err);
  GetString(CMD_DEVICE, "~DeviceName", out.firmware, err);
  if (out.firmware.empty()) GetString(CMD_DEVICE, "FirmVer", out.firmware, err);

  // Device time
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (SendCommand(CMD_GET_TIME, {}, reply, cmd, err) && reply.size() >= 4) {
    uint32_t t = ReadU32(reply.data());
    // ZK encoded datetime
    int second = static_cast<int>(t % 60);
    int minute = static_cast<int>((t / 60) % 60);
    int hour = static_cast<int>((t / 3600) % 24);
    int day = static_cast<int>(((t / (3600 * 24)) % 31) + 1);
    int month = static_cast<int>(((t / (3600 * 24 * 31)) % 12) + 1);
    int year = static_cast<int>((t / (3600 * 24 * 31 * 12)) + 2000);
    out.device_time_iso = FormatIso8601Utc(year, month, day, hour, minute, second);
  }
  info_ = out;
  return true;
}

bool ZkDevice::ReadUsers(std::vector<UserRecord>& out, std::string& err) {
  out.clear();
  if (!connected_) {
    err = "not connected";
    return false;
  }
  // Request users via CMD_USERTEMP_RRQ with flag 5 (users only) — same as pyzk get_users
  std::vector<uint8_t> data = {0x05};
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!EnableDevice(false, err)) return false;
  bool ok = SendCommand(CMD_USERTEMP_RRQ, data, reply, cmd, err, timeout_sec_ * 1000);
  if (!ok) {
    EnableDevice(true, err);
    return false;
  }

  std::vector<uint8_t> blob;
  if (cmd == CMD_PREPARE_DATA && reply.size() >= 4) {
    uint32_t size = ReadU32(reply.data());
    blob.reserve(size);
    while (blob.size() < size) {
      std::vector<uint8_t> chunk;
      uint16_t c = 0;
      if (!RecvPacket(chunk, c, err, timeout_sec_ * 1000)) {
        EnableDevice(true, err);
        return false;
      }
      if (c == CMD_DATA) {
        blob.insert(blob.end(), chunk.begin(), chunk.end());
      } else if (c == CMD_ACK_OK) {
        break;
      } else {
        break;
      }
    }
    std::vector<uint8_t> freply;
    uint16_t fcmd = 0;
    SendCommand(CMD_FREE_DATA, {}, freply, fcmd, err, 3000);
  } else if (cmd == CMD_DATA || cmd == CMD_ACK_OK) {
    blob = reply;
  }
  EnableDevice(true, err);

  // SSR user record: 72 bytes typical
  const size_t rec = 72;
  for (size_t off = 0; off + rec <= blob.size(); off += rec) {
    const uint8_t* p = blob.data() + off;
    UserRecord u;
    // uid at 0 (u16), privilege at 2, password 3..11, name 11..35, card 35..39, userid string 48..72
    u.privilege = p[2];
    char name[28] = {};
    std::memcpy(name, p + 11, 24);
    u.name = CleanText(name);
    char uidstr[28] = {};
    std::memcpy(uidstr, p + 48, 24);
    u.user_id = CleanText(uidstr);
    if (u.user_id.empty()) {
      uint16_t uid = ReadU16(p);
      if (uid == 0) continue;
      u.user_id = std::to_string(uid);
    }
    u.enabled = (p[0] != 0) || !u.user_id.empty();
    out.push_back(u);
  }
  users_cache_ = out;
  return true;
}

bool ZkDevice::ReadAttendanceLogs(std::vector<AttendanceEvent>& out, std::string& err) {
  out.clear();
  if (!connected_) {
    err = "not connected";
    return false;
  }
  // Temporarily stop live so ATTLOG_RRQ is not interleaved with events.
  bool was_live = live_;
  if (was_live) StopLiveCapture();

  if (!EnableDevice(false, err)) {
    if (was_live) StartLiveCapture(err);
    return false;
  }

  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  bool ok = SendCommand(CMD_ATTLOG_RRQ, {}, reply, cmd, err, timeout_sec_ * 1000);
  if (!ok) {
    EnableDevice(true, err);
    if (was_live) StartLiveCapture(err);
    return false;
  }

  std::vector<uint8_t> blob;
  if (cmd == CMD_PREPARE_DATA && reply.size() >= 4) {
    uint32_t size = ReadU32(reply.data());
    blob.reserve(size);
    while (blob.size() < size) {
      std::vector<uint8_t> chunk;
      uint16_t c = 0;
      if (!RecvPacket(chunk, c, err, timeout_sec_ * 1000)) {
        EnableDevice(true, err);
        if (was_live) StartLiveCapture(err);
        return false;
      }
      if (c == CMD_DATA) {
        blob.insert(blob.end(), chunk.begin(), chunk.end());
      } else if (c == CMD_ACK_OK) {
        break;
      } else {
        break;
      }
    }
    std::vector<uint8_t> freply;
    uint16_t fcmd = 0;
    SendCommand(CMD_FREE_DATA, {}, freply, fcmd, err, 3000);
  } else if (cmd == CMD_DATA || cmd == CMD_ACK_OK) {
    blob = reply;
  }

  EnableDevice(true, err);
  if (was_live) {
    std::string e2;
    StartLiveCapture(e2);
  }

  // SSR attendance record: typically 40 bytes
  // user_id[24] + time(u32) + status(u8) + punch(u8) + reserved...
  const size_t rec = 40;
  std::string received = UtcNowIso8601();
  for (size_t off = 0; off + 16 <= blob.size();) {
    size_t step = (off + rec <= blob.size()) ? rec : 16;
    const uint8_t* p = blob.data() + off;
    AttendanceEvent ev;
    ev.from_live = false;
    ev.received_at_iso = received;

    char uidstr[28] = {};
    std::memcpy(uidstr, p, 24);
    ev.user_id = CleanText(uidstr);
    size_t time_off = 24;
    if (ev.user_id.empty()) {
      // legacy: uid u16 at 0, time at 4
      uint16_t uid = ReadU16(p);
      if (uid == 0) {
        off += step;
        continue;
      }
      ev.user_id = std::to_string(uid);
      time_off = 4;
      step = 16;
    }
    if (time_off + 4 > blob.size() - off) break;
    uint32_t t = ReadU32(p + time_off);
    ev.second = static_cast<int>(t % 60);
    ev.minute = static_cast<int>((t / 60) % 60);
    ev.hour = static_cast<int>((t / 3600) % 24);
    ev.day = static_cast<int>(((t / (3600 * 24)) % 31) + 1);
    ev.month = static_cast<int>(((t / (3600 * 24 * 31)) % 12) + 1);
    ev.year = static_cast<int>((t / (3600 * 24 * 31 * 12)) + 2000);
    if (ev.year < 2000 || ev.year > 2099) {
      off += step;
      continue;
    }
    ev.timestamp_iso = FormatIso8601Utc(ev.year, ev.month, ev.day, ev.hour, ev.minute, ev.second);
    if (time_off + 4 < step) ev.verify_mode = p[time_off + 4];
    if (time_off + 5 < step) ev.inout_mode = p[time_off + 5];
    if (time_off + 6 < step) ev.work_code = p[time_off + 6];
    for (const auto& u : users_cache_) {
      if (u.user_id == ev.user_id) {
        ev.user_name = u.name;
        break;
      }
    }
    if (!ev.user_id.empty() && ev.user_id != "0") out.push_back(ev);
    off += step;
  }
  return true;
}

bool ZkDevice::StartLiveCapture(std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  // RegEvent with EF_ATTLOG mask (and related)
  std::vector<uint8_t> data;
  WriteU32(data, 0xFFFF);  // all events — mirrors SDK RegEvent(machine, 65535)
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_REG_EVENT, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK) {
    err = "RegEvent failed";
    return false;
  }
  live_ = true;
  return true;
}

void ZkDevice::StopLiveCapture() {
  if (!connected_ || !live_) {
    live_ = false;
    return;
  }
  std::string err;
  std::vector<uint8_t> data;
  WriteU32(data, 0);
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  SendCommand(CMD_REG_EVENT, data, reply, cmd, err, 2000);
  live_ = false;
}

bool ZkDevice::ParseAttEvent(const std::vector<uint8_t>& data, AttendanceEvent& ev) {
  // Realtime ATTLOG: typically 36+ bytes (user_id string / uid + time + status + punch)
  // pyzk live_capture parses several formats. Support common SSR-style:
  // [userid\0...][time u32][status][punch] or 40-byte variant.
  if (data.size() < 12) return false;

  ev = AttendanceEvent{};
  ev.from_live = true;
  ev.received_at_iso = UtcNowIso8601();

  // Try string user id at start (null-terminated, up to 9–24 chars)
  std::string uid;
  size_t i = 0;
  for (; i < data.size() && i < 24; ++i) {
    if (data[i] == 0) {
      ++i;
      break;
    }
    if (data[i] >= 32 && data[i] < 127) uid.push_back(static_cast<char>(data[i]));
    else break;
  }
  if (uid.empty() && data.size() >= 2) {
    uid = std::to_string(ReadU16(data.data()));
    i = 2;
  }
  ev.user_id = CleanText(uid);

  // Align to time field — common layouts put time at offset 8 or after userid padded to 9
  size_t time_off = 8;
  if (data.size() >= 16) {
    // Heuristic: if bytes 8..11 look like ZK time, use them
    time_off = (i <= 8) ? 8 : i;
    if (time_off + 4 > data.size()) time_off = data.size() - 6;
  }
  if (time_off + 4 <= data.size()) {
    uint32_t t = ReadU32(data.data() + time_off);
    ev.second = static_cast<int>(t % 60);
    ev.minute = static_cast<int>((t / 60) % 60);
    ev.hour = static_cast<int>((t / 3600) % 24);
    ev.day = static_cast<int>(((t / (3600 * 24)) % 31) + 1);
    ev.month = static_cast<int>(((t / (3600 * 24 * 31)) % 12) + 1);
    ev.year = static_cast<int>((t / (3600 * 24 * 31 * 12)) + 2000);
    if (ev.year < 2000 || ev.year > 2099) {
      // Fallback: use now
      std::time_t now = std::time(nullptr);
      std::tm tmb{};
      gmtime_r(&now, &tmb);
      ev.year = tmb.tm_year + 1900;
      ev.month = tmb.tm_mon + 1;
      ev.day = tmb.tm_mday;
      ev.hour = tmb.tm_hour;
      ev.minute = tmb.tm_min;
      ev.second = tmb.tm_sec;
    }
  }
  ev.timestamp_iso = FormatIso8601Utc(ev.year, ev.month, ev.day, ev.hour, ev.minute, ev.second);

  size_t status_off = time_off + 4;
  if (status_off < data.size()) ev.verify_mode = data[status_off];
  if (status_off + 1 < data.size()) ev.inout_mode = data[status_off + 1];
  if (status_off + 2 < data.size()) ev.work_code = data[status_off + 2];

  for (const auto& u : users_cache_) {
    if (u.user_id == ev.user_id) {
      ev.user_name = u.name;
      break;
    }
  }
  return !ev.user_id.empty() && ev.user_id != "0";
}

bool ZkDevice::PollLive(AttendanceCallback cb, int wait_ms, std::string& err) {
  if (!connected_ || !live_) {
    err = "live capture not started";
    return false;
  }
  if (!WaitReadable(fd_, wait_ms)) {
    err.clear();
    return true;  // idle
  }
  std::vector<uint8_t> payload;
  uint16_t cmd = 0;
  if (!RecvPacket(payload, cmd, err, wait_ms > 0 ? wait_ms : 1000)) {
    // Distinguishing timeout vs disconnect
    if (err == "recv timeout") {
      err.clear();
      return true;
    }
    return false;
  }
  // Unsolicited realtime: command often EF_ATTLOG (1) or packed in ACK_DATA
  if (cmd == EF_ATTLOG || cmd == 1 || cmd == CMD_REG_EVENT || cmd == CMD_ACK_DATA ||
      cmd == CMD_DATA) {
    AttendanceEvent ev;
    if (ParseAttEvent(payload, ev)) {
      if (cb) cb(ev);
    }
  }
  // Some devices send nested: first byte event code
  if (payload.size() > 1 && (payload[0] == 1 /*ATTLOG*/)) {
    AttendanceEvent ev;
    std::vector<uint8_t> slice(payload.begin() + 1, payload.end());
    if (ParseAttEvent(slice, ev)) {
      if (cb) cb(ev);
    }
  }
  return true;
}

}  // namespace cg
