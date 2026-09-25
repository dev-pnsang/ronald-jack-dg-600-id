#include "zk_device.hpp"
#include <algorithm>

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

#include "log.hpp"
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
constexpr uint16_t CMD_PREPARE_BUFFER = 1503;  // pyzk read_with_buffer
constexpr uint16_t CMD_READ_BUFFER = 1504;
constexpr uint16_t CMD_USERTEMP_RRQ = 9;
constexpr uint16_t CMD_ATTLOG_RRQ = 13;
constexpr uint16_t CMD_CLEAR_ATTLOG = 15;
constexpr uint16_t CMD_DEVICE = 11;
constexpr uint16_t CMD_GET_TIME = 201;
constexpr uint16_t CMD_SET_TIME = 202;
constexpr uint16_t CMD_GET_FREE_SIZES = 50;
constexpr uint16_t CMD_REFRESHDATA = 1013;
constexpr uint16_t CMD_REG_EVENT = 500;
constexpr int32_t FCT_USER = 5;
constexpr uint32_t BUF_MAX_CHUNK = 0xFFc0;  // ~64KiB TCP chunk (pyzk)
constexpr uint16_t EF_ATTLOG = 1;

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
  // Match pyzk ZK._ZK__create_checksum (from zkemsdk.c).
  int32_t checksum = 0;
  size_t off = 0;
  size_t l = payload.size();
  while (l > 1) {
    checksum += static_cast<int32_t>(payload[off] | (payload[off + 1] << 8));
    off += 2;
    l -= 2;
    if (checksum > 65535) checksum -= 65535;
  }
  if (l) checksum += payload[off];
  while (checksum > 65535) checksum -= 65535;
  checksum = ~checksum;
  while (checksum < 0) checksum += 65535;
  return static_cast<uint16_t>(checksum & 0xFFFF);
}

std::vector<uint8_t> MakePacket(uint16_t command, uint16_t session_id, uint16_t& reply_id,
                                const std::vector<uint8_t>& data) {
  // pyzk: checksum over header with *current* reply_id, then reply_id = (reply_id+1) % 65535
  // and the transmitted header uses the incremented reply_id.
  std::vector<uint8_t> body;
  WriteU16(body, command);
  WriteU16(body, 0);  // checksum placeholder
  WriteU16(body, session_id);
  WriteU16(body, reply_id);
  body.insert(body.end(), data.begin(), data.end());
  uint16_t chk = Checksum(body);
  reply_id = static_cast<uint16_t>(reply_id + 1);
  if (reply_id >= 65535) reply_id = static_cast<uint16_t>(reply_id - 65535);
  body.clear();
  WriteU16(body, command);
  WriteU16(body, chk);
  WriteU16(body, session_id);
  WriteU16(body, reply_id);
  body.insert(body.end(), data.begin(), data.end());

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

// Score a candidate name segment for DG-600 USERTEMP fields.
// Prefer pure ASCII letter names; treat high-bit tokens (e.g. d0 e7 4f) as garbage.
int ScoreNameSegment(const std::string& s) {
  int letters = 0;
  int digits = 0;
  int high = 0;
  int other = 0;
  for (unsigned char c : s) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
      ++letters;
    else if (c >= '0' && c <= '9')
      ++digits;
    else if (c >= 128)
      ++high;
    else
      ++other;
  }
  if (high > 0) {
    // Binary/GBK stub before NUL — never preferred over ASCII.
    return -10000 - high * 10 + letters;
  }
  return letters * 100 + digits * 10 + static_cast<int>(s.size()) - other * 5;
}

// Extract best printable C-string inside a fixed field.
// DG-600 USERTEMP name field often packs a short token + NUL + ASCII name.
// Stopping at the first NUL (old behavior) yields only the token, which becomes
// "??O" after UTF-8 sanitize on the gateway/server path.
std::string CleanTextField(const uint8_t* p, size_t len) {
  std::string best;
  int best_score = -1000000;
  size_t i = 0;
  while (i < len) {
    while (i < len && p[i] == 0) ++i;
    if (i >= len) break;
    std::string seg;
    while (i < len && p[i] != 0) {
      unsigned char c = p[i++];
      if (c >= 32) seg.push_back(static_cast<char>(c));
    }
    seg = Trim(seg);
    if (seg.empty()) continue;
    int sc = ScoreNameSegment(seg);
    if (sc > best_score) {
      best_score = sc;
      best = seg;
    }
  }
  // Drop high-bit stubs when no ASCII name was enrolled on the terminal.
  if (best_score < 0) return {};
  return best;
}

std::string BytesToHex(const uint8_t* data, size_t len) {
  return HexEncode(data, len);
}

std::string BytesToHex(const std::vector<uint8_t>& v) { return BytesToHex(v.data(), v.size()); }

}  // namespace

std::string RawBlob::hex() const { return HexEncode(bytes.data(), bytes.size()); }

uint32_t EncodeZkTime(int year, int month, int day, int hour, int minute, int second) {
  return static_cast<uint32_t>(((year - 2000) * 12 * 31 + (month - 1) * 31 + (day - 1)) *
                                   (24 * 60 * 60) +
                               (hour * 60 + minute) * 60 + second);
}

bool DecodeZkTime(uint32_t t, int& year, int& month, int& day, int& hour, int& minute,
                  int& second) {
  second = static_cast<int>(t % 60);
  minute = static_cast<int>((t / 60) % 60);
  hour = static_cast<int>((t / 3600) % 24);
  day = static_cast<int>(((t / (3600 * 24)) % 31) + 1);
  month = static_cast<int>(((t / (3600 * 24 * 31)) % 12) + 1);
  year = static_cast<int>((t / (3600 * 24 * 31 * 12)) + 2000);
  return year >= 2000 && year <= 2099 && month >= 1 && month <= 12 && day >= 1 && day <= 31;
}

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

const char* PrivilegeText(int privilege) {
  switch (privilege) {
    case 0: return "user";
    case 2: return "enroller";
    case 6: return "admin";
    case 14: return "super_admin";
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
    err = "Connection timeout";
    CloseSocket();
    return false;
  }
  int so_error = 0;
  socklen_t len = sizeof(so_error);
  getsockopt(fd_, SOL_SOCKET, SO_ERROR, &so_error, &len);
  if (so_error != 0) {
    err = std::string("Connection failed: ") + std::strerror(so_error);
    CloseSocket();
    return false;
  }
  SetNonBlocking(fd_, false);
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
    err = "Connection timeout";
    return false;
  }
  uint8_t header[8];
  size_t got = 0;
  while (got < sizeof(header)) {
    ssize_t n = ::recv(fd_, header + got, sizeof(header) - got, 0);
    if (n <= 0) {
      err = "Device disconnected";
      return false;
    }
    got += static_cast<size_t>(n);
  }
  if (header[0] != 0x50 || header[1] != 0x50 || header[2] != 0x82 || header[3] != 0x7D) {
    err = "Invalid response: bad packet magic";
    return false;
  }
  uint32_t size = ReadU32(header + 4);
  if (size < 8 || size > 1024 * 1024) {
    err = "Invalid response: bad packet size";
    return false;
  }
  std::vector<uint8_t> body(size);
  got = 0;
  while (got < size) {
    if (!WaitReadable(fd_, timeout_ms)) {
      err = "Connection timeout";
      return false;
    }
    ssize_t n = ::recv(fd_, body.data() + got, size - got, 0);
    if (n <= 0) {
      err = "Device disconnected";
      return false;
    }
    got += static_cast<size_t>(n);
  }
  command = ReadU16(body.data());
  // session_id is echoed/assigned by device in response header (pyzk uses this)
  session_id_ = ReadU16(body.data() + 4);
  // reply_id counter is owned by MakePacket (increments on send). Do NOT overwrite from
  // response the way older code did — that desyncs checksum vs pyzk.
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
      err = "Device disconnected";
      return false;
    }
    sent += static_cast<size_t>(n);
  }
  if (!RecvPacket(reply, reply_cmd, err, timeout_ms)) return false;
  if (reply_cmd == CMD_ACK_UNAUTH) {
    err = "Authentication failed (device unauthorized — need comm password?)";
    return false;
  }
  if (reply_cmd == CMD_ACK_ERROR) {
    err = "Unsupported command or device ACK_ERROR";
    return false;
  }
  return true;
}

bool ZkDevice::Handshake(std::string& err) {
  session_id_ = 0;
  reply_id_ = 65534;  // pyzk: USHRT_MAX - 1
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_CONNECT, {}, reply, cmd, err)) return false;
  return true;
}

bool ZkDevice::Authenticate(int password, std::string& err) {
  if (password == 0) return true;
  constexpr uint16_t CMD_AUTH = 1102;
  uint32_t key = static_cast<uint32_t>(password);
  uint32_t session = session_id_;
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
  static const uint8_t xor_key[4] = {0x5A, 0x4B, 0x53, 0x4F};  // ZKSO
  for (int i = 0; i < 4; ++i) data[i] ^= xor_key[i];
  std::swap(data[0], data[2]);
  std::swap(data[1], data[3]);
  for (int i = 0; i < 4; ++i) data[i] = static_cast<uint8_t>((~data[i]) & 0xFF);

  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_AUTH, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK) {
    err = "Authentication failed";
    return false;
  }
  return true;
}

bool ZkDevice::EnableDevice(bool enable, std::string& err, int timeout_ms) {
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  return SendCommand(enable ? CMD_ENABLEDEVICE : CMD_DISABLEDEVICE, {}, reply, cmd, err,
                     timeout_ms > 0 ? timeout_ms : 5000);
}

bool ZkDevice::RecoverDevice(std::string& err) {
  // Soft enable only. Bulk pulls no longer call DisableDevice; hammering Enable + hard
  // reconnect after ATTLOG/USERTEMP is what freezes the panel (Enable times out 5–10s).
  if (!connected_) {
    err = "not connected";
    return false;
  }
  if (EnableDevice(true, err, 1500)) {
    err.clear();
    return true;
  }
  LogWarning("RecoverDevice soft Enable failed (ignored): " + err);
  return false;
}

bool ZkDevice::ClearAttendanceLogs(std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  // pyzk clear_attendance sends CMD_CLEAR_ATTLOG without DisableDevice / RecoverDevice.
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  bool ok = SendCommand(CMD_CLEAR_ATTLOG, {}, reply, cmd, err, 10000);
  if (ok) {
    std::string e_ref;
    uint16_t rcmd = 0;
    SendCommand(CMD_REFRESHDATA, {}, reply, rcmd, e_ref, 3000);
    LogInfo("ClearAttendanceLogs ok");
  } else {
    LogWarning("ClearAttendanceLogs failed: " + err);
  }
  return ok;
}

bool ZkDevice::GetString(uint16_t /*command*/, const std::string& param, std::string& value,
                         std::string& err) {
  auto r = ProbeOption(param);
  if (r.status == "FAILED" || r.status == "NOT_SUPPORTED") {
    err = r.error.empty() ? r.status : r.error;
    value.clear();
    return false;
  }
  value = r.value;
  err.clear();
  return true;
}

DeviceOptionResult ZkDevice::ProbeOption(const std::string& key) {
  DeviceOptionResult r;
  r.key = key;
  if (!connected_) {
    r.status = "FAILED";
    r.error = "not connected";
    return r;
  }
  std::vector<uint8_t> data(key.begin(), key.end());
  data.push_back(0);
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  std::string err;
  if (!SendCommand(CMD_DEVICE, data, reply, cmd, err)) {
    // ACK_ERROR often means unsupported option on this firmware
    if (err.find("ACK_ERROR") != std::string::npos ||
        err.find("Unsupported command") != std::string::npos) {
      r.status = "NOT_SUPPORTED";
    } else {
      r.status = "FAILED";
    }
    r.error = err;
    r.reply_cmd = cmd;
    return r;
  }
  r.reply_cmd = cmd;
  r.raw_hex = BytesToHex(reply);
  if (cmd != CMD_ACK_OK && cmd != CMD_ACK_DATA) {
    r.status = "NOT_SUPPORTED";
    r.error = "unexpected reply_cmd=" + std::to_string(cmd);
    return r;
  }
  if (reply.empty()) {
    r.status = "empty";
    return r;
  }
  std::string raw(reply.begin(), reply.end());
  auto eq = raw.find('=');
  if (eq != std::string::npos) r.value = CleanText(raw.substr(eq + 1));
  else r.value = CleanText(raw);
  if (r.value.empty()) {
    r.status = "empty";
  } else {
    r.status = "ok";
  }
  return r;
}

bool ZkDevice::Connect(const std::string& ip, int port, int password, int timeout_sec,
                       std::string& err) {
  Disconnect();
  ip_ = ip;
  port_ = port;
  password_ = password;
  timeout_sec_ = timeout_sec > 0 ? timeout_sec : 10;
  LogInfo("Connecting to " + ip_ + ":" + std::to_string(port_) + " via " + ProtocolName());
  if (!CreateSocket(err)) {
    LogError("Connection failed: " + err);
    return false;
  }
  if (!Handshake(err)) {
    LogError("Handshake failed: " + err);
    CloseSocket();
    return false;
  }
  if (!Authenticate(password, err)) {
    LogError("Authentication failed: " + err);
    CloseSocket();
    return false;
  }
  std::string e2;
  EnableDevice(true, e2, 2000);  // best-effort, short timeout — do not block panel
  connected_ = true;
  info_.ip = ip_;
  info_.port = port_;
  LogInfo("Connection success: " + ip_ + ":" + std::to_string(port_) + " protocol=" +
          ProtocolName());
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

bool ZkDevice::GetTime(DeviceTime& out, std::string& err) {
  out = DeviceTime{};
  if (!connected_) {
    err = "not connected";
    return false;
  }
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_GET_TIME, {}, reply, cmd, err)) return false;
  out.raw_hex = BytesToHex(reply);
  if (reply.size() < 4) {
    err = "Invalid response: GET_TIME payload too short";
    return false;
  }
  out.encoded = ReadU32(reply.data());
  if (!DecodeZkTime(out.encoded, out.year, out.month, out.day, out.hour, out.minute, out.second)) {
    err = "Parse error: invalid ZK time encoding";
    return false;
  }
  char buf[32];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d", out.year, out.month, out.day,
                out.hour, out.minute, out.second);
  out.iso_local = buf;
  return true;
}

bool ZkDevice::SetTime(int year, int month, int day, int hour, int minute, int second,
                       std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  uint32_t enc = EncodeZkTime(year, month, day, hour, minute, second);
  std::vector<uint8_t> data;
  WriteU32(data, enc);
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_SET_TIME, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK) {
    err = "SET_TIME failed reply_cmd=" + std::to_string(cmd);
    return false;
  }
  return true;
}

bool ZkDevice::ReadFreeSizes(DeviceInfo& info, RawBlob& raw, std::string& err) {
  raw = RawBlob{};
  raw.label = "CMD_GET_FREE_SIZES";
  if (!connected_) {
    err = "not connected";
    raw.status = "FAILED";
    raw.error = err;
    return false;
  }
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_GET_FREE_SIZES, {}, reply, cmd, err)) {
    raw.status = "FAILED";
    raw.error = err;
    raw.reply_cmd = cmd;
    return false;
  }
  raw.reply_cmd = cmd;
  raw.bytes = reply;
  raw.status = reply.empty() ? "empty" : "ok";
  // pyzk layout: various offsets; common: users at 4, fingers at 24? — parse cautiously
  // ZK free sizes typically 92+ bytes. Users count often at offset 4 (u32), records at 8 or similar.
  if (reply.size() >= 8) {
    info.user_count = static_cast<int>(ReadU32(reply.data() + 4));
  }
  if (reply.size() >= 16) {
    info.finger_count = static_cast<int>(ReadU32(reply.data() + 8));
  }
  if (reply.size() >= 20) {
    info.log_count = static_cast<int>(ReadU32(reply.data() + 12));
  }
  // Some firmwares use different packing; keep raw always.
  return true;
}

bool ZkDevice::ReadDeviceInfo(DeviceInfo& out, std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  out = DeviceInfo{};
  out.ip = ip_;
  out.port = port_;

  auto serial = ProbeOption("~SerialNumber");
  if (serial.status == "ok") out.serial = serial.value;

  auto oem = ProbeOption("~OEMVendor");
  if (oem.status == "ok") out.platform = oem.value;
  if (out.platform.empty()) {
    auto plat = ProbeOption("~Platform");
    if (plat.status == "ok") out.platform = plat.value;
  }

  auto dname = ProbeOption("~DeviceName");
  if (dname.status == "ok") out.device_name = dname.value;
  auto firm = ProbeOption("FirmVer");
  if (firm.status == "ok") out.firmware = firm.value;
  if (out.firmware.empty() && dname.status == "ok") out.firmware = dname.value;

  DeviceTime dt;
  if (GetTime(dt, err)) {
    out.device_time_local = dt.iso_local;
    out.device_time_iso = FormatIso8601Offset(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second, tz_offset_min_);
  } else {
    LogWarning("GET_TIME failed: " + err);
    err.clear();
  }

  RawBlob sizes;
  std::string e2;
  if (!ReadFreeSizes(out, sizes, e2)) {
    LogDebug("GET_FREE_SIZES: " + e2);
  }

  info_ = out;
  return true;
}

bool ZkDevice::FetchLargeData(uint16_t command, const std::vector<uint8_t>& req, RawBlob& raw,
                              std::string& err) {
  raw = RawBlob{};
  raw.label = "cmd_" + std::to_string(command);
  const int bulk_timeout_ms = std::max(timeout_sec_ * 1000, 120000);
  // No DisableDevice / RecoverDevice — same as pyzk. Post-bulk Enable was timing out and
  // freezing the panel; Disconnect (CMD_EXIT) is enough to release the device.
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  LogInfo("Bulk request cmd=" + std::to_string(command) + " timeout_ms=" +
          std::to_string(bulk_timeout_ms));
  bool ok = SendCommand(command, req, reply, cmd, err, bulk_timeout_ms);
  if (!ok) {
    raw.status = "FAILED";
    raw.error = err;
    raw.reply_cmd = cmd;
    return false;
  }
  raw.reply_cmd = cmd;
  std::vector<uint8_t> blob;
  if (cmd == CMD_PREPARE_DATA && reply.size() >= 4) {
    uint32_t size = ReadU32(reply.data());
    LogInfo("PREPARE_DATA size=" + std::to_string(size));
    blob.reserve(size);
    while (blob.size() < size) {
      std::vector<uint8_t> chunk;
      uint16_t c = 0;
      if (!RecvPacket(chunk, c, err, bulk_timeout_ms)) {
        raw.status = "FAILED";
        raw.error = err + " (got " + std::to_string(blob.size()) + "/" + std::to_string(size) + ")";
        raw.bytes = blob;
        return false;
      }
      if (c == CMD_DATA) {
        blob.insert(blob.end(), chunk.begin(), chunk.end());
        if (blob.size() % 50000 < chunk.size()) {
          LogDebug("bulk progress " + std::to_string(blob.size()) + "/" + std::to_string(size));
        }
      } else if (c == CMD_ACK_OK) {
        break;
      } else {
        LogWarning("bulk unexpected cmd=" + std::to_string(c) + " len=" +
                   std::to_string(chunk.size()));
        break;
      }
    }
    std::vector<uint8_t> freply;
    uint16_t fcmd = 0;
    std::string e_free;
    SendCommand(CMD_FREE_DATA, {}, freply, fcmd, e_free, 3000);
  } else if (cmd == CMD_DATA || cmd == CMD_ACK_OK) {
    blob = reply;
  } else {
    raw.status = "FAILED";
    raw.error = "unexpected reply_cmd=" + std::to_string(cmd);
    raw.bytes = reply;
    return false;
  }
  raw.bytes = std::move(blob);
  raw.status = raw.bytes.empty() ? "empty" : "ok";
  LogInfo("Bulk done cmd=" + std::to_string(command) + " bytes=" + std::to_string(raw.bytes.size()));
  return true;
}


bool ZkDevice::FetchLargeDataBuffered(uint16_t command, int32_t fct, int32_t ext, RawBlob& raw,
                                      std::string& err) {
  raw = RawBlob{};
  raw.label = "buf_cmd_" + std::to_string(command);
  const int bulk_timeout_ms = std::max(timeout_sec_ * 1000, 180000);
  // IMPORTANT: Do NOT DisableDevice / RecoverDevice here.
  // Dg600ReaderPy/pyzk read_with_buffer pulls USERTEMP/ATTLOG without disabling;
  // EnableDevice after bulk was freezing the panel when it timed out.

  // pyzk: pack('<bhii', 1, command, fct, ext)
  std::vector<uint8_t> prep;
  prep.push_back(1);
  WriteU16(prep, command);
  auto write_i32 = [](std::vector<uint8_t>& b, int32_t v) {
    uint32_t u = static_cast<uint32_t>(v);
    WriteU32(b, u);
  };
  write_i32(prep, fct);
  write_i32(prep, ext);

  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  // Short prepare timeout: if firmware lacks 1503 or hangs, fall back to stream quickly.
  const int prepare_timeout_ms = std::min(bulk_timeout_ms, 20000);
  LogInfo("Buffered prepare cmd=" + std::to_string(command) + " fct=" + std::to_string(fct) +
          " prepare_timeout_ms=" + std::to_string(prepare_timeout_ms));
  if (!SendCommand(CMD_PREPARE_BUFFER, prep, reply, cmd, err, prepare_timeout_ms)) {
    raw.status = "FAILED";
    raw.error = err;
    raw.reply_cmd = cmd;
    return false;
  }
  raw.reply_cmd = cmd;
  std::vector<uint8_t> blob;

  if (cmd == CMD_DATA) {
    blob = std::move(reply);
  } else {
    // pyzk: size = unpack('I', data[1:5])
    if (reply.size() < 5) {
      raw.status = "FAILED";
      raw.error = "PREPARE_BUFFER short reply len=" + std::to_string(reply.size());
      return false;
    }
    uint32_t size = ReadU32(reply.data() + 1);
    LogInfo("PREPARE_BUFFER size=" + std::to_string(size));
    if (size == 0) {
      blob.clear();
    } else if (size > 64u * 1024u * 1024u) {
      raw.status = "FAILED";
      raw.error = "PREPARE_BUFFER size too large: " + std::to_string(size);
      return false;
    } else {
      blob.reserve(size);
      uint32_t start = 0;
      bool first_chunk = true;
      while (start < size) {
        uint32_t need = size - start;
        if (need > BUF_MAX_CHUNK) need = BUF_MAX_CHUNK;
        std::vector<uint8_t> req;
        WriteU32(req, start);
        WriteU32(req, need);
        bool got = false;
        std::string last_err;
        std::vector<uint8_t> creply;
        for (int attempt = 0; attempt < 3; ++attempt) {
          creply.clear();
          uint16_t ccmd = 0;
          if (!SendCommand(CMD_READ_BUFFER, req, creply, ccmd, last_err, bulk_timeout_ms)) {
            continue;
          }
          if (ccmd == CMD_DATA || ccmd == CMD_ACK_OK || ccmd == CMD_ACK_DATA) {
            got = true;
            break;
          }
          last_err = "READ_BUFFER unexpected cmd=" + std::to_string(ccmd);
        }
        if (!got) {
          raw.status = "FAILED";
          raw.error = last_err + " at offset " + std::to_string(start);
          raw.bytes = blob;
          return false;
        }
        if (creply.empty()) {
          // Some firmwares end early with empty DATA; accept what we have.
          break;
        }
        // DG-600 often returns ~1KiB per READ_BUFFER. Advancing by requested `need`
        // (pyzk uses start = len(buffer)) skipped most of the table and falsely "succeeded".
        // Tiny chunks on a large buffer also mean hundreds of RTTs → panel lag; abort to stream.
        if (first_chunk && creply.size() < 4096 && size > 16u * 1024u) {
          std::vector<uint8_t> freply;
          uint16_t fcmd = 0;
          std::string e_free;
          SendCommand(CMD_FREE_DATA, {}, freply, fcmd, e_free, 3000);
          raw.status = "FAILED";
          raw.error = "buffered chunks too small (" + std::to_string(creply.size()) +
                      "B); prefer stream";
          LogWarning(raw.error);
          return false;
        }
        first_chunk = false;
        blob.insert(blob.end(), creply.begin(), creply.end());
        start += static_cast<uint32_t>(creply.size());
        if (blob.size() <= creply.size() || blob.size() % (64u * 1024u) < creply.size()) {
          LogInfo("buffer progress " + std::to_string(blob.size()) + "/" + std::to_string(size));
        }
      }
    }
    std::vector<uint8_t> freply;
    uint16_t fcmd = 0;
    std::string e_free;
    SendCommand(CMD_FREE_DATA, {}, freply, fcmd, e_free, 3000);
  }

  raw.bytes = std::move(blob);
  raw.status = raw.bytes.empty() ? "empty" : "ok";
  LogInfo("Buffered done cmd=" + std::to_string(command) + " bytes=" +
          std::to_string(raw.bytes.size()));
  return true;
}

bool ZkDevice::FetchLargeDataSmart(uint16_t command, int32_t fct, const std::vector<uint8_t>& legacy_req,
                                   RawBlob& raw, std::string& err) {
  auto reconnect = [&](std::string& e) -> bool {
    const std::string ip = ip_;
    const int port = port_;
    const int pw = password_;
    const int to = timeout_sec_;
    Disconnect();
    if (!Connect(ip, port, pw, to, e)) {
      e = "reconnect before fallback: " + e;
      return false;
    }
    return true;
  };

  // DG-600 READ_BUFFER often returns ~1KiB chunks. For large ATTLOG that means hundreds of
  // RTTs (panel lag). Prefer continuous PREPARE_DATA stream for attendance.
  if (command == CMD_ATTLOG_RRQ) {
    if (FetchLargeData(command, legacy_req, raw, err)) return true;
    LogWarning("stream attlog failed, try buffered: " + err);
    std::string e_re;
    if (!reconnect(e_re)) {
      err = e_re;
      return false;
    }
    return FetchLargeDataBuffered(command, fct, 0, raw, err);
  }

  std::string buf_err;
  if (FetchLargeDataBuffered(command, fct, 0, raw, buf_err)) {
    return true;
  }
  LogWarning("buffered read failed, fallback stream: " + buf_err);
  std::string e_re;
  if (!reconnect(e_re)) {
    err = e_re;
    return false;
  }
  return FetchLargeData(command, legacy_req, raw, err);
}


bool ZkDevice::ReadUsersRaw(std::vector<UserRecord>& out, RawBlob& raw, std::string& err) {
  out.clear();
  if (!connected_) {
    err = "not connected";
    return false;
  }
  std::vector<uint8_t> data = {0x05};
  if (!FetchLargeDataSmart(CMD_USERTEMP_RRQ, FCT_USER, data, raw, err)) return false;
  raw.label = "CMD_USERTEMP_RRQ_users";

  // Buffered path may prefix a u32 total size (pyzk); stream path is raw 72-byte records.
  size_t base = 0;
  if (raw.bytes.size() >= 4) {
    uint32_t maybe = ReadU32(raw.bytes.data());
    if (maybe > 0 && maybe + 4 == raw.bytes.size()) {
      base = 4;
    } else if ((raw.bytes.size() % 72) != 0 && ((raw.bytes.size() - 4) % 72) == 0) {
      base = 4;
    }
  }

  const size_t rec = 72;
  for (size_t off = base; off + rec <= raw.bytes.size(); off += rec) {
    const uint8_t* p = raw.bytes.data() + off;
    UserRecord u;
    u.uid = ReadU16(p);
    u.privilege = p[2];
    u.password = CleanTextField(p + 3, 8);
    u.name = CleanTextField(p + 11, 24);
    u.card = ReadU32(p + 35);
    u.user_id = CleanTextField(p + 48, 24);
    if (u.user_id.empty()) {
      if (u.uid == 0) continue;
      u.user_id = std::to_string(u.uid);
    }
    u.enabled = true;
    u.raw_hex = BytesToHex(p, rec);
    out.push_back(u);
  }
  users_cache_ = out;
  return true;
}

bool ZkDevice::ReadUsers(std::vector<UserRecord>& out, std::string& err) {
  RawBlob raw;
  return ReadUsersRaw(out, raw, err);
}

bool ZkDevice::ReadAttendanceLogsRaw(std::vector<AttendanceEvent>& out, RawBlob& raw,
                                     std::string& err) {
  out.clear();
  if (!connected_) {
    err = "not connected";
    return false;
  }
  bool was_live = live_;
  if (was_live) StopLiveCapture();

  if (!FetchLargeDataSmart(CMD_ATTLOG_RRQ, 0, {}, raw, err)) {
    if (was_live) {
      std::string e2;
      StartLiveCapture(e2);
    }
    return false;
  }
  raw.label = "CMD_ATTLOG_RRQ";
  // Some buffered firmwares prefix attlog with u32 size.
  if (raw.bytes.size() >= 4) {
    uint32_t maybe = ReadU32(raw.bytes.data());
    if (maybe > 0 && maybe + 4 == raw.bytes.size()) {
      raw.bytes.erase(raw.bytes.begin(), raw.bytes.begin() + 4);
    }
  }

  if (was_live) {
    std::string e2;
    StartLiveCapture(e2);
  }

  const size_t rec = 40;
  std::string received = UtcNowIso8601();
  for (size_t off = 0; off + 16 <= raw.bytes.size();) {
    size_t step = (off + rec <= raw.bytes.size()) ? rec : 16;
    const uint8_t* p = raw.bytes.data() + off;
    AttendanceEvent ev;
    ev.from_live = false;
    ev.received_at_iso = received;

    char uidstr[28] = {};
    std::memcpy(uidstr, p, 24);
    ev.user_id = CleanTextField(p, 24);
    size_t time_off = 24;
    if (ev.user_id.empty()) {
      uint16_t uid = ReadU16(p);
      if (uid == 0) {
        off += step;
        continue;
      }
      ev.user_id = std::to_string(uid);
      time_off = 4;
      step = 16;
    }
    if (time_off + 4 > raw.bytes.size() - off) break;
    uint32_t t = ReadU32(p + time_off);
    if (!DecodeZkTime(t, ev.year, ev.month, ev.day, ev.hour, ev.minute, ev.second)) {
      off += step;
      continue;
    }
    ev.timestamp_iso = FormatIso8601Offset(ev.year, ev.month, ev.day, ev.hour, ev.minute, ev.second, tz_offset_min_);
    if (time_off + 4 < step) ev.verify_mode = p[time_off + 4];
    if (time_off + 5 < step) ev.inout_mode = p[time_off + 5];
    if (time_off + 6 < step) ev.work_code = p[time_off + 6];
    ev.raw_hex = BytesToHex(p, step);
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

bool ZkDevice::ReadAttendanceLogs(std::vector<AttendanceEvent>& out, std::string& err) {
  RawBlob raw;
  return ReadAttendanceLogsRaw(out, raw, err);
}

bool ZkDevice::StartLiveCapture(std::string& err) {
  if (!connected_) {
    err = "not connected";
    return false;
  }
  std::vector<uint8_t> data;
  WriteU32(data, 0xFFFF);
  std::vector<uint8_t> reply;
  uint16_t cmd = 0;
  if (!SendCommand(CMD_REG_EVENT, data, reply, cmd, err)) return false;
  if (cmd != CMD_ACK_OK) {
    err = "RegEvent failed";
    return false;
  }
  live_ = true;
  LogInfo("Realtime live capture ON (RegEvent mask=0xFFFF)");
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
  if (data.size() < 12) return false;

  ev = AttendanceEvent{};
  ev.from_live = true;
  ev.received_at_iso = UtcNowIso8601();
  ev.raw_hex = BytesToHex(data);

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

  auto fill_local_now = [&]() {
    std::time_t now = std::time(nullptr);
    std::tm tmb{};
    localtime_r(&now, &tmb);
    ev.year = tmb.tm_year + 1900;
    ev.month = tmb.tm_mon + 1;
    ev.day = tmb.tm_mday;
    ev.hour = tmb.tm_hour;
    ev.minute = tmb.tm_min;
    ev.second = tmb.tm_sec;
  };

  // DG-600 live packets often pad PIN to 24 bytes; time at offset 8 is zeros → year 2000.
  // Try candidates: after UID, fixed 24 (SSR pad), then 8. Reject year < 2020.
  size_t time_off = 0;
  bool time_ok = false;
  size_t candidates[] = {i, 24, 8};
  for (size_t cand : candidates) {
    if (cand + 4 > data.size()) continue;
    uint32_t enc = ReadU32(data.data() + cand);
    int y = 0, m = 0, d = 0, h = 0, mi = 0, s = 0;
    if (!DecodeZkTime(enc, y, m, d, h, mi, s)) continue;
    if (y < 2020 || y > 2038) continue;
    ev.year = y;
    ev.month = m;
    ev.day = d;
    ev.hour = h;
    ev.minute = mi;
    ev.second = s;
    time_off = cand;
    time_ok = true;
    break;
  }
  if (!time_ok) {
    fill_local_now();
    time_off = (i + 4 <= data.size()) ? i : 0;
  }
  ev.timestamp_iso = FormatIso8601Offset(ev.year, ev.month, ev.day, ev.hour, ev.minute, ev.second, tz_offset_min_);

  size_t status_off = time_off + 4;
  if (time_ok && status_off < data.size()) ev.verify_mode = data[status_off];
  if (time_ok && status_off + 1 < data.size()) ev.inout_mode = data[status_off + 1];
  if (time_ok && status_off + 2 < data.size()) ev.work_code = data[status_off + 2];

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
    return true;
  }
  std::vector<uint8_t> payload;
  uint16_t cmd = 0;
  if (!RecvPacket(payload, cmd, err, wait_ms > 0 ? wait_ms : 1000)) {
    if (err.find("timeout") != std::string::npos || err == "Connection timeout") {
      err.clear();
      return true;
    }
    LogError("Device disconnected: " + err);
    return false;
  }

  auto try_parse = [&](const std::vector<uint8_t>& data) {
    AttendanceEvent ev;
    if (ParseAttEvent(data, ev)) {
      ev.raw_cmd = cmd;
      LogInfo("Attendance event received user=" + ev.user_id + " ts=" + ev.timestamp_iso +
              " verify=" + std::to_string(ev.verify_mode) + " inout=" +
              std::to_string(ev.inout_mode));
      if (cb) cb(ev);
    }
  };

  if (cmd == EF_ATTLOG || cmd == 1 || cmd == CMD_REG_EVENT || cmd == CMD_ACK_DATA ||
      cmd == CMD_DATA) {
    try_parse(payload);
  }
  if (payload.size() > 1 && payload[0] == 1) {
    std::vector<uint8_t> slice(payload.begin() + 1, payload.end());
    try_parse(slice);
  }
  // Always keep unknown realtime packets in debug
  LogDebug("live packet cmd=" + std::to_string(cmd) + " len=" + std::to_string(payload.size()) +
           " hex=" + BytesToHex(payload).substr(0, 128));
  return true;
}

}  // namespace cg
