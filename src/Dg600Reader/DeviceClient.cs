using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;

namespace Dg600Reader
{
    public sealed class DeviceClient : IDisposable
    {
        public const int DefaultPort = 4370;
        public const int DefaultMachineNumber = 1;

        private dynamic _zk;
        private bool _connected;
        private bool _disposed;
        private bool _eventsHooked;

        private static readonly Guid ZkemEventsIid = new Guid("cf83b580-5d32-4c65-b44e-bedc750cdfa8");
        private AttTransactionExHandler _attExHandler;
        private AttTransactionHandler _attHandler;
        private VerifyHandler _verifyHandler;
        private HidNumHandler _hidHandler;
        private string _lastVerifyUserId = "";
        private DateTime _lastVerifyAt = DateTime.MinValue;
        private int _lastLogCount = -1;
        private AttendanceRecord _anonymousPunch;

        public delegate void AttTransactionExHandler(string enrollNumber, int isInvalid, int attState, int verifyMethod, int year, int month, int day, int hour, int minute, int second, int workCode);
        public delegate void AttTransactionHandler(int enrollNumber, int isInvalid, int attState, int verifyMethod, int year, int month, int day, int hour, int minute, int second);
        public delegate void VerifyHandler(int userId);
        public delegate void HidNumHandler(int cardNumber);

        public event Action<AttendanceRecord> AttendanceReceived;

        public bool IsConnected { get { return _connected; } }
        public int MachineNumber { get; private set; }
        public string IpAddress { get; private set; }
        public int Port { get; private set; }

        public DeviceClient()
        {
            MachineNumber = DefaultMachineNumber;
            var type = Type.GetTypeFromProgID("zkemkeeper.ZKEM.1");
            if (type == null)
            {
                throw new InvalidOperationException(
                    "Không tìm thấy COM zkemkeeper.ZKEM.1. Hãy chạy tools\\register-sdk.bat bằng quyền Administrator (bản 32-bit).");
            }
            _zk = Activator.CreateInstance(type);
        }

        public void Connect(string ip, int port, int commPassword)
        {
            EnsureAlive();
            if (_connected)
                Disconnect();

            _zk.SetCommPassword(commPassword);
            if (!_zk.Connect_Net(ip, port))
                throw NewDeviceException("Không kết nối được máy chấm công " + ip + ":" + port + ".");

            _connected = true;
            IpAddress = ip;
            Port = port;
            try
            {
                _zk.EnableDevice(MachineNumber, true);
            }
            catch
            {
            }
        }

        public void Disconnect()
        {
            if (_zk == null || !_connected)
                return;
            try
            {
                UnhookEvents();
                _zk.RegEvent(MachineNumber, 0);
            }
            catch
            {
            }
            try
            {
                _zk.EnableDevice(MachineNumber, true);
            }
            catch
            {
            }
            try
            {
                _zk.Disconnect();
            }
            catch
            {
            }
            _connected = false;
        }

        public DeviceInfo ReadDeviceInfo()
        {
            EnsureConnected();
            var info = new DeviceInfo
            {
                IpAddress = IpAddress,
                Port = Port
            };

            string firmware = "";
            if (_zk.GetFirmwareVersion(MachineNumber, out firmware))
                info.Firmware = firmware;

            string serial = "";
            if (_zk.GetSerialNumber(MachineNumber, out serial))
                info.SerialNumber = serial;

            string product = "";
            if (_zk.GetProductCode(MachineNumber, out product))
                info.ProductCode = product;

            string sdk = "";
            if (_zk.GetSDKVersion(ref sdk))
                info.SdkVersion = sdk;

            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
            if (_zk.GetDeviceTime(MachineNumber, ref year, ref month, ref day, ref hour, ref minute, ref second))
            {
                try
                {
                    info.DeviceTime = new DateTime(year, month, day, hour, minute, second);
                }
                catch (ArgumentOutOfRangeException)
                {
                    info.DeviceTime = DateTime.MinValue;
                }
            }

            int userCount = 0;
            if (_zk.GetDeviceStatus(MachineNumber, 2, ref userCount))
                info.UserCount = userCount;

            int logCount = 0;
            if (_zk.GetDeviceStatus(MachineNumber, 6, ref logCount))
                info.LogCount = logCount;

            return info;
        }

        public IList<UserRecord> ReadUsers()
        {
            EnsureConnected();
            var users = new List<UserRecord>();
            WithDeviceLocked(delegate
            {
                if (!_zk.ReadAllUserID(MachineNumber))
                    throw NewDeviceException("Không đọc được danh sách nhân viên.");

                string userId = "";
                string name = "";
                string password = "";
                int privilege = 0;
                bool enabled = false;
                while (_zk.SSR_GetAllUserInfo(MachineNumber, out userId, out name, out password, out privilege, out enabled))
                {
                    users.Add(new UserRecord
                    {
                        UserId = Clean(userId),
                        Name = Clean(name),
                        Privilege = privilege,
                        Enabled = enabled,
                        Password = Clean(password)
                    });
                }
            });
            users.Sort((a, b) => string.Compare(a.UserId, b.UserId, StringComparison.Ordinal));
            return users;
        }

        public void UpdateUserName(string userId, string newName)
        {
            EnsureConnected();
            if (string.IsNullOrEmpty(userId))
                throw new InvalidOperationException("Thiếu mã nhân viên.");

            if (newName != null && newName.Length > 24)
                newName = newName.Substring(0, 24);
            string currentName = "";
            string password = "";
            int privilege = 0;
            bool enabled = true;
            WithDeviceLocked(delegate
            {
                if (!_zk.SSR_GetUserInfo(MachineNumber, userId, out currentName, out password, out privilege, out enabled))
                    throw NewDeviceException("Không đọc được nhân viên " + userId + " trên máy.");
                if (!_zk.SSR_SetUserInfo(MachineNumber, userId, newName ?? "", password ?? "", privilege, enabled))
                    throw NewDeviceException("Không cập nhật được tên nhân viên " + userId + " lên máy.");
                _zk.RefreshData(MachineNumber);
            });
        }

        public IList<AttendanceRecord> ReadAttendanceLogs(IDictionary<string, string> userNames)
        {
            EnsureConnected();
            var logs = new List<AttendanceRecord>();
            WithDeviceLocked(delegate
            {
                if (!_zk.ReadGeneralLogData(MachineNumber))
                    throw NewDeviceException("Không đọc được nhật ký chấm công.");
                logs.AddRange(DrainLogBuffer(userNames));
            });
            logs.Sort((a, b) => a.Timestamp.CompareTo(b.Timestamp));
            return logs;
        }

        public bool RegisterRealtime()
        {
            EnsureConnected();
            try
            {
                _zk.EnableDevice(MachineNumber, true);
            }
            catch
            {
            }
            try
            {
                _zk.ReadMark = true;
            }
            catch
            {
            }
            HookEvents();
            SnapshotLogCount();
            return _zk.RegEvent(MachineNumber, 65535);
        }

        public void UnregisterRealtime()
        {
            if (_zk == null || !_connected)
                return;
            try
            {
                _zk.RegEvent(MachineNumber, 0);
            }
            catch
            {
            }
            UnhookEvents();
        }

        public void PumpRealtime()
        {
            EnsureConnected();
            try
            {
                if (!_zk.ReadRTLog(MachineNumber))
                    return;
                int guard = 0;
                while (guard++ < 8 && _zk.GetRTLog(MachineNumber))
                {
                }
            }
            catch
            {
            }
        }

        public IList<AttendanceRecord> PollNewLogs(IDictionary<string, string> userNames)
        {
            EnsureConnected();
            PumpRealtime();
            return new List<AttendanceRecord>();
        }

        public AttendanceRecord TryIdentifyLastPunch(IDictionary<string, string> userNames)
        {
            EnsureConnected();
            PumpRealtime();
            var freshId = FreshVerifyUserId();
            if (!string.IsNullOrEmpty(freshId))
                return new AttendanceRecord
                {
                    UserId = freshId,
                    ReceivedAt = DateTime.Now,
                    Timestamp = DateTime.Now
                };

            DateTime deviceNow;
            if (!TryGetDeviceTime(out deviceNow))
                deviceNow = DateTime.Now;
            var matchFrom = deviceNow.AddSeconds(-30);

            var logs = FetchRecentLogs(userNames, deviceNow.AddMinutes(-3));
            for (int i = logs.Count - 1; i >= 0; i--)
            {
                var log = logs[i];
                if (string.IsNullOrEmpty(log.UserId) || log.UserId == "0")
                    continue;
                if (log.Timestamp >= matchFrom)
                    return log;
            }
            return null;
        }

        public int SnapshotLogCount()
        {
            int count = 0;
            try
            {
                if (_zk.GetDeviceStatus(MachineNumber, 6, ref count))
                    _lastLogCount = count;
            }
            catch
            {
            }
            return _lastLogCount;
        }

        private bool TryGetDeviceTime(out DateTime deviceNow)
        {
            deviceNow = DateTime.MinValue;
            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
            try
            {
                if (!_zk.GetDeviceTime(MachineNumber, ref year, ref month, ref day, ref hour, ref minute, ref second))
                    return false;
                deviceNow = new DateTime(year, month, day, hour, minute, second);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private List<AttendanceRecord> FetchRecentLogs(IDictionary<string, string> userNames, DateTime from)
        {
            var logs = new List<AttendanceRecord>();
            if (from.Year < 2000)
                from = DateTime.Now.AddMinutes(-3);
            try
            {
                if (_zk.ReadLastestLogData(MachineNumber, 1, from.Year, from.Month, from.Day, from.Hour, from.Minute, from.Second))
                    logs.AddRange(DrainLogBuffer(userNames));
            }
            catch
            {
            }
            foreach (var log in logs)
            {
                if (log.ReceivedAt == DateTime.MinValue)
                    log.ReceivedAt = DateTime.Now;
            }
            return logs;
        }

        public void SyncDeviceTime()
        {
            EnsureConnected();
            if (!_zk.SetDeviceTime(MachineNumber))
                throw NewDeviceException("Không đồng bộ được giờ máy chấm công.");
            _zk.RefreshData(MachineNumber);
        }

        public void Dispose()
        {
            if (_disposed)
                return;
            Disconnect();
            _zk = null;
            _disposed = true;
        }

        private List<AttendanceRecord> DrainLogBuffer(IDictionary<string, string> userNames)
        {
            var logs = new List<AttendanceRecord>();
            string userId = "";
            int verifyMode = 0;
            int inOutMode = 0;
            int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
            int workCode = 0;
            while (_zk.SSR_GetGeneralLogData(
                MachineNumber,
                out userId,
                out verifyMode,
                out inOutMode,
                out year,
                out month,
                out day,
                out hour,
                out minute,
                out second,
                ref workCode))
            {
                DateTime timestamp;
                try
                {
                    timestamp = new DateTime(year, month, day, hour, minute, second);
                }
                catch (ArgumentOutOfRangeException)
                {
                    continue;
                }

                string id = Clean(userId);
                string name = "";
                if (userNames != null)
                    userNames.TryGetValue(id, out name);

                    logs.Add(new AttendanceRecord
                    {
                        UserId = id,
                        UserName = name ?? "",
                        Timestamp = timestamp,
                        ReceivedAt = DateTime.Now,
                        VerifyMode = verifyMode,
                        InOutMode = inOutMode,
                        WorkCode = workCode
                    });
            }
            return logs;
        }

        private void WithDeviceLocked(Action action)
        {
            _zk.EnableDevice(MachineNumber, false);
            try
            {
                action();
            }
            finally
            {
                try
                {
                    _zk.EnableDevice(MachineNumber, true);
                }
                catch
                {
                }
            }
        }

        private void EnsureAlive()
        {
            if (_disposed || _zk == null)
                throw new ObjectDisposedException("DeviceClient");
        }

        private void EnsureConnected()
        {
            EnsureAlive();
            if (!_connected)
                throw new InvalidOperationException("Chưa kết nối máy chấm công.");
        }

        private Exception NewDeviceException(string message)
        {
            int error = 0;
            try
            {
                _zk.GetLastError(ref error);
            }
            catch
            {
            }
            return new InvalidOperationException(message + " Mã lỗi SDK: " + error + " (" + DescribeError(error) + ").");
        }

        private static string DescribeError(int error)
        {
            switch (error)
            {
                case 0: return "Không có lỗi / không có dữ liệu";
                case 1: return "Thao tác sai";
                case 4: return "Không có dữ liệu";
                case -1: return "Lệnh thất bại";
                case -2: return "Lệnh không được hỗ trợ";
                case -3: return "Tràn bộ đệm";
                case -4: return "Không kết nối được";
                case 100: return "Truyền dữ liệu thất bại";
                case 101: return "Kết nối bị hủy";
                default: return "Không rõ";
            }
        }

        private static string Clean(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            var chars = value.ToCharArray();
            var buffer = new char[chars.Length];
            int n = 0;
            for (int i = 0; i < chars.Length; i++)
            {
                if (chars[i] != '\0')
                    buffer[n++] = chars[i];
            }
            return new string(buffer, 0, n).Trim();
        }

        private void HookEvents()
        {
            if (_eventsHooked || _zk == null)
                return;
            _attExHandler = OnAttTransactionEx;
            _attHandler = OnAttTransaction;
            _verifyHandler = OnVerify;
            _hidHandler = OnHIDNum;
            try
            {
                ComEventsHelper.Combine(_zk, ZkemEventsIid, 17, _attExHandler);
                ComEventsHelper.Combine(_zk, ZkemEventsIid, 1, _attHandler);
                ComEventsHelper.Combine(_zk, ZkemEventsIid, 9, _verifyHandler);
                ComEventsHelper.Combine(_zk, ZkemEventsIid, 11, _hidHandler);
                _eventsHooked = true;
            }
            catch
            {
                _eventsHooked = false;
            }
        }

        private void UnhookEvents()
        {
            if (!_eventsHooked || _zk == null)
                return;
            try { ComEventsHelper.Remove(_zk, ZkemEventsIid, 17, _attExHandler); } catch { }
            try { ComEventsHelper.Remove(_zk, ZkemEventsIid, 1, _attHandler); } catch { }
            try { ComEventsHelper.Remove(_zk, ZkemEventsIid, 9, _verifyHandler); } catch { }
            try { ComEventsHelper.Remove(_zk, ZkemEventsIid, 11, _hidHandler); } catch { }
            _eventsHooked = false;
        }

        private void OnVerify(int userId)
        {
            if (userId <= 0)
                return;
            _lastVerifyUserId = userId.ToString();
            _lastVerifyAt = DateTime.Now;
            if (_anonymousPunch != null)
            {
                _anonymousPunch.UserId = _lastVerifyUserId;
                var identified = _anonymousPunch;
                _anonymousPunch = null;
                EmitPunch(identified);
            }
        }

        private void OnHIDNum(int cardNumber)
        {
        }

        private void OnAttTransactionEx(string enrollNumber, int isInvalid, int attState, int verifyMethod, int year, int month, int day, int hour, int minute, int second, int workCode)
        {
            if (isInvalid != 0)
                return;
            RaiseFromEvent(ResolveUserId(enrollNumber), verifyMethod, attState, year, month, day, hour, minute, second, workCode);
        }

        private void OnAttTransaction(int enrollNumber, int isInvalid, int attState, int verifyMethod, int year, int month, int day, int hour, int minute, int second)
        {
            if (isInvalid != 0)
                return;
            RaiseFromEvent(ResolveUserId(enrollNumber), verifyMethod, attState, year, month, day, hour, minute, second, 0);
        }

        private List<AttendanceRecord> TakeLiveTail(List<AttendanceRecord> logs, int maxCount)
        {
            var live = new List<AttendanceRecord>();
            if (logs == null || logs.Count == 0 || maxCount <= 0)
                return live;
            int start = logs.Count - maxCount;
            if (start < 0)
                start = 0;
            for (int i = start; i < logs.Count; i++)
            {
                if (IsLivePunch(logs[i]))
                    live.Add(logs[i]);
            }
            return live;
        }

        public static bool IsLivePunch(AttendanceRecord log)
        {
            if (log == null)
                return false;
            var ts = log.Timestamp;
            if (ts.Year > 0 && ts.Year < 2015)
                return true;
            return ts >= DateTime.Now.AddMinutes(-3);
        }

        private void RaiseFromEvent(string userId, int verifyMode, int inOutMode, int year, int month, int day, int hour, int minute, int second, int workCode)
        {
            userId = Clean(userId);
            if (string.IsNullOrEmpty(userId) || userId == "0")
                userId = FreshVerifyUserId();
            RaisePunch(userId, verifyMode, inOutMode, year, month, day, hour, minute, second, workCode);
        }

        private string ResolveUserId(object enrollNumber)
        {
            var id = Clean(enrollNumber == null ? "" : Convert.ToString(enrollNumber));
            if (!string.IsNullOrEmpty(id) && id != "0")
                return id;
            return FreshVerifyUserId();

        }

        private string FreshVerifyUserId()
        {
            if (string.IsNullOrEmpty(_lastVerifyUserId) || _lastVerifyUserId == "0")
                return "";
            if (_lastVerifyAt == DateTime.MinValue)
                return "";
            if ((DateTime.Now - _lastVerifyAt).TotalSeconds > 3)
                return "";
            return _lastVerifyUserId;
        }

        private void EmitPunch(AttendanceRecord log)
        {
            var handler = AttendanceReceived;
            if (handler != null)
                handler(log);
        }

        private void RaisePunch(string userId, int verifyMode, int inOutMode, int year, int month, int day, int hour, int minute, int second, int workCode)
        {
            DateTime timestamp;
            try
            {
                timestamp = new DateTime(year, month, day, hour, minute, second);
            }
            catch (ArgumentOutOfRangeException)
            {
                timestamp = DateTime.Now;
            }

            var log = new AttendanceRecord
            {
                UserId = userId,
                UserName = "",
                Timestamp = timestamp,
                ReceivedAt = DateTime.Now,
                VerifyMode = verifyMode,
                InOutMode = inOutMode,
                WorkCode = workCode
            };
            if (!IsLivePunch(log))
                return;
            if (string.IsNullOrEmpty(log.UserId) || log.UserId == "0")
                _anonymousPunch = log;
            else
                _anonymousPunch = null;
            EmitPunch(log);
        }

        public static string FormatStamp(DateTime value)
        {
            if (value == DateTime.MinValue)
                return "";
            return value.ToString("dd/MM/yyyy HH:mm:ss", CultureInfo.InvariantCulture);
        }
    }
}
