using System;

namespace Dg600Reader
{
    public sealed class DeviceInfo
    {
        public string IpAddress { get; set; }
        public int Port { get; set; }
        public string Firmware { get; set; }
        public string SerialNumber { get; set; }
        public string ProductCode { get; set; }
        public DateTime DeviceTime { get; set; }
        public int UserCount { get; set; }
        public int LogCount { get; set; }
        public string SdkVersion { get; set; }
    }

    public sealed class UserRecord
    {
        public string UserId { get; set; }
        public string Name { get; set; }
        public int Privilege { get; set; }
        public bool Enabled { get; set; }
        public string Password { get; set; }

        public string PrivilegeText
        {
            get
            {
                switch (Privilege)
                {
                    case 0: return "Nhân viên";
                    case 2: return "Đăng ký";
                    case 3: return "Admin";
                    case 6: return "Quản trị";
                    case 14: return "Super admin";
                    default: return Privilege.ToString();
                }
            }
        }
    }

    public sealed class AttendanceRecord
    {
        public string UserId { get; set; }
        public string UserName { get; set; }
        public DateTime Timestamp { get; set; }
        public DateTime ReceivedAt { get; set; }
        public int VerifyMode { get; set; }
        public int InOutMode { get; set; }
        public int WorkCode { get; set; }

        public string VerifyText
        {
            get
            {
                switch (VerifyMode)
                {
                    case 0: return "Mật khẩu";
                    case 1: return "Vân tay";
                    case 2: return "Thẻ";
                    case 3: return "Vân tay + mật khẩu";
                    case 4: return "Vân tay + thẻ";
                    case 5: return "Mật khẩu + thẻ";
                    case 6: return "Vân tay + mật khẩu + thẻ";
                    case 7: return "Thẻ + vân tay";
                    case 8: return "Khuôn mặt";
                    case 9: return "Khuôn mặt + vân tay";
                    case 10: return "Khuôn mặt + mật khẩu";
                    case 11: return "Khuôn mặt + thẻ";
                    case 15: return "Khuôn mặt + mật khẩu";
                    default: return VerifyMode.ToString();
                }
            }
        }

        public string InOutText
        {
            get
            {
                switch (InOutMode)
                {
                    case 0: return "Vào";
                    case 1: return "Ra";
                    case 2: return "Ra nghỉ";
                    case 3: return "Vào nghỉ";
                    case 4: return "Vào OT";
                    case 5: return "Ra OT";
                    default: return InOutMode.ToString();
                }
            }
        }
    }
}
