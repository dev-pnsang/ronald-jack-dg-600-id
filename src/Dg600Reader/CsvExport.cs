using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Dg600Reader
{
    public static class CsvExport
    {
        public static void WriteLogs(string path, IEnumerable<AttendanceRecord> logs)
        {
            var sb = new StringBuilder();
            sb.AppendLine("MaNV,HoTen,ThoiGian,XacThuc,VaoRa,WorkCode");
            foreach (var log in logs)
            {
                sb.Append(Escape(log.UserId)).Append(',')
                    .Append(Escape(log.UserName)).Append(',')
                    .Append(Escape(DeviceClient.FormatStamp(log.Timestamp))).Append(',')
                    .Append(Escape(log.VerifyText)).Append(',')
                    .Append(Escape(log.InOutText)).Append(',')
                    .Append(log.WorkCode)
                    .AppendLine();
            }
            WriteUtf8Bom(path, sb.ToString());
        }

        public static void WriteUsers(string path, IEnumerable<UserRecord> users)
        {
            var sb = new StringBuilder();
            sb.AppendLine("MaNV,HoTen,Quyen,KichHoat");
            foreach (var user in users)
            {
                sb.Append(Escape(user.UserId)).Append(',')
                    .Append(Escape(user.Name)).Append(',')
                    .Append(Escape(user.PrivilegeText)).Append(',')
                    .Append(user.Enabled ? "Co" : "Khong")
                    .AppendLine();
            }
            WriteUtf8Bom(path, sb.ToString());
        }

        private static void WriteUtf8Bom(string path, string content)
        {
            var utf8Bom = new UTF8Encoding(true);
            File.WriteAllText(path, content, utf8Bom);
        }

        private static string Escape(string value)
        {
            if (string.IsNullOrEmpty(value))
                return "";
            if (value.IndexOfAny(new[] { ',', '"', '\r', '\n' }) >= 0)
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            return value;
        }
    }
}
