using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;
using System.Windows.Forms;

namespace Dg600Reader
{
    internal static class Program
    {
        [DllImport("kernel32.dll")]
        private static extern bool AttachConsole(int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool AllocConsole();

        [STAThread]
        private static int Main(string[] args)
        {
            if (args != null && args.Length > 0)
            {
                if (!AttachConsole(-1))
                    AllocConsole();
                return RunCli(args);
            }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }

        private static int RunCli(string[] args)
        {
            string ip = "192.168.2.96";
            int port = DeviceClient.DefaultPort;
            int key = 0;
            string logsPath = null;
            string usersPath = null;
            bool live = false;

            for (int i = 0; i < args.Length; i++)
            {
                var arg = args[i];
                if (arg == "--ip" && i + 1 < args.Length)
                    ip = args[++i];
                else if (arg == "--port" && i + 1 < args.Length)
                    port = int.Parse(args[++i]);
                else if ((arg == "--key" || arg == "--comm-key") && i + 1 < args.Length)
                    key = int.Parse(args[++i]);
                else if (arg == "--export-logs" && i + 1 < args.Length)
                    logsPath = args[++i];
                else if (arg == "--export-users" && i + 1 < args.Length)
                    usersPath = args[++i];
                else if (arg == "--live")
                    live = true;
                else if (arg == "--help" || arg == "-h")
                {
                    Console.WriteLine("Dg600Reader.exe [--ip 192.168.2.96] [--port 4370] [--key 0] [--export-users users.csv] [--export-logs logs.csv] [--live]");
                    return 0;
                }
            }

            using (var device = new DeviceClient())
            {
                Console.WriteLine("Connecting " + ip + ":" + port + " ...");
                device.Connect(ip, port, key);
                var info = device.ReadDeviceInfo();
                Console.WriteLine("Firmware: " + info.Firmware);
                Console.WriteLine("Serial:   " + info.SerialNumber);
                Console.WriteLine("Time:     " + DeviceClient.FormatStamp(info.DeviceTime));
                Console.WriteLine("Users:    " + info.UserCount);
                Console.WriteLine("Logs:     " + info.LogCount);

                IList<UserRecord> users = new List<UserRecord>();
                var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                if (usersPath != null || logsPath != null || live)
                {
                    users = device.ReadUsers();
                    foreach (var user in users)
                    {
                        if (!string.IsNullOrEmpty(user.UserId) && !names.ContainsKey(user.UserId))
                            names.Add(user.UserId, user.Name ?? "");
                    }
                    Console.WriteLine("Downloaded users: " + users.Count);
                }
                if (usersPath != null)
                {
                    var full = Path.GetFullPath(usersPath);
                    CsvExport.WriteUsers(full, users);
                    Console.WriteLine("Wrote " + full);
                }
                if (logsPath != null)
                {
                    var logs = device.ReadAttendanceLogs(names);
                    var full = Path.GetFullPath(logsPath);
                    CsvExport.WriteLogs(full, logs);
                    Console.WriteLine("Downloaded logs: " + logs.Count);
                    Console.WriteLine("Wrote " + full);
                }
                if (live)
                {
                    device.RegisterRealtime();
                    Console.WriteLine("Realtime ON. Cham cong tren may se in ra ngay. Ctrl+C de dung.");
                    while (true)
                    {
                        var fresh = device.PollNewLogs(names);
                        foreach (var log in fresh)
                        {
                            Console.WriteLine(
                                DeviceClient.FormatStamp(log.Timestamp) + "  " +
                                log.UserId + "  " + log.UserName + "  " +
                                log.VerifyText + "  " + log.InOutText);
                        }
                        Thread.Sleep(800);
                    }
                }
            }
            return 0;
        }
    }
}
