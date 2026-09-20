using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace Dg600Reader
{
    public sealed class NameStore
    {
        private readonly string _path;
        private readonly Dictionary<string, string> _names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public NameStore()
        {
            _path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "employee-names.json");
            Load();
        }

        public string Get(string userId)
        {
            string name;
            if (!string.IsNullOrEmpty(userId) && _names.TryGetValue(userId.Trim(), out name))
                return name ?? "";
            return "";
        }

        public void Set(string userId, string name)
        {
            if (string.IsNullOrEmpty(userId))
                return;
            _names[userId.Trim()] = name == null ? "" : name.Trim();
            Save();
        }

        public void MergeInto(IList<UserRecord> users)
        {
            if (users == null)
                return;
            foreach (var user in users)
            {
                var local = Get(user.UserId);
                if (!string.IsNullOrEmpty(local))
                    user.Name = local;
            }
        }

        private void Load()
        {
            _names.Clear();
            if (!File.Exists(_path))
                return;
            var text = File.ReadAllText(_path, Encoding.UTF8);
            foreach (Match match in Regex.Matches(text, "\"((?:\\\\.|[^\"])*)\"\\s*:\\s*\"((?:\\\\.|[^\"])*)\""))
            {
                var key = Unescape(match.Groups[1].Value);
                var value = Unescape(match.Groups[2].Value);
                if (!string.IsNullOrEmpty(key))
                    _names[key] = value;
            }
        }

        private void Save()
        {
            var sb = new StringBuilder();
            sb.Append("{\r\n");
            bool first = true;
            foreach (var pair in _names)
            {
                if (!first)
                    sb.Append(",\r\n");
                first = false;
                sb.Append("  \"").Append(Escape(pair.Key)).Append("\": \"").Append(Escape(pair.Value)).Append("\"");
            }
            sb.Append("\r\n}\r\n");
            File.WriteAllText(_path, sb.ToString(), new UTF8Encoding(true));
        }

        private static string Escape(string value)
        {
            return (value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"");
        }

        private static string Unescape(string value)
        {
            return (value ?? "").Replace("\\\"", "\"").Replace("\\\\", "\\");
        }
    }
}
