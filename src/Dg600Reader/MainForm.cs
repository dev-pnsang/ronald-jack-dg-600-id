using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Media;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace Dg600Reader
{
    public sealed class MainForm : Form
    {
        private readonly Color _navy = Color.FromArgb(27, 79, 114);
        private readonly Color _navyDark = Color.FromArgb(21, 67, 96);
        private readonly Color _ok = Color.FromArgb(39, 174, 96);
        private readonly Color _warn = Color.FromArgb(192, 57, 43);

        private DeviceClient _device;
        private DeviceInfo _info;
        private List<UserRecord> _users = new List<UserRecord>();
        private List<AttendanceRecord> _logs = new List<AttendanceRecord>();
        private Dictionary<string, string> _userNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private TextBox _ipBox;
        private NumericUpDown _portBox;
        private NumericUpDown _keyBox;
        private Button _connectBtn;
        private Button _disconnectBtn;
        private Label _statusDot;
        private Label _infoLabel;
        private DateTimePicker _fromDate;
        private DateTimePicker _toDate;
        private TextBox _searchBox;
        private DataGridView _logGrid;
        private DataGridView _userGrid;
        private TabControl _tabs;
        private ToolStripStatusLabel _statusLabel;
        private Label _logCountLabel;
        private Label _userCountLabel;
        private CheckBox _realtimeBox;
        private CheckBox _notifyBox;
        private Label _liveBanner;
        private Timer _realtimeTimer;
        private Timer _identifyTimer;
        private bool _needIdentify;
        private int _identifyTries;
        private bool _namedNotifyDone;
        private NotifyIcon _tray;
        private Form _toast;
        private Timer _toastCloser;
        private bool _busy;
        private bool _hadLivePunch;
        private readonly HashSet<string> _seenLogs = new HashSet<string>(StringComparer.Ordinal);
        private readonly NameStore _nameStore = new NameStore();

        [DllImport("user32.dll")]
        private static extern bool FlashWindow(IntPtr hwnd, bool invert);

        public MainForm()
        {
            Text = "Ronald Jack DG-600-ID";
            StartPosition = FormStartPosition.CenterScreen;
            MinimumSize = new Size(1080, 680);
            Size = new Size(1200, 760);
            Font = new Font("Segoe UI", 9.5f);
            BackColor = Color.FromArgb(245, 247, 250);

            BuildUi();
            InitTray();
            Shown += delegate { TryAutoConnect(); };
            FormClosed += delegate
            {
                DisposeDevice();
                if (_identifyTimer != null)
                {
                    _identifyTimer.Stop();
                    _identifyTimer.Dispose();
                }
                if (_toastCloser != null)
                {
                    _toastCloser.Stop();
                    _toastCloser.Dispose();
                }
                if (_toast != null)
                {
                    _toast.Close();
                    _toast.Dispose();
                }
                if (_tray != null)
                {
                    _tray.Visible = false;
                    _tray.Dispose();
                    _tray = null;
                }
            };
        }

        private void BuildUi()
        {
            var header = new Panel
            {
                Dock = DockStyle.Top,
                Height = 78,
                BackColor = _navy
            };
            var title = new Label
            {
                Text = "Đọc dữ liệu máy chấm công Ronald Jack DG-600-ID",
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 16f),
                AutoSize = true,
                Location = new Point(22, 12)
            };
            var subtitle = new Label
            {
                Text = "Standalone SDK (zkemkeeper)  •  TCP port 4370",
                ForeColor = Color.FromArgb(214, 234, 248),
                AutoSize = true,
                Location = new Point(24, 46)
            };
            header.Controls.Add(title);
            header.Controls.Add(subtitle);

            var connectPanel = new Panel
            {
                Dock = DockStyle.Top,
                Height = 58,
                Padding = new Padding(16, 10, 16, 8),
                BackColor = Color.White
            };
            connectPanel.Paint += delegate(object s, PaintEventArgs e)
            {
                using (var pen = new Pen(Color.FromArgb(225, 229, 233)))
                    e.Graphics.DrawLine(pen, 0, connectPanel.Height - 1, connectPanel.Width, connectPanel.Height - 1);
            };

            _statusDot = new Label
            {
                Text = "●",
                ForeColor = Color.Gray,
                AutoSize = true,
                Location = new Point(18, 16),
                Font = new Font("Segoe UI", 12f)
            };
            var ipLbl = MakeCaption("IP", 42, 8);
            _ipBox = new TextBox { Text = "192.168.2.96", Width = 130, Location = new Point(42, 26) };
            var portLbl = MakeCaption("Cổng", 184, 8);
            _portBox = new NumericUpDown
            {
                Minimum = 1,
                Maximum = 65535,
                Value = DeviceClient.DefaultPort,
                Width = 80,
                Location = new Point(184, 26)
            };
            var keyLbl = MakeCaption("Comm Key", 276, 8);
            _keyBox = new NumericUpDown
            {
                Minimum = 0,
                Maximum = 999999,
                Value = 0,
                Width = 80,
                Location = new Point(276, 26)
            };
            _connectBtn = MakeButton("Kết nối", 380, 18, 110, _navy, true);
            _disconnectBtn = MakeButton("Ngắt", 500, 18, 90, Color.FromArgb(127, 140, 141), false);
            _disconnectBtn.Enabled = false;
            _connectBtn.Click += delegate { Connect(); };
            _disconnectBtn.Click += delegate { Disconnect(); };
            _realtimeBox = new CheckBox
            {
                Text = "Realtime (tức thì)",
                AutoSize = true,
                Location = new Point(610, 22),
                Checked = true,
                ForeColor = Color.FromArgb(39, 174, 96),
                Font = new Font("Segoe UI Semibold", 9.5f)
            };
            _realtimeBox.CheckedChanged += delegate { ToggleRealtime(); };
            _notifyBox = new CheckBox
            {
                Text = "Thông báo",
                AutoSize = true,
                Location = new Point(790, 22),
                Checked = true,
                ForeColor = Color.FromArgb(41, 128, 185),
                Font = new Font("Segoe UI Semibold", 9.5f)
            };

            connectPanel.Controls.AddRange(new Control[]
            {
                _statusDot, ipLbl, _ipBox, portLbl, _portBox, keyLbl, _keyBox, _connectBtn, _disconnectBtn, _realtimeBox, _notifyBox
            });

            _infoLabel = new Label
            {
                Dock = DockStyle.Top,
                Height = 54,
                Padding = new Padding(20, 10, 20, 8),
                Text = "Chưa kết nối. Nhấn Kết nối để đọc thông tin máy tại 192.168.2.96.",
                ForeColor = Color.FromArgb(52, 73, 94)
            };

            _liveBanner = new Label
            {
                Dock = DockStyle.Top,
                Height = 62,
                Padding = new Padding(20, 8, 20, 8),
                Text = "Realtime tắt. Bật checkbox để nhận chấm công ngay khi nhân viên xác thực.",
                BackColor = Color.FromArgb(232, 248, 245),
                ForeColor = Color.FromArgb(22, 160, 133),
                Font = new Font("Segoe UI Semibold", 12f)
            };

            var toolbar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 52,
                Padding = new Padding(16, 8, 16, 8),
                BackColor = Color.FromArgb(236, 240, 241)
            };
            var loadLogsBtn = MakeButton("Tải nhật ký chấm công", 16, 10, 190, _navy, true);
            var loadUsersBtn = MakeButton("Tải nhân viên", 216, 10, 130, _navyDark, true);
            var syncBtn = MakeButton("Đồng bộ giờ máy", 356, 10, 150, Color.FromArgb(41, 128, 185), true);
            var exportBtn = MakeButton("Xuất CSV", 516, 10, 110, _ok, true);
            var saveNamesBtn = MakeButton("Cập nhật tên lên máy", 636, 10, 180, Color.FromArgb(142, 68, 173), true);
            loadLogsBtn.Click += delegate { LoadLogs(); };
            loadUsersBtn.Click += delegate { LoadUsers(); };
            syncBtn.Click += delegate { SyncTime(); };
            exportBtn.Click += delegate { ExportCsv(); };
            saveNamesBtn.Click += delegate { PushNamesToDevice(); };
            toolbar.Controls.AddRange(new Control[] { loadLogsBtn, loadUsersBtn, syncBtn, exportBtn, saveNamesBtn });

            var filter = new Panel
            {
                Dock = DockStyle.Top,
                Height = 48,
                Padding = new Padding(16, 8, 16, 8),
                BackColor = Color.White
            };
            var fromLbl = new Label { Text = "Từ ngày", AutoSize = true, Location = new Point(16, 14) };
            _fromDate = new DateTimePicker
            {
                Format = DateTimePickerFormat.Custom,
                CustomFormat = "dd/MM/yyyy",
                Width = 120,
                Location = new Point(76, 10),
                ShowCheckBox = true,
                Checked = false
            };
            var toLbl = new Label { Text = "Đến", AutoSize = true, Location = new Point(210, 14) };
            _toDate = new DateTimePicker
            {
                Format = DateTimePickerFormat.Custom,
                CustomFormat = "dd/MM/yyyy",
                Width = 120,
                Location = new Point(248, 10),
                ShowCheckBox = true,
                Checked = false
            };
            var searchLbl = new Label { Text = "Tìm", AutoSize = true, Location = new Point(388, 14) };
            _searchBox = new TextBox { Width = 220, Location = new Point(422, 10) };
            var applyBtn = MakeButton("Lọc", 656, 8, 80, _navyDark, true);
            applyBtn.Click += delegate { ApplyFilters(); };
            _searchBox.KeyDown += delegate(object s, KeyEventArgs e)
            {
                if (e.KeyCode == Keys.Enter)
                {
                    ApplyFilters();
                    e.SuppressKeyPress = true;
                }
            };
            _logCountLabel = new Label { AutoSize = true, Location = new Point(752, 14), ForeColor = Color.FromArgb(86, 101, 115) };
            filter.Controls.AddRange(new Control[]
            {
                fromLbl, _fromDate, toLbl, _toDate, searchLbl, _searchBox, applyBtn, _logCountLabel
            });

            _tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(12, 6) };
            var logTab = new TabPage("Nhật ký chấm công");
            var userTab = new TabPage("Nhân viên");
            _logGrid = CreateGrid();
            _logGrid.Columns.AddRange(new DataGridViewColumn[]
            {
                NewTextColumn("UserId", "Mã NV", 110),
                NewTextColumn("UserName", "Họ tên", 220),
                NewTextColumn("TimestampText", "Thời gian", 160),
                NewTextColumn("VerifyText", "Xác thực", 160),
                NewTextColumn("InOutText", "Vào/Ra", 90),
                NewTextColumn("WorkCode", "Work code", 90)
            });
            _userGrid = CreateGrid();
            _userGrid.ReadOnly = false;
            _userGrid.Columns.AddRange(new DataGridViewColumn[]
            {
                NewTextColumn("UserId", "Mã NV", 120),
                NewTextColumn("Name", "Họ tên (nhấp để sửa)", 280),
                NewTextColumn("PrivilegeText", "Quyền", 130),
                NewTextColumn("EnabledText", "Kích hoạt", 100)
            });
            _userGrid.Columns["UserId"].ReadOnly = true;
            _userGrid.Columns["PrivilegeText"].ReadOnly = true;
            _userGrid.Columns["EnabledText"].ReadOnly = true;
            _userGrid.Columns["Name"].ReadOnly = false;
            _userGrid.EditMode = DataGridViewEditMode.EditOnKeystrokeOrF2;
            _userGrid.CellEndEdit += OnUserNameEdited;
            _userCountLabel = new Label
            {
                Dock = DockStyle.Top,
                Height = 28,
                Padding = new Padding(8, 6, 8, 0),
                ForeColor = Color.FromArgb(86, 101, 115),
                Text = "Nhấp vào cột Họ tên để sửa. Bấm 'Cập nhật tên lên máy' để ghi vào máy chấm công."
            };
            logTab.Controls.Add(_logGrid);
            userTab.Controls.Add(_userGrid);
            userTab.Controls.Add(_userCountLabel);
            _tabs.TabPages.Add(logTab);
            _tabs.TabPages.Add(userTab);

            var status = new StatusStrip();
            _statusLabel = new ToolStripStatusLabel("Sẵn sàng.");
            status.Items.Add(_statusLabel);

            Controls.Add(_tabs);
            Controls.Add(filter);
            Controls.Add(toolbar);
            Controls.Add(_liveBanner);
            Controls.Add(_infoLabel);
            Controls.Add(connectPanel);
            Controls.Add(header);
            Controls.Add(status);

            _realtimeTimer = new Timer { Interval = 150 };
            _realtimeTimer.Tick += delegate { PollRealtime(); };
            _identifyTimer = new Timer { Interval = 400 };
            _identifyTimer.Tick += delegate { IdentifyPendingPunch(); };
        }

        private static Label MakeCaption(string text, int x, int y)
        {
            return new Label
            {
                Text = text,
                AutoSize = true,
                Location = new Point(x, y),
                ForeColor = Color.FromArgb(127, 140, 141)
            };
        }

        private static Button MakeButton(string text, int x, int y, int width, Color back, bool bold)
        {
            var btn = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Width = width,
                Height = 32,
                FlatStyle = FlatStyle.Flat,
                BackColor = back,
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 9f, bold ? FontStyle.Bold : FontStyle.Regular)
            };
            btn.FlatAppearance.BorderSize = 0;
            btn.Cursor = Cursors.Hand;
            return btn;
        }

        private static DataGridView CreateGrid()
        {
            var grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                RowHeadersVisible = false,
                BackgroundColor = Color.White,
                BorderStyle = BorderStyle.None,
                EnableHeadersVisualStyles = false
            };
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(27, 79, 114);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            grid.ColumnHeadersDefaultCellStyle.Font = new Font("Segoe UI Semibold", 9.5f);
            grid.ColumnHeadersHeight = 34;
            grid.RowTemplate.Height = 28;
            grid.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(242, 248, 252);
            typeof(DataGridView).InvokeMember("DoubleBuffered",
                BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.SetProperty,
                null, grid, new object[] { true });
            return grid;
        }

        private static DataGridViewTextBoxColumn NewTextColumn(string name, string header, int width)
        {
            return new DataGridViewTextBoxColumn
            {
                Name = name,
                HeaderText = header,
                FillWeight = width,
                SortMode = DataGridViewColumnSortMode.Automatic
            };
        }

        private void TryAutoConnect()
        {
            try
            {
                Connect();
            }
            catch
            {
            }
        }

        private void Connect()
        {
            RunBusy("Đang kết nối " + _ipBox.Text.Trim() + "...", delegate
            {
                DisposeDevice();
                _device = new DeviceClient();
                _device.Connect(_ipBox.Text.Trim(), (int)_portBox.Value, (int)_keyBox.Value);
                _info = _device.ReadDeviceInfo();
                try
                {
                    _users = new List<UserRecord>(_device.ReadUsers());
                    _nameStore.MergeInto(_users);
                    RebuildNameMap();
                }
                catch
                {
                    _users = new List<UserRecord>();
                }
            }, delegate
            {
                _connectBtn.Enabled = false;
                _disconnectBtn.Enabled = true;
                _statusDot.ForeColor = _ok;
                BindUsers(_users);
                ShowDeviceInfo();
                RememberLogs(_logs);
                StartRealtimeIfNeeded();
                SetStatus("Đã kết nối " + _info.IpAddress + ". Serial " + _info.SerialNumber + ".");
            });
        }

        private void Disconnect()
        {
            StopRealtime();
            DisposeDevice();
            _connectBtn.Enabled = true;
            _disconnectBtn.Enabled = false;
            _statusDot.ForeColor = Color.Gray;
            _infoLabel.Text = "Đã ngắt kết nối.";
            _liveBanner.Text = "Đã ngắt kết nối. Realtime dừng.";
            _liveBanner.BackColor = Color.FromArgb(236, 240, 241);
            _liveBanner.ForeColor = Color.FromArgb(127, 140, 141);
            SetStatus("Đã ngắt kết nối.");
        }

        private void LoadUsers()
        {
            EnsureConnected();
            RunBusy("Đang tải danh sách nhân viên...", delegate
            {
                _users = new List<UserRecord>(_device.ReadUsers());
                _nameStore.MergeInto(_users);
                RebuildNameMap();
            }, delegate
            {
                BindUsers(_users);
                _tabs.SelectedIndex = 1;
                ShowDeviceInfo();
                SetStatus("Đã tải " + _users.Count + " nhân viên.");
            });
        }

        private void LoadLogs()
        {
            EnsureConnected();
            RunBusy("Đang tải nhật ký chấm công (có thể mất khoảng 20 giây)...", delegate
            {
                if (_users.Count == 0)
                {
                    _users = new List<UserRecord>(_device.ReadUsers());
                    _nameStore.MergeInto(_users);
                    RebuildNameMap();
                }
                _logs = new List<AttendanceRecord>(_device.ReadAttendanceLogs(_userNames));
            }, delegate
            {
                BindUsers(_users);
                RememberLogs(_logs);
                ApplyFilters();
                _tabs.SelectedIndex = 0;
                ShowDeviceInfo();
                SetStatus("Đã tải " + _logs.Count + " bản ghi chấm công.");
            });
        }

        private void SyncTime()
        {
            EnsureConnected();
            var confirm = MessageBox.Show(
                this,
                "Đặt giờ máy chấm công theo giờ máy tính này?\nGiờ hiện tại của máy chấm công: " +
                DeviceClient.FormatStamp(_info == null ? DateTime.MinValue : _info.DeviceTime),
                "Đồng bộ giờ",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (confirm != DialogResult.Yes)
                return;

            RunBusy("Đang đồng bộ giờ...", delegate
            {
                _device.SyncDeviceTime();
                _info = _device.ReadDeviceInfo();
            }, delegate
            {
                ShowDeviceInfo();
                SetStatus("Đã đồng bộ giờ máy chấm công: " + DeviceClient.FormatStamp(_info.DeviceTime));
            });
        }

        private void ExportCsv()
        {
            if (_tabs.SelectedIndex == 1)
            {
                if (_users.Count == 0)
                {
                    MessageBox.Show(this, "Chưa có danh sách nhân viên để xuất.", "Xuất CSV", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }
                using (var dlg = new SaveFileDialog())
                {
                    dlg.Filter = "CSV (*.csv)|*.csv";
                    dlg.FileName = "nhan-vien-dg600.csv";
                    if (dlg.ShowDialog(this) == DialogResult.OK)
                    {
                        CsvExport.WriteUsers(dlg.FileName, _users);
                        SetStatus("Đã xuất nhân viên: " + dlg.FileName);
                    }
                }
                return;
            }

            var view = GetFilteredLogs();
            if (view.Count == 0)
            {
                MessageBox.Show(this, "Chưa có nhật ký để xuất. Hãy tải nhật ký trước.", "Xuất CSV", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            using (var dlg = new SaveFileDialog())
            {
                dlg.Filter = "CSV (*.csv)|*.csv";
                dlg.FileName = "nhat-ky-cham-cong-dg600.csv";
                if (dlg.ShowDialog(this) == DialogResult.OK)
                {
                    CsvExport.WriteLogs(dlg.FileName, view);
                    SetStatus("Đã xuất " + view.Count + " bản ghi: " + dlg.FileName);
                }
            }
        }

        private void ApplyFilters()
        {
            var view = GetFilteredLogs();
            _logGrid.Rows.Clear();
            _logGrid.SuspendLayout();
            foreach (var log in view)
            {
                var rowIndex = _logGrid.Rows.Add(
                    string.IsNullOrEmpty(log.UserId) ? "(không rõ)" : log.UserId,
                    string.IsNullOrEmpty(log.UserName) ? "(chưa đặt tên)" : log.UserName,
                    DeviceClient.FormatStamp(EffectiveTime(log)),
                    log.VerifyText,
                    log.InOutText,
                    log.WorkCode);
                if (log.Timestamp.Year < 2015)
                    _logGrid.Rows[rowIndex].DefaultCellStyle.ForeColor = _warn;
            }
            _logGrid.ResumeLayout();
            _logCountLabel.Text = view.Count + " / " + _logs.Count + " bản ghi";
        }

        private List<AttendanceRecord> GetFilteredLogs()
        {
            IEnumerable<AttendanceRecord> query = _logs;
            if (_fromDate.Checked)
            {
                var from = _fromDate.Value.Date;
                query = query.Where(x => EffectiveTime(x).Date >= from);
            }
            if (_toDate.Checked)
            {
                var to = _toDate.Value.Date;
                query = query.Where(x => EffectiveTime(x).Date <= to);
            }
            var keyword = (_searchBox.Text ?? "").Trim();
            if (keyword.Length > 0)
            {
                query = query.Where(x =>
                    (x.UserId != null && x.UserId.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (x.UserName != null && x.UserName.IndexOf(keyword, StringComparison.OrdinalIgnoreCase) >= 0));
            }
            return query.ToList();
        }

        private void BindUsers(IList<UserRecord> users)
        {
            _userGrid.Rows.Clear();
            foreach (var user in users)
            {
                _userGrid.Rows.Add(user.UserId, user.Name, user.PrivilegeText, user.Enabled ? "Có" : "Không");
            }
            _userCountLabel.Text = users.Count + " nhân viên  •  Nhấp cột Họ tên để sửa, rồi bấm 'Cập nhật tên lên máy'.";
        }

        private void OnUserNameEdited(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex < 0 || _userGrid.Columns[e.ColumnIndex].Name != "Name")
                return;
            var row = _userGrid.Rows[e.RowIndex];
            var userId = Convert.ToString(row.Cells["UserId"].Value);
            var newName = Convert.ToString(row.Cells["Name"].Value);
            if (string.IsNullOrEmpty(userId))
                return;
            newName = (newName ?? "").Trim();
            foreach (var user in _users)
            {
                if (string.Equals(user.UserId, userId, StringComparison.OrdinalIgnoreCase))
                    user.Name = newName;
            }
            _nameStore.Set(userId, newName);
            RebuildNameMap();
            RefreshLogNames();
            SetStatus("Đã lưu tên local cho " + userId + ". Bấm 'Cập nhật tên lên máy' nếu muốn ghi vào máy chấm công.");
        }

        private void PushNamesToDevice()
        {
            EnsureConnected();
            if (_users.Count == 0)
            {
                MessageBox.Show(this, "Chưa có danh sách nhân viên.", "Cập nhật tên", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            var confirm = MessageBox.Show(
                this,
                "Ghi " + _users.Count + " tên nhân viên từ bảng này lên máy chấm công?",
                "Cập nhật tên lên máy",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);
            if (confirm != DialogResult.Yes)
                return;

            RunBusy("Đang cập nhật tên lên máy...", delegate
            {
                foreach (var user in _users)
                {
                    _nameStore.Set(user.UserId, user.Name);
                    _device.UpdateUserName(user.UserId, user.Name ?? "");
                }
            }, delegate
            {
                RebuildNameMap();
                RefreshLogNames();
                _tabs.SelectedIndex = 1;
                SetStatus("Đã cập nhật tên nhân viên lên máy chấm công.");
            });
        }

        private void RefreshLogNames()
        {
            foreach (var log in _logs)
                log.UserName = ResolveName(log.UserId);
            ApplyFilters();
        }

        private string ResolveName(string userId)
        {
            if (string.IsNullOrEmpty(userId))
                return "";
            var local = _nameStore.Get(userId);
            if (!string.IsNullOrEmpty(local))
                return local;
            string name;
            if (_userNames != null && _userNames.TryGetValue(userId, out name) && !string.IsNullOrEmpty(name))
                return name;
            return "";
        }

        private static DateTime EffectiveTime(AttendanceRecord log)
        {
            if (log.Timestamp.Year >= 2015)
                return log.Timestamp;
            if (log.ReceivedAt != DateTime.MinValue)
                return log.ReceivedAt;
            return log.Timestamp;
        }

        private void RebuildNameMap()
        {
            _userNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var user in _users)
            {
                if (string.IsNullOrEmpty(user.UserId) || _userNames.ContainsKey(user.UserId))
                    continue;
                var name = _nameStore.Get(user.UserId);
                _userNames.Add(user.UserId, string.IsNullOrEmpty(name) ? (user.Name ?? "") : name);
            }
        }

        private void ShowDeviceInfo()
        {
            if (_info == null)
                return;
            var timeText = DeviceClient.FormatStamp(_info.DeviceTime);
            var clockNote = _info.DeviceTime.Year < 2015 ? "  ⚠ giờ máy đang sai, nên đồng bộ" : "";
            _infoLabel.Text = string.Format(
                "Firmware {0}   •   Serial {1}   •   Mã SP {2}   •   Giờ máy {3}{4}   •   {5} NV / {6} log",
                _info.Firmware,
                _info.SerialNumber,
                string.IsNullOrEmpty(_info.ProductCode) ? "-" : _info.ProductCode,
                timeText,
                clockNote,
                _info.UserCount,
                _info.LogCount);
        }

        private void EnsureConnected()
        {
            if (_device == null || !_device.IsConnected)
                throw new InvalidOperationException("Hãy kết nối máy chấm công trước.");
        }

        private void RunBusy(string message, Action work, Action onSuccess)
        {
            _busy = true;
            var resumeRealtime = _realtimeTimer != null && _realtimeTimer.Enabled;
            if (_realtimeTimer != null)
                _realtimeTimer.Stop();
            Cursor = Cursors.WaitCursor;
            SetStatus(message);
            Refresh();
            try
            {
                work();
                onSuccess();
            }
            catch (Exception ex)
            {
                SetStatus("Lỗi: " + ex.Message);
                MessageBox.Show(this, ex.Message, "DG-600-ID", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                Cursor = Cursors.Default;
                _busy = false;
                if (resumeRealtime && _device != null && _device.IsConnected && _realtimeBox.Checked)
                    _realtimeTimer.Start();
            }
        }

        private void ToggleRealtime()
        {
            if (_realtimeBox.Checked && _device != null && _device.IsConnected)
                StartRealtimeIfNeeded();
            else
                StopRealtime();
        }

        private void StartRealtimeIfNeeded()
        {
            if (_device == null || !_device.IsConnected || !_realtimeBox.Checked)
                return;
            try
            {
                _device.AttendanceReceived -= OnDevicePunch;
                _device.AttendanceReceived += OnDevicePunch;
                _device.RegisterRealtime();
            }
            catch
            {
            }
            _seenLogs.Clear();
            _hadLivePunch = false;
            _realtimeTimer.Start();
            _liveBanner.BackColor = Color.FromArgb(232, 248, 245);
            _liveBanner.ForeColor = Color.FromArgb(22, 160, 133);
            _liveBanner.Text = "Đang lắng nghe máy chấm công...\nKhi nhân viên xác thực, tên / mã NV / giờ sẽ hiện ở đây.";
            SetStatus("Realtime bật. Đang chờ nhân viên chấm công...");
        }

        private void StopRealtime()
        {
            if (_realtimeTimer != null)
                _realtimeTimer.Stop();
            if (_identifyTimer != null)
                _identifyTimer.Stop();
            _needIdentify = false;
            if (_device != null)
            {
                try { _device.UnregisterRealtime(); }
                catch { }
            }
            if (!_realtimeBox.Checked)
            {
                _liveBanner.BackColor = Color.FromArgb(253, 237, 236);
                _liveBanner.ForeColor = Color.FromArgb(192, 57, 43);
                _liveBanner.Text = "Realtime tắt. Bật checkbox để nhận chấm công tức thì.";
            }
        }

        private void PollRealtime()
        {
            if (_busy || _device == null || !_device.IsConnected)
                return;
            try
            {
                _device.PumpRealtime();
            }
            catch
            {
            }
        }

        private void OnDevicePunch(AttendanceRecord log)
        {
            if (IsDisposed)
                return;
            if (InvokeRequired)
            {
                BeginInvoke(new Action<AttendanceRecord>(OnDevicePunch), log);
                return;
            }
            HandleLivePunch(log);
        }

        private void HandleLivePunch(AttendanceRecord log)
        {
            if (log == null)
                return;
            if (!DeviceClient.IsLivePunch(log))
                return;
            if (string.IsNullOrEmpty(log.UserId) || log.UserId == "0")
            {
                log.UserId = "";
                log.ReceivedAt = DateTime.Now;
                _liveBanner.BackColor = Color.FromArgb(212, 239, 223);
                _liveBanner.ForeColor = Color.FromArgb(30, 132, 73);
                _liveBanner.Text = "Có người chấm công lúc " + DeviceClient.FormatStamp(DateTime.Now) +
                    "\nĐang lấy tên nhân viên...";
                SetStatus("Có người chấm công, đang lấy tên...");
                NotifyPunch(log, true);
                _needIdentify = true;
                _identifyTries = 0;
                _namedNotifyDone = true;
                if (_identifyTimer != null)
                {
                    _identifyTimer.Stop();
                    _identifyTimer.Start();
                }
                return;
            }
            log.UserName = ResolveName(log.UserId);
            if (!_seenLogs.Add(LogKey(log)))
                return;
            _logs.Add(log);
            _hadLivePunch = true;
            _needIdentify = false;
            if (_identifyTimer != null)
                _identifyTimer.Stop();

            var when = EffectiveTime(log);
            var who = string.IsNullOrEmpty(log.UserName)
                ? "Mã NV " + log.UserId + " (chưa đặt tên)"
                : log.UserName + "  (" + log.UserId + ")";
            _liveBanner.BackColor = Color.FromArgb(212, 239, 223);
            _liveBanner.ForeColor = Color.FromArgb(30, 132, 73);
            _liveBanner.Text = "Nhân viên: " + who + "\nLúc: " + DeviceClient.FormatStamp(when) +
                "   •   " + log.VerifyText + " / " + log.InOutText;
            SetStatus("Chấm công: " + who + " lúc " + DeviceClient.FormatStamp(when));
            NotifyPunch(log, !_namedNotifyDone);
            _namedNotifyDone = true;
            AppendLogRow(log);
        }

        private void IdentifyPendingPunch()
        {
            if (_identifyTimer != null)
                _identifyTimer.Stop();
            if (!_needIdentify || _busy || _device == null || !_device.IsConnected)
                return;
            _identifyTries++;
            var resumeRealtime = _realtimeTimer != null && _realtimeTimer.Enabled;
            if (_realtimeTimer != null)
                _realtimeTimer.Stop();
            AttendanceRecord found = null;
            try
            {
                found = _device.TryIdentifyLastPunch(_userNames);
            }
            catch
            {
                found = null;
            }
            finally
            {
                if (resumeRealtime && _device != null && _device.IsConnected && _realtimeBox.Checked)
                    _realtimeTimer.Start();
            }
            if (found != null && !string.IsNullOrEmpty(found.UserId) && found.UserId != "0")
            {
                found.ReceivedAt = DateTime.Now;
                HandleLivePunch(found);
                return;
            }
            if (_identifyTries < 6 && _needIdentify && _identifyTimer != null)
            {
                _liveBanner.Text = "Có người chấm công lúc " + DeviceClient.FormatStamp(DateTime.Now) +
                    "\nĐang lấy tên nhân viên (" + _identifyTries + ")...";
                _identifyTimer.Start();
                return;
            }
            _needIdentify = false;
            _liveBanner.Text = "Có người chấm công lúc " + DeviceClient.FormatStamp(DateTime.Now) +
                "\nChưa đọc được mã NV. Thử bấm 'Tải nhật ký chấm công'.";
            SetStatus("Chấm công rồi nhưng máy chưa trả mã nhân viên.");
        }

        private void AppendLogRow(AttendanceRecord log)
        {
            if (_fromDate.Checked || _toDate.Checked || !string.IsNullOrEmpty((_searchBox.Text ?? "").Trim()))
            {
                ApplyFilters();
            }
            else
            {
                var rowIndex = _logGrid.Rows.Add(
                    log.UserId,
                    string.IsNullOrEmpty(log.UserName) ? "(chưa đặt tên)" : log.UserName,
                    DeviceClient.FormatStamp(EffectiveTime(log)),
                    log.VerifyText,
                    log.InOutText,
                    log.WorkCode);
                _logGrid.FirstDisplayedScrollingRowIndex = rowIndex;
            }
            _logCountLabel.Text = _logGrid.Rows.Count + " / " + _logs.Count + " bản ghi";
        }

        private void InitTray()
        {
            _tray = new NotifyIcon
            {
                Icon = SystemIcons.Information,
                Visible = true,
                Text = "Ronald Jack DG-600-ID"
            };
            _tray.DoubleClick += delegate
            {
                Show();
                WindowState = FormWindowState.Normal;
                Activate();
            };
            var menu = new ContextMenu();
            menu.MenuItems.Add("Hiện cửa sổ", delegate
            {
                Show();
                WindowState = FormWindowState.Normal;
                Activate();
            });
            menu.MenuItems.Add("Thoát", delegate { Close(); });
            _tray.ContextMenu = menu;
        }

        private void NotifyPunch(AttendanceRecord log, bool playSound)
        {
            if (_notifyBox == null || !_notifyBox.Checked)
                return;

            var who = string.IsNullOrEmpty(log.UserName)
                ? (string.IsNullOrEmpty(log.UserId) ? "Có người chấm công" : "Mã NV " + log.UserId)
                : log.UserName + " (" + log.UserId + ")";
            var when = EffectiveTime(log);
            if (when.Year < 2015)
                when = log.ReceivedAt == DateTime.MinValue ? DateTime.Now : log.ReceivedAt;
            var body = who + "\n" + DeviceClient.FormatStamp(when) +
                "  •  " + log.VerifyText + " / " + log.InOutText;

            if (_tray != null)
            {
                _tray.BalloonTipTitle = "Chấm công mới";
                _tray.BalloonTipText = body;
                _tray.BalloonTipIcon = ToolTipIcon.Info;
                _tray.ShowBalloonTip(5000);
            }

            if (playSound)
            {
                try { SystemSounds.Asterisk.Play(); }
                catch { }
            }

            ShowToast("Chấm công mới", body);

            if (WindowState == FormWindowState.Minimized || !ContainsFocus)
                FlashWindow(Handle, true);
        }

        private void ShowToast(string title, string body)
        {
            if (_toastCloser != null)
            {
                _toastCloser.Stop();
                _toastCloser.Dispose();
                _toastCloser = null;
            }
            if (_toast != null)
            {
                _toast.Close();
                _toast.Dispose();
                _toast = null;
            }

            var toast = new PunchToast();
            toast.FormBorderStyle = FormBorderStyle.None;
            toast.StartPosition = FormStartPosition.Manual;
            toast.ShowInTaskbar = false;
            toast.TopMost = true;
            toast.BackColor = Color.FromArgb(27, 79, 114);
            toast.Size = new Size(380, 100);
            toast.Padding = new Padding(16);

            var titleLbl = new Label
            {
                Text = title,
                ForeColor = Color.White,
                Font = new Font("Segoe UI Semibold", 12f),
                AutoSize = true,
                Location = new Point(16, 12)
            };
            var bodyLbl = new Label
            {
                Text = body,
                ForeColor = Color.FromArgb(213, 245, 227),
                Font = new Font("Segoe UI", 10f),
                AutoSize = true,
                Location = new Point(16, 42)
            };
            toast.Controls.Add(titleLbl);
            toast.Controls.Add(bodyLbl);

            var area = Screen.FromControl(this).WorkingArea;
            toast.Location = new Point(area.Right - toast.Width - 18, area.Bottom - toast.Height - 18);
            toast.Show();
            _toast = toast;

            _toastCloser = new Timer { Interval = 4500 };
            _toastCloser.Tick += delegate
            {
                _toastCloser.Stop();
                if (_toast != null)
                {
                    _toast.Close();
                    _toast.Dispose();
                    _toast = null;
                }
            };
            _toastCloser.Start();
        }

        private sealed class PunchToast : Form
        {
            protected override bool ShowWithoutActivation
            {
                get { return true; }
            }

            protected override CreateParams CreateParams
            {
                get
                {
                    var cp = base.CreateParams;
                    cp.ExStyle |= 0x08000008;
                    return cp;
                }
            }
        }

        private void SetStatus(string text)
        {
            _statusLabel.Text = text;
        }

        private void RememberLogs(IEnumerable<AttendanceRecord> logs)
        {
            foreach (var log in logs)
                _seenLogs.Add(LogKey(log));
        }

        private static string LogKey(AttendanceRecord log)
        {
            return log.UserId + "|" + log.Timestamp.Ticks + "|" + log.InOutMode + "|" + log.VerifyMode;
        }

        private void DisposeDevice()
        {
            StopRealtime();
            if (_device != null)
            {
                _device.Dispose();
                _device = null;
            }
        }
    }
}
