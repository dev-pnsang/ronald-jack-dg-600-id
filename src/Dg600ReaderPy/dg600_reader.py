#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Doc du lieu may cham cong Ronald Jack DG-600-ID tren macOS/Windows/Linux.

Dung protocol ZK (cung protocol voi Standalone SDK), khong can zkemkeeper.dll.
"""
from __future__ import annotations

import argparse
import csv
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

DEFAULT_IP = "192.168.2.96"
DEFAULT_PORT = 4370

PRIVILEGE_TEXT = {
    0: "Nhân viên",
    2: "Đăng ký",
    3: "Admin",
    6: "Quản trị",
    14: "Super admin",
}
VERIFY_TEXT = {
    0: "Mật khẩu",
    1: "Vân tay",
    2: "Thẻ",
    3: "Vân tay + mật khẩu",
    4: "Vân tay + thẻ",
    5: "Mật khẩu + thẻ",
    6: "Vân tay + mật khẩu + thẻ",
    7: "Thẻ + vân tay",
    8: "Khuôn mặt",
    9: "Khuôn mặt + vân tay",
    10: "Khuôn mặt + mật khẩu",
    11: "Khuôn mặt + thẻ",
    15: "Khuôn mặt + mật khẩu",
}
INOUT_TEXT = {
    0: "Vào",
    1: "Ra",
    2: "Ra nghỉ",
    3: "Vào nghỉ",
    4: "Vào OT",
    5: "Ra OT",
}


def clean_text(value) -> str:
    if value is None:
        return ""
    return str(value).replace("\x00", "").strip()


def privilege_text(value: int) -> str:
    return PRIVILEGE_TEXT.get(int(value), str(value))


def verify_text(value: int) -> str:
    return VERIFY_TEXT.get(int(value), str(value))


def inout_text(value: int) -> str:
    return INOUT_TEXT.get(int(value), str(value))


def format_stamp(value: datetime | None) -> str:
    if not value:
        return ""
    return value.strftime("%d/%m/%Y %H:%M:%S")


def connect_device(ip: str, port: int, password: int = 0, timeout: int = 10):
    try:
        from zk import ZK
    except ImportError as exc:
        raise RuntimeError(
            "Chưa cài pyzk. Chạy: python3 -m pip install -r requirements.txt"
        ) from exc
    zk = ZK(
        ip,
        port=port,
        timeout=timeout,
        password=password,
        force_udp=False,
        ommit_ping=True,
    )
    return zk.connect()


def read_device_info(conn, ip: str, port: int) -> dict:
    info = {
        "ip": ip,
        "port": port,
        "firmware": clean_text(conn.get_firmware_version()),
        "serial": clean_text(conn.get_serialnumber()),
        "platform": "",
        "device_time": conn.get_time(),
        "user_count": 0,
        "log_count": 0,
    }
    try:
        info["platform"] = clean_text(conn.get_platform())
    except Exception:
        pass
    try:
        conn.read_sizes()
        info["user_count"] = int(getattr(conn, "users", 0) or 0)
        info["log_count"] = int(getattr(conn, "records", 0) or 0)
    except Exception:
        pass
    return info


def read_users(conn) -> list[dict]:
    users = []
    for user in conn.get_users() or []:
        users.append(
            {
                "user_id": clean_text(user.user_id),
                "name": clean_text(user.name),
                "privilege": int(user.privilege or 0),
                "privilege_text": privilege_text(int(user.privilege or 0)),
                "enabled": "Có",
            }
        )
    users.sort(key=lambda item: item["user_id"])
    return users


def read_logs(conn, names: dict[str, str]) -> list[dict]:
    logs = []
    for row in conn.get_attendance() or []:
        logs.append(attendance_row(row, names))
    logs.sort(key=lambda item: item["timestamp"] or datetime.min)
    return logs


def attendance_row(att, names: dict[str, str]) -> dict:
    user_id = clean_text(att.user_id)
    return {
        "user_id": user_id,
        "user_name": names.get(user_id, ""),
        "timestamp": att.timestamp,
        "timestamp_text": format_stamp(att.timestamp),
        "received_at": datetime.now(),
        "received_text": format_stamp(datetime.now()),
        "verify_mode": int(att.status or 0),
        "verify_text": verify_text(int(att.status or 0)),
        "inout_mode": int(att.punch or 0),
        "inout_text": inout_text(int(att.punch or 0)),
    }


def log_key(row: dict) -> str:
    return f"{row['user_id']}|{row['timestamp']}|{row['inout_mode']}|{row['verify_mode']}"


def punch_message(row: dict) -> tuple[str, str]:
    who = row["user_id"]
    if row.get("user_name"):
        who = f"{row['user_name']} ({row['user_id']})"
    body = f"{who}\n{row.get('received_text') or row['timestamp_text']}  •  {row['verify_text']} / {row['inout_text']}"
    return "Chấm công mới", body


def desktop_notify(title: str, message: str) -> None:
    title = title.replace("\n", " ")
    message = message.replace('"', "'")
    title_safe = title.replace('"', "'")
    try:
        if sys.platform == "darwin":
            script = (
                f'display notification "{message.replace(chr(10), " ")}" '
                f'with title "{title_safe}" sound name "Glass"'
            )
            subprocess.Popen(["osascript", "-e", script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif sys.platform == "win32":
            try:
                import winsound

                winsound.MessageBeep(winsound.MB_ICONASTERISK)
            except Exception:
                pass
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] > $null; "
                "$template = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
                "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                "$text = $template.GetElementsByTagName('text'); "
                f"$text.Item(0).AppendChild($template.CreateTextNode('{title_safe}')) | Out-Null; "
                f"$text.Item(1).AppendChild($template.CreateTextNode('{message.replace(chr(10), ' - ')}')) | Out-Null; "
                "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
                "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier('DG-600-ID').Show($toast)"
            )
            subprocess.Popen(
                ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        else:
            subprocess.Popen(["notify-send", title_safe, message], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def write_csv(path: str, fieldnames: list[str], rows: list[dict]) -> None:
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def export_users(path: str, users: list[dict]) -> None:
    write_csv(
        path,
        ["user_id", "name", "privilege_text", "enabled"],
        [
            {
                "user_id": u["user_id"],
                "name": u["name"],
                "privilege_text": u["privilege_text"],
                "enabled": u["enabled"],
            }
            for u in users
        ],
    )


def export_logs(path: str, logs: list[dict]) -> None:
    write_csv(
        path,
        ["user_id", "user_name", "timestamp_text", "verify_text", "inout_text"],
        logs,
    )


def run_cli(args: argparse.Namespace) -> int:
    conn = None
    try:
        print(f"Connecting {args.ip}:{args.port} ...")
        conn = connect_device(args.ip, args.port, args.key)
        info = read_device_info(conn, args.ip, args.port)
        print(f"Firmware: {info['firmware']}")
        print(f"Serial:   {info['serial']}")
        print(f"Time:     {format_stamp(info['device_time'])}")
        users = read_users(conn)
        names = {u["user_id"]: u["name"] for u in users}
        print(f"Users:    {len(users)}")
        if args.export_users:
            export_users(args.export_users, users)
            print(f"Wrote {args.export_users}")
        if args.export_logs:
            logs = read_logs(conn, names)
            export_logs(args.export_logs, logs)
            print(f"Logs:     {len(logs)}")
            print(f"Wrote {args.export_logs}")
        if args.live:
            print("Realtime ON. Cham cong tren may se in ra ngay. Ctrl+C de dung.")
            try:
                for att in conn.live_capture(new_timeout=1):
                    if att is None:
                        continue
                    row = attendance_row(att, names)
                    title, body = punch_message(row)
                    print(f"{row['timestamp_text']}  {row['user_id']}  {row['user_name']}  "
                          f"{row['verify_text']}  {row['inout_text']}", flush=True)
                    desktop_notify(title, body)
            except KeyboardInterrupt:
                print("\nStopped.")
        return 0
    finally:
        if conn is not None:
            try:
                conn.end_live_capture = True
                conn.disconnect()
            except Exception:
                pass


def run_gui(defaults: argparse.Namespace) -> int:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    class App(tk.Tk):
        def __init__(self):
            super().__init__()
            self.title("Ronald Jack DG-600-ID")
            self.geometry("1100x720")
            self.minsize(960, 600)
            self.conn = None
            self.info = None
            self.users: list[dict] = []
            self.logs: list[dict] = []
            self.seen: set[str] = set()
            self._busy = False
            self._live_thread = None
            self.live_var = tk.BooleanVar(value=True)
            self.notify_var = tk.BooleanVar(value=True)
            self._build()
            self.after(300, self.connect)

        def _build(self):
            header = tk.Frame(self, bg="#1B4F72", height=72)
            header.pack(fill="x")
            tk.Label(
                header,
                text="Đọc dữ liệu máy chấm công Ronald Jack DG-600-ID",
                bg="#1B4F72",
                fg="white",
                font=("Helvetica", 16, "bold"),
            ).pack(anchor="w", padx=18, pady=(12, 0))
            tk.Label(
                header,
                text="Bản macOS/Windows/Linux  •  protocol ZK port 4370  •  không cần zkemkeeper.dll",
                bg="#1B4F72",
                fg="#D6EAF8",
            ).pack(anchor="w", padx=18, pady=(2, 12))

            bar = tk.Frame(self, padx=12, pady=8)
            bar.pack(fill="x")
            tk.Label(bar, text="IP").grid(row=0, column=0, sticky="w")
            self.ip_var = tk.StringVar(value=defaults.ip)
            tk.Entry(bar, textvariable=self.ip_var, width=16).grid(row=1, column=0, padx=(0, 8))
            tk.Label(bar, text="Cổng").grid(row=0, column=1, sticky="w")
            self.port_var = tk.StringVar(value=str(defaults.port))
            tk.Entry(bar, textvariable=self.port_var, width=8).grid(row=1, column=1, padx=(0, 8))
            tk.Label(bar, text="Comm Key").grid(row=0, column=2, sticky="w")
            self.key_var = tk.StringVar(value=str(defaults.key))
            tk.Entry(bar, textvariable=self.key_var, width=8).grid(row=1, column=2, padx=(0, 8))
            ttk.Button(bar, text="Kết nối", command=self.connect).grid(row=1, column=3, padx=4)
            ttk.Button(bar, text="Ngắt", command=self.disconnect).grid(row=1, column=4, padx=4)
            ttk.Button(bar, text="Tải nhật ký", command=self.load_logs).grid(row=1, column=5, padx=4)
            ttk.Button(bar, text="Tải nhân viên", command=self.load_users).grid(row=1, column=6, padx=4)
            ttk.Button(bar, text="Đồng bộ giờ", command=self.sync_time).grid(row=1, column=7, padx=4)
            ttk.Button(bar, text="Xuất CSV", command=self.export_csv).grid(row=1, column=8, padx=4)
            tk.Checkbutton(
                bar,
                text="Realtime (tức thì)",
                variable=self.live_var,
                command=self.toggle_live,
                fg="#27AE60",
                font=("Helvetica", 10, "bold"),
            ).grid(row=1, column=9, padx=8)
            tk.Checkbutton(
                bar,
                text="Thông báo",
                variable=self.notify_var,
                fg="#2980B9",
                font=("Helvetica", 10, "bold"),
            ).grid(row=1, column=10, padx=8)

            self.info_var = tk.StringVar(value="Chưa kết nối.")
            tk.Label(self, textvariable=self.info_var, anchor="w", padx=14, pady=6).pack(fill="x")
            self.live_banner_var = tk.StringVar(value="Realtime sẽ bật sau khi kết nối.")
            tk.Label(
                self,
                textvariable=self.live_banner_var,
                anchor="w",
                padx=14,
                pady=8,
                bg="#E8F8F5",
                fg="#16A085",
                font=("Helvetica", 11, "bold"),
            ).pack(fill="x")

            filter_bar = tk.Frame(self, padx=12, pady=4)
            filter_bar.pack(fill="x")
            tk.Label(filter_bar, text="Từ ngày (dd/mm/yyyy)").pack(side="left")
            self.from_var = tk.StringVar()
            tk.Entry(filter_bar, textvariable=self.from_var, width=12).pack(side="left", padx=6)
            tk.Label(filter_bar, text="Đến").pack(side="left")
            self.to_var = tk.StringVar()
            tk.Entry(filter_bar, textvariable=self.to_var, width=12).pack(side="left", padx=6)
            tk.Label(filter_bar, text="Tìm").pack(side="left", padx=(12, 0))
            self.search_var = tk.StringVar()
            tk.Entry(filter_bar, textvariable=self.search_var, width=20).pack(side="left", padx=6)
            ttk.Button(filter_bar, text="Lọc", command=self.apply_filter).pack(side="left")
            self.count_var = tk.StringVar()
            tk.Label(filter_bar, textvariable=self.count_var).pack(side="left", padx=12)

            self.tabs = ttk.Notebook(self)
            self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 8))
            log_frame = ttk.Frame(self.tabs)
            user_frame = ttk.Frame(self.tabs)
            self.tabs.add(log_frame, text="Nhật ký chấm công")
            self.tabs.add(user_frame, text="Nhân viên")

            self.log_tree = self._tree(
                log_frame,
                ("user_id", "user_name", "timestamp_text", "verify_text", "inout_text"),
                ("Mã NV", "Họ tên", "Thời gian", "Xác thực", "Vào/Ra"),
                (110, 220, 160, 160, 90),
            )
            self.user_tree = self._tree(
                user_frame,
                ("user_id", "name", "privilege_text", "enabled"),
                ("Mã NV", "Họ tên", "Quyền", "Kích hoạt"),
                (120, 260, 140, 100),
            )

            self.status_var = tk.StringVar(value="Sẵn sàng.")
            tk.Label(self, textvariable=self.status_var, anchor="w", padx=12, pady=6, relief="sunken").pack(fill="x")

        def _tree(self, parent, columns, headings, widths):
            wrap = ttk.Frame(parent)
            wrap.pack(fill="both", expand=True)
            tree = ttk.Treeview(wrap, columns=columns, show="headings")
            yscroll = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=yscroll.set)
            tree.pack(side="left", fill="both", expand=True)
            yscroll.pack(side="right", fill="y")
            for col, head, width in zip(columns, headings, widths):
                tree.heading(col, text=head)
                tree.column(col, width=width, stretch=True)
            return tree

        def set_status(self, text: str):
            self.status_var.set(text)
            self.update_idletasks()

        def ensure_idle(self) -> bool:
            if self._busy:
                messagebox.showinfo("DG-600-ID", "Đang xử lý, vui lòng đợi.")
                return False
            return True

        def run_bg(self, title: str, work, done=None):
            if not self.ensure_idle():
                return
            self._busy = True
            self.configure(cursor="watch")
            self.set_status(title)

            def runner():
                error = None
                result = None
                try:
                    self.stop_live()
                    result = work()
                except Exception as exc:
                    error = exc

                def finish():
                    self._busy = False
                    self.configure(cursor="")
                    if error:
                        self.set_status("Lỗi: " + str(error))
                        messagebox.showerror("DG-600-ID", str(error))
                    elif done:
                        done(result)
                    if self.conn is not None and self.live_var.get():
                        self.start_live()

                self.after(0, finish)

            threading.Thread(target=runner, daemon=True).start()

        def connect(self):
            ip = self.ip_var.get().strip()
            port = int(self.port_var.get().strip() or DEFAULT_PORT)
            key = int(self.key_var.get().strip() or 0)

            def work():
                self.disconnect(silent=True)
                conn = connect_device(ip, port, key)
                info = read_device_info(conn, ip, port)
                users = read_users(conn)
                return conn, info, users

            def done(result):
                self.conn, self.info, self.users = result
                self.bind_users()
                self.show_info()
                self.remember_logs(self.logs)
                clock_note = ""
                if self.info["device_time"] and self.info["device_time"].year < 2015:
                    clock_note = "  |  giờ máy đang sai, nên đồng bộ"
                self.set_status(f"Đã kết nối {ip}. Serial {self.info['serial']}.{clock_note}")

            self.run_bg(f"Đang kết nối {ip}...", work, done)

        def disconnect(self, silent: bool = False):
            self.stop_live()
            if self.conn is not None:
                try:
                    self.conn.disconnect()
                except Exception:
                    pass
                self.conn = None
            if not silent:
                self.info_var.set("Đã ngắt kết nối.")
                self.live_banner_var.set("Đã ngắt kết nối. Realtime dừng.")
                self.set_status("Đã ngắt kết nối.")

        def load_users(self):
            if self.conn is None:
                messagebox.showinfo("DG-600-ID", "Hãy kết nối máy trước.")
                return

            def work():
                return read_users(self.conn)

            def done(users):
                self.users = users
                self.bind_users()
                self.tabs.select(1)
                self.set_status(f"Đã tải {len(users)} nhân viên.")

            self.run_bg("Đang tải nhân viên...", work, done)

        def load_logs(self):
            if self.conn is None:
                messagebox.showinfo("DG-600-ID", "Hãy kết nối máy trước.")
                return

            def work():
                users = self.users or read_users(self.conn)
                names = {u["user_id"]: u["name"] for u in users}
                logs = read_logs(self.conn, names)
                return users, logs

            def done(result):
                self.users, self.logs = result
                self.remember_logs(self.logs)
                self.bind_users()
                self.apply_filter()
                self.tabs.select(0)
                self.set_status(f"Đã tải {len(self.logs)} bản ghi chấm công.")

            self.run_bg("Đang tải nhật ký (có thể mất khoảng 20 giây)...", work, done)

        def sync_time(self):
            if self.conn is None:
                messagebox.showinfo("DG-600-ID", "Hãy kết nối máy trước.")
                return
            now = datetime.now()
            current = format_stamp(self.info["device_time"] if self.info else None)
            if not messagebox.askyesno(
                "Đồng bộ giờ",
                f"Đặt giờ máy chấm công theo máy tính này ({format_stamp(now)})?\nGiờ hiện tại của máy: {current}",
            ):
                return

            def work():
                self.conn.set_time(datetime.now())
                return read_device_info(self.conn, self.ip_var.get().strip(), int(self.port_var.get()))

            def done(info):
                self.info = info
                self.show_info()
                self.set_status("Đã đồng bộ giờ máy: " + format_stamp(info["device_time"]))

            self.run_bg("Đang đồng bộ giờ...", work, done)

        def export_csv(self):
            if self.tabs.index(self.tabs.select()) == 1:
                if not self.users:
                    messagebox.showinfo("Xuất CSV", "Chưa có danh sách nhân viên.")
                    return
                path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    filetypes=[("CSV", "*.csv")],
                    initialfile="nhan-vien-dg600.csv",
                )
                if path:
                    export_users(path, self.users)
                    self.set_status("Đã xuất nhân viên: " + path)
                return
            view = self.filtered_logs()
            if not view:
                messagebox.showinfo("Xuất CSV", "Chưa có nhật ký. Hãy tải nhật ký trước.")
                return
            path = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV", "*.csv")],
                initialfile="nhat-ky-cham-cong-dg600.csv",
            )
            if path:
                export_logs(path, view)
                self.set_status(f"Đã xuất {len(view)} bản ghi: {path}")

        def parse_date(self, text: str):
            text = (text or "").strip()
            if not text:
                return None
            return datetime.strptime(text, "%d/%m/%Y").date()

        def filtered_logs(self) -> list[dict]:
            view = self.logs
            try:
                start = self.parse_date(self.from_var.get())
                end = self.parse_date(self.to_var.get())
            except ValueError:
                messagebox.showerror("Lọc", "Ngày phải có dạng dd/mm/yyyy.")
                return view
            keyword = (self.search_var.get() or "").strip().lower()
            result = []
            for row in view:
                stamp = row["timestamp"]
                if start and stamp.date() < start:
                    continue
                if end and stamp.date() > end:
                    continue
                if keyword and keyword not in row["user_id"].lower() and keyword not in row["user_name"].lower():
                    continue
                result.append(row)
            return result

        def apply_filter(self):
            view = self.filtered_logs()
            self.log_tree.delete(*self.log_tree.get_children())
            for row in view:
                self.log_tree.insert(
                    "",
                    "end",
                    values=(
                        row["user_id"],
                        row["user_name"],
                        row["timestamp_text"],
                        row["verify_text"],
                        row["inout_text"],
                    ),
                )
            self.count_var.set(f"{len(view)} / {len(self.logs)} bản ghi")

        def remember_logs(self, rows: list[dict]):
            for row in rows:
                self.seen.add(log_key(row))

        def toggle_live(self):
            if self.live_var.get() and self.conn is not None:
                self.start_live()
            else:
                self.stop_live()
                self.live_banner_var.set("Realtime tắt. Bật checkbox để nhận chấm công tức thì.")

        def start_live(self):
            if self.conn is None or not self.live_var.get():
                return
            if self._live_thread is not None and self._live_thread.is_alive():
                return
            self.conn.end_live_capture = False
            self._live_thread = threading.Thread(target=self._live_loop, daemon=True)
            self._live_thread.start()
            self.live_banner_var.set("Realtime đang chạy. Chấm công trên máy sẽ hiện ngay tại đây.")
            self.set_status("Realtime bật. Đang chờ nhân viên chấm công...")

        def stop_live(self):
            conn = self.conn
            if conn is not None:
                conn.end_live_capture = True
            thread = self._live_thread
            self._live_thread = None
            if thread is not None and thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=2)

        def _live_loop(self):
            conn = self.conn
            if conn is None:
                return
            names = {u["user_id"]: u["name"] for u in self.users}
            try:
                for att in conn.live_capture(new_timeout=1):
                    if not self.live_var.get() or self.conn is None:
                        conn.end_live_capture = True
                        break
                    if att is None:
                        continue
                    row = attendance_row(att, names)
                    self.after(0, lambda r=row: self.on_live_log(r))
            except Exception as exc:
                self.after(0, lambda: self.set_status("Realtime lỗi: " + str(exc)))

        def on_live_log(self, row: dict):
            key = log_key(row)
            if key in self.seen:
                return
            self.seen.add(key)
            self.logs.append(row)
            self.apply_filter()
            children = self.log_tree.get_children()
            if children:
                self.log_tree.see(children[-1])
            self.tabs.select(0)
            name = f"  {row['user_name']}" if row["user_name"] else ""
            when = row.get("received_text") or row["timestamp_text"]
            self.live_banner_var.set(
                f"Nhân viên: {row['user_id']}{name}\nLúc: {when}  •  {row['verify_text']} / {row['inout_text']}"
            )
            self.set_status(f"Chấm công: {row['user_id']} lúc {when}")
            if self.notify_var.get():
                title, body = punch_message(row)
                desktop_notify(title, body)
                self.show_toast(title, body.replace("\n", "\n"))

        def show_toast(self, title: str, message: str):
            toast = tk.Toplevel(self)
            toast.overrideredirect(True)
            toast.configure(bg="#1B4F72")
            toast.attributes("-topmost", True)
            tk.Label(
                toast,
                text=title,
                fg="white",
                bg="#1B4F72",
                font=("Helvetica", 12, "bold"),
            ).pack(anchor="w", padx=16, pady=(12, 0))
            tk.Label(
                toast,
                text=message,
                fg="#D5F5E3",
                bg="#1B4F72",
                font=("Helvetica", 10),
                justify="left",
            ).pack(anchor="w", padx=16, pady=(4, 14))
            toast.update_idletasks()
            width = max(toast.winfo_reqwidth(), 320)
            height = toast.winfo_reqheight()
            screen_w = toast.winfo_screenwidth()
            screen_h = toast.winfo_screenheight()
            toast.geometry(f"{width}x{height}+{screen_w - width - 28}+{screen_h - height - 90}")
            toast.after(4500, toast.destroy)

        def bind_users(self):
            self.user_tree.delete(*self.user_tree.get_children())
            for user in self.users:
                self.user_tree.insert(
                    "",
                    "end",
                    values=(user["user_id"], user["name"], user["privilege_text"], user["enabled"]),
                )

        def show_info(self):
            if not self.info:
                return
            clock_note = ""
            if self.info["device_time"] and self.info["device_time"].year < 2015:
                clock_note = "  ⚠ giờ máy đang sai"
            self.info_var.set(
                f"Firmware {self.info['firmware']}   •   Serial {self.info['serial']}   •   "
                f"Giờ máy {format_stamp(self.info['device_time'])}{clock_note}   •   "
                f"{len(self.users) or self.info['user_count']} NV / {self.info['log_count']} log"
            )

        def destroy(self):
            self.disconnect(silent=True)
            super().destroy()

    App().mainloop()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Đọc dữ liệu Ronald Jack DG-600-ID")
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--key", type=int, default=0, help="Comm password, mặc định 0")
    parser.add_argument("--export-users")
    parser.add_argument("--export-logs")
    parser.add_argument("--live", action="store_true", help="Nhận chấm công realtime")
    args = parser.parse_args(argv)
    if args.export_users or args.export_logs or args.live:
        return run_cli(args)
    return run_gui(args)


if __name__ == "__main__":
    sys.exit(main())
