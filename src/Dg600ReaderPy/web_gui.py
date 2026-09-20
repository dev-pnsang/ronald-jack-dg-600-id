#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI web cho DG-600-ID — ổn định trên macOS (tránh Tk Aqua lỗi Label/Entry)."""
from __future__ import annotations

import argparse
import json
import threading
import time
import webbrowser
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from dg600_reader import (
    DEFAULT_IP,
    DEFAULT_PORT,
    attendance_row,
    connect_device,
    desktop_notify,
    export_logs,
    export_users,
    format_stamp,
    log_key,
    punch_message,
    read_device_info,
    read_logs,
    read_users,
)

HOST = "127.0.0.1"
PORT = 8765

STATE = {
    "lock": threading.RLock(),
    "conn": None,
    "info": None,
    "users": [],
    "logs": [],
    "seen": set(),
    "status": "Chưa kết nối.",
    "banner": "Realtime sẽ bật sau khi kết nối.",
    "ip": DEFAULT_IP,
    "port": DEFAULT_PORT,
    "key": 0,
    "live": True,
    "notify": True,
    "live_thread": None,
    "events": [],
    "filter": {"from": "", "to": "", "search": ""},
}


HTML = """<!DOCTYPE html>
<html lang="vi">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Ronald Jack DG-600-ID</title>
<style>
  :root { --ink:#1a2332; --muted:#5b6777; --line:#d7dde5; --bg:#f4f6f8; --card:#fff; --accent:#1b4f72; --ok:#0e6655; }
  * { box-sizing: border-box; }
  body { margin:0; font:15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color:var(--ink); background:var(--bg); }
  header { background:var(--accent); color:#fff; padding:18px 22px; }
  header h1 { margin:0; font-size:20px; font-weight:700; }
  main { max-width:1100px; margin:0 auto; padding:18px; }
  .panel { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:16px; margin-bottom:14px; }
  .row { display:flex; flex-wrap:wrap; gap:10px; align-items:end; }
  label { display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted); font-weight:600; }
  input[type=text], input[type=number] { width:140px; padding:8px 10px; border:1px solid var(--line); border-radius:6px; font:inherit; color:var(--ink); background:#fff; }
  input.wide { width:200px; }
  button { padding:8px 14px; border:1px solid var(--line); border-radius:6px; background:#eef2f6; color:var(--ink); font:inherit; font-weight:600; cursor:pointer; }
  button.primary { background:var(--accent); color:#fff; border-color:var(--accent); }
  button:disabled { opacity:.55; cursor:wait; }
  .checks { display:flex; gap:16px; align-items:center; margin-top:12px; color:var(--ink); }
  .checks label { flex-direction:row; align-items:center; gap:6px; font-size:14px; color:var(--ink); }
  .status { margin-top:12px; padding:10px 12px; background:#eef6fb; border-radius:6px; color:var(--accent); font-weight:600; }
  .banner { margin-top:8px; color:var(--ok); font-weight:600; white-space:pre-line; }
  .banner.flash { background:#e8f8f5; border:1px solid #a3e4d7; border-radius:8px; padding:12px 14px; color:#0e6655; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { padding:8px 10px; border-bottom:1px solid var(--line); text-align:left; }
  th { background:#f0f3f7; position:sticky; top:0; }
  .table-wrap { max-height:420px; overflow:auto; border:1px solid var(--line); border-radius:8px; }
  .tabs { display:flex; gap:8px; margin-bottom:10px; }
  .tabs button.active { background:var(--accent); color:#fff; border-color:var(--accent); }
  .hidden { display:none; }
  .err { color:#a93226; white-space:pre-wrap; }
  #toast {
    position:fixed; right:20px; bottom:20px; min-width:280px; max-width:380px;
    background:#1b4f72; color:#fff; border-radius:10px; padding:14px 16px;
    box-shadow:0 10px 30px rgba(0,0,0,.25); z-index:99; display:none;
  }
  #toast strong { display:block; margin-bottom:4px; font-size:15px; }
  #toast span { white-space:pre-line; opacity:.95; font-size:13px; }
  tr.new-row { background:#e8f8f5; }
</style>
</head>
<body>
<header>
  <h1>Đọc dữ liệu máy chấm công Ronald Jack DG-600-ID</h1>
</header>
<main>
  <section class="panel">
    <div class="row">
      <label>IP <input id="ip" type="text" value="__IP__"/></label>
      <label>Cổng <input id="port" type="number" value="__PORT__"/></label>
      <label>Comm Key <input id="key" type="number" value="__KEY__"/></label>
      <button class="primary" onclick="connect()">Kết nối</button>
      <button onclick="disconnect()">Ngắt</button>
      <button onclick="loadLogs()">Tải nhật ký</button>
      <button onclick="loadUsers()">Tải nhân viên</button>
      <button onclick="syncTime()">Đồng bộ giờ</button>
      <button onclick="exportCsv()">Xuất CSV</button>
    </div>
    <div class="checks">
      <label><input id="live" type="checkbox" checked onchange="setOptions()"/> Realtime (tức thì)</label>
      <label><input id="notify" type="checkbox" checked onchange="setOptions()"/> Thông báo</label>
    </div>
    <div id="info" class="status">Chưa kết nối.</div>
    <div id="banner" class="banner">Realtime sẽ bật sau khi kết nối.</div>
  </section>

  <section class="panel">
    <div class="row">
      <label>Từ ngày (dd/mm/yyyy) <input id="from" type="text" placeholder="01/01/2026"/></label>
      <label>Đến <input id="to" type="text" placeholder="31/12/2026"/></label>
      <label>Tìm <input id="search" class="wide" type="text" placeholder="Mã NV / tên"/></label>
      <button onclick="applyFilter()">Lọc</button>
      <span id="count"></span>
    </div>
  </section>

  <section class="panel">
    <div class="tabs">
      <button id="tab-logs" class="active" onclick="showTab('logs')">Nhật ký chấm công</button>
      <button id="tab-users" onclick="showTab('users')">Nhân viên</button>
    </div>
    <div id="panel-logs" class="table-wrap">
      <table>
        <thead><tr><th>Mã NV</th><th>Họ tên</th><th>Thời gian</th><th>Xác thực</th><th>Vào/Ra</th></tr></thead>
        <tbody id="logs-body"></tbody>
      </table>
    </div>
    <div id="panel-users" class="table-wrap hidden">
      <table>
        <thead><tr><th>Mã NV</th><th>Họ tên</th><th>Quyền</th><th>Kích hoạt</th></tr></thead>
        <tbody id="users-body"></tbody>
      </table>
    </div>
  </section>
  <p id="error" class="err"></p>
</main>
<div id="toast"><strong id="toast-title"></strong><span id="toast-body"></span></div>
<script>
let currentTab = 'logs';
let busy = false;

function showTab(name) {
  currentTab = name;
  document.getElementById('panel-logs').classList.toggle('hidden', name !== 'logs');
  document.getElementById('panel-users').classList.toggle('hidden', name !== 'users');
  document.getElementById('tab-logs').classList.toggle('active', name === 'logs');
  document.getElementById('tab-users').classList.toggle('active', name === 'users');
}

async function api(path, body) {
  const opts = body !== undefined
    ? { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) }
    : {};
  const res = await fetch(path, opts);
  const data = await res.json();
  if (!res.ok || data.error) throw new Error(data.error || res.statusText);
  return data;
}

function fill(data, opts) {
  opts = opts || {};
  if (data.status) document.getElementById('info').textContent = data.status;
  if (data.banner != null) {
    const el = document.getElementById('banner');
    el.textContent = data.banner;
    el.classList.toggle('flash', !!data.punch);
  }
  if (data.count != null) document.getElementById('count').textContent = data.count;
  if (data.users) {
    document.getElementById('users-body').innerHTML = data.users.map(u =>
      '<tr><td>'+esc(u.user_id)+'</td><td>'+esc(u.name)+'</td><td>'+esc(u.privilege_text)+'</td><td>'+esc(u.enabled)+'</td></tr>'
    ).join('');
  }
  if (data.logs) {
    document.getElementById('logs-body').innerHTML = data.logs.map((r, i) => {
      const cls = opts.highlightLast && i === data.logs.length - 1 ? ' class="new-row"' : '';
      return '<tr'+cls+'><td>'+esc(r.user_id)+'</td><td>'+esc(r.user_name)+'</td><td>'+esc(r.timestamp_text)+'</td><td>'+esc(r.verify_text)+'</td><td>'+esc(r.inout_text)+'</td></tr>';
    }).join('');
    if (opts.highlightLast && data.logs.length) {
      const wrap = document.getElementById('panel-logs');
      wrap.scrollTop = wrap.scrollHeight;
      showTab('logs');
    }
  }
}

function showToast(title, body) {
  if (!document.getElementById('notify').checked) return;
  const box = document.getElementById('toast');
  document.getElementById('toast-title').textContent = title;
  document.getElementById('toast-body').textContent = body;
  box.style.display = 'block';
  clearTimeout(showToast._t);
  showToast._t = setTimeout(function(){ box.style.display = 'none'; }, 5000);
}

function esc(v){
  return String(v == null ? '' : v).replace(/[&<>"']/g, function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
  });
}

function form() {
  return {
    ip: document.getElementById('ip').value.trim(),
    port: Number(document.getElementById('port').value || 4370),
    key: Number(document.getElementById('key').value || 0),
    from: document.getElementById('from').value.trim(),
    to: document.getElementById('to').value.trim(),
    search: document.getElementById('search').value.trim(),
    live: document.getElementById('live').checked,
    notify: document.getElementById('notify').checked,
    tab: currentTab,
  };
}

async function run(fn) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(function(b){ b.disabled = true; });
  document.getElementById('error').textContent = '';
  try { fill(await fn()); }
  catch (e) { document.getElementById('error').textContent = e.message || String(e); }
  finally {
    busy = false;
    document.querySelectorAll('button').forEach(function(b){ b.disabled = false; });
  }
}

function connect(){ return run(function(){ return api('/api/connect', form()); }); }
function disconnect(){ return run(function(){ return api('/api/disconnect', {}); }); }
function loadLogs(){ return run(function(){ return api('/api/logs', form()); }); }
function loadUsers(){ return run(function(){ return api('/api/users', form()); }); }
function syncTime(){ return run(function(){ return api('/api/sync-time', form()); }); }
function applyFilter(){ return run(function(){ return api('/api/filter', form()); }); }
function exportCsv(){ return run(function(){ return api('/api/export', form()); }); }
function setOptions(){ return run(function(){ return api('/api/options', form()); }); }

async function poll() {
  if (busy) return;
  try {
    const data = await api('/api/poll', form());
    if (data.events && data.events.length) {
      fill(data, { highlightLast: true });
      const last = data.events[data.events.length - 1];
      showToast(last.title, last.body);
    } else if (data.banner) {
      document.getElementById('banner').textContent = data.banner;
      if (data.status) document.getElementById('info').textContent = data.status;
    }
  } catch (e) {}
}

run(function(){ return api('/api/state'); });
setInterval(poll, 1000);
</script>
</body>
</html>
"""


def _serialize_logs(logs):
    return [
        {
            "user_id": r["user_id"],
            "user_name": r.get("user_name", ""),
            "timestamp_text": r.get("timestamp_text", ""),
            "verify_text": r.get("verify_text", ""),
            "inout_text": r.get("inout_text", ""),
        }
        for r in logs
    ]


def _parse_date(text):
    text = (text or "").strip()
    if not text:
        return None
    return datetime.strptime(text, "%d/%m/%Y").date()


def _remember_filter(payload):
    STATE["filter"] = {
        "from": payload.get("from") or "",
        "to": payload.get("to") or "",
        "search": payload.get("search") or "",
    }


def _filter_logs(payload=None):
    payload = payload or STATE["filter"]
    logs = STATE["logs"]
    start = _parse_date(payload.get("from"))
    end = _parse_date(payload.get("to"))
    keyword = (payload.get("search") or "").strip().lower()
    result = []
    for row in logs:
        stamp = row.get("timestamp")
        if start and (not stamp or stamp.date() < start):
            continue
        if end and (not stamp or stamp.date() > end):
            continue
        blob = f"{row.get('user_id', '')} {row.get('user_name', '')}".lower()
        if keyword and keyword not in blob:
            continue
        result.append(row)
    return result


def _info_text():
    info = STATE["info"]
    if not info:
        return STATE["status"]
    note = ""
    if info.get("device_time") and info["device_time"].year < 2015:
        note = "  |  giờ máy đang sai, nên đồng bộ"
    return (
        f"Firmware {info.get('firmware', '')}  •  Serial {info.get('serial', '')}  •  "
        f"Giờ máy {format_stamp(info.get('device_time'))}{note}  •  "
        f"{len(STATE['users']) or info.get('user_count', 0)} NV / {info.get('log_count', 0)} log"
    )


def _snapshot(filtered=None, punch=False):
    logs = filtered if filtered is not None else _filter_logs()
    return {
        "status": _info_text(),
        "banner": STATE["banner"],
        "users": STATE["users"],
        "logs": _serialize_logs(logs),
        "count": f"{len(logs)} / {len(STATE['logs'])} bản ghi",
        "punch": punch,
        "live": STATE["live"],
        "notify": STATE["notify"],
    }


def _stop_live():
    conn = STATE["conn"]
    if conn is not None:
        try:
            conn.end_live_capture = True
        except Exception:
            pass
    thread = STATE["live_thread"]
    STATE["live_thread"] = None
    return thread


def _join_live(thread):
    if thread is not None and thread.is_alive() and thread is not threading.current_thread():
        thread.join(timeout=2)


def _start_live():
    if not STATE["live"] or STATE["conn"] is None:
        return
    thread = STATE["live_thread"]
    if thread is not None and thread.is_alive():
        return
    try:
        STATE["conn"].end_live_capture = False
    except Exception:
        pass
    t = threading.Thread(target=_live_loop, daemon=True)
    STATE["live_thread"] = t
    t.start()
    STATE["banner"] = "Realtime đang chạy. Chấm công trên máy sẽ hiện ngay tại đây."
    STATE["status"] = "Realtime bật. Đang chờ nhân viên chấm công..."


def _live_loop():
    conn = STATE["conn"]
    if conn is None:
        return
    try:
        with STATE["lock"]:
            names = {u["user_id"]: u["name"] for u in STATE["users"]}
        for att in conn.live_capture(new_timeout=1):
            if not STATE["live"] or STATE["conn"] is None:
                try:
                    conn.end_live_capture = True
                except Exception:
                    pass
                break
            if att is None:
                continue
            row = attendance_row(att, names)
            _on_live_log(row)
    except Exception as exc:
        with STATE["lock"]:
            STATE["status"] = "Realtime lỗi: " + str(exc)
            STATE["banner"] = STATE["status"]


def _on_live_log(row):
    with STATE["lock"]:
        key = log_key(row)
        if key in STATE["seen"]:
            return
        STATE["seen"].add(key)
        STATE["logs"].append(row)
        name = f"  {row['user_name']}" if row.get("user_name") else ""
        when = row.get("received_text") or row["timestamp_text"]
        STATE["banner"] = (
            f"Nhân viên: {row['user_id']}{name}\n"
            f"Lúc: {when}  •  {row['verify_text']} / {row['inout_text']}"
        )
        STATE["status"] = f"Chấm công: {row['user_id']} lúc {when}"
        title, body = punch_message(row)
        STATE["events"].append({"title": title, "body": body, "row": _serialize_logs([row])[0]})
        if len(STATE["events"]) > 50:
            STATE["events"] = STATE["events"][-50:]
        notify = STATE["notify"]
    if notify:
        desktop_notify(title, body)


def _close_conn():
    thread = _stop_live()
    conn = STATE["conn"]
    STATE["conn"] = None
    if conn is not None:
        try:
            conn.end_live_capture = True
        except Exception:
            pass
        try:
            conn.disconnect()
        except Exception:
            pass
    return thread


def _pause_live_run(fn):
    with STATE["lock"]:
        thread = _stop_live()
    _join_live(thread)
    time.sleep(0.15)
    try:
        with STATE["lock"]:
            result = fn()
            _start_live()
            return result
    except Exception:
        with STATE["lock"]:
            _start_live()
        raise


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _json(self, code, payload):
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            body = (
                HTML.replace("__IP__", STATE["ip"])
                .replace("__PORT__", str(STATE["port"]))
                .replace("__KEY__", str(STATE["key"]))
                .encode("utf-8")
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/state":
            with STATE["lock"]:
                self._json(200, _snapshot())
            return
        self._json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            payload = self._read_json()

            if path == "/api/connect":
                with STATE["lock"]:
                    thread = _close_conn()
                _join_live(thread)
                with STATE["lock"]:
                    ip = (payload.get("ip") or DEFAULT_IP).strip()
                    port = int(payload.get("port") or DEFAULT_PORT)
                    key = int(payload.get("key") or 0)
                    STATE["live"] = bool(payload.get("live", True))
                    STATE["notify"] = bool(payload.get("notify", True))
                    STATE["ip"], STATE["port"], STATE["key"] = ip, port, key
                    STATE["status"] = f"Đang kết nối {ip}..."
                    conn = connect_device(ip, port, key)
                    info = read_device_info(conn, ip, port)
                    users = read_users(conn)
                    STATE["conn"], STATE["info"], STATE["users"] = conn, info, users
                    STATE["status"] = f"Đã kết nối {ip}. Serial {info.get('serial', '')}."
                    _start_live()
                    self._json(200, _snapshot())
                return

            if path == "/api/disconnect":
                with STATE["lock"]:
                    thread = _close_conn()
                _join_live(thread)
                with STATE["lock"]:
                    STATE["info"] = None
                    STATE["status"] = "Đã ngắt kết nối."
                    STATE["banner"] = "Đã ngắt kết nối. Realtime dừng."
                    self._json(200, _snapshot())
                return

            if path == "/api/options":
                with STATE["lock"]:
                    STATE["live"] = bool(payload.get("live", True))
                    STATE["notify"] = bool(payload.get("notify", True))
                    want_live = STATE["live"] and STATE["conn"] is not None
                    if want_live:
                        _start_live()
                        STATE["banner"] = "Realtime đang chạy. Chấm công trên máy sẽ hiện ngay tại đây."
                        self._json(200, _snapshot())
                        return
                    thread = _stop_live()
                _join_live(thread)
                with STATE["lock"]:
                    STATE["banner"] = "Realtime tắt. Bật checkbox để nhận chấm công tức thì."
                    self._json(200, _snapshot())
                return

            if path == "/api/poll":
                with STATE["lock"]:
                    _remember_filter(payload)
                    events = list(STATE["events"])
                    STATE["events"] = []
                    snap = _snapshot(punch=bool(events))
                    snap["events"] = events
                    self._json(200, snap)
                return

            if path == "/api/users":
                def work():
                    if STATE["conn"] is None:
                        raise RuntimeError("Hãy kết nối máy trước.")
                    STATE["users"] = read_users(STATE["conn"])
                    STATE["status"] = f"Đã tải {len(STATE['users'])} nhân viên."
                    return _snapshot()

                self._json(200, _pause_live_run(work))
                return

            if path == "/api/logs":
                def work():
                    if STATE["conn"] is None:
                        raise RuntimeError("Hãy kết nối máy trước.")
                    _remember_filter(payload)
                    users = STATE["users"] or read_users(STATE["conn"])
                    STATE["users"] = users
                    names = {u["user_id"]: u["name"] for u in users}
                    logs = read_logs(STATE["conn"], names)
                    STATE["logs"] = logs
                    STATE["seen"] = {log_key(r) for r in logs}
                    filtered = _filter_logs(payload)
                    STATE["status"] = f"Đã tải {len(logs)} bản ghi chấm công."
                    STATE["banner"] = STATE["status"]
                    return _snapshot(filtered)

                self._json(200, _pause_live_run(work))
                return

            if path == "/api/filter":
                with STATE["lock"]:
                    _remember_filter(payload)
                    filtered = _filter_logs(payload)
                    STATE["status"] = f"Đang xem {len(filtered)}/{len(STATE['logs'])} bản ghi."
                    self._json(200, _snapshot(filtered))
                return

            if path == "/api/sync-time":
                def work():
                    if STATE["conn"] is None:
                        raise RuntimeError("Hãy kết nối máy trước.")
                    STATE["conn"].set_time(datetime.now())
                    STATE["info"] = read_device_info(STATE["conn"], STATE["ip"], STATE["port"])
                    STATE["status"] = "Đã đồng bộ giờ máy: " + format_stamp(STATE["info"]["device_time"])
                    return _snapshot()

                self._json(200, _pause_live_run(work))
                return

            if path == "/api/export":
                with STATE["lock"]:
                    tab = payload.get("tab") or "logs"
                    if tab == "users":
                        if not STATE["users"]:
                            raise RuntimeError("Chưa có danh sách nhân viên.")
                        path_out = "nhan-vien-dg600.csv"
                        export_users(path_out, STATE["users"])
                    else:
                        filtered = _filter_logs(payload)
                        if not filtered:
                            raise RuntimeError("Chưa có nhật ký. Hãy tải nhật ký trước.")
                        path_out = "nhat-ky-cham-cong-dg600.csv"
                        export_logs(path_out, filtered)
                    STATE["status"] = "Đã xuất: " + path_out
                    self._json(200, _snapshot(_filter_logs(payload)))
                return

            self._json(404, {"error": "Not found"})
        except Exception as exc:
            self._json(400, {"error": str(exc)})


def run_web(defaults):
    STATE["ip"] = defaults.ip
    STATE["port"] = defaults.port
    STATE["key"] = defaults.key
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    url = f"http://{HOST}:{PORT}/"
    print(f"Mo GUI web: {url}")
    print("Giữ cửa sổ Terminal này mở. Ctrl+C để dừng.")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDung server.")
    finally:
        with STATE["lock"]:
            thread = _close_conn()
        _join_live(thread)
        server.server_close()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="DG-600-ID web GUI")
    parser.add_argument("--ip", default=DEFAULT_IP)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--key", type=int, default=0)
    return run_web(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
