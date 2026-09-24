# Checkin Gateway — kế hoạch tiếp tục

> Cập nhật: 2026-09-24  
> Phạm vi: Ronald Jack DG-600-ID → CommaDesk Device Identity + `device-ingest`  
> Agent: `gateway/` (C++ / Linux / systemd)

## Đã có (MVP skeleton trong repo)

- [x] Scaffold CMake C++17: config, ZK TCP client, Device Identity enroll + HMAC, ingest, SQLite outbox, systemd unit
- [x] Config: `device_ip` / `device_port`, `base_url` CommaDesk, `data_dir`
- [x] Enroll CLI: `--enroll <pairing_code>` → lưu `auth_secret` / `signing_secret` vào SQLite
- [x] Live listen → enqueue → `POST /api/v1/checkin/device-ingest` (HMAC `cp_dsig_`)
- [x] Payload: `attendance_code` + `employee_code` = ID local máy + extras (verify/inout/work_code/device/agent)
- [x] Ghi chú Standalone-SDK: Windows DLL không chạy Linux → wire protocol ZK (cùng họ SDK / Dg600Reader)
- [x] `.gitignore` loại `gateway/build/`, `state.db`
- [x] Tài liệu vận hành sơ bộ: `gateway/README.md`

## Việc cần làm tiếp (theo thứ tự)

### P0 — Ổn định build & chạy thử

1. **Compile sạch** trên máy đích (ARM/x86): `./gateway/scripts/build.sh` — sửa warning/error còn lại nếu có; không commit `gateway/build/`.
2. **Smoke test enroll** với pairing code thật trên org CommaDesk (type `gateway`, methods GET/POST/PUT).
3. **Smoke test live punch**: 1 chấm công trên DG-600 → thấy log `[punch]` → HTTP 201 từ device-ingest.
4. **Xác nhận body extras**: nếu server trả `INVALID_BODY` vì field lạ → chuyển extras sang object `metadata` (nếu API cho phép) hoặc thêm config `ingest_minimal=true` chỉ gửi `attendance_code` + `timestamp`.

### P1 — ZK protocol đúng với DG-600-ID

5. **Đối chiếu realtime packet** với `pyzk` / Dg600Reader trên cùng máy (userid, time, verify, punch).
6. **Fix parse ATTLOG** nếu layout firmware khác (SSR string userid vs uid u16).
7. **Reconnect bền**: mất LAN / reboot máy / session timeout → auto reconnect không mất outbox.
8. **Comm password**: xác thực `device_password` trên firmware thực tế.
9. (Tuỳ chọn) **Poll fallback** đọc log mới khi live event thiếu (giống heuristic `TryIdentifyLastPunch` phía Windows SDK).

### P2 — Device Identity lifecycle

10. **Rotate + ACK**: nhận secret mới (file drop / lệnh CLI) → lưu → `POST /device-identity/credentials/ack` bằng credential mới.
11. **Không log plaintext** secrets; quyền file `state.db` / conf (`0600` / `0640`).
12. **NTP**: đảm bảo đồng hồ host ±5 phút (yêu cầu HMAC trong tài liệu).

### P3 — Vận hành

13. Chạy `scripts/install.sh` → user `checkin-gateway` → `systemctl enable --now`.
14. Log journald có cấu trúc đủ debug (không dump body chứa secrets).
15. Tài liệu vận hành ngắn: enroll / rotate / đổi IP máy / đổi `base_url`.
16. Giới hạn outbox (retention / max attempts) tránh phình SQLite trên thiết bị ~1 GB RAM.

### P4 — Không làm trong scope hiện tại

- Không enroll riêng từng DG-600 như `attendance_terminal` (gateway là principal).
- Không AuthN CommaDesk bằng IP.
- Không dùng Org API Key `cp_ak_` cho production punch.
- Không mở rộng camera / storage_agent.

## Quyết định đã chốt

| # | Quyết định |
|---|------------|
| 1 | Tên/vai trò: **checkin gateway**, `device_type = gateway` |
| 2 | Agent **không** set scope; admin cấp **GET, POST, PUT** |
| 3 | Gửi ID local + toàn bộ field lấy được để server map sau |
| 4 | Mỗi lần listen được punch → gửi API (outbox nếu lỗi mạng) |
| 5 | Tái sử dụng mô hình kết nối Standalone-SDK / Dg600Reader; trên Linux dùng ZK TCP |

## Source of truth

1. `requirements/api-may-cham-cong-device-ingest.md`
2. `requirements/device-identity-authentication.md`
3. `requirements/device-identity-device-types.md`

## Definition of done (MVP shippable)

- [ ] Binary build OK trên host gateway
- [ ] Enroll 1 lần thành công, secrets chỉ nằm trong `data_dir`
- [ ] Punch realtime → 201 device-ingest, punch hiện trên CommaDesk
- [ ] Mất mạng tạm thời → outbox retry thành công khi mạng lại
- [ ] systemd tự start lúc boot
- [ ] Checklist auth: HMAC + nonce mới mỗi request, không dùng IP làm AuthN
