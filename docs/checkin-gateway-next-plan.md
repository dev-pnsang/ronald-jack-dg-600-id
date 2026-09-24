# Checkin Gateway — kế hoạch tiếp tục

> Cập nhật: 2026-09-24  
> Phạm vi: Ronald Jack DG-600-ID → CommaDesk Device Identity + `device-ingest`  
> Agent: `gateway/` (C++ / Linux / systemd)

## Đã có

- [x] Scaffold CMake C++17: config, ZK TCP, enroll + HMAC, ingest, SQLite outbox, systemd
- [x] Live listen → outbox → `POST /checkin/device-ingest`
- [x] Payload đầy đủ + `ingest_minimal` + auto-retry minimal khi `INVALID_BODY`
- [x] `--ack-rotate <secrets.json>` (Device Identity rotate ACK)
- [x] Poll fallback ATTLOG (chỉ punch ~5 phút gần đây)
- [x] Outbox `max_attempts` / abandon + prune `seen` theo retention
- [x] `state.db` chmod `0600`, data_dir `0700`
- [x] Standalone-SDK note: Windows DLL → ZK TCP trên Linux

## Việc cần làm tiếp

### P0 — Chạy thử trên thiết bị thật

1. **Compile sạch** trên host gateway: `./gateway/scripts/build.sh`
2. **Smoke enroll** với pairing code org thật (`gateway` + GET/POST/PUT)
3. **Smoke live punch** → log `[punch]` → HTTP 201 trên CommaDesk
4. Nếu vẫn `INVALID_BODY` với full body → bật `ingest_minimal=true` (hoặc mở rộng API server chấp nhận extras/`metadata`)

### P1 — ZK protocol đúng DG-600-ID

5. Đối chiếu realtime packet với `pyzk` / Dg600Reader (userid, time, verify, punch)
6. Fix parse ATTLOG nếu layout firmware khác
7. Stress reconnect (rút LAN / reboot máy)
8. Xác thực `device_password` trên firmware thật

### P2 — Vận hành

9. `scripts/install.sh` + `systemctl enable --now`
10. NTP host ±5 phút
11. Runbook ngắn: đổi IP máy / đổi `base_url` / rotate

### P3 — Ngoài scope

- Không enroll DG-600 như `attendance_terminal`
- Không AuthN bằng IP / Org API Key `cp_ak_`

## Quyết định đã chốt

| # | Quyết định |
|---|------------|
| 1 | **checkin gateway**, `device_type = gateway` |
| 2 | Admin cấp **GET, POST, PUT** — agent không set scope |
| 3 | Gửi ID local + field lấy được (hoặc minimal) |
| 4 | Listen punch → gửi API (outbox nếu lỗi) |
| 5 | Linux: ZK TCP (cùng họ Standalone SDK) |

## Source of truth

1. `requirements/api-may-cham-cong-device-ingest.md`
2. `requirements/device-identity-authentication.md`
3. `requirements/device-identity-device-types.md`

## Definition of done

- [x] Binary build OK (ARM host, `./gateway/scripts/build.sh`)
- [ ] Enroll OK, secrets chỉ trong `data_dir`
- [ ] Punch realtime → 201 + hiện trên CommaDesk
- [ ] Mất mạng → outbox retry OK
- [ ] systemd auto-start
- [ ] HMAC + nonce mới mỗi request
