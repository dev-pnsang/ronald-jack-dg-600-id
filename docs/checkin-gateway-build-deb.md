# Build & cài `.deb` Checkin Gateway

> Cập nhật: 2026-09-25  
> Package hiện tại: **checkin-gateway 1.2.8** (arm64)  
> Gồm 2 process độc lập: `checkin-gateway` + `checkin-ota`

## Kiến trúc CPU (bắt buộc)

| Máy build | File `.deb` | Chạy trên Orange Pi Zero3 / Armbian arm64 |
|-----------|-------------|-------------------------------------------|
| **arm64 / aarch64** (Pi, Zero3, VM arm64) | `*_arm64.deb` | OK |
| x86_64 (PC/laptop thường) | `*_amd64.deb` | **Không** — sai kiến trúc |
| armhf (32-bit) | `*_armhf.deb` | **Không** |

Kiểm tra máy build / máy cài:

```bash
uname -m          # kỳ vọng: aarch64
dpkg --print-architecture   # kỳ vọng: arm64
```

Build trên máy arm64 A rồi copy `.deb` sang Zero3 (cùng arm64) là đúng cách — **không** ảnh hưởng runtime.

## Dependencies (một lần trên máy build)

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config \
  libcurl4-openssl-dev libssl-dev libsqlite3-dev nlohmann-json3-dev
```

## Build `.deb` 1.2.8

Từ thư mục `gateway/` trong repo:

```bash
cd /path/to/ronald-jack-dg-600-id/gateway

# Version mặc định trong scripts/build-deb.sh là 1.2.8; có thể override:
export CHECKIN_GATEWAY_VERSION=1.2.8

./scripts/build-deb.sh
```

Kết quả:

```text
dist/checkin-gateway_1.2.8_arm64.deb
```

Gói cài:

- `/usr/bin/checkin-gateway`, `/usr/bin/checkin-ota`
- `/usr/sbin/checkin-gatewayctl`
- `/etc/checkin-gateway/checkin-gateway.conf`
- `/lib/systemd/system/checkin-gateway.service`
- `/lib/systemd/system/checkin-ota.service` (không `BindsTo` gateway — OTA sống sót nếu update gateway lỗi)
- State: `/var/lib/checkin-gateway/`

## Cài trên gateway (vd. Zero3 `192.168.2.29`)

```bash
# Copy file sang máy đích rồi:
sudo dpkg -i ./checkin-gateway_1.2.8_arm64.deb
# nếu thiếu shared libs:
sudo apt-get -y -f install
```

### Lần đầu (plug-and-run)

```bash
# API backend — KHÔNG dùng cổng frontend :3000
sudo checkin-gatewayctl set-server https://YOUR-HOST/api/v1
# Lab ví dụ: http://192.168.2.19:8080/api/v1

sudo checkin-gatewayctl enroll 'cp_pair_....'
sudo checkin-gatewayctl enable
sudo checkin-gatewayctl status
```

Kỳ vọng: `enrolled=true`, cả `checkin-gateway` và `checkin-ota` đều `active` / `enabled`.

Từ **1.2.7+**, enroll (chạy root) tự `chown` `state.db` sang user `checkin-gateway` — tránh lỗi `store: unable to open database file`. Từ **1.2.8**, OTA `.deb` giữ conf local (không hỏi Y/N).

### Nâng cấp (máy đã enroll)

```bash
sudo dpkg -i ./checkin-gateway_1.2.8_arm64.deb
# conf + state.db được giữ; postinst restart gateway (OTA unit độc lập)
sudo checkin-gatewayctl status
```

## Chỉ build binary (không đóng gói)

```bash
cd gateway
./scripts/build.sh
# ra: build/checkin-gateway , build/checkin-ota
```

## Kiểm tra nhanh sau cài

```bash
dpkg -l checkin-gateway
cat /etc/checkin-gateway.ota-version
systemctl status checkin-gateway checkin-ota --no-pager
journalctl -u checkin-gateway -n 30 --no-pager
```

Log tốt: `[catalog]`, `[heartbeat] ok`, `[bootstrap] ok`, `[zk] live listen ON` (khi máy chấm TCP :4370 thông).

Trên Device Monitor (ops logs tiếng Việt): `terminal_matched` / `connect_ok` khi catalog trùng IP:port local và ZK kết nối được; `connect_fail` nếu LAN tới máy chấm lỗi.

## OTA (cập nhật từ xa)

Sau khi có `.deb` / `.tar.gz` (gzip) + SHA-256 trên HTTPS:

1. Đăng ký gói trên UI Device OTA (CommaDesk)
2. Tạo job cho device
3. Trên gateway:

```bash
sudo /usr/bin/checkin-ota --once --config /etc/checkin-gateway/checkin-gateway.conf
```

Agent nhận diện format bằng magic bytes (`.tar.gz` hoặc `.deb`). Khi cài chỉ restart **checkin-gateway**, không kill process OTA.

**Conffile khi OTA `.deb`:** agent chạy `dpkg --force-confdef --force-confold` + `DEBIAN_FRONTEND=noninteractive` → **không hỏi** Y/N; **giữ** `/etc/checkin-gateway/checkin-gateway.conf` đang dùng (không ghi đè `base_url` / `device_ip`). Không chọn `Y` kiểu tay khi chạy `--once` trên terminal với bản OTA cũ hơn fix này.

## Xem thêm

- Vận hành / enroll: [`gateway/README.md`](../gateway/README.md)
- Kế hoạch tiếp: [`checkin-gateway-next-plan.md`](./checkin-gateway-next-plan.md)
