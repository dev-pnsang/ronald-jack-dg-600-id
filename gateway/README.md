# Checkin Gateway (Ronald Jack DG-600-ID)

Linux background agent: listen attendance punches from **Ronald Jack DG-600-ID** (ZK protocol, port 4370) and POST them to CommaDesk `POST /api/v1/checkin/device-ingest` using **Device Identity** (Bearer `cp_dev_` + HMAC `cp_dsig_`).

Platform device role: **checkin gateway** (`device_type = gateway`). Agent does **not** set scopes — admin grants **GET / POST / PUT** on the CommaDesk Device Identity.

Next-step plan: [`docs/checkin-gateway-next-plan.md`](../docs/checkin-gateway-next-plan.md)


## Install from .deb (recommended)

```bash
./scripts/build-deb.sh
sudo apt install -y ./dist/checkin-gateway_*_*.deb
# or: sudo dpkg -i ./dist/checkin-gateway_*_*.deb
```

First boot / plug-and-run:

```bash
sudo checkin-gatewayctl set-server https://YOUR-HOST/api/v1
# optional LAN terminal fallback if catalog empty:
sudo checkin-gatewayctl set-device 192.168.2.96 4370
sudo checkin-gatewayctl enroll 'cp_pair_....'
sudo checkin-gatewayctl enable
sudo checkin-gatewayctl status
```

Service uses `/etc/checkin-gateway/checkin-gateway.conf` and state in `/var/lib/checkin-gateway`.
ATTLOG sync runs at local **00:00** and **12:00** only (from `usage_started_on`).

## Source of truth

- `requirements/api-may-cham-cong-device-ingest.md`
- `requirements/device-identity-authentication.md`
- `requirements/device-identity-device-types.md`

## Standalone SDK note

`requirements/Standalone-SDK` ships **Windows 32-bit COM DLLs** (`zkemkeeper.dll`, …). They cannot load on Linux.

This agent reuses the **same wire protocol / field model** as the Standalone SDK and the existing `src/Dg600Reader` client:

| SDK / Dg600Reader | Gateway |
|-------------------|---------|
| `Connect_Net(ip, port)` | ZK TCP connect |
| `RegEvent(..., 65535)` + RT events | `StartLiveCapture` + `PollLive` |
| `SSR_GetGeneralLogData` / ATTLOG | `ReadAttendanceLogs` (poll fallback) |
| IP/port | Config only (LAN connectivity — **not** CommaDesk AuthN) |

## Build

```bash
sudo apt-get install -y build-essential cmake pkg-config \
  libcurl4-openssl-dev libssl-dev libsqlite3-dev nlohmann-json3-dev
./gateway/scripts/build.sh
```

## Configure

```bash
cp gateway/config/checkin-gateway.conf.example /etc/checkin-gateway/checkin-gateway.conf
# set device_ip, device_port, base_url
```

Useful keys: `ingest_minimal`, `poll_fallback`, `outbox_max_attempts`, `outbox_retention_days`.

## Enroll (once)

1. Admin creates Device Identity type **Gateway**, methods **GET, POST, PUT**, then **Pairing**.
2. On the gateway host:

```bash
checkin-gateway --config /etc/checkin-gateway/checkin-gateway.conf --enroll 'cp_pair_....'
```

Secrets are stored in `$data_dir/state.db` (mode `0600`) — do not commit or log them.

## Rotate + ACK

After admin **Rotate** on CommaDesk, write new secrets to a temp JSON file (delete after):

```json
{"auth_secret":"cp_dev_...","signing_secret":"cp_dsig_..."}
```

```bash
checkin-gateway --config /etc/checkin-gateway/checkin-gateway.conf \
  --ack-rotate /tmp/new-secrets.json
shred -u /tmp/new-secrets.json   # or rm
```

## Run as systemd service

```bash
sudo ./gateway/scripts/install.sh
sudo systemctl enable --now checkin-gateway
journalctl -u checkin-gateway -f
```

## Ingest payload

Default (`ingest_minimal=false`): contract fields + extras for server-side mapping:

- `attendance_code` / `employee_code` = local machine user ID  
- `timestamp` = device punch time (ISO-8601 `Z`)  
- `verify_mode`, `inout_mode`, `work_code`, `user_name`, device serial/firmware, agent metadata  

If server returns `INVALID_BODY`, the agent retries that punch with minimal `{attendance_code,timestamp}` once. Set `ingest_minimal=true` to always send minimal.

## Auth rules (unchanged)

- No Org API Key (`cp_ak_`), no user JWT for production punches  
- No IP-based CommaDesk authentication  
- DG-600 itself is **not** enrolled — only the checkin gateway agent is  
