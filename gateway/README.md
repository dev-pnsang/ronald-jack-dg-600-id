# Checkin Gateway (Ronald Jack DG-600-ID)

Linux background agent: listen attendance punches from **Ronald Jack DG-600-ID** (ZK protocol, port 4370) and POST them to CommaDesk `POST /api/v1/checkin/device-ingest` using **Device Identity** (Bearer `cp_dev_` + HMAC `cp_dsig_`).

Platform device role: **checkin gateway** (`device_type = gateway`). Agent does **not** set scopes — admin grants **GET / POST / PUT** on the CommaDesk Device Identity.

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
| `SSR_GetGeneralLogData` fields | `user_id`, verify, inout, work_code, timestamp |
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

## Enroll (once)

1. Admin creates Device Identity type **Gateway**, methods **GET, POST, PUT**, then **Pairing**.
2. On the gateway host:

```bash
checkin-gateway --config /etc/checkin-gateway/checkin-gateway.conf --enroll 'cp_pair_....'
```

Secrets are stored in `$data_dir/state.db` — do not commit or log them.

## Run as systemd service

```bash
sudo ./gateway/scripts/install.sh
sudo systemctl enable --now checkin-gateway
journalctl -u checkin-gateway -f
```

## Ingest payload

Each live punch sends compact JSON including contract fields plus extras for server-side mapping:

- `attendance_code` / `employee_code` = local machine user ID  
- `timestamp` = device punch time (ISO-8601 `Z`)  
- `verify_mode`, `inout_mode`, `work_code`, `user_name`, device serial/firmware, agent metadata  

If the current server rejects unknown fields, trim extras server-side or tell us to send a minimal body.

## Auth rules (unchanged)

- No Org API Key (`cp_ak_`), no user JWT for production punches  
- No IP-based CommaDesk authentication  
- DG-600 itself is **not** enrolled — only the checkin gateway agent is  
