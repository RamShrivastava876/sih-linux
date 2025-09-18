# Secure Wipe Backend

A FastAPI backend for secure data wiping.

## Features
- List storage devices
- Secure erase (multiple methods)
- Real-time progress
- Certificate generation (JSON + PDF, Ed25519 signature)

## Setup
1. Create a Python virtual environment:
   ```sh
   python -m venv venv
   venv\Scripts\activate  # Windows
   # or
   source venv/bin/activate  # Linux/Mac
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Run the server:
   ```sh
   uvicorn main:app --reload
   ```

## Endpoints
- `GET /devices` — List storage devices
- `POST /erase` — Start erase process
- `GET /certificate` — Download certificate

## Platform behavior and limits

This project uses a local backend to interact with disks; the browser alone cannot access raw devices. Capabilities vary by OS and device type.

### Privileges
- Run the backend with Administrator/root privileges.
- Ensure the target disk is not in use by other processes.

### Hidden areas (HPA/DCO — ATA only)
- Enable via `CERTIWIPE_ENABLE_HPA_DCO=1`.
- Linux: requires `hdparm`; attempts `-N p<NATIVE>` and `--dco-restore` with evidence recorded in certificates (`device_facts.hpa_dco`).
- Windows: best-effort if `hdparm.exe` is installed; outcomes saved under `device_facts.hpa_dco_windows`. If unavailable, use Linux or vendor tools.
- NVMe is not affected by HPA/DCO.

### SSD/NVMe controller operations
- Enable via `CERTIWIPE_ENABLE_SECURE_ERASE=1` (Linux recommended):
   - NVMe: attempts `nvme sanitize` when `nvme` CLI is present.
   - ATA/SATA: attempts `hdparm --security-erase` when available.
   - Fallbacks: overwrite (`shred`) and/or `blkdiscard`.
- Windows uses `diskpart clean all`/`sdelete`/raw overwrite; for controller sanitize, prefer vendor tools or use Linux.

### Capability discovery
- `GET /platform_capabilities?device_id=...` returns tool availability and a bus hint for the device to inform UI guidance.

### Quick examples

Windows (PowerShell):
```powershell
$env:CERTIWIPE_ENABLE_HPA_DCO = "1"; python .\secure-wipe-backend\main.py
# Check capabilities
irm "http://localhost:8000/platform_capabilities?device_id=\\.\PHYSICALDRIVE1"
```

Linux:
```bash
export CERTIWIPE_ENABLE_SECURE_ERASE=1 CERTIWIPE_ENABLE_HPA_DCO=1
python secure-wipe-backend/main.py
# Check capabilities
curl "http://localhost:8000/platform_capabilities?device_id=/dev/sdb"
```

## Linux Quick Start

### 1. Prerequisites
Install core packages (Debian/Ubuntu example):
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip build-essential \
   smartmontools hdparm nvme-cli util-linux parted coreutils jq curl
```
Optional (PDF generation / advanced cert features if added later): `ghostscript`, `libreoffice` or a headless HTML to PDF tool.

### 2. Clone & Enter Project
```bash
git clone https://github.com/RamShrivastava876/sih2025.git
cd sih2025/secure-wipe-backend
```

### 3. Virtual Environment & Dependencies
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. (Optional) Generate Signing Key
If certificate signing requires a key and none is present:
```bash
mkdir -p keys
openssl genpkey -algorithm Ed25519 -out keys/active.pem
echo active.pem > key_active.txt
```
Ensure the `keys/` directory is secured (permissions 600/700):
```bash
chmod 700 keys; chmod 600 keys/active.pem
```

### 5. Environment Variables (Common)
```bash
export CERTIWIPE_ENABLE_SECURE_ERASE=1      # Try controller-level erase (nvme sanitize / hdparm)
export CERTIWIPE_ENABLE_HPA_DCO=1           # Attempt to remove hidden HPA/DCO areas
export CERTIWIPE_POST_FORMAT_FS=ext4        # Force post-wipe format (fallback chain: ext4 -> xfs -> vfat)
export CERTIWIPE_AUTO_PREPARE=1             # Auto partition + mkfs after erase
export CERTIWIPE_JSONL=logs.jsonl           # Append JSONL audit lines
export CERTIWIPE_DB=certiwipe.db            # SQLite database path
```
For testing without touching real disks you may (when mock mode implemented) use:
```bash
export CERTIWIPE_ENABLE_MOCK=1
```

### 6. Start the Backend (Dev)
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
Or run directly (if `if __name__ == "__main__"` block exists):
```bash
python main.py
```

### 7. List Devices & Capabilities
```bash
curl http://localhost:8000/devices | jq
curl "http://localhost:8000/platform_capabilities?device_id=/dev/sdb" | jq
```

### 8. Start an Erase (Example)
```bash
curl -X POST http://localhost:8000/erase \
   -H 'Content-Type: application/json' \
   -d '{"device_id": "/dev/sdb", "method": "auto"}'
```
Poll progress (if endpoint exists):
```bash
curl http://localhost:8000/progress?device_id=/dev/sdb | jq
```

### 9. Retrieve Certificate
```bash
curl -OJ http://localhost:8000/certificate?device_id=/dev/sdb
```

### 10. Safety Checklist (Linux)
Before executing a destructive wipe:
```bash
lsblk -o NAME,MODEL,SIZE,SERIAL,TYPE,MOUNTPOINT
sudo smartctl -i /dev/sdb | grep -E "Model|Serial|Capacity"
```
Confirm the target is not your system disk (`/` or `/boot` mounted). Unmount any partitions:
```bash
sudo umount /dev/sdb? 2>/dev/null || true
```
Optionally drop caches / re-read partition table after operations:
```bash
sudo partprobe /dev/sdb
```

### 11. Using Root Privileges
Controller-level operations and raw overwrite typically require root:
```bash
sudo -E uvicorn main:app --host 0.0.0.0 --port 8000
```
`-E` preserves exported environment variables.

### 12. Post-Wipe Verification
Check partition table is blank or newly created:
```bash
sudo fdisk -l /dev/sdb
sudo blkid /dev/sdb*
```
Optionally sample random sectors to confirm patterns (simple heuristic):
```bash
sudo hexdump -C -n 512 -s $((RANDOM % 1000000 * 512)) /dev/sdb | head
```

### 13. Systemd (Preview)
A full systemd unit will be documented later. Minimal example:
```ini
[Unit]
Description=Secure Wipe API
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/sih2025/secure-wipe-backend
Environment=CERTIWIPE_ENABLE_SECURE_ERASE=1
ExecStart=/opt/sih2025/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

### 14. Common Issues
| Symptom | Hint |
|---------|------|
| Permission denied on /dev/sdX | Run as root / adjust udev rules |
| nvme: command not found | Install `nvme-cli` package |
| hdparm secure-erase fails frozen | Suspend & resume laptop; try power cycle |
| Erase slow (fallback overwrite) | Driver/controller sanitize unsupported |
| Certificate missing signature | Ensure key file present & readable |

---
This section augments earlier platform notes; advanced feature and security hardening docs will follow.
