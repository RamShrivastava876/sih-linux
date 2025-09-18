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
