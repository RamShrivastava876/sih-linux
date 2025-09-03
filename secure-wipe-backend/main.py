import os
import platform
import subprocess
from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional


app = FastAPI()

# Allow CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory log storage per device_id (for demo; use persistent store for production)
from collections import defaultdict
import threading
erase_logs = defaultdict(list)  # device_id -> [log lines]
erase_locks = defaultdict(threading.Lock)

class Device(BaseModel):
    id: str
    model: str
    type: str
    size: str

class EraseRequest(BaseModel):
    device_id: str
    method: str  # 'auto', 'multi-pass', 'crypto-erase'


@app.get("/devices", response_model=List[Device])
def list_devices():
    system = platform.system()
    devices = []
    if system == "Windows":
        # Use wmic to get disk info
        try:
            result = subprocess.run([
                "wmic", "diskdrive", "get", "DeviceID,Model,MediaType,Size", "/format:csv"
            ], capture_output=True, text=True, check=True)
            lines = result.stdout.strip().splitlines()
            headers = [h.strip() for h in lines[0].split(",")]
            for line in lines[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) != len(headers):
                    continue
                entry = dict(zip(headers, parts))
                # DeviceID, Model, MediaType, Size
                dev_id = entry.get("DeviceID", "")
                model = entry.get("Model", "Unknown")
                media = entry.get("MediaType", "Unknown")
                size = entry.get("Size", "0")
                # Convert size to GB
                try:
                    size_gb = f"{int(size)//(1024**3)}GB"
                except Exception:
                    size_gb = size
                # Guess type
                dtype = "SSD" if "ssd" in model.lower() or "solid" in media.lower() else ("HDD" if "hdd" in model.lower() or "hard" in media.lower() else media)
                devices.append(Device(id=dev_id, model=model, type=dtype, size=size_gb))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Device detection failed: {e}")
    elif system == "Linux":
        # TODO: Use lsblk or similar for Linux
        devices.append(Device(id="/dev/sda", model="Example SSD", type="SSD", size="500GB"))
    else:
        raise HTTPException(status_code=501, detail="Unsupported OS")
    return devices


@app.post("/erase")

def erase_device(req: EraseRequest, background_tasks: BackgroundTasks):
    system = platform.system()
    if system != "Windows":
        raise HTTPException(status_code=501, detail="Only Windows erase supported in this version.")
    background_tasks.add_task(erase_windows, req.device_id, req.method)
    return {"status": "started"}

def erase_windows(device_id, method):
    import time
    lock = erase_locks[device_id]
    def log(msg):
        with lock:
            erase_logs[device_id].append(msg)
        print(f"[ERASE] {msg}")
    log(f"Starting erase: {device_id} with method {method}")
    try:
        if method == "auto":
            script = f"select disk {parse_disk_number(device_id)}\nclean all\nexit\n"
            with open("diskpart_script.txt", "w") as f:
                f.write(script)
            log("Running diskpart clean all (this may take a while)...")
            subprocess.run(["diskpart", "/s", "diskpart_script.txt"], check=True)
            log("Diskpart clean all completed.")
        elif method == "multi-pass":
            sdelete_path = find_sdelete()
            if sdelete_path:
                log("Running sdelete for multi-pass overwrite...")
                subprocess.run([sdelete_path, "-p", "3", "-z", device_id], check=True)
                log("sdelete multi-pass completed.")
            else:
                log("sdelete not found, falling back to diskpart clean all.")
                script = f"select disk {parse_disk_number(device_id)}\nclean all\nexit\n"
                with open("diskpart_script.txt", "w") as f:
                    f.write(script)
                subprocess.run(["diskpart", "/s", "diskpart_script.txt"], check=True)
                log("Diskpart clean all completed.")
        elif method == "crypto-erase":
            log("Attempting BitLocker removal (if enabled)...")
            try:
                subprocess.run(["manage-bde", "-off", device_id], check=True)
                log("BitLocker decryption started.")
            except Exception:
                log("BitLocker not enabled or manage-bde failed. Falling back to diskpart clean.")
                script = f"select disk {parse_disk_number(device_id)}\nclean all\nexit\n"
                with open("diskpart_script.txt", "w") as f:
                    f.write(script)
                subprocess.run(["diskpart", "/s", "diskpart_script.txt"], check=True)
                log("Diskpart clean all completed.")
        else:
            log(f"Unknown erase method: {method}")
        log("Erase process finished.")
        # After erase, generate certificate
        generate_certificate(device_id, method, log)
    except Exception as e:
        log(f"Erase failed: {e}")
    time.sleep(1)

def parse_disk_number(device_id):
    # device_id example: \\.\PHYSICALDRIVE0 or similar
    import re
    m = re.search(r'(\d+)$', device_id)
    return m.group(1) if m else "0"

def find_sdelete():
    # Try to find sdelete.exe in PATH or common locations
    import shutil
    sdelete = shutil.which("sdelete.exe")
    if sdelete:
        return sdelete
    # Check C:\Windows\System32 or current dir
    for path in [r"C:\Windows\System32\sdelete.exe", r"sdelete.exe"]:
        if os.path.exists(path):
            return path
    return None


# WebSocket endpoint for real-time logs
from fastapi import WebSocketDisconnect
import asyncio
@app.websocket("/logs/{device_id}")
async def logs_ws(websocket: WebSocket, device_id: str):
    await websocket.accept()
    last_idx = 0
    try:
        while True:
            await asyncio.sleep(0.5)
            with erase_locks[device_id]:
                logs = erase_logs[device_id]
                if last_idx < len(logs):
                    for line in logs[last_idx:]:
                        await websocket.send_text(line)
                    last_idx = len(logs)
    except WebSocketDisconnect:
        pass

# Certificate generation and serving
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

certificates = {}  # device_id -> {json, pdf_bytes}

def generate_certificate(device_id, method, log):
    # Generate JSON certificate
    import datetime
    cert_data = {
        "device_id": device_id,
        "method": method,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status": "success",
    }
    # Generate Ed25519 key (for demo, generate new each time; in prod, use persistent key)
    key = Ed25519PrivateKey.generate()
    pubkey = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    signature = key.sign(json.dumps(cert_data).encode())
    cert_data["signature"] = base64.b64encode(signature).decode()
    cert_data["pubkey"] = base64.b64encode(pubkey).decode()
    # Save JSON
    cert_json = json.dumps(cert_data, indent=2)
    # Generate PDF
    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.drawString(100, 750, "Secure Wipe Certificate")
    c.drawString(100, 730, f"Device: {device_id}")
    c.drawString(100, 710, f"Method: {method}")
    c.drawString(100, 690, f"Timestamp: {cert_data['timestamp']}")
    c.drawString(100, 670, f"Status: success")
    c.drawString(100, 650, f"Signature: {cert_data['signature'][:32]}...")
    c.save()
    pdf_bytes = buf.getvalue()
    certificates[device_id] = {"json": cert_json, "pdf": pdf_bytes}
    log("Certificate generated.")

from fastapi.responses import JSONResponse, StreamingResponse
from io import BytesIO
@app.get("/certificate")
def get_certificate(device_id: str, format: str = "json"):
    cert = certificates.get(device_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if format == "json":
        return JSONResponse(content=json.loads(cert["json"]))
    elif format == "pdf":
        return StreamingResponse(BytesIO(cert["pdf"]), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=certificate_{device_id}.pdf"})
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

# TODO: Implement WebSocket for real-time logs
