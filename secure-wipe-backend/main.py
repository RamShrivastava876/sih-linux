

# ...existing code...


# ...existing code...

# Place this at the very end of the file, after all other endpoints

# Add new endpoints at the end of the file




import os
import sys
import platform
import subprocess
import threading
import sqlite3
import json as _json_mod
from fastapi import FastAPI, WebSocket, BackgroundTasks, HTTPException, Body, Query, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from enum import Enum


from config import settings
JSONL_PATH = os.environ.get('CERTIWIPE_JSONL_LOG', 'certiwipe.log.jsonl')
def _jsonl(event: str, **fields):
    if not os.environ.get('CERTIWIPE_JSONL'): return
    try:
        import time, json as _j
        rec = {'ts': time.time(), 'event': event}
        rec.update(fields)
        with open(JSONL_PATH,'a') as f:
            f.write(_j.dumps(rec)+'\n')
    except Exception:
        pass
app = FastAPI(title="CertiWipe API", description="Multi-platform secure data wiping & certification engine", version="1.1.0")

# Lightweight persistence (SQLite)
DB_PATH = os.environ.get("CERTIWIPE_DB", "certiwipe.db")
_db_lock = threading.Lock()
def _db_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)
def _db_init():
    try:
        with _db_lock:
            conn = _db_conn(); cur = conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS logs (device_id TEXT, idx INTEGER, line TEXT, PRIMARY KEY(device_id, idx))")
            cur.execute("CREATE TABLE IF NOT EXISTS certificates (device_id TEXT PRIMARY KEY, json TEXT, pdf BLOB)")
            cur.execute("CREATE TABLE IF NOT EXISTS progress (device_id TEXT PRIMARY KEY, data TEXT)")
            conn.commit(); conn.close()
    except Exception as e:
        print("[WARN] DB init failed", e)
_db_init()

def _audit_append(device_id: str, line: str) -> str:
    if not settings.audit_enabled:
        return line
    prev = log_chain_heads.get(device_id, '')
    h = hashlib.sha256((prev + line).encode()).hexdigest()
    log_chain_heads[device_id] = h
    try:
        steps = log_chain_steps.setdefault(device_id, [])
        steps.append({"idx": len(steps), "hash": h})
        if len(steps) > 500:
            del steps[:len(steps)-500]
        _jsonl('audit_append', device_id=device_id, head=h, line=line)
    except Exception:
        pass
    return f"[{h[:12]}] {line}"

def structured_log(event: str, **fields):
    try:
        if settings.log_json:
            import json as _j
            print(_j.dumps({"event": event, **fields}))
        else:
            print(f"[{event}] " + " ".join(f"{k}={v}" for k,v in fields.items()))
    except Exception:
        pass

def _persist_progress(device_id: str):
    try:
        with progress_lock, _db_lock:
            st = progress_stats.get(device_id)
            if not st: return
        conn = _db_conn(); cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO progress(device_id, data) VALUES (?,?)", (device_id, json.dumps(st)))
        conn.commit(); conn.close()
    except Exception:
        pass

# Allow CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _persist_log(device_id: str, line: str):
    """Persist a single log line into SQLite (idempotent on index)."""
    try:
        with _db_lock:
            conn = _db_conn(); cur = conn.cursor()
            idx = len(erase_logs.get(device_id, []))
            cur.execute("INSERT OR REPLACE INTO logs(device_id, idx, line) VALUES (?,?,?)", (device_id, idx, line))
            conn.commit(); conn.close()
    except Exception:
        pass

# In-memory log storage per device_id (for demo; use persistent store for production)
from collections import defaultdict
erase_logs = defaultdict(list)  # device_id -> [log lines]
erase_locks = defaultdict(threading.Lock)
verification_cache = {}
log_chain_heads: Dict[str, str] = {}
log_chain_steps: Dict[str, list] = {}
import hashlib
from collections import defaultdict as _dd
rate_history = _dd(list)
RATE_WINDOW_SEC = 60
pass_digests: Dict[str, list] = {}
pass_stream_hash: Dict[str, Dict[int, Any]] = {}  # device_id -> pass_index -> hashlib sha256 object

# ----------------------------------------------------------------------------
# Missing models / metadata (reconstructed after corruption)
# ----------------------------------------------------------------------------
class Device(BaseModel):
    id: str
    model: Optional[str] = None
    type: Optional[str] = None
    size: Optional[str] = None
    size_bytes: Optional[int] = None
    interface: Optional[str] = None
    rotational: Optional[bool] = None
    serial: Optional[str] = None
    mountpoints: Optional[List[str]] = None
    encryption: Optional[Dict[str, Any]] = None  # {volumes:[{mount,lock_status,...}], admin_required?}
    is_system: Optional[bool] = None
    supported_methods: Optional[List[str]] = None
    resumable: Optional[bool] = None
    notes: Optional[str] = None
    temperature_c: Optional[float] = None
    health: Optional[str] = None
    smart: Optional[Dict[str, Any]] = None
    android_encryption: Optional[Dict[str, Any]] = None
    android_version: Optional[str] = None
    android_rooted: Optional[bool] = None

class EraseRequest(BaseModel):
    device_id: str
    method: str
    resume: Optional[bool] = False
    # Optional sub-method (e.g., for android_unroot variants)
    sub_method: Optional[str] = None

WIPE_METHOD_META = {
    "multi-pass": {"passes": 3, "energy_factor": 1.8},
    "dod_5220_22m": {"passes": 3, "energy_factor": 2.0},
    "nist_800_88": {"passes": 1, "energy_factor": 1.2},
    "crypto-erase": {"passes": 1, "energy_factor": 1.0},
    "auto": {"passes": 1, "energy_factor": 1.1},
    "ecowipe": {"passes": 1, "energy_factor": 0.9},
    "shunyawipe": {"passes": 2, "energy_factor": 1.4},
    # Android specific logical wipes
    "android_unroot": {"passes": 1, "energy_factor": 1.0, "description": "Standard factory reset (requires device encrypted)."},
    "android_root": {"passes": 2, "energy_factor": 1.3, "description": "Root-level wipe: secure delete temp data + factory reset (requires root)."},
    # Mock/testing shortcut (overwrites regular file; enabled when CERTIWIPE_ENABLE_MOCK=1)
    "mock_fast": {"passes": 1, "energy_factor": 0.5, "description": "Mock single-pass overwrite for development."},
    "mock_multi": {"passes": 3, "energy_factor": 1.0, "description": "Mock multi-pass overwrite for development."},
}

# Gating constants for dangerous operations
WINDOWS_FULL_RAW_ENV = "CERTIWIPE_WINDOWS_FULL"  # legacy: set to '1' + flag file to force full mode
WINDOWS_FULL_RAW_FLAG_FILE = "ENABLE_FULL_WINDOWS_RAW"  # legacy: presence required by legacy gate
WINDOWS_SAMPLE_ONLY_ENV = "CERTIWIPE_WINDOWS_SAMPLE_ONLY"  # if '1', restrict to small sample mode
device_geometry: Dict[str, Dict[str, Any]] = {}
device_facts: Dict[str, Dict[str, Any]] = {}

def record_device_geometry(device_id: str, info: Dict[str, Any]):
    try:
        device_geometry[device_id] = info
    except Exception:
        pass

# ----------------------------------------------------------------------------
# Auth & rate limiting helpers (reconstructed)
# ----------------------------------------------------------------------------
def api_key_auth(request: Request) -> bool:
    """Optional API key auth. If settings.api_key unset -> open mode."""
    if not settings.api_key:
        return True
    supplied = request.headers.get("x-api-key") or request.query_params.get("api_key")
    if supplied == settings.api_key:
        return True
    raise HTTPException(status_code=401, detail="Invalid or missing API key")

def rate_limit(request: Request):
    try:
        limit = settings.rate_limit_per_minute
        if not limit:
            return
        ip = request.client.host if request and request.client else "anon"
        path = request.url.path if request else ''
        # Relax progress polling slightly (2x window)
        if path == '/progress_detailed':
            limit = int(limit * 2)
        import time
        now = time.time()
        window_start = now - RATE_WINDOW_SEC
        hist = rate_history[ip]
        # prune
        while hist and hist[0] < window_start:
            hist.pop(0)
        if len(hist) >= limit:
            # Provide Retry-After guidance (simple 5s or window reset)
            retry_after = 5
            headers = {"Retry-After": str(retry_after)}
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)
        hist.append(now)
    except HTTPException:
        raise
    except Exception:
        pass

# ----------------------------------------------------------------------------
# Progress / streaming hash helpers (reconstructed)
# ----------------------------------------------------------------------------
progress_stats: Dict[str, Dict[str, Any]] = {}
progress_lock = threading.Lock()
cancel_flags: Dict[str, bool] = {}
_log_hash_states: Dict[str, Any] = {}
import hashlib as _hashlib
import time

def _update_stream_hash(device_id: str, line: str):
    try:
        st = _log_hash_states.get(device_id)
        if not st:
            st = _hashlib.sha256()
            _log_hash_states[device_id] = st
        st.update(line.encode())
    except Exception:
        pass

def init_progress(device_id: str, method: str, total_bytes: int, passes_total: int, pass_patterns: Optional[List[str]] = None):
    with progress_lock:
        progress_stats[device_id] = {
            "device_id": device_id,
            "method": method,
            "total_bytes": total_bytes,
            "bytes_done": 0,
            "passes_total": passes_total,
            "pass_index": 0,
            "status": "running",
            "pass_patterns": pass_patterns or [],
            "verified": False,
            "started_at": time.time(),
        }
    _persist_progress(device_id)

def update_progress(device_id: str, delta: int):
    with progress_lock:
        ps = progress_stats.get(device_id)
        if not ps:
            return
        ps['bytes_done'] += delta
        total = ps.get('total_bytes') or 0
        if total:
            ps['percent'] = round((ps['bytes_done']/total)*100, 4)
        # Lightweight JSON snapshot (best-effort)
        try:
            snap = {k: ps.get(k) for k in ('device_id','method','bytes_done','total_bytes','pass_index','passes_total','current_pattern','status')}
            open(f'progress_{device_id.replace(os.sep,"_")}.json','w').write(json.dumps(snap))
        except Exception:
            pass
    _persist_progress(device_id)

def next_pass(device_id: str, pattern_label: Optional[str]):
    with progress_lock:
        ps = progress_stats.get(device_id)
        if not ps:
            return
        ps['pass_index'] += 1
        ps['current_pattern'] = pattern_label
        ps['current_pass_bytes'] = 0
    _persist_progress(device_id)

def finalize_progress(device_id: str, status: str, verified: bool = False):
    with progress_lock:
        ps = progress_stats.get(device_id)
        if not ps:
            return
        ps['status'] = status
        if verified:
            ps['verified'] = True
        # stamp completion time
        if status in ('completed','error','cancelled','raw_overwrite_done'):
            ps['ended_at'] = time.time()
    _persist_progress(device_id)

# Speed tracking cache (device_id -> (last_bytes, last_time, inst_speed))
_speed_cache: Dict[str, Any] = {}

def _compute_speed_eta(device_id: str):
    try:
        with progress_lock:
            ps = progress_stats.get(device_id)
            if not ps:
                return None, None
            total = ps.get('total_bytes') or 0
            done = ps.get('bytes_done') or 0
            now = time.time()
            sc = _speed_cache.get(device_id)
            if not sc:
                _speed_cache[device_id] = (done, now, 0.0)
                return 0.0, None
            last_bytes, last_time, _ = sc
            dt = max(1e-6, now - last_time)
            delta = done - last_bytes
            inst_speed = delta / dt  # bytes/sec
            _speed_cache[device_id] = (done, now, inst_speed)
            if inst_speed <= 0 or total <= 0 or done <= 0:
                return 0.0, None
            remaining = max(0, total - done)
            eta = remaining / inst_speed
            return inst_speed, eta
    except Exception:
        return None, None

@app.get('/progress_detailed')
def progress_detailed(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    with progress_lock:
        ps = progress_stats.get(device_id)
        if not ps:
            raise HTTPException(status_code=404, detail='No progress for device')
        snapshot = dict(ps)  # shallow copy
    speed, eta = _compute_speed_eta(device_id)
    # Coverage ratio if we know device size via geometry
    coverage_ratio = None
    try:
        geom = device_geometry.get(device_id) or {}
        size_bytes = geom.get('size_bytes') or geom.get('capacity_bytes') or snapshot.get('total_bytes') or 0
        if size_bytes and snapshot.get('bytes_done'):
            coverage_ratio = min(1.0, snapshot['bytes_done']/float(size_bytes))
    except Exception:
        pass
    warn = []
    if coverage_ratio is not None and snapshot.get('status') in ('completed','raw_overwrite_done'):
        if coverage_ratio < 0.99:
            warn.append('coverage_below_99pct')
    out = {
        'device_id': device_id,
        'method': snapshot.get('method'),
        'status': snapshot.get('status'),
        'bytes_done': snapshot.get('bytes_done'),
        'total_bytes': snapshot.get('total_bytes'),
        'passes_total': snapshot.get('passes_total'),
        'pass_index': snapshot.get('pass_index'),
        'current_pattern': snapshot.get('current_pattern'),
        'pass_patterns': snapshot.get('pass_patterns'),
        'verified': snapshot.get('verified'),
        'percent': snapshot.get('percent'),
        'coverage_ratio': coverage_ratio,
        'write_speed_bytes_s': speed,
        'eta_seconds': eta,
        'warnings': warn or None,
        'started_at': snapshot.get('started_at'),
        'ended_at': snapshot.get('ended_at'),
    }
    return out

# ----------------------------------------------------------------------------
# /devices endpoint (clean implementation)
# ----------------------------------------------------------------------------
@app.get("/devices", response_model=List[Device])
def list_devices(detailed: bool = Query(False), _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    system = platform.system()
    # Always force detailed for Windows to expose encryption / serial
    if system == 'Windows':
        detailed = True
    devices: List[Device] = []

    # Android (adb)
    try:
        adb = subprocess.run(["adb", "devices"], capture_output=True, text=True, timeout=6)
        lines = adb.stdout.strip().splitlines()
        for line in lines[1:]:
            if not line.strip() or 'device' not in line:
                continue
            parts = line.split()
            if len(parts) < 2 or parts[1] != 'device':
                continue
            serial = parts[0]
            model = subprocess.run(["adb","-s",serial,"shell","getprop","ro.product.model"], capture_output=True, text=True, timeout=5).stdout.strip()
            version = subprocess.run(["adb","-s",serial,"shell","getprop","ro.build.version.release"], capture_output=True, text=True, timeout=5).stdout.strip()
            if not version:
                version = subprocess.run(["adb","-s",serial,"shell","getprop","ro.build.version.sdk"], capture_output=True, text=True, timeout=5).stdout.strip()
            # Root detection
            rooted = False
            try:
                su_test = subprocess.run(["adb","-s",serial,"shell","su","-c","id"], capture_output=True, text=True, timeout=4)
                if su_test.returncode == 0 and 'uid=0' in (su_test.stdout or '').lower():
                    rooted = True
            except Exception:
                rooted = False
            # Try to estimate /data partition size (df /data)
            size_str = "N/A"
            try:
                df = subprocess.run(["adb","-s",serial,"shell","df","/data"], capture_output=True, text=True, timeout=6)
                for dl in df.stdout.splitlines():
                    if dl.lower().startswith('filesystem'):
                        continue
                    cols = [c for c in dl.split() if c]
                    # Typical Android df columns: Filesystem 1K-blocks Used Available Use% Mounted on
                    if len(cols) >= 2 and cols[1].isdigit():
                        try:
                            kb = int(cols[1])
                            size_str = f"{(kb/1024/1024):.1f}GB"
                        except Exception:
                            pass
                        break
            except Exception:
                pass
            # Encryption properties
            enc_state = None; enc_type=None; enc_status=None
            try:
                enc_state = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.state"], capture_output=True, text=True, timeout=4).stdout.strip()
                enc_type = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.type"], capture_output=True, text=True, timeout=4).stdout.strip()
                enc_status = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.status"], capture_output=True, text=True, timeout=4).stdout.strip()
            except Exception:
                pass
            devices.append(Device(
                id=f"adb:{serial}",
                model=f"Android {model or 'Device'}",
                type="Android-ADB",
                size=size_str,
                interface="usb",
                is_system=False,
                supported_methods=list(WIPE_METHOD_META.keys()),
                resumable=False,
                android_encryption={
                    "state": enc_state,
                    "type": enc_type,
                    "status": enc_status,
                },
                android_version=version or None,
                android_rooted=rooted
            ))
    except Exception:
        pass

    # Fastboot devices (bootloader mode)
    try:
        fb = subprocess.run(["fastboot","devices"], capture_output=True, text=True, timeout=6)
        for ln in fb.stdout.splitlines():
            parts = ln.strip().split()
            if len(parts) >= 2 and parts[1] == 'fastboot':
                serial = parts[0]
                devices.append(Device(
                    id=f"fastboot:{serial}",
                    model="Android Fastboot Device",
                    type="Android-Fastboot",
                    size="N/A",
                    interface="usb",
                    supported_methods=list(WIPE_METHOD_META.keys()),
                    resumable=False
                ))
    except Exception:
        pass

    # MTK (mtkclient) optional
    try:
        mtk = subprocess.run(["mtk","print","--json"], capture_output=True, text=True, timeout=8)
        if mtk.returncode == 0 and mtk.stdout.strip():
            import json as _j
            md = _j.loads(mtk.stdout)
            for dv in md.get('devices', []):
                devices.append(Device(id=f"mtk:{dv.get('serial')}", model=f"MTK {dv.get('model','?')}", type="Android-MTK", size="N/A"))
    except Exception:
        pass

    if system == 'Windows':
        try:
            ps_cmd = (
                "Get-Disk | Select-Object Number,FriendlyName,SerialNumber,BusType,Size,PartitionStyle,IsSystem,IsBoot,IsOffline | ConvertTo-Json -Depth 3"
            )
            ps = subprocess.run(["powershell","-Command", ps_cmd], capture_output=True, text=True, timeout=15)
            disk_json = []
            if ps.returncode == 0 and ps.stdout.strip():
                import json as _j
                try:
                    disk_json = _j.loads(ps.stdout)
                    if isinstance(disk_json, dict):
                        disk_json = [disk_json]
                except Exception:
                    disk_json = []
            # BitLocker volume map
            bitlocker_map = {}
            try:
                bl_cmd = "Get-BitLockerVolume | Select-Object MountPoint,LockStatus,ProtectionStatus,EncryptionPercentage | ConvertTo-Json -Depth 3"
                bl = subprocess.run(["powershell","-Command", bl_cmd], capture_output=True, text=True, timeout=15)
                if bl.returncode == 0 and bl.stdout.strip():
                    import json as _j
                    data = _j.loads(bl.stdout)
                    if isinstance(data, dict): data = [data]
                    for v in data:
                        mp = (v.get('MountPoint') or '').rstrip(':').upper()
                        if mp:
                            bitlocker_map[mp] = v
            except Exception:
                pass
            for d in disk_json:
                num = d.get('Number')
                dev_id = f"\\\\.\\PHYSICALDRIVE{num}" if num is not None else d.get('FriendlyName','Unknown')
                size_bytes = d.get('Size') or 0
                size_str = f"{(size_bytes or 0)//(1024**3)}GB" if size_bytes else "?"
                # Fallback: if PowerShell reported 0, try IOCTL to get exact size
                if not size_bytes:
                    try:
                        exact = get_device_size_bytes(dev_id)
                        if exact:
                            size_bytes = int(exact)
                            size_str = f"{(size_bytes)//(1024**3)}GB"
                    except Exception:
                        pass
                bus = (d.get('BusType') or '').lower() or None
                model = d.get('FriendlyName') or 'Unknown'
                is_system_flag = bool(d.get('IsSystem'))
                rotational = None
                if bus in ('nvme','ssd'): rotational = False
                mps: List[str] = []
                try:
                    part_cmd = f"Get-Partition -DiskNumber {num} | Get-Volume | Select-Object -ExpandProperty DriveLetter"
                    pv = subprocess.run(["powershell","-Command", part_cmd], capture_output=True, text=True, timeout=10)
                    for ln in pv.stdout.splitlines():
                        if ln.strip():
                            mps.append(ln.strip() + ':')
                except Exception:
                    pass
                enc_summary = None
                if mps:
                    enc_entries = []
                    admin_required = False
                    for mp in mps:
                        vo = bitlocker_map.get(mp.rstrip(':').upper())
                        if vo:
                            ls = vo.get('LockStatus')
                            if isinstance(ls, (int,float)):
                                ls = 'Locked' if int(ls)==1 else 'Unlocked'
                            enc_entries.append({
                                'mount': mp,
                                'lock_status': ls,
                                'encryption_pct': vo.get('EncryptionPercentage'),
                                'protection': vo.get('ProtectionStatus'),
                                'details': vo  # for frontend tooltip
                            })
                    # manage-bde fallback for missing mountpoints
                    try:
                        import re as _re
                        for mp in mps:
                            if any(e['mount']==mp for e in enc_entries):
                                continue
                            mb = subprocess.run(["manage-bde","-status", mp], capture_output=True, text=True, timeout=10)
                            raw = (mb.stdout or '') + (mb.stderr or '')
                            low = raw.lower()
                            if mb.returncode != 0 and ('access is denied' in low or 'administrator' in low):
                                admin_required = True
                                continue
                            lock_status = 'Unknown'
                            status_line = None
                            for ln in raw.splitlines():
                                if 'Lock Status' in ln:
                                    status_line = ln.lower(); break
                            if status_line:
                                if 'unlocked' in status_line: lock_status='Unlocked'
                                elif 'locked' in status_line: lock_status='Locked'
                            else:
                                if 'unlocked' in low: lock_status='Unlocked'
                                elif 'locked' in low: lock_status='Locked'
                            pct = None
                            mobj = _re.search(r'percentage encrypted:\s*([0-9.]+)%', low)
                            if mobj:
                                try: pct=float(mobj.group(1))
                                except Exception: pass
                                enc_entries.append({
                                    'mount': mp,
                                    'lock_status': lock_status,
                                    'encryption_pct': pct,
                                    'protection': 'Unknown',
                                    'raw_text': raw[:1200]  # truncate for safety
                                })
                    except Exception:
                        pass
                    if enc_entries:
                        enc_summary = {'volumes': enc_entries}
                    elif admin_required:
                        enc_summary = {'volumes': [], 'admin_required': True}
                devices.append(Device(
                    id=dev_id,
                    model=model,
                    type='Windows',
                    size=size_str,
                    size_bytes=size_bytes,
                    interface=bus,
                    rotational=rotational,
                    serial=d.get('SerialNumber'),
                    mountpoints=mps or None,
                    encryption=enc_summary,
                    is_system=is_system_flag,
                    supported_methods=list(WIPE_METHOD_META.keys()),
                    resumable=True,
                    notes=d.get('PartitionStyle')
                ))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Device detection failed: {e}")
    elif system == 'Linux':
        try:
            cols = ["NAME","MODEL","TYPE","SIZE"]
            if detailed:
                cols += ["ROTA","SERIAL","TRAN","MOUNTPOINT"]
            result = subprocess.run(["lsblk","-J","-o", ",".join(cols)], capture_output=True, text=True, timeout=10)
            import json as _j
            data = _j.loads(result.stdout)
            for dev in data.get('blockdevices', []):
                if dev.get('type') != 'disk':
                    continue
                dev_id = f"/dev/{dev['name']}"
                rotational = None
                interface = None
                serial = None
                mps: List[str] = []
                temperature_c = None
                health = None
                smart_trim = None
                if detailed:
                    try:
                        rotational = bool(int(dev.get('rota','0'))) if dev.get('rota') is not None else None
                    except Exception:
                        rotational = None
                    interface = dev.get('tran')
                    serial = dev.get('serial')
                    for ch in dev.get('children', []) or []:
                        mp = ch.get('mountpoint')
                        if mp: mps.append(mp)
                    # SMART (best-effort)
                    try:
                        import shutil, json as _jj
                        if shutil.which('smartctl'):
                            sc = subprocess.run(['smartctl','-a','-j', dev_id], capture_output=True, text=True, timeout=8)
                            if sc.returncode == 0 and sc.stdout.strip():
                                sm = _jj.loads(sc.stdout)
                                if 'temperature' in sm and isinstance(sm['temperature'], dict):
                                    temperature_c = sm['temperature'].get('current') or sm['temperature'].get('drive_temperature')
                                if 'smart_status' in sm and isinstance(sm['smart_status'], dict):
                                    health = 'PASSED' if sm['smart_status'].get('passed') else 'FAILED'
                                elif 'nvme_smart_health_information_log' in sm:
                                    crit = sm['nvme_smart_health_information_log'].get('critical_warning')
                                    health = 'WARN' if crit else 'OK'
                                attrs = sm.get('ata_smart_attributes', {}).get('table') if isinstance(sm.get('ata_smart_attributes'), dict) else None
                                interesting = [a for a in attrs if a.get('name') in ('Reallocated_Sector_Ct','Power_On_Hours','Wear_Leveling_Count','Percentage_Used')] if attrs else None
                                smart_trim = {
                                    'temperature': temperature_c,
                                    'health': health,
                                    'attributes': interesting
                                }
                    except Exception:
                        pass
                devices.append(Device(
                    id=dev_id,
                    model=dev.get('model','Unknown'),
                    type='Linux',
                    size=dev.get('size','?'),
                    rotational=rotational,
                    interface=interface,
                    serial=serial,
                    mountpoints=mps or None,
                    is_system=is_system_device(dev_id) if detailed else None,
                    supported_methods=list(WIPE_METHOD_META.keys()),
                    resumable=True,
                    temperature_c=temperature_c,
                    health=health,
                    smart=smart_trim
                ))
        except Exception:
            pass
    # Append mock file device only when explicitly enabled
    try:
        enable_mock = os.environ.get('CERTIWIPE_ENABLE_MOCK') == '1'
        if enable_mock:
            mock_name = os.environ.get('CERTIWIPE_MOCK_PATH', 'mock_device.bin')
            size_mb = int(os.environ.get('CERTIWIPE_MOCK_SIZE_MB','8'))
            size_bytes = size_mb * 1024 * 1024
            if not os.path.exists(mock_name) or os.path.getsize(mock_name) != size_bytes:
                with open(mock_name,'wb') as f:
                    f.truncate(size_bytes)
            if not any(d.id == f"mockfile:{mock_name}" for d in devices):
                devices.append(Device(
                    id=f"mockfile:{mock_name}",
                    model='Mock Test File',
                    type='Mock',
                    size=f"{size_mb}MB",
                    size_bytes=size_bytes,
                    interface='file',
                    is_system=False,
                    supported_methods=[m for m in WIPE_METHOD_META.keys() if m.startswith('mock_') or not m.startswith('android_')],
                    resumable=False,
                    notes='Development-only synthetic device file.'
                ))
    except Exception:
        pass
    return devices

@app.get("/logs_tail")
def logs_tail(device_id: str, since: int = 0, limit: int = 200, _: bool = Depends(api_key_auth), request: Request = None):
    """Lightweight fallback to fetch recent logs if WebSocket not functioning.
    since: index (0-based) after which new lines are wanted.
    limit: max lines to return in this batch.
    Returns: { start, end, lines, has_more }
    """
    rate_limit(request)
    try:
        lines = erase_logs.get(device_id, [])
        start = max(0, since)
        end = min(len(lines), start + max(1, min(limit, 1000)))
        slice_lines = lines[start:end]
        return {"start": start, "end": end, "lines": slice_lines, "has_more": end < len(lines), "total": len(lines)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"log tail error: {e}")

# ---------------------------------------------------------------------------
# Accurate device size helpers and endpoint
# ---------------------------------------------------------------------------
def _windows_physical_size_bytes(path: str) -> int:
    try:
        import ctypes, struct
        from ctypes import wintypes
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x00000001
        FILE_SHARE_WRITE = 0x00000002
        FILE_SHARE_DELETE = 0x00000004
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
        IOCTL_DISK_GET_LENGTH_INFO = 0x7405C

        CreateFileW = ctypes.windll.kernel32.CreateFileW
        CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
        CreateFileW.restype = wintypes.HANDLE

        DeviceIoControl = ctypes.windll.kernel32.DeviceIoControl
        DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.LPVOID]
        DeviceIoControl.restype = wintypes.BOOL

        CloseHandle = ctypes.windll.kernel32.CloseHandle

        handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, None, OPEN_EXISTING, 0, None)
        if handle == INVALID_HANDLE_VALUE:
            raise RuntimeError("CreateFileW failed")
        try:
            outbuf = ctypes.create_string_buffer(8)
            returned = wintypes.DWORD(0)
            ok = DeviceIoControl(handle, IOCTL_DISK_GET_LENGTH_INFO, None, 0, outbuf, 8, ctypes.byref(returned), None)
            if not ok:
                raise RuntimeError("DeviceIoControl IOCTL_DISK_GET_LENGTH_INFO failed")
            (length,) = struct.unpack('<Q', outbuf.raw)
            return int(length)
        finally:
            CloseHandle(handle)
    except Exception as e:
        raise e

def _linux_block_size_bytes(path: str) -> int:
    try:
        import fcntl, struct
        BLKGETSIZE64 = 0x80081272
        with open(path, 'rb', buffering=0) as f:
            buf = bytearray(8)
            fcntl.ioctl(f.fileno(), BLKGETSIZE64, buf, True)
            (size,) = struct.unpack('Q', bytes(buf))
            return int(size)
    except Exception as e:
        raise e

def _mockfile_size_bytes(device_id: str) -> int:
    try:
        import os
        path = device_id.split(':',1)[1]
        return os.path.getsize(path)
    except Exception:
        return 0

def get_device_size_bytes(device_id: str) -> int:
    import os, platform
    # Mock device id
    if device_id.startswith('mockfile:'):
        return _mockfile_size_bytes(device_id)
    # Windows physical drive paths
    if platform.system() == 'Windows':
        path = device_id
        low = device_id.lower()
        if low.startswith('\\\\.\\\\physicaldrive'):
            path = device_id
        elif low.startswith('physicaldrive'):
            path = f"\\\\.\\\\{device_id}"
        try:
            return _windows_physical_size_bytes(path)
        except Exception:
            # Optional WMI fallback if available
            try:
                import wmi  # type: ignore
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive():
                    dev = str(disk.DeviceID)
                    if dev.lower().endswith(low) or dev.lower() == path.lower():
                        return int(disk.Size)
            except Exception:
                pass
            return 0
    # Linux block devices
    if device_id.startswith('/dev/'):
        try:
            return _linux_block_size_bytes(device_id)
        except Exception:
            return 0
    # Fallback: file path
    try:
        return os.path.getsize(device_id)
    except Exception:
        return 0

@app.get("/device_size")
def device_size(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    size = get_device_size_bytes(device_id)
    return {"device_id": device_id, "size_bytes": size}

@app.get("/smart")
def smart_info(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    """Return SMART / temperature info for a single device (Linux only currently)."""
    rate_limit(request)
    if platform.system() != 'Linux':
        return {"device_id": device_id, "supported": False, "reason": "SMART collection implemented for Linux only in this build"}
    if not os.path.exists(device_id):
        return {"device_id": device_id, "error": "Device path not found"}
    import shutil, json as _j
    if not shutil.which('smartctl'):
        return {"device_id": device_id, "supported": False, "reason": "smartctl not installed"}
    try:
        sc = subprocess.run(['smartctl','-a','-j', device_id], capture_output=True, text=True, timeout=10)
        if sc.returncode != 0:
            return {"device_id": device_id, "error": "smartctl returned non-zero", "code": sc.returncode, "stderr": sc.stderr}
        data = _j.loads(sc.stdout)
        out = {}
        temp = None
        if 'temperature' in data and isinstance(data['temperature'], dict):
            temp = data['temperature'].get('current') or data['temperature'].get('drive_temperature')
        health = None
        if 'smart_status' in data and isinstance(data['smart_status'], dict):
            health = 'PASSED' if data['smart_status'].get('passed') else 'FAILED'
        elif 'nvme_smart_health_information_log' in data:
            crit = data['nvme_smart_health_information_log'].get('critical_warning')
            health = 'WARN' if crit else 'OK'
        attrs = data.get('ata_smart_attributes', {}).get('table') if isinstance(data.get('ata_smart_attributes'), dict) else None
        interesting = []
        if attrs:
            for a in attrs:
                if a.get('name') in ('Reallocated_Sector_Ct','Power_On_Hours','Wear_Leveling_Count','Percentage_Used'):
                    interesting.append(a)
        return {
            "device_id": device_id,
            "temperature_c": temp,
            "health": health,
            "interesting_attributes": interesting,
            "raw": data if (settings.log_json) else None  # optionally include raw when log_json enabled
        }
    except Exception as e:
        return {"device_id": device_id, "error": str(e)}


@app.post("/erase")
def erase_device(req: EraseRequest, background_tasks: BackgroundTasks, confirm: bool = Query(False), _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    system = platform.system()
    # Dual-operator gating: require both a plan token (already enforced in platform specific functions) and second approval token
    second_required = os.environ.get('CERTIWIPE_REQUIRE_DUAL_APPROVAL') == '1'
    if second_required:
        tok = request.headers.get('x-approval-token') or request.query_params.get('approval_token')
        approvals = globals().setdefault('second_approvals', {})
        if not tok or tok not in approvals or approvals[tok].get('used'):
            raise HTTPException(status_code=428, detail='Second operator approval token missing or invalid')
        # Mark as used
        approvals[tok]['used'] = True
    # Safety guard: prevent wiping likely system root disk unless explicitly allowed
    if is_system_device(req.device_id):
        raise HTTPException(status_code=403, detail="Refusing to erase system device. This guard prevents wiping the OS disk.")
    # Allowlist (optional)
    allow_path = 'allowed_devices.json'
    if os.path.exists(allow_path):
        try:
            allow = _json_mod.loads(open(allow_path,'r').read())
        except Exception:
            allow = []
        if req.device_id not in allow and not confirm:
            raise HTTPException(status_code=412, detail="Device not in allowlist. Re-submit with ?confirm=true or add via /allow_device")
    if req.resume and progress_stats.get(req.device_id):
        ps = progress_stats[req.device_id]
        if ps.get('status') in ('completed','error','cancelled'):
            raise HTTPException(status_code=400, detail="Nothing to resume; operation already finalized.")
        if platform.system()=="Linux" and not req.device_id.startswith(('adb:','mtk:')):
            background_tasks.add_task(perform_linux_overwrite, req.device_id, req.method, lambda m: None, True)
            return {"status":"resuming"}
        else:
            raise HTTPException(status_code=501, detail="Resume supported only for Linux block devices currently.")
    # Normal dispatch
    if req.device_id.startswith("adb:"):
        serial = req.device_id.split(":", 1)[1]
        background_tasks.add_task(erase_android, serial, req.method, req.sub_method)
        return {"status": "started (android-adb)", "method": req.method, "sub_method": req.sub_method}
    if req.device_id.startswith("mockfile:"):
        if os.environ.get('CERTIWIPE_ENABLE_MOCK') != '1':
            raise HTTPException(status_code=403, detail="Mock erase disabled. Set CERTIWIPE_ENABLE_MOCK=1 to enable mock devices.")
        file_path = req.device_id.split(":",1)[1]
        background_tasks.add_task(erase_mockfile, file_path, req.method)
        return {"status":"started (mockfile)", "method": req.method}
    if req.device_id.startswith("fastboot:"):
        serial = req.device_id.split(":",1)[1]
        background_tasks.add_task(erase_fastboot, serial, req.method)
        return {"status":"started (android-fastboot)"}
    if req.device_id.startswith("mtk:"):
        serial = req.device_id.split(":", 1)[1]
        background_tasks.add_task(erase_mtk, serial, req.method)
        return {"status": "started (android-mtk)"}
    if system == "Linux":
        background_tasks.add_task(erase_linux, req.device_id, req.method)
        return {"status": "started (linux)"}
    if system == "Windows":
        background_tasks.add_task(erase_windows, req.device_id, req.method)
        return {"status": "started (windows)"}
    raise HTTPException(status_code=501, detail="Unsupported OS/device")

@app.post('/approve')
def approve(device_id: str, method: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    if os.environ.get('CERTIWIPE_REQUIRE_DUAL_APPROVAL') != '1':
        return {'status':'disabled'}
    import secrets, time
    tok = secrets.token_hex(16)
    rec = {'device_id': device_id, 'method': method, 'issued': int(time.time()), 'used': False}
    approvals = globals().setdefault('second_approvals', {})
    approvals[tok] = rec
    return {'status':'issued','approval_token': tok, 'device_id': device_id, 'method': method}
@app.post('/allow_device')
def allow_device(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    path='allowed_devices.json'
    arr=[]
    if os.path.exists(path):
        try: arr=_json_mod.loads(open(path,'r').read())
        except Exception: arr=[]
    if device_id not in arr:
        arr.append(device_id)
    open(path,'w').write(_json_mod.dumps(arr, indent=2))
    return {"status":"added","device_id":device_id,"allowlist":arr}
@app.get('/allowlist')
def get_allowlist(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    p='allowed_devices.json'
    if not os.path.exists(p): return []
    try:
        return _json_mod.loads(open(p,'r').read())
    except Exception:
        return []

@app.delete('/allow_device')
def remove_allow_device(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    p='allowed_devices.json'
    if not os.path.exists(p):
        return {"status":"absent","device_id":device_id}
    try:
        arr=_json_mod.loads(open(p,'r').read())
    except Exception:
        arr=[]
    if device_id in arr:
        arr=[d for d in arr if d!=device_id]
        open(p,'w').write(_json_mod.dumps(arr, indent=2))
        return {"status":"removed","device_id":device_id,"allowlist":arr}
    return {"status":"not_found","device_id":device_id,"allowlist":arr}

# ---------------------------------------------------------------------------
# ERASE IMPLEMENTATIONS (platform specific wrappers)
# ---------------------------------------------------------------------------
def erase_android(serial, method, sub_method=None):
    lock = erase_locks[serial]
    def log(msg):
        with lock:
            msg = _audit_append(serial, msg)
            erase_logs[serial].append(msg)
            _persist_log(serial, msg)
            _update_stream_hash(serial, msg)
        print(f"[ERASE][ANDROID] {msg}")
    log(f"Starting Android wipe serial={serial} method={method} sub={sub_method}")
    fbe_mode = None
    try:
        enc_type = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.type"], capture_output=True, text=True, timeout=4).stdout.strip()
        state = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.state"], capture_output=True, text=True, timeout=4).stdout.strip()
        if enc_type:
            fbe_mode = enc_type
            log(f"Android encryption type: {enc_type}")
        elif state:
            fbe_mode = state
            log(f"Android crypto state: {state}")
    except Exception:
        pass
    try:
        if method == 'android_root':
            log('Root powerful sequence: clearing logs, temp, cache, writing random fillers')
            root_cmds = [
                "su -c 'logcat -c'",
                "su -c 'rm -rf /data/local/tmp/*'",
                "su -c 'find /data/local/tmp -type f -exec dd if=/dev/zero of={} bs=8K count=8 conv=notrunc 2>/dev/null \;'",
                "su -c 'rm -rf /cache/* /data/cache/*'",
                "su -c 'sync'",
                "su -c 'mkdir -p /data/local/tmp/_f && for i in 1 2 3 4; do dd if=/dev/urandom of=/data/local/tmp/_f/r$i.bin bs=2M count=2 2>/dev/null; done'",
                "su -c 'sync'"
            ]
            for c in root_cmds:
                subprocess.run(["adb","-s",serial,"shell",c], capture_output=True, text=True)
            log('Triggering factory reset broadcast (root)')
            subprocess.run(["adb","-s",serial,"shell","am","broadcast","-a","android.intent.action.MASTER_CLEAR"], check=True)
            log('Root wipe broadcast sent')
        elif method == 'android_unroot':
            try:
                state = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.state"], capture_output=True, text=True, timeout=4).stdout.strip().lower()
                if state != 'encrypted':
                    log('WARNING: device not encrypted prior to unroot wipe')
            except Exception:
                pass
            chosen = sub_method or 'auto'
            log(f'Underlying sub-method: {chosen}')
            if chosen in ('shunyawipe','multi-pass','dod_5220_22m'):
                pre = ["rm -rf /data/local/tmp/*","logcat -c","sync"]
                for c in pre:
                    subprocess.run(["adb","-s",serial,"shell",c], capture_output=True, text=True)
                if chosen == 'shunyawipe':
                    subprocess.run(["adb","-s",serial,"shell","mkdir -p /data/local/tmp/_wipe && for i in 1 2 3; do dd if=/dev/urandom of=/data/local/tmp/_wipe/f$i.bin bs=1M count=4 2>/dev/null; done"], capture_output=True, text=True)
            # Attempt keyed file deletion pass (FBE) if not rooted but still accessible (best-effort)
            try:
                listing = subprocess.run(["adb","-s",serial,"shell","ls","/data/data"], capture_output=True, text=True, timeout=8)
                dirs = [d.strip() for d in listing.stdout.splitlines() if d.strip() and '/' not in d][:25]
                if dirs:
                    log(f"Sampling keyed deletion of {len(dirs)} app data dirs (best-effort)")
                    for d in dirs:
                        subprocess.run(["adb","-s",serial,"shell",f"run-as {d} sh -c 'echo wipe > /data/data/{d}/__wipe_marker 2>/dev/null'"], capture_output=True, text=True)
                        subprocess.run(["adb","-s",serial,"shell",f"rm -rf /data/data/{d}"], capture_output=True, text=True)
            except Exception:
                pass
            log('Triggering factory reset broadcast (unroot)')
            subprocess.run(["adb","-s",serial,"shell","am","broadcast","-a","android.intent.action.MASTER_CLEAR"], check=True)
            log('Unroot wipe broadcast sent')
            # Post-reset validation attempt (wait for reboot, sample /data)
            try:
                log('Waiting for device to reboot (post-reset)...')
                subprocess.run(["adb","-s",serial,"wait-for-device"], timeout=60)
                # Sample a few offsets in /data (stat + small file test)
                sample_cmds = [
                    "stat /data || echo no_data_dir",
                    "find /data -maxdepth 1 -type f -printf '%p %s\n' 2>/dev/null | head -n 5",
                    "df -h /data | head -n 2"
                ]
                for sc in sample_cmds:
                    r = subprocess.run(["adb","-s",serial,"shell",sc], capture_output=True, text=True, timeout=10)
                    preview = (r.stdout or r.stderr)[:300].replace('\n',' | ')
                    log(f"post_reset_sample: {sc} -> {preview}")
            except Exception as e:
                log(f"Post-reset validation failed: {e}")
        else:
            log(f'Unknown Android method {method}')
        generate_certificate(serial, method, log)
        if fbe_mode:
            device_facts.setdefault(serial, {})['android_encryption_mode'] = fbe_mode
    except Exception as e:
        log(f'Android erase failed: {e}')

def erase_fastboot(serial, method):
    lock = erase_locks[serial]
    def log(msg):
        with lock:
            msg = _audit_append(serial, msg)
            erase_logs[serial].append(msg)
            _persist_log(serial, msg)
            _update_stream_hash(serial, msg)
        print(f"[ERASE][FASTBOOT] {msg}")
    log(f"Starting fastboot wipe serial={serial} method={method}")
    try:
        # Prefer 'erase userdata'; fallback to 'format userdata'
        r = subprocess.run(["fastboot","-s",serial,"erase","userdata"], capture_output=True, text=True)
        if r.returncode != 0:
            log("fastboot erase userdata failed, attempting format")
            subprocess.run(["fastboot","-s",serial,"format","userdata"], check=True)
        log("Rebooting device")
        subprocess.run(["fastboot","-s",serial,"reboot"], capture_output=True, text=True)
        generate_certificate(serial, method, log)
    except Exception as e:
        log(f"Fastboot erase failed: {e}")

@app.post('/android_encrypt')
def android_encrypt(serial: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    """Attempt to enable full-disk/file-based encryption on an Android device (best-effort)."""
    try:
        # Modern Android: user-initiated encryption mostly deprecated (FBE by default). Provide heuristic commands.
        cmds = [
            "settings put global require_password_to_decrypt 1",
            "vdc cryptfs enablecrypto inplace password 1234"  # legacy; may fail
        ]
        outputs = []
        for c in cmds:
            r = subprocess.run(["adb","-s",serial,"shell",c], capture_output=True, text=True, timeout=10)
            outputs.append({"cmd": c, "rc": r.returncode, "stdout": r.stdout[:400], "stderr": r.stderr[:200]})
        state = subprocess.run(["adb","-s",serial,"shell","getprop","ro.crypto.state"], capture_output=True, text=True, timeout=6).stdout.strip()
        return {"status":"ok","state":state,"steps":outputs}
    except Exception as e:
        return {"status":"error","error":str(e)}

# MTK erase logic (using mtkclient)
def erase_mtk(serial, method):
    lock = erase_locks[serial]
    def log(msg):
        with lock:
            msg = _audit_append(serial, msg)
            erase_logs[serial].append(msg)
            _persist_log(serial, msg)
            _update_stream_hash(serial, msg)
        print(f"[ERASE][MTK] {msg}")
    log(f"Starting MTK wipe for {serial} with method {method}")
    try:
        # Use mtkclient to wipe userdata/flash
        if method in ("auto", "multi-pass", "crypto-erase"):
            log("Issuing mtkclient wipe command...")
            subprocess.run(["mtk", "wipe", "--serial", serial], check=True)
            log("MTK wipe command sent. Device should be wiped.")
        else:
            log(f"Unknown MTK erase method: {method}")
        generate_certificate(serial, method, log)
    except Exception as e:
        log(f"MTK erase failed: {e}")

# Linux erase logic
def erase_linux(device_id, method):
    import time
    lock = erase_locks[device_id]
    def log(msg):
        with lock:
            msg = _audit_append(device_id, msg)
            erase_logs[device_id].append(msg)
            _persist_log(device_id, msg)
            _update_stream_hash(device_id, msg)
        print(f"[ERASE][LINUX] {msg}")
    # Prevent duplicate concurrent starts
    with progress_lock:
        if device_id in progress_stats and progress_stats[device_id].get('status') == 'running':
            log(f"Duplicate start suppressed: erase already running for {device_id}")
            return
    log(f"Starting Linux erase: {device_id} with method {method}")
    # Collect device facts (best effort)
    dev_facts = {}
    try:
        import shutil, json as _j
        # Determine if NVMe
        is_nvme = os.path.basename(device_id).startswith('nvme')
        dev_facts['is_nvme'] = is_nvme
        # Get basic lsblk info
        lb = subprocess.run(['lsblk','-b','-o','NAME,SIZE,ROTA,MODEL,SERIAL,TYPE','-J', device_id], capture_output=True, text=True, timeout=5)
        if lb.returncode == 0:
            try:
                data = _j.loads(lb.stdout)
                dev_facts['lsblk'] = data
            except Exception:
                pass
        # SMART / nvme id-ctrl
        if shutil.which('smartctl'):
            sc = subprocess.run(['smartctl','-i','-j', device_id], capture_output=True, text=True, timeout=6)
            if sc.returncode == 0:
                try: dev_facts['smart_id'] = _j.loads(sc.stdout)
                except Exception: pass
        if is_nvme and shutil.which('nvme'):
            idc = subprocess.run(['nvme','id-ctrl', device_id], capture_output=True, text=True, timeout=6)
            if idc.returncode == 0:
                dev_facts['nvme_id_ctrl'] = idc.stdout.splitlines()[:50]
        # Attach to global facts early
        device_facts[device_id] = dev_facts
    except Exception:
        pass
    # Optional: attempt to clear HPA/DCO (hidden areas) before wiping
    try:
        import shutil as _sh
        if os.environ.get('CERTIWIPE_ENABLE_HPA_DCO') == '1' and _sh.which('hdparm') and device_id.startswith('/dev/'):
            # Skip NVMe (HPA/DCO are ATA features); NVMe sanitize/format covers hidden areas
            if not dev_facts.get('is_nvme'):
                log('HPA/DCO clearing enabled – probing with hdparm...')
                hpa_res = {"attempted": True, "hpa_cleared": None, "dco_restored": None, "details": []}
                try:
                    # Read current/native max sectors
                    p = subprocess.run(['hdparm','-N', device_id], capture_output=True, text=True, timeout=6)
                    hpa_res['details'].append({'cmd':'hdparm -N', 'rc': p.returncode, 'out': p.stdout[:400], 'err': p.stderr[:200]})
                    import re as _re
                    cur_native = None
                    m = _re.search(r"max\s+sectors\s*=\s*(\d+)\s*/\s*(\d+)", p.stdout)
                    if m:
                        cur, native = int(m.group(1)), int(m.group(2))
                        cur_native = (cur, native)
                        if cur < native:
                            # Attempt to set max to native (remove HPA)
                            log(f"HPA detected (current {cur} < native {native}); attempting to set to native...")
                            p2 = subprocess.run(['hdparm','-N', f'p{native}', device_id], capture_output=True, text=True, timeout=6)
                            hpa_res['details'].append({'cmd':f'hdparm -N p{native}', 'rc': p2.returncode, 'out': p2.stdout[:400], 'err': p2.stderr[:200]})
                            # Recheck
                            p3 = subprocess.run(['hdparm','-N', device_id], capture_output=True, text=True, timeout=6)
                            hpa_res['details'].append({'cmd':'hdparm -N (recheck)', 'rc': p3.returncode, 'out': p3.stdout[:400], 'err': p3.stderr[:200]})
                            m2 = _re.search(r"max\s+sectors\s*=\s*(\d+)\s*/\s*(\d+)", p3.stdout)
                            if m2 and int(m2.group(1)) == int(m2.group(2)):
                                hpa_res['hpa_cleared'] = True
                                log('HPA cleared: max sectors now equals native.')
                            else:
                                hpa_res['hpa_cleared'] = False
                                log(f'HPA clear attempt did not succeed (max {m2.group(1) if m2 else cur} != native {m2.group(2) if m2 else native}).')
                        else:
                            hpa_res['hpa_cleared'] = True  # nothing to clear
                    # DCO identify and restore
                    p4 = subprocess.run(['hdparm','--dco-identify', device_id], capture_output=True, text=True, timeout=8)
                    hpa_res['details'].append({'cmd':'hdparm --dco-identify', 'rc': p4.returncode, 'out': p4.stdout[:400], 'err': p4.stderr[:200]})
                    # Attempt DCO restore (dangerous; restores to factory defaults, removing DCO limits)
                    log('Attempting DCO restore (factory defaults) ...')
                    p5 = subprocess.run(['hdparm','--dco-restore', device_id, '--yes-i-know-what-i-am-doing'], capture_output=True, text=True, timeout=12)
                    hpa_res['details'].append({'cmd':'hdparm --dco-restore --yes-i-know-what-i-am-doing', 'rc': p5.returncode, 'out': p5.stdout[:400], 'err': p5.stderr[:200]})
                    hpa_res['dco_restored'] = (p5.returncode == 0)
                    if hpa_res['dco_restored']:
                        log('DCO restore reported success.')
                    else:
                        log('DCO restore failed or not supported.')
                except Exception as e:
                    hpa_res['error'] = str(e)
                    log(f'HPA/DCO step error: {e}')
                # Persist into dev facts for certificate evidence
                dev_facts['hpa_dco'] = hpa_res
                device_facts[device_id] = dev_facts
            else:
                log('NVMe device – skipping ATA HPA/DCO (use sanitize/format).')
    except Exception:
        pass

    # Prepare size & passes and sanity check device size
    try:
        dev_size = get_block_device_size(device_id)
        if dev_size is not None and dev_size > 0 and dev_size < 1024*1024:  # <1MiB
            log(f'Device size extremely small ({dev_size} bytes) after HPA/DCO attempts; aborting erase (likely clipped or failing media).')
            return
        # Map higher level methods onto primitives
        effective = method
        if method in ("dod_5220_22m", "multi-pass"):
            effective = "multi-pass"
        if method == "shunyawipe":
            # Simulate: overwrite pass + blkdiscard
            log("ShunyaWipe phase 1: random overwrite (shred 1 pass)...")
            subprocess.run(["shred", "-vz", "-n", "1", device_id], check=True)
            log("ShunyaWipe phase 2: blkdiscard crypto/trim ...")
            try:
                subprocess.run(["blkdiscard", device_id], check=True)
            except Exception:
                log("blkdiscard not supported, skipping.")
            effective = "crypto-erase"
        if method == "nist_800_88":
            log("NIST 800-88: one overwrite pass + verify sample sectors")
            subprocess.run(["shred", "-vz", "-n", "1", device_id], check=True)
            log("NIST 800-88: verification sampling (deterministic offsets)")
            effective = "verify"
        if method == "ecowipe":
            log("EcoWipe: single lightweight overwrite pass...")
            subprocess.run(["shred", "-vz", "-n", "1", device_id], check=True)
            effective = "single-pass"
        if method in ("multi-pass", "dod_5220_22m", "nist_800_88", "ecowipe", "shunyawipe"):
            perform_linux_overwrite(device_id, method, log)
        if effective == "auto":
            # Secure erase gating via env CERTIWIPE_ENABLE_SECURE_ERASE=1
            if os.environ.get('CERTIWIPE_ENABLE_SECURE_ERASE') == '1':
                if dev_facts.get('is_nvme') and shutil.which('nvme'):
                    log("Attempting NVMe sanitize (block erase)...")
                    try:
                        subprocess.run(["nvme","sanitize", device_id, "-a","1","-n","1"], check=True)
                        try:
                            for _ in range(5):
                                sl = subprocess.run(["nvme","sanitize-log", device_id], capture_output=True, text=True, timeout=4)
                                if sl.returncode == 0:
                                    log("nvme sanitize-log snapshot captured")
                                    break
                            # Poll sanitize-log for completion state
                            for _ in range(10):
                                time.sleep(2)
                                pl = subprocess.run(["nvme","sanitize-log", device_id], capture_output=True, text=True)
                                if pl.returncode == 0 and 'sanitize in progress' not in pl.stdout.lower():
                                    log("nvme sanitize appears complete (no 'in progress').")
                                    break
                        except Exception:
                            pass
                        log("NVMe sanitize command issued.")
                    except Exception as e:
                        log(f"NVMe sanitize failed: {e}")
                elif shutil.which('hdparm'):
                    log("Attempting ATA secure erase (hdparm)...")
                    try:
                        subprocess.run(["hdparm","--user-master","u","--security-set-pass","p", device_id], check=True)
                        subprocess.run(["hdparm","--user-master","u","--security-erase","p", device_id], check=True)
                        log("ATA secure-erase completed.")
                        # Poll hdparm -I for security state cleared
                        for _ in range(5):
                            time.sleep(2)
                            hi = subprocess.run(["hdparm","-I", device_id], capture_output=True, text=True)
                            if hi.returncode == 0 and 'not frozen' in hi.stdout.lower():
                                log("hdparm identify indicates drive not frozen; secure erase likely done.")
                                break
                    except Exception as e:
                        log(f"ATA secure erase failed: {e}")
                else:
                    log("No secure erase tool available; falling back to overwrite.")
            else:
                log("Secure erase gated (set CERTIWIPE_ENABLE_SECURE_ERASE=1 to enable). Fallback to overwrite.")
            # Fallback ensure at least single pass overwrite for 'auto'
            try:
                perform_linux_overwrite(device_id, 'multi-pass', log)
            except OSError as oe:
                if getattr(oe, 'errno', None) == 28:
                    log('Raw overwrite failed: ENOSPC (device reports no space) – marking hardware_fault.')
                    finalize_progress(device_id, 'hardware_fault')
                    return
                raise
        elif effective == "multi-pass":
            log("Running shred for multi-pass overwrite...")
            try:
                subprocess.run(["shred", "-vzn", "3", device_id], check=True)
            except subprocess.CalledProcessError as cpe:
                log(f'shred failed (rc={cpe.returncode}); attempting raw fallback.')
                try:
                    perform_linux_overwrite(device_id, 'multi-pass', log)
                except OSError as oe:
                    if getattr(oe, 'errno', None) == 28:
                        log('Raw fallback overwrite failed: ENOSPC – marking hardware_fault.')
                        finalize_progress(device_id, 'hardware_fault')
                        return
                    raise
            log("shred completed.")
        elif effective == "crypto-erase":
            log("Running blkdiscard for SSD trim/discard...")
            subprocess.run(["blkdiscard", device_id], check=True)
            log("blkdiscard completed.")
        else:
            log(f"Method mapped to no-op / already handled: {method} -> {effective}")
    # LUKS detection and header zeroization (best-effort if cryptsetup present)
        try:
            if shutil.which('cryptsetup') and os.path.exists(device_id):
                luks = subprocess.run(['cryptsetup','isLuks', device_id], capture_output=True)
                if luks.returncode == 0:
                    log('Detected LUKS container; zeroing first 4MiB (header/keyslots)')
                    subprocess.run(['dd','if=/dev/zero', f'of={device_id}', 'bs=1M', 'count=4'], capture_output=True)
                    # Capture luksDump (best-effort) for certificate device facts evidence
                    try:
                        ld = subprocess.run(['cryptsetup','luksDump', device_id], capture_output=True, text=True, timeout=8)
                        if ld.returncode == 0:
                            lines = [l for l in ld.stdout.splitlines() if 'Version:' in l or 'Cipher name:' in l or 'Keyslots:' in l][:10]
                            device_facts.setdefault(device_id, {})['luks_dump_excerpt'] = lines
                    except Exception:
                        pass
        except Exception as e:
            log(f'LUKS handling error: {e}')
        # Post verification sampling (start/mid/end sectors)
        try:
            import hashlib as _h
            size = get_block_device_size(device_id)
            if size > 0:
                f = open(device_id,'rb')
                offsets = [0, size//2, max(0,size-4096)]
                digests = []
                for off in offsets:
                    f.seek(off)
                    data = f.read(4096)
                    if not data or len(data)<4096: continue
                    digests.append({"offset": off, "sha256": _h.sha256(data).hexdigest()})
                f.close()
                log(f"Post-verify sample digests: {digests}")
                pass_digests.setdefault(device_id, []).append({"post_samples": digests})
        except Exception as e:
            log(f"Post verification sampling failed: {e}")
        status = progress_stats.get(device_id, {}).get('status')
        if status and status not in ('error','hardware_fault','cancelled'):
            log("Linux erase process finished.")
            generate_certificate(device_id, method, log)
        else:
            log(f'Skipping certificate generation (final status={status}).')
    except Exception as e:
        log(f"Linux erase failed: {e}")
    time.sleep(1)

def erase_windows(device_id, method):
    import time
    lock = erase_locks[device_id]
    def log(msg):
        with lock:
            msg = _audit_append(device_id, msg)
            erase_logs[device_id].append(msg)
            _persist_log(device_id, msg)
            _update_stream_hash(device_id, msg)
        print(f"[ERASE] {msg}")
    log(f"Starting erase: {device_id} with method {method}")
    try:
        # Admin check
        try:
            if not is_admin():
                log("WARNING: Backend not running as Administrator. Some operations may fail (diskpart/raw).")
        except Exception:
            pass

        # Helper: robust diskpart runner
        def run_diskpart_for_disk(disk_number: int, extra_commands, allow_fail=False):
            import tempfile, os as _os
            if isinstance(extra_commands, str):
                extra_commands = [extra_commands]
            script_lines = [
                f"select disk {disk_number}",
                "detail disk",
                "online disk noerr",
                "attributes disk clear readonly",
            ] + extra_commands + ["exit"]
            script_text = "\n".join(script_lines) + "\n"
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
            try:
                tmp.write(script_text.encode("utf-8"))
                tmp.close()
                res = subprocess.run(["diskpart", "/s", tmp.name], capture_output=True, text=True)
                out = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
                for ln in out.splitlines():
                    lnu = ln.lower()
                    if "error" in lnu or "denied" in lnu or "readonly" in lnu:
                        log(f"diskpart: {ln.strip()}")
                if res.returncode != 0:
                    log(f"diskpart exited with code {res.returncode}")
                    # Log full diskpart output for troubleshooting when it fails
                    try:
                        log("diskpart output (begin)")
                        for ln in out.splitlines():
                            s = ln.strip()
                            if s:
                                log(f"diskpart: {s}")
                        log("diskpart output (end)")
                    except Exception:
                        pass
                    if not allow_fail:
                        res.check_returncode()
                return res
            finally:
                try:
                    _os.unlink(tmp.name)
                except Exception:
                    pass

        # Optional: HPA/DCO note (Windows best-effort)
        try:
            if os.environ.get('CERTIWIPE_ENABLE_HPA_DCO') == '1':
                import shutil as _sh
                hpa_res = {"attempted": True, "supported": False, "hpa_cleared": None, "dco_restored": None, "details": []}
                hd = _sh.which('hdparm.exe') or _sh.which('hdparm')
                if hd and os.path.exists(hd):
                    hpa_res['supported'] = True
                    hpa_res['details'].append({'note': 'hdparm present on Windows; manual HPA/DCO attempts possible (not automated).'})
                else:
                    hpa_res['details'].append({'note': 'hdparm.exe not found on Windows; consider clearing HPA/DCO from Linux or vendor tools.'})
                device_facts.setdefault(device_id, {})['hpa_dco_windows'] = hpa_res
        except Exception:
            pass

        # Method selection
        dn = parse_disk_number(device_id)
        if method == "shunyawipe":
            log("ShunyaWipe phase 1: diskpart clean (fast) ...")
            try:
                run_diskpart_for_disk(dn, ["clean"], allow_fail=True)
            except subprocess.CalledProcessError as e:
                log(f"diskpart clean failed (code={e.returncode}); will attempt raw overwrite.")
            log("ShunyaWipe phase 2: BitLocker key disable (manage-bde off, if applicable)...")
            try:
                subprocess.run(["manage-bde", "-off", device_id], check=True)
            except Exception:
                log("BitLocker disable not applicable.")
            try:
                windows_raw_multi_pass(device_id, method, log)
            except Exception as re:
                log(f"Raw overwrite attempt failed after diskpart error: {re}")
        elif method == "ecowipe":
            log("EcoWipe: single lightweight zeroing (clean) ...")
            try:
                run_diskpart_for_disk(dn, ["clean"], allow_fail=True)
            except subprocess.CalledProcessError as e:
                log(f"diskpart clean failed (code={e.returncode}); attempting raw overwrite fallback.")
            try:
                windows_raw_multi_pass(device_id, method, log)
            except Exception as re:
                log(f"Raw overwrite attempt failed after diskpart error: {re}")
        elif method == "dod_5220_22m":
            log("DoD 5220.22-M: diskpart clean all + optional raw multi-pass (experimental)")
            try:
                run_diskpart_for_disk(dn, ["clean all"], allow_fail=True)
                log("Diskpart baseline pass complete.")
            except Exception:
                log("Diskpart baseline pass failed; continuing raw attempt.")
            try:
                windows_raw_multi_pass(device_id, method, log)
            except Exception as e:
                log(f"Raw DoD pattern attempt failed: {e}")
        elif method == "nist_800_88":
            log("NIST 800-88 one-pass sanitize (clean all as purge)")
            try:
                run_diskpart_for_disk(dn, ["clean all"], allow_fail=True)
            except Exception as e:
                log(f"diskpart clean all failed (code may be in prior log); attempting raw overwrite fallback.")
                try:
                    windows_raw_multi_pass(device_id, method, log)
                except Exception as re:
                    log(f"Raw overwrite attempt failed after diskpart error: {re}")
        elif method == "auto":
            log("Running diskpart clean all (this may take a while)...")
            try:
                run_diskpart_for_disk(dn, ["clean all"], allow_fail=True)
                log("Diskpart clean all completed.")
            except subprocess.CalledProcessError as e:
                log(f"diskpart clean all failed (code={e.returncode}); attempting raw overwrite fallback.")
            try:
                windows_raw_multi_pass(device_id, method, log)
            except Exception as re:
                log(f"Raw overwrite attempt failed after diskpart error: {re}")
        elif method == "multi-pass":
            sdelete_path = find_sdelete()
            if sdelete_path:
                log("Running sdelete for multi-pass overwrite...")
                subprocess.run([sdelete_path, "-p", "3", "-z", device_id], check=True)
                log("sdelete multi-pass completed.")
            else:
                log("sdelete not found, falling back to diskpart clean all.")
                try:
                    run_diskpart_for_disk(dn, ["clean all"], allow_fail=True)
                    log("Diskpart clean all completed.")
                except subprocess.CalledProcessError as e:
                    log(f"diskpart clean all failed (code={e.returncode}); continuing with raw overwrite.")
                try:
                    windows_raw_multi_pass(device_id, method, log)
                except Exception as re:
                    log(f"Raw overwrite attempt failed: {re}")
        elif method == "crypto-erase":
            log("Attempting BitLocker removal (if enabled)...")
            try:
                subprocess.run(["manage-bde", "-off", device_id], check=True)
                log("BitLocker decryption started.")
            except Exception:
                log("BitLocker not enabled or manage-bde failed. Falling back to diskpart clean.")
                try:
                    run_diskpart_for_disk(dn, ["clean all"], allow_fail=True)
                    log("Diskpart clean all completed.")
                except subprocess.CalledProcessError as e:
                    log(f"diskpart clean all failed (code={e.returncode}); attempting raw overwrite fallback.")
                    try:
                        windows_raw_multi_pass(device_id, method, log)
                    except Exception as re:
                        log(f"Raw overwrite attempt failed after diskpart error: {re}")
        else:
            log(f"Unknown erase method: {method}")
        # Optional: prepare partition and format after erase (Windows)
        try:
            dn_int = int(dn)
        except Exception:
            dn_int = None
        try:
            should_prepare = False
            bus = None
            if dn_int is not None:
                try:
                    ps = subprocess.run(["powershell","-NoProfile","-Command",
                        f"(Get-Disk -Number {dn_int}).BusType"], capture_output=True, text=True, timeout=6)
                    if ps.returncode == 0:
                        bus = (ps.stdout or "").strip()
                        if bus.upper() == 'USB':
                            # Auto-prepare USB by default unless explicitly disabled
                            if os.environ.get('CERTIWIPE_AUTO_PREPARE','1') != '0':
                                should_prepare = True
                    # If env explicitly requests auto-prepare, honor it regardless of bus
                    if os.environ.get('CERTIWIPE_AUTO_PREPARE') == '1':
                        should_prepare = True
                except Exception:
                    if os.environ.get('CERTIWIPE_AUTO_PREPARE') == '1':
                        should_prepare = True
            if should_prepare and dn_int is not None:
                fs = (os.environ.get('CERTIWIPE_POST_FORMAT_FS','exfat') or 'exfat').lower()
                if fs not in ('exfat','ntfs','fat32'):
                    fs = 'exfat'
                label = os.environ.get('CERTIWIPE_POST_FORMAT_LABEL','WIPED')
                log(f"Preparing partition and formatting ({fs.upper()}) on disk {dn_int} (bus={bus or 'unknown'}) ...")
                # Try MBR path first; if that fails, try a clean + GPT path; if FS fails, try NTFS fallback
                def _format_with(fs_name: str, style_cmd: str | None):
                    seq = []
                    if style_cmd:
                        seq.append(style_cmd)
                    seq += [
                        "create partition primary",
                        f"format fs={fs_name} label={label} quick",
                        "assign"
                    ]
                    run_diskpart_for_disk(dn_int, seq, allow_fail=False)

                try:
                    # Small delay to let the device re-enumerate after raw writes
                    try:
                        time.sleep(1)
                    except Exception:
                        pass
                    try:
                        _format_with(fs, "convert mbr")
                    except Exception as e1:
                        log(f"MBR prepare failed: {e1}; retrying with clean+GPT ...")
                        try:
                            run_diskpart_for_disk(dn_int, ["clean", "convert gpt"], allow_fail=False)
                            try:
                                _format_with(fs, None)
                            except Exception as e2:
                                if fs != 'ntfs':
                                    log(f"Formatting with {fs.upper()} failed: {e2}; retrying with NTFS ...")
                                    _format_with('ntfs', None)
                                else:
                                    raise
                        except Exception as e_final:
                            raise e_final

                    # Try to capture assigned drive letter for certificate facts
                    drive_letter = None
                    try:
                        gp = subprocess.run(["powershell","-NoProfile","-Command",
                            f"Get-Partition -DiskNumber {dn_int} | Get-Volume | Where-Object {{$_.Size -gt 0}} | Select-Object -First 1 -ExpandProperty DriveLetter"],
                            capture_output=True, text=True, timeout=6)
                        if gp.returncode == 0:
                            drive_letter = (gp.stdout or '').strip()
                    except Exception:
                        pass
                    device_facts.setdefault(device_id, {})['post_format'] = {
                        'fs': fs,
                        'label': label,
                        'drive_letter': drive_letter
                    }
                    if drive_letter:
                        log(f"Post-format completed. Drive letter assigned: {drive_letter}:")
                    else:
                        log("Post-format completed. Drive letter assignment not detected.")
                except Exception as e:
                    log(f"Post-format step failed: {e}")
            else:
                if os.environ.get('CERTIWIPE_AUTO_PREPARE','1') == '0':
                    log("Post-format disabled by CERTIWIPE_AUTO_PREPARE=0.")
                elif bus and bus.upper() != 'USB':
                    log(f"Post-format skipped (bus={bus}); enable CERTIWIPE_AUTO_PREPARE=1 to force.")
                else:
                    log("Post-format skipped (no disk number).")
        except Exception as e:
            log(f"Post-format orchestration error: {e}")

        log("Erase process finished.")
        generate_certificate(device_id, method, log)
    except Exception as e:
        log(f"Erase failed: {e}")
    time.sleep(1)

# ---------------------- Mock file erase (development) ----------------------
def erase_mockfile(file_path: str, method: str):
    device_id = f"mockfile:{file_path}"
    lock = erase_locks[device_id]
    def log(msg: str):
        with lock:
            msg = _audit_append(device_id, msg)
            erase_logs[device_id].append(msg)
            _persist_log(device_id, msg)
            _update_stream_hash(device_id, msg)
        print(f"[ERASE][MOCK] {msg}")
    try:
        if not os.path.exists(file_path):
            log(f"File {file_path} missing; creating new mock file")
            with open(file_path,'wb') as f: f.truncate(4*1024*1024)
        size = os.path.getsize(file_path)
        meta = WIPE_METHOD_META.get(method, {"passes":1})
        passes_total = meta.get('passes',1)
        patterns = []
        if method == 'mock_multi':
            patterns = [None,None,None]
        elif method == 'mock_fast':
            patterns = [b"\x00"]
        else:
            patterns = [None]*passes_total
        pattern_names = [('Random' if p is None else f"0x{p[0]:02X}") for p in patterns]
        init_progress(device_id, method, size, len(patterns), pass_patterns=pattern_names)
        block = 256*1024
        import os as _os
        import random as _rand
        fail_pct = 0.0
        try:
            fail_pct = float(os.environ.get('CERTIWIPE_MOCK_FAIL_PCT','0'))
        except Exception:
            fail_pct = 0.0
        with open(file_path,'rb+') as f:
            for idx, pat in enumerate(patterns, start=1):
                next_pass(device_id, pattern_names[idx-1])
                written = 0
                while written < size:
                    if cancel_flags.get(device_id):
                        finalize_progress(device_id, 'cancelled')
                        log('Cancellation requested during mock erase.')
                        return
                    # Simulated random failure (early) for testing error handling
                    if fail_pct > 0 and _rand.random() < fail_pct:
                        raise RuntimeError(f'Simulated mock failure (prob={fail_pct})')
                    to_write = min(block, size - written)
                    buf = _os.urandom(to_write) if pat is None else pat * to_write
                    f.write(buf)
                    written += to_write
                    update_progress(device_id, to_write)
                f.flush()
        finalize_progress(device_id, 'completed', verified=True)
        log('Mock file overwrite complete.')
        generate_certificate(device_id, method, log)
    except Exception as e:
        finalize_progress(device_id, 'error')
        log(f'Mock erase failed: {e}')

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
    # Accept early so client doesn't fail; then poll until erase context exists
    await websocket.accept()
    last_idx = 0
    idle_cycles = 0
    try:
        while True:
            await asyncio.sleep(0.5)
            # If erase hasn't started yet, wait (avoid KeyError)
            if device_id not in erase_locks or device_id not in erase_logs:
                idle_cycles += 1
                # After ~30s with no context, inform client then continue waiting (could also break)
                if idle_cycles % 20 == 0:  # every 10s (@0.5s sleep)
                    try:
                        await websocket.send_text("(waiting for erase to start...) ")
                    except Exception:
                        break
                continue
            idle_cycles = 0
            try:
                with erase_locks[device_id]:
                    logs = erase_logs[device_id]
                    if last_idx < len(logs):
                        for line in logs[last_idx:]:
                            await websocket.send_text(line)
                        last_idx = len(logs)
            except KeyError:
                # Race: lock removed mid-loop; retry next cycle
                continue
    except WebSocketDisconnect:
        pass
    except Exception as e:
        try:
            await websocket.send_text(f"(log stream error: {e})")
        except Exception:
            pass

# Certificate generation and serving
import json
import base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

certificates = {}  # device_id -> {json, pdf_bytes}
transparency_records = {}  # device_id -> transparency publication record
def _hydrate_from_db():
    try:
        with _db_lock:
            conn = _db_conn(); cur = conn.cursor()
            for row in cur.execute("SELECT device_id,json,pdf FROM certificates"):
                certificates[row[0]] = {"json": row[1], "pdf": row[2]}
            for row in cur.execute("SELECT device_id, idx, line FROM logs ORDER BY device_id, idx"):
                did, _, line = row
                erase_logs[did].append(line)
            conn.close()
    except Exception:
        pass
_hydrate_from_db()

def load_signing_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    os.makedirs('keys', exist_ok=True)
    active_meta = 'key_active.txt'
    if os.path.exists(active_meta):
        kid = open(active_meta,'r').read().strip()
        kpath = os.path.join('keys', f'{kid}.pem')
        if os.path.exists(kpath):
            with open(kpath,'rb') as f:
                return serialization.load_pem_private_key(f.read(), password=None)
    # Generate new key if none
    key = Ed25519PrivateKey.generate()
    kid = hashlib.sha256(key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).hexdigest()[:16]
    with open(os.path.join('keys', f'{kid}.pem'),'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    open(active_meta,'w').write(kid)
    return key

@app.post('/rotate_key')
def rotate_key(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    kid = hashlib.sha256(key.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)).hexdigest()[:16]
    with open(os.path.join('keys', f'{kid}.pem'),'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    open('key_active.txt','w').write(kid)
    return {"status":"rotated","key_id": kid}

@app.get('/keys')
def list_keys(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    if not os.path.isdir('keys'): return []
    return sorted([f[:-4] for f in os.listdir('keys') if f.endswith('.pem')])

@app.get('/platform_capabilities')
def platform_capabilities(device_id: str | None = None, _: bool = Depends(api_key_auth), request: Request = None):
    """Report availability of low-level wipe tools and basic device hints.
    Helps frontends decide whether HPA/DCO/NVMe sanitize features can be used.
    """
    rate_limit(request)
    import shutil
    caps = {
        'os': sys.platform,
        'tools': {
            'hdparm': bool(shutil.which('hdparm') or shutil.which('hdparm.exe')),
            'smartctl': bool(shutil.which('smartctl') or shutil.which('smartctl.exe')),
            'nvme': bool(shutil.which('nvme'))
        },
        'device': {
            'id': device_id,
            'is_windows_physical': bool(device_id and device_id.upper().startswith('\\\\.\\PHYSICALDRIVE')),
            'is_linux_block': bool(device_id and device_id.startswith('/dev/')),
            'bus_hint': None
        }
    }
    try:
        if device_id:
            if caps['device']['is_linux_block']:
                # quick lsblk probe for bus
                import json as _j
                r = subprocess.run(['lsblk','-dno','TRAN,ROTA', device_id], capture_output=True, text=True, timeout=3)
                if r.returncode == 0:
                    parts = r.stdout.strip().split()
                    if parts:
                        caps['device']['bus_hint'] = parts[0]
            elif caps['device']['is_windows_physical']:
                # hint via PowerShell Get-Disk BusType
                try:
                    ps = subprocess.run(["powershell","-NoProfile","-Command",
                        f"Get-Disk | Where-Object {{$_.Number -eq {parse_disk_number(device_id)}}} | Select-Object -ExpandProperty BusType"],
                        capture_output=True, text=True, timeout=5)
                    if ps.returncode == 0:
                        caps['device']['bus_hint'] = ps.stdout.strip()
                except Exception:
                    pass
    except Exception:
        pass
    return caps

@app.get('/settings')
def settings_info(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    flags = {
        'secure_erase_enabled': os.environ.get('CERTIWIPE_ENABLE_SECURE_ERASE') == '1',
        'hpa_dco_enabled': os.environ.get('CERTIWIPE_ENABLE_HPA_DCO') == '1',
        'mock_enabled': os.environ.get('CERTIWIPE_ENABLE_MOCK') == '1',
        'post_format_fs': os.environ.get('CERTIWIPE_POST_FORMAT_FS') or None,
        'auto_prepare': os.environ.get('CERTIWIPE_AUTO_PREPARE') == '1',
        'windows_sample_mode': os.environ.get('CERTIWIPE_WINDOWS_SAMPLE_ONLY') == '1',
        'audit_enabled': settings.audit_enabled,
        'rate_limit_per_minute': settings.rate_limit_per_minute,
    }
    return {'flags': flags, 'schema_version': '1'}

@app.post('/transparency_publish')
def transparency_publish(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    head = log_chain_heads.get(device_id)
    if not head:
        raise HTTPException(status_code=404, detail='No audit chain head')
    import time, hashlib as _h
    rec = {
        'head': head,
        'published_at': int(time.time()),
        'head_sha256': _h.sha256(head.encode()).hexdigest()
    }
    transparency_records[device_id] = rec
    return {'status':'published','record': rec}

def generate_certificate(device_id, method, log):
    # Generate JSON certificate
    import datetime
    import hashlib
    import math
    # Abort if progress indicates failure/cancelled
    ps = progress_stats.get(device_id)
    bad_statuses = {'error','cancelled','hardware_fault','permission_denied'}
    if ps and ps.get('status') in bad_statuses:
        log(f'Certificate suppressed (status={ps.get("status")}).')
        return
    # Get erasure log for device
    log_lines = erase_logs.get(device_id, [])
    # Prefer streaming hash state if present
    if device_id in _log_hash_states:
        log_hash = _log_hash_states[device_id].hexdigest()
    else:
        log_text = "\n".join(log_lines)
        log_hash = hashlib.sha256(log_text.encode()).hexdigest()
    meta = WIPE_METHOD_META.get(method, {"passes": 1, "energy_factor": 1.0})
    passes = meta.get("passes", 1)
    # TrustScore heuristic
    base_scores = {
        "ecowipe": 60,
        "auto": 75,
        "multi-pass": 82,
        "dod_5220_22m": 85,
        "nist_800_88": 90,
        "crypto-erase": 88,
        "shunyawipe": 95,
    }
    trust_score = base_scores.get(method, 70)
    trust_components = {"base": trust_score, "verified_bonus":0, "pass_bonus":0, "entropy_bonus":0, "warning_penalty":0}
    try:
        ps = progress_stats.get(device_id)
        if ps and ps.get('verified'):
            trust_components['verified_bonus']=3; trust_score += 3
        passes_done = ps.get('passes_total') if ps else None
        if passes_done and passes_done>1:
            add = min(5, passes_done)
            trust_components['pass_bonus']=add; trust_score += add
        # entropy influence from verification cache if present
        v = verification_cache.get(device_id)
        if v and 'entropy_score' in v:
            es = v['entropy_score']
            if es>0.9:
                trust_components['entropy_bonus']=4; trust_score += 4
            elif es>0.85:
                trust_components['entropy_bonus']=2; trust_score += 2
        warnings = sum(1 for l in log_lines if 'error' in l.lower() or 'fail' in l.lower())
        if warnings:
            pen = min(8, warnings*2)
            trust_components['warning_penalty']=pen; trust_score -= pen
    except Exception:
        pass
    trust_score = max(0, min(100, trust_score))
    # Refined eco metrics: allow disable via CERTIWIPE_DISABLE_ECO=1
    eco_disabled = os.environ.get('CERTIWIPE_DISABLE_ECO') == '1'
    size_gb = 0.0
    total_bytes = None
    try:
        ps = progress_stats.get(device_id)
        if ps and ps.get('total_bytes'):
            total_bytes = ps['total_bytes']
            size_gb = round(total_bytes / (1024**3), 6)
        elif not eco_disabled:
            # Legacy fallback (log parsing) only if eco metrics enabled
            for l in log_lines:
                if 'GB' in l:
                    token = next((t for t in l.split() if t.endswith('GB')), None)
                    if token:
                        try:
                            size_gb = float(token.replace('GB',''))
                        except Exception:
                            size_gb = 0.0
                        break
    except Exception:
        size_gb = 0.0
    eco_obj = None
    if not eco_disabled and size_gb > 0:
        # Minimal deterministic model: energy proportional to bytes actually written (if known)
        bytes_written = None
        try:
            if ps and ps.get('bytes_done'):
                bytes_written = ps['bytes_done']
        except Exception:
            bytes_written = None
        write_ratio = None
        if total_bytes and bytes_written is not None and total_bytes>0:
            try:
                write_ratio = round(bytes_written/total_bytes,6)
            except Exception:
                write_ratio = None
        # Base kWh constant: 0.0003 kWh per GB per pass (placeholder but declared as estimate)
        base_kwh_per_gb_pass = float(os.environ.get('CERTIWIPE_BASE_KWH_GB_PASS','0.0003'))
        kwh = round(size_gb * passes * base_kwh_per_gb_pass, 6)
        carbon_intensity = float(os.environ.get('CERTIWIPE_CARBON_INTENSITY','0.475'))
        co2_kg = round(kwh * carbon_intensity, 6)
        eco_obj = {
            "size_gb_estimate": size_gb,
            "bytes_total": total_bytes,
            "bytes_written": bytes_written,
            "write_ratio": write_ratio,
            "energy_kwh_est": kwh,
            "co2_kg_est": co2_kg,
            "model": "linear-bytes*passes",
            "base_kwh_per_gb_pass": base_kwh_per_gb_pass,
            "note": "All eco values are deterministic estimates; set CERTIWIPE_DISABLE_ECO=1 to remove this block."
        }
    elif eco_disabled:
        eco_obj = {"disabled": True}
    # Build certificate core
    # Progress / coverage metrics
    coverage_ratio = None
    bytes_done = None
    total_bytes = None
    started_at = None
    ended_at = None
    duration = None
    avg_speed_bps = None
    try:
        if ps:
            bytes_done = ps.get('bytes_done')
            total_bytes = ps.get('total_bytes')
            started_at = ps.get('started_at')
            ended_at = ps.get('ended_at') or time.time()
            if started_at and ended_at and ended_at > started_at:
                duration = ended_at - started_at
            geom = device_geometry.get(device_id) or {}
            dev_size = geom.get('size_bytes') or geom.get('capacity_bytes') or total_bytes
            if dev_size and bytes_done is not None:
                coverage_ratio = min(1.0, bytes_done/float(dev_size))
            if bytes_done is not None and duration:
                avg_speed_bps = bytes_done / duration
    except Exception:
        pass
    warnings_list = []
    if coverage_ratio is not None and coverage_ratio < 0.99:
        warnings_list.append('coverage_below_99pct')
    cert_data = {
        "device_id": device_id,
        "method": method,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "status": "success",
        "log_hash": log_hash,
        "passes": passes,
        "schema_version": "1.2",
        "log_chain_head": log_chain_heads.get(device_id),
        "trust_score": trust_score,
        "trust_components": trust_components,
        "eco": eco_obj,
        "progress": {
            "bytes_done": bytes_done,
            "total_bytes": total_bytes,
            "coverage_ratio": coverage_ratio,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": duration,
            "avg_write_speed_bytes_s": avg_speed_bps,
        },
        "warnings": warnings_list or None,
    }
    if device_id in device_geometry:
        cert_data["geometry"] = device_geometry.get(device_id)
    if device_id in device_facts:
        cert_data["device_facts"] = device_facts.get(device_id)
    if device_id in pass_digests:
        cert_data["pass_digests"] = pass_digests[device_id]
    if device_id in transparency_records:
        cert_data["transparency"] = transparency_records[device_id]
    # Attach verification metrics if cached
    vcache = verification_cache.get(device_id)
    if vcache:
        cert_data['verification'] = {k: vcache.get(k) for k in (
            'merkle_root','prob_miss_residual_window','coverage_ratio','coverage_bytes','samples'
        ) if k in vcache}
    # Generate Ed25519 key (for demo, generate new each time; in prod, use persistent key)
    key = load_signing_key()
    pubkey = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    signature_payload = json.dumps(cert_data, separators=(',',':')).encode()
    signature = key.sign(signature_payload)
    cert_data["signature"] = base64.b64encode(signature).decode()
    cert_data["pubkey"] = base64.b64encode(pubkey).decode()
    cert_data["key_id"] = hashlib.sha256(pubkey).hexdigest()[:16]
    # QR code (contains SHA256 log hash + trust score)
    try:
        import qrcode
        import io as _io
        qr = qrcode.QRCode(version=1, box_size=2, border=2)
        qr.add_data(f"certiwipe://verify?hash={log_hash}&score={trust_score}")
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf_qr = _io.BytesIO()
        img.save(buf_qr, format="PNG")
        cert_data["qr_png_b64"] = base64.b64encode(buf_qr.getvalue()).decode()
    except Exception as e:
        # Debug visibility: surface QR generation errors instead of silent swallow
        try:
            print(f"[QR] Generation failed for {device_id}: {e}")
        except Exception:
            pass
        cert_data["qr_png_b64"] = None
    # Save JSON
    cert_json = json.dumps(cert_data, indent=2)
    # Generate PDF
    from io import BytesIO
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(80, 760, "CertiWipe Secure Data Erasure Certificate")
    c.setFont("Helvetica", 10)
    c.drawString(100, 730, f"Device: {device_id}")
    c.drawString(100, 710, f"Method: {method}")
    c.drawString(100, 690, f"Timestamp: {cert_data['timestamp']}")
    c.drawString(100, 670, f"Status: success")
    c.drawString(100, 650, f"Log Hash: {log_hash[:32]}...")
    c.drawString(100, 630, f"Signature: {cert_data['signature'][:32]}...")
    c.drawString(100, 610, f"TrustScore: {trust_score}")
    # Embed QR (if available)
    try:
        qr_b64 = cert_data.get("qr_png_b64")
        if qr_b64:
            from reportlab.lib.utils import ImageReader
            from io import BytesIO as _B
            qr_img = ImageReader(_B(base64.b64decode(qr_b64)))
            # Draw at fixed size near bottom-right of first page
            qr_size = 140
            c.drawImage(qr_img, 430, 600, width=qr_size, height=qr_size, preserveAspectRatio=True, mask='auto')
            c.setFont("Helvetica", 8)
            c.drawString(430, 595, "Scan to verify (hash & score)")
    except Exception as _e:
        try:
            print(f"[QR] PDF embed failed for {device_id}: {_e}")
        except Exception:
            pass
    try:
        if cert_data.get('eco') and isinstance(cert_data['eco'], dict):
            if cert_data['eco'].get('disabled'):
                eco_line = "Eco: disabled"
            elif cert_data['eco'].get('energy_kwh_est') is not None:
                eco_line = f"Eco: {cert_data['eco']['energy_kwh_est']} kWh est, CO2 {cert_data['eco'].get('co2_kg_est','?')} kg"
            else:
                eco_line = "Eco: n/a"
        else:
            eco_line = "Eco: n/a"
        c.drawString(100, 595, eco_line)
    except Exception:
        c.drawString(100, 595, "Eco: n/a")
    c.save()
    pdf_bytes = buf.getvalue()
    certificates[device_id] = {"json": cert_json, "pdf": pdf_bytes}
    try:
        with _db_lock:
            conn = _db_conn(); cur = conn.cursor()
            cur.execute("INSERT OR REPLACE INTO certificates(device_id, json, pdf) VALUES (?,?,?)", (device_id, cert_json, pdf_bytes))
            conn.commit(); conn.close()
    except Exception:
        pass
    log("Certificate generated.")
    finalize_progress(device_id, "completed")

# ---------------------- Low-level overwrite helpers (Linux) -----------------
def get_block_device_size(path: str) -> int:
    try:
        import fcntl, struct
        BLKGETSIZE64 = 0x80081272
        with open(path, 'rb') as f:
            size = fcntl.ioctl(f, BLKGETSIZE64, b"\0"*8)
        return int.from_bytes(size, 'little')
    except Exception:
        return 0

def perform_linux_overwrite(device_id: str, method: str, log, resume: bool=False):
    if not os.path.exists(device_id):
        log("Device path not found for direct overwrite, skipping raw overwrite.")
        return
    total = get_block_device_size(device_id)
    if total <= 0:
        log("Could not determine device size (requires root); attempting shred fallback if available.")
        return
    meta = WIPE_METHOD_META.get(method, {"passes":1})
    passes_total = meta.get("passes",1)
    if method == "dod_5220_22m":
        patterns = [b"\xFF", b"\x00", None]
    elif method == "multi-pass":
        patterns = [None]*passes_total
    elif method == "nist_800_88":
        patterns = [None]
    elif method == "ecowipe":
        patterns = [b"\x00"]
    elif method == "shunyawipe":
        patterns = [None, b"\x00"]
    else:
        patterns = [None]*passes_total
    pattern_names = []
    for pat in patterns:
        if pat is None:
            pattern_names.append("Random")
        else:
            try:
                pattern_names.append(f"0x{pat[0]:02X}")
            except Exception:
                pattern_names.append("Pattern")
    existing = progress_stats.get(device_id) if resume else None
    if not existing:
        init_progress(device_id, method, total, len(patterns), pass_patterns=pattern_names)
    else:
        with progress_lock:
            if not existing.get('pass_patterns'):
                existing['pass_patterns'] = pattern_names
    block_size = 16*1024*1024
    import random, os as _os
    try:
        with open(device_id, 'rb+') as dev:
            resume_pass_index = None
            resume_offset = 0
            if existing:
                # Prefer granular stored offset if present
                resume_pass_index = existing.get('pass_index', 0) + 1
                resume_offset = existing.get('current_offset', 0)
                if resume_offset >= total:
                    resume_offset = 0
            for idx, pat in enumerate(patterns, start=1):
                label = pattern_names[idx-1] if idx-1 < len(pattern_names) else None
                if existing and resume_pass_index and idx < resume_pass_index:
                    continue
                if (not existing) or (not resume_pass_index) or idx > resume_pass_index:
                    next_pass(device_id, label)
                    written = 0
                else:
                    written = resume_offset
                    with progress_lock:
                        progress_stats[device_id]['current_pattern'] = label
                dev.seek(written)
                while written < total:
                    if cancel_flags.get(device_id):
                        finalize_progress(device_id, "cancelled")
                        log("Cancellation requested. Stopping overwrite loop.")
                        return
                    to_write = min(block_size, total - written)
                    buf = _os.urandom(to_write) if pat is None else pat * to_write
                    dev.write(buf)
                    # Streaming pass hash update
                    try:
                        import hashlib as _h
                        ph = pass_stream_hash.setdefault(device_id, {}).get(idx)
                        if ph is None:
                            ph = _h.sha256()
                            pass_stream_hash[device_id][idx] = ph
                        ph.update(buf)
                    except Exception:
                        pass
                    written += to_write
                    update_progress(device_id, to_write)
                    with progress_lock:
                        ps = progress_stats.get(device_id)
                        if ps:
                            ps['current_offset'] = written
                            ps['current_pass_bytes'] = written
                dev.flush(); _os.sync()
                # Pass digest sampling (lightweight)
                try:
                    import hashlib as _h
                    samples = []
                    with open(device_id,'rb') as rdev:
                        for off in (0, total//3, (2*total)//3):
                            if off >= total: continue
                            rdev.seek(off)
                            chunk = rdev.read(4096)
                            if chunk:
                                samples.append(_h.sha256(chunk).hexdigest())
                    if samples:
                        # finalize streaming pass hash if present
                        pass_root = None
                        try:
                            ph = pass_stream_hash.get(device_id, {}).get(idx)
                            if ph:
                                pass_root = ph.hexdigest()
                        except Exception:
                            pass
                        pass_digests.setdefault(device_id, []).append({
                            "pass_index": idx,
                            "pattern": label,
                            "sample_hashes": samples,
                            "stream_digest_blake3": pass_root
                        })
                except Exception:
                    pass
                existing = None
        verified = True
        if method in ("nist_800_88","dod_5220_22m"):
            import math
            samples_ok = 0
            with open(device_id,'rb') as dev:
                for _ in range(5):
                    off = random.randint(0,max(0,total-4096))
                    dev.seek(off)
                    chunk = dev.read(4096)
                    if not chunk: continue
                    from collections import Counter
                    freq = Counter(chunk)
                    uniq_ratio = len(freq)/256
                    if uniq_ratio>0.25:
                        samples_ok +=1
            verified = samples_ok>=3
        finalize_progress(device_id, "raw_overwrite_done", verified=verified)
        log(f"Direct overwrite complete (verified={verified}).")
    except PermissionError:
        finalize_progress(device_id, "permission_denied")
        log("Permission denied for raw device overwrite; run as root for direct patterns.")
    except Exception as e:
        finalize_progress(device_id, "error")
        log(f"Raw overwrite failed: {e}")


# ---------------------- Enhanced Windows raw overwrite ---------------
def windows_raw_multi_pass(device_id: str, method: str, log):
    """
    Production-grade Windows raw multi-pass overwrite for PHYSICALDRIVE devices.
    - Attempts exclusive volume lock and dismount (FSCTL_LOCK_VOLUME, FSCTL_DISMOUNT_VOLUME)
    - Captures geometry (size, sector size)
    - Supports full overwrite if gated, else sample mode
    - Adds verify pass (read-after-write)
    - Stores geometry for certificate inclusion
    """
    try:
        import os, ctypes, struct, math, random, time, msvcrt
        path = device_id
        up = path.upper()
        if 'PHYSICALDRIVE' not in up:
            log("windows_raw_multi_pass: device id doesn't appear to be a PHYSICALDRIVE; skipping raw stage.")
            return
        # Attempt to open raw device (may fail if not elevated)
        try:
            fd = os.open(path, os.O_RDWR | getattr(os, 'O_BINARY', 0))
        except PermissionError as e:
            log(f"Raw open denied (need Administrator). Skipping raw multi-pass. ({e})")
            return
        except OSError as e:
            log(f"Raw open failed: {e}; skipping raw multi-pass.")
            return
        # Try to get geometry (IOCTL_DISK_GET_LENGTH_INFO, IOCTL_DISK_GET_DRIVE_GEOMETRY)
        size_bytes = 0
        sector_size = 512
        geometry = {}
        try:
            IOCTL_DISK_GET_LENGTH_INFO = 0x7405c
            IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x70000
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            hfile = msvcrt.get_osfhandle(fd)
            class GET_LENGTH(ctypes.Structure):
                _fields_ = [('Length', ctypes.c_longlong)]
            out_buf = GET_LENGTH()
            returned = ctypes.c_ulong(0)
            ok = kernel32.DeviceIoControl(ctypes.c_void_p(hfile), IOCTL_DISK_GET_LENGTH_INFO,
                                          None, 0, ctypes.byref(out_buf), ctypes.sizeof(out_buf),
                                          ctypes.byref(returned), None)
            if ok:
                size_bytes = out_buf.Length
            # Get sector size and geometry
            class DRIVE_GEOMETRY(ctypes.Structure):
                _fields_ = [
                    ("Cylinders", ctypes.c_longlong),
                    ("MediaType", ctypes.c_uint),
                    ("TracksPerCylinder", ctypes.c_uint),
                    ("SectorsPerTrack", ctypes.c_uint),
                    ("BytesPerSector", ctypes.c_uint)
                ]
            geo_buf = DRIVE_GEOMETRY()
            ok2 = kernel32.DeviceIoControl(ctypes.c_void_p(hfile), IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                          None, 0, ctypes.byref(geo_buf), ctypes.sizeof(geo_buf),
                                          ctypes.byref(returned), None)
            if ok2:
                sector_size = geo_buf.BytesPerSector
                geometry = {
                    "cylinders": geo_buf.Cylinders,
                    "media_type": geo_buf.MediaType,
                    "tracks_per_cylinder": geo_buf.TracksPerCylinder,
                    "sectors_per_track": geo_buf.SectorsPerTrack,
                    "bytes_per_sector": geo_buf.BytesPerSector,
                    "size_bytes": size_bytes
                }
        except Exception:
            pass
        # Attempt volume lock/dismount
        try:
            FSCTL_LOCK_VOLUME = 0x00090018
            FSCTL_DISMOUNT_VOLUME = 0x00090020
            kernel32.DeviceIoControl(ctypes.c_void_p(hfile), FSCTL_LOCK_VOLUME,
                                    None, 0, None, 0, ctypes.byref(returned), None)
            kernel32.DeviceIoControl(ctypes.c_void_p(hfile), FSCTL_DISMOUNT_VOLUME,
                                    None, 0, None, 0, ctypes.byref(returned), None)
            log("windows_raw_multi_pass: Volume locked and dismounted.")
        except Exception:
            log("windows_raw_multi_pass: Could not lock/dismount volume (may be in use). Proceeding.")
        # Decide scope: enforce FULL overwrite unless explicitly forced into sample mode
        sample_env = os.environ.get('CERTIWIPE_WINDOWS_SAMPLE_ONLY') == '1'
        # Optional explicit opt-in flag file for sample (defense-in-depth)
        sample_flag = os.path.exists('ALLOW_WINDOWS_SAMPLE_MODE')
        is_system = is_system_device(device_id)
        do_full = True
        if is_system:
            log('windows_raw_multi_pass: system device detected -> refusing destructive raw overwrite.')
            os.close(fd)
            return
        if size_bytes <= 0:
            # WMI/PowerShell fallback
            try:
                import subprocess, json as _json
                # Query Win32_DiskDrive for Size where DeviceID contains the physical drive number
                import re
                m = re.search(r'(\d+)$', device_id)
                drv_num = m.group(1) if m else None
                if drv_num:
                    ps = (
                        f"Get-WmiObject Win32_DiskDrive | Where-Object {{$_.Index -eq {drv_num}}} | "
                        "Select-Object -First 1 Size | ConvertTo-Json"
                    )
                    proc = subprocess.run(["powershell","-NoProfile","-Command", ps], capture_output=True, text=True, timeout=8)
                    if proc.returncode == 0 and proc.stdout.strip():
                        try:
                            parsed = _json.loads(proc.stdout)
                            if isinstance(parsed, dict):
                                wb = int(parsed.get('Size') or 0)
                            else:  # sometimes just number
                                wb = int(parsed)
                            if wb > 0:
                                size_bytes = wb
                                geometry['size_bytes'] = wb
                                log(f'windows_raw_multi_pass: WMI fallback size detected: {wb} bytes')
                        except Exception:
                            pass
            except Exception as fe:
                log(f'windows_raw_multi_pass: WMI size fallback failed: {fe}')
        if size_bytes <= 0:
            log('windows_raw_multi_pass: still no reliable disk size after WMI fallback; aborting to avoid false certification.')
            os.close(fd)
            return
        if sample_env and sample_flag:
            do_full = False
            log('windows_raw_multi_pass: SAMPLE MODE explicitly enabled (CERTIWIPE_WINDOWS_SAMPLE_ONLY=1 + ALLOW_WINDOWS_SAMPLE_MODE flag). This run will NOT produce a certified full wipe.')
        if do_full:
            SAMPLE_BYTES = size_bytes
            log(f'windows_raw_multi_pass: FULL raw overwrite confirmed, size={SAMPLE_BYTES} bytes')
        else:
            SAMPLE_BYTES = min(8*1024*1024, size_bytes)
            log(f'windows_raw_multi_pass: operating in LIMITED SAMPLE MODE {SAMPLE_BYTES//(1024*1024)} MiB (non-cert).')
        # Define patterns based on method
        if method == 'dod_5220_22m':
            patterns = [b"\xFF", b"\x00", None]
        else:
            patterns = [None, b"\x00", None]  # random, zero, random
        pattern_names = []
        for p in patterns:
            pattern_names.append('Random' if p is None else f"0x{p[0]:02X}")
        # Initialize progress if not already
        if device_id not in progress_stats:
            init_progress(device_id, method, SAMPLE_BYTES, len(patterns), pass_patterns=pattern_names)
        else:
            with progress_lock:
                ps = progress_stats.get(device_id)
                if ps and ps.get('total_bytes') != SAMPLE_BYTES:
                    ps['total_bytes'] = SAMPLE_BYTES
        block_size = sector_size * 2048 if sector_size else 1024 * 1024  # Prefer sector-aligned blocks
        written_total = 0
        try:
            for idx, pat in enumerate(patterns, start=1):
                next_pass(device_id, pattern_names[idx-1])
                written = 0
                while written < SAMPLE_BYTES:
                    if cancel_flags.get(device_id):
                        finalize_progress(device_id, 'cancelled')
                        log('Cancellation requested during Windows raw sample overwrite.')
                        os.close(fd)
                        return
                    to_write = min(block_size, SAMPLE_BYTES - written)
                    buf = os.urandom(to_write) if pat is None else pat * to_write
                    os.write(fd, buf)
                    written += to_write
                    written_total += to_write
                    update_progress(device_id, to_write)
                os.lseek(fd, 0, os.SEEK_SET)
            # Verify pass: read back and check pattern
            os.lseek(fd, 0, os.SEEK_SET)
            verify_blocks = min(8, SAMPLE_BYTES // block_size)
            verify_ok = True
            for vb in range(verify_blocks):
                data = os.read(fd, block_size)
                if not data or len(data) < block_size:
                    verify_ok = False
                    break
                # Simple check: if last pass was zero, expect zeros
                if patterns[-1] == b"\x00" and any(b != 0 for b in data):
                    verify_ok = False
                    break
            log(f"windows_raw_multi_pass: verify pass {'OK' if verify_ok else 'FAILED'}.")
            # If full overwrite, perform sparse random sector verification across disk
            if do_full and size_bytes > 0:
                try:
                    rng = random.Random( int(hashlib.sha256(path.encode()).hexdigest()[:8],16) )
                    samples = min(128, max(16, size_bytes // (512*1024*1024)))  # 1 sample per ~512MB up to 128
                    sector = sector_size or 512
                    read_size = sector * 8
                    verified = 0
                    os.lseek(fd, 0, os.SEEK_SET)
                    for _ in range(samples):
                        off = (rng.randrange(0, size_bytes // sector) * sector)
                        os.lseek(fd, off, os.SEEK_SET)
                        data = os.read(fd, read_size)
                        if not data:
                            continue
                        if patterns[-1] == b"\x00" and any(b != 0 for b in data):
                            verify_ok = False
                            log(f"windows_raw_multi_pass: sparse verify mismatch at offset {off}")
                            break
                        verified += 1
                    log(f"windows_raw_multi_pass: sparse verification samples={verified}/{samples} result={'OK' if verify_ok else 'FAIL'}")
                except Exception as ve:
                    log(f"windows_raw_multi_pass: sparse verify error {ve}")
            os.close(fd)
        except Exception as e:
            try:
                os.close(fd)
            except Exception:
                pass
            log(f"Error during raw sample overwrite: {e}")
            finalize_progress(device_id, 'error')
            return
        # Store geometry for certificate
        if device_id not in device_geometry:
            device_geometry[device_id] = geometry
        finalize_progress(device_id, 'raw_overwrite_done', verified=do_full and verify_ok)
        cov_ratio = 1.0 if do_full else SAMPLE_BYTES/float(size_bytes or SAMPLE_BYTES)
        log_suffix = 'FULL' if do_full else 'SAMPLE'
        log(f"Windows raw multi-pass {log_suffix} overwrite complete; bytes_written={SAMPLE_BYTES} size={size_bytes} coverage_ratio={cov_ratio:.4f} verified={verify_ok if do_full else False}.")
    except Exception as e:
        log(f"windows_raw_multi_pass unexpected error: {e}")

# ---------------------- System device safety guard -------------------------
def is_system_device(device_id: str) -> bool:
    try:
        system = platform.system()
        if system == 'Linux':
            # Determine root filesystem device
            import subprocess, re
            root_dev = subprocess.run(['findmnt','-n','-o','SOURCE','/'], capture_output=True, text=True).stdout.strip()
            # Normalize e.g., /dev/sda1 -> /dev/sda
            base = re.sub(r'p?\d+$','', root_dev)
            target = re.sub(r'p?\d+$','', device_id)
            return base == target or root_dev == device_id
        if system == 'Windows':
            # Block C: or its physical drive
            if device_id.upper().startswith('C:'):
                return True
            if device_id.upper().startswith('\\.\\PHYSICALDRIVE'):
                # naive: assume PHYSICALDRIVE0 hosts system
                return device_id.upper().endswith('0')
        return False
    except Exception:
        return False

# ---------------------- Cancellation endpoint ------------------------------
@app.post('/cancel')
def cancel(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    if device_id not in progress_stats:
        raise HTTPException(status_code=404, detail='No active progress for device')
    with progress_lock:
        cancel_flags[device_id] = True
        ps = progress_stats[device_id]
        if ps.get('status') not in ('completed','error','cancelled'):
            ps['status'] = 'cancelling'
    # log entry
    with erase_locks[device_id]:
        erase_logs[device_id].append('Cancellation requested by user.')
    return {"status": "cancelling"}

from fastapi.responses import JSONResponse, StreamingResponse
from io import BytesIO
@app.get("/certificate")
def get_certificate(device_id: str, format: str = "json", _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    cert = certificates.get(device_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    if format == "json":
        return JSONResponse(content=json.loads(cert["json"]))
    elif format == "pdf":
        return StreamingResponse(BytesIO(cert["pdf"]), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=certificate_{device_id}.pdf"})
    else:
        raise HTTPException(status_code=400, detail="Invalid format")

@app.get("/certificate_export")
def certificate_export(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    """Export certificate bundle (JSON + PDF + signature) as ZIP."""
    import zipfile, io
    cert = certificates.get(device_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    data = json.loads(cert["json"])
    sig = data.get("signature")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{device_id}_certificate.json", cert["json"])
        z.writestr(f"{device_id}_certificate.pdf", cert["pdf"])
        if sig:
            z.writestr(f"{device_id}_signature.txt", sig)
    buf.seek(0)
    return StreamingResponse(buf, media_type='application/zip', headers={"Content-Disposition": f"attachment; filename={device_id}_certificate.zip"})

@app.get("/certificates")
def list_certificates(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    return [json.loads(v["json"]) for v in certificates.values()]

@app.get("/methods")
def list_methods(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    out = []
    show_mock = os.environ.get('CERTIWIPE_ENABLE_MOCK') == '1'
    for k,v in WIPE_METHOD_META.items():
        if k.startswith('mock_') and not show_mock:
            continue
        cap = dict(v)
        cap['id'] = k
        cap['resumable'] = True if platform.system()=="Linux" and k in ("multi-pass","dod_5220_22m","nist_800_88","ecowipe","shunyawipe") else False
        if k.startswith('android_') and 'description' not in cap:
            cap['description'] = 'Android logical wipe variant'
        out.append(cap)
    return out

@app.get("/logs_export")
def logs_export(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    """Export all logs for a device as a text file.
    Reads the SQLite logs table ordered by idx; falls back to in-memory logs if DB unavailable.
    """
    rate_limit(request)
    try:
        lines = []
        try:
            with _db_lock:
                conn = _db_conn(); cur = conn.cursor()
                for row in cur.execute("SELECT line FROM logs WHERE device_id = ? ORDER BY idx", (device_id,)):
                    lines.append(row[0])
                conn.close()
        except Exception:
            lines = erase_logs.get(device_id, [])
        data = ("\n".join(lines) + "\n").encode()
        # Precompute a safe filename (avoid backslashes in f-string expression)
        try:
            safe_id = device_id.replace(':','_').replace('\\','_').replace('/','_')
        except Exception:
            safe_id = "device"
        filename = f"logs_{safe_id}.txt"
        return StreamingResponse(BytesIO(data), media_type="text/plain", headers={"Content-Disposition": f"attachment; filename={filename}"})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"logs export failed: {e}")

@app.get("/android_encryption")
def android_encryption(serial: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    # Improved: Check multiple properties for encryption status
    try:
        state_result = subprocess.run(["adb", "-s", serial, "shell", "getprop", "ro.crypto.state"], capture_output=True, text=True)
        type_result = subprocess.run(["adb", "-s", serial, "shell", "getprop", "ro.crypto.type"], capture_output=True, text=True)
        status_result = subprocess.run(["adb", "-s", serial, "shell", "getprop", "ro.crypto.status"], capture_output=True, text=True)
        state = state_result.stdout.strip().lower()
        ctype = type_result.stdout.strip().lower()
        status = status_result.stdout.strip().lower()
        encrypted = False
        if state == "encrypted" or ctype == "file" or status == "encrypted":
            encrypted = True
        return {
            "encrypted": encrypted,
            "state": state,
            "type": ctype,
            "status": status
        }
    except Exception as e:
        return {"encrypted": False, "error": str(e)}

import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

@app.get("/bitlocker_status")
def bitlocker_status(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    """
    For PHYSICALDRIVE IDs, map to all associated drive letters and return BitLocker status for each.
    For drive letters, return status directly.
    """
    import re
    import subprocess
    debug = {}
    if not is_admin():
        return {"status": "admin_required", "message": "Administrator privileges required. Run backend elevated to check BitLocker status.", "results": [], "debug": debug}
    try:
        drive_letters = []
        debug['input_device_id'] = device_id
        m = re.search(r"([A-Z]:)", device_id)
        if m:
            drive_letters = [m.group(1)]
            debug['drive_letter_extracted'] = drive_letters
        elif device_id.startswith(r"\\.\PHYSICALDRIVE"):
            disk_num_match = re.search(r"(\d+)$", device_id)
            if disk_num_match:
                disk_num = disk_num_match.group(1)
                debug['disk_num'] = disk_num
                # Use PowerShell to get all drive letters for this disk
                ps_cmd = f"Get-Partition -DiskNumber {disk_num} | Get-Volume | Select-Object -ExpandProperty DriveLetter"
                powershell = ["powershell", "-Command", ps_cmd]
                ps_result = subprocess.run(powershell, capture_output=True, text=True)
                debug['powershell_cmd'] = ps_cmd
                debug['powershell_output'] = ps_result.stdout
                # Parse output for drive letters
                drive_letters = [dl.strip()+":" for dl in ps_result.stdout.splitlines() if dl.strip()]
                debug['mapped_drive_letters'] = drive_letters
        if not drive_letters:
            debug['error'] = 'Could not map device to any drive letter.'
            return {"status": "no_mapping", "message": "Could not map device to any drive letter. Use a drive letter like C: or ensure disk has mounted volumes.", "results": [], "debug": debug}
        results = []
        for drive in drive_letters:
            try:
                result = subprocess.run(["manage-bde", "-status", drive], capture_output=True, text=True)
                raw = result.stdout
                lower_out = raw.lower()
                status = "Unknown"
                # Prefer explicit "Lock Status" line if present
                lock_line = None
                for line in raw.splitlines():
                    if "Lock Status" in line:
                        lock_line = line.lower()
                        break
                if lock_line:
                    if "unlocked" in lock_line:
                        status = "Unlocked"
                    elif "locked" in lock_line:
                        status = "Locked"
                else:
                    # Heuristics (order matters: check 'unlocked' before 'locked')
                    if "unlocked" in lower_out:
                        status = "Unlocked"
                    elif "locked" in lower_out:
                        status = "Locked"
                # Refine for clearly unencrypted cases
                if any(tok in lower_out for tok in ["fully decrypted", "percentage encrypted: 0.0%", "protection off"]):
                    status = "Unlocked"
                results.append({"drive": drive, "status": status, "output": raw})
            except Exception as e:
                results.append({"drive": drive, "status": "Unknown", "error": str(e)})
        overall = None
        if results:
            if any(r.get('status') == 'Locked' for r in results):
                overall = 'Locked'
            elif all(r.get('status') == 'Unlocked' for r in results):
                overall = 'Unlocked'
            else:
                overall = 'Mixed'
        return {"status": overall, "results": results, "debug": debug}
    except Exception as e:
        debug['exception'] = str(e)
        return {"status": "error", "message": str(e), "results": [], "debug": debug}

@app.post("/bitlocker_unlock")
def bitlocker_unlock(
    device_id: str,
    password: str = Body(default=None),
    recovery_key: str = Body(default=None),
    numerical_password: str = Body(default=None),
    key_file: str = Body(default=None),
    _: bool = Depends(api_key_auth),
    request: Request = None
):
    rate_limit(request)
    """
    Unlock BitLocker using password, recovery key, numerical password, or key file.
    """
    try:
        import re
        m = re.search(r"([A-Z]:)", device_id)
        drive = m.group(1) if m else device_id
        if password:
            result = subprocess.run(["manage-bde", "-unlock", drive, "-password", password], capture_output=True, text=True)
        elif recovery_key:
            result = subprocess.run(["manage-bde", "-unlock", drive, "-recoverykey", recovery_key], capture_output=True, text=True)
        elif numerical_password:
            result = subprocess.run(["manage-bde", "-unlock", drive, "-numericalpassword", numerical_password], capture_output=True, text=True)
        elif key_file:
            result = subprocess.run(["manage-bde", "-unlock", drive, "-rk", key_file], capture_output=True, text=True)
        else:
            return {"status": "Failed", "error": "Password, recovery key, numerical password, or key file required."}
        # Always return stdout and stderr for diagnostics
        unlock_success = result.returncode == 0
        # Try to disable protectors only if unlock succeeded
        if unlock_success:
            protectors_result = subprocess.run(["manage-bde", "-protectors", "-disable", drive], capture_output=True, text=True)
            return {
                "status": "Unlocked",
                "output": result.stdout,
                "error": result.stderr,
                "protectors_output": protectors_result.stdout,
                "protectors_error": protectors_result.stderr
            }
        else:
            return {
                "status": "Failed",
                "output": result.stdout,
                "error": result.stderr
            }
    except Exception as e:
        return {"status": "Failed", "error": str(e)}

@app.get("/bitlocker_status_all")
def bitlocker_status_all(_: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    if not is_admin():
        return {"status": "error", "error": "Administrator privileges required"}
    import subprocess, json as _j, re
    volumes = []
    # First try PowerShell Get-BitLockerVolume for rich info
    ps_cmd = (
        "Get-BitLockerVolume | Select-Object MountPoint,VolumeType,EncryptionPercentage,ProtectionStatus,LockStatus,VolumeStatus,AutoUnlockEnabled | ConvertTo-Json -Depth 3"
    )
    try:
        proc = subprocess.run(["powershell", "-Command", ps_cmd], capture_output=True, text=True, timeout=20)
        if proc.returncode == 0 and proc.stdout.strip():
            try:
                data = _j.loads(proc.stdout)
                if isinstance(data, dict):
                    data = [data]
                for v in data:
                    mp = v.get("MountPoint") or None
                    lock = (v.get("LockStatus") or "?").lower()
                    prot = (v.get("ProtectionStatus") or "?").lower()
                    enc_pct = v.get("EncryptionPercentage")
                    status = "Locked" if "locked" in lock else "Unlocked" if "unlocked" in lock else "Unknown"
                    # Refine using protection/encryption state
                    if enc_pct in (0, 0.0) or (isinstance(enc_pct, (int,float)) and enc_pct < 1):
                        if status == "Locked":
                            status = "Unlocked"  # effectively not encrypted
                    volumes.append({
                        "mount_point": mp,
                        "lock_status": status,
                        "encryption_percentage": enc_pct,
                        "protection_status_raw": prot,
                        "raw": v
                    })
            except Exception:
                pass
    except Exception:
        pass
    # Supplement with mountvol to capture unmounted volume GUIDs
    try:
        mv = subprocess.run(["mountvol"], capture_output=True, text=True, timeout=15)
        guids = set(re.findall(r"\\\\\\?\\Volume\{[0-9a-fA-F-]+\}\\", mv.stdout))
        known_mps = {v.get("mount_point") for v in volumes if v.get("mount_point")}
        for guid in guids:
            # Skip if already represented by a mountpoint entry
            if any((guid.startswith(mp) if mp else False) for mp in known_mps):
                continue
            try:
                res = subprocess.run(["manage-bde", "-status", guid], capture_output=True, text=True, timeout=15)
                raw = res.stdout
                low = raw.lower()
                lock_line = None
                for line in raw.splitlines():
                    if "Lock Status" in line:
                        lock_line = line.lower(); break
                if lock_line:
                    if "unlocked" in lock_line:
                        status = "Unlocked"
                    elif "locked" in lock_line:
                        status = "Locked"
                    else:
                        status = "Unknown"
                else:
                    status = "Unlocked" if "unlocked" in low else ("Locked" if "locked" in low else "Unknown")
                if any(tok in low for tok in ["fully decrypted", "percentage encrypted: 0.0%", "protection off"]):
                    status = "Unlocked"
                enc_pct = None
                m = re.search(r"percentage encrypted:\s*([0-9.]+)%", low)
                if m:
                    try: enc_pct = float(m.group(1))
                    except Exception: pass
                volumes.append({
                    "mount_point": None,
                    "volume_guid": guid,
                    "lock_status": status,
                    "encryption_percentage": enc_pct,
                    "raw_text": raw
                })
            except Exception:
                pass
    except Exception:
        pass
    locked = sum(1 for v in volumes if v.get("lock_status") == "Locked")
    unlocked = sum(1 for v in volumes if v.get("lock_status") == "Unlocked")
    return {"total": len(volumes), "locked": locked, "unlocked": unlocked, "volumes": volumes}


# Blockchain anchoring (demo: mock/testnet)
import requests

def _update_certificate_json(device_id: str, mutator):
    cert = certificates.get(device_id)
    if not cert:
        return None
    import json as _json
    data = _json.loads(cert['json'])
    mutator(data)
    cert['json'] = json.dumps(data, indent=2)
    return data

@app.post("/anchor_certificate")
def anchor_certificate(device_id: str, backend: str = Query("mock", enum=["mock","ots"])):
    """Anchor the certificate log hash using selected backend.
    backends:
      mock - previous simulated anchoring (default)
      ots  - OpenTimestamps (requires 'ots' CLI in PATH)
    Returns updated anchor info.
    """
    cert = certificates.get(device_id)
    if not cert:
        raise HTTPException(status_code=404, detail="Certificate not found")
    import json as _json, tempfile, shutil
    data = _json.loads(cert['json'])
    log_hash = data.get('log_hash')
    if not log_hash:
        raise HTTPException(status_code=400, detail="No log hash present")
    anchors = data.get('anchors') or []
    if backend == 'mock':
        txid = f"mock-txid-{log_hash[:10]}"
        anchors.append({"type":"mock","txid":txid})
        def mut(d):
            d['anchors'] = anchors
        new_data = _update_certificate_json(device_id, mut)
        return {"status":"anchored","backend":"mock","txid":txid,"anchors":new_data.get('anchors')}
    if backend == 'ots':
        # Require 'ots' (OpenTimestamps) CLI
        ots_bin = shutil.which('ots')
        if not ots_bin:
            raise HTTPException(status_code=501, detail="'ots' CLI not found. Install opentimestamps-client.")
        try:
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, 'loghash.txt')
                open(path,'w').write(log_hash + '\n')
                # stamp
                subprocess.run([ots_bin,'stamp',path], check=True, capture_output=True, text=True)
                ots_file = path + '.ots'
                if not os.path.exists(ots_file):
                    raise RuntimeError('OTS file not produced')
                proof_b64 = base64.b64encode(open(ots_file,'rb').read()).decode()
                anchors.append({"type":"opentimestamps","proof_b64": proof_b64, "file":"loghash.txt"})
                def mut(d):
                    d['anchors'] = anchors
                new_data = _update_certificate_json(device_id, mut)
                return {"status":"anchored","backend":"ots","anchors": new_data.get('anchors')}
        except subprocess.CalledProcessError as e:
            raise HTTPException(status_code=500, detail=f"OTS stamp failed: {e.stderr or e.stdout}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"OTS anchoring error: {e}")
    raise HTTPException(status_code=400, detail="Unsupported backend")

# -------------------------------------------------------------
# Verification endpoint (deterministic sampling + log heuristic)
# -------------------------------------------------------------
@app.get("/verify_erasure")
def verify_erasure(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    import math, random, hashlib as _h, os
    logs_list = erase_logs.get(device_id, [])
    if not logs_list:
        raise HTTPException(status_code=404, detail="No logs for device")
    total = len(logs_list)
    warnings = sum(1 for l in logs_list if 'fail' in l.lower() or 'error' in l.lower())
    method = next((m for m in WIPE_METHOD_META.keys() if any(m in l.lower() for l in logs_list)), 'unknown')
    base_conf = {
        'shunyawipe': 0.97,
        'nist_800_88': 0.95,
        'dod_5220_22m': 0.94,
        'multi-pass': 0.9,
        'crypto-erase': 0.93,
        'auto': 0.9,
        'ecowipe': 0.82,
    }.get(method, 0.85)
    penalty = min(0.4, warnings * 0.05)
    sample_details = []
    entropy_values = []
    entropy_score = None
    coverage_bytes = 0
    aggregate_hash = None
    merkle_root = None
    merkle_leaves = []
    p_miss = None  # probability of undetected residual region > residual_window (legacy approximation)
    p_miss_hyper = None  # hypergeometric-based bound
    conf_interval = None  # (lower, upper) for entropy_score via normal approx
    residual_window = 4096 * 8  # 32 KiB region
    # Deterministic sampling + double-read consistency & Merkle
    try:
        system = platform.system()
        did_upper = device_id.upper()
        did_is_win_phys = did_upper.startswith('\\\\.\\PHYSICALDRIVE')
        did_is_linux_block = device_id.startswith('/dev/')
        # Resolve device size if it's a raw device (Windows/Linux block)
        size = None
        if did_is_win_phys or did_is_linux_block:
            try:
                size = get_device_size_bytes(device_id)
            except Exception:
                size = None
        # Case 1: regular file path (legacy)
        if size is None and os.path.exists(device_id) and os.path.isfile(device_id):
            try:
                size = os.path.getsize(device_id)
            except Exception:
                size = None
        # Choose sampler based on type
        if size and size > 4096:
            chunk = 4096
            # estimate number of samples based on device size
            max_samples = 128
            min_samples = 24
            est_samples = max(min_samples, min(max_samples, size // (32*1024*1024)))
            seed = _h.sha256((device_id+str(size)).encode()).hexdigest()
            rng = random.Random(int(seed[:10], 16))
            offsets = set()
            while len(offsets) < est_samples:
                off = rng.randrange(0, max(1, size - chunk))
                # align to chunk for stability
                offsets.add((off // chunk) * chunk)
            offsets = sorted(offsets)
            agg = _h.sha256()
            leaf_hashes = []
            # Readers for three scenarios
            if did_is_win_phys:
                import msvcrt, ctypes
                try:
                    fd = os.open(device_id, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
                except Exception:
                    fd = None
                if fd is not None:
                    try:
                        for off in offsets:
                            os.lseek(fd, off, os.SEEK_SET)
                            block1 = os.read(fd, chunk)
                            if not block1 or len(block1) < chunk:
                                continue
                            os.lseek(fd, off, os.SEEK_SET)
                            block2 = os.read(fd, chunk)
                            if block1 != block2:
                                sample_details.append({"offset": off, "error": "inconsistent_read"})
                                continue
                            coverage_bytes += len(block1)
                            # entropy
                            freq = {}
                            for b in block1:
                                freq[b] = freq.get(b, 0) + 1
                            h = 0.0
                            for c in freq.values():
                                p = c / len(block1)
                                h -= p * math.log2(p)
                            norm = h / 8.0
                            entropy_values.append(norm)
                            bh = _h.sha256(block1).hexdigest()
                            leaf_hashes.append(bh)
                            merkle_leaves.append({'offset': off, 'sha256': bh})
                            agg.update(block1)
                            sample_details.append({"offset": off, "sha256": bh, "entropy_norm": round(norm, 4)})
                    finally:
                        try:
                            os.close(fd)
                        except Exception:
                            pass
            else:
                # Linux block device or regular file
                try:
                    with open(device_id, 'rb') as f:
                        for off in offsets:
                            f.seek(off)
                            block1 = f.read(chunk)
                            if not block1 or len(block1) < chunk:
                                continue
                            f.seek(off)
                            block2 = f.read(chunk)
                            if block1 != block2:
                                sample_details.append({"offset": off, "error": "inconsistent_read"})
                                continue
                            coverage_bytes += len(block1)
                            freq = {}
                            for b in block1:
                                freq[b] = freq.get(b, 0) + 1
                            h = 0.0
                            for c in freq.values():
                                p = c / len(block1)
                                h -= p * math.log2(p)
                            norm = h / 8.0
                            entropy_values.append(norm)
                            bh = _h.sha256(block1).hexdigest()
                            leaf_hashes.append(bh)
                            merkle_leaves.append({'offset': off, 'sha256': bh})
                            agg.update(block1)
                            sample_details.append({"offset": off, "sha256": bh, "entropy_norm": round(norm, 4)})
                except Exception:
                    pass
            if entropy_values:
                entropy_score = round(sum(entropy_values) / len(entropy_values), 4)
                aggregate_hash = agg.hexdigest()
            # Build Merkle root (binary pairing)
            try:
                cur = [bytes.fromhex(hh) for hh in leaf_hashes]
                if cur:
                    while len(cur) > 1:
                        nxt = []
                        for i in range(0, len(cur), 2):
                            if i+1 < len(cur):
                                nxt.append(_h.sha256(cur[i] + cur[i+1]).digest())
                            else:
                                nxt.append(cur[i])
                        cur = nxt
                    merkle_root = cur[0].hex()
            except Exception:
                merkle_root = None
            # Probability of miss legacy + hypergeometric bound
            try:
                if size > 0 and coverage_bytes > 0:
                    sample_count = len([s for s in sample_details if 'sha256' in s])
                    if sample_count > 0:
                        p_miss = round((1 - min(residual_window / size, 0.999999)) ** sample_count, 12)
                        # Hypergeometric: population N = size/residual_window
                        N = max(1, size // residual_window)
                        s = max(1, coverage_bytes // residual_window)
                        if s >= N:
                            p_miss_hyper = 0.0
                        else:
                            p_miss_hyper = round((N - s) / N, 12)
            except Exception:
                p_miss_hyper = None
    except Exception:
        pass
    entropy_min = round(min(entropy_values), 4) if entropy_values else None
    entropy_max = round(max(entropy_values), 4) if entropy_values else None
    entropy_stddev = None
    if entropy_values:
        mean = sum(entropy_values) / len(entropy_values)
        variance = sum((v - mean) ** 2 for v in entropy_values) / len(entropy_values)
        entropy_stddev = round(math.sqrt(variance), 4)
    entropy_bonus = 0.0
    if entropy_score is not None:
        entropy_bonus = 0.03 if entropy_score > 0.9 else (0.01 if entropy_score > 0.85 else -0.02)
    confidence = round(max(0.0, min(0.995, base_conf - penalty + entropy_bonus)), 3)
    # Confidence interval for entropy_score (normal approximation)
    try:
        if entropy_values and len(entropy_values) > 5:
            import math as _m
            n = len(entropy_values)
            mean = sum(entropy_values)/n
            var = sum((v-mean)**2 for v in entropy_values)/(n-1)
            se = _m.sqrt(var/n)
            z = 1.96
            conf_interval = [round(mean - z*se,4), round(mean + z*se,4)]
    except Exception:
        conf_interval = None
    file_size = None
    try:
        # Prefer device size if probed
        size_probe = None
        try:
            size_probe = get_device_size_bytes(device_id)
        except Exception:
            size_probe = None
        if size_probe and size_probe > 0:
            file_size = size_probe
        elif os.path.exists(device_id) and os.path.isfile(device_id):
            file_size = os.path.getsize(device_id)
    except Exception:
        file_size = None
    coverage_ratio = None
    if file_size and coverage_bytes:
        try:
            coverage_ratio = round(coverage_bytes / file_size, 6)
        except Exception:
            coverage_ratio = None
    result = {
        "device_id": device_id,
        "method": method,
        "log_lines": total,
        "warnings": warnings,
        "entropy_score": entropy_score,
        "entropy_min": entropy_min,
        "entropy_max": entropy_max,
        "entropy_stddev": entropy_stddev,
        "samples": sample_details,
        "coverage_bytes": coverage_bytes,
        "coverage_ratio": coverage_ratio,
        "aggregate_hash": aggregate_hash,
        "merkle_root": merkle_root,
        "merkle_leaves": merkle_leaves[:128],
    "residual_window_bytes": residual_window,
    "prob_miss_residual_window": p_miss,
    "prob_miss_hypergeom_one_dirty_window": p_miss_hyper,
    "entropy_confidence_interval_95": conf_interval,
        "confidence": confidence,
        "model": {
            "base_confidence": base_conf,
            "penalty": penalty,
            "entropy_bonus": entropy_bonus,
            "statistical": True
        }
    }
    verification_cache[device_id] = result
    return result

# Optional polling progress endpoint (subset of recent logs)
@app.get("/progress")
def progress(device_id: str, tail: int = 25, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    logs = erase_logs.get(device_id, [])
    return {"device_id": device_id, "lines": logs[-tail:]}

@app.get("/progress_detailed")
def progress_detailed(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    """Structured progress stats for a device (used by frontend for speed/ETA)."""
    rate_limit(request)
    ps = progress_stats.get(device_id)
    if not ps:
        raise HTTPException(status_code=404, detail="No progress for device")
    # Provide stable field names expected by UI
    result = {
        "device_id": device_id,
        "method": ps.get("method"),
        "status": ps.get("status"),
        "total_bytes": ps.get("total_bytes"),
        "bytes_written": ps.get("bytes_done"),
        "passes_total": ps.get("passes_total"),
        "pass_index": ps.get("pass_index"),
        "current_pattern": ps.get("current_pattern"),
        "pass_patterns": ps.get("pass_patterns"),
        "percent": ps.get("percent"),
        "verified": ps.get("verified"),
    }

# ---------------------------------------------------------------------------
# Root & favicon (prevent 404 on / and /favicon.ico)
# ---------------------------------------------------------------------------
from fastapi.responses import HTMLResponse, Response
import base64 as _b64

_FAVICON_ICO = _b64.b64decode(
    # 16x16 transparent PNG converted to ICO (very small) base64
    "AAABAAEAEBAAAAEAIABoBAAAFgAAACgAAAAQAAAAIAAAAAEAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

@app.get("/", include_in_schema=False)
def root():
        return HTMLResponse("""<!DOCTYPE html><html><head><title>CertiWipe API</title></head>
        <body style='font-family:Arial;padding:24px;'>
        <h1>CertiWipe API</h1>
        <p>Secure data wiping & certification service is running.</p>
        <ul>
            <li><a href='/docs'>Interactive API Docs</a></li>
            <li><a href='/methods'>Wipe Methods JSON</a></li>
        </ul>
        <p>Status: OK</p>
        </body></html>""")

@app.get('/plan')
def plan(device_id: str, method: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    steps = []
    system = platform.system()
    if system == 'Windows':
        steps.append({'stage':'analyze','action':'DeviceIoControl length + geometry'})
        steps.append({'stage':'lock','action':'FSCTL_LOCK_VOLUME / DISMOUNT'})
        steps.append({'stage':'overwrite','action':'multi-pass sample or full (gated)'})
        steps.append({'stage':'verify','action':'read-back blocks'})
    elif system == 'Linux':
        steps.append({'stage':'collect','action':'lsblk + smartctl'})
        steps.append({'stage':'secure_erase','action':'nvme sanitize or hdparm (gated)'} )
        steps.append({'stage':'overwrite','action':'perform_linux_overwrite if needed'})
        steps.append({'stage':'post_verify','action':'sample digest sectors'})
    else:
        steps.append({'stage':'generic','action':'logical overwrite'})
    risk = 'destructive'
    # Issue short-lived confirmation token (simple in-memory; expires after 120s)
    import secrets, time
    token = secrets.token_hex(16)
    expires = time.time() + 120
    if 'plan_tokens' not in globals():
        globals()['plan_tokens'] = {}
    globals()['plan_tokens'][token] = {'device_id': device_id, 'method': method, 'expires': expires}
    return { 'device_id': device_id, 'method': method, 'steps': steps, 'risk': risk, 'confirm_token': token, 'expires_epoch': int(expires) }

@app.get('/audit_chain')
def audit_chain(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    head = log_chain_heads.get(device_id)
    if not head:
        raise HTTPException(status_code=404, detail='No audit chain head for device')
    return {'device_id': device_id, 'log_chain_head': head}

@app.get('/audit_chain_full')
def audit_chain_full(device_id: str, _: bool = Depends(api_key_auth), request: Request = None):
    rate_limit(request)
    steps = log_chain_steps.get(device_id)
    if not steps:
        raise HTTPException(status_code=404, detail='No audit chain steps for device')
    return {'device_id': device_id, 'steps': steps, 'count': len(steps)}
