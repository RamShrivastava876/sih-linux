import os, json, math
from fastapi.testclient import TestClient
import importlib

# Import main app
spec = importlib.util.spec_from_file_location('app_main','main.py')
app_main = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app_main)
client = TestClient(app_main.app)

API_KEY_HEADER = {}
if app_main.settings.api_key:
    API_KEY_HEADER = {'x-api-key': app_main.settings.api_key}

def call_verify(path):
    # Inject fake logs so verify endpoint can infer method
    app_main.erase_logs[path] = [f"multi-pass sample log {i}" for i in range(10)]
    return client.get('/verify_erasure', params={'device_id': path}, headers=API_KEY_HEADER)

def test_entropy_random(temp_file_random):
    r = call_verify(temp_file_random)
    assert r.status_code == 200
    data = r.json()
    assert data['entropy_score'] is None or data['entropy_score'] > 0.75

def test_entropy_zero(temp_file_zero):
    r = call_verify(temp_file_zero)
    assert r.status_code == 200
    data = r.json()
    # Pure zeros => low coverage entropy expected (if any sample)
    if data['entropy_score'] is not None:
        assert data['entropy_score'] < 0.3

def test_prob_miss_monotonic(temp_file_random):
    # Run twice with manipulated coverage to ensure p_miss decreases
    r1 = call_verify(temp_file_random)
    d1 = r1.json()
    # artificially inflate coverage_bytes to simulate more sampling
    app_main.verification_cache[temp_file_random]['coverage_bytes'] *= 2
    r2 = call_verify(temp_file_random)
    d2 = r2.json()
    pm1 = d1.get('prob_miss_residual_window') or 1.0
    pm2 = d2.get('prob_miss_residual_window') or 1.0
    assert pm2 <= pm1

def test_merkle_root_changes(temp_file_random):
    r1 = call_verify(temp_file_random)
    d1 = r1.json()
    # Flip one byte in file then re-run
    with open(temp_file_random,'r+b') as f:
        f.seek(0)
        b = f.read(1)
        f.seek(0)
        f.write(b'\xFF' if b != b'\xFF' else b'\x00')
    r2 = call_verify(temp_file_random)
    d2 = r2.json()
    if d1.get('merkle_root') and d2.get('merkle_root'):
        assert d1['merkle_root'] != d2['merkle_root']
