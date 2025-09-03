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
