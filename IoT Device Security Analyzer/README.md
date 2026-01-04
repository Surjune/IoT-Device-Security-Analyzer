# IoT Analyzer (single-file backend + editable frontend)

## Quick start (Windows)

1. Create & activate venv (PowerShell):
```
python -m venv venv
.\venv\Scripts\Activate.ps1
```

2. Install deps:
```
pip install fastapi uvicorn
```

3. Run:
```
cd backend
python app.py
```

4. Open:
http://localhost:8000

Frontend files are in `frontend/` and editable. Changes appear after refresh.

Default scan CIDR: 192.168.31.0/24
