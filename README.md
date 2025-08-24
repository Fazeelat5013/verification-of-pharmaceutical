# Verify Pharma – Full MVP (Flask)

## What’s inside
- Roles: **User**, **Company**, **Admin**
- Auth: signup/login (hashed passwords)
- Company registration → **Admin approval**
- Approved companies can **Add / Update / Delete** medicines
- Users can verify **by batch number**, **by uploading QR image**, or **Live QR scan in browser**
- Admin: review companies (approve/delete) and see/delete medicines
- Bootstrap UI, SQLite DB (auto-created), uploads folder
- CORS + .env support
- Replit friendly (no system-level deps). QR by upload uses OpenCV if available.

## Run locally (VS Code)
```bash
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # Windows: copy .env.example .env
python app.py
```
Open: http://127.0.0.1:5000

**Default Admin**: `admin@verifypharma.com` / `admin123` (can be set via .env)

## Deploy on Replit
1) Create a new Python Repl and upload all files/folders (not the `venv`).
2) Shell: `pip install -r requirements.txt`
3) Secrets: add `SECRET_KEY` (and optionally `ADMIN_EMAIL`, `ADMIN_PASSWORD`).
4) Run (the `.replit` is already set).

## Notes
- Live camera scan uses the front-end library **html5-qrcode** (QR only). For 1D barcodes (EAN/Code128), consider QuaggaJS later.
- Server-side QR from image upload uses OpenCV. If OpenCV cannot install in your environment, batch number verification and live scan still work.


---

## Local Run (VS Code)

1. Install Python 3.9 or newer from python.org.
2. Open this folder in VS Code.
3. In the terminal:

```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate

pip install -r requirements.txt
python app.py
```

4. Visit http://127.0.0.1:5000 in your browser.

### Environment variables (.env)

Create a `.env` file in the project root:

```
SECRET_KEY=change_me
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=StrongPass!234
ALLOWED_ORIGINS=*
```

### Notes
- First run will create `pharma.db` SQLite database automatically.
- Logs are written to `logs/app.log`.
- If an older database exists, we auto-add `expiry_date` column if missing.
