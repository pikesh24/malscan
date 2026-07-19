# Running MALSCAN

## Prerequisites

- Python 3.11+ and pip
- Node.js 20+ and npm
- (Android APK only) Android Studio + an Android SDK

## 1. Backend (FastAPI)

```powershell
cd backend
pip install -r requirements.txt
pip install -r analysis_engine/requirements.txt
pip install -r attribution_module/requirements.txt
playwright install chromium   # optional — only needed for PDF export (GET /report/{id}/pdf)
uvicorn app.main:app --reload --port 8001
```

Port 8001 (not 8000) matches the frontend's `/api` proxy — port 8000 is commonly taken by other local services (e.g. Splunk).

**API keys** (all optional — the pipeline skips enrichers whose keys are missing) go in `backend/.env`:

```
VT_API_KEY=...
URLSCAN_API_KEY=...
ABUSEIPDB_API_KEY=...
ABUSECH_AUTH_KEY=...
```

`yara-python` is optional on Windows (needs VC++ build tools) — YARA scanning is skipped gracefully if it's not installed.

### Backend tests

```powershell
cd backend
pip install -r requirements-dev.txt
pytest
```

Runs offline and deterministically — no real network calls, no real API keys needed.

## 2. Website (Next.js)

```powershell
cd frontend
npm install
npm run dev      # http://localhost:3000
```

In dev, `/api/*` requests are proxied to `http://127.0.0.1:8001` (the local backend) automatically — no config needed.

### Hosting the website (e.g. Vercel)

1. Import the repo, **Root Directory = `frontend`**.
2. Set an environment variable **`BACKEND_ORIGIN`** to your backend's URL (e.g. `https://malscan-api.onrender.com`) — this is what `/api/*` proxies to in a hosted build.
3. Deploy. The site stays same-origin with the backend through the proxy, so no CORS setup is required.

## 3. Android APK (Capacitor)

The `frontend/` web app is also packaged as a native Android app via Capacitor (`frontend/android/`).

### One-time setup

Create `frontend/.env.capacitor` (git-ignored — copy `frontend/.env.capacitor.example` as a starting point):

```
BUILD_TARGET=capacitor
NEXT_PUBLIC_API_BASE_URL=https://malscan-api.onrender.com
```

`NEXT_PUBLIC_API_BASE_URL` is baked into the app at build time — set it to whichever backend the APK should talk to (the Render URL, a LAN IP, a tunnel, etc.). It can also be changed at runtime without rebuilding, from the app's in-app **Settings** screen.

### Build

```powershell
cd frontend
npm run build:capacitor   # static export -> out/
npx cap sync android       # copies web assets into android/
```

Then build the APK either:

- **In Android Studio:** open `frontend/android/`, then Run (installs on a connected device/emulator) or Build → Build APK.
- **From the command line:**
  ```powershell
  cd frontend/android
  .\gradlew.bat assembleDebug
  ```
  Output: `frontend/android/app/build/outputs/apk/debug/app-debug.apk`

### Installing on another device/emulator

If a different (or older) build of the app is already installed and the install fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE`, the existing install was signed with a different debug key. Uninstall the existing app first (`adb uninstall com.malscan.app`, or long-press the icon → App info → Uninstall), then install the new APK.

## Cloud backend (Render)

`render.yaml` at the repo root is a Render Blueprint that provisions the backend + a Postgres database in one step:

1. Push this repo to GitHub.
2. Render dashboard → **New +** → **Blueprint** → select the repo → **Deploy Blueprint**.
3. Add API keys under the `malscan-api` service's **Environment** tab (same keys as local `.env`, above).

**Free-tier notes:**
- The service sleeps after 15 minutes idle; the next request wakes it (~50s cold start). It only consumes "instance hours" while actually awake, not while asleep.
- Free Postgres expires after some time — scan results are lost when it does (upgrading to a paid DB plan avoids this, no code change needed).
- PDF export (`GET /report/{id}/pdf`) is unavailable on the free-tier build (returns a clean `501`) since headless Chromium isn't installed there — everything else works identically to local.
