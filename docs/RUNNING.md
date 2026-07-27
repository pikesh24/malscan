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
playwright install chromium   # optional — local browser for PDF export (GET /report/{id}/pdf).
                              # Skip it and set BROWSERLESS_WS_URL to rent one instead (see Cloud backend).

uvicorn app.main:app --reload --port 8001
```

Port 8001 (not 8000) matches the frontend's `/api` proxy — port 8000 is commonly taken by other local services (e.g. Splunk).

### After pulling changes

```powershell
cd backend
pip install -r requirements.txt   # picks up new dependencies
python -m pytest -q               # ~15s, confirms the install is complete
```

**`yara-python` became a required dependency.** Pulling without reinstalling leaves YARA
off — 21 detection rules silently inactive, with no error and no warning, just scans that
never detect anything. The same is true of most optional pieces here (RAR extraction, PDF
export): they degrade quietly by design, so a half-installed environment looks like a working
one. Running the test suite after a pull is the quickest way to confirm otherwise.

### API keys

Go in `backend/.env` (gitignored):

```
VT_API_KEY=...
URLSCAN_API_KEY=...
ABUSECH_AUTH_KEY=...
ABUSEIPDB_API_KEY=...
```

The app runs without them — uploads, static analysis and YARA all work. What stops working
is threat intelligence, and **the failure is quiet: a scan of real malware can come back
Clear.** Two matter most:

| key | why |
|---|---|
| `VT_API_KEY` | the heaviest signal (up to +100), and a clean 40+ engine result is what stops ordinary documents scoring high |
| `ABUSECH_AUTH_KEY` | **now required** — abuse.ch made auth mandatory. Without it URLhaus, ThreatFox and MalwareBazaar all return 401, and every lookup reads as "not found" |

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

> **`ABUSECH_AUTH_KEY` must be set on Render too.** It is easy to miss because a local
> `.env` is invisible to the deploy — the file is gitignored and never leaves your machine.
> Without it, abuse.ch returns 401 and URLhaus, ThreatFox and MalwareBazaar all silently
> report "not found" in production while working perfectly on your laptop. Same for
> `VT_API_KEY`.

**YARA now runs in production.** `yara-python` is a declared dependency, so the next deploy
installs it and 21 detection rules become active for the first time. Prebuilt Linux wheels
exist for every Python version Render uses, so the build does not compile YARA from source.
Worth deploying deliberately and watching the first few scans rather than discovering it.

**Free-tier notes:**
- The service sleeps after 15 minutes idle; the next request wakes it (~50s cold start). It only consumes "instance hours" while actually awake, not while asleep.
- Free Postgres expires after some time — scan results are lost when it does (upgrading to a paid DB plan avoids this, no code change needed).
- PDF export (`GET /report/{id}/pdf`) needs a browser the free tier cannot host — see below. Unconfigured, it returns a clean `501`; everything else works identically to local.

### PDF export in the cloud

The build deliberately skips `playwright install chromium`: the binary is large and running it needs more RAM than the free plan gives. But the Android app *cannot* fall back to rendering the PDF itself — `window.print()` does nothing in its WebView — so with no browser reachable from the backend, **every phone user loses export entirely**, not just this one instance.

Rather than upgrade the plan to host a browser, point the backend at one over the network:

1. Sign up at [browserless.io](https://www.browserless.io/) and copy your API token.
2. Render dashboard → `malscan-api` → **Environment** → add:
   ```
   BROWSERLESS_WS_URL = wss://production-sfo.browserless.io/chromium?token=YOUR_TOKEN
   ```
   Swap the region host for `production-lon` or `production-ams` if closer. The `/chromium` path is the CDP endpoint — the one `connect_over_cdp` speaks. (`/chromium/playwright` is a *different*, Playwright-native protocol and will not connect here.)
3. Redeploy is not required — Render restarts the service when an env var changes.

The endpoint then drives the rented browser exactly as it drives a local one: the report HTML is pushed over the connection with `set_content`, so the remote browser never has to reach back into this service to fetch anything.

Failure modes are kept distinguishable on purpose:

| Response | Meaning |
| --- | --- |
| `501` | No browser from either source — nothing installed locally, `BROWSERLESS_WS_URL` unset. |
| `502` | A browser *was* configured but the render failed — bad token, exhausted quota, service down, or a render timeout. |

Locally nothing changes: leave `BROWSERLESS_WS_URL` unset and `playwright install chromium` keeps working. Setting it in `backend/.env` is the quickest way to test the rented path before deploying.
