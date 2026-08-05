import { Capacitor } from "@capacitor/core"

// Resolves where the FastAPI backend lives.
//
// Normal web deploy (npm run dev / next start, or anyone just visiting the
// site in a browser): always uses the relative "/api" path, full stop —
// next.config.ts's rewrite proxies that to the backend. The localStorage
// override below is intentionally never consulted here, even if a stray
// value exists from earlier testing — that's what caused the website to
// break by inheriting a backend URL meant only for the packaged app.
//
// Capacitor build (npm run build:capacitor): the app is static HTML/JS with
// no Next.js server, so there's no rewrite proxy. NEXT_PUBLIC_API_BASE_URL is
// baked in at build time as the default, and can be overridden at runtime
// (without rebuilding) via the in-app Settings page, stored in localStorage —
// mirroring malscan-mobile's constants/config.ts + Settings screen.
const BUILD_TIME_API_BASE_URL = process.env.NEXT_PUBLIC_API_BASE_URL || ""

const STORAGE_KEY = "malscan_api_base_url"

export function getApiBaseUrl(): string {
  if (typeof window !== "undefined" && Capacitor.isNativePlatform()) {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    if (stored) return stored
  }
  return BUILD_TIME_API_BASE_URL
}

export function setApiBaseUrl(url: string): void {
  if (typeof window === "undefined") return
  if (url) window.localStorage.setItem(STORAGE_KEY, url)
  else window.localStorage.removeItem(STORAGE_KEY)
}

/**
 * path must start with "/api/..." (matches the existing call sites and the
 * next.config.ts rewrite). When a base URL is configured, the "/api" prefix
 * is stripped since the backend's own routes have no such prefix.
 */
export function apiUrl(path: string): string {
  const base = getApiBaseUrl()
  if (!base) return path
  return base.replace(/\/$/, "") + path.replace(/^\/api/, "")
}

/**
 * Probes a backend and reports whether it answered.
 *
 * Pass an explicit baseUrl to test *that* host. Without it the probe follows
 * getApiBaseUrl(), which on the web build deliberately ignores the stored
 * override — so a Settings page that tested the typed URL this way was really
 * testing the /api proxy, and reported "connected" for a host it had never
 * contacted. Reporting a connection that was never attempted is the one answer
 * this check must never give.
 */
export async function checkBackendHealth(baseUrl?: string): Promise<boolean> {
  const explicit = baseUrl?.trim()
  const target = explicit
    ? explicit.replace(/\/$/, "") + "/status/health-ping"
    : apiUrl("/api/status/health-ping")
  try {
    const res = await fetch(target, { cache: "no-store" })
    return res.ok || res.status === 404
  } catch {
    return false
  }
}
