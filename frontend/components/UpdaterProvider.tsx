"use client"

import { useEffect, useState } from "react"
import { Capacitor } from "@capacitor/core"
import { App } from "@capacitor/app"
import { Browser } from "@capacitor/browser"
import { CapacitorUpdater } from "@capgo/capacitor-updater"
import { AlertTriangle, Download, X } from "lucide-react"

// GitHub API Gist URL, e.g. https://api.github.com/gists/<gistId>
// (NOT the gist.githubusercontent.com "raw" URL — that sits behind a CDN that
// can lag several minutes behind the actual content after an update.)
const VERSION_MANIFEST_URL = process.env.NEXT_PUBLIC_VERSION_MANIFEST_URL || ""

interface VersionManifest {
  versionCode: number
  versionName: string
  otaUrl: string
  apkUrl: string
}

// The manifest decides what code this app downloads and runs, and it lives in a
// Gist whose write token sits in CI secrets. Anyone who obtains that token could
// point every installed copy at a bundle of their choosing — and neither URL was
// checked before use: not the scheme, not the host, not a signature.
//
// An allowlist is not a substitute for signing the bundle (tracked separately),
// but it removes the one-step version of that attack. These are the hosts CI
// actually publishes to: build-apk.yml attaches update.zip and app-debug.apk to
// a GitHub Release, and release asset downloads redirect via objects.*.
const ALLOWED_UPDATE_HOSTS = [
  "github.com",
  "objects.githubusercontent.com",
  "raw.githubusercontent.com",
]

function isTrustedUpdateUrl(raw: string | undefined): boolean {
  if (!raw) return false
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    return false
  }
  // https only: an OTA bundle fetched over http can be swapped in transit, and
  // the app permits cleartext for LAN development.
  if (url.protocol !== "https:") return false
  return ALLOWED_UPDATE_HOSTS.includes(url.hostname)
}

type OtaState =
  | { phase: "available"; versionName: string; otaUrl: string }
  | { phase: "downloading"; versionName: string; percent: number }
  | { phase: "installing"; versionName: string }

/**
 * Wraps the app root. Handles both update mechanisms:
 * - OTA: user taps "Update", we download the new JS bundle with a progress bar and
 *   hot-swap it via capacitor-updater, no reinstall.
 * - Native: shows a blocking modal + manual APK download link when the installed
 *   build is older than what version.json requires (no in-app install path on Android).
 *
 * notifyAppReady() must fire on every launch within ~10s (see capacitor.config.ts
 * appReadyTimeout) or Capgo assumes the bundle is broken and rolls it back.
 */
export function UpdaterProvider({ children }: { children: React.ReactNode }) {
  const [nativeUpdate, setNativeUpdate] = useState<{ versionName: string; apkUrl: string } | null>(null)
  const [rollbackReason, setRollbackReason] = useState<string | null>(null)
  const [otaState, setOtaState] = useState<OtaState | null>(null)

  useEffect(() => {
    if (!Capacitor.isNativePlatform()) return

    ;(async () => {
      await CapacitorUpdater.notifyAppReady()

      const failedUpdate = await CapacitorUpdater.getFailedUpdate()
      if (failedUpdate) {
        setRollbackReason(`Update to ${failedUpdate.bundle.version} failed to load and was rolled back.`)
      }

      if (!VERSION_MANIFEST_URL) return
      // The manifest is baked in at build time, so this is a misconfiguration
      // guard rather than an attack surface — but a plaintext manifest would
      // hand an on-path attacker the update pointer directly.
      if (!VERSION_MANIFEST_URL.startsWith("https://")) {
        console.error("[MalScan] Update manifest URL must be https — skipping update check.")
        return
      }

      try {
        const [{ build: currentVersionCode }, { bundle: currentBundle }, gistResponse] = await Promise.all([
          App.getInfo(),
          CapacitorUpdater.current(),
          fetch(`${VERSION_MANIFEST_URL}?t=${Date.now()}`).then((r) => r.json()),
        ])
        const manifest: VersionManifest = JSON.parse(gistResponse.files["version.json"].content)

        if (Number(manifest.versionCode) > Number(currentVersionCode)) {
          if (!isTrustedUpdateUrl(manifest.apkUrl)) {
            console.error("[MalScan] Refusing APK update from untrusted URL:", manifest.apkUrl)
            return
          }
          setNativeUpdate({ versionName: manifest.versionName, apkUrl: manifest.apkUrl })
          return
        }

        if (manifest.versionName === currentBundle.version) return

        if (!isTrustedUpdateUrl(manifest.otaUrl)) {
          console.error("[MalScan] Refusing OTA bundle from untrusted URL:", manifest.otaUrl)
          return
        }
        setOtaState({ phase: "available", versionName: manifest.versionName, otaUrl: manifest.otaUrl })
      } catch (e) {
        console.error("[MalScan] Update check failed:", e)
      }
    })()
  }, [])

  const applyOtaUpdate = async () => {
    if (!otaState || otaState.phase !== "available") return
    const { versionName, otaUrl } = otaState

    const progressListener = await CapacitorUpdater.addListener("download", (event) => {
      setOtaState({ phase: "downloading", versionName, percent: event.percent })
    })

    try {
      const downloaded = await CapacitorUpdater.download({ url: otaUrl, version: versionName })
      setOtaState({ phase: "installing", versionName })
      await CapacitorUpdater.set({ id: downloaded.id })
    } catch (e) {
      console.error("[MalScan] OTA update failed:", e)
      setOtaState(null)
    } finally {
      progressListener.remove()
    }
  }

  return (
    <>
      {rollbackReason && (
        <div className="fixed top-0 inset-x-0 z-[110] flex items-center justify-between gap-3 bg-[#FF3B00] text-white px-4 py-2 font-mono text-[10px] tracking-widest uppercase">
          <span>{rollbackReason}</span>
          <button onClick={() => setRollbackReason(null)} className="shrink-0">
            <X size={14} />
          </button>
        </div>
      )}

      {otaState && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/50 px-6">
          <div className="relative w-full max-w-sm bg-white border-2 border-[#121212] p-6">
            <Download className="w-10 h-10 text-[#FF3B00] mb-4" />
            <h2 className="text-lg font-medium tracking-tight mb-2">
              {otaState.phase === "available" && "Update Required"}
              {otaState.phase === "downloading" && "Downloading update"}
              {otaState.phase === "installing" && "Installing update"}
            </h2>
            <p className="font-mono text-xs text-gray-500 leading-relaxed mb-6">Version {otaState.versionName}</p>

            {otaState.phase === "available" ? (
              <button
                onClick={applyOtaUpdate}
                className="w-full py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors"
              >
                Update Now
              </button>
            ) : (
              <div className="h-2 w-full bg-gray-200">
                <div
                  className="h-full bg-[#121212] transition-all"
                  style={{ width: `${otaState.phase === "downloading" ? otaState.percent : 100}%` }}
                />
              </div>
            )}
          </div>
        </div>
      )}

      {nativeUpdate && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/50 px-6">
          <div className="relative w-full max-w-sm bg-white border-2 border-[#121212] p-6">
            <AlertTriangle className="w-10 h-10 text-[#FF3B00] mb-4" />
            <h2 className="text-lg font-medium tracking-tight mb-2">Update Required</h2>
            <p className="font-mono text-xs text-gray-500 leading-relaxed mb-6">
              A new version ({nativeUpdate.versionName}) of MalScan is required to continue. Please download and
              install it.
            </p>
            <button
              onClick={() => Browser.open({ url: nativeUpdate.apkUrl })}
              className="w-full py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors"
            >
              Download Update
            </button>
          </div>
        </div>
      )}

      {children}
    </>
  )
}
