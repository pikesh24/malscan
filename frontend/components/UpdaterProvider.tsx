"use client"

import { useEffect, useState } from "react"
import { Capacitor } from "@capacitor/core"
import { App } from "@capacitor/app"
import { Browser } from "@capacitor/browser"
import { CapacitorUpdater } from "@capgo/capacitor-updater"
import { AlertTriangle, Download, X } from "lucide-react"

// Raw Gist URL, e.g. https://gist.githubusercontent.com/<user>/<gistId>/raw/version.json
const VERSION_MANIFEST_URL = process.env.NEXT_PUBLIC_VERSION_MANIFEST_URL || ""

interface VersionManifest {
  versionCode: number
  versionName: string
  otaUrl: string
  apkUrl: string
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

      try {
        const [{ build: currentVersionCode }, { bundle: currentBundle }, manifest] = await Promise.all([
          App.getInfo(),
          CapacitorUpdater.current(),
          fetch(`${VERSION_MANIFEST_URL}?t=${Date.now()}`).then((r) => r.json() as Promise<VersionManifest>),
        ])

        if (Number(manifest.versionCode) > Number(currentVersionCode)) {
          setNativeUpdate({ versionName: manifest.versionName, apkUrl: manifest.apkUrl })
          return
        }

        if (manifest.versionName === currentBundle.version) return

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

      {otaState?.phase === "available" && (
        <div className="fixed bottom-0 inset-x-0 z-[110] px-4 pb-4">
          <div className="flex items-center justify-between gap-3 bg-white border-2 border-[#121212] px-4 py-3 shadow-lg">
            <div className="min-w-0">
              <p className="text-sm font-medium tracking-tight truncate">Update available</p>
              <p className="font-mono text-[10px] text-gray-500 truncate">Version {otaState.versionName}</p>
            </div>
            <button
              onClick={applyOtaUpdate}
              className="shrink-0 flex items-center gap-2 py-2 px-4 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors"
            >
              <Download size={14} />
              Update
            </button>
          </div>
        </div>
      )}

      {(otaState?.phase === "downloading" || otaState?.phase === "installing") && (
        <div className="fixed inset-0 z-[120] flex items-center justify-center bg-black/50 px-6">
          <div className="relative w-full max-w-sm bg-white border-2 border-[#121212] p-6">
            <h2 className="text-lg font-medium tracking-tight mb-2">
              {otaState.phase === "downloading" ? "Downloading update" : "Installing update"}
            </h2>
            <p className="font-mono text-xs text-gray-500 leading-relaxed mb-4">Version {otaState.versionName}</p>
            <div className="h-2 w-full bg-gray-200">
              <div
                className="h-full bg-[#121212] transition-all"
                style={{ width: `${otaState.phase === "downloading" ? otaState.percent : 100}%` }}
              />
            </div>
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
