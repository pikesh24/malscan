"use client"

import { useEffect, useState } from "react"
import { Capacitor } from "@capacitor/core"
import { App } from "@capacitor/app"
import { Browser } from "@capacitor/browser"
import { CapacitorUpdater } from "@capgo/capacitor-updater"
import { AlertTriangle, X } from "lucide-react"

// Raw Gist URL, e.g. https://gist.githubusercontent.com/<user>/<gistId>/raw/version.json
const VERSION_MANIFEST_URL = process.env.NEXT_PUBLIC_VERSION_MANIFEST_URL || ""

interface VersionManifest {
  versionCode: number
  versionName: string
  otaUrl: string
  apkUrl: string
}

/**
 * Wraps the app root. Handles both update mechanisms:
 * - OTA: downloads and hot-swaps a new JS bundle via capacitor-updater, no reinstall.
 * - Native: shows a blocking modal + manual APK download link when the installed
 *   build is older than what version.json requires (no in-app install path on Android).
 *
 * notifyAppReady() must fire on every launch within ~10s (see capacitor.config.ts
 * appReadyTimeout) or Capgo assumes the bundle is broken and rolls it back.
 */
export function UpdaterProvider({ children }: { children: React.ReactNode }) {
  const [nativeUpdate, setNativeUpdate] = useState<{ versionName: string; apkUrl: string } | null>(null)
  const [rollbackReason, setRollbackReason] = useState<string | null>(null)

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

        const downloaded = await CapacitorUpdater.download({
          url: manifest.otaUrl,
          version: manifest.versionName,
        })
        await CapacitorUpdater.set({ id: downloaded.id })
      } catch (e) {
        console.error("[MalScan] Update check failed:", e)
      }
    })()
  }, [])

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
