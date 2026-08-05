"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { ArrowLeft, ShieldCheck } from "lucide-react"
import { Capacitor } from "@capacitor/core"
import { getApiBaseUrl, setApiBaseUrl, checkBackendHealth } from "../../lib/config"
import DefaultBrowser from "../../lib/native/defaultBrowser"

type TestState = "idle" | "testing" | "ok" | "fail"
type BrowserRoleState = "unsupported" | "checking" | "default" | "not-default"

async function checkBrowserRole(): Promise<BrowserRoleState> {
  if (!Capacitor.isNativePlatform()) return "unsupported"
  const { value: available } = await DefaultBrowser.isRoleAvailable()
  if (!available) return "unsupported"
  const { value: isDefault } = await DefaultBrowser.isDefaultBrowser()
  return isDefault ? "default" : "not-default"
}

export default function SettingsPage() {
  const router = useRouter()
  const [url, setUrl] = useState(() => getApiBaseUrl())
  const [testState, setTestState] = useState<TestState>("idle")
  const [browserRole, setBrowserRole] = useState<BrowserRoleState>("checking")

  useEffect(() => {
    let cancelled = false
    checkBrowserRole().then((state) => { if (!cancelled) setBrowserRole(state) })
    return () => { cancelled = true }
  }, [])

  const handleRequestBrowserRole = async () => {
    await DefaultBrowser.requestRole()
    setBrowserRole(await checkBrowserRole())
  }

  const handleSave = () => {
    const trimmed = url.trim()
    if (trimmed && !trimmed.startsWith("http://") && !trimmed.startsWith("https://")) {
      setTestState("fail")
      return
    }
    setApiBaseUrl(trimmed)
    setTestState("idle")
  }

  // Tests the URL in the box, not whatever the app is currently pointed at, and
  // without saving it — a test that silently persists its input makes "try a
  // value" indistinguishable from "commit to it".
  const handleTest = async () => {
    setTestState("testing")
    setTestState((await checkBackendHealth(url.trim())) ? "ok" : "fail")
  }

  const testLabel =
    testState === "testing" ? "TESTING..."
    : testState === "ok"   ? "✓ CONNECTED"
    : testState === "fail" ? "✕ UNREACHABLE"
    : "TEST CONNECTION"

  return (
    <div className="min-h-screen bg-[#F5F5F3] text-[#121212] font-sans px-6 py-10">
      <div className="max-w-xl mx-auto">
        <button
          onClick={() => router.push("/")}
          className="flex items-center gap-2 font-mono text-xs text-gray-500 hover:text-[#FF3B00] transition-colors mb-10"
        >
          <ArrowLeft size={14} /> BACK
        </button>

        <h1 className="text-3xl font-medium tracking-tight mb-2">Settings</h1>
        <p className="font-mono text-xs text-gray-400 mb-10">
          Only needed when MalScan is packaged as a standalone app (Capacitor) — the
          web version at malscan.example talks to the backend automatically.
        </p>

        <div className="border-2 border-[#121212] bg-white p-6 mb-6">
          <h2 className="font-mono text-[10px] tracking-widest uppercase text-gray-400 mb-3">
            Backend URL
          </h2>
          <input
            type="text"
            value={url}
            onChange={(e) => { setUrl(e.target.value); setTestState("idle") }}
            placeholder="http://192.168.x.x:8000"
            className="w-full px-4 py-3 font-mono text-xs border border-gray-300 outline-none focus:border-[#FF3B00] transition-colors"
          />
          <div className="flex gap-3 mt-4">
            <button
              onClick={handleTest}
              disabled={testState === "testing"}
              className={`flex-1 py-3 font-mono text-[10px] tracking-widest border transition-colors disabled:opacity-50 ${
                testState === "ok" ? "border-green-600 text-green-600"
                : testState === "fail" ? "border-[#FF3B00] text-[#FF3B00]"
                : "border-gray-300 text-gray-500 hover:border-[#121212]"
              }`}
            >
              {testLabel}
            </button>
            <button
              onClick={handleSave}
              className="flex-1 py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest hover:bg-[#FF3B00] transition-colors"
            >
              SAVE
            </button>
          </div>
        </div>

        <p className="font-mono text-[10px] text-gray-400 leading-relaxed mb-10">
          Leave this empty to use the relative /api path (only works for the
          browser-hosted version of MalScan, where Next.js proxies requests to
          the backend). When packaged as an Android app, set this to your
          backend machine&apos;s LAN IP, e.g. http://192.168.0.101:8000.
        </p>

        {browserRole !== "unsupported" && (
          <div className="border-2 border-[#121212] bg-white p-6">
            <h2 className="font-mono text-[10px] tracking-widest uppercase text-gray-400 mb-3 flex items-center gap-2">
              <ShieldCheck size={14} /> Default Browser Protection
            </h2>
            <p className="font-mono text-xs text-gray-500 leading-relaxed mb-4">
              When MalScan is your default browser, links tapped in WhatsApp or
              other apps are checked here before they open anywhere else.
            </p>
            {browserRole === "default" ? (
              <span className="inline-block py-2 px-4 font-mono text-[10px] tracking-widest uppercase text-green-600 border border-green-600">
                ✓ Active
              </span>
            ) : (
              <button
                onClick={handleRequestBrowserRole}
                disabled={browserRole === "checking"}
                className="w-full py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors disabled:opacity-50"
              >
                {browserRole === "checking" ? "Checking..." : "Set as Default Browser"}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
