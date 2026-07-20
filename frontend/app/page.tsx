"use client"

import { useState, useRef } from "react"
import { useRouter } from "next/navigation"
import { motion, useScroll, useTransform } from "framer-motion"
import { UploadCloud, ArrowRight } from "lucide-react"
import { Capacitor } from "@capacitor/core"
import { submitFileForScan, submitUrlForScan } from "../lib/scan"

// --- BACKGROUND PLACEHOLDER ---
const BackgroundMedia = () => (
  <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-200 via-[#F5F5F3] to-[#F5F5F3] opacity-50"></div>
    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/graphy.png')] opacity-[0.05]"></div>
  </div>
)

export default function LandingPage() {
  const router = useRouter()
  const { scrollY } = useScroll()
  const yText = useTransform(scrollY, [0, 300], [0, -50])
  const yUpload = useTransform(scrollY, [0, 300], [0, -20])

  // Settings (backend URL) only matters in the packaged app — hidden on the
  // website so visitors can't stumble into a control that does nothing there.
  const [isNative] = useState(() => typeof window !== "undefined" && Capacitor.isNativePlatform())

  const fileInputRef = useRef<HTMLInputElement>(null)
  const [isUploading, setIsUploading] = useState(false)
  const [urlInput, setUrlInput] = useState("")
  const [isSubmittingUrl, setIsSubmittingUrl] = useState(false)
  const [urlError, setUrlError] = useState<string | null>(null)

  const handleUploadClick = () => {
    fileInputRef.current?.click()
  }

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setIsUploading(true)
    try {
      const jobId = await submitFileForScan(file, file.name)
      router.push(`/analysis?id=${jobId}`)
    } catch (err) {
      console.error(err)
      router.push(`/analysis?id=job-demo-8x9921`)
    }
    setIsUploading(false)
  }

  const handleUrlSubmit = async () => {
    const trimmed = urlInput.trim()
    if (!trimmed) { setUrlError("Please enter a URL."); return }
    setUrlError(null)
    setIsSubmittingUrl(true)
    try {
      const jobId = await submitUrlForScan(trimmed)
      router.push(`/analysis?id=${jobId}`)
    } catch (err) {
      console.error(err)
      setUrlError("Submission failed. Is the backend running?")
    }
    setIsSubmittingUrl(false)
  }

  return (
    <div className="min-h-screen bg-[#F5F5F3] text-[#121212] font-sans selection:bg-[#FF3B00] selection:text-white relative">
      <BackgroundMedia />
      
      {/* HEADER */}
      <nav className="fixed top-0 w-full p-8 flex justify-end z-50 mix-blend-difference text-white/80 uppercase tracking-widest text-xs font-mono">
        <div className="flex gap-6 items-center">
            {isNative && (
              <button onClick={() => router.push('/settings')} className="hover:text-[#FF3B00] transition-colors">SETTINGS</button>
            )}
        </div>
      </nav>
      
      {/* HERO SECTION (UPDATED TEXT) */}
      <main className="min-h-screen flex flex-col justify-center items-center relative z-10 px-6 pt-20">
        <motion.div style={{ y: yText }} className="text-center mb-16 relative w-full flex flex-col items-center">
          <div className="inline-block px-4 py-1.5 mb-6 bg-[#FF3B00]/5 border border-[#FF3B00]/30 text-[#FF3B00] text-[10px] font-bold tracking-[0.3em] uppercase rounded-full backdrop-blur-sm">
            Automated Forensic Intelligence
          </div>
          <h1 className="text-7xl md:text-[11vw] font-black tracking-tighter leading-[0.8] text-[#121212] mb-6">
            MALSCAN<span className="text-[#FF3B00]">.</span>
          </h1>
          <div className="flex items-center justify-center gap-4 mb-8 w-full max-w-2xl">
             <div className="h-px flex-1 bg-gradient-to-r from-transparent to-gray-300"></div>
             <span className="text-gray-500 font-bold tracking-[0.4em] text-xs md:text-sm uppercase whitespace-nowrap">
               Threat. Visualized.
             </span>
             <div className="h-px flex-1 bg-gradient-to-l from-transparent to-gray-300"></div>
          </div>
          <p className="max-w-xl mx-auto text-gray-500 font-mono text-[10px] leading-relaxed uppercase tracking-widest">
            Enterprise-grade static analysis, heuristic clustering, and infrastructure mapping for modern threat landscapes. Isolated execution environment.
          </p>
        </motion.div>

        {/* UPLOAD MODULE */}
        <input type="file" ref={fileInputRef} onChange={handleFileChange} className="hidden" />
        <motion.div 
          style={{ y: yUpload }}
          whileHover={{ scale: 1.01 }}
          onClick={handleUploadClick}
          className={`group relative w-full max-w-xl h-40 bg-white border-2 border-[#121212] cursor-pointer overflow-hidden shadow-[0_20px_50px_rgba(0,0,0,0.1)] ${isUploading ? 'opacity-50 pointer-events-none' : ''}`}
        >
          <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/graphy.png')] opacity-[0.05]"></div>
          <div className="flex flex-col items-center justify-center h-full relative z-10">
             <UploadCloud className="w-8 h-8 text-[#121212] mb-4 group-hover:text-[#FF3B00] transition-colors" />
             <p className="font-bold text-lg tracking-tight text-[#121212]">DROP ARTIFACT FOR INGESTION</p>
             <p className="font-mono text-[10px] text-gray-400 mt-2">SUPPORTED: .EXE .DLL .APK .ELF .TXT AND MORE</p>
          </div>
          <div className="absolute top-0 h-full w-1 bg-[#FF3B00] opacity-50 group-hover:animate-scan"></div>
        </motion.div>

        {/* OR DIVIDER */}
        <div className="flex items-center w-full max-w-xl gap-4 my-2">
          <div className="flex-1 h-px bg-gray-300" />
          <span className="font-mono text-[10px] text-gray-400 tracking-widest">OR SUBMIT URL</span>
          <div className="flex-1 h-px bg-gray-300" />
        </div>

        {/* URL INPUT */}
        <div className="w-full max-w-xl">
          <div className="flex gap-0 border-2 border-[#121212] bg-white shadow-[0_10px_30px_rgba(0,0,0,0.08)] overflow-hidden">
            <input
              type="text"
              value={urlInput}
              onChange={e => { setUrlInput(e.target.value); setUrlError(null) }}
              onKeyDown={e => e.key === 'Enter' && handleUrlSubmit()}
              placeholder="https://suspicious-domain.com/payload"
              className="flex-1 px-4 py-3 font-mono text-xs text-[#121212] placeholder-gray-300 bg-transparent outline-none"
            />
            <button
              onClick={handleUrlSubmit}
              disabled={isSubmittingUrl}
              className="px-5 py-3 bg-[#121212] text-white font-mono text-[10px] tracking-widest uppercase hover:bg-[#FF3B00] transition-colors disabled:opacity-50 flex items-center gap-2"
            >
              <ArrowRight size={12} />
              {isSubmittingUrl ? "SCANNING..." : "SCAN URL"}
            </button>
          </div>
          {urlError && <p className="font-mono text-[10px] text-[#FF3B00] mt-2 tracking-wider">{urlError}</p>}
        </div>
      </main>
    </div>
  )
}