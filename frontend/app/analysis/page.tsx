"use client"

import { useState, useEffect, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { motion } from "framer-motion"
import { apiUrl } from "../../lib/config"

// --- BACKGROUND PLACEHOLDER ---
const BackgroundMedia = () => (
  <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
    <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,_var(--tw-gradient-stops))] from-gray-200 via-[#F5F5F3] to-[#F5F5F3] opacity-50"></div>
    <div className="absolute inset-0 bg-[url('https://www.transparenttextures.com/patterns/graphy.png')] opacity-[0.05]"></div>
  </div>
)

function AnalysisContent() {
  const router = useRouter()
  const searchParams = useSearchParams()
  const id = searchParams.get("id") || "job-demo-8x9921"
  // Present only when this scan came from the default-browser link interceptor.
  const target = searchParams.get("target")
  // Present only when this scan came from a native file intent (share sheet
  // or "Open with") — lets the report offer an "Open File" action.
  const fileUri = searchParams.get("fileUri")
  const mimeType = searchParams.get("mimeType")

  const [progress, setProgress] = useState(0)
  const [realStatus, setRealStatus] = useState("SUBMITTED")

  // These mirror the real pipeline in backend/app/main.py (stages 1 to 7). They
  // previously named an isolated sandbox, an artifact volume, API import
  // reconstruction and passive-DNS clusters — none of which Malscan has. A
  // scanner that overstates what it did on the way to a verdict has no standing
  // to be believed about the verdict, so the list stays tied to the code.
  const steps = [
    "CALCULATING_HASHES (SHA256/MD5)", "DETECTING_FILE_TYPE (magic bytes)",
    "EXTRACTING_ARCHIVE_MEMBERS", "ANALYSING_FORMAT (APK/OFFICE/PDF/LNK)",
    "EXTRACTING_STRINGS & INDICATORS", "YARA_RULE_MATCHING",
    "QUERYING_THREAT_INTELLIGENCE", "CLUSTERING_SHARED_INFRASTRUCTURE",
    "SCORING & GENERATING_VERDICT"
  ]
  const [currentStep, setCurrentStep] = useState(0)

  // Real Polling mixed with visual progression
  useEffect(() => {
    let targetProgress = 10;
    let increment = 0.5; // Start with decent speed
    
    const visualInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= targetProgress) return targetProgress;
        return prev + increment;
      })
    }, 50)

    if (id.includes('demo')) {
       targetProgress = 100;
       return () => clearInterval(visualInterval)
    }

    const pollInterval = setInterval(async () => {
        try {
            const res = await fetch(apiUrl(`/api/status/${id}`))
            if (res.ok) {
                const data = await res.json()
                if (data.status === 'Completed' || data.status === 'Failed') {
                    setRealStatus(data.status === 'Failed' ? 'FAILED' : 'FINALIZING')
                    targetProgress = 100;
                    increment = 2.0; // Fast finish once completed
                } else if (data.status === 'Processing') {
                    setRealStatus('PROCESSING')
                    targetProgress = 95;
                    increment = 0.15; // Slow crawl through processing to prevent freezing
                } else if (data.status === 'Submitted') {
                    setRealStatus('QUEUED')
                    targetProgress = 20;
                    increment = 0.5;
                }
            }
        } catch (e) {
            // Ignore for robust polling
        }
    }, 2000)

    return () => {
        clearInterval(visualInterval)
        clearInterval(pollInterval)
    }
  }, [id])

  // Watch progress for navigation
  useEffect(() => {
    if (progress >= 100) {
      const params = new URLSearchParams({ id })
      if (target) params.set("target", target)
      if (fileUri) params.set("fileUri", fileUri)
      if (mimeType) params.set("mimeType", mimeType)
      router.push(`/report?${params.toString()}`)
    }
  }, [progress, router, id, target, fileUri, mimeType])

  // Update current step text based on progress
  useEffect(() => {
    setCurrentStep(Math.min(Math.floor((progress / 100) * steps.length), steps.length - 1))
  }, [progress, steps.length])

  // Calculate ETA (assuming ~45 seconds total for a scan)
  const etaSeconds = Math.max(0, Math.round(45 * (1 - progress / 100)));
  const formatETA = (seconds: number) => {
      const m = Math.floor(seconds / 60);
      const s = seconds % 60;
      return `${m}:${s.toString().padStart(2, '0')}`;
  };

  return (
    <div className="h-screen bg-[#F5F5F3] text-[#121212] font-sans flex relative overflow-hidden selection:bg-[#FF3B00] selection:text-white">
      <BackgroundMedia />
      
      {/* MAIN CONTENT AREA */}
      <div className="flex-1 overflow-y-auto relative z-10">
        <div className="min-h-full flex flex-col justify-center items-center py-12">
            <div className="w-full max-w-4xl px-4 md:px-8">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4 md:gap-0 mb-8">
                    <div className="max-w-full overflow-hidden w-full md:w-auto">
                      <h2 className="text-[10px] font-bold tracking-[0.3em] uppercase text-gray-500 mb-1">JOB ID</h2>
                      <p className="text-xl sm:text-2xl md:text-3xl font-black text-[#121212] tracking-tight truncate">{id.toUpperCase()}</p>
                    </div>
                    <div className="text-left md:text-right shrink-0">
                      <h2 className="text-[10px] font-bold tracking-[0.3em] uppercase text-gray-500 mb-1">STATUS</h2>
                      <p className="text-xl font-bold text-[#FF3B00] animate-pulse">{realStatus}</p>
                    </div>
                </div>
            
            <div className="flex justify-between items-end mb-3">
                <p className="font-mono text-[10px] text-gray-400 tracking-widest uppercase">EST. TIME: <span className="text-[#121212] font-bold">{formatETA(etaSeconds)}</span></p>
                <p className="font-mono text-[10px] text-gray-400 tracking-widest uppercase">PROGRESS: <span className="text-[#121212] font-bold">{Math.floor(progress)}%</span></p>
            </div>
            <div className="w-full h-4 bg-white border-2 border-[#121212] mb-12 relative overflow-hidden shadow-[0_10px_20px_rgba(0,0,0,0.05)]">
                <motion.div 
                    className="absolute top-0 left-0 h-full bg-[#FF3B00]" 
                    style={{ width: `${progress}%` }} 
                    transition={{ ease: "linear" }} 
                />
            </div>

            <div className="space-y-0 bg-white border-2 border-[#121212] shadow-[0_20px_50px_rgba(0,0,0,0.1)]">
                {steps.map((step, i) => (
                    <motion.div 
                        key={step} 
                        initial={{ opacity: 0, y: 10 }} 
                        animate={{ 
                            opacity: i <= currentStep ? 1 : 0.4, 
                            y: 0,
                            backgroundColor: i === currentStep ? "#F9F9F9" : "transparent"
                        }} 
                        className={`flex items-center gap-3 md:gap-4 px-4 py-3 md:px-6 md:py-4 border-b border-gray-100 last:border-b-0 transition-colors ${i === currentStep ? 'border-l-4 border-l-[#FF3B00]' : 'border-l-4 border-l-transparent'}`}
                    >
                        <div className="w-4 flex justify-center">
                            {i < currentStep ? (
                                <span className="text-[#121212] font-bold">✓</span>
                            ) : i === currentStep ? (
                                <span className="w-2 h-2 bg-[#FF3B00] rounded-sm animate-pulse"></span>
                            ) : (
                                <span className="text-gray-300">-</span>
                            )}
                        </div>
                        <span className={`font-mono text-xs tracking-widest uppercase ${i === currentStep ? "text-[#121212] font-bold" : "text-gray-500"}`}>{step}</span>
                    </motion.div>
                ))}
            </div>
        </div>
      </div>
    </div>
  </div>
  )
}

export default function AnalysisPage() {
  return (
    <Suspense fallback={null}>
      <AnalysisContent />
    </Suspense>
  )
}