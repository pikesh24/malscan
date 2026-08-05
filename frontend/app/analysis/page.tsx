"use client"

import { useState, useEffect, Suspense } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { motion } from "framer-motion"
import { apiUrl } from "../../lib/config"

// --- BACKGROUND PLACEHOLDER ---
const BackgroundMedia = () => (
  <div className="absolute inset-0 z-0 overflow-hidden pointer-events-none">
    <div className="absolute inset-0 bg-[#121212] opacity-90"></div>
    <div className="absolute inset-0 opacity-20" 
         style={{ backgroundImage: 'linear-gradient(rgba(255,59,0,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,59,0,0.1) 1px, transparent 1px)', backgroundSize: '30px 30px' }}>
    </div>
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
    <div className="h-screen bg-[#0A0A0A] text-white font-mono flex relative overflow-hidden">
      <BackgroundMedia />
      
      {/* MAIN CONTENT AREA */}
      <div className="flex-1 flex flex-col justify-center items-center relative z-10">
        <div className="w-full max-w-2xl px-6">
            <div className="flex justify-between items-end mb-8">
                <div>
                  <h2 className="text-xs font-bold tracking-widest text-[#666]">JOB ID</h2>
                  <p className="text-2xl text-[#FF3B00]">{id.toUpperCase()}</p>
                </div>
                <div className="text-right">
                  <h2 className="text-xs font-bold tracking-widest text-[#666]">STATUS</h2>
                  <p className="text-lg animate-pulse">{realStatus}</p>
                </div>
            </div>
            
            <div className="flex justify-between items-end mb-2">
                <p className="text-sm text-[#888]">Estimated time remaining: <span className="text-white font-semibold">{formatETA(etaSeconds)}</span></p>
                <p className="text-sm text-[#888]">Progress: <span className="text-[#FF3B00] font-bold">{Math.floor(progress)}%</span></p>
            </div>
            <div className="w-full h-2 bg-[#222] mb-12 relative overflow-hidden border border-[#333]">
                <motion.div className="absolute top-0 left-0 h-full bg-[#FF3B00]" style={{ width: `${progress}%` }} transition={{ ease: "linear" }} />
            </div>

            <div className="space-y-2 h-64 overflow-y-auto border border-[#333] p-4 bg-[#000]/50 backdrop-blur-sm">
                {steps.map((step, i) => (
                    <motion.div key={step} initial={{ opacity: 0, x: -10 }} animate={{ opacity: i === currentStep ? 1 : 0.4, x: 0, color: i === currentStep ? "#FFF" : "#666" }} className="flex items-center gap-3 text-xs tracking-wider">
                        <span className="w-4 text-[#FF3B00]">{i === currentStep ? ">" : i < currentStep ? "✓" : ""}</span><span>{step}</span>{i === currentStep && <span className="animate-blink">_</span>}
                    </motion.div>
                ))}
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