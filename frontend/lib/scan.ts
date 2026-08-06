import { apiUrl } from "./config"

// "Backend offline or error" was the message for every failure, including the
// two the user can actually act on. The caller shows this text verbatim, so it
// needs to name the real cause.
function submissionError(status: number): Error {
  if (status === 413) return new Error("this file is larger than the 50 MB limit")
  if (status === 429) return new Error("too many scans in the last minute — wait a moment and retry")
  if (status === 0) return new Error("the scanner could not be reached")
  return new Error(`the scanner returned an error (HTTP ${status})`)
}

export async function submitFileForScan(file: File | Blob, filename = "scan_target"): Promise<string> {
  const formData = new FormData()
  formData.append("file", file, filename)
  const res = await fetch(apiUrl("/api/upload"), { method: "POST", body: formData })
  if (!res.ok) throw submissionError(res.status)
  const data = await res.json()
  return data.job_id
}

export async function submitUrlForScan(url: string): Promise<string> {
  const res = await fetch(apiUrl("/api/submit-url"), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  })
  if (!res.ok) throw submissionError(res.status)
  const data = await res.json()
  return data.job_id
}

export function looksLikeUrl(text: string): boolean {
  return /^https?:\/\//i.test(text.trim())
}

const MIME_BY_EXTENSION: Record<string, string> = {
  pdf: "application/pdf",
  apk: "application/vnd.android.package-archive",
  zip: "application/zip",
  exe: "application/x-msdownload",
  dll: "application/x-msdownload",
  doc: "application/msword",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  xls: "application/vnd.ms-excel",
  xlsx: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  ppt: "application/vnd.ms-powerpoint",
  pptx: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  rtf: "application/rtf",
  rar: "application/x-rar-compressed",
  "7z": "application/x-7z-compressed",
  txt: "text/plain",
}

export function guessMimeFromName(name: string): string {
  const ext = name.split(".").pop()?.toLowerCase() || ""
  return MIME_BY_EXTENSION[ext] || "application/octet-stream"
}
