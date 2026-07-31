import { Network, MapPin, Camera, Mic, FileText, Phone, MessageSquare, Users, Settings, Lock } from "lucide-react"

export interface PermissionInfo {
  name: string
  description: string
  riskLevel: "high" | "medium" | "low"
  category: string
  icon: typeof Network
}

export const ANDROID_PERMISSIONS: Record<string, PermissionInfo> = {
  // Network & Communication
  INTERNET: {
    name: "Internet",
    description: "Connect to the internet. Can exfiltrate data to remote servers.",
    riskLevel: "high",
    category: "Network",
    icon: Network,
  },
  ACCESS_NETWORK_STATE: {
    name: "Network State",
    description: "Check network connectivity status and see which networks are available.",
    riskLevel: "low",
    category: "Network",
    icon: Network,
  },
  CHANGE_NETWORK_STATE: {
    name: "Change Network",
    description: "Modify network connectivity settings.",
    riskLevel: "medium",
    category: "Network",
    icon: Network,
  },

  // Location
  ACCESS_FINE_LOCATION: {
    name: "Precise Location",
    description: "Track your exact GPS location in real-time. High privacy concern.",
    riskLevel: "high",
    category: "Location",
    icon: MapPin,
  },
  ACCESS_COARSE_LOCATION: {
    name: "Approximate Location",
    description: "Track your approximate location using cellular/WiFi networks.",
    riskLevel: "medium",
    category: "Location",
    icon: MapPin,
  },

  // Camera & Sensors
  CAMERA: {
    name: "Camera",
    description: "Access the device camera to take photos/videos without permission.",
    riskLevel: "high",
    category: "Sensors",
    icon: Camera,
  },
  RECORD_AUDIO: {
    name: "Microphone",
    description: "Record audio without explicit user consent.",
    riskLevel: "high",
    category: "Sensors",
    icon: Mic,
  },

  // Contacts & Messages
  READ_CONTACTS: {
    name: "Read Contacts",
    description: "Access your contact list, email addresses, and phone numbers.",
    riskLevel: "high",
    category: "Contacts",
    icon: Users,
  },
  WRITE_CONTACTS: {
    name: "Write Contacts",
    description: "Modify or add contacts to your device.",
    riskLevel: "medium",
    category: "Contacts",
    icon: Users,
  },
  READ_SMS: {
    name: "Read Messages",
    description: "Access SMS messages, including sensitive 2FA codes.",
    riskLevel: "high",
    category: "Messages",
    icon: MessageSquare,
  },
  SEND_SMS: {
    name: "Send Messages",
    description: "Send SMS messages, potentially causing financial loss.",
    riskLevel: "high",
    category: "Messages",
    icon: MessageSquare,
  },
  READ_CALL_LOG: {
    name: "Read Call History",
    description: "Access your call history and phone numbers you've contacted.",
    riskLevel: "high",
    category: "Messages",
    icon: Phone,
  },

  // Files
  READ_EXTERNAL_STORAGE: {
    name: "Read Files",
    description: "Access photos, documents, and other files on your device.",
    riskLevel: "medium",
    category: "Files",
    icon: FileText,
  },
  WRITE_EXTERNAL_STORAGE: {
    name: "Write Files",
    description: "Create, modify, or delete files on your device.",
    riskLevel: "medium",
    category: "Files",
    icon: FileText,
  },

  // System
  CHANGE_SETTINGS: {
    name: "Change Settings",
    description: "Modify system settings and preferences.",
    riskLevel: "medium",
    category: "System",
    icon: Settings,
  },
  WRITE_SETTINGS: {
    name: "Write Settings",
    description: "Write to secure system settings.",
    riskLevel: "medium",
    category: "System",
    icon: Settings,
  },
  DUMP: {
    name: "Dump",
    description: "Low-level system debugging access.",
    riskLevel: "low",
    category: "System",
    icon: Lock,
  },
}

export function getPermissionInfo(permissionName: string): PermissionInfo {
  const key = permissionName.replace("android.permission.", "").toUpperCase()
  return (
    ANDROID_PERMISSIONS[key] || {
      name: permissionName.replace("android.permission.", ""),
      description: "Unknown permission",
      riskLevel: "low",
      category: "Other",
      icon: Lock,
    }
  )
}

export function categorizePermissions(permissions: string[]): Record<string, string[]> {
  const categorized: Record<string, string[]> = {}
  permissions.forEach((perm) => {
    const info = getPermissionInfo(perm)
    if (!categorized[info.category]) {
      categorized[info.category] = []
    }
    categorized[info.category].push(perm)
  })
  return categorized
}

export const RISK_COLORS = {
  high: "bg-red-50 border-red-200 text-red-700",
  medium: "bg-amber-50 border-amber-200 text-amber-700",
  low: "bg-green-50 border-green-200 text-green-700",
}

export const RISK_BADGE = {
  high: "bg-red-900 text-red-300",
  medium: "bg-amber-900 text-amber-300",
  low: "bg-green-900 text-green-300",
}
