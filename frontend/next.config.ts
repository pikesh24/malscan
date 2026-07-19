import type { NextConfig } from "next";

// Capacitor packages this app as static HTML/JS with no Next.js server, so
// rewrites (which need a server) can't run — see lib/config.ts for how API
// calls are pointed at the backend directly in that build instead.
const isCapacitorBuild = process.env.BUILD_TARGET === "capacitor";

// Where the /api rewrite proxies to. Local dev defaults to the laptop backend
// (port 8000 is permanently occupied by Splunk on this machine — backend runs
// on 8001 instead). Hosted web deploys (e.g. Vercel) set BACKEND_ORIGIN to the
// cloud backend URL (e.g. https://malscan-api.onrender.com) so the browser
// stays same-origin and no CORS is needed.
const backendOrigin = process.env.BACKEND_ORIGIN || "http://127.0.0.1:8001";

const nextConfig: NextConfig = isCapacitorBuild
  ? {
      output: "export",
      images: { unoptimized: true },
    }
  : {
      async rewrites() {
        return [
          {
            source: "/api/:path*",
            destination: `${backendOrigin}/:path*`, // Proxy to FastAPI Backend
          },
        ];
      },
    };

export default nextConfig;
