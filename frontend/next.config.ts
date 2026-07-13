import type { NextConfig } from "next"
import path from "path"

/**
 * Backend origin for /api/* rewrites.
 * Local: http://127.0.0.1:8000
 * Vercel: set VAULTSCAN_API_ORIGIN to your deployed FastAPI URL
 *         (e.g. https://vaultscan-api.example.com)
 */
const API_ORIGIN = (
  process.env.VAULTSCAN_API_ORIGIN ?? "http://127.0.0.1:8000"
).replace(/\/$/, "")

const nextConfig: NextConfig = {
  // Pin file tracing to this app (avoids parent lockfile confusion on Vercel)
  outputFileTracingRoot: path.resolve(process.cwd()),

  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },

  // Local dev: proxy /api → FastAPI. On Vercel multi-service, root vercel.json
  // routes /api to the backend service — do NOT rewrite to localhost.
  async rewrites() {
    if (process.env.VERCEL) {
      return []
    }
    return [
      {
        source: "/api/:path*",
        destination: `${API_ORIGIN}/api/:path*`,
      },
    ]
  },

  async headers() {
    return [
      {
        source: "/(.*)",
        headers: [
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        ],
      },
    ]
  },
}

export default nextConfig
