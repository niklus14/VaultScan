import type { NextConfig } from "next"

const API_ORIGIN = process.env.VAULTSCAN_API_ORIGIN ?? "http://127.0.0.1:8000"

const nextConfig: NextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_ORIGIN}/api/:path*`,
      },
    ]
  },
}

export default nextConfig

