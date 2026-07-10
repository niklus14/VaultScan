"use client";

/**
 * Animated cloud mark for the sidebar — slow 3D turn + float.
 */
export function BrandCloud({ className = "" }: { className?: string }) {
  return (
    <div className={`brand-cloud-stage ${className}`} aria-hidden>
      <div className="brand-cloud-orbit">
        <svg
          className="brand-cloud-svg"
          viewBox="0 0 120 80"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          {/* Soft glow blobs */}
          <ellipse
            className="brand-cloud-glow"
            cx="60"
            cy="48"
            rx="42"
            ry="18"
            fill="url(#cloudGlow)"
          />
          {/* Main cloud body */}
          <path
            className="brand-cloud-body"
            d="M30 58c-9 0-16-6.5-16-14.5S21 29 30 29c1.2-8.5 8.5-15 17.5-15 7.2 0 13.5 4 16.2 9.8C66 21.2 70.5 19 75.5 19c9.1 0 16.5 7 16.5 15.6 0 1.1-.1 2.1-.3 3.1 7.2 1.6 12.3 7.8 12.3 15.3 0 8.6-7.2 15.5-16.1 15.5H30z"
            fill="url(#cloudFill)"
            stroke="url(#cloudStroke)"
            strokeWidth="1.5"
          />
          {/* Highlight edge */}
          <path
            d="M34 36c2.5-6 8-10 14.5-10 4 0 7.6 1.5 10.3 4"
            stroke="rgba(255,255,255,0.35)"
            strokeWidth="1.2"
            strokeLinecap="round"
            fill="none"
          />
          {/* Shield badge on cloud */}
          <g className="brand-cloud-shield" transform="translate(52 38)">
            <path
              d="M8 2 L14 5 V11 C14 15 11 18 8 19.5 C5 18 2 15 2 11 V5 Z"
              fill="#0b0c10"
              stroke="#3874ff"
              strokeWidth="1.2"
            />
            <path
              d="M5.5 11 L7.2 12.7 L11 8.5"
              stroke="#00e676"
              strokeWidth="1.3"
              strokeLinecap="round"
              strokeLinejoin="round"
              fill="none"
            />
          </g>
          <defs>
            <linearGradient id="cloudFill" x1="20" y1="20" x2="100" y2="70">
              <stop stopColor="#4d7cff" />
              <stop offset="0.55" stopColor="#3874ff" />
              <stop offset="1" stopColor="#1a4fd4" />
            </linearGradient>
            <linearGradient id="cloudStroke" x1="20" y1="20" x2="100" y2="70">
              <stop stopColor="#9bb6ff" stopOpacity="0.9" />
              <stop offset="1" stopColor="#3874ff" stopOpacity="0.4" />
            </linearGradient>
            <radialGradient id="cloudGlow" cx="50%" cy="50%" r="50%">
              <stop stopColor="#3874ff" stopOpacity="0.45" />
              <stop offset="1" stopColor="#3874ff" stopOpacity="0" />
            </radialGradient>
          </defs>
        </svg>
      </div>
      {/* Orbiting particle */}
      <span className="brand-cloud-spark brand-cloud-spark-a" />
      <span className="brand-cloud-spark brand-cloud-spark-b" />
    </div>
  );
}
