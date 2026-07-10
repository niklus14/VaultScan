"use client";

/**
 * Google Cloud–style mark with shields revolving around it (sidebar brand).
 * Visual homage for a CSPM product — not an official Google asset.
 */
export function BrandCloud({ className = "" }: { className?: string }) {
  return (
    <div className={`gc-brand ${className}`} aria-hidden>
      {/* Orbit ring */}
      <div className="gc-orbit-ring" />

      {/* Revolving shields */}
      <div className="gc-orbit gc-orbit-1">
        <span className="gc-orbit-item">
          <ShieldIcon />
        </span>
      </div>
      <div className="gc-orbit gc-orbit-2">
        <span className="gc-orbit-item">
          <ShieldIcon />
        </span>
      </div>
      <div className="gc-orbit gc-orbit-3">
        <span className="gc-orbit-item">
          <ShieldIcon />
        </span>
      </div>

      {/* Center: Google Cloud style multi-color cloud */}
      <div className="gc-logo-core">
        <GoogleCloudMark />
      </div>
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" width="14" height="14" fill="none" aria-hidden>
      <path
        d="M12 2.5 L19 5.5 V11.5 C19 16.2 15.8 20.1 12 21.5 C8.2 20.1 5 16.2 5 11.5 V5.5 L12 2.5 Z"
        fill="#0b0c10"
        stroke="#00e676"
        strokeWidth="1.4"
        strokeLinejoin="round"
      />
      <path
        d="M9 12 L11 14 L15.5 9"
        stroke="#00e676"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Simplified multi-tone cloud inspired by Google Cloud logo geometry */
function GoogleCloudMark() {
  return (
    <svg
      className="gc-logo-svg"
      viewBox="0 0 192 144"
      xmlns="http://www.w3.org/2000/svg"
      role="img"
      aria-label="Cloud"
    >
      {/* Shadow */}
      <ellipse cx="96" cy="122" rx="52" ry="8" fill="rgba(56,116,255,0.2)" />

      {/* Right lobe — Google Blue */}
      <path
        d="M118 104c22 0 40-17.5 40-39 0-20.5-16-37.2-36.3-38.8C117.2 12.2 103.5 4 88 4 67.6 4 50.5 17.3 46.2 36.2 29.5 38.5 17 52.8 17 70c0 18.8 15.2 34 34 34h67z"
        fill="#4285F4"
      />
      {/* Left lower — Google Green accent */}
      <path
        d="M51 104c-14.4 0-26-11.6-26-26 0-12.8 9.3-23.5 21.5-25.5C50.8 39.8 63.2 30 78 30c6.2 0 12 1.7 17 4.7C90 25.2 79.5 18 67 18 48.3 18 33 32.8 32 51.2 18.5 54.2 8 66.5 8 81c0 16 13 29 29 29h14c0-2.1.2-4.1.6-6z"
        fill="#34A853"
        opacity="0.95"
      />
      {/* Top highlight lobe — lighter blue */}
      <path
        d="M96 28c12.7 0 24 6.2 31.2 15.8C140.5 40.2 152 50.5 152 64.5c0 2.2-.3 4.3-.7 6.3 4.2 3.8 6.7 9.3 6.7 15.4 0 1.4-.1 2.7-.4 4-5.5-10.2-16.2-17.2-28.6-17.2-1.8 0-3.5.2-5.2.5C119 56.2 108.5 45 96 45c-8.5 0-16.1 3.7-21.3 9.6 5.2-16.2 20.3-26.6 37.3-26.6z"
        fill="#669DF6"
      />
      {/* Yellow accent (Google yellow) — small edge */}
      <path
        d="M138 78c4.5 0 8.5 1.8 11.5 4.7 1.8-2.5 2.9-5.5 2.9-8.8 0-8.3-6.7-15-15-15-.9 0-1.8.1-2.6.2 1.2 2.2 1.9 4.6 2.2 7.2 0 .4 0 .8 0 1.2.3 3.5.5 7 .5 10.5h.5z"
        fill="#FBBC04"
      />
      {/* Red accent tip */}
      <path
        d="M44 72c0-3.2.7-6.2 1.9-9-7.2 3.2-12.2 10.3-12.2 18.7 0 5.2 2 9.9 5.2 13.4C36.2 89.5 34 82.2 34 74.5c0-12.5 8.2-23 19.5-26.5C48.2 55 44 63 44 72z"
        fill="#EA4335"
        opacity="0.9"
      />
    </svg>
  );
}
