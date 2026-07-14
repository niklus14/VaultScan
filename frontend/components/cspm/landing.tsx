"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import {
  motion,
  AnimatePresence,
  useInView,
  useMotionValue,
  useSpring,
} from "motion/react";
import { Menu, X } from "lucide-react";
import { cn } from "@/lib/utils";

/* ─── JARVIS tokens ───────────────────────────────────────────────────────── */
const C = {
  bg: "#050505",
  border: "#1e1e1e",
  text: "#f2ede6",
  mute: "#5a5a5a",
  dim: "#3a3a3a",
  blue: "#2196f3",
  blueHot: "#42a5f5",
  green: "#22c55e",
  amber: "#f59e0b",
};

/** Hero rotating middle line — same pattern as JARVIS: ORCHESTRATE / REASON / PLAN / EXECUTE / ADAPT */
const HERO_WORDS = ["SCAN", "DETECT", "EXPOSE", "PRIORITIZE", "PROVE"] as const;

const NAV = [
  { href: "#features", label: "CAPABILITIES", n: "01" },
  { href: "#impact", label: "IMPACT", n: "02" },
  { href: "#pipeline", label: "PIPELINE", n: "03" },
  { href: "#metrics", label: "METRICS", n: "04" },
  { href: "#coverage", label: "COVERAGE", n: "05" },
  { href: "#trust", label: "TRUST", n: "06" },
  { href: "#why", label: "WHY US", n: "07" },
];

const MARQUEE = [
  "PUBLIC S3 DETECTION",
  "IAM LEAST-PRIVILEGE",
  "ATTACK PATH MAPPING",
  "CIS / NIST / GDPR",
  "ASSUME ROLE SAFE",
  "PDF · WORD EXPORTS",
  "CLOUD ASSISTANT",
  "ZERO WRITE ACCESS",
];

const CAPABILITIES = [
  {
    n: "01",
    tag: "DETECTION",
    title: "MISCONFIG\nENGINE",
    desc: "Deterministic rules across S3, IAM, EC2, RDS, KMS, SQS, and Secrets Manager. Evidence from live AWS APIs — not checkbox theater.",
    metric: "10+",
    metricLabel: "lab rule families",
  },
  {
    n: "02",
    tag: "NARRATIVE",
    title: "ATTACK\nPATHS",
    desc: "See how issues chain into breach outcomes — public storage, wildcard trust, privilege escalation, exposed messaging.",
    metric: "KILL",
    metricLabel: "chain storytelling",
  },
  {
    n: "03",
    tag: "ASSISTANT",
    title: "CLOUD\nASSISTANT",
    desc: "Ask questions on your last scan. Plain-language risk for managers, CLI fixes for engineers — grounded in findings.",
    metric: "AI",
    metricLabel: "scan-aware replies",
  },
  {
    n: "04",
    tag: "EVIDENCE",
    title: "BOARD\nREPORTS",
    desc: "Executive brief, severity charts, findings tables. Export PDF & Word in one click for auditors and leadership.",
    metric: "PDF",
    metricLabel: "+ Word packages",
  },
];

const IMPACT = [
  {
    v: "$4.88M",
    l: "AVG BREACH COST",
    d: "Industry benchmark total cost of a data breach — incident response, legal, downtime, and brand damage stack fast.",
  },
  {
    v: "23%+",
    l: "CLOUD MISCONFIG",
    d: "A large share of cloud breaches start with a wrong setting — public buckets, open ports, over-privileged roles.",
  },
  {
    v: "200d",
    l: "DWELL TIME",
    d: "Silent exposure often sits undetected for months. Attackers bill you long before the invoice shows up.",
  },
  {
    v: "10×",
    l: "COST IF LATE",
    d: "Finding it yourself is cheap. Finding it via ransomware, fines, or customer loss is not.",
  },
];

const MONEY = [
  {
    tag: "STORAGE",
    t: "Public cloud data",
    d: "Open S3 policies leak PII and backups — GDPR/CCPA fines plus class-action exposure.",
  },
  {
    tag: "IDENTITY",
    t: "Admin IAM & trust *",
    d: "One stolen key + AdministratorAccess = full account takeover and crypto-mining bills.",
  },
  {
    tag: "NETWORK",
    t: "World-open admin ports",
    d: "SSH/RDP to 0.0.0.0/0 invites brute force; IMDSv1 turns SSRF into role theft.",
  },
  {
    tag: "SECRETS",
    t: "Blind SOC & loose secrets",
    d: "CloudTrail kill rights and broad secret policies erase your flight recorder.",
  },
];

const STEPS = [
  {
    n: "01",
    tag: "CONNECT",
    t: "LINK THE CLOUD",
    d: "AssumeRole or read-only keys — or Demo mode with zero credentials.",
    code: `// Settings → Cloud Connection
auth_mode: "assume_role"
role_arn: "arn:aws:iam::…:role/ReadOnly"
// VaultScan never needs write access`,
  },
  {
    n: "02",
    tag: "SCAN",
    t: "RUN THE ENGINE",
    d: "Inventory configs and evaluate the full misconfiguration pack (lab Steps 1–10).",
    code: `POST /api/scan
→ S3 · IAM · EC2 · KMS · SQS · Secrets
→ findings[] + attack_paths[]
→ posture score 0–100`,
  },
  {
    n: "03",
    tag: "PROVE",
    t: "EXPORT & FIX",
    d: "Prioritize criticals, follow remediations, export PDF/Word, re-scan the trend.",
    code: `GET /api/report/export/pdf
// Board package with charts
// + Cloud Assistant narrative`,
  },
];

const COVERAGE = [
  ["S3", "Public ACL/policy · BPA · encryption · versioning"],
  ["IAM", "Admin · MFA · trust * · CloudTrail kill · priv-esc"],
  ["EC2", "0.0.0.0/0 ports · IMDSv1 · EBS encryption"],
  ["KMS", "CMK policy Principal *"],
  ["SQS", "Public queue resource policies"],
  ["SECRETS", "Public / root-broad resource policies"],
  ["RDS", "Public DB · encryption · backups"],
  ["PATHS", "Multi-step kill chains for stakeholders"],
];

const WHY = [
  {
    n: "01",
    t: "Real APIs, real evidence",
    d: "Every finding ties back to live cloud configuration you can open in the AWS console.",
  },
  {
    n: "02",
    t: "Lab-proven rules (1–10)",
    d: "Built against intentional misconfigs so you can validate detection before production.",
  },
  {
    n: "03",
    t: "Two audiences, one console",
    d: "Posture & compliance for managers. Attack paths & CLI fixes for engineers.",
  },
  {
    n: "04",
    t: "Least privilege always",
    d: "AssumeRole + read-only. Demo mode when you cannot touch live accounts yet.",
  },
];

const TRUST = [
  {
    n: "01",
    tag: "ACCESS",
    t: "READ-ONLY BY DEFAULT",
    d: "Scanning never mutates resources. Connect with short-lived role credentials.",
  },
  {
    n: "02",
    tag: "SECRETS",
    t: "SERVER-SIDE ONLY",
    d: "Keys stay on the API host — never embedded in the browser bundle.",
  },
  {
    n: "03",
    tag: "MAP",
    t: "COMPLIANCE TAGS",
    d: "Findings mapped to CIS AWS, NIST SP 800-53, and GDPR security controls.",
  },
  {
    n: "04",
    tag: "DEMO",
    t: "SAFE TRAINING MODE",
    d: "Full UI and reports without live cloud risk for workshops and demos.",
  },
];

/* ─── hooks / primitives ──────────────────────────────────────────────────── */

function useUtcClock() {
  const [t, setT] = useState("");
  useEffect(() => {
    const tick = () =>
      setT(new Date().toISOString().replace("T", " ").slice(0, 19) + "Z");
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return t;
}

function Fade({
  children,
  className,
  delay = 0,
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-60px" });
  return (
    <motion.div
      ref={ref}
      className={className}
      initial={{ opacity: 0, y: 32 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.65, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

function SysTag({ children }: { children: React.ReactNode }) {
  return (
    <span className="mb-4 block font-mono text-[10px] tracking-[0.22em] text-[#2196f3]">
      {children}
    </span>
  );
}

/** Giant rotating word — JARVIS hero middle line */
function RotatingWord({ words }: { words: readonly string[] }) {
  const [i, setI] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setI((v) => (v + 1) % words.length), 2200);
    return () => clearInterval(id);
  }, [words.length]);

  return (
    <div className="relative overflow-hidden h-[clamp(2.75rem,9vw,7.25rem)] leading-[0.88]">
      <AnimatePresence mode="wait">
        <motion.h1
          key={words[i]}
          className="font-display absolute inset-0 text-[clamp(2.75rem,9vw,7.25rem)] font-bold uppercase leading-[0.88] tracking-tight text-[#2196f3]"
          style={{ fontFamily: "var(--font-space-grotesk), system-ui, sans-serif" }}
          initial={{ y: "110%", opacity: 0 }}
          animate={{ y: "0%", opacity: 1 }}
          exit={{ y: "-110%", opacity: 0 }}
          transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
        >
          {words[i]}
        </motion.h1>
      </AnimatePresence>
      {/* reserve space so layout doesn't jump */}
      <h1
        className="invisible text-[clamp(2.75rem,9vw,7.25rem)] font-bold uppercase leading-[0.88]"
        aria-hidden
      >
        {words.reduce((a, b) => (a.length >= b.length ? a : b))}
      </h1>
    </div>
  );
}

function HeroCanvas() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    let raf = 0;
    let w = 0;
    let h = 0;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    type P = { x: number; y: number; vx: number; vy: number };
    let pts: P[] = [];

    const resize = () => {
      const parent = canvas.parentElement;
      if (!parent) return;
      w = parent.clientWidth;
      h = parent.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const n = Math.floor((w * h) / 12000);
      pts = Array.from({ length: Math.max(32, Math.min(n, 80)) }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.4,
        vy: (Math.random() - 0.5) * 0.4,
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      const g = ctx.createRadialGradient(
        w * 0.72,
        h * 0.42,
        0,
        w * 0.72,
        h * 0.42,
        w * 0.5,
      );
      g.addColorStop(0, "rgba(33,150,243,0.1)");
      g.addColorStop(1, "rgba(33,150,243,0)");
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);

      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }
      const link = Math.min(w, h) * 0.16;
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const a = pts[i];
          const b = pts[j];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < link) {
            ctx.strokeStyle = `rgba(33,150,243,${(1 - d / link) * 0.32})`;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }
      for (const p of pts) {
        ctx.fillStyle = "rgba(33,150,243,0.9)";
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.5, 0, Math.PI * 2);
        ctx.fill();
      }
      const t = (performance.now() / 35) % (h + 60);
      const lg = ctx.createLinearGradient(0, t - 30, 0, t + 30);
      lg.addColorStop(0, "rgba(33,150,243,0)");
      lg.addColorStop(0.5, "rgba(33,150,243,0.15)");
      lg.addColorStop(1, "rgba(33,150,243,0)");
      ctx.fillStyle = lg;
      ctx.fillRect(0, t - 30, w, 60);
      raf = requestAnimationFrame(draw);
    };

    resize();
    draw();
    window.addEventListener("resize", resize);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
    };
  }, []);
  return <canvas ref={ref} className="h-full w-full" aria-hidden />;
}

function MagneticCta({
  children,
  onClick,
  variant = "primary",
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  variant?: "primary" | "ghost";
  className?: string;
}) {
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 240, damping: 18 });
  const sy = useSpring(y, { stiffness: 240, damping: 18 });
  return (
    <motion.button
      type="button"
      onClick={onClick}
      style={{ x: sx, y: sy }}
      onMouseMove={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        x.set((e.clientX - r.left - r.width / 2) * 0.2);
        y.set((e.clientY - r.top - r.height / 2) * 0.2);
      }}
      onMouseLeave={() => {
        x.set(0);
        y.set(0);
      }}
      whileTap={{ scale: 0.98 }}
      className={cn(
        "group inline-flex items-center gap-6 whitespace-nowrap px-6 py-4 font-mono text-sm font-semibold tracking-widest transition-colors",
        variant === "primary"
          ? "bg-[#2196f3] text-[#050505] hover:bg-[#42a5f5]"
          : "border border-[#1e1e1e] text-[#f2ede6] hover:border-[#2196f3]/40 hover:text-[#2196f3]",
        className,
      )}
    >
      {children}
    </motion.button>
  );
}

function CountUp({ to, suffix = "" }: { to: number; suffix?: string }) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true });
  const [v, setV] = useState(0);
  useEffect(() => {
    if (!inView) return;
    const start = performance.now();
    const dur = 1400;
    let raf = 0;
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / dur);
      const eased = 1 - Math.pow(1 - p, 3);
      setV(Math.round(to * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, to]);
  return (
    <span ref={ref}>
      {v.toLocaleString()}
      {suffix}
    </span>
  );
}

/* ─── page ────────────────────────────────────────────────────────────────── */

export function Landing({ onEnter }: { onEnter: () => void }) {
  const utc = useUtcClock();
  const [menu, setMenu] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [step, setStep] = useState(0);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 8);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  useEffect(() => {
    const id = setInterval(() => setStep((s) => (s + 1) % STEPS.length), 5000);
    return () => clearInterval(id);
  }, []);

  const go = useCallback(() => {
    setMenu(false);
    onEnter();
  }, [onEnter]);

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-[#050505] text-[#f2ede6] antialiased">
      {/* ── Header ───────────────────────────────────────────────────────── */}
      <header
        className={cn(
          "fixed inset-x-0 top-0 z-50 transition-all duration-300",
          scrolled ? "bg-[#050505]/95 backdrop-blur-md" : "bg-transparent",
        )}
      >
        <div className="flex h-8 items-center justify-between border-b border-[#1e1e1e] px-6 lg:px-12">
          <span className="font-mono text-[10px] uppercase tracking-widest text-[#3a3a3a]">
            SYS:VAULTSCAN-OS &nbsp;/&nbsp; BUILD 2026.07
          </span>
          <div className="hidden items-center gap-6 md:flex">
            <span className="font-mono text-[10px] text-[#3a3a3a]">
              <span className="text-[#22c55e]">●</span>
              &nbsp;ALL_SYSTEMS_NOMINAL
            </span>
            <span className="font-mono text-[10px] tabular-nums text-[#3a3a3a]">
              {utc}
            </span>
          </div>
        </div>
        <div className="flex h-14 items-center justify-between px-6 lg:px-12">
          <a href="#" className="group flex items-center gap-3">
            <div className="relative flex h-7 w-7 items-center justify-center border border-[#2196f3]">
              <div className="h-2 w-2 bg-[#2196f3]" />
              <div className="absolute inset-0 bg-[#2196f3]/10 transition-colors group-hover:bg-[#2196f3]/20" />
            </div>
            <span
              className="text-2xl tracking-[0.15em] text-[#f2ede6]"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              VAULTSCAN
            </span>
            <span className="ml-1 hidden border-l border-[#1e1e1e] pl-3 font-mono text-[10px] tracking-widest text-[#3a3a3a] lg:block">
              CSPM
            </span>
          </a>
          <nav className="hidden items-center gap-7 lg:flex">
            {NAV.map((n) => (
              <a
                key={n.href}
                href={n.href}
                className="font-mono text-[11px] tracking-[0.18em] text-[#5a5a5a] transition-colors duration-200 hover:text-[#2196f3]"
              >
                {n.label}
              </a>
            ))}
          </nav>
          <div className="hidden items-center gap-4 md:flex">
            <button
              type="button"
              onClick={go}
              className="font-mono text-[11px] tracking-widest text-[#5a5a5a] transition-colors hover:text-[#f2ede6]"
            >
              CONSOLE
            </button>
            <button
              type="button"
              onClick={go}
              className="flex h-9 items-center bg-[#2196f3] px-5 font-mono text-[11px] font-semibold tracking-widest text-[#050505] transition-colors hover:bg-[#42a5f5]"
            >
              LAUNCH_SCAN →
            </button>
          </div>
          <button
            type="button"
            className="p-1 text-[#f2ede6] lg:hidden"
            aria-label="Menu"
            onClick={() => setMenu((v) => !v)}
          >
            {menu ? <X className="size-5" /> : <Menu className="size-5" />}
          </button>
        </div>
      </header>

      {/* Mobile */}
      <div
        className={cn(
          "fixed inset-0 z-40 flex flex-col bg-[#050505] transition-opacity duration-300 lg:hidden",
          menu ? "pointer-events-auto opacity-100" : "pointer-events-none opacity-0",
        )}
        style={{ paddingTop: 88 }}
      >
        <div className="flex flex-col border-t border-[#1e1e1e]">
          {NAV.map((n) => (
            <a
              key={n.href}
              href={n.href}
              onClick={() => setMenu(false)}
              className="flex items-center justify-between border-b border-[#1e1e1e] px-8 py-6 text-3xl tracking-wider text-[#f2ede6] transition-colors hover:text-[#2196f3]"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              {n.label}
              <span className="font-mono text-xs text-[#3a3a3a]">{n.n}</span>
            </a>
          ))}
        </div>
        <div className="mt-auto border-t border-[#1e1e1e] p-8">
          <button
            type="button"
            onClick={go}
            className="block w-full bg-[#2196f3] py-5 text-center font-mono text-sm font-semibold tracking-widest text-[#050505]"
          >
            LAUNCH_SCAN →
          </button>
        </div>
      </div>

      {/* ── HERO (JARVIS structure) ───────────────────────────────────────── */}
      <section className="relative flex min-h-screen flex-col justify-center overflow-hidden pt-[88px] grid-bg-jarvis">
        <div className="pointer-events-none absolute inset-y-0 right-0 z-0 w-full lg:w-[55%]">
          <HeroCanvas />
        </div>
        <div
          className="pointer-events-none absolute inset-0 z-0"
          style={{
            background:
              "radial-gradient(ellipse 50% 60% at 80% 50%, rgba(33,150,243,0.06) 0%, transparent 70%)",
          }}
        />

        <div className="relative z-20 mx-auto w-full max-w-[1400px] px-6 py-16 lg:px-12 lg:py-24">
          <motion.div
            initial={{ opacity: 0, y: 24 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
          >
            <p className="mb-4 font-mono text-[11px] tracking-[0.2em] text-[#2196f3]">
              — VAULTSCAN v1.3 · CLOUD SECURITY POSTURE
            </p>

            {/* Three-line hero with rotating middle — THE impact piece */}
            <h1
              className="text-[clamp(2.75rem,9vw,7.25rem)] font-bold uppercase leading-[0.88] tracking-tight text-[#f2ede6]"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              CLOUDS THAT
            </h1>
            <RotatingWord words={HERO_WORDS} />
            <h1
              className="text-[clamp(2.75rem,9vw,7.25rem)] font-bold uppercase leading-[0.88] tracking-tight text-[#f2ede6]"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              THEMSELVES
            </h1>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25, duration: 0.65 }}
            className="mt-12 max-w-xl"
          >
            <p className="text-base leading-relaxed text-[#5a5a5a]">
              Misconfigurations empty bank accounts — public storage, admin IAM,
              open ports, exposed secrets. VaultScan detects them on real AWS
              APIs, maps attack paths, and ships board-ready reports before
              attackers (or auditors) do.
            </p>
            <div className="mt-8 flex w-fit flex-col gap-3 sm:flex-row">
              <MagneticCta onClick={go} variant="primary">
                LAUNCH CONSOLE
                <span className="transition-transform group-hover:translate-x-1">
                  →
                </span>
              </MagneticCta>
              <MagneticCta
                onClick={() =>
                  document.getElementById("impact")?.scrollIntoView({
                    behavior: "smooth",
                  })
                }
                variant="ghost"
              >
                SEE THE COST
                <span className="transition-transform group-hover:translate-x-1">
                  →
                </span>
              </MagneticCta>
            </div>
            <div className="mt-5 flex items-center gap-3">
              <div className="flex -space-x-2">
                {["#3b82f6", "#a855f7", "#ec4899", "#2196f3"].map((c) => (
                  <div
                    key={c}
                    className="h-6 w-6 rounded-full border border-[#050505]"
                    style={{ background: c }}
                  />
                ))}
              </div>
              <span className="font-mono text-[10px] text-[#3a3a3a]">
                Built for validation labs · portfolio CSPM · real AWS scans
              </span>
            </div>
          </motion.div>
        </div>

        {/* Bottom marquee */}
        <div className="absolute bottom-0 left-0 right-0 border-t border-[#1e1e1e] py-5">
          <div className="overflow-hidden">
            <div className="vs-marquee flex whitespace-nowrap">
              {[0, 1].map((copy) => (
                <span key={copy} className="inline-flex items-center gap-16 px-8">
                  {MARQUEE.map((m) => (
                    <span
                      key={`${copy}-${m}`}
                      className="inline-flex items-center gap-3 font-mono text-[10px] tracking-[0.2em] text-[#3a3a3a]"
                    >
                      <span className="inline-block h-1 w-1 shrink-0 bg-[#2196f3]" />
                      {m}
                    </span>
                  ))}
                </span>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ── CAPABILITIES (JARVIS row grid) ────────────────────────────────── */}
      <section id="features" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px] px-0 lg:px-0">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e] lg:grid-cols-[56px_260px_1fr_160px]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="col-span-1 flex flex-col justify-between gap-4 p-6 lg:col-span-3 lg:flex-row lg:items-end">
              <div>
                <SysTag>CAPABILITIES</SysTag>
                <h2
                  className="text-5xl leading-[0.88] tracking-tight text-[#f2ede6] lg:text-7xl"
                  style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                >
                  WHAT VAULTSCAN
                  <br />
                  <span
                    className="text-transparent"
                    style={{ WebkitTextStroke: "1px #3a3a3a" }}
                  >
                    CAN DO
                  </span>
                </h2>
              </div>
              <p className="hidden max-w-[200px] text-right font-mono text-[10px] tracking-widest text-[#3a3a3a] lg:block">
                FOUR CORE MODULES &nbsp;/&nbsp; LAB-PROVEN &nbsp;/&nbsp;
                PRODUCTION-READY
              </p>
            </div>
          </Fade>

          {CAPABILITIES.map((c, i) => (
            <Fade key={c.n} delay={i * 0.05}>
              <div className="group border-b border-[#1e1e1e] transition-colors hover:bg-[#080808]">
                <div className="grid grid-cols-[56px_1fr] gap-0 lg:grid-cols-[56px_260px_1fr_160px]">
                  <div className="flex items-start border-r border-[#1e1e1e] p-5 pt-6">
                    <span className="font-mono text-[10px] tracking-widest text-[#3a3a3a]">
                      {c.n}
                    </span>
                  </div>
                  <div className="flex flex-col gap-3 border-r border-[#1e1e1e] p-6">
                    <span className="font-mono text-[9px] tracking-[0.2em] text-[#2196f3]">
                      {c.tag}
                    </span>
                    <h3
                      className="whitespace-pre-line text-3xl leading-[0.9] text-[#f2ede6] transition-colors duration-300 group-hover:text-[#2196f3] lg:text-4xl"
                      style={{
                        fontFamily: "var(--font-space-grotesk), system-ui",
                      }}
                    >
                      {c.title}
                    </h3>
                  </div>
                  <div className="border-r border-[#1e1e1e] p-6">
                    <p className="max-w-xl text-sm leading-relaxed text-[#5a5a5a]">
                      {c.desc}
                    </p>
                  </div>
                  <div className="hidden flex-col justify-center p-6 lg:flex">
                    <p className="font-mono text-2xl font-bold text-[#f2ede6]">
                      {c.metric}
                    </p>
                    <p className="mt-1 font-mono text-[10px] tracking-widest text-[#3a3a3a]">
                      {c.metricLabel.toUpperCase()}
                    </p>
                  </div>
                </div>
              </div>
            </Fade>
          ))}
        </div>
      </section>

      {/* ── IMPACT ───────────────────────────────────────────────────────── */}
      <section id="impact" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e] lg:grid-cols-[56px_1fr]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="p-6 lg:p-10">
              <SysTag>BUSINESS_IMPACT</SysTag>
              <h2
                className="max-w-3xl text-5xl leading-[0.9] tracking-tight lg:text-7xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                MISCONFIGS
                <br />
                <span
                  className="text-transparent"
                  style={{ WebkitTextStroke: "1px #3a3a3a" }}
                >
                  BURN CASH
                </span>
              </h2>
              <p className="mt-5 max-w-2xl text-sm leading-relaxed text-[#5a5a5a]">
                Most cloud breaches start with a setting left open — not a
                zero-day. The bill arrives as incident response, legal, fines,
                churn, and months of SOC overtime.
              </p>
            </div>
          </Fade>

          <div className="grid border-b border-[#1e1e1e] sm:grid-cols-2 lg:grid-cols-4">
            {IMPACT.map((s, i) => (
              <Fade key={s.l} delay={i * 0.06}>
                <div className="h-full border-b border-r border-[#1e1e1e] p-7 sm:border-b-0">
                  <p className="font-mono text-4xl font-bold tracking-tight text-[#2196f3]">
                    {s.v}
                  </p>
                  <p className="mt-2 font-mono text-[11px] font-semibold tracking-[0.16em] text-[#f2ede6]">
                    {s.l}
                  </p>
                  <p className="mt-3 text-xs leading-relaxed text-[#5a5a5a]">
                    {s.d}
                  </p>
                </div>
              </Fade>
            ))}
          </div>

          <div className="grid md:grid-cols-2">
            {MONEY.map((m, i) => (
              <Fade key={m.t} delay={i * 0.05}>
                <div className="group border-b border-r border-[#1e1e1e] p-8 transition-colors hover:bg-[#080808]">
                  <span className="font-mono text-[9px] tracking-[0.22em] text-[#2196f3]">
                    {m.tag}
                  </span>
                  <h3
                    className="mt-3 text-2xl transition-colors group-hover:text-[#2196f3]"
                    style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                  >
                    {m.t}
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed text-[#5a5a5a]">
                    {m.d}
                  </p>
                </div>
              </Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ── PIPELINE + code ──────────────────────────────────────────────── */}
      <section id="pipeline" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="p-6 lg:flex lg:items-end lg:justify-between lg:p-10">
              <div>
                <SysTag>PROCESS</SysTag>
                <h2
                  className="text-5xl leading-[0.88] tracking-tight lg:text-7xl"
                  style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                >
                  SHIP IN
                  <br />
                  <span
                    className="text-transparent"
                    style={{ WebkitTextStroke: "1px #3a3a3a" }}
                  >
                    THREE STEPS
                  </span>
                </h2>
              </div>
              <p className="mt-4 font-mono text-[10px] tracking-widest text-[#3a3a3a] lg:mt-0">
                CONNECT &nbsp;·&nbsp; SCAN &nbsp;·&nbsp; PROVE
              </p>
            </div>
          </Fade>

          <div className="grid lg:grid-cols-2">
            <div className="border-r border-[#1e1e1e]">
              {STEPS.map((s, i) => (
                <button
                  key={s.n}
                  type="button"
                  onClick={() => setStep(i)}
                  className={cn(
                    "flex w-full border-b border-[#1e1e1e] p-6 text-left transition-colors",
                    step === i ? "bg-[#0a0a0a]" : "hover:bg-[#080808]",
                  )}
                >
                  <div className="grid w-full grid-cols-[48px_1fr] gap-4">
                    <span className="font-mono text-[10px] text-[#3a3a3a]">
                      {s.n}
                    </span>
                    <div>
                      <span className="font-mono text-[9px] tracking-[0.2em] text-[#2196f3]">
                        {s.tag}
                      </span>
                      <h3
                        className={cn(
                          "mt-1 text-2xl transition-colors",
                          step === i ? "text-[#2196f3]" : "text-[#f2ede6]",
                        )}
                        style={{
                          fontFamily: "var(--font-space-grotesk), system-ui",
                        }}
                      >
                        {s.t}
                      </h3>
                      <p className="mt-2 text-sm text-[#5a5a5a]">{s.d}</p>
                    </div>
                  </div>
                </button>
              ))}
            </div>
            <div className="bg-[#080808] p-6 lg:p-10">
              <div className="mb-4 flex items-center justify-between">
                <span className="font-mono text-[10px] tracking-widest text-[#3a3a3a]">
                  STEP &nbsp;{String(step + 1).padStart(2, "0")}&nbsp;OF&nbsp;03
                </span>
                <span className="font-mono text-[10px] text-[#22c55e]">
                  ● READY
                </span>
              </div>
              <AnimatePresence mode="wait">
                <motion.pre
                  key={step}
                  initial={{ opacity: 0, y: 8 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -8 }}
                  transition={{ duration: 0.35 }}
                  className="overflow-x-auto border border-[#1e1e1e] bg-[#050505] p-5 font-mono text-[11px] leading-relaxed text-[#5a5a5a]"
                >
                  {STEPS[step].code}
                </motion.pre>
              </AnimatePresence>
              <MagneticCta onClick={go} variant="primary" className="mt-6 w-full justify-center sm:w-auto">
                RUN THIS FLOW →
              </MagneticCta>
            </div>
          </div>
        </div>
      </section>

      {/* ── METRICS ──────────────────────────────────────────────────────── */}
      <section id="metrics" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="flex items-end justify-between p-6 lg:p-10">
              <div>
                <SysTag>LIVE METRICS</SysTag>
                <h2
                  className="text-5xl leading-[0.88] tracking-tight lg:text-7xl"
                  style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                >
                  SCALE YOU
                  <br />
                  <span
                    className="text-transparent"
                    style={{ WebkitTextStroke: "1px #3a3a3a" }}
                  >
                    CAN MEASURE
                  </span>
                </h2>
              </div>
              <span className="hidden items-center gap-2 font-mono text-[10px] text-[#22c55e] sm:flex">
                <span className="size-1.5 animate-pulse rounded-full bg-[#22c55e]" />
                LIVE
              </span>
            </div>
          </Fade>
          <div className="grid sm:grid-cols-2 lg:grid-cols-4">
            {[
              { n: 100, s: "/100", l: "POSTURE SCORE MODEL", d: "Starts perfect; severity penalties drop it" },
              { n: 10, s: "+", l: "RULE FAMILIES", d: "S3 · IAM · EC2 · KMS · SQS · Secrets · more" },
              { n: 3, s: "", l: "FRAMEWORK MAPS", d: "CIS AWS · NIST SP 800-53 · GDPR Art.32" },
              { n: 0, s: "", l: "WRITE ACCESS", d: "Read-only scan model by design" },
            ].map((m, i) => (
              <Fade key={m.l} delay={i * 0.06}>
                <div className="border-b border-r border-[#1e1e1e] p-8">
                  <p className="font-mono text-4xl font-bold text-[#f2ede6] lg:text-5xl">
                    <CountUp to={m.n} />
                    {m.s}
                  </p>
                  <p className="mt-3 font-mono text-[10px] tracking-[0.18em] text-[#2196f3]">
                    {m.l}
                  </p>
                  <p className="mt-2 text-xs text-[#5a5a5a]">{m.d}</p>
                </div>
              </Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ── COVERAGE ─────────────────────────────────────────────────────── */}
      <section id="coverage" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="p-6 lg:p-10">
              <SysTag>DETECTION_SURFACE</SysTag>
              <h2
                className="text-5xl leading-[0.88] tracking-tight lg:text-7xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                WHAT WE
                <br />
                <span
                  className="text-transparent"
                  style={{ WebkitTextStroke: "1px #3a3a3a" }}
                >
                  ACTUALLY CHECK
                </span>
              </h2>
            </div>
          </Fade>
          {COVERAGE.map(([svc, items], i) => (
            <Fade key={svc} delay={i * 0.03}>
              <div className="group grid grid-cols-[56px_100px_1fr] border-b border-[#1e1e1e] transition-colors hover:bg-[#080808] sm:grid-cols-[56px_140px_1fr]">
                <div className="flex items-center border-r border-[#1e1e1e] px-4 font-mono text-[10px] text-[#3a3a3a]">
                  {String(i + 1).padStart(2, "0")}
                </div>
                <div className="flex items-center border-r border-[#1e1e1e] px-4 font-mono text-xs font-bold tracking-widest text-[#2196f3]">
                  {svc}
                </div>
                <div className="px-5 py-4 text-sm text-[#5a5a5a] group-hover:text-[#f2ede6]">
                  {items}
                </div>
              </div>
            </Fade>
          ))}
        </div>
      </section>

      {/* ── TRUST ────────────────────────────────────────────────────────── */}
      <section id="trust" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="p-6 lg:p-10">
              <SysTag>TRUST & SECURITY</SysTag>
              <h2
                className="text-5xl leading-[0.88] tracking-tight lg:text-7xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                SCANS YOU
                <br />
                <span
                  className="text-transparent"
                  style={{ WebkitTextStroke: "1px #3a3a3a" }}
                >
                  CAN TRUST
                </span>
              </h2>
              <div className="mt-6 flex flex-wrap gap-3 font-mono text-[10px] tracking-widest text-[#3a3a3a]">
                {["READ_ONLY", "ASSUME_ROLE", "DEMO_MODE", "CIS_MAPPED", "PDF_EXPORT"].map(
                  (b) => (
                    <span key={b} className="border border-[#1e1e1e] px-3 py-1.5">
                      {b}
                    </span>
                  ),
                )}
              </div>
            </div>
          </Fade>
          <div className="grid md:grid-cols-2">
            {TRUST.map((t, i) => (
              <Fade key={t.n} delay={i * 0.05}>
                <div className="group border-b border-r border-[#1e1e1e] p-8 transition-colors hover:bg-[#080808]">
                  <div className="flex items-start gap-4">
                    <span className="font-mono text-[10px] text-[#3a3a3a]">
                      {t.n}
                    </span>
                    <div>
                      <span className="font-mono text-[9px] tracking-[0.2em] text-[#2196f3]">
                        {t.tag}
                      </span>
                      <h3
                        className="mt-2 text-2xl group-hover:text-[#2196f3]"
                        style={{
                          fontFamily: "var(--font-space-grotesk), system-ui",
                        }}
                      >
                        {t.t}
                      </h3>
                      <p className="mt-2 text-sm text-[#5a5a5a]">{t.d}</p>
                    </div>
                  </div>
                </div>
              </Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ── WHY US ───────────────────────────────────────────────────────── */}
      <section id="why" className="scroll-mt-[88px] border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr] border-b border-[#1e1e1e]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="p-6 lg:p-10">
              <SysTag>WHY_VAULTSCAN</SysTag>
              <h2
                className="text-5xl leading-[0.88] tracking-tight lg:text-7xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                WHY TEAMS
                <br />
                <span
                  className="text-transparent"
                  style={{ WebkitTextStroke: "1px #3a3a3a" }}
                >
                  CHOOSE US
                </span>
              </h2>
            </div>
          </Fade>
          <div className="grid md:grid-cols-2">
            {WHY.map((w, i) => (
              <Fade key={w.n} delay={i * 0.05}>
                <div className="border-b border-r border-[#1e1e1e] p-8">
                  <span className="font-mono text-xs text-[#2196f3]">{w.n}</span>
                  <h3
                    className="mt-3 text-xl"
                    style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                  >
                    {w.t}
                  </h3>
                  <p className="mt-2 text-sm text-[#5a5a5a]">{w.d}</p>
                </div>
              </Fade>
            ))}
          </div>
        </div>
      </section>

      {/* ── FINAL CTA ────────────────────────────────────────────────────── */}
      <section className="border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px]">
          <Fade className="grid grid-cols-[56px_1fr]">
            <div className="border-r border-[#1e1e1e] p-5" />
            <div className="relative overflow-hidden p-10 lg:p-16">
              <motion.div
                className="pointer-events-none absolute -right-20 -top-20 size-80 rounded-full bg-[#2196f3]/15 blur-3xl"
                animate={{ opacity: [0.25, 0.5, 0.25] }}
                transition={{ duration: 5, repeat: Infinity }}
              />
              <SysTag>VAULTSCAN RUNTIME · READY</SysTag>
              <h2
                className="relative max-w-3xl text-5xl leading-[0.9] tracking-tight lg:text-7xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                YOUR FIRST
                <br />
                SCAN
                <br />
                STARTS NOW.
              </h2>
              <p className="relative mt-6 max-w-lg text-sm text-[#5a5a5a]">
                Open the console. Use Demo mode in seconds — or connect AWS and
                generate a board-ready posture report today.
              </p>
              <div className="relative mt-10 flex flex-col gap-3 sm:flex-row">
                <MagneticCta onClick={go} variant="primary">
                  LAUNCH CONSOLE
                  <span className="transition-transform group-hover:translate-x-1">
                    →
                  </span>
                </MagneticCta>
                <MagneticCta
                  onClick={() =>
                    document.getElementById("features")?.scrollIntoView({
                      behavior: "smooth",
                    })
                  }
                  variant="ghost"
                >
                  EXPLORE CAPABILITIES
                  <span className="transition-transform group-hover:translate-x-1">
                    →
                  </span>
                </MagneticCta>
              </div>
              <div className="relative mt-12 grid max-w-lg grid-cols-3 gap-6 border-t border-[#1e1e1e] pt-8">
                {[
                  { v: "10+", l: "rule families" },
                  { v: "0", l: "write access" },
                  { v: "CIS", l: "mapped" },
                ].map((x) => (
                  <div key={x.l}>
                    <p className="font-mono text-2xl font-bold text-[#f2ede6]">
                      {x.v}
                    </p>
                    <p className="font-mono text-[10px] tracking-widest text-[#3a3a3a]">
                      {x.l.toUpperCase()}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </Fade>
        </div>
      </section>

      {/* ── FOOTER ───────────────────────────────────────────────────────── */}
      <footer className="border-t border-[#1e1e1e]">
        <div className="mx-auto max-w-[1400px] px-6 py-12 lg:px-12">
          <div className="grid gap-10 md:grid-cols-4">
            <div className="md:col-span-2">
              <div className="flex items-center gap-3">
                <div className="flex h-7 w-7 items-center justify-center border border-[#2196f3]">
                  <div className="h-2 w-2 bg-[#2196f3]" />
                </div>
                <span
                  className="text-xl tracking-[0.15em]"
                  style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
                >
                  VAULTSCAN
                </span>
              </div>
              <p className="mt-4 max-w-sm text-xs leading-relaxed text-[#3a3a3a]">
                Cloud Security Posture Management — scan, prioritize, prove.
                Misconfigurations found before they become invoices.
              </p>
            </div>
            <div>
              <h3 className="mb-4 font-mono text-[9px] tracking-[0.2em] text-[#2196f3]">
                PRODUCT
              </h3>
              <ul className="space-y-3 font-mono text-[11px] text-[#3a3a3a]">
                {NAV.slice(0, 4).map((n) => (
                  <li key={n.href}>
                    <a href={n.href} className="hover:text-[#f2ede6]">
                      {n.label}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3 className="mb-4 font-mono text-[9px] tracking-[0.2em] text-[#2196f3]">
                TRUST
              </h3>
              <ul className="space-y-3 font-mono text-[11px] text-[#3a3a3a]">
                <li>
                  <a href="#trust" className="hover:text-[#f2ede6]">
                    Security model
                  </a>
                </li>
                <li>
                  <a href="#impact" className="hover:text-[#f2ede6]">
                    Business impact
                  </a>
                </li>
                <li>
                  <button type="button" onClick={go} className="hover:text-[#f2ede6]">
                    Open console
                  </button>
                </li>
              </ul>
            </div>
          </div>
          <div className="mt-10 flex flex-col items-center justify-between gap-4 border-t border-[#1e1e1e] pt-6 md:flex-row">
            <p className="font-mono text-[10px] text-[#3a3a3a]">
              © 2026 VAULTSCAN · ALL RIGHTS RESERVED.
            </p>
            <div className="flex items-center gap-6">
              <span className="font-mono text-[10px] tabular-nums text-[#3a3a3a]">
                {utc}
              </span>
              <div className="flex items-center gap-2">
                <span className="inline-block size-1.5 animate-pulse rounded-full bg-[#22c55e]" />
                <span className="font-mono text-[10px] tracking-widest text-[#22c55e]">
                  ALL_SYSTEMS_OPERATIONAL
                </span>
              </div>
            </div>
          </div>
        </div>
      </footer>

    </div>
  );
}
