"use client";

import { useEffect, useRef, useState } from "react";
import { motion, useMotionValue, useSpring, useInView } from "motion/react";
import {
  Radar,
  FileText,
  Cloud,
  Lock,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  DollarSign,
  Target,
  GitBranch,
  ScanSearch,
  KeyRound,
  Menu,
  X,
  Activity,
  Eye,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

/* ─── JARVIS-style palette (landing only) ─────────────────────────────────── */
const C = {
  bg: "#050505",
  border: "#1e1e1e",
  text: "#f2ede6",
  mute: "#5a5a5a",
  dim: "#3a3a3a",
  blue: "#2196f3",
  blueHot: "#42a5f5",
  green: "#22c55e",
  red: "#ef4444",
  amber: "#f59e0b",
};

const NAV = [
  { href: "#impact", label: "IMPACT" },
  { href: "#why", label: "WHY US" },
  { href: "#features", label: "CAPABILITIES" },
  { href: "#pipeline", label: "PIPELINE" },
  { href: "#coverage", label: "COVERAGE" },
  { href: "#security", label: "TRUST" },
];

const IMPACT_STATS = [
  {
    v: "$4.88M",
    l: "Avg. global data breach cost",
    s: "IBM Cost of a Data Breach Report — industry benchmark for total incident cost.",
  },
  {
    v: "23%",
    l: "Breaches involve cloud misconfig",
    s: "Wrong-by-default storage, IAM, and network settings are a top breach vector.",
  },
  {
    v: "200+",
    l: "Days to identify & contain",
    s: "Silent exposure compounds: public buckets and open ports often go unnoticed.",
  },
  {
    v: "10×",
    l: "Cost if found by attackers first",
    s: "Proactive scanning is cheaper than incident response, legal, and brand recovery.",
  },
];

const MONEY_PATHS = [
  {
    icon: Cloud,
    title: "Public cloud storage",
    body: "A single open S3 bucket can leak customer PII, backups, and API keys overnight — regulatory fines (GDPR, CCPA) plus class-action exposure.",
    loss: "Fines · lawsuits · churn",
  },
  {
    icon: KeyRound,
    title: "Over-privileged IAM",
    body: "Admin roles and wildcard trust policies turn one compromised identity into full account takeover — ransomware and resource hijacking.",
    loss: "Ransomware · crypto-mining",
  },
  {
    icon: Eye,
    title: "Open admin ports",
    body: "SSH/RDP to 0.0.0.0/0 + IMDSv1 is a classic path from internet scan → credential theft → lateral movement.",
    loss: "Downtime · data exfil",
  },
  {
    icon: AlertTriangle,
    title: "Blind SOC / weak secrets",
    body: "CloudTrail kill permissions and exposed secrets remove your flight recorder and hand attackers the keys to every integration.",
    loss: "Undetected dwell time",
  },
];

const WHY_US = [
  {
    n: "01",
    t: "Real AWS APIs — not checkbox theater",
    d: "VaultScan reads live configuration (S3, IAM, EC2, KMS, SQS, Secrets…) and returns evidence you can verify in the console.",
  },
  {
    n: "02",
    t: "Lab-proven detection (Steps 1–10)",
    d: "Built against intentional misconfigs: public storage, admin roles, open ports, KMS/SQS exposure, privilege escalation, and more.",
  },
  {
    n: "03",
    t: "Business language + engineer fixes",
    d: "Posture score and compliance coverage for managers; CLI remediations and attack paths for security engineers.",
  },
  {
    n: "04",
    t: "Least privilege by design",
    d: "AssumeRole + read-only patterns. We never need write access to your production workloads.",
  },
  {
    n: "05",
    t: "Board-ready exports",
    d: "One-click PDF / Word packages with severity charts, findings tables, and executive narrative via Cloud Assistant.",
  },
  {
    n: "06",
    t: "From demo to production in minutes",
    d: "Start in Demo mode with zero credentials, then connect real AWS when you’re ready — same console.",
  },
];

const FEATURES = [
  {
    icon: ScanSearch,
    title: "Misconfiguration engine",
    body: "Deterministic rules across S3, IAM, EC2/SG, RDS, KMS, SQS, Secrets Manager — severity-scored with compliance tags.",
  },
  {
    icon: GitBranch,
    title: "Attack path theater",
    body: "See how issues chain into breach outcomes — public storage, trust-wildcard takeover, priv-esc, exposed queues.",
  },
  {
    icon: Sparkles,
    title: "Cloud Assistant",
    body: "Ask questions on your last scan. Get plain-language risk and prioritized remediation grounded in findings.",
  },
  {
    icon: FileText,
    title: "Evidence packages",
    body: "Executive brief, metrics, and findings table — export for auditors, customers, and the board.",
  },
  {
    icon: Target,
    title: "Compliance map",
    body: "Findings mapped to CIS AWS, NIST SP 800-53, and GDPR security controls — coverage you can explain.",
  },
  {
    icon: Lock,
    title: "Safe connection model",
    body: "IAM keys or AssumeRole; secrets stay server-side; Demo mode for training without live risk.",
  },
];

const STEPS = [
  { n: "01", t: "CONNECT", d: "Link AWS with AssumeRole or direct read keys — or use Demo." },
  { n: "02", t: "SCAN", d: "Inventory configuration and evaluate the full rule pack." },
  { n: "03", t: "PRIORITIZE", d: "Posture score, criticals, compliance, and attack paths." },
  { n: "04", t: "PROVE", d: "Export PDF/Word, remediate, re-scan, watch the trend climb." },
];

const COVERAGE = [
  { svc: "S3", items: "Public ACL/policy, BPA, encryption, versioning" },
  { svc: "IAM", items: "Admin policies, MFA, trust *, CloudTrail kill, priv-esc" },
  { svc: "EC2", items: "0.0.0.0/0 ports, IMDSv1, unencrypted EBS" },
  { svc: "KMS", items: "Key policy Principal * on customer CMKs" },
  { svc: "SQS", items: "Public queue resource policies" },
  { svc: "Secrets", items: "Public or root-broad resource policies" },
  { svc: "RDS", items: "Public instances, encryption, backups" },
  { svc: "Paths", items: "Multi-step kill chains for board storytelling" },
];

function useUtcClock() {
  const [t, setT] = useState("");
  useEffect(() => {
    const tick = () =>
      setT(
        new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC",
      );
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return t;
}

/** Particle / network canvas — JARVIS-style right-side hero motion */
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
      const n = Math.floor((w * h) / 14000);
      pts = Array.from({ length: Math.max(28, Math.min(n, 70)) }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.45,
        vy: (Math.random() - 0.5) * 0.45,
      }));
    };

    const draw = () => {
      ctx.clearRect(0, 0, w, h);
      // soft blue bloom
      const g = ctx.createRadialGradient(w * 0.7, h * 0.45, 0, w * 0.7, h * 0.45, w * 0.55);
      g.addColorStop(0, "rgba(33,150,243,0.12)");
      g.addColorStop(1, "rgba(33,150,243,0)");
      ctx.fillStyle = g;
      ctx.fillRect(0, 0, w, h);

      for (const p of pts) {
        p.x += p.vx;
        p.y += p.vy;
        if (p.x < 0 || p.x > w) p.vx *= -1;
        if (p.y < 0 || p.y > h) p.vy *= -1;
      }

      const link = Math.min(w, h) * 0.18;
      for (let i = 0; i < pts.length; i++) {
        for (let j = i + 1; j < pts.length; j++) {
          const a = pts[i];
          const b = pts[j];
          const dx = a.x - b.x;
          const dy = a.y - b.y;
          const d = Math.hypot(dx, dy);
          if (d < link) {
            const alpha = (1 - d / link) * 0.35;
            ctx.strokeStyle = `rgba(33,150,243,${alpha})`;
            ctx.lineWidth = 1;
            ctx.beginPath();
            ctx.moveTo(a.x, a.y);
            ctx.lineTo(b.x, b.y);
            ctx.stroke();
          }
        }
      }

      for (const p of pts) {
        ctx.fillStyle = "rgba(33,150,243,0.85)";
        ctx.beginPath();
        ctx.arc(p.x, p.y, 1.6, 0, Math.PI * 2);
        ctx.fill();
      }

      // scanning line
      const t = (performance.now() / 40) % (h + 80);
      const lg = ctx.createLinearGradient(0, t - 40, 0, t + 40);
      lg.addColorStop(0, "rgba(33,150,243,0)");
      lg.addColorStop(0.5, "rgba(33,150,243,0.18)");
      lg.addColorStop(1, "rgba(33,150,243,0)");
      ctx.fillStyle = lg;
      ctx.fillRect(0, t - 40, w, 80);

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

function MagneticButton({
  children,
  onClick,
  className,
}: {
  children: React.ReactNode;
  onClick?: () => void;
  className?: string;
}) {
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 220, damping: 16 });
  const sy = useSpring(y, { stiffness: 220, damping: 16 });

  return (
    <motion.button
      type="button"
      onClick={onClick}
      style={{ x: sx, y: sy }}
      onMouseMove={(e) => {
        const r = e.currentTarget.getBoundingClientRect();
        x.set((e.clientX - r.left - r.width / 2) * 0.22);
        y.set((e.clientY - r.top - r.height / 2) * 0.22);
      }}
      onMouseLeave={() => {
        x.set(0);
        y.set(0);
      }}
      whileTap={{ scale: 0.98 }}
      className={className}
    >
      {children}
    </motion.button>
  );
}

function FadeIn({
  children,
  className,
  delay = 0,
}: {
  children: React.ReactNode;
  className?: string;
  delay?: number;
}) {
  const ref = useRef(null);
  const inView = useInView(ref, { once: true, margin: "-80px" });
  return (
    <motion.div
      ref={ref}
      className={className}
      initial={{ opacity: 0, y: 28 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.65, delay, ease: [0.22, 1, 0.36, 1] }}
    >
      {children}
    </motion.div>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <p
      className="font-mono text-[10px] tracking-[0.22em]"
      style={{ color: C.blue }}
    >
      {children}
    </p>
  );
}

export function Landing({ onEnter }: { onEnter: () => void }) {
  const utc = useUtcClock();
  const [menuOpen, setMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <div
      className="relative min-h-screen overflow-x-hidden antialiased"
      style={{ background: C.bg, color: C.text }}
    >
      {/* Fixed header — dual bar like JARVIS */}
      <header
        className={cn(
          "fixed inset-x-0 top-0 z-50 transition-all duration-300",
          scrolled ? "bg-[#050505]/95 backdrop-blur-md" : "bg-transparent",
        )}
      >
        <div
          className="flex h-8 items-center justify-between border-b px-6 lg:px-12"
          style={{ borderColor: C.border }}
        >
          <span
            className="font-mono text-[10px] uppercase tracking-widest"
            style={{ color: C.dim }}
          >
            SYS:VAULTSCAN-OS &nbsp;/&nbsp; BUILD 2026.07
          </span>
          <div className="hidden items-center gap-6 md:flex">
            <span
              className="font-mono text-[10px]"
              style={{ color: C.dim }}
            >
              <span style={{ color: C.green }}>●</span>
              &nbsp;ALL_SYSTEMS_NOMINAL
            </span>
            <span
              className="font-mono text-[10px] tabular-nums"
              style={{ color: C.dim }}
            >
              {utc}
            </span>
          </div>
        </div>
        <div className="flex h-14 items-center justify-between px-6 lg:px-12">
          <a href="#" className="group flex items-center gap-3">
            <div
              className="relative flex h-7 w-7 items-center justify-center border"
              style={{ borderColor: C.blue }}
            >
              <div className="h-2 w-2" style={{ background: C.blue }} />
              <div
                className="absolute inset-0 opacity-10 transition group-hover:opacity-20"
                style={{ background: C.blue }}
              />
            </div>
            <span
              className="text-2xl tracking-[0.15em]"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              VAULTSCAN
            </span>
            <span
              className="ml-1 hidden border-l pl-3 font-mono text-[10px] tracking-widest lg:block"
              style={{ borderColor: C.border, color: C.dim }}
            >
              CSPM
            </span>
          </a>

          <nav className="hidden items-center gap-7 md:flex">
            {NAV.map((n) => (
              <a
                key={n.href}
                href={n.href}
                className="font-mono text-[11px] tracking-[0.18em] transition-colors duration-200 hover:text-[#2196f3]"
                style={{ color: C.mute }}
              >
                {n.label}
              </a>
            ))}
          </nav>

          <div className="hidden items-center gap-4 md:flex">
            <button
              type="button"
              onClick={onEnter}
              className="font-mono text-[11px] tracking-widest transition-colors hover:text-[#f2ede6]"
              style={{ color: C.mute }}
            >
              CONSOLE
            </button>
            <MagneticButton
              onClick={onEnter}
              className="flex h-9 items-center px-5 font-mono text-[11px] font-semibold tracking-widest transition-colors"
              style={{ background: C.blue, color: C.bg }}
            >
              LAUNCH_SCAN →
            </MagneticButton>
          </div>

          <button
            type="button"
            className="p-1 md:hidden"
            style={{ color: C.text }}
            aria-label="Menu"
            onClick={() => setMenuOpen((v) => !v)}
          >
            {menuOpen ? <X className="size-5" /> : <Menu className="size-5" />}
          </button>
        </div>
      </header>

      {/* Mobile drawer */}
      <div
        className={cn(
          "fixed inset-0 z-40 flex flex-col transition-opacity duration-300 md:hidden",
          menuOpen
            ? "pointer-events-auto opacity-100"
            : "pointer-events-none opacity-0",
        )}
        style={{ background: C.bg, paddingTop: 88 }}
      >
        <div className="flex flex-col border-t" style={{ borderColor: C.border }}>
          {NAV.map((n, i) => (
            <a
              key={n.href}
              href={n.href}
              onClick={() => setMenuOpen(false)}
              className="flex items-center justify-between border-b px-8 py-7 text-4xl tracking-wider transition-colors hover:text-[#2196f3]"
              style={{ borderColor: C.border, color: C.text }}
            >
              {n.label}
              <span className="font-mono text-xs" style={{ color: C.dim }}>
                {String(i + 1).padStart(2, "0")}
              </span>
            </a>
          ))}
        </div>
        <div className="mt-auto border-t p-8" style={{ borderColor: C.border }}>
          <button
            type="button"
            onClick={() => {
              setMenuOpen(false);
              onEnter();
            }}
            className="block w-full py-5 text-center font-mono text-sm font-semibold tracking-widest"
            style={{ background: C.blue, color: C.bg }}
          >
            LAUNCH_SCAN →
          </button>
        </div>
      </div>

      {/* ─── HERO ─────────────────────────────────────────────────────────── */}
      <section
        className="relative flex min-h-screen flex-col justify-center overflow-hidden pt-[88px]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(30,30,30,0.45) 1px, transparent 1px), linear-gradient(90deg, rgba(30,30,30,0.45) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      >
        <div className="pointer-events-none absolute inset-y-0 right-0 z-0 w-full lg:w-[55%]">
          <HeroCanvas />
        </div>
        <div
          className="pointer-events-none absolute inset-0 z-0"
          style={{
            background:
              "radial-gradient(ellipse 50% 60% at 80% 50%, rgba(33,150,243,0.07) 0%, transparent 70%)",
          }}
        />

        <div className="relative z-20 mx-auto w-full max-w-[1400px] px-6 py-20 lg:px-12 lg:py-28">
          <FadeIn delay={0.05}>
            <div
              className="mb-6 inline-flex items-center gap-2 border px-3 py-1.5 font-mono text-[10px] tracking-[0.2em]"
              style={{ borderColor: C.border, color: C.mute }}
            >
              <span
                className="size-1.5 animate-pulse rounded-full"
                style={{ background: C.green }}
              />
              CLOUD SECURITY POSTURE · READ-ONLY · CIS MAPPED
            </div>
          </FadeIn>

          <FadeIn delay={0.12}>
            <h1
              className="max-w-4xl text-4xl font-bold leading-[1.05] tracking-tight sm:text-6xl lg:text-7xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              Stop paying for
              <br />
              <span style={{ color: C.blue }}>cloud mistakes</span>
              <br />
              you can detect today.
            </h1>
          </FadeIn>

          <FadeIn delay={0.22}>
            <p
              className="mt-6 max-w-xl text-base leading-relaxed sm:text-lg"
              style={{ color: C.mute }}
            >
              VaultScan finds the misconfigurations that empty bank accounts —
              public storage, admin IAM, open ports, exposed keys — then shows
              attack paths and ships board-ready reports before attackers bill
              you in downtime and fines.
            </p>
          </FadeIn>

          <FadeIn delay={0.32}>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              <MagneticButton
                onClick={onEnter}
                className="group relative flex h-12 items-center gap-2 overflow-hidden px-7 font-mono text-[12px] font-semibold tracking-[0.16em]"
                style={{ background: C.blue, color: C.bg }}
              >
                <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/25 to-transparent transition duration-700 group-hover:translate-x-full" />
                <Radar className="size-4" />
                ENTER_CONSOLE
                <ArrowRight className="size-4 transition group-hover:translate-x-0.5" />
              </MagneticButton>
              <a
                href="#impact"
                className="flex h-12 items-center gap-2 border px-6 font-mono text-[12px] tracking-[0.14em] transition hover:border-[#2196f3] hover:text-[#2196f3]"
                style={{ borderColor: C.border, color: C.mute }}
              >
                <DollarSign className="size-4" />
                SEE_THE_COST
              </a>
            </div>
          </FadeIn>

          <FadeIn delay={0.42}>
            <ul className="mt-10 flex flex-wrap gap-x-6 gap-y-2 font-mono text-[10px] tracking-wider" style={{ color: C.dim }}>
              {[
                "ASSUME_ROLE",
                "ZERO_WRITE",
                "DEMO_MODE",
                "PDF_WORD",
                "ATTACK_PATHS",
              ].map((t) => (
                <li key={t} className="flex items-center gap-1.5">
                  <CheckCircle2 className="size-3" style={{ color: C.green }} />
                  {t}
                </li>
              ))}
            </ul>
          </FadeIn>
        </div>
      </section>

      {/* ─── IMPACT / MONEY ───────────────────────────────────────────────── */}
      <section
        id="impact"
        className="border-t py-24"
        style={{ borderColor: C.border }}
      >
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn>
            <SectionLabel>// BUSINESS_IMPACT</SectionLabel>
            <h2
              className="mt-3 max-w-3xl text-3xl font-bold tracking-tight sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              Misconfigurations don’t just “fail audits.”
              <span style={{ color: C.blue }}> They burn cash.</span>
            </h2>
            <p className="mt-4 max-w-2xl text-sm leading-relaxed sm:text-base" style={{ color: C.mute }}>
              Most cloud breaches start with a setting left open — not a
              zero-day. The bill shows up later as incident response, legal,
              regulatory fines, customer churn, and months of SOC overtime.
            </p>
          </FadeIn>

          <div className="mt-12 grid gap-px sm:grid-cols-2 lg:grid-cols-4" style={{ background: C.border }}>
            {IMPACT_STATS.map((s, i) => (
              <FadeIn key={s.l} delay={i * 0.06}>
                <div className="h-full p-7" style={{ background: C.bg }}>
                  <p
                    className="font-mono text-3xl font-bold tracking-tight sm:text-4xl"
                    style={{ color: C.blue }}
                  >
                    {s.v}
                  </p>
                  <p className="mt-2 font-mono text-[11px] font-semibold tracking-[0.14em]" style={{ color: C.text }}>
                    {s.l.toUpperCase()}
                  </p>
                  <p className="mt-3 text-xs leading-relaxed" style={{ color: C.mute }}>
                    {s.s}
                  </p>
                </div>
              </FadeIn>
            ))}
          </div>

          <div className="mt-16 grid gap-4 md:grid-cols-2">
            {MONEY_PATHS.map((m, i) => (
              <FadeIn key={m.title} delay={i * 0.07}>
                <div
                  className="group h-full border p-6 transition hover:border-[#2196f3]/50"
                  style={{ borderColor: C.border, background: "#080808" }}
                >
                  <div className="mb-4 flex items-start justify-between gap-3">
                    <div
                      className="flex size-10 items-center justify-center border"
                      style={{ borderColor: C.blue, color: C.blue }}
                    >
                      <m.icon className="size-5" />
                    </div>
                    <span
                      className="font-mono text-[10px] tracking-widest"
                      style={{ color: C.amber }}
                    >
                      {m.loss.toUpperCase()}
                    </span>
                  </div>
                  <h3 className="text-lg font-semibold" style={{ color: C.text }}>
                    {m.title}
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed" style={{ color: C.mute }}>
                    {m.body}
                  </p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ─── WHY US ───────────────────────────────────────────────────────── */}
      <section
        id="why"
        className="border-t py-24"
        style={{ borderColor: C.border, background: "#070707" }}
      >
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn>
            <SectionLabel>// WHY_VAULTSCAN</SectionLabel>
            <h2
              className="mt-3 max-w-2xl text-3xl font-bold sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              Why teams choose us
            </h2>
            <p className="mt-3 max-w-xl text-sm" style={{ color: C.mute }}>
              Built for portfolio-grade CSPM demos and real AWS validation labs —
              clarity for executives, evidence for engineers.
            </p>
          </FadeIn>

          <div className="mt-12 grid gap-0 border md:grid-cols-2 lg:grid-cols-3" style={{ borderColor: C.border }}>
            {WHY_US.map((w, i) => (
              <FadeIn key={w.n} delay={i * 0.05}>
                <div
                  className="h-full border-b border-r p-7 transition hover:bg-[#0a0a0a]"
                  style={{ borderColor: C.border }}
                >
                  <span className="font-mono text-xs" style={{ color: C.blue }}>
                    {w.n}
                  </span>
                  <h3 className="mt-3 text-base font-semibold" style={{ color: C.text }}>
                    {w.t}
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed" style={{ color: C.mute }}>
                    {w.d}
                  </p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ─── FEATURES ─────────────────────────────────────────────────────── */}
      <section id="features" className="border-t py-24" style={{ borderColor: C.border }}>
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn>
            <SectionLabel>// CAPABILITIES</SectionLabel>
            <h2
              className="mt-3 text-3xl font-bold sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              One console. Full posture story.
            </h2>
          </FadeIn>
          <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {FEATURES.map((f, i) => (
              <FadeIn key={f.title} delay={i * 0.06}>
                <motion.div
                  whileHover={{ y: -3 }}
                  className="h-full border p-6"
                  style={{ borderColor: C.border, background: "#080808" }}
                >
                  <div
                    className="mb-4 flex size-10 items-center justify-center border"
                    style={{ borderColor: `${C.blue}66`, color: C.blue }}
                  >
                    <f.icon className="size-5" />
                  </div>
                  <h3 className="font-semibold" style={{ color: C.text }}>
                    {f.title}
                  </h3>
                  <p className="mt-2 text-sm leading-relaxed" style={{ color: C.mute }}>
                    {f.body}
                  </p>
                </motion.div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ─── PIPELINE ─────────────────────────────────────────────────────── */}
      <section
        id="pipeline"
        className="border-t py-24"
        style={{ borderColor: C.border, background: "#070707" }}
      >
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn className="text-center">
            <SectionLabel>// PIPELINE</SectionLabel>
            <h2
              className="mt-3 text-3xl font-bold sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              From connect to proof in four steps
            </h2>
          </FadeIn>
          <div className="relative mt-14 grid gap-6 md:grid-cols-4">
            <div
              className="pointer-events-none absolute left-[12%] right-[12%] top-7 hidden h-px md:block"
              style={{
                background: `linear-gradient(90deg, transparent, ${C.blue}66, transparent)`,
              }}
            />
            {STEPS.map((s, i) => (
              <FadeIn key={s.n} delay={i * 0.1}>
                <div
                  className="relative border p-6 text-center"
                  style={{ borderColor: C.border, background: C.bg }}
                >
                  <motion.span
                    className="mx-auto mb-4 flex size-14 items-center justify-center border font-mono text-sm font-bold"
                    style={{ borderColor: C.blue, color: C.blue }}
                    whileInView={{ scale: [0.85, 1.06, 1] }}
                    viewport={{ once: true }}
                    transition={{ delay: 0.1 + i * 0.08, duration: 0.45 }}
                  >
                    {s.n}
                  </motion.span>
                  <h3 className="font-mono text-sm tracking-[0.18em]" style={{ color: C.text }}>
                    {s.t}
                  </h3>
                  <p className="mt-2 text-xs leading-relaxed" style={{ color: C.mute }}>
                    {s.d}
                  </p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ─── COVERAGE ─────────────────────────────────────────────────────── */}
      <section id="coverage" className="border-t py-24" style={{ borderColor: C.border }}>
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn>
            <SectionLabel>// DETECTION_SURFACE</SectionLabel>
            <h2
              className="mt-3 max-w-2xl text-3xl font-bold sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              What we actually check
            </h2>
            <p className="mt-3 max-w-xl text-sm" style={{ color: C.mute }}>
              Validation-lab coverage including intentional high-risk patterns —
              so you can prove the scanner before production rollout.
            </p>
          </FadeIn>
          <div className="mt-10 grid gap-px sm:grid-cols-2 lg:grid-cols-4" style={{ background: C.border }}>
            {COVERAGE.map((c, i) => (
              <FadeIn key={c.svc} delay={i * 0.04}>
                <div className="h-full p-5" style={{ background: C.bg }}>
                  <p className="font-mono text-xs font-bold tracking-[0.2em]" style={{ color: C.blue }}>
                    {c.svc}
                  </p>
                  <p className="mt-2 text-sm leading-relaxed" style={{ color: C.mute }}>
                    {c.items}
                  </p>
                </div>
              </FadeIn>
            ))}
          </div>
        </div>
      </section>

      {/* ─── TRUST ────────────────────────────────────────────────────────── */}
      <section
        id="security"
        className="border-t py-24"
        style={{ borderColor: C.border, background: "#070707" }}
      >
        <div className="mx-auto grid max-w-[1400px] gap-12 px-6 lg:grid-cols-2 lg:px-12">
          <FadeIn>
            <SectionLabel>// TRUST_MODEL</SectionLabel>
            <h2
              className="mt-3 text-3xl font-bold sm:text-4xl"
              style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
            >
              Security that respects your perimeter
            </h2>
            <ul className="mt-8 space-y-4">
              {[
                "Read-only scanning — no resource mutation from the engine",
                "Prefer STS AssumeRole with short-lived credentials",
                "Secrets stored server-side; never in the browser bundle",
                "Demo mode for training without live cloud risk",
                "Findings tagged to CIS / NIST / GDPR for stakeholder mapping",
              ].map((t) => (
                <li key={t} className="flex items-start gap-3 text-sm" style={{ color: C.mute }}>
                  <CheckCircle2 className="mt-0.5 size-4 shrink-0" style={{ color: C.green }} />
                  {t}
                </li>
              ))}
            </ul>
          </FadeIn>
          <FadeIn delay={0.12}>
            <div
              className="border p-8"
              style={{ borderColor: C.border, background: C.bg }}
            >
              <div className="mb-6 flex items-center gap-3">
                <Activity className="size-5" style={{ color: C.blue }} />
                <p className="font-mono text-[11px] tracking-[0.2em]" style={{ color: C.blue }}>
                  LIVE_POSTURE_LOOP
                </p>
              </div>
              {[
                { t: "Connect", d: "Settings → cloud credentials" },
                { t: "Scan", d: "Engine evaluates configs + lab rules" },
                { t: "Explain", d: "Scores, compliance, attack paths" },
                { t: "Export", d: "PDF / Word for leadership" },
                { t: "Re-scan", d: "Prove remediation with trend" },
              ].map((row, i) => (
                <div
                  key={row.t}
                  className="flex items-center gap-4 border-b py-3 last:border-0"
                  style={{ borderColor: C.border }}
                >
                  <span className="font-mono text-[10px]" style={{ color: C.dim }}>
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span className="w-20 font-mono text-xs font-bold" style={{ color: C.text }}>
                    {row.t}
                  </span>
                  <span className="text-xs" style={{ color: C.mute }}>
                    {row.d}
                  </span>
                </div>
              ))}
              <MagneticButton
                onClick={onEnter}
                className="mt-8 flex w-full items-center justify-center gap-2 py-4 font-mono text-[12px] font-semibold tracking-widest"
                style={{ background: C.blue, color: C.bg }}
              >
                OPEN_CONSOLE
                <Zap className="size-4" />
              </MagneticButton>
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ─── CTA ──────────────────────────────────────────────────────────── */}
      <section className="border-t py-24" style={{ borderColor: C.border }}>
        <div className="mx-auto max-w-[1400px] px-6 lg:px-12">
          <FadeIn>
            <div
              className="relative overflow-hidden border px-8 py-16 text-center sm:px-16"
              style={{
                borderColor: `${C.blue}55`,
                background:
                  "linear-gradient(135deg, rgba(33,150,243,0.12) 0%, #050505 45%, #050505 100%)",
              }}
            >
              <motion.div
                className="pointer-events-none absolute -right-16 -top-16 size-72 rounded-full blur-3xl"
                style={{ background: "rgba(33,150,243,0.2)" }}
                animate={{ opacity: [0.3, 0.55, 0.3] }}
                transition={{ duration: 5, repeat: Infinity }}
              />
              <SectionLabel>// READY_STATE</SectionLabel>
              <h2
                className="relative mt-4 text-3xl font-bold sm:text-5xl"
                style={{ fontFamily: "var(--font-space-grotesk), system-ui" }}
              >
                Find open doors before
                <br />
                they become invoices.
              </h2>
              <p className="relative mx-auto mt-4 max-w-lg text-sm" style={{ color: C.mute }}>
                Launch the console, run Demo mode in seconds, or connect AWS and
                generate your first posture report today.
              </p>
              <MagneticButton
                onClick={onEnter}
                className="relative mt-10 inline-flex items-center gap-2 px-10 py-4 font-mono text-[12px] font-semibold tracking-[0.18em]"
                style={{ background: C.blue, color: C.bg }}
              >
                LAUNCH_VAULTSCAN →
              </MagneticButton>
            </div>
          </FadeIn>
        </div>
      </section>

      {/* ─── FOOTER ───────────────────────────────────────────────────────── */}
      <footer className="border-t" style={{ borderColor: C.border }}>
        <div className="mx-auto max-w-[1400px] px-6 py-12 lg:px-12">
          <div className="grid gap-10 md:grid-cols-4">
            <div className="md:col-span-2">
              <div className="flex items-center gap-3">
                <div
                  className="flex h-7 w-7 items-center justify-center border"
                  style={{ borderColor: C.blue }}
                >
                  <div className="h-2 w-2" style={{ background: C.blue }} />
                </div>
                <span className="text-xl tracking-[0.15em]">VAULTSCAN</span>
              </div>
              <p className="mt-4 max-w-sm text-xs leading-relaxed" style={{ color: C.dim }}>
                Cloud Security Posture Management for teams that need evidence,
                not buzzwords. Scan · prioritize · prove.
              </p>
            </div>
            <div>
              <h3 className="mb-4 font-mono text-[9px] tracking-[0.2em]" style={{ color: C.blue }}>
                PRODUCT
              </h3>
              <ul className="space-y-3 font-mono text-[11px]" style={{ color: C.dim }}>
                <li>
                  <a href="#features" className="hover:text-[#f2ede6]">
                    Capabilities
                  </a>
                </li>
                <li>
                  <a href="#coverage" className="hover:text-[#f2ede6]">
                    Coverage
                  </a>
                </li>
                <li>
                  <button type="button" onClick={onEnter} className="hover:text-[#f2ede6]">
                    Open console
                  </button>
                </li>
              </ul>
            </div>
            <div>
              <h3 className="mb-4 font-mono text-[9px] tracking-[0.2em]" style={{ color: C.blue }}>
                TRUST
              </h3>
              <ul className="space-y-3 font-mono text-[11px]" style={{ color: C.dim }}>
                <li>
                  <a href="#security" className="hover:text-[#f2ede6]">
                    Security model
                  </a>
                </li>
                <li>
                  <a href="#impact" className="hover:text-[#f2ede6]">
                    Business impact
                  </a>
                </li>
                <li>
                  <a href="#why" className="hover:text-[#f2ede6]">
                    Why VaultScan
                  </a>
                </li>
              </ul>
            </div>
          </div>
          <div
            className="mt-10 flex flex-col items-center justify-between gap-4 border-t pt-6 md:flex-row"
            style={{ borderColor: C.border }}
          >
            <p className="font-mono text-[10px]" style={{ color: C.dim }}>
              © 2026 VAULTSCAN · CLOUD SECURITY POSTURE MGMT · ALL RIGHTS RESERVED
            </p>
            <div className="flex items-center gap-4">
              <span className="font-mono text-[10px] tabular-nums" style={{ color: C.dim }}>
                {utc}
              </span>
              <div className="flex items-center gap-2">
                <span
                  className="inline-block size-1.5 animate-pulse rounded-full"
                  style={{ background: C.green }}
                />
                <span
                  className="font-mono text-[10px] tracking-widest"
                  style={{ color: C.green }}
                >
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
