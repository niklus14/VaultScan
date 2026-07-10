"use client";

import { useEffect, useState } from "react";
import { motion, useMotionValue, useSpring, useTransform } from "motion/react";
import {
  Shield,
  Radar,
  FileText,
  Cloud,
  Lock,
  Sparkles,
  ArrowRight,
  CheckCircle2,
  Activity,
  Layers,
} from "lucide-react";
import {
  MagneticCard,
  RippleSurface,
  SpotlightFrame,
} from "@/components/cspm/interactive";
import { cn } from "@/lib/utils";

const FEATURES = [
  {
    icon: Cloud,
    title: "Multi-cloud connect",
    body: "AWS AssumeRole and Google Cloud service accounts — industry-standard, revocable access.",
    accent: "text-accent-blue",
    ring: "border-accent-blue/30 bg-accent-blue/10",
  },
  {
    icon: Radar,
    title: "Live misconfig engine",
    body: "Deterministic rules for S3, IAM, EC2, RDS — evidence from real cloud APIs, not guesses.",
    accent: "text-success",
    ring: "border-success/30 bg-success/10",
  },
  {
    icon: Sparkles,
    title: "Cloud Assistant",
    body: "Plain-language risk explanations and remediation steps grounded in your scan results.",
    accent: "text-warning",
    ring: "border-warning/30 bg-warning/10",
  },
  {
    icon: FileText,
    title: "Board-ready reports",
    body: "Executive briefs, charts, findings tables — export PDF & Word in one click.",
    accent: "text-danger",
    ring: "border-danger/30 bg-danger/10",
  },
];

const STEPS = [
  { n: "01", t: "Connect", d: "Link AWS or GCP with least-privilege credentials." },
  { n: "02", t: "Scan", d: "Inventory configs and evaluate posture rules." },
  { n: "03", t: "Prioritize", d: "Severity, compliance maps, and attack-relevant risk." },
  { n: "04", t: "Remediate", d: "CLI fixes, re-scan, watch the posture trend climb." },
];

const STATS = [
  { v: "29+", l: "Detection rules" },
  { v: "4", l: "Core services" },
  { v: "CIS", l: "Mapped frameworks" },
  { v: "0", l: "Write access needed" },
];

function FloatingOrbs() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden">
      <motion.div
        className="absolute -left-32 top-20 size-[420px] rounded-full bg-accent-blue/20 blur-[100px]"
        animate={{ x: [0, 40, 0], y: [0, 30, 0], opacity: [0.35, 0.55, 0.35] }}
        transition={{ duration: 12, repeat: Infinity, ease: "easeInOut" }}
      />
      <motion.div
        className="absolute -right-24 top-40 size-[380px] rounded-full bg-[#00e676]/12 blur-[100px]"
        animate={{ x: [0, -30, 0], y: [0, 40, 0], opacity: [0.25, 0.45, 0.25] }}
        transition={{ duration: 14, repeat: Infinity, ease: "easeInOut", delay: 1 }}
      />
      <motion.div
        className="absolute bottom-0 left-1/3 size-[300px] rounded-full bg-[#ff9900]/10 blur-[90px]"
        animate={{ scale: [1, 1.15, 1], opacity: [0.2, 0.4, 0.2] }}
        transition={{ duration: 10, repeat: Infinity, ease: "easeInOut", delay: 0.5 }}
      />
      {/* Grid overlay */}
      <div
        className="absolute inset-0 opacity-[0.07]"
        style={{
          backgroundImage:
            "linear-gradient(rgba(56,116,255,0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(56,116,255,0.5) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
          maskImage: "radial-gradient(ellipse 70% 60% at 50% 30%, black, transparent)",
        }}
      />
    </div>
  );
}

function OrbitHero() {
  return (
    <div className="relative mx-auto flex h-[280px] w-[280px] items-center justify-center sm:h-[340px] sm:w-[340px]">
      {/* Rings */}
      {[1, 2, 3].map((i) => (
        <motion.div
          key={i}
          className="absolute rounded-full border border-accent-blue/20"
          style={{
            width: 80 + i * 70,
            height: 80 + i * 70,
          }}
          animate={{ rotate: i % 2 === 0 ? 360 : -360 }}
          transition={{
            duration: 18 + i * 6,
            repeat: Infinity,
            ease: "linear",
          }}
        >
          <span
            className={cn(
              "absolute left-1/2 top-0 flex size-7 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border bg-panel shadow-lg",
              i === 1 && "border-success/50 text-success",
              i === 2 && "border-accent-blue/50 text-accent-blue",
              i === 3 && "border-warning/50 text-warning",
            )}
          >
            {i === 1 ? (
              <Lock className="size-3.5" />
            ) : i === 2 ? (
              <Shield className="size-3.5" />
            ) : (
              <Activity className="size-3.5" />
            )}
          </span>
        </motion.div>
      ))}

      {/* Core */}
      <motion.div
        className="relative z-10 flex size-28 items-center justify-center rounded-2xl border border-accent-blue/40 bg-gradient-to-br from-accent-blue/30 via-panel to-[#0d1528] shadow-[0_0_60px_-10px_rgba(56,116,255,0.7)] sm:size-32"
        animate={{ y: [0, -8, 0] }}
        transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
      >
        <Shield className="size-12 text-accent-blue sm:size-14" strokeWidth={1.5} />
        <motion.span
          className="absolute inset-0 rounded-2xl border border-accent-blue/30"
          animate={{ opacity: [0.3, 0.9, 0.3], scale: [1, 1.06, 1] }}
          transition={{ duration: 2.4, repeat: Infinity }}
        />
      </motion.div>
    </div>
  );
}

function MagneticButton({
  children,
  onClick,
  className,
}: {
  children: React.ReactNode;
  onClick: () => void;
  className?: string;
}) {
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 200, damping: 15 });
  const sy = useSpring(y, { stiffness: 200, damping: 15 });

  return (
    <motion.button
      type="button"
      onClick={onClick}
      style={{ x: sx, y: sy }}
      onMouseMove={(e) => {
        const rect = e.currentTarget.getBoundingClientRect();
        x.set((e.clientX - rect.left - rect.width / 2) * 0.25);
        y.set((e.clientY - rect.top - rect.height / 2) * 0.25);
      }}
      onMouseLeave={() => {
        x.set(0);
        y.set(0);
      }}
      whileTap={{ scale: 0.97 }}
      className={className}
    >
      {children}
    </motion.button>
  );
}

export function Landing({ onEnter }: { onEnter: () => void }) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  return (
    <div className="relative min-h-screen overflow-x-hidden bg-background text-foreground">
      <FloatingOrbs />

      {/* Nav */}
      <motion.header
        initial={{ y: -24, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-20 mx-auto flex max-w-6xl items-center justify-between px-6 py-5"
      >
        <div className="flex items-center gap-2.5">
          <div className="flex size-9 items-center justify-center rounded-lg bg-accent-blue">
            <Shield className="size-4.5 text-background" strokeWidth={2.4} />
          </div>
          <div>
            <p className="font-mono text-xs font-bold tracking-[0.2em] text-foreground">
              VAULTSCAN
            </p>
            <p className="font-mono text-[9px] tracking-[0.18em] text-muted-foreground">
              CSPM
            </p>
          </div>
        </div>
        <div className="hidden items-center gap-6 font-mono text-[11px] tracking-wider text-muted-foreground sm:flex">
          <a href="#features" className="transition hover:text-foreground">
            FEATURES
          </a>
          <a href="#how" className="transition hover:text-foreground">
            HOW IT WORKS
          </a>
          <button
            type="button"
            onClick={onEnter}
            className="rounded-md border border-accent-blue/40 bg-accent-blue/10 px-3 py-1.5 font-bold text-accent-blue transition hover:bg-accent-blue/20"
          >
            OPEN CONSOLE
          </button>
        </div>
      </motion.header>

      {/* Hero */}
      <section className="relative z-10 mx-auto grid max-w-6xl items-center gap-10 px-6 pb-20 pt-8 lg:grid-cols-2 lg:pb-28 lg:pt-12">
        <div>
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.15, duration: 0.55 }}
            className="mb-5 inline-flex items-center gap-2 rounded-full border border-border bg-panel/80 px-3 py-1 font-mono text-[10px] tracking-[0.16em] text-muted-foreground backdrop-blur"
          >
            <span className="pulse-dot size-1.5 rounded-full bg-success" />
            CLOUD SECURITY POSTURE MANAGEMENT
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 28 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.25, duration: 0.7, ease: [0.22, 1, 0.36, 1] }}
            className="text-4xl font-bold leading-[1.08] tracking-tight sm:text-5xl lg:text-[3.4rem]"
          >
            See every open door
            <br />
            <span className="bg-gradient-to-r from-accent-blue via-[#7aa2ff] to-success bg-clip-text text-transparent">
              before attackers do.
            </span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4, duration: 0.6 }}
            className="mt-5 max-w-lg text-sm leading-relaxed text-muted-foreground sm:text-base"
          >
            VaultScan inspects AWS (and connects Google Cloud) for dangerous
            misconfigurations — public storage, open admin ports, weak IAM —
            then explains risk and ships PDF/Word reports your team can act on.
          </motion.p>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.55, duration: 0.55 }}
            className="mt-8 flex flex-wrap items-center gap-3"
          >
            <MagneticButton
              onClick={onEnter}
              className="group relative flex items-center gap-2 overflow-hidden rounded-lg bg-accent-blue px-6 py-3.5 font-mono text-xs font-bold tracking-[0.14em] text-background shadow-[0_0_40px_-8px_rgba(56,116,255,0.8)]"
            >
              <span className="absolute inset-0 -translate-x-full bg-gradient-to-r from-transparent via-white/25 to-transparent transition duration-700 group-hover:translate-x-full" />
              <Radar className="size-4" />
              ENTER DASHBOARD
              <ArrowRight className="size-4 transition group-hover:translate-x-0.5" />
            </MagneticButton>
            <a
              href="#how"
              className="flex items-center gap-2 rounded-lg border border-border bg-panel/60 px-5 py-3.5 font-mono text-xs font-bold tracking-[0.12em] text-muted-foreground backdrop-blur transition hover:border-border-strong hover:text-foreground"
            >
              <Layers className="size-4" />
              HOW IT WORKS
            </a>
          </motion.div>

          <motion.ul
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.75 }}
            className="mt-8 flex flex-wrap gap-x-5 gap-y-2 font-mono text-[10px] tracking-wider text-muted-foreground"
          >
            {["READ-ONLY SCAN", "ASSUME ROLE", "CIS MAPPED", "PDF EXPORT"].map(
              (t) => (
                <li key={t} className="flex items-center gap-1.5">
                  <CheckCircle2 className="size-3 text-success" />
                  {t}
                </li>
              ),
            )}
          </motion.ul>
        </div>

        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.35, duration: 0.8, ease: [0.22, 1, 0.36, 1] }}
          className="relative"
        >
          {mounted && <OrbitHero />}
        </motion.div>
      </section>

      {/* Stats strip */}
      <section className="relative z-10 border-y border-border bg-panel/40 backdrop-blur">
        <div className="mx-auto grid max-w-6xl grid-cols-2 gap-px sm:grid-cols-4">
          {STATS.map((s, i) => (
            <motion.div
              key={s.l}
              initial={{ opacity: 0, y: 12 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-40px" }}
              transition={{ delay: i * 0.08, duration: 0.45 }}
              className="px-6 py-7 text-center"
            >
              <p className="font-mono text-2xl font-bold tracking-tight text-foreground sm:text-3xl">
                {s.v}
              </p>
              <p className="mt-1 font-mono text-[10px] tracking-[0.16em] text-muted-foreground">
                {s.l.toUpperCase()}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section id="features" className="relative z-10 mx-auto max-w-6xl px-6 py-20">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mb-10 max-w-xl"
        >
          <p className="font-mono text-[10px] tracking-[0.22em] text-accent-blue">
            CAPABILITIES
          </p>
          <h2 className="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">
            Built for clarity under pressure
          </h2>
          <p className="mt-2 text-sm text-muted-foreground">
            From connection to report — one console for posture, risk, and proof.
          </p>
        </motion.div>

        <div className="grid gap-4 sm:grid-cols-2">
          {FEATURES.map((f, i) => (
            <motion.div
              key={f.title}
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true, margin: "-60px" }}
              transition={{ delay: i * 0.08, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
              whileHover={{ y: -4, transition: { duration: 0.2 } }}
              className="group rounded-xl border border-border bg-panel/80 p-6 backdrop-blur transition hover:border-accent-blue/35 hover:shadow-[0_20px_50px_-30px_rgba(56,116,255,0.5)]"
            >
              <div
                className={cn(
                  "mb-4 flex size-11 items-center justify-center rounded-lg border",
                  f.ring,
                  f.accent,
                )}
              >
                <f.icon className="size-5" />
              </div>
              <h3 className="text-base font-semibold text-foreground">{f.title}</h3>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {f.body}
              </p>
            </motion.div>
          ))}
        </div>
      </section>

      {/* How it works */}
      <section id="how" className="relative z-10 border-t border-border bg-panel/30 py-20">
        <div className="mx-auto max-w-6xl px-6">
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="mb-12 text-center"
          >
            <p className="font-mono text-[10px] tracking-[0.22em] text-accent-blue">
              PIPELINE
            </p>
            <h2 className="mt-2 text-2xl font-bold sm:text-3xl">
              Four steps to clear posture
            </h2>
          </motion.div>

          <div className="relative grid gap-6 md:grid-cols-4">
            <div className="pointer-events-none absolute left-[12%] right-[12%] top-8 hidden h-px bg-gradient-to-r from-transparent via-accent-blue/40 to-transparent md:block" />
            {STEPS.map((s, i) => (
              <motion.div
                key={s.n}
                initial={{ opacity: 0, y: 28 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12, duration: 0.5 }}
                className="relative rounded-xl border border-border bg-background/60 p-5 text-center backdrop-blur"
              >
                <motion.span
                  className="mx-auto mb-4 flex size-12 items-center justify-center rounded-full border border-accent-blue/40 bg-accent-blue/10 font-mono text-sm font-bold text-accent-blue"
                  whileInView={{ scale: [0.8, 1.08, 1] }}
                  viewport={{ once: true }}
                  transition={{ delay: 0.15 + i * 0.12, duration: 0.5 }}
                >
                  {s.n}
                </motion.span>
                <h3 className="font-semibold text-foreground">{s.t}</h3>
                <p className="mt-2 text-xs leading-relaxed text-muted-foreground">
                  {s.d}
                </p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Final CTA */}
      <section className="relative z-10 mx-auto max-w-6xl px-6 py-20">
        <motion.div
          initial={{ opacity: 0, scale: 0.96 }}
          whileInView={{ opacity: 1, scale: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.55 }}
          className="relative overflow-hidden rounded-2xl border border-accent-blue/30 bg-gradient-to-br from-accent-blue/15 via-panel to-background px-8 py-14 text-center"
        >
          <motion.div
            className="pointer-events-none absolute -right-20 -top-20 size-64 rounded-full bg-accent-blue/20 blur-3xl"
            animate={{ opacity: [0.3, 0.6, 0.3] }}
            transition={{ duration: 5, repeat: Infinity }}
          />
          <p className="font-mono text-[10px] tracking-[0.22em] text-accent-blue">
            READY WHEN YOU ARE
          </p>
          <h2 className="mt-3 text-2xl font-bold sm:text-3xl">
            Launch the security console
          </h2>
          <p className="mx-auto mt-3 max-w-md text-sm text-muted-foreground">
            Connect a cloud, run a scan, generate a report — posture you can
            prove.
          </p>
          <MagneticButton
            onClick={onEnter}
            className="mt-8 inline-flex items-center gap-2 rounded-lg bg-accent-blue px-8 py-3.5 font-mono text-xs font-bold tracking-[0.16em] text-background"
          >
            OPEN VAULTSCAN
            <ArrowRight className="size-4" />
          </MagneticButton>
        </motion.div>
      </section>

      <footer className="relative z-10 border-t border-border py-6 text-center font-mono text-[10px] tracking-wider text-muted-foreground">
        VAULTSCAN · CLOUD SECURITY POSTURE MGMT · 2026
      </footer>
    </div>
  );
}
