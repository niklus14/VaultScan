"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import {
  GitBranch,
  ShieldAlert,
  ArrowRight,
  Crosshair,
  Lightbulb,
  Sparkles,
  Loader2,
  Skull,
  Target,
  Clock,
  Flame,
  Zap,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useLiveData } from "@/lib/scan-store";
import {
  enrichAttackPaths,
  type AttackPathEnriched,
} from "@/lib/api";
import {
  MagneticCard,
  RippleSurface,
  SpotlightFrame,
} from "@/components/cspm/interactive";
import { cn } from "@/lib/utils";
import type { Severity } from "@/components/cspm/data";

const severityStyles: Record<string, string> = {
  CRITICAL: "border-danger/50 bg-danger/15 text-danger",
  HIGH: "border-warning/50 bg-warning/15 text-warning",
  MEDIUM: "border-accent-blue/50 bg-accent-blue/15 text-accent-blue",
  LOW: "border-border text-muted-foreground",
};

const roleLabel: Record<string, string> = {
  entry: "ENTRY POINT",
  amplify: "AMPLIFY",
  escalate: "ESCALATE",
  impact: "IMPACT",
};

type PathStep = AttackPathEnriched["steps"][number];

function deriveClientPaths(
  vulnerabilities: Array<{
    id: string;
    service: string;
    severity: Severity;
    title?: string;
    description: string;
    remediation?: string;
    rule_id?: string;
  }>,
): AttackPathEnriched[] {
  if (!vulnerabilities.length) return [];
  const by = (pred: (v: (typeof vulnerabilities)[0]) => boolean) =>
    vulnerabilities.filter(pred);
  const paths: AttackPathEnriched[] = [];

  const s3pub = by(
    (v) =>
      v.service === "S3" &&
      (v.severity === "CRITICAL" ||
        (v.title || v.description).toLowerCase().includes("public")),
  );
  const s3enc = by(
    (v) =>
      v.service === "S3" &&
      (v.title || v.description).toLowerCase().includes("encrypt"),
  );
  if (s3pub[0]) {
    const steps: PathStep[] = [
      {
        role: "entry",
        ...s3pub[0],
        resource: s3pub[0].id,
        title: s3pub[0].title || s3pub[0].description,
      },
    ];
    if (s3enc[0]) {
      steps.push({
        role: "amplify",
        ...s3enc[0],
        resource: s3enc[0].id,
        title: s3enc[0].title || s3enc[0].description,
      });
    }
    paths.push({
      id: "client-s3",
      name: "Public storage → data exposure",
      outcome: "Sensitive objects readable from the internet",
      severity: "CRITICAL",
      likelihood: "High — automated scanners hunt open buckets 24/7",
      impact: "Data breach, regulatory fines, brand damage",
      steps,
      break_chain: [
        "Enable all Block Public Access flags",
        "Remove public ACLs and Principal * policies",
        "Enable default encryption",
      ],
      wow_headline: "Your data may already be one Google search away",
      story:
        "Attackers continuously scan for public S3 endpoints. Once found, objects can be listed or downloaded without authentication—especially dangerous when encryption is also missing.",
      attacker_playbook:
        "1. Enumerate public buckets\n2. List and exfiltrate objects\n3. Leverage unencrypted data offline",
      time_to_compromise: "Minutes after discovery",
      blast_radius: "Any object in the exposed bucket(s)",
    });
  }

  const sg = by(
    (v) =>
      v.service === "EC2" &&
      (v.severity === "CRITICAL" ||
        (v.title || "").toLowerCase().includes("world") ||
        (v.title || "").toLowerCase().includes("0.0.0.0")),
  );
  const iam = by(
    (v) =>
      v.service === "IAM" &&
      (v.severity === "HIGH" || v.severity === "CRITICAL"),
  );
  if (sg[0] && iam[0]) {
    paths.push({
      id: "client-takeover",
      name: "Open admin port + weak IAM → takeover",
      outcome: "Foothold then privilege abuse across the account",
      severity: "CRITICAL",
      likelihood: "High when SSH/RDP is world-open",
      impact: "Full cloud account compromise",
      steps: [
        {
          role: "entry",
          ...sg[0],
          resource: sg[0].id,
          title: sg[0].title || sg[0].description,
        },
        {
          role: "escalate",
          ...iam[0],
          resource: iam[0].id,
          title: iam[0].title || iam[0].description,
        },
      ],
      break_chain: [
        "Close world-open SSH/RDP; use SSM/bastion",
        "Enforce MFA and remove admin wildcards",
      ],
      wow_headline: "Internet-facing admin + weak identity = game over",
      story:
        "An open management port is the front door. Combined with missing MFA or admin policies, a single compromised credential can become total account control.",
      attacker_playbook:
        "1. Port-scan for 22/3389\n2. Brute-force or use leaked keys\n3. Abuse IAM privileges to own the account",
      time_to_compromise: "Hours (automated brute force) to days",
      blast_radius: "Entire AWS account and attached data services",
    });
  }

  return paths;
}

function CinematicGraph({
  path,
  activeStep,
  onStep,
}: {
  path: AttackPathEnriched;
  activeStep: number;
  onStep: (i: number) => void;
}) {
  const nodes = [
    ...path.steps.map((s, i) => ({
      ...s,
      idx: i,
      kind: "step" as const,
    })),
    {
      idx: path.steps.length,
      kind: "impact" as const,
      role: "impact",
      title: path.outcome,
      severity: path.severity,
      service: "IMPACT",
      resource: path.blast_radius || path.impact,
    },
  ];

  return (
    <div className="relative overflow-hidden rounded-xl border border-danger/20 bg-gradient-to-b from-[#1a0a0e] via-panel to-panel p-6 sm:p-8">
      {/* Glow backdrop */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-1/2 top-0 h-40 w-[80%] -translate-x-1/2 rounded-full bg-danger/15 blur-3xl" />
        <div
          className="absolute inset-0 opacity-[0.07]"
          style={{
            backgroundImage:
              "radial-gradient(circle at 1px 1px, rgba(255,61,87,0.5) 1px, transparent 0)",
            backgroundSize: "24px 24px",
          }}
        />
      </div>

      <div className="relative flex flex-col items-stretch gap-0 lg:flex-row lg:items-center lg:justify-between lg:gap-2">
        {nodes.map((node, i) => (
          <div
            key={i}
            className="relative flex flex-1 flex-col items-center lg:flex-row"
          >
            <MagneticCard
              strength={14}
              onClick={() => onStep(Math.min(i, path.steps.length - 1))}
              className="relative z-10 w-full max-w-[220px]"
            >
              <RippleSurface
                className={cn(
                  "rounded-xl border px-4 py-4 text-left transition",
                  node.kind === "impact"
                    ? "border-danger/60 bg-danger/20 shadow-[0_0_40px_-8px_rgba(255,61,87,0.7)]"
                    : activeStep === i
                      ? "border-accent-blue/60 bg-accent-blue/10 shadow-[0_0_30px_-10px_rgba(56,116,255,0.6)]"
                      : "border-border bg-panel-alt/90 hover:border-border-strong",
                )}
              >
                <motion.div
                  initial={{ opacity: 0, scale: 0.85, y: 12 }}
                  animate={{ opacity: 1, scale: 1, y: 0 }}
                  transition={{
                    delay: i * 0.12,
                    duration: 0.45,
                    ease: [0.22, 1, 0.36, 1],
                  }}
                >
                  <div className="mb-2 flex items-center gap-2">
                    <span
                      className={cn(
                        "flex size-7 items-center justify-center rounded-full border font-mono text-[10px] font-bold",
                        node.kind === "impact"
                          ? "border-danger/50 bg-danger/20 text-danger"
                          : "border-border bg-background text-muted-foreground",
                      )}
                    >
                      {node.kind === "impact" ? (
                        <Skull className="size-3.5" />
                      ) : (
                        i + 1
                      )}
                    </span>
                    <span className="font-mono text-[9px] font-bold tracking-[0.16em] text-muted-foreground">
                      {roleLabel[node.role] || node.role?.toUpperCase()}
                    </span>
                  </div>
                  {node.severity && node.kind !== "impact" && (
                    <span
                      className={cn(
                        "mb-2 inline-block rounded-sm border px-1.5 py-0.5 font-mono text-[9px] font-bold",
                        severityStyles[node.severity || "HIGH"],
                      )}
                    >
                      {node.severity}
                    </span>
                  )}
                  <p className="text-sm font-semibold leading-snug text-foreground">
                    {node.title}
                  </p>
                  {node.resource && (
                    <p className="mt-1 line-clamp-2 font-mono text-[10px] text-muted-foreground">
                      {node.service ? `${node.service} · ` : ""}
                      {node.resource}
                    </p>
                  )}
                </motion.div>
              </RippleSurface>
            </MagneticCard>

            {i < nodes.length - 1 && (
              <>
                {/* Desktop arrow */}
                <div className="relative z-0 hidden flex-1 items-center px-1 lg:flex">
                  <motion.div
                    className="h-0.5 w-full bg-gradient-to-r from-danger/60 via-warning/50 to-danger/40"
                    initial={{ scaleX: 0 }}
                    animate={{ scaleX: 1 }}
                    transition={{ delay: 0.2 + i * 0.15, duration: 0.4 }}
                    style={{ transformOrigin: "left" }}
                  />
                  <ArrowRight className="-ml-1 size-4 shrink-0 text-danger" />
                </div>
                {/* Mobile arrow */}
                <div className="flex flex-col items-center py-1 lg:hidden">
                  <div className="h-5 w-0.5 bg-gradient-to-b from-danger/50 to-warning/40" />
                  <ArrowRight className="size-4 rotate-90 text-danger" />
                </div>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function AttackPathsTab() {
  const { scan, vulnerabilities, isLive, scanId } = useLiveData();
  const [paths, setPaths] = useState<AttackPathEnriched[]>([]);
  const [idx, setIdx] = useState(0);
  const [activeStep, setActiveStep] = useState(0);
  const [loadingAi, setLoadingAi] = useState(false);
  const [aiNote, setAiNote] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const basePaths = useMemo(() => {
    const fromScan = (scan as { attack_paths?: AttackPathEnriched[] } | null)
      ?.attack_paths;
    if (fromScan && fromScan.length > 0) return fromScan;
    return deriveClientPaths(vulnerabilities);
  }, [scan, vulnerabilities]);

  const loadAi = useCallback(async () => {
    if (!isLive && !scanId) {
      setPaths(basePaths);
      return;
    }
    setLoadingAi(true);
    setError(null);
    try {
      const res = await enrichAttackPaths(
        isLive && scanId !== "SCAN-DEMO" ? scanId : undefined,
      );
      setPaths(res.paths.length ? res.paths : basePaths);
      setAiNote(
        res.ai_used
          ? "Cloud Assistant narrative active"
          : "Deterministic chains (enable GROK_API_KEY for full AI story)",
      );
      setIdx(0);
      setActiveStep(0);
    } catch (e) {
      setPaths(basePaths);
      setError(
        e instanceof Error
          ? e.message
          : "AI enrichment unavailable — showing structural paths",
      );
      setAiNote("Structural attack chains");
    } finally {
      setLoadingAi(false);
    }
  }, [basePaths, isLive, scanId]);

  useEffect(() => {
    setPaths(basePaths);
    setIdx(0);
    setActiveStep(0);
  }, [basePaths]);

  useEffect(() => {
    // Auto-enrich when live scan present
    if (isLive && scanId && scanId !== "SCAN-DEMO") {
      void loadAi();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId, isLive]);

  const path = paths[idx];

  const prev = () => {
    setIdx((i) => Math.max(0, i - 1));
    setActiveStep(0);
  };
  const next = () => {
    setIdx((i) => Math.min(paths.length - 1, i + 1));
    setActiveStep(0);
  };

  return (
    <div className="relative space-y-5">
      <CursorGlow color="rgba(255, 61, 87, 0.22)" size={320} />

      {/* Hero header */}
      <SpotlightFrame
        spotColor="rgba(255, 61, 87, 0.16)"
        className="rounded-xl border border-danger/25 bg-gradient-to-br from-[#1c0b10] via-panel to-panel p-6"
      >
      <div className="relative overflow-hidden">
        <motion.div
          className="pointer-events-none absolute -right-10 -top-10 size-56 rounded-full bg-danger/20 blur-3xl"
          animate={{ opacity: [0.3, 0.6, 0.3], scale: [1, 1.1, 1] }}
          transition={{ duration: 5, repeat: Infinity }}
        />
        <div className="relative flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex size-12 items-center justify-center rounded-xl border border-danger/40 bg-danger/15 text-danger shadow-[0_0_30px_-8px_rgba(255,61,87,0.6)]">
              <GitBranch className="size-6" />
            </div>
            <div>
              <p className="font-mono text-[10px] tracking-[0.22em] text-danger">
                ADVERSARY SIMULATION
              </p>
              <h3 className="mt-1 text-xl font-bold tracking-tight text-foreground sm:text-2xl">
                Attack Path Theater
              </h3>
              <p className="mt-1.5 max-w-xl text-xs leading-relaxed text-muted-foreground sm:text-sm">
                Watch how misconfigurations chain into real breach outcomes —
                then break the chain before an attacker walks it.
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <button
              type="button"
              onClick={() => void loadAi()}
              disabled={loadingAi || (!isLive && paths.length === 0)}
              className="flex items-center gap-2 rounded-lg border border-accent-blue/40 bg-accent-blue/15 px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-accent-blue transition hover:bg-accent-blue/25 disabled:opacity-50"
            >
              {loadingAi ? (
                <Loader2 className="size-3.5 animate-spin" />
              ) : (
                <Sparkles className="size-3.5" />
              )}
              {loadingAi ? "ANALYZING…" : "AI ENRICH PATHS"}
            </button>
            {aiNote && (
              <span className="font-mono text-[10px] text-muted-foreground">
                {aiNote}
              </span>
            )}
          </div>
        </div>
        {error && (
          <p className="relative mt-3 font-mono text-[11px] text-warning">
            {error}
          </p>
        )}
      </div>
      </SpotlightFrame>

      {paths.length === 0 ? (
        <div className="flex flex-col items-center justify-center gap-4 rounded-xl border border-dashed border-border bg-panel px-6 py-24 text-center">
          <ShieldAlert className="size-12 text-success/50" />
          <p className="font-mono text-sm font-bold tracking-wider text-foreground">
            NO ATTACK PATHS DETECTED
          </p>
          <p className="max-w-md text-sm text-muted-foreground">
            {vulnerabilities.length === 0
              ? "Launch a scan first. When misconfigurations stack into a kill chain, they appear here with AI storytelling."
              : "Findings exist but do not form a known multi-step kill chain. Keep fixing individual HIGH/CRITICAL issues."}
          </p>
        </div>
      ) : (
        <>
          {/* Path selector rail */}
          <div className="flex flex-wrap items-center gap-2">
            {paths.map((p, i) => (
              <MagneticCard
                key={p.id}
                strength={10}
                onClick={() => {
                  setIdx(i);
                  setActiveStep(0);
                }}
              >
                <RippleSurface
                  className={cn(
                    "rounded-lg border px-3 py-2 text-left transition",
                    i === idx
                      ? "border-danger/50 bg-danger/10"
                      : "border-border bg-panel hover:border-border-strong",
                  )}
                >
                  <p className="font-mono text-[9px] text-muted-foreground">
                    PATH {String(i + 1).padStart(2, "0")}
                  </p>
                  <p className="max-w-[160px] truncate text-xs font-semibold text-foreground">
                    {p.wow_headline || p.name}
                  </p>
                </RippleSurface>
              </MagneticCard>
            ))}
            <div className="ml-auto flex items-center gap-1">
              <RippleSurface
                className="rounded border border-border"
                onClick={idx === 0 ? undefined : prev}
              >
                <button
                  type="button"
                  onClick={prev}
                  disabled={idx === 0}
                  className="p-2 text-muted-foreground hover:text-foreground disabled:opacity-30"
                >
                  <ChevronLeft className="size-4" />
                </button>
              </RippleSurface>
              <RippleSurface
                className="rounded border border-border"
                onClick={idx >= paths.length - 1 ? undefined : next}
              >
                <button
                  type="button"
                  onClick={next}
                  disabled={idx >= paths.length - 1}
                  className="p-2 text-muted-foreground hover:text-foreground disabled:opacity-30"
                >
                  <ChevronRight className="size-4" />
                </button>
              </RippleSurface>
            </div>
          </div>

          <AnimatePresence mode="wait">
            {path && (
              <motion.div
                key={path.id}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -12 }}
                transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1] }}
                className="space-y-5"
              >
                {/* Wow headline */}
                <SpotlightFrame
                  spotColor="rgba(56, 116, 255, 0.14)"
                  className="rounded-xl border border-border bg-panel px-5 py-5 sm:px-7"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={cn(
                        "rounded-sm border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider",
                        severityStyles[path.severity],
                      )}
                    >
                      {path.severity}
                    </span>
                    {path.ai_enriched && (
                      <span className="inline-flex items-center gap-1 rounded-sm border border-accent-blue/30 bg-accent-blue/10 px-2 py-0.5 font-mono text-[10px] text-accent-blue">
                        <Sparkles className="size-3" />
                        CLOUD ASSISTANT
                      </span>
                    )}
                  </div>
                  <h2 className="mt-3 text-2xl font-bold leading-tight tracking-tight text-foreground sm:text-3xl">
                    {path.wow_headline || path.name}
                  </h2>
                  <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
                    {path.story || path.outcome}
                  </p>

                  <div className="mt-5 grid gap-3 sm:grid-cols-3">
                    {[
                      {
                        icon: Clock,
                        color: "text-warning",
                        label: "TIME TO COMPROMISE",
                        value: path.time_to_compromise || path.likelihood,
                      },
                      {
                        icon: Flame,
                        color: "text-danger",
                        label: "BLAST RADIUS",
                        value: path.blast_radius || path.impact,
                      },
                      {
                        icon: Target,
                        color: "text-accent-blue",
                        label: "LIKELIHOOD",
                        value: path.likelihood,
                      },
                    ].map((card) => (
                      <MagneticCard key={card.label} strength={8}>
                        <div className="rounded-lg border border-border bg-panel-alt px-4 py-3">
                          <div className={cn("flex items-center gap-2", card.color)}>
                            <card.icon className="size-4" />
                            <p className="font-mono text-[10px] font-bold tracking-wider">
                              {card.label}
                            </p>
                          </div>
                          <p className="mt-1.5 text-sm font-medium text-foreground">
                            {card.value}
                          </p>
                        </div>
                      </MagneticCard>
                    ))}
                  </div>
                </SpotlightFrame>

                {/* Cinematic graph */}
                <CinematicGraph
                  path={path}
                  activeStep={activeStep}
                  onStep={setActiveStep}
                />

                {/* Two column: playbook + break chain */}
                <div className="grid gap-4 lg:grid-cols-2">
                  <MagneticCard strength={9} className="h-full">
                    <SpotlightFrame
                      spotColor="rgba(255, 153, 0, 0.12)"
                      className="h-full rounded-xl border border-border bg-panel p-5"
                    >
                      <div className="mb-3 flex items-center gap-2 text-warning">
                        <Zap className="size-4" />
                        <h4 className="font-mono text-[11px] font-bold tracking-[0.16em]">
                          ATTACKER PLAYBOOK
                        </h4>
                      </div>
                      <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed text-foreground/90">
                        {path.attacker_playbook ||
                          path.steps
                            .map(
                              (s, i) =>
                                `${i + 1}. Abuse ${s.service}: ${s.title}`,
                            )
                            .join("\n")}
                      </pre>
                    </SpotlightFrame>
                  </MagneticCard>
                  <MagneticCard strength={9} className="h-full">
                    <SpotlightFrame
                      spotColor="rgba(0, 230, 118, 0.12)"
                      className="h-full rounded-xl border border-success/25 bg-success/5 p-5"
                    >
                      <div className="mb-3 flex items-center gap-2 text-success">
                        <Lightbulb className="size-4" />
                        <h4 className="font-mono text-[11px] font-bold tracking-[0.16em]">
                          BREAK THE CHAIN
                        </h4>
                      </div>
                      <ol className="list-decimal space-y-2 pl-4 text-sm leading-relaxed text-foreground/90">
                        {path.break_chain.map((b) => (
                          <li key={b}>{b}</li>
                        ))}
                      </ol>
                      {path.steps[activeStep]?.remediation && (
                        <div className="mt-4 rounded-md border border-border bg-background p-3">
                          <p className="font-mono text-[10px] text-muted-foreground">
                            FIX FOR SELECTED STEP
                          </p>
                          <pre className="mt-1 overflow-x-auto font-mono text-[11px] text-success/90">
                            {path.steps[activeStep].remediation}
                          </pre>
                        </div>
                      )}
                    </SpotlightFrame>
                  </MagneticCard>
                </div>

                <div className="flex items-center gap-2 rounded-lg border border-border bg-panel-alt px-4 py-3 font-mono text-[10px] text-muted-foreground">
                  <Crosshair className="size-3.5 text-danger" />
                  Click a node on the kill chain to focus its remediation. Use{" "}
                  <span className="text-accent-blue">AI ENRICH PATHS</span> for
                  boardroom storytelling powered by Cloud Assistant.
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </>
      )}
    </div>
  );
}
