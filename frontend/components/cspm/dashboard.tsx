"use client";

import { useEffect, useState } from "react";
import {
  LayoutGrid,
  ShieldAlert,
  ClipboardCheck,
  Wrench,
  History,
  FileText,
  Settings2,
} from "lucide-react";
import { Sidebar } from "./sidebar";
import { ScanReport } from "./scan-report";
import { AuditStream } from "./audit-stream";
import { AiAssistant } from "./ai-assistant";
import { OverviewTab } from "./tabs/overview";
import { VulnerabilityFeedTab } from "./tabs/vulnerability-feed";
import { ComplianceRegistryTab } from "./tabs/compliance-registry";
import { RemediationHubTab } from "./tabs/remediation-hub";
import { ScanHistoryTab } from "./tabs/scan-history";
import { SettingsTab } from "./tabs/settings";
import { type TabId } from "./data";
import { useLiveData } from "@/lib/scan-store";

const pageMeta: Record<
  TabId,
  { title: string; icon: React.ElementType }
> = {
  overview: { title: "OVERVIEW", icon: LayoutGrid },
  vulnerability: { title: "VULNERABILITY FEED", icon: ShieldAlert },
  compliance: { title: "COMPLIANCE REGISTRY", icon: ClipboardCheck },
  remediation: { title: "REMEDIATION HUB", icon: Wrench },
  history: { title: "SCAN HISTORY", icon: History },
  settings: { title: "SETTINGS", icon: Settings2 },
};

function useClock() {
  const [time, setTime] = useState<string>("");
  useEffect(() => {
    const tick = () =>
      setTime(
        new Date().toLocaleTimeString("en-US", {
          hour12: true,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }),
      );
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return time;
}

export function Dashboard() {
  const [active, setActive] = useState<TabId>("overview");
  const [reportOpen, setReportOpen] = useState(false);
  const time = useClock();
  const meta = pageMeta[active];
  const Icon = meta.icon;
  const { bootstrap, isLive, loading, connection, mode } = useLiveData();

  useEffect(() => {
    void bootstrap();
  }, [bootstrap]);

  const statusLabel = loading
    ? "SCANNING"
    : isLive
      ? "LIVE"
      : connection?.connected
        ? "READY"
        : mode === "simulate"
          ? "SIM READY"
          : "STANDBY";

  return (
    <div className="flex h-screen w-full overflow-hidden bg-background">
      <div className="hidden w-[260px] shrink-0 lg:block">
        <Sidebar active={active} onSelect={setActive} />
      </div>

      <main className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b border-border bg-panel px-6 py-4">
          <div className="flex items-center gap-3">
            <div className="glow-blue flex size-9 items-center justify-center rounded-md bg-accent-blue">
              <Icon className="size-5 text-background" strokeWidth={2.2} />
            </div>
            <h2 className="font-mono text-lg font-bold tracking-[0.1em] text-foreground">
              {meta.title}
            </h2>
          </div>
          <div className="flex items-center gap-3 pr-16 sm:pr-20">
            <button
              onClick={() => setReportOpen(true)}
              className="flex items-center gap-2 rounded-md border border-accent-blue/40 bg-accent-blue/10 px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-accent-blue transition-colors hover:bg-accent-blue/20"
            >
              <FileText className="size-3.5" />
              GENERATE REPORT
            </button>
            <div className="flex items-center gap-2 rounded-md border border-border bg-panel-alt px-3 py-1.5">
              <span
                className={`pulse-dot size-1.5 rounded-full ${
                  isLive || loading ? "bg-success" : "bg-warning"
                }`}
              />
              <span className="font-mono text-[11px] tracking-wider text-muted-foreground">
                {statusLabel}:{" "}
                <span className="font-bold text-foreground">
                  {time || "--:--:--"}
                </span>
              </span>
            </div>
          </div>
        </header>

        <div className="flex-1 overflow-y-auto p-6">
          {active === "overview" && <OverviewTab />}
          {active === "vulnerability" && <VulnerabilityFeedTab />}
          {active === "compliance" && <ComplianceRegistryTab />}
          {active === "remediation" && <RemediationHubTab />}
          {active === "history" && <ScanHistoryTab />}
          {active === "settings" && <SettingsTab />}
        </div>

        <nav className="flex items-center justify-around border-t border-border bg-panel lg:hidden">
          {(Object.keys(pageMeta) as TabId[]).map((id) => {
            const TabIcon = pageMeta[id].icon;
            const isActive = active === id;
            return (
              <button
                key={id}
                onClick={() => setActive(id)}
                className="flex flex-1 flex-col items-center gap-1 py-2.5"
                aria-label={pageMeta[id].title}
              >
                <TabIcon
                  className={`size-5 ${isActive ? "text-accent-blue" : "text-muted-foreground"}`}
                />
                <span
                  className={`h-1 w-1 rounded-full ${isActive ? "bg-accent-blue" : "bg-transparent"}`}
                />
              </button>
            );
          })}
        </nav>
      </main>

      <div className="hidden w-[320px] shrink-0 xl:block">
        <AuditStream />
      </div>

      {reportOpen && <ScanReport onClose={() => setReportOpen(false)} />}
      <AiAssistant />
    </div>
  );
}
