"use client";

import { useEffect, useState } from "react";
import {
  CheckCircle2,
  AlertTriangle,
  Info,
  KeyRound,
  Shield,
  Cloud,
  Loader2,
  Eye,
  EyeOff,
  Trash2,
  Save,
  PlugZap,
  BookOpen,
  Lock,
  Clock,
  Mail,
  Play,
} from "lucide-react";
import {
  getConnectionSettings,
  saveConnectionSettings,
  testConnectionSettings,
  clearConnectionCredentials,
  rememberAwsCreds,
  clearAwsCreds,
  getScheduleSettings,
  saveScheduleSettings,
  runScheduleNow,
  testScheduleEmail,
  type ConnectionSettings,
  type CloudProvider,
  type ScanMode,
  type ScheduleSettings,
  type AlertWhen,
} from "@/lib/api";
import { useScanStore } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

/** Optional quick picks — user can still type any minute value. */
const INTERVAL_PRESETS = [5, 15, 30, 60, 120, 360, 1440] as const;

const ALERT_WHEN_OPTIONS: { id: AlertWhen; label: string; hint: string }[] = [
  {
    id: "always",
    label: "After every scan",
    hint: "Email even when the cloud looks clean.",
  },
  {
    id: "any_findings",
    label: "Any findings",
    hint: "Email only if the scan found at least one issue.",
  },
  {
    id: "high_or_critical",
    label: "High or critical",
    hint: "Email only for serious risk (recommended).",
  },
  {
    id: "critical_only",
    label: "Critical only",
    hint: "Email only when critical issues appear.",
  },
];

const REGIONS = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "eu-west-1",
  "eu-west-2",
  "eu-central-1",
  "ap-southeast-1",
  "ap-northeast-1",
];

const PROVIDERS: {
  id: CloudProvider;
  title: string;
  subtitle: string;
  badge: string;
}[] = [
  {
    id: "aws",
    title: "Amazon Web Services",
    subtitle: "Connect with IAM keys + optional AssumeRole (full scan engine).",
    badge: "AWS",
  },
  {
    id: "gcp",
    title: "Google Cloud",
    subtitle: "Connect with a Project ID + service account JSON key.",
    badge: "GCP",
  },
];

const AUTH_OPTIONS: {
  id: ScanMode;
  title: string;
  badge: string;
  description: string;
  recommended?: boolean;
}[] = [
  {
    id: "assume_role",
    title: "IAM Role assumption",
    badge: "Recommended",
    recommended: true,
    description:
      "Access Key only calls sts:AssumeRole. Scanning uses short-lived role credentials.",
  },
  {
    id: "direct",
    title: "Access keys (direct)",
    badge: "Simple",
    description:
      "Scan with the Access Key itself. Faster for a single account.",
  },
  {
    id: "simulate",
    title: "Demo environment",
    badge: "No cloud required",
    description:
      "Simulated vulnerable resources for demos and training.",
  },
];

function FieldLabel({
  label,
  required,
  hint,
}: {
  label: string;
  required?: boolean;
  hint?: string;
}) {
  return (
    <div className="mb-1.5">
      <label className="font-mono text-[11px] font-bold tracking-[0.12em] text-foreground">
        {label}
        {required && <span className="ml-1 text-danger">*</span>}
      </label>
      {hint && (
        <p className="mt-0.5 text-[11px] leading-snug text-muted-foreground">
          {hint}
        </p>
      )}
    </div>
  );
}

function TextInput({
  value,
  onChange,
  placeholder,
  type = "text",
  mono = true,
  disabled,
  autoComplete = "off",
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  type?: string;
  mono?: boolean;
  disabled?: boolean;
  autoComplete?: string;
}) {
  return (
    <input
      type={type}
      value={value}
      disabled={disabled}
      autoComplete={autoComplete}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      className={cn(
        "w-full rounded-md border border-border bg-background px-3 py-2.5 text-sm text-foreground outline-none transition placeholder:text-muted-foreground/50 focus:border-accent-blue/50 disabled:opacity-50",
        mono && "font-mono text-xs",
      )}
    />
  );
}

function StatusPill({
  status,
}: {
  status: ConnectionSettings["last_test_status"];
}) {
  if (status === "ok") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-sm border border-success/40 bg-success/10 px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-success">
        <CheckCircle2 className="size-3" />
        VERIFIED
      </span>
    );
  }
  if (status === "failed") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-sm border border-danger/40 bg-danger/10 px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-danger">
        <AlertTriangle className="size-3" />
        FAILED
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
      NOT TESTED
    </span>
  );
}

export function SettingsTab() {
  const refreshConnection = useScanStore((s) => s.refreshConnection);
  const bootstrap = useScanStore((s) => s.bootstrap);
  const setMode = useScanStore((s) => s.setMode);
  const setRoleArn = useScanStore((s) => s.setRoleArn);
  const setRegion = useScanStore((s) => s.setRegion);

  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [showSecret, setShowSecret] = useState(false);
  const [banner, setBanner] = useState<{
    type: "ok" | "error" | "info";
    text: string;
  } | null>(null);
  const [settings, setSettings] = useState<ConnectionSettings | null>(null);

  const [provider, setProvider] = useState<CloudProvider>("aws");
  const [connectionName, setConnectionName] = useState("Primary Cloud Account");
  const [authMode, setAuthMode] = useState<ScanMode>("assume_role");
  const [roleArn, setRoleArnLocal] = useState("");
  const [externalId, setExternalId] = useState("");
  const [region, setRegionLocal] = useState("us-east-1");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");
  const [gcpProjectId, setGcpProjectId] = useState("");
  const [gcpSaJson, setGcpSaJson] = useState("");

  // Schedule + Gmail alerts
  const [schedule, setSchedule] = useState<ScheduleSettings | null>(null);
  const [schedEnabled, setSchedEnabled] = useState(false);
  const [intervalMinutes, setIntervalMinutes] = useState(60);
  const [emailEnabled, setEmailEnabled] = useState(false);
  const [recipients, setRecipients] = useState("");
  const [alertWhen, setAlertWhen] = useState<AlertWhen>("high_or_critical");
  const [includeDetails, setIncludeDetails] = useState(true);
  const [savingSchedule, setSavingSchedule] = useState(false);
  const [runningSchedule, setRunningSchedule] = useState(false);
  const [testingEmail, setTestingEmail] = useState(false);

  const applySchedule = (s: ScheduleSettings) => {
    setSchedule(s);
    setSchedEnabled(s.enabled);
    setIntervalMinutes(s.interval_minutes || 60);
    setEmailEnabled(s.email_enabled);
    setRecipients(s.recipients || "");
    setAlertWhen((s.alert_when as AlertWhen) || "high_or_critical");
    setIncludeDetails(s.include_finding_details !== false);
  };

  const load = async () => {
    setLoading(true);
    try {
      const s = await getConnectionSettings();
      setSettings(s);
      setProvider((s.provider as CloudProvider) === "gcp" ? "gcp" : "aws");
      setConnectionName(s.connection_name);
      setAuthMode(s.auth_mode);
      setRoleArnLocal(s.role_arn || "");
      setExternalId(s.external_id || "");
      setRegionLocal(s.region || "us-east-1");
      setGcpProjectId(s.gcp_project_id || "");
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
      setGcpSaJson("");
      try {
        const sch = await getScheduleSettings();
        applySchedule(sch);
      } catch {
        /* schedule API optional if older backend */
      }
    } catch (e) {
      setBanner({
        type: "error",
        text:
          e instanceof Error
            ? e.message
            : "Could not load connection settings. Is the API running?",
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const payload = () => ({
    connection_name: connectionName,
    provider,
    auth_mode: authMode,
    role_arn: roleArn,
    external_id: externalId,
    region,
    access_key_id: accessKeyId || undefined,
    secret_access_key: secretKey || undefined,
    session_token: sessionToken || undefined,
    gcp_project_id: gcpProjectId || undefined,
    gcp_service_account_json: gcpSaJson || undefined,
  });

  const onSave = async () => {
    setSaving(true);
    setBanner(null);
    try {
      const p = payload();
      // Keep secrets in sessionStorage so Fixing options can re-hydrate on Vercel
      rememberAwsCreds({
        access_key_id: p.access_key_id,
        secret_access_key: p.secret_access_key,
        session_token: p.session_token,
        role_arn: p.role_arn,
        auth_mode: p.auth_mode,
        region: p.region,
        external_id: p.external_id,
      });
      const res = await saveConnectionSettings(p);
      setSettings(res.connection);
      setMode(res.connection.auth_mode);
      setRoleArn(res.connection.role_arn);
      setRegion(res.connection.region);
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
      setGcpSaJson("");
      setBanner({ type: "ok", text: res.message });
      await refreshConnection();
      await bootstrap();
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Save failed",
      });
    } finally {
      setSaving(false);
    }
  };

  const onTest = async () => {
    setTesting(true);
    setBanner(null);
    try {
      const p = payload();
      rememberAwsCreds({
        access_key_id: p.access_key_id,
        secret_access_key: p.secret_access_key,
        session_token: p.session_token,
        role_arn: p.role_arn,
        auth_mode: p.auth_mode,
        region: p.region,
        external_id: p.external_id,
      });
      await saveConnectionSettings(p);
      const res = await testConnectionSettings();
      setSettings(res.settings);
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
      setGcpSaJson("");
      setBanner({ type: res.ok ? "ok" : "error", text: res.message });
      setMode(res.settings.auth_mode);
      setRoleArn(res.settings.role_arn);
      setRegion(res.settings.region);
      await refreshConnection();
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Connection test failed",
      });
    } finally {
      setTesting(false);
    }
  };

  const onClearKeys = async () => {
    if (
      !confirm(
        "Remove stored cloud credentials from the VaultScan server?",
      )
    ) {
      return;
    }
    setClearing(true);
    setBanner(null);
    try {
      const res = await clearConnectionCredentials();
      setSettings(res.connection);
      setAccessKeyId("");
      setSecretKey("");
      setGcpSaJson("");
      setBanner({ type: "info", text: res.message });
      await refreshConnection();
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Could not clear credentials",
      });
    } finally {
      setClearing(false);
    }
  };

  const onSaveSchedule = async () => {
    setSavingSchedule(true);
    setBanner(null);
    try {
      const res = await saveScheduleSettings({
        enabled: schedEnabled,
        interval_minutes: intervalMinutes,
        email_enabled: emailEnabled,
        recipients,
        alert_when: alertWhen,
        include_finding_details: includeDetails,
      });
      applySchedule(res.settings);
      setBanner({ type: "ok", text: res.message });
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Could not save schedule",
      });
    } finally {
      setSavingSchedule(false);
    }
  };

  const onRunScheduleNow = async () => {
    setRunningSchedule(true);
    setBanner(null);
    try {
      const res = await runScheduleNow();
      if (res.settings) applySchedule(res.settings);
      const emailNote = res.email?.message ? ` · ${res.email.message}` : "";
      setBanner({
        type: "ok",
        text: `${res.message}${emailNote}`,
      });
      await bootstrap();
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Scheduled scan failed",
      });
    } finally {
      setRunningSchedule(false);
    }
  };

  const onTestEmail = async () => {
    setTestingEmail(true);
    setBanner(null);
    try {
      // Save first so SMTP credentials are on the server
      const saved = await saveScheduleSettings({
        enabled: schedEnabled,
        interval_minutes: intervalMinutes,
        email_enabled: emailEnabled,
        recipients,
        alert_when: alertWhen,
        include_finding_details: includeDetails,
      });
      applySchedule(saved.settings);
      const res = await testScheduleEmail();
      applySchedule(res.settings);
      setBanner({ type: "ok", text: res.message });
    } catch (e) {
      setBanner({
        type: "error",
        text: e instanceof Error ? e.message : "Test email failed",
      });
    } finally {
      setTestingEmail(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-20 font-mono text-xs text-muted-foreground">
        <Loader2 className="size-4 animate-spin" />
        Loading connection settings…
      </div>
    );
  }

  const isAws = provider === "aws";
  const isGcp = provider === "gcp";
  const needsKeys = isAws && authMode !== "simulate";
  const needsRole = isAws && authMode === "assume_role";

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      {/* Header */}
      <div className="rounded-lg border border-border bg-panel p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="flex size-10 items-center justify-center rounded-md bg-accent-blue/15 text-accent-blue">
              <Cloud className="size-5" />
            </div>
            <div>
              <h3 className="font-mono text-sm font-bold tracking-[0.12em] text-foreground">
                CLOUD CONNECTION
              </h3>
              <p className="mt-1 max-w-xl text-xs leading-relaxed text-muted-foreground">
                Choose a cloud provider, then connect securely. Credentials stay
                on the VaultScan server and are never shown in full after save.
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <StatusPill status={settings?.last_test_status ?? "never"} />
            {settings?.last_account_id && (
              <span className="font-mono text-[10px] text-muted-foreground">
                {isGcp ? "Project" : "Account"} {settings.last_account_id}
              </span>
            )}
            <span className="rounded-sm border border-border px-2 py-0.5 font-mono text-[10px] font-bold tracking-wider text-muted-foreground">
              {(settings?.provider || provider).toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {banner && (
        <div
          className={cn(
            "rounded-md border px-4 py-3 text-xs leading-relaxed",
            banner.type === "ok" &&
              "border-success/30 bg-success/10 text-success",
            banner.type === "error" &&
              "border-danger/30 bg-danger/10 text-danger",
            banner.type === "info" &&
              "border-accent-blue/30 bg-accent-blue/10 text-accent-blue",
          )}
        >
          {banner.text}
        </div>
      )}

      {/* 1. Provider selection */}
      <section className="rounded-lg border border-border bg-panel p-5">
        <div className="mb-4 flex items-center gap-2">
          <Cloud className="size-4 text-accent-blue" />
          <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            1. CLOUD PROVIDER
          </h4>
        </div>
        <p className="mb-4 text-[11px] text-muted-foreground">
          Select where VaultScan should connect. Each provider uses a different
          authentication method.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          {PROVIDERS.map((p) => {
            const active = provider === p.id;
            return (
              <button
                key={p.id}
                type="button"
                onClick={() => {
                  setProvider(p.id);
                  if (p.id === "gcp" && authMode === "assume_role") {
                    /* keep auth_mode for demo; GCP ignores assume_role fields */
                  }
                }}
                className={cn(
                  "rounded-lg border p-4 text-left transition",
                  active
                    ? "border-accent-blue/50 bg-accent-blue/10"
                    : "border-border bg-panel-alt hover:border-border-strong",
                )}
              >
                <div className="mb-2 flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-foreground">
                    {p.title}
                  </span>
                  <span
                    className={cn(
                      "rounded-sm px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-wider",
                      active
                        ? "bg-accent-blue/20 text-accent-blue"
                        : "bg-white/5 text-muted-foreground",
                    )}
                  >
                    {p.badge}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  {p.subtitle}
                </p>
                {active && (
                  <p className="mt-2 font-mono text-[10px] font-bold text-accent-blue">
                    SELECTED
                  </p>
                )}
              </button>
            );
          })}
        </div>
      </section>

      {/* Profile */}
      <section className="rounded-lg border border-border bg-panel p-5">
        <div className="mb-4 flex items-center gap-2">
          <BookOpen className="size-4 text-accent-blue" />
          <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            2. CONNECTION PROFILE
          </h4>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <FieldLabel
              label="DISPLAY NAME"
              hint="Friendly name in the dashboard (e.g. Production, Lab)."
            />
            <TextInput
              value={connectionName}
              onChange={setConnectionName}
              placeholder="Primary Cloud Account"
              mono={false}
            />
          </div>
          {isAws && (
            <div>
              <FieldLabel label="AWS REGION" required hint="Primary region for regional APIs." />
              <select
                value={region}
                onChange={(e) => setRegionLocal(e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-2.5 font-mono text-xs text-foreground outline-none focus:border-accent-blue/50"
              >
                {REGIONS.map((r) => (
                  <option key={r} value={r}>
                    {r}
                  </option>
                ))}
              </select>
            </div>
          )}
          {isGcp && (
            <div>
              <FieldLabel
                label="GCP PROJECT ID"
                required
                hint="Project ID from Google Cloud Console (not the display name)."
              />
              <TextInput
                value={gcpProjectId}
                onChange={setGcpProjectId}
                placeholder="my-project-123456"
              />
            </div>
          )}
        </div>
      </section>

      {/* AWS-only sections */}
      {isAws && (
        <>
          <section className="rounded-lg border border-border bg-panel p-5">
            <div className="mb-4 flex items-center gap-2">
              <Shield className="size-4 text-accent-blue" />
              <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                3. AWS CONNECTION METHOD
              </h4>
            </div>
            <div className="grid gap-3 md:grid-cols-3">
              {AUTH_OPTIONS.map((opt) => {
                const active = authMode === opt.id;
                return (
                  <button
                    key={opt.id}
                    type="button"
                    onClick={() => setAuthMode(opt.id)}
                    className={cn(
                      "rounded-md border p-4 text-left transition-colors",
                      active
                        ? "border-accent-blue/50 bg-accent-blue/10"
                        : "border-border bg-panel-alt hover:border-border-strong",
                    )}
                  >
                    <div className="mb-2 flex items-center justify-between gap-2">
                      <span className="text-xs font-semibold text-foreground">
                        {opt.title}
                      </span>
                      <span
                        className={cn(
                          "shrink-0 rounded-sm px-1.5 py-0.5 font-mono text-[9px] font-bold tracking-wider",
                          opt.recommended
                            ? "bg-success/15 text-success"
                            : "bg-white/5 text-muted-foreground",
                        )}
                      >
                        {opt.badge}
                      </span>
                    </div>
                    <p className="text-[11px] leading-relaxed text-muted-foreground">
                      {opt.description}
                    </p>
                  </button>
                );
              })}
            </div>
          </section>

          {needsRole && (
            <section className="rounded-lg border border-border bg-panel p-5">
              <div className="mb-4 flex items-center gap-2">
                <Shield className="size-4 text-accent-blue" />
                <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                  4. TARGET IAM ROLE
                </h4>
              </div>
              <div className="space-y-4">
                <div>
                  <FieldLabel
                    label="ROLE ARN"
                    required
                    hint="Must be an IAM Role (…:role/…), not a User ARN."
                  />
                  <TextInput
                    value={roleArn}
                    onChange={setRoleArnLocal}
                    placeholder="arn:aws:iam::123456789012:role/VaultScan-ReadOnly"
                  />
                  {roleArn.includes(":user/") && (
                    <p className="mt-2 rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-[11px] text-danger">
                      This looks like a User ARN. Use a Role ARN or switch to
                      Access keys (direct).
                    </p>
                  )}
                </div>
                <div>
                  <FieldLabel
                    label="EXTERNAL ID (OPTIONAL)"
                    hint="Only if the role trust policy requires ExternalId."
                  />
                  <TextInput
                    value={externalId}
                    onChange={setExternalId}
                    placeholder="vaultscan-external-id"
                  />
                </div>
              </div>
            </section>
          )}

          {needsKeys && (
            <section className="rounded-lg border border-border bg-panel p-5">
              <div className="mb-1 flex items-center gap-2">
                <KeyRound className="size-4 text-accent-blue" />
                <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
                  {needsRole ? "5." : "4."} AWS ACCESS CREDENTIALS
                </h4>
              </div>
              <p className="mb-4 text-[11px] leading-relaxed text-muted-foreground">
                IAM → Users → Security credentials → Create access key.
              </p>
              {settings?.credentials_configured && settings.provider === "aws" && (
                <div className="mb-4 flex items-start gap-2 rounded-md border border-success/20 bg-success/5 px-3 py-2.5 text-[11px] text-muted-foreground">
                  <Lock className="mt-0.5 size-3.5 shrink-0 text-success" />
                  <p>
                    Keys stored on server
                    {settings.access_key_id_masked
                      ? `: ${settings.access_key_id_masked}`
                      : ""}
                    . Leave fields blank to keep them.
                  </p>
                </div>
              )}
              <div className="space-y-4">
                <div>
                  <FieldLabel label="ACCESS KEY ID" required={!settings?.has_access_key} />
                  <TextInput
                    value={accessKeyId}
                    onChange={setAccessKeyId}
                    placeholder={
                      settings?.access_key_id_masked
                        ? `Stored: ${settings.access_key_id_masked}`
                        : "AKIA…"
                    }
                  />
                </div>
                <div>
                  <FieldLabel
                    label="SECRET ACCESS KEY"
                    required={!settings?.has_secret_key}
                  />
                  <div className="relative">
                    <TextInput
                      value={secretKey}
                      onChange={setSecretKey}
                      type={showSecret ? "text" : "password"}
                      placeholder={
                        settings?.has_secret_key
                          ? "•••••••• (leave blank to keep)"
                          : "Enter secret access key"
                      }
                      autoComplete="new-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowSecret((v) => !v)}
                      className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground hover:text-foreground"
                    >
                      {showSecret ? (
                        <EyeOff className="size-4" />
                      ) : (
                        <Eye className="size-4" />
                      )}
                    </button>
                  </div>
                </div>
                <div>
                  <FieldLabel
                    label="SESSION TOKEN (OPTIONAL)"
                    hint="Only for temporary credentials (SSO)."
                  />
                  <TextInput
                    value={sessionToken}
                    onChange={setSessionToken}
                    type="password"
                    placeholder="Optional"
                  />
                </div>
              </div>
            </section>
          )}
        </>
      )}

      {/* GCP section */}
      {isGcp && (
        <section className="rounded-lg border border-border bg-panel p-5">
          <div className="mb-1 flex items-center gap-2">
            <KeyRound className="size-4 text-accent-blue" />
            <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
              3. GOOGLE CLOUD CREDENTIALS
            </h4>
          </div>
          <p className="mb-4 text-[11px] leading-relaxed text-muted-foreground">
            Create a service account in{" "}
            <span className="text-foreground">
              GCP Console → IAM &amp; Admin → Service Accounts
            </span>
            , grant read-only roles (e.g. Viewer / Security Reviewer), then{" "}
            <span className="text-foreground">Keys → Add key → JSON</span> and
            paste the full file below.
          </p>
          {settings?.has_gcp_service_account && (
            <div className="mb-4 flex items-start gap-2 rounded-md border border-success/20 bg-success/5 px-3 py-2.5 text-[11px] text-muted-foreground">
              <Lock className="mt-0.5 size-3.5 shrink-0 text-success" />
              <p>
                Service account stored
                {settings.gcp_service_account_email_masked
                  ? `: ${settings.gcp_service_account_email_masked}`
                  : ""}
                . Leave JSON blank to keep it.
              </p>
            </div>
          )}
          <div>
            <FieldLabel
              label="SERVICE ACCOUNT JSON"
              required={!settings?.has_gcp_service_account}
              hint="Paste the entire JSON key file contents."
            />
            <textarea
              value={gcpSaJson}
              onChange={(e) => setGcpSaJson(e.target.value)}
              rows={8}
              placeholder={
                settings?.has_gcp_service_account
                  ? "••••  (leave blank to keep existing key)"
                  : '{\n  "type": "service_account",\n  "project_id": "...",\n  "private_key": "...",\n  "client_email": "...",\n  ...\n}'
              }
              className="w-full rounded-md border border-border bg-background px-3 py-2.5 font-mono text-[11px] leading-relaxed text-foreground outline-none placeholder:text-muted-foreground/40 focus:border-accent-blue/50"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <div className="mt-4 rounded-md border border-accent-blue/25 bg-accent-blue/5 px-3 py-2.5 text-[11px] text-muted-foreground">
            <p className="font-medium text-foreground">Note</p>
            <p className="mt-1">
              Connection + Test validate your GCP identity. Full Google Cloud
              misconfig checks use this profile as the connector; AWS remains the
              primary deep scan engine today. Demo mode still works for simulated
              findings on either provider.
            </p>
          </div>
        </section>
      )}

      {/* Demo for either provider */}
      {authMode === "simulate" && isAws && (
        <div className="rounded-md border border-accent-blue/30 bg-accent-blue/5 px-4 py-3 text-[11px] text-accent-blue">
          Demo mode selected — no live AWS credentials required. Launch scan to
          use simulated misconfigurations.
        </div>
      )}

      {settings?.guidance && settings.guidance.length > 0 && (
        <section className="space-y-2">
          {settings.guidance.map((g, i) => (
            <div
              key={i}
              className={cn(
                "flex items-start gap-2 rounded-md border px-3 py-2.5 text-[11px] leading-relaxed",
                g.level === "warning"
                  ? "border-warning/30 bg-warning/5 text-warning"
                  : "border-border bg-panel text-muted-foreground",
              )}
            >
              {g.level === "warning" ? (
                <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
              ) : (
                <Info className="mt-0.5 size-3.5 shrink-0 text-accent-blue" />
              )}
              <p>{g.text}</p>
            </div>
          ))}
        </section>
      )}

      {/* Actions */}
      <div className="flex flex-wrap items-center gap-3 border-t border-border pt-4">
        <button
          type="button"
          onClick={() => void onSave()}
          disabled={saving || testing}
          className="flex items-center gap-2 rounded-md bg-accent-blue px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-background transition hover:bg-accent-blue/90 disabled:opacity-50"
        >
          {saving ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : (
            <Save className="size-3.5" />
          )}
          SAVE CONNECTION
        </button>
        <button
          type="button"
          onClick={() => void onTest()}
          disabled={saving || testing}
          className="flex items-center gap-2 rounded-md border border-success/40 bg-success/10 px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-success transition hover:bg-success/15 disabled:opacity-50"
        >
          {testing ? (
            <Loader2 className="size-3.5 animate-spin" />
          ) : (
            <PlugZap className="size-3.5" />
          )}
          TEST CONNECTION
        </button>
        {settings?.credentials_configured && (
          <button
            type="button"
            onClick={() => void onClearKeys()}
            disabled={clearing}
            className="flex items-center gap-2 rounded-md border border-danger/30 px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-danger transition hover:bg-danger/10 disabled:opacity-50"
          >
            {clearing ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Trash2 className="size-3.5" />
            )}
            REMOVE KEYS
          </button>
        )}
        {settings?.last_tested_at && (
          <span className="ml-auto font-mono text-[10px] text-muted-foreground">
            Last test: {settings.last_tested_at}
          </span>
        )}
      </div>

      {/* Schedule + Gmail alerts */}
      <section className="rounded-lg border border-border bg-panel p-5">
        <div className="mb-1 flex items-center gap-2">
          <Clock className="size-4 text-accent-blue" />
          <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            SCHEDULED CHECKS &amp; GMAIL ALERTS
          </h4>
        </div>
        <p className="mb-4 max-w-2xl text-[11px] leading-relaxed text-muted-foreground">
          Automatically re-check the cloud on a timer, and email after{" "}
          <span className="text-foreground">Launch active scan</span> as well as
          scheduled runs. Alerts are sent as{" "}
          <span className="text-foreground">VaultScan Company</span> — you only enter
          your Gmail to receive them.
        </p>

        <div className="mb-4 grid gap-3 sm:grid-cols-2">
          <label className="flex cursor-pointer items-start gap-3 rounded-md border border-border bg-panel-alt p-3">
            <input
              type="checkbox"
              checked={schedEnabled}
              onChange={(e) => setSchedEnabled(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--accent-blue)]"
            />
            <span>
              <span className="block text-xs font-semibold text-foreground">
                Enable automatic scans
              </span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">
                Uses your saved Cloud Connection (real AWS or Demo).
              </span>
            </span>
          </label>
          <label className="flex cursor-pointer items-start gap-3 rounded-md border border-border bg-panel-alt p-3">
            <input
              type="checkbox"
              checked={emailEnabled}
              onChange={(e) => setEmailEnabled(e.target.checked)}
              className="mt-0.5 size-4 accent-[var(--accent-blue)]"
            />
            <span>
              <span className="block text-xs font-semibold text-foreground">
                Enable Gmail alerts
              </span>
              <span className="mt-0.5 block text-[11px] text-muted-foreground">
                Email after Launch active scan and scheduled checks (by alert rule).
              </span>
            </span>
          </label>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <FieldLabel
              label="CHECK EVERY (MINUTES)"
              hint="Any number of minutes you want — e.g. 7, 45, 90. Not limited to presets."
            />
            <div className="flex items-center gap-2">
              <input
                type="number"
                min={1}
                max={10080}
                step={1}
                value={intervalMinutes}
                onChange={(e) => {
                  const n = Number(e.target.value);
                  if (Number.isFinite(n)) {
                    setIntervalMinutes(Math.max(1, Math.min(10080, Math.floor(n))));
                  } else if (e.target.value === "") {
                    setIntervalMinutes(1);
                  }
                }}
                className="w-full rounded-md border border-border bg-background px-3 py-2.5 font-mono text-xs text-foreground outline-none focus:border-accent-blue/50"
              />
              <span className="shrink-0 font-mono text-[10px] tracking-wider text-muted-foreground">
                MIN
              </span>
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {INTERVAL_PRESETS.map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setIntervalMinutes(m)}
                  className={cn(
                    "rounded-sm border px-2 py-1 font-mono text-[10px] tracking-wider transition",
                    intervalMinutes === m
                      ? "border-accent-blue/50 bg-accent-blue/15 text-accent-blue"
                      : "border-border text-muted-foreground hover:border-border-strong hover:text-foreground",
                  )}
                >
                  {m}m
                </button>
              ))}
            </div>
            <p className="mt-1.5 text-[10px] text-muted-foreground">
              {intervalMinutes === 1
                ? "Every 1 minute"
                : intervalMinutes < 60
                  ? `Every ${intervalMinutes} minutes`
                  : intervalMinutes % 60 === 0
                    ? `Every ${intervalMinutes / 60} hour${intervalMinutes / 60 === 1 ? "" : "s"}`
                    : `Every ${intervalMinutes} minutes (~${(intervalMinutes / 60).toFixed(1)} h)`}
              {" · "}allowed 1–10080 (7 days)
            </p>
          </div>
          <div>
            <FieldLabel
              label="SEND ALERT WHEN"
              hint="Avoid inbox noise — only email when risk matches this rule."
            />
            <select
              value={alertWhen}
              onChange={(e) => setAlertWhen(e.target.value as AlertWhen)}
              className="w-full rounded-md border border-border bg-background px-3 py-2.5 font-mono text-xs text-foreground outline-none focus:border-accent-blue/50"
            >
              {ALERT_WHEN_OPTIONS.map((o) => (
                <option key={o.id} value={o.id}>
                  {o.label}
                </option>
              ))}
            </select>
            <p className="mt-1 text-[10px] text-muted-foreground">
              {ALERT_WHEN_OPTIONS.find((o) => o.id === alertWhen)?.hint}
            </p>
          </div>
        </div>

        <div className="mt-4">
          <FieldLabel
            label="YOUR GMAIL"
            hint="Where VaultScan should send alerts. Sender is always VaultScan Company (no password needed from you)."
          />
          <TextInput
            value={recipients}
            onChange={setRecipients}
            placeholder="you@gmail.com"
            mono={false}
            autoComplete="email"
          />
        </div>

        <label className="mt-4 flex cursor-pointer items-start gap-2">
          <input
            type="checkbox"
            checked={includeDetails}
            onChange={(e) => setIncludeDetails(e.target.checked)}
            className="mt-0.5 size-4 accent-[var(--accent-blue)]"
          />
          <span className="text-[11px] text-muted-foreground">
            Include top findings in the email (score + critical/high list).
          </span>
        </label>

        {(schedule?.guidance?.length ?? 0) > 0 && (
          <div className="mt-4 space-y-2">
            {schedule!.guidance.map((g, i) => (
              <div
                key={i}
                className={cn(
                  "flex items-start gap-2 rounded-md border px-3 py-2.5 text-[11px] leading-relaxed",
                  g.level === "warning"
                    ? "border-warning/30 bg-warning/5 text-warning"
                    : "border-border bg-panel-alt text-muted-foreground",
                )}
              >
                {g.level === "warning" ? (
                  <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                ) : (
                  <Info className="mt-0.5 size-3.5 shrink-0 text-accent-blue" />
                )}
                <p>{g.text}</p>
              </div>
            ))}
          </div>
        )}

        <div className="mt-4 flex flex-wrap items-center gap-3 border-t border-border pt-4">
          <button
            type="button"
            onClick={() => void onSaveSchedule()}
            disabled={savingSchedule}
            className="flex items-center gap-2 rounded-md bg-accent-blue px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-background transition hover:bg-accent-blue/90 disabled:opacity-50"
          >
            {savingSchedule ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Save className="size-3.5" />
            )}
            SAVE SCHEDULE
          </button>
          <button
            type="button"
            onClick={() => void onRunScheduleNow()}
            disabled={runningSchedule}
            className="flex items-center gap-2 rounded-md border border-accent-blue/40 bg-accent-blue/10 px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-accent-blue transition hover:bg-accent-blue/15 disabled:opacity-50"
          >
            {runningSchedule ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Play className="size-3.5" />
            )}
            RUN CHECK NOW
          </button>
          <button
            type="button"
            onClick={() => void onTestEmail()}
            disabled={testingEmail}
            className="flex items-center gap-2 rounded-md border border-border px-4 py-2.5 font-mono text-[11px] font-bold tracking-wider text-muted-foreground transition hover:border-border-strong hover:text-foreground disabled:opacity-50"
          >
            {testingEmail ? (
              <Loader2 className="size-3.5 animate-spin" />
            ) : (
              <Mail className="size-3.5" />
            )}
            SEND TEST EMAIL
          </button>
        </div>

        <div className="mt-4 grid gap-2 rounded-md border border-border bg-panel-alt p-3 font-mono text-[10px] text-muted-foreground sm:grid-cols-2">
          <p>
            Last auto-scan:{" "}
            <span className="text-foreground">
              {schedule?.last_run_at || "never"}
            </span>
            {schedule?.last_run_status && schedule.last_run_status !== "never"
              ? ` (${schedule.last_run_status})`
              : ""}
          </p>
          <p>
            Next run:{" "}
            <span className="text-foreground">
              {schedule?.next_run_at || "—"}
            </span>
          </p>
          <p>
            Last email:{" "}
            <span className="text-foreground">
              {schedule?.last_email_at || "never"}
            </span>
            {schedule?.last_email_status &&
            schedule.last_email_status !== "never"
              ? ` (${schedule.last_email_status})`
              : ""}
          </p>
          <p>
            Completed runs:{" "}
            <span className="text-foreground">{schedule?.run_count ?? 0}</span>
          </p>
          {schedule?.last_run_message && (
            <p className="sm:col-span-2 text-[10px] leading-relaxed">
              {schedule.last_run_message}
            </p>
          )}
          {schedule?.last_email_message && (
            <p className="sm:col-span-2 text-[10px] leading-relaxed">
              Email: {schedule.last_email_message}
            </p>
          )}
        </div>
      </section>
    </div>
  );
}
