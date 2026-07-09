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
} from "lucide-react";
import {
  getConnectionSettings,
  saveConnectionSettings,
  testConnectionSettings,
  clearConnectionCredentials,
  type ConnectionSettings,
  type ScanMode,
} from "@/lib/api";
import { useScanStore } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

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
      "VaultScan uses your Access Key only to assume a read-only IAM Role in the target account. Short-lived credentials are used for scanning — industry standard for CSPM platforms.",
  },
  {
    id: "direct",
    title: "Access keys (direct)",
    badge: "Simple",
    description:
      "Scan with the Access Key itself. Faster to set up for a single account, but less ideal for multi-account production.",
  },
  {
    id: "simulate",
    title: "Demo environment",
    badge: "No AWS required",
    description:
      "Run against a simulated vulnerable cloud. Perfect for demos and training without connecting a real account.",
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
      <div className="flex items-center gap-2">
        <label className="font-mono text-[11px] font-bold tracking-[0.12em] text-foreground">
          {label}
          {required && <span className="ml-1 text-danger">*</span>}
        </label>
      </div>
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

  // Form state
  const [connectionName, setConnectionName] = useState("Primary AWS Account");
  const [authMode, setAuthMode] = useState<ScanMode>("assume_role");
  const [roleArn, setRoleArnLocal] = useState("");
  const [externalId, setExternalId] = useState("");
  const [region, setRegionLocal] = useState("us-east-1");
  const [accessKeyId, setAccessKeyId] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [sessionToken, setSessionToken] = useState("");

  const load = async () => {
    setLoading(true);
    try {
      const s = await getConnectionSettings();
      setSettings(s);
      setConnectionName(s.connection_name);
      setAuthMode(s.auth_mode);
      setRoleArnLocal(s.role_arn || "");
      setExternalId(s.external_id || "");
      setRegionLocal(s.region || "us-east-1");
      // Never prefill secret; access key stays empty unless user re-enters
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
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

  const onSave = async () => {
    setSaving(true);
    setBanner(null);
    try {
      const res = await saveConnectionSettings({
        connection_name: connectionName,
        auth_mode: authMode,
        role_arn: roleArn,
        external_id: externalId,
        region,
        access_key_id: accessKeyId || undefined,
        secret_access_key: secretKey || undefined,
        session_token: sessionToken || undefined,
      });
      setSettings(res.connection);
      setMode(res.connection.auth_mode);
      setRoleArn(res.connection.role_arn);
      setRegion(res.connection.region);
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
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
      // Save first so test uses current form values
      await saveConnectionSettings({
        connection_name: connectionName,
        auth_mode: authMode,
        role_arn: roleArn,
        external_id: externalId,
        region,
        access_key_id: accessKeyId || undefined,
        secret_access_key: secretKey || undefined,
        session_token: sessionToken || undefined,
      });
      const res = await testConnectionSettings();
      setSettings(res.settings);
      setAccessKeyId("");
      setSecretKey("");
      setSessionToken("");
      setBanner({
        type: res.ok ? "ok" : "error",
        text: res.message,
      });
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
        "Remove stored Access Key and Secret from the VaultScan server? You can add new keys later.",
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

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-2 py-20 font-mono text-xs text-muted-foreground">
        <Loader2 className="size-4 animate-spin" />
        Loading connection settings…
      </div>
    );
  }

  const needsKeys = authMode !== "simulate";
  const needsRole = authMode === "assume_role";

  return (
    <div className="mx-auto max-w-4xl space-y-5">
      {/* Header card */}
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
                Connect an AWS account so VaultScan can discover misconfigurations.
                Credentials stay on the VaultScan server and are never exposed in
                full after you save them.
              </p>
            </div>
          </div>
          <div className="flex flex-col items-end gap-2">
            <StatusPill status={settings?.last_test_status ?? "never"} />
            {settings?.last_account_id && (
              <span className="font-mono text-[10px] text-muted-foreground">
                Account {settings.last_account_id}
              </span>
            )}
            {settings?.access_key_id_masked && (
              <span className="font-mono text-[10px] text-muted-foreground">
                Key {settings.access_key_id_masked}
              </span>
            )}
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

      {/* Connection method */}
      <section className="rounded-lg border border-border bg-panel p-5">
        <div className="mb-4 flex items-center gap-2">
          <Shield className="size-4 text-accent-blue" />
          <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
            1. CONNECTION METHOD
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
              hint="A friendly name shown in the dashboard (e.g. Production, Staging)."
            />
            <TextInput
              value={connectionName}
              onChange={setConnectionName}
              placeholder="Primary AWS Account"
              mono={false}
            />
          </div>
          <div>
            <FieldLabel
              label="AWS REGION"
              hint="Primary region used for regional services (EC2, RDS, etc.)."
              required
            />
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
        </div>
      </section>

      {/* Role */}
      {needsRole && (
        <section className="rounded-lg border border-border bg-panel p-5">
          <div className="mb-4 flex items-center gap-2">
            <Shield className="size-4 text-accent-blue" />
            <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
              3. TARGET IAM ROLE
            </h4>
          </div>
          <div className="space-y-4">
            <div>
              <FieldLabel
                label="ROLE ARN"
                required
                hint="Must be an IAM Role (contains :role/), not an IAM User (:user/). Example: arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role"
              />
              <TextInput
                value={roleArn}
                onChange={setRoleArnLocal}
                placeholder="arn:aws:iam::850919910218:role/demo-test-vulnerable-ec2-role"
              />
              {roleArn.includes(":user/") && (
                <p className="mt-2 rounded-md border border-danger/30 bg-danger/10 px-3 py-2 text-[11px] leading-relaxed text-danger">
                  This looks like a <strong>User</strong> ARN. You cannot
                  AssumeRole on a user. Either paste a{" "}
                  <strong>Role</strong> ARN (…:role/Name), or switch connection
                  method to <strong>Access keys (direct)</strong> if scanning as
                  this user.
                </p>
              )}
            </div>
            <div>
              <FieldLabel
                label="EXTERNAL ID (OPTIONAL)"
                hint="Shared secret if the role trust policy requires sts:ExternalId. Leave blank if not used."
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

      {/* Credentials */}
      {needsKeys && (
        <section className="rounded-lg border border-border bg-panel p-5">
          <div className="mb-1 flex items-center gap-2">
            <KeyRound className="size-4 text-accent-blue" />
            <h4 className="font-mono text-xs font-bold tracking-[0.14em] text-foreground">
              {needsRole ? "4." : "3."} AWS ACCESS CREDENTIALS
            </h4>
          </div>
          <p className="mb-4 text-[11px] leading-relaxed text-muted-foreground">
            Create these in the{" "}
            <span className="text-foreground">AWS Console → IAM → Users → Security credentials → Create access key</span>
            . Prefer a dedicated user with only the permissions VaultScan needs
            {needsRole ? " (typically sts:AssumeRole on the role above)." : "."}
          </p>

          {settings?.credentials_configured && (
            <div className="mb-4 flex items-start gap-2 rounded-md border border-success/20 bg-success/5 px-3 py-2.5 text-[11px] text-muted-foreground">
              <Lock className="mt-0.5 size-3.5 shrink-0 text-success" />
              <div>
                <p className="font-medium text-foreground">
                  Credentials are already stored on the server
                </p>
                <p className="mt-0.5">
                  Access Key:{" "}
                  <span className="font-mono text-foreground">
                    {settings.access_key_id_masked}
                  </span>
                  . Leave the fields below empty to keep the current secret, or
                  enter new values to replace them.
                </p>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <FieldLabel
                label="ACCESS KEY ID"
                required={!settings?.has_access_key}
                hint="Public identifier starting with AKIA… (or ASIA… for temporary keys)."
              />
              <TextInput
                value={accessKeyId}
                onChange={setAccessKeyId}
                placeholder={
                  settings?.access_key_id_masked
                    ? `Stored: ${settings.access_key_id_masked} — enter new to replace`
                    : "AKIA…"
                }
                autoComplete="off"
              />
            </div>
            <div>
              <FieldLabel
                label="SECRET ACCESS KEY"
                required={!settings?.has_secret_key}
                hint="Private secret shown only once when the key is created in AWS. Treat it like a password."
              />
              <div className="relative">
                <TextInput
                  value={secretKey}
                  onChange={setSecretKey}
                  type={showSecret ? "text" : "password"}
                  placeholder={
                    settings?.has_secret_key
                      ? "••••••••  (leave blank to keep existing)"
                      : "Enter secret access key"
                  }
                  autoComplete="new-password"
                />
                <button
                  type="button"
                  onClick={() => setShowSecret((v) => !v)}
                  className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1.5 text-muted-foreground hover:text-foreground"
                  aria-label={showSecret ? "Hide secret" : "Show secret"}
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
                hint="Only needed for temporary credentials (SSO / assumed sessions). Leave blank for standard long-lived IAM user keys."
              />
              <TextInput
                value={sessionToken}
                onChange={setSessionToken}
                type="password"
                placeholder={
                  settings?.has_session_token
                    ? "••••  (leave blank to keep existing)"
                    : "Optional"
                }
                autoComplete="off"
              />
            </div>
          </div>
        </section>
      )}

      {/* Guidance */}
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

      {/* How to create keys */}
      <section className="rounded-lg border border-border bg-panel p-5">
        <h4 className="mb-3 font-mono text-xs font-bold tracking-[0.14em] text-foreground">
          HOW TO CREATE AWS ACCESS KEYS
        </h4>
        <ol className="list-decimal space-y-2 pl-5 text-xs leading-relaxed text-muted-foreground">
          <li>
            Sign in to the{" "}
            <span className="text-foreground">AWS Management Console</span>.
          </li>
          <li>
            Open <span className="text-foreground">IAM → Users</span> and select
            (or create) a dedicated user such as{" "}
            <span className="font-mono text-foreground">vaultscan-connector</span>.
          </li>
          <li>
            Open <span className="text-foreground">Security credentials</span> →{" "}
            <span className="text-foreground">Create access key</span>. Choose
            “Application running outside AWS” or “CLI”.
          </li>
          <li>
            Copy the <span className="text-foreground">Access key ID</span> and{" "}
            <span className="text-foreground">Secret access key</span> into the
            fields above. The secret is shown only once.
          </li>
          <li>
            {needsRole
              ? "Ensure the role’s trust policy allows this user (or account) to assume it, and grant the user sts:AssumeRole on that Role ARN."
              : "Attach least-privilege read policies (e.g. SecurityAudit) to the user."}
          </li>
          <li>
            Click <span className="text-foreground">Test connection</span>, then{" "}
            <span className="text-foreground">Save</span>.
          </li>
        </ol>
      </section>

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
    </div>
  );
}
