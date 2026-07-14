"use client";

import { useEffect, useState } from "react";
import { motion } from "motion/react";
import { Eye, EyeOff, Loader2, Lock, Shield, User } from "lucide-react";
import { getAuthInfo, loginRequest } from "@/lib/api";
import {
  getRememberedUsername,
  saveSession,
} from "@/lib/auth";
import { cn } from "@/lib/utils";

export function LoginPage({ onSuccess }: { onSuccess: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hint, setHint] = useState<string | null>(null);

  useEffect(() => {
    setUsername(getRememberedUsername());
    void getAuthInfo()
      .then((info) => {
        if (info.hint) setHint(info.hint);
      })
      .catch(() => {
        /* offline / API down — still allow form */
      });
  }, []);

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await loginRequest({
        username: username.trim(),
        password,
        remember,
      });
      saveSession({
        token: res.token,
        username: res.username,
        display_name: res.display_name,
        role: res.role,
        expires_at: res.expires_at,
        remember: res.remember,
      });
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sign-in failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-background px-4 py-12">
      {/* Background grid + glow */}
      <div
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{
          backgroundImage:
            "linear-gradient(rgba(56,116,255,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(56,116,255,0.06) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />
      <div
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            "radial-gradient(ellipse 50% 40% at 50% 30%, rgba(56,116,255,0.18), transparent 70%)",
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 18, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
        className="relative z-10 w-full max-w-[420px]"
      >
        <div className="mb-8 flex flex-col items-center text-center">
          <div className="mb-4 flex size-14 items-center justify-center rounded-xl bg-accent-blue shadow-[0_0_40px_rgba(56,116,255,0.45)]">
            <Shield className="size-7 text-background" strokeWidth={2.2} />
          </div>
          <h1 className="font-mono text-xl font-bold tracking-[0.22em] text-foreground">
            VAULTSCAN
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Sign in to the cloud security console
          </p>
        </div>

        <form
          onSubmit={(e) => void onSubmit(e)}
          className="rounded-xl border border-border bg-panel/90 p-6 shadow-[0_20px_60px_rgba(0,0,0,0.45)] backdrop-blur"
        >
          <p className="mb-5 font-mono text-[10px] tracking-[0.2em] text-accent-blue">
            SECURE ACCESS
          </p>

          {error && (
            <div className="mb-4 rounded-md border border-danger/30 bg-danger/10 px-3 py-2.5 text-xs text-danger">
              {error}
            </div>
          )}

          <label className="mb-4 block">
            <span className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] font-bold tracking-[0.14em] text-muted-foreground">
              <User className="size-3" />
              USERNAME
            </span>
            <input
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin"
              required
              className="w-full rounded-md border border-border bg-background px-3 py-2.5 text-sm text-foreground outline-none transition placeholder:text-muted-foreground/40 focus:border-accent-blue/50"
            />
          </label>

          <label className="mb-4 block">
            <span className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] font-bold tracking-[0.14em] text-muted-foreground">
              <Lock className="size-3" />
              PASSWORD
            </span>
            <div className="relative">
              <input
                type={showPw ? "text" : "password"}
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                className="w-full rounded-md border border-border bg-background px-3 py-2.5 pr-10 text-sm text-foreground outline-none transition placeholder:text-muted-foreground/40 focus:border-accent-blue/50"
              />
              <button
                type="button"
                onClick={() => setShowPw((v) => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                aria-label="Toggle password"
              >
                {showPw ? (
                  <EyeOff className="size-4" />
                ) : (
                  <Eye className="size-4" />
                )}
              </button>
            </div>
          </label>

          <label className="mb-5 flex cursor-pointer items-center gap-2">
            <input
              type="checkbox"
              checked={remember}
              onChange={(e) => setRemember(e.target.checked)}
              className="size-4 accent-[var(--accent-blue)]"
            />
            <span className="text-xs text-muted-foreground">
              Keep me signed in (don&apos;t ask for password every time)
            </span>
          </label>

          <button
            type="submit"
            disabled={loading}
            className={cn(
              "flex w-full items-center justify-center gap-2 rounded-md bg-accent-blue py-3 font-mono text-[11px] font-bold tracking-[0.16em] text-background transition hover:bg-accent-blue/90 disabled:opacity-60",
            )}
          >
            {loading ? (
              <Loader2 className="size-4 animate-spin" />
            ) : (
              <Shield className="size-3.5" />
            )}
            {loading ? "SIGNING IN…" : "SIGN IN"}
          </button>

          {hint && (
            <p className="mt-4 text-center text-[11px] leading-relaxed text-muted-foreground">
              {hint}
            </p>
          )}
        </form>

        <p className="mt-6 text-center font-mono text-[10px] tracking-wider text-muted-foreground/70">
          Cloud keys stay saved in Settings after you connect once.
        </p>
      </motion.div>
    </div>
  );
}
