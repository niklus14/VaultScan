"use client";

import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import { Landing } from "@/components/cspm/landing";
import { Dashboard } from "@/components/cspm/dashboard";
import { LoginPage } from "@/components/cspm/login";
import { authMe } from "@/lib/api";
import { clearSession, getToken, getStoredUser } from "@/lib/auth";

type View = "loading" | "login" | "landing" | "transition" | "dashboard";

export default function Page() {
  const [view, setView] = useState<View>("loading");

  useEffect(() => {
    let cancelled = false;
    const boot = async () => {
      const token = getToken();
      if (!token) {
        if (!cancelled) setView("login");
        return;
      }
      try {
        await authMe();
        if (!cancelled) setView("landing");
      } catch {
        clearSession();
        if (!cancelled) setView("login");
      }
    };
    void boot();
    return () => {
      cancelled = true;
    };
  }, []);

  const enterDashboard = useCallback(() => {
    setView("transition");
    window.setTimeout(() => setView("dashboard"), 900);
  }, []);

  const onLoginSuccess = useCallback(() => {
    setView("landing");
  }, []);

  const onLogout = useCallback(() => {
    clearSession();
    setView("login");
  }, []);

  if (view === "loading") {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-3 bg-background">
        <div className="size-10 animate-pulse rounded-lg bg-accent-blue/30" />
        <p className="font-mono text-[10px] tracking-[0.24em] text-muted-foreground">
          CHECKING SESSION…
        </p>
      </div>
    );
  }

  return (
    <div className="relative min-h-screen bg-background">
      <AnimatePresence mode="wait">
        {view === "login" && (
          <motion.div
            key="login"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.35 }}
          >
            <LoginPage onSuccess={onLoginSuccess} />
          </motion.div>
        )}

        {view === "landing" && (
          <motion.div
            key="landing"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, scale: 1.02, filter: "blur(6px)" }}
            transition={{ duration: 0.45, ease: [0.22, 1, 0.36, 1] }}
          >
            <Landing onEnter={enterDashboard} />
          </motion.div>
        )}

        {view === "transition" && (
          <motion.div
            key="transition"
            className="fixed inset-0 z-[100] flex items-center justify-center overflow-hidden bg-background"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.25 }}
          >
            <motion.div
              className="absolute size-24 rounded-full border border-accent-blue/40"
              initial={{ scale: 0.4, opacity: 1 }}
              animate={{ scale: 12, opacity: 0 }}
              transition={{ duration: 0.9, ease: [0.22, 1, 0.36, 1] }}
            />
            <motion.div
              className="absolute size-24 rounded-full border border-success/30"
              initial={{ scale: 0.3, opacity: 0.8 }}
              animate={{ scale: 10, opacity: 0 }}
              transition={{ duration: 0.95, delay: 0.08, ease: [0.22, 1, 0.36, 1] }}
            />
            <motion.div
              className="absolute inset-y-0 left-0 w-full bg-gradient-to-r from-accent-blue/20 via-panel to-background"
              initial={{ x: "-100%" }}
              animate={{ x: "100%" }}
              transition={{ duration: 0.85, ease: [0.65, 0, 0.35, 1] }}
            />
            <motion.div
              className="relative z-10 flex flex-col items-center gap-3"
              initial={{ opacity: 0, y: 12, scale: 0.92 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.4 }}
            >
              <motion.div
                className="flex size-14 items-center justify-center rounded-xl bg-accent-blue shadow-[0_0_40px_rgba(56,116,255,0.5)]"
                animate={{ rotate: [0, 8, -8, 0] }}
                transition={{ duration: 0.7 }}
              >
                <svg
                  viewBox="0 0 24 24"
                  className="size-7 text-background"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                >
                  <path d="M12 3 L20 6.5 V12 C20 16.5 16.5 20.2 12 21.5 C7.5 20.2 4 16.5 4 12 V6.5 L12 3 Z" />
                </svg>
              </motion.div>
              <p className="font-mono text-[11px] font-bold tracking-[0.28em] text-foreground">
                VAULTSCAN
              </p>
              <p className="font-mono text-[10px] tracking-[0.2em] text-muted-foreground">
                {getStoredUser()?.display_name
                  ? `WELCOME ${getStoredUser()?.display_name?.toUpperCase()}`
                  : "INITIALIZING CONSOLE…"}
              </p>
              <div className="mt-2 h-0.5 w-40 overflow-hidden rounded-full bg-border">
                <motion.div
                  className="h-full bg-accent-blue"
                  initial={{ width: "0%" }}
                  animate={{ width: "100%" }}
                  transition={{ duration: 0.8, ease: "easeInOut" }}
                />
              </div>
            </motion.div>
          </motion.div>
        )}

        {view === "dashboard" && (
          <motion.div
            key="dashboard"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
            className="min-h-screen"
          >
            <Dashboard onLogout={onLogout} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
