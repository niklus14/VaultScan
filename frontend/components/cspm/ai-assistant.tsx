"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Sparkles, X, Loader2 } from "lucide-react";
import { motion } from "motion/react";
import { chatWithGrok, summarizeScan } from "@/lib/api";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

type Msg = { role: "user" | "assistant"; content: string };

const HELP_BUBBLES = [
  "Need a hand?",
  "Do you need help?",
  "Ask me about findings!",
  "Want a risk summary?",
  "I can explain attack paths",
  "Stuck on a fix? Ask me",
  "Ready when you are ✨",
];

/** Animated robot face — blinks, smiles, turns */
function CloudRobotIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 64 64"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("ca-robot-face", className)}
      aria-hidden
    >
      {/* Antenna */}
      <circle className="ca-antenna-dot" cx="32" cy="8" r="3.2" fill="currentColor" />
      <path
        d="M32 11.5V18"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      {/* Ears */}
      <path
        d="M14 30H10a2 2 0 0 0 0 4h4"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      <path
        d="M50 30h4a2 2 0 0 1 0 4h-4"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
      {/* Head */}
      <rect
        x="14"
        y="18"
        width="36"
        height="28"
        rx="9"
        stroke="currentColor"
        strokeWidth="2.6"
        fill="currentColor"
        fillOpacity="0.08"
      />
      {/* Eyes — blink via CSS scaleY */}
      <g className="ca-eyes">
        <ellipse className="ca-eye" cx="25" cy="31" rx="4" ry="4.2" fill="currentColor" />
        <ellipse className="ca-eye" cx="39" cy="31" rx="4" ry="4.2" fill="currentColor" />
        {/* Shine dots */}
        <circle cx="26.5" cy="29.5" r="1.1" fill="var(--background, #0b0c10)" className="ca-eye-shine" />
        <circle cx="40.5" cy="29.5" r="1.1" fill="var(--background, #0b0c10)" className="ca-eye-shine" />
      </g>
      {/* Smile */}
      <path
        className="ca-smile"
        d="M24 40.5c2.2 3.2 5.5 4.8 8 4.8s5.8-1.6 8-4.8"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
        fill="none"
      />
      {/* Body hint */}
      <path
        d="M24 46v5a8 8 0 0 0 16 0v-5"
        stroke="currentColor"
        strokeWidth="2.4"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function AiAssistant() {
  const { scanId, isLive, config } = useLiveData();
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([
    {
      role: "assistant",
      content:
        "Hi — I'm **Cloud Assistant**, your VaultScan security analyst.\n\nAsk about misconfigurations, compliance, attack paths, or remediation steps. After a scan, use **Summarize scan** for an executive brief.",
    },
  ]);
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, open, busy]);

  useEffect(() => {
    if (open) {
      const t = setTimeout(() => inputRef.current?.focus(), 280);
      return () => clearTimeout(t);
    }
  }, [open]);

  // Escape closes panel
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  const send = async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || busy) return;
    const next: Msg[] = [...messages, { role: "user", content: trimmed }];
    setMessages(next);
    setInput("");
    setBusy(true);
    try {
      const history = next
        .filter((m) => m.role === "user" || m.role === "assistant")
        .slice(0, -1)
        .map((m) => ({ role: m.role, content: m.content }));
      const res = await chatWithGrok({
        message: trimmed,
        history,
        scan_id: isLive ? scanId : undefined,
      });
      setMessages((m) => [...m, { role: "assistant", content: res.reply }]);
    } catch (e) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `Sorry — I couldn't complete that request. ${
            e instanceof Error ? e.message : "Please try again."
          }`,
        },
      ]);
    } finally {
      setBusy(false);
    }
  };

  const onSummarize = async () => {
    if (busy) return;
    setBusy(true);
    setMessages((m) => [
      ...m,
      { role: "user", content: "Summarize the latest scan for me." },
    ]);
    try {
      const res = await summarizeScan(isLive ? scanId : undefined);
      setMessages((m) => [...m, { role: "assistant", content: res.summary }]);
    } catch (e) {
      setMessages((m) => [
        ...m,
        {
          role: "assistant",
          content: `Could not summarize: ${
            e instanceof Error ? e.message : "run a scan first, then try again."
          }`,
        },
      ]);
    } finally {
      setBusy(false);
    }
  };

  const toggle = () => setOpen((v) => !v);

  return (
    <>
      {/* Dim backdrop when open — click to close */}
      <div
        className={cn(
          "fixed inset-0 z-40 bg-black/45 backdrop-blur-[2px] transition-opacity duration-300",
          open
            ? "pointer-events-auto opacity-100"
            : "pointer-events-none opacity-0",
        )}
        onClick={() => setOpen(false)}
        aria-hidden={!open}
      />

      {/* Half-screen panel — slides from the right */}
      <aside
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex w-full flex-col border-l border-border bg-panel shadow-2xl transition-transform duration-300 ease-out",
          "sm:w-1/2",
          open ? "translate-x-0" : "translate-x-full",
        )}
        aria-hidden={!open}
        aria-label="Cloud Assistant"
      >
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border bg-panel-alt px-5 py-4">
          <div className="flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-full border border-accent-blue/40 bg-accent-blue/15 text-accent-blue">
              <CloudRobotIcon className="size-6" />
            </div>
            <div>
              <p className="font-mono text-sm font-bold tracking-[0.14em] text-foreground">
                CLOUD ASSISTANT
              </p>
              <p className="font-mono text-[11px] text-muted-foreground">
                VaultScan security analyst
                {config?.grok_enabled === false ? " · offline" : " · online"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void onSummarize()}
              disabled={busy}
              className="flex items-center gap-1.5 rounded-md border border-accent-blue/40 bg-accent-blue/10 px-3 py-1.5 font-mono text-[11px] font-bold tracking-wider text-accent-blue transition hover:bg-accent-blue/20 disabled:opacity-50"
              title="Summarize latest scan"
            >
              <Sparkles className="size-3.5" />
              SUMMARIZE SCAN
            </button>
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="flex size-9 items-center justify-center rounded-md border border-border text-muted-foreground transition hover:bg-white/5 hover:text-foreground"
              aria-label="Close Cloud Assistant"
            >
              <X className="size-4" />
            </button>
          </div>
        </div>

        {/* Messages — larger, readable */}
        <div className="flex-1 space-y-4 overflow-y-auto px-5 py-5">
          {messages.map((m, i) => (
            <div
              key={i}
              className={cn(
                "max-w-[95%] rounded-lg border px-4 py-3 text-[13px] leading-relaxed sm:text-sm",
                m.role === "user"
                  ? "ml-auto border-accent-blue/35 bg-accent-blue/10 text-foreground"
                  : "mr-auto border-border bg-panel-alt text-foreground/90",
              )}
            >
              <p className="mb-1.5 font-mono text-[10px] font-bold tracking-[0.16em] text-muted-foreground">
                {m.role === "user" ? "YOU" : "CLOUD ASSISTANT"}
              </p>
              <div className="whitespace-pre-wrap break-words">{m.content}</div>
            </div>
          ))}
          {busy && (
            <div className="flex items-center gap-2 px-1 font-mono text-xs text-muted-foreground">
              <Loader2 className="size-3.5 animate-spin text-accent-blue" />
              Analyzing…
            </div>
          )}
          <div ref={bottomRef} />
        </div>

        {/* Composer */}
        <form
          className="border-t border-border bg-panel-alt p-4"
          onSubmit={(e) => {
            e.preventDefault();
            void send(input);
          }}
        >
          <div className="flex items-end gap-3">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send(input);
                }
              }}
              rows={3}
              placeholder="Ask about findings, CIS controls, remediations…"
              className="min-h-[72px] flex-1 resize-none rounded-lg border border-border bg-background px-4 py-3 text-sm leading-relaxed text-foreground outline-none transition placeholder:text-muted-foreground/50 focus:border-accent-blue/50"
              disabled={busy}
            />
            <button
              type="submit"
              disabled={busy || !input.trim()}
              className="flex h-[72px] w-12 shrink-0 items-center justify-center rounded-lg bg-accent-blue text-background transition hover:bg-accent-blue/90 disabled:opacity-40"
              aria-label="Send message"
            >
              <Send className="size-5" />
            </button>
          </div>
          <p className="mt-2 font-mono text-[10px] text-muted-foreground">
            Enter to send · Shift+Enter for new line · Esc to close
          </p>
        </form>
      </aside>

      {/* Top floating robot — Y-axis turn-around (not flat spin) */}
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-label={open ? "Close Cloud Assistant" : "Open Cloud Assistant"}
        title="Cloud Assistant"
        className={cn(
          "cloud-assistant-fab fixed z-[60] flex size-[5rem] items-center justify-center rounded-full border-2 shadow-xl transition-colors duration-300 sm:size-[5.25rem]",
          "right-4 top-3 sm:right-5 sm:top-4",
          open
            ? "border-accent-blue bg-accent-blue text-background"
            : "border-accent-blue/50 bg-panel text-accent-blue hover:border-accent-blue hover:bg-accent-blue/15",
        )}
        style={{ perspective: 900 }}
      >
        <motion.span
          className="cloud-robot-spin flex items-center justify-center will-change-transform"
          style={{ transformStyle: "preserve-3d" }}
          animate={
            open
              ? { rotateY: 0, scale: 1.08 }
              : {
                  // Face → sweep around → face again (bottom-arrow “turn around”)
                  rotateY: [0, 0, 90, 180, 270, 360, 360],
                  scale: 1,
                }
          }
          transition={
            open
              ? { type: "spring", stiffness: 260, damping: 22 }
              : {
                  rotateY: {
                    duration: 5.2,
                    times: [0, 0.28, 0.4, 0.52, 0.64, 0.76, 1],
                    repeat: Infinity,
                    ease: "easeInOut",
                  },
                  scale: { duration: 0.25 },
                }
          }
        >
          <CloudRobotIcon className="size-12 sm:size-[3.35rem]" />
        </motion.span>
        {/* Online pulse ring */}
        {!open && (
          <span className="pointer-events-none absolute right-0.5 top-0.5 size-3.5 rounded-full border-2 border-panel bg-success" />
        )}
      </button>

      {/* Label chip under FAB when closed (desktop) */}
      {!open && (
        <div className="pointer-events-none fixed right-4 top-[6.1rem] z-[60] hidden sm:right-5 sm:block">
          <span className="rounded-md border border-border bg-panel/95 px-2 py-1 font-mono text-[9px] font-bold tracking-[0.14em] text-muted-foreground shadow-lg backdrop-blur">
            CLOUD ASSISTANT
          </span>
        </div>
      )}
    </>
  );
}
