"use client";

import { useState, useRef, useEffect } from "react";
import { Send, Sparkles, X, Loader2 } from "lucide-react";
import { chatWithGrok, summarizeScan } from "@/lib/api";
import { useLiveData } from "@/lib/scan-store";
import { cn } from "@/lib/utils";

type Msg = { role: "user" | "assistant"; content: string };

/** Circular robot mark — Creative Cloud–style floating toggle */
function CloudRobotIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 48 48"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={className}
      aria-hidden
    >
      {/* Antenna */}
      <circle cx="24" cy="6" r="2.5" fill="currentColor" />
      <path
        d="M24 8.5V13"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      {/* Head */}
      <rect
        x="10"
        y="13"
        width="28"
        height="22"
        rx="6"
        stroke="currentColor"
        strokeWidth="2.2"
      />
      {/* Eyes */}
      <circle cx="18.5" cy="23" r="2.8" fill="currentColor" />
      <circle cx="29.5" cy="23" r="2.8" fill="currentColor" />
      {/* Mouth */}
      <path
        d="M17 30.5h14"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      {/* Ears */}
      <path
        d="M10 22H7.5a1.5 1.5 0 0 0 0 3H10"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path
        d="M38 22h2.5a1.5 1.5 0 0 1 0 3H38"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      {/* Body hint */}
      <path
        d="M18 35v4a6 6 0 0 0 12 0v-4"
        stroke="currentColor"
        strokeWidth="2"
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

      {/* Top floating robot — Creative Cloud style */}
      <button
        type="button"
        onClick={toggle}
        aria-expanded={open}
        aria-label={open ? "Close Cloud Assistant" : "Open Cloud Assistant"}
        title="Cloud Assistant"
        className={cn(
          "cloud-assistant-fab fixed z-[60] flex size-14 items-center justify-center rounded-full border-2 shadow-xl transition-all duration-300",
          "right-5 top-4 sm:right-6 sm:top-5",
          open
            ? "border-accent-blue bg-accent-blue text-background"
            : "border-accent-blue/50 bg-panel text-accent-blue hover:border-accent-blue hover:bg-accent-blue/15",
        )}
      >
        <span
          className={cn(
            "cloud-robot-spin flex items-center justify-center transition-transform duration-500 ease-out",
            open && "rotate-[180deg] scale-110",
          )}
        >
          <CloudRobotIcon className="size-7" />
        </span>
        {/* Online pulse ring */}
        {!open && (
          <span className="pointer-events-none absolute -right-0.5 -top-0.5 size-3 rounded-full border-2 border-panel bg-success" />
        )}
      </button>

      {/* Label chip under FAB when closed (desktop) */}
      {!open && (
        <div className="pointer-events-none fixed right-5 top-[4.75rem] z-[60] hidden sm:right-6 sm:block">
          <span className="rounded-md border border-border bg-panel/95 px-2 py-1 font-mono text-[9px] font-bold tracking-[0.14em] text-muted-foreground shadow-lg backdrop-blur">
            CLOUD ASSISTANT
          </span>
        </div>
      )}
    </>
  );
}
