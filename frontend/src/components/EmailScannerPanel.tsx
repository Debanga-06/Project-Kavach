import { useState, type FormEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import HUDFrame from "./HUDFrame";
import { useAuth } from "../lib/auth-context";
import { scanEmail, apiErrorMessage, type ScanResult } from "../lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  SAFE: "#00E5FF",
  LOW: "#00E5FF",
  SUSPICIOUS: "#7C3AED",
  HIGH: "#FF2D78",
  CRITICAL: "#FF2D78",
};

export default function EmailScannerPanel({ onScanned }: { onScanned?: () => void }) {
  const { accessToken } = useAuth();
  const [sender, setSender] = useState("");
  const [subject, setSubject] = useState("");
  const [body, setBody] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!accessToken) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await scanEmail(accessToken, sender, subject, body);
      setResult(res);
      onScanned?.();
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  const color = result ? SEVERITY_COLOR[result.severity] ?? "#00E5FF" : "#00E5FF";

  return (
    <HUDFrame className="p-6">
      <div className="flex items-center justify-between mb-4">
        <p className="font-mono text-xs tracking-[0.3em] text-signal/80 uppercase">
          Email Analyzer
        </p>
        <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulse-dot" />
      </div>

      <form onSubmit={handleSubmit} className="space-y-3 mb-2">
        <input
          required
          value={sender}
          onChange={(e) => setSender(e.target.value)}
          placeholder='From — e.g. "PayPal Support <support@paypa1-secure.com>"'
          className="terminal-input"
        />
        <input
          value={subject}
          onChange={(e) => setSubject(e.target.value)}
          placeholder="Subject"
          className="terminal-input"
        />
        <textarea
          required
          value={body}
          onChange={(e) => setBody(e.target.value)}
          placeholder="Paste the email body here…"
          rows={4}
          className="terminal-input resize-none"
        />
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 rounded-lg font-display uppercase text-sm tracking-wider
                     bg-gradient-to-r from-signal to-pulse text-void
                     hover:shadow-[0_0_30px_-5px_rgba(0,229,255,0.6)]
                     transition-shadow duration-300 disabled:opacity-50 cursor-pointer"
        >
          {loading ? "Analyzing…" : "Analyze Email"}
        </button>
      </form>

      {error && (
        <p className="text-threat text-xs font-mono border border-threat/30 bg-threat/10 rounded-md px-3 py-2 mt-3">
          {error}
        </p>
      )}

      <AnimatePresence>
        {result && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-5 pt-5 border-t border-signal/15">
              <div className="flex items-center gap-4 mb-5">
                <span
                  className="font-mono text-2xl font-bold px-3 py-1 rounded-lg border"
                  style={{ color, borderColor: `${color}55`, textShadow: `0 0 14px ${color}88` }}
                >
                  {result.risk_score}
                </span>
                <div>
                  <p className="font-display text-lg tracking-wide" style={{ color }}>
                    {result.severity}
                  </p>
                  <p className="text-xs text-ghost-dim font-mono mt-0.5">
                    {result.classification} · confidence {(result.confidence * 100).toFixed(0)}%
                  </p>
                </div>
              </div>

              {result.ai_summary && (
                <div className="mb-5 bg-pulse/10 border border-pulse/25 rounded-lg px-4 py-3">
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-pulse">
                      AI Analysis
                    </p>
                    <span className="text-[10px] font-mono text-ghost-dim">{result.ai_model}</span>
                  </div>
                  <p className="text-sm mb-2">{result.ai_summary}</p>
                  {result.ai_explanation.length > 0 && (
                    <ul className="space-y-1">
                      {result.ai_explanation.map((point, i) => (
                        <li key={i} className="text-xs text-ghost-dim flex gap-1.5">
                          <span className="text-pulse">·</span>
                          {point}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              )}

              {result.evidence.length > 0 && (
                <div className="mb-5">
                  <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-ghost-dim mb-2">
                    Evidence
                  </p>
                  <ul className="space-y-2">
                    {result.evidence.map((e) => (
                      <li
                        key={e.signal}
                        className="text-sm bg-panel-light/40 border border-signal/10 rounded-lg px-3 py-2"
                      >
                        <span className="font-mono text-[11px] text-pulse mr-2">+{e.weight}</span>
                        {e.description}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div>
                <p className="text-[10px] font-mono uppercase tracking-[0.2em] text-ghost-dim mb-2">
                  Recommended actions
                </p>
                <ul className="space-y-1.5">
                  {result.recommendations.map((r, i) => (
                    <li key={i} className="text-sm text-ghost-dim flex gap-2">
                      <span className="text-signal">›</span>
                      {r}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </HUDFrame>
  );
}
