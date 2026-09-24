import { useState, type FormEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import HUDFrame from "./HUDFrame";
import { useAuth } from "../lib/auth-context";
import { scanUrl, apiErrorMessage, type ScanResult } from "../lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  SAFE: "#00E5FF",
  LOW: "#00E5FF",
  SUSPICIOUS: "#7C3AED",
  HIGH: "#FF2D78",
  CRITICAL: "#FF2D78",
};

export default function URLScannerPanel({ onScanned }: { onScanned?: () => void }) {
  const { accessToken } = useAuth();
  const [url, setUrl] = useState("");
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
      const res = await scanUrl(accessToken, url);
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
          URL Scanner
        </p>
        <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulse-dot" />
      </div>

      <form onSubmit={handleSubmit} className="flex gap-2 mb-2">
        <input
          required
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/suspicious-link"
          className="terminal-input flex-1"
        />
        <button
          type="submit"
          disabled={loading}
          className="px-5 rounded-lg font-display uppercase text-sm tracking-wider
                     bg-gradient-to-r from-signal to-pulse text-void
                     hover:shadow-[0_0_30px_-5px_rgba(0,229,255,0.6)]
                     transition-shadow duration-300 disabled:opacity-50 cursor-pointer whitespace-nowrap"
        >
          {loading ? "Scanning…" : "Scan"}
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
              <div className="flex items-center gap-5 mb-5">
                <RiskGauge score={result.risk_score} color={color} />
                <div>
                  <p
                    className="font-display text-xl tracking-wide"
                    style={{ color, textShadow: `0 0 14px ${color}88` }}
                  >
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
                        <span className="font-mono text-[11px] text-pulse mr-2">
                          +{e.weight}
                        </span>
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

function RiskGauge({ score, color }: { score: number; color: string }) {
  const radius = 30;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <svg width="76" height="76" viewBox="0 0 76 76" className="shrink-0">
      <circle cx="38" cy="38" r={radius} fill="none" stroke="#10182C" strokeWidth="6" />
      <circle
        cx="38"
        cy="38"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="6"
        strokeLinecap="round"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        transform="rotate(-90 38 38)"
        style={{ transition: "stroke-dashoffset 0.6s ease-out", filter: `drop-shadow(0 0 6px ${color}aa)` }}
      />
      <text
        x="38"
        y="43"
        textAnchor="middle"
        className="font-mono"
        fontSize="18"
        fill="#E8F1FF"
      >
        {score}
      </text>
    </svg>
  );
}
