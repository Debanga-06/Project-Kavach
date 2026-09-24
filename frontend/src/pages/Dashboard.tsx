import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import HUDFrame from "../components/HUDFrame";
import URLScannerPanel from "../components/URLScannerPanel";
import EmailScannerPanel from "../components/EmailScannerPanel";
import AnalyticsPanel from "../components/AnalyticsPanel";
import { useAuth } from "../lib/auth-context";
import { listScans, type ScanSummary } from "../lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  SAFE: "#00E5FF",
  LOW: "#00E5FF",
  SUSPICIOUS: "#7C3AED",
  HIGH: "#FF2D78",
  CRITICAL: "#FF2D78",
};

export default function Dashboard() {
  const { user, accessToken, logout } = useAuth();
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [refreshKey, setRefreshKey] = useState(0);
  const [scannerTab, setScannerTab] = useState<"url" | "email">("url");

  const loadHistory = useCallback(() => {
    if (!accessToken) return;
    listScans(accessToken).then(setHistory).catch(() => {});
    setRefreshKey((k) => k + 1);
  }, [accessToken]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  return (
    <div className="relative min-h-screen bg-void grid-fade">
      <header className="flex items-center justify-between px-6 md:px-10 py-6">
        <span className="font-display tracking-[0.25em] text-sm">KAVACHAI</span>
        <button
          onClick={logout}
          className="font-mono text-xs text-ghost-dim hover:text-threat transition-colors cursor-pointer"
        >
          Sign out
        </button>
      </header>

      <main className="px-6 md:px-10 pb-20 max-w-4xl mx-auto">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }}>
          <p className="font-mono text-xs tracking-[0.3em] text-signal/80 uppercase mb-2">
            Session Authenticated
          </p>
          <h1 className="font-display text-3xl mb-8">
            Welcome, {user?.name ?? "operator"}.
          </h1>
        </motion.div>

        <HUDFrame className="p-6 mb-6">
          <p className="font-mono text-xs text-ghost-dim uppercase tracking-widest mb-3">
            Identity
          </p>
          <dl className="grid grid-cols-2 gap-y-3 text-sm">
            <dt className="text-ghost-dim">Email</dt>
            <dd className="font-mono">{user?.email}</dd>
            <dt className="text-ghost-dim">Role</dt>
            <dd className="font-mono uppercase">{user?.role}</dd>
            <dt className="text-ghost-dim">User ID</dt>
            <dd className="font-mono text-xs break-all">{user?.id}</dd>
          </dl>
        </HUDFrame>

        <AnalyticsPanel refreshKey={refreshKey} />

        <div className="mb-6">
          <div className="flex mb-3 rounded-lg overflow-hidden border border-signal/20 font-mono text-xs max-w-xs">
            {(["url", "email"] as const).map((t) => (
              <button
                key={t}
                onClick={() => setScannerTab(t)}
                className={`flex-1 py-2 tracking-wider uppercase transition-colors duration-300 cursor-pointer ${
                  scannerTab === t ? "bg-signal/15 text-signal" : "text-ghost-dim hover:text-ghost"
                }`}
              >
                {t === "url" ? "URL Scanner" : "Email Analyzer"}
              </button>
            ))}
          </div>
          {scannerTab === "url" ? (
            <URLScannerPanel onScanned={loadHistory} />
          ) : (
            <EmailScannerPanel onScanned={loadHistory} />
          )}
        </div>

        <HUDFrame className="p-6">
          <p className="font-mono text-xs text-ghost-dim uppercase tracking-widest mb-4">
            Scan History
          </p>
          {history.length === 0 ? (
            <p className="text-sm text-ghost-dim">No scans yet — run one above.</p>
          ) : (
            <ul className="space-y-2">
              {history.map((s) => (
                <li
                  key={s.scan_id}
                  className="flex items-center justify-between text-sm bg-panel-light/30 rounded-lg px-3 py-2.5 border border-signal/10"
                >
                  <span className="font-mono text-xs truncate max-w-[55%]" title={s.target}>
                    {s.target}
                  </span>
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="font-mono text-xs text-ghost-dim">{s.risk_score}</span>
                    <span
                      className="font-mono text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full border"
                      style={{
                        color: SEVERITY_COLOR[s.severity] ?? "#00E5FF",
                        borderColor: `${SEVERITY_COLOR[s.severity] ?? "#00E5FF"}55`,
                      }}
                    >
                      {s.severity}
                    </span>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </HUDFrame>
      </main>
    </div>
  );
}
