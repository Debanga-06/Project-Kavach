import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  LineChart, Line, XAxis, YAxis, Tooltip, CartesianGrid,
} from "recharts";
import HUDFrame from "./HUDFrame";
import { useAuth } from "../lib/auth-context";
import { fetchDashboardStats, type DashboardStats } from "../lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  SAFE: "#00E5FF",
  LOW: "#3FD1E0",
  SUSPICIOUS: "#7C3AED",
  HIGH: "#FF7A9C",
  CRITICAL: "#FF2D78",
};

export default function AnalyticsPanel({ refreshKey }: { refreshKey: number }) {
  const { accessToken } = useAuth();
  const [stats, setStats] = useState<DashboardStats | null>(null);

  useEffect(() => {
    if (!accessToken) return;
    fetchDashboardStats(accessToken).then(setStats).catch(() => {});
  }, [accessToken, refreshKey]);

  if (!stats) return null;

  const pieData = stats.severity_distribution.filter((d) => d.count > 0);
  const hasTrend = stats.risk_trend.length > 0;

  return (
    <div className="mb-6 space-y-6">
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total Scans" value={stats.total_scans} color="#00E5FF" />
        <StatCard label="Threats Detected" value={stats.threats_detected} color="#7C3AED" />
        <StatCard label="Critical" value={stats.critical_threats} color="#FF2D78" />
        <StatCard label="Safe" value={stats.safe_scans} color="#00E5FF" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <HUDFrame className="p-6">
          <p className="font-mono text-xs text-ghost-dim uppercase tracking-widest mb-4">
            Threat Distribution
          </p>
          {pieData.length === 0 ? (
            <p className="text-sm text-ghost-dim py-8 text-center">No scans yet</p>
          ) : (
            <div className="flex items-center gap-4">
              <div className="w-32 h-32 shrink-0">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      dataKey="count"
                      nameKey="severity"
                      innerRadius={32}
                      outerRadius={56}
                      paddingAngle={3}
                      stroke="none"
                    >
                      {pieData.map((entry) => (
                        <Cell key={entry.severity} fill={SEVERITY_COLOR[entry.severity]} />
                      ))}
                    </Pie>
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <ul className="space-y-1.5 text-sm">
                {pieData.map((d) => (
                  <li key={d.severity} className="flex items-center gap-2">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ background: SEVERITY_COLOR[d.severity] }}
                    />
                    <span className="text-ghost-dim font-mono text-xs uppercase">{d.severity}</span>
                    <span className="font-mono text-xs">{d.count}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </HUDFrame>

        <HUDFrame className="p-6">
          <p className="font-mono text-xs text-ghost-dim uppercase tracking-widest mb-4">
            Average Risk Trend
          </p>
          {!hasTrend ? (
            <p className="text-sm text-ghost-dim py-8 text-center">No trend data yet</p>
          ) : (
            <div className="h-32">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={stats.risk_trend}>
                  <CartesianGrid stroke="#10182C" vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "#8DA0C4", fontSize: 10, fontFamily: "JetBrains Mono" }}
                    axisLine={{ stroke: "#10182C" }}
                    tickLine={false}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: "#8DA0C4", fontSize: 10, fontFamily: "JetBrains Mono" }}
                    axisLine={false}
                    tickLine={false}
                    width={28}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "#0B0F1E",
                      border: "1px solid rgba(0,229,255,0.25)",
                      borderRadius: 8,
                      fontFamily: "JetBrains Mono",
                      fontSize: 12,
                    }}
                    labelStyle={{ color: "#8DA0C4" }}
                  />
                  <Line
                    type="monotone"
                    dataKey="avg_risk_score"
                    stroke="#00E5FF"
                    strokeWidth={2}
                    dot={{ fill: "#00E5FF", r: 3 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </HUDFrame>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <HUDFrame className="p-4">
        <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-ghost-dim mb-1.5">
          {label}
        </p>
        <p
          className="font-display text-3xl"
          style={{ color, textShadow: `0 0 14px ${color}55` }}
        >
          {value}
        </p>
      </HUDFrame>
    </motion.div>
  );
}
