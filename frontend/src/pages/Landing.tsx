import { motion } from "framer-motion";
import { Navigate } from "react-router-dom";
import Scene from "../components/Scene";
import AuthTerminal from "../components/AuthTerminal";
import FeatureReadouts from "../components/FeatureReadouts";
import { useAuth } from "../lib/auth-context";

export default function Landing() {
  const { user, loading } = useAuth();

  if (!loading && user) return <Navigate to="/dashboard" replace />;

  return (
    <div className="relative min-h-screen">
      <Scene />
      <div className="fixed inset-0 -z-10 grid-fade" />

      {/* Top wordmark / status bar */}
      <header className="relative z-10 flex items-center justify-between px-6 md:px-10 py-6">
        <div className="flex items-center gap-2.5">
          <ShieldMark />
          <span className="font-display tracking-[0.25em] text-sm">KAVACHAI</span>
        </div>
        <div className="hidden sm:flex items-center gap-2 font-mono text-[11px] text-ghost-dim">
          <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulse-dot" />
          SYSTEM ONLINE · v1.0
        </div>
      </header>

      {/* Hero + auth terminal */}
      <main className="relative z-10 flex flex-col items-center justify-center px-6 pt-8 pb-24 min-h-[86vh]">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2 }}
          className="text-center mb-10 max-w-2xl"
        >
          <p className="font-mono text-xs tracking-[0.35em] text-signal/80 uppercase mb-4 text-glow-signal">
            Evidence-based threat intelligence
          </p>
          <h1 className="font-display text-4xl md:text-6xl leading-[1.05] tracking-wide mb-5">
            See the threat.
            <br />
            <span className="bg-gradient-to-r from-signal via-signal to-pulse bg-clip-text text-transparent">
              Understand the evidence.
            </span>
          </h1>
          <p className="text-ghost-dim text-sm md:text-base max-w-lg mx-auto leading-relaxed">
            KavachAI fuses rule engines, ML classifiers, and threat intelligence into a single
            risk score — then explains exactly why, in plain language.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 24, scale: 0.98 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.6, delay: 0.4 }}
        >
          <AuthTerminal />
        </motion.div>
      </main>

      <FeatureReadouts />

      <footer className="relative z-10 text-center pb-10 font-mono text-[11px] text-ghost-dim/70">
        KavachAI · risk scoring is advisory, not a substitute for judgement
      </footer>
    </div>
  );
}

function ShieldMark() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" className="text-signal">
      <path
        d="M12 2 L21 6 V12 C21 17 17 20.5 12 22 C7 20.5 3 17 3 12 V6 Z"
        stroke="currentColor"
        strokeWidth="1.6"
        className="text-glow-signal"
      />
    </svg>
  );
}
