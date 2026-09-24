import { motion } from "framer-motion";
import HUDFrame from "./HUDFrame";

const FEATURES = [
  {
    code: "01",
    title: "URL Scanner",
    detail: "Domain signals, redirect chains, reputation and ML classification fused into one score.",
  },
  {
    code: "02",
    title: "Email Analyzer",
    detail: "Sender mismatch, urgency language, and embedded-link risk surfaced with evidence.",
  },
  {
    code: "03",
    title: "File Scanner",
    detail: "Static analysis of uploads in quarantine — nothing executes on the API surface.",
  },
  {
    code: "04",
    title: "Secret Scanner",
    detail: "Pattern + entropy detection for exposed keys, tokens, and credentials in your code.",
  },
];

export default function FeatureReadouts() {
  return (
    <section className="relative z-10 max-w-5xl mx-auto px-6 py-32">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        whileInView={{ opacity: 1, y: 0 }}
        viewport={{ once: true, margin: "-80px" }}
        transition={{ duration: 0.5 }}
        className="mb-14 text-center"
      >
        <p className="font-mono text-xs tracking-[0.3em] text-signal/80 uppercase mb-3">
          Detection Surfaces
        </p>
        <h2 className="font-display text-3xl md:text-4xl tracking-wide">
          Four scanners. One risk engine.
        </h2>
      </motion.div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
        {FEATURES.map((f, i) => (
          <motion.div
            key={f.code}
            initial={{ opacity: 0, y: 24 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true, margin: "-60px" }}
            transition={{ duration: 0.45, delay: i * 0.08 }}
          >
            <HUDFrame className="p-6 h-full hover:border-signal/40 transition-colors duration-300">
              <div className="flex items-start justify-between mb-3">
                <span className="font-mono text-[11px] text-pulse/90 tracking-widest">
                  {f.code}
                </span>
                <span className="h-1.5 w-1.5 rounded-full bg-signal/70 animate-pulse-dot" />
              </div>
              <h3 className="font-display text-lg mb-2 tracking-wide">{f.title}</h3>
              <p className="text-sm text-ghost-dim leading-relaxed">{f.detail}</p>
            </HUDFrame>
          </motion.div>
        ))}
      </div>
    </section>
  );
}
