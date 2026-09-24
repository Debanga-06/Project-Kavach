import { useState, type FormEvent } from "react";
import { motion, AnimatePresence } from "framer-motion";
import HUDFrame from "./HUDFrame";
import { useAuth } from "../lib/auth-context";
import { apiErrorMessage } from "../lib/api";

type Mode = "login" | "register";

export default function AuthTerminal() {
  const [mode, setMode] = useState<Mode>("login");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const { login, register } = useAuth();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      if (mode === "login") {
        await login(email, password);
      } else {
        await register(name, email, password);
      }
    } catch (err) {
      setError(apiErrorMessage(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <HUDFrame className="w-full max-w-md p-8">
      <div className="flex items-center justify-between mb-6">
        <div>
          <p className="font-mono text-xs tracking-[0.3em] text-signal/80 uppercase">
            Access Terminal
          </p>
          <h2 className="font-display text-2xl mt-1 tracking-wide">
            {mode === "login" ? "Authenticate" : "Provision Identity"}
          </h2>
        </div>
        <div className="flex items-center gap-1.5 font-mono text-[10px] text-ghost-dim">
          <span className="h-1.5 w-1.5 rounded-full bg-signal animate-pulse-dot" />
          ONLINE
        </div>
      </div>

      <div className="flex mb-6 rounded-lg overflow-hidden border border-signal/20 font-mono text-xs">
        {(["login", "register"] as Mode[]).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => {
              setMode(m);
              setError(null);
            }}
            className={`flex-1 py-2.5 tracking-wider uppercase transition-colors duration-300 cursor-pointer ${
              mode === m
                ? "bg-signal/15 text-signal text-glow-signal"
                : "text-ghost-dim hover:text-ghost"
            }`}
          >
            {m === "login" ? "Sign In" : "Register"}
          </button>
        ))}
      </div>

      <AnimatePresence mode="wait">
        <motion.form
          key={mode}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -8 }}
          transition={{ duration: 0.25 }}
          onSubmit={handleSubmit}
          className="space-y-4"
        >
          {mode === "register" && (
            <Field label="Name">
              <input
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="terminal-input"
                placeholder="Ada Lovelace"
                autoComplete="name"
              />
            </Field>
          )}

          <Field label="Email">
            <input
              required
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="terminal-input"
              placeholder="you@domain.com"
              autoComplete="email"
            />
          </Field>

          <Field label="Password">
            <input
              required
              type="password"
              minLength={8}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="terminal-input"
              placeholder="••••••••"
              autoComplete={mode === "login" ? "current-password" : "new-password"}
            />
          </Field>

          {error && (
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="text-threat text-xs font-mono border border-threat/30 bg-threat/10 rounded-md px-3 py-2"
            >
              {error}
            </motion.p>
          )}

          <button
            type="submit"
            disabled={submitting}
            className="w-full mt-2 py-3 rounded-lg font-display tracking-wider uppercase text-sm
                       bg-gradient-to-r from-signal to-pulse text-void
                       hover:shadow-[0_0_30px_-5px_rgba(0,229,255,0.6)]
                       transition-shadow duration-300 disabled:opacity-50 cursor-pointer"
          >
            {submitting ? "Verifying…" : mode === "login" ? "Enter" : "Create Access"}
          </button>
        </motion.form>
      </AnimatePresence>

      <p className="mt-5 text-[11px] text-ghost-dim font-mono text-center">
        Risk scoring · evidence-based explanations · zero-trust by default
      </p>
    </HUDFrame>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="block text-[10px] font-mono uppercase tracking-[0.2em] text-ghost-dim mb-1.5">
        {label}
      </span>
      {children}
    </label>
  );
}
