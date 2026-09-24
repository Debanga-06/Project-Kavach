import type { ReactNode } from "react";

export default function HUDFrame({
  children,
  className = "",
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={`relative glass-panel rounded-2xl ${className}`}>
      <span className="hud-corner hud-corner--tl" />
      <span className="hud-corner hud-corner--tr" />
      <span className="hud-corner hud-corner--bl" />
      <span className="hud-corner hud-corner--br" />
      <div className="scanline-sweep rounded-2xl" />
      {children}
    </div>
  );
}
