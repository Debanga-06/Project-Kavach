import { useEffect, useRef } from "react";
import { Canvas } from "@react-three/fiber";
import { EffectComposer, Bloom, Vignette } from "@react-three/postprocessing";
import ShieldGlyph from "./ShieldGlyph";
import StarField from "./StarField";

function usePointerRef() {
  const ref = useRef({ x: 0, y: 0 });
  useEffect(() => {
    function handle(e: PointerEvent) {
      ref.current.x = (e.clientX / window.innerWidth) * 2 - 1;
      ref.current.y = (e.clientY / window.innerHeight) * 2 - 1;
    }
    window.addEventListener("pointermove", handle);
    return () => window.removeEventListener("pointermove", handle);
  }, []);
  return ref;
}

export default function Scene() {
  const pointer = usePointerRef();

  return (
    <div className="fixed inset-0 -z-10">
      <Canvas
        camera={{ position: [0, 0, 8], fov: 45 }}
        dpr={[1, 1.75]}
        gl={{ antialias: true, alpha: true }}
      >
        <color attach="background" args={["#05070D"]} />
        <fog attach="fog" args={["#05070D", 8, 22]} />
        <StarField />
        <ShieldGlyph pointer={pointer} />
        <EffectComposer multisampling={0}>
          <Bloom
            intensity={0.85}
            luminanceThreshold={0.15}
            luminanceSmoothing={0.4}
            mipmapBlur
          />
          <Vignette eskil={false} offset={0.15} darkness={0.9} />
        </EffectComposer>
      </Canvas>
    </div>
  );
}
