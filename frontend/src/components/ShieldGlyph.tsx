import { useEffect, useMemo, useRef } from "react";
import { useFrame } from "@react-three/fiber";
import * as THREE from "three";

/** Rasterizes a shield silhouette to a hidden canvas and samples filled pixels as 3D points. */
function sampleShieldPoints(count: number): Float32Array {
  const size = 256;
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d")!;
  ctx.clearRect(0, 0, size, size);
  ctx.fillStyle = "#fff";

  const w = size;
  const h = size;
  ctx.beginPath();
  ctx.moveTo(w * 0.5, h * 0.05);
  ctx.lineTo(w * 0.87, h * 0.19);
  ctx.lineTo(w * 0.87, h * 0.53);
  ctx.quadraticCurveTo(w * 0.87, h * 0.8, w * 0.5, h * 0.98);
  ctx.quadraticCurveTo(w * 0.13, h * 0.8, w * 0.13, h * 0.53);
  ctx.lineTo(w * 0.13, h * 0.19);
  ctx.closePath();
  ctx.fill();

  const img = ctx.getImageData(0, 0, size, size).data;
  const candidates: { x: number; y: number }[] = [];
  for (let y = 0; y < size; y += 2) {
    for (let x = 0; x < size; x += 2) {
      const alpha = img[(y * size + x) * 4 + 3];
      if (alpha > 100) candidates.push({ x, y });
    }
  }

  const positions = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    const c = candidates[Math.floor(Math.random() * candidates.length)];
    const nx = (c.x / size - 0.5) * 6.2;
    const ny = -(c.y / size - 0.5) * 6.2;
    const nz = (Math.random() - 0.5) * 0.5;
    positions[i * 3] = nx;
    positions[i * 3 + 1] = ny;
    positions[i * 3 + 2] = nz;
  }
  return positions;
}

function scatterPoints(count: number): Float32Array {
  const positions = new Float32Array(count * 3);
  for (let i = 0; i < count; i++) {
    const radius = 6 + Math.random() * 10;
    const theta = Math.random() * Math.PI * 2;
    const phi = Math.acos(2 * Math.random() - 1);
    positions[i * 3] = radius * Math.sin(phi) * Math.cos(theta);
    positions[i * 3 + 1] = radius * Math.sin(phi) * Math.sin(theta);
    positions[i * 3 + 2] = radius * Math.cos(phi) * 0.4;
  }
  return positions;
}

function easeOutCubic(t: number) {
  return 1 - Math.pow(1 - t, 3);
}

interface Props {
  pointer: React.MutableRefObject<{ x: number; y: number }>;
  count?: number;
}

export default function ShieldGlyph({ pointer, count = 1600 }: Props) {
  const pointsRef = useRef<THREE.Points>(null);
  const groupRef = useRef<THREE.Group>(null);
  const startTime = useRef<number | null>(null);

  const target = useMemo(() => sampleShieldPoints(count), [count]);
  const scatter = useMemo(() => scatterPoints(count), [count]);
  const current = useMemo(() => new Float32Array(scatter), [scatter]);

  const colorAttr = useMemo(() => {
    const colors = new Float32Array(count * 3);
    const base = new THREE.Color("#00E5FF");
    for (let i = 0; i < count; i++) {
      colors[i * 3] = base.r;
      colors[i * 3 + 1] = base.g;
      colors[i * 3 + 2] = base.b;
    }
    return colors;
  }, [count]);

  const radii = useMemo(() => {
    const r = new Float32Array(count);
    for (let i = 0; i < count; i++) {
      r[i] = Math.hypot(target[i * 3], target[i * 3 + 1]);
    }
    return r;
  }, [target, count]);

  useEffect(() => {
    startTime.current = null;
  }, []);

  const pulse = new THREE.Color("#7C3AED");
  const base = new THREE.Color("#00E5FF");
  const tmpColor = new THREE.Color();

  useFrame((state) => {
    if (startTime.current === null) startTime.current = state.clock.elapsedTime;
    const t = state.clock.elapsedTime - startTime.current;

    const assembleT = Math.min(t / 2.4, 1);
    const eased = easeOutCubic(assembleT);

    // Traveling scan ring outward from center, repeats every ~3.2s
    const period = 3.2;
    const ringFront = ((t % period) / period) * 4.5;

    const posAttr = pointsRef.current!.geometry.attributes.position as THREE.BufferAttribute;
    const colAttr = pointsRef.current!.geometry.attributes.color as THREE.BufferAttribute;

    for (let i = 0; i < count; i++) {
      const tx = target[i * 3];
      const ty = target[i * 3 + 1];
      const tz = target[i * 3 + 2];
      const sx = scatter[i * 3];
      const sy = scatter[i * 3 + 1];
      const sz = scatter[i * 3 + 2];

      let x = sx + (tx - sx) * eased;
      let y = sy + (ty - sy) * eased;
      let z = sz + (tz - sz) * eased;

      if (assembleT > 0.85) {
        const dist = Math.abs(radii[i] - ringFront);
        const ring = Math.exp(-(dist * dist) / 0.06);
        z += ring * 0.35;
        const glowT = Math.min(ring * 1.6, 1);
        tmpColor.copy(base).lerp(pulse, glowT);
        colAttr.setXYZ(i, tmpColor.r, tmpColor.g, tmpColor.b);
      }

      current[i * 3] = x;
      current[i * 3 + 1] = y;
      current[i * 3 + 2] = z;
    }

    posAttr.array = current;
    posAttr.needsUpdate = true;
    colAttr.needsUpdate = true;

    if (groupRef.current) {
      const px = pointer.current.x;
      const py = pointer.current.y;
      groupRef.current.rotation.y += (px * 0.35 - groupRef.current.rotation.y) * 0.04;
      groupRef.current.rotation.x += (-py * 0.2 - groupRef.current.rotation.x) * 0.04;
      groupRef.current.rotation.z = Math.sin(t * 0.15) * 0.03;
    }
  });

  return (
    <group ref={groupRef}>
      <points ref={pointsRef}>
        <bufferGeometry>
          <bufferAttribute attach="attributes-position" args={[current, 3]} />
          <bufferAttribute attach="attributes-color" args={[colorAttr, 3]} />
        </bufferGeometry>
        <pointsMaterial
          size={0.052}
          vertexColors
          transparent
          opacity={0.92}
          sizeAttenuation
          depthWrite={false}
          blending={THREE.AdditiveBlending}
        />
      </points>
    </group>
  );
}
