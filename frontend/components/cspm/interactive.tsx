"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useState,
  type MouseEvent,
  type ReactNode,
} from "react";
import {
  motion,
  useMotionTemplate,
  useMotionValue,
  useSpring,
} from "motion/react";
import { cn } from "@/lib/utils";

/** Cursor spotlight that follows the mouse inside a container */
export function SpotlightFrame({
  children,
  className,
  spotColor = "rgba(56, 116, 255, 0.18)",
}: {
  children: ReactNode;
  className?: string;
  spotColor?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const mx = useMotionValue(0);
  const my = useMotionValue(0);
  const opacity = useMotionValue(0);
  const background = useMotionTemplate`radial-gradient(420px circle at ${mx}px ${my}px, ${spotColor}, transparent 55%)`;

  const onMove = (e: MouseEvent) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    mx.set(e.clientX - r.left);
    my.set(e.clientY - r.top);
    opacity.set(1);
  };

  return (
    <div
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={() => opacity.set(0)}
      className={cn("relative overflow-hidden", className)}
    >
      <motion.div
        className="pointer-events-none absolute inset-0 z-0 transition-opacity duration-300"
        style={{ background, opacity }}
      />
      <div className="relative z-10">{children}</div>
    </div>
  );
}

/** Card that magnetically tilts / shifts toward the cursor */
export function MagneticCard({
  children,
  className,
  strength = 12,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  strength?: number;
  onClick?: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const rX = useMotionValue(0);
  const rY = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 260, damping: 20 });
  const sy = useSpring(y, { stiffness: 260, damping: 20 });
  const srX = useSpring(rX, { stiffness: 260, damping: 20 });
  const srY = useSpring(rY, { stiffness: 260, damping: 20 });

  const onMove = (e: MouseEvent) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    const px = (e.clientX - r.left) / r.width - 0.5;
    const py = (e.clientY - r.top) / r.height - 0.5;
    x.set(px * strength);
    y.set(py * strength);
    rX.set(py * -6);
    rY.set(px * 8);
  };

  const reset = () => {
    x.set(0);
    y.set(0);
    rX.set(0);
    rY.set(0);
  };

  return (
    <motion.div
      ref={ref}
      onMouseMove={onMove}
      onMouseLeave={reset}
      onClick={onClick}
      style={{
        x: sx,
        y: sy,
        rotateX: srX,
        rotateY: srY,
        transformPerspective: 800,
      }}
      whileTap={{ scale: 0.98 }}
      className={cn("cursor-pointer will-change-transform", className)}
    >
      {children}
    </motion.div>
  );
}

/** Button/card with click ripple bursts */
export function RippleSurface({
  children,
  className,
  onClick,
}: {
  children: ReactNode;
  className?: string;
  onClick?: () => void;
}) {
  const [ripples, setRipples] = useState<
    Array<{ id: number; x: number; y: number }>
  >([]);
  const idRef = useRef(0);

  const spawn = useCallback((e: MouseEvent<HTMLDivElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    const id = ++idRef.current;
    const x = e.clientX - r.left;
    const y = e.clientY - r.top;
    setRipples((prev) => [...prev, { id, x, y }]);
    window.setTimeout(() => {
      setRipples((prev) => prev.filter((p) => p.id !== id));
    }, 650);
  }, []);

  return (
    <div
      className={cn("relative overflow-hidden", className)}
      onMouseDown={spawn}
      onClick={onClick}
    >
      {children}
      {ripples.map((r) => (
        <span
          key={r.id}
          className="pointer-events-none absolute z-20 rounded-full bg-white/25"
          style={{
            left: r.x,
            top: r.y,
            width: 12,
            height: 12,
            marginLeft: -6,
            marginTop: -6,
            animation: "vs-ripple 0.65s ease-out forwards",
          }}
        />
      ))}
    </div>
  );
}

/** Soft custom cursor glow that follows mouse on a page section */
export function CursorGlow({
  color = "rgba(56, 116, 255, 0.35)",
  size = 280,
}: {
  color?: string;
  size?: number;
}) {
  const x = useMotionValue(-999);
  const y = useMotionValue(-999);
  const o = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 150, damping: 20 });
  const sy = useSpring(y, { stiffness: 150, damping: 20 });

  useEffect(() => {
    const move = (e: globalThis.MouseEvent) => {
      x.set(e.clientX);
      y.set(e.clientY);
      o.set(1);
    };
    const leave = () => o.set(0);
    window.addEventListener("mousemove", move);
    window.addEventListener("mouseleave", leave);
    return () => {
      window.removeEventListener("mousemove", move);
      window.removeEventListener("mouseleave", leave);
    };
  }, [x, y, o]);

  return (
    <motion.div
      aria-hidden
      className="pointer-events-none fixed z-[30] mix-blend-screen"
      style={{
        width: size,
        height: size,
        x: sx,
        y: sy,
        opacity: o,
        marginLeft: -size / 2,
        marginTop: -size / 2,
        background: `radial-gradient(circle, ${color} 0%, transparent 70%)`,
      }}
    />
  );
}

