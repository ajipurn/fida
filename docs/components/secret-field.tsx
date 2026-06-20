'use client';

import { useEffect, useRef } from 'react';

type Props = {
  /**
   * Live exposure level read every frame: 0 = locked/calm, 1 = exposed.
   * The hero's scroll-scrubbed demo writes this ref as the synthetic secret
   * appears and is redacted; the shader lerps toward it so the state shift
   * reads as a slow settle rather than a snap.
   */
  exposureRef: React.MutableRefObject<number>;
};

// Fullscreen-triangle pass-through.
const VERT = /* glsl */ `
  attribute vec2 uv;
  attribute vec2 position;
  varying vec2 vUv;
  void main() {
    vUv = uv;
    gl_Position = vec4(position, 0.0, 1.0);
  }
`;

// Domain-warped fbm nebula on a near-black canvas. Deep navy → sky blue bands,
// a slow drift that never fully rests, a vignette that melts the edges into the
// page, fine grain, a pointer bloom, and an exposure tint that warms + churns
// the field while a secret is on screen.
const FRAG = /* glsl */ `
  precision highp float;
  varying vec2 vUv;
  uniform float uTime;
  uniform vec2 uRes;
  uniform vec2 uPointer;
  uniform float uExposure;

  vec2 hash22(vec2 p) {
    p = vec2(dot(p, vec2(127.1, 311.7)), dot(p, vec2(269.5, 183.3)));
    return fract(sin(p) * 43758.5453) * 2.0 - 1.0;
  }
  float noise(vec2 p) {
    vec2 i = floor(p);
    vec2 f = fract(p);
    vec2 u = f * f * (3.0 - 2.0 * f);
    float a = dot(hash22(i + vec2(0.0, 0.0)), f - vec2(0.0, 0.0));
    float b = dot(hash22(i + vec2(1.0, 0.0)), f - vec2(1.0, 0.0));
    float c = dot(hash22(i + vec2(0.0, 1.0)), f - vec2(0.0, 1.0));
    float d = dot(hash22(i + vec2(1.0, 1.0)), f - vec2(1.0, 1.0));
    return mix(mix(a, b, u.x), mix(c, d, u.x), u.y);
  }
  float fbm(vec2 p) {
    float v = 0.0;
    float a = 0.5;
    for (int i = 0; i < 6; i++) {
      v += a * noise(p);
      p = p * 2.02 + 7.3;
      a *= 0.5;
    }
    return v;
  }
  float grain(vec2 p) {
    return fract(sin(dot(p, vec2(12.9898, 78.233))) * 43758.5453);
  }

  void main() {
    vec2 p = vUv - 0.5;
    p.x *= uRes.x / uRes.y;

    float t = uTime * 0.05;
    float ex = uExposure;

    // domain warp
    vec2 q = vec2(fbm(p * 1.4 + vec2(0.0, t)), fbm(p * 1.4 + vec2(5.2, -t)));
    float churn = mix(0.35, 1.1, ex);
    vec2 r = p * 1.6 + churn * q + vec2(-t * 0.6, t * 0.4);
    float n = fbm(r);
    n = n * 0.5 + 0.5;
    n = pow(n, 1.35);

    // pointer bloom
    vec2 pc = uPointer - 0.5;
    pc.x *= uRes.x / uRes.y;
    float pd = exp(-dot(p - pc, p - pc) * 5.0);
    n += pd * 0.4;

    // palette — base ink, deep navy, sky highlight, warm leak when exposed
    vec3 ink = vec3(0.024, 0.031, 0.047);
    vec3 navy = vec3(0.07, 0.16, 0.38);
    vec3 sky = vec3(0.43, 0.66, 1.0);
    vec3 warm = vec3(0.85, 0.55, 0.42);

    vec3 col = mix(ink, navy, smoothstep(0.25, 0.75, n));
    col = mix(col, sky, smoothstep(0.62, 0.98, n) * (0.55 + 0.45 * pd));
    col = mix(col, warm, ex * smoothstep(0.55, 0.95, n) * 0.55);
    col += pd * sky * 0.12;

    // vignette → fade to page ink at the edges
    float vig = smoothstep(1.15, 0.25, length(p));
    col *= 0.35 + 0.65 * vig;

    // grain
    col += (grain(vUv * uRes.xy + t) - 0.5) * 0.035;

    float alpha = clamp(0.55 + n * 0.4, 0.0, 1.0) * vig;
    gl_FragColor = vec4(col, alpha);
  }
`;

/**
 * Full-bleed WebGL nebula behind the hero.
 *
 * Desktop fine-pointer only: on touch / coarse pointers and when the user
 * prefers reduced motion the effect never initialises and the CSS gradient
 * fallback stays. OGL is dynamically imported after mount so it never blocks
 * hydration or LCP, the loop pauses whenever the canvas leaves the viewport,
 * and a missing WebGL context fails silently.
 */
export function SecretField({ exposureRef }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (!fine || reduce) return;

    let raf = 0;
    let visible = true;
    let disposed = false;
    let io: IntersectionObserver | undefined;
    let cleanup = () => {};

    const pointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };
    let exposure = exposureRef.current ?? 0;

    const onPointer = (e: PointerEvent) => {
      const rect = canvas.getBoundingClientRect();
      pointer.tx = (e.clientX - rect.left) / rect.width;
      pointer.ty = 1 - (e.clientY - rect.top) / rect.height;
    };

    import('ogl')
      // ogl's published types are loose; the bridge below is intentionally untyped.
      .then((m) => {
        if (disposed) return;
        const { Renderer, Program, Mesh, Triangle, Vec2 } = m as any;

        const renderer = new Renderer({
          canvas,
          alpha: true,
          dpr: Math.min(window.devicePixelRatio || 1, 1.75),
        });
        const gl = renderer.gl;

        const program = new Program(gl, {
          vertex: VERT,
          fragment: FRAG,
          uniforms: {
            uTime: { value: 0 },
            uRes: { value: new Vec2(1, 1) },
            uPointer: { value: new Vec2(0.5, 0.5) },
            uExposure: { value: exposure },
          },
        });
        const mesh = new Mesh(gl, { geometry: new Triangle(gl), program });

        const resize = () => {
          // Measure the host, not the canvas — a canvas sized width/height:100%
          // reports its own intrinsic 300×150 before layout resolves (circular).
          const host = canvas.parentElement ?? canvas;
          const rect = host.getBoundingClientRect();
          renderer.setSize(Math.max(1, rect.width), Math.max(1, rect.height));
          program.uniforms.uRes.value.set(
            gl.drawingBufferWidth,
            gl.drawingBufferHeight
          );
        };
        resize();
        window.addEventListener('resize', resize);
        window.addEventListener('pointermove', onPointer);

        io = new IntersectionObserver(
          ([entry]) => {
            visible = entry.isIntersecting;
            if (visible && !raf && !disposed) raf = requestAnimationFrame(loop);
          },
          { threshold: 0.01 }
        );
        io.observe(canvas);

        const start = performance.now();
        let last = 0;
        const minDelta = 1000 / 40; // ponytail: 40fps cap — ambient nebula, 60 just burns battery
        function loop(now: number) {
          if (disposed || !visible) {
            raf = 0;
            return;
          }
          raf = requestAnimationFrame(loop);
          if (now - last < minDelta) return;
          last = now;
          pointer.x += (pointer.tx - pointer.x) * 0.06;
          pointer.y += (pointer.ty - pointer.y) * 0.06;
          exposure += ((exposureRef.current ?? 0) - exposure) * 0.05;
          program.uniforms.uTime.value = (now - start) / 1000;
          program.uniforms.uPointer.value.set(pointer.x, pointer.y);
          program.uniforms.uExposure.value = exposure;
          renderer.render({ scene: mesh });
        }
        raf = requestAnimationFrame(loop);

        cleanup = () => {
          window.removeEventListener('resize', resize);
          window.removeEventListener('pointermove', onPointer);
          gl.getExtension('WEBGL_lose_context')?.loseContext();
        };
      })
      .catch(() => {
        /* OGL unavailable / WebGL blocked — the CSS gradient remains */
      });

    return () => {
      disposed = true;
      if (raf) cancelAnimationFrame(raf);
      io?.disconnect();
      cleanup();
    };
  }, [exposureRef]);

  return <canvas ref={canvasRef} className="fida-field" aria-hidden="true" />;
}
