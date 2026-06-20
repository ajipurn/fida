'use client';

import { useEffect, useRef } from 'react';
import gsap from 'gsap';

/**
 * Custom cursor — a fast dot trailed by a lerping ring that swells over
 * interactive targets. Fine-pointer + motion-allowed only; otherwise the
 * native cursor is left untouched (no DOM, no listeners).
 */
export function Cursor() {
  const dot = useRef<HTMLDivElement>(null);
  const ring = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const fine = window.matchMedia('(hover: hover) and (pointer: fine)').matches;
    const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const d = dot.current;
    const r = ring.current;
    if (!fine || reduce || !d || !r) return;

    gsap.set([d, r], { xPercent: -50, yPercent: -50, x: -100, y: -100 });
    const dx = gsap.quickTo(d, 'x', { duration: 0.12, ease: 'power3' });
    const dy = gsap.quickTo(d, 'y', { duration: 0.12, ease: 'power3' });
    const rx = gsap.quickTo(r, 'x', { duration: 0.35, ease: 'power3' });
    const ry = gsap.quickTo(r, 'y', { duration: 0.35, ease: 'power3' });

    const move = (e: PointerEvent) => {
      dx(e.clientX);
      dy(e.clientY);
      rx(e.clientX);
      ry(e.clientY);
    };
    const hot = (t: EventTarget | null) =>
      t instanceof Element && !!t.closest('a, button, [data-cursor]');
    const over = (e: PointerEvent) => {
      if (hot(e.target)) gsap.to(r, { scale: 1.9, duration: 0.3, ease: 'power3' });
    };
    const out = (e: PointerEvent) => {
      if (hot(e.target)) gsap.to(r, { scale: 1, duration: 0.3, ease: 'power3' });
    };
    const down = () => gsap.to(r, { scale: 0.7, duration: 0.18, ease: 'power3' });
    const up = () => gsap.to(r, { scale: 1, duration: 0.3, ease: 'power3' });

    window.addEventListener('pointermove', move);
    document.addEventListener('pointerover', over);
    document.addEventListener('pointerout', out);
    window.addEventListener('pointerdown', down);
    window.addEventListener('pointerup', up);
    document.documentElement.classList.add('fida-has-cursor');

    return () => {
      window.removeEventListener('pointermove', move);
      document.removeEventListener('pointerover', over);
      document.removeEventListener('pointerout', out);
      window.removeEventListener('pointerdown', down);
      window.removeEventListener('pointerup', up);
      document.documentElement.classList.remove('fida-has-cursor');
    };
  }, []);

  return (
    <>
      <div ref={ring} className="fida-cursor-ring" aria-hidden="true" />
      <div ref={dot} className="fida-cursor-dot" aria-hidden="true" />
    </>
  );
}
