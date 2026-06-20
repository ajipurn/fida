'use client';

import { useEffect, useRef, useState } from 'react';
import gsap from 'gsap';

/**
 * Intro loader — counts up to 100 behind a progress rule, then wipes upward to
 * hand off to the hero. Calls onDone at the wipe so the hero entrance starts as
 * the curtain lifts. Reduced motion skips straight through.
 */
export function Loader({ onDone }: { onDone: () => void }) {
  const root = useRef<HTMLDivElement>(null);
  const num = useRef<HTMLSpanElement>(null);
  const [gone, setGone] = useState(false);

  useEffect(() => {
    // Reduced motion, or already seen this session → skip straight to the hero.
    let seen = false;
    try {
      seen = sessionStorage.getItem('fida-intro') === '1';
    } catch {
      /* storage blocked — treat as first visit */
    }
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches || seen) {
      onDone();
      setGone(true);
      return;
    }
    try {
      sessionStorage.setItem('fida-intro', '1');
    } catch {
      /* storage blocked — loader simply replays next visit */
    }
    // Loader DOM is gone (finished / fast-refresh re-run) — don't build a
    // timeline against missing targets.
    if (!root.current) return;
    const counter = { v: 0 };
    const tl = gsap.timeline();
    tl.to(counter, {
      v: 100,
      duration: 1.25,
      ease: 'power2.inOut',
      onUpdate: () => {
        if (num.current) num.current.textContent = String(Math.round(counter.v)).padStart(3, '0');
      },
    })
      .to('.fida-loader__rule > i', { scaleX: 1, duration: 1.25, ease: 'power2.inOut' }, 0)
      .to('.fida-loader__mark, .fida-loader__meta', {
        yPercent: -120,
        autoAlpha: 0,
        duration: 0.6,
        ease: 'power3.in',
      })
      .call(onDone)
      .to(root.current, { yPercent: -100, duration: 0.9, ease: 'expo.inOut' }, '-=0.1')
      .call(() => setGone(true));
    return () => {
      tl.kill();
    };
  }, [onDone]);

  if (gone) return null;
  return (
    <div ref={root} className="fida-loader" aria-hidden="true">
      <div className="fida-loader__mark">FIDA</div>
      <div className="fida-loader__meta">
        <span ref={num}>000</span>
        <span>secrets stay secret</span>
      </div>
      <div className="fida-loader__rule">
        <i />
      </div>
    </div>
  );
}
