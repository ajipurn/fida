'use client';

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import Image from 'next/image';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Lenis from 'lenis';
import fidaLogo from '@assets/fida-logo.png';
import packageJson from '../package.json';
import { Loader } from './loader';
import Link from 'next/link';

const INSTALL_CMD =
  'curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh';
const TYPED = 'fida_read .env';
const DEMO_SECRET = 'synthetic-credential-value';
const REDACTED = '•'.repeat(20);

// Hero headline, split into words for clip-mask reveals.
const HEADLINE = ['Let', 'agents', 'read', 'your', 'code,'];
const HEADLINE_ACCENT = ['not', 'your', 'secrets.'];

// Scroll statement, brightened word-by-word as it crosses the viewport.
const STATEMENT =
  'Coding agents read everything you point them at — including the .env you forgot was there.'.split(
    ' '
  );

const AGENTS = [
  'Codex',
  'Claude Code',
  'Cursor',
  'OpenCode',
  'Windsurf',
  'Copilot',
  'Antigravity',
];

// Feature blocks — each a real-output mini-terminal. Line colour classes:
// p=prompt, ok=enforced/safe, eff=best_effort, warn=exposed, dim=muted, lead=resolved.
type TermLine = { p?: boolean; c?: string; t: string };
type Feature = {
  tag: string;
  cmd: string;
  title: string;
  body: string;
  status: string;
  lines: TermLine[];
};

const FEATURES: Feature[] = [
  {
    tag: '01 / protect',
    cmd: 'fida',
    title: 'Install agent protection',
    body: 'One command detects every supported agent, installs its redacting gateway and steering, and runs a synthetic-secret self-test. Protection is global — one install guards every repository.',
    status: 'installing',
    lines: [
      { p: true, t: 'fida' },
      { c: 'dim', t: '◇ detecting agents…' },
      { c: 'ok', t: '✓ Codex          enforced' },
      { c: 'ok', t: '✓ Claude Code    enforced' },
      { c: 'eff', t: '✓ Cursor         best_effort' },
      { c: 'eff', t: '✓ Windsurf       best_effort' },
      { c: 'dim', t: '◇ synthetic-secret self-test … passed' },
      { c: 'ok', t: '✓ protection installed · global' },
    ],
  },
  {
    tag: '02 / verify',
    cmd: 'fida status',
    title: 'Know your coverage',
    body: 'See enforced, best-effort, or incomplete protection per agent — alongside the count of secrets Fida has already protected in this repository. No guessing what is actually guarded.',
    status: 'coverage',
    lines: [
      { p: true, t: 'fida status' },
      { c: 'ok', t: 'Codex          enforced' },
      { c: 'ok', t: 'Claude Code    enforced' },
      { c: 'eff', t: 'Cursor         best_effort' },
      { c: 'eff', t: 'Copilot        best_effort' },
      { c: 'dim', t: '────────────────────────────' },
      { c: 'lead', t: '12 secrets protected · this repo' },
    ],
  },
  {
    tag: '03 / scan',
    cmd: 'fida scan',
    title: 'Find raw-secret risk',
    body: 'Scan tracked and sensitive files, then read the answer that matters: raw_secret_exposure — whether an unredacted value could ever reach a model. It never prints a secret value, length, or fragment.',
    status: 'scanning',
    lines: [
      { p: true, t: 'fida scan' },
      { c: 'dim', t: 'scanning tracked + sensitive files…' },
      { c: 'warn', t: '.env   secret detected · git-tracked' },
      { t: 'risk                 medium' },
      { c: 'ok', t: 'protection           enforced' },
      { c: 'ok', t: 'raw_secret_exposure  false' },
      { c: 'lead', t: '→ no unredacted value reaches a model' },
    ],
  },
];

const clamp01 = (v: number) => (v < 0 ? 0 : v > 1 ? 1 : v);

const useIsomorphicLayoutEffect =
  typeof window !== 'undefined' ? useLayoutEffect : useEffect;

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 3l7 3v5c0 4.5-3 7.6-7 9-4-1.4-7-4.5-7-9V6l7-3z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="M9 12l2 2 4-4"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export function Landing() {
  const root = useRef<HTMLDivElement>(null);
  const introRef = useRef<gsap.core.Timeline | null>(null);
  const lenisRef = useRef<Lenis | null>(null);
  const [copied, setCopied] = useState(false);
  const [started, setStarted] = useState(false);

  const onLoaderDone = useCallback(() => setStarted(true), []);

  // Lenis smooth scroll, driven by GSAP's ticker and synced to ScrollTrigger.
  // Starts stopped; the loader hand-off releases it.
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    gsap.registerPlugin(ScrollTrigger);
    const lenis = new Lenis({ lerp: 0.1 });
    lenis.stop();
    lenis.on('scroll', ScrollTrigger.update);
    const tick = (time: number) => lenis.raf(time * 1000);
    gsap.ticker.add(tick);
    gsap.ticker.lagSmoothing(0);
    lenisRef.current = lenis;
    return () => {
      gsap.ticker.remove(tick);
      lenis.destroy();
      lenisRef.current = null;
    };
  }, []);

  // Lock the page while the loader runs.
  useEffect(() => {
    document.body.style.overflow = 'hidden';
    return () => {
      document.body.style.overflow = '';
    };
  }, []);

  // Release scroll + play the hero entrance once the loader lifts.
  useEffect(() => {
    if (!started) return;
    document.body.style.overflow = '';
    lenisRef.current?.start();
    introRef.current?.play();
    ScrollTrigger.refresh();
  }, [started]);

  // Solidify the nav once the hero top scrolls away (native IO, motion-agnostic).
  useEffect(() => {
    const el = root.current;
    const sentinel = el?.querySelector('.fida-nav-sentinel');
    const nav = el?.querySelector('.fida-nav');
    if (!sentinel || !nav) return;
    const io = new IntersectionObserver(
      ([e]) => nav.classList.toggle('fida-nav--solid', !e.isIntersecting),
      { threshold: 0 }
    );
    io.observe(sentinel);
    return () => io.disconnect();
  }, []);

  useIsomorphicLayoutEffect(() => {
    const el = root.current;
    if (!el) return;
    gsap.registerPlugin(ScrollTrigger);

    const q = <T extends Element>(sel: string) => el.querySelector<T>(sel);
    const heroEl = q<HTMLElement>('.fida-hero');
    const typeEl = q<HTMLElement>('[data-type]');
    const secretEl = q<HTMLElement>('[data-secret]');
    const caret = q<HTMLElement>('[data-caret]');
    const scan = q<HTMLElement>('[data-scan]');
    const leak = q<HTMLElement>('[data-leak]');
    const blocked = q<HTMLElement>('[data-blocked]');
    const note = q<HTMLElement>('[data-note]');

    // Deterministic demo state for a scrub position p ∈ [0,1] — read→type→
    // leak→scan→redact→safe. Pure function of p so it scrubs both ways.
    // It also resolves the headline accent (--resolve) as the secret is redacted.
    const renderDemo = (p: number) => {
      const tp = clamp01(p / 0.3);
      if (typeEl) typeEl.textContent = TYPED.slice(0, Math.round(tp * TYPED.length));
      if (caret) caret.style.opacity = p < 0.34 ? '1' : '0';

      const redacted = p >= 0.6;
      const showSecret = p >= 0.3;
      if (secretEl)
        secretEl.textContent = redacted ? REDACTED : showSecret ? DEMO_SECRET : '';

      if (leak) {
        const lp = clamp01((p - 0.3) / 0.08);
        leak.style.opacity = String(lp);
        leak.style.transform = `translateY(${(1 - lp) * 6}px)`;
        leak.setAttribute('data-redacted', redacted ? 'true' : 'false');
      }
      if (scan) {
        const sp = clamp01((p - 0.45) / 0.27);
        scan.style.opacity = sp > 0 && sp < 1 ? '1' : '0';
        scan.style.transform = `translateX(${-140 + sp * 460}%)`;
      }
      if (blocked) {
        const bp = clamp01((p - 0.72) / 0.1);
        blocked.style.opacity = String(bp);
        blocked.style.transform = `translateY(${(1 - bp) * 8}px)`;
      }
      if (note) {
        const np = clamp01((p - 0.82) / 0.1);
        note.style.opacity = String(np);
        note.style.transform = `translateY(${(1 - np) * 8}px)`;
      }
      // Headline accent resolves as the redaction completes.
      if (heroEl) heroEl.style.setProperty('--resolve', String(clamp01((p - 0.6) / 0.35)));
    };

    const mm = gsap.matchMedia();
    mm.add(
      {
        reduce: '(prefers-reduced-motion: reduce)',
        ok: '(prefers-reduced-motion: no-preference)',
        pin: '(min-width: 880px) and (prefers-reduced-motion: no-preference)',
        pointer: '(hover: hover) and (pointer: fine)',
      },
      (ctx) => {
        const { reduce, pin, pointer } = ctx.conditions as {
          reduce: boolean;
          ok: boolean;
          pin: boolean;
          pointer: boolean;
        };

        // ---- reduced motion: show everything settled, no scroll machinery ----
        if (reduce) {
          renderDemo(1);
          gsap.set(
            [
              '.fida-nav',
              '.fida-eyebrow',
              '.fida-headline .fida-word > span',
              '.fida-sub',
              '.fida-cta-row',
              '.fida-install',
              '.fida-hero__demo',
              '[data-reveal]',
              '.fida-term__line',
              '.fida-statement .fida-w',
            ],
            { autoAlpha: 1, y: 0, yPercent: 0 }
          );
          return;
        }

        renderDemo(0);

        // ---- hero entrance (paused; released by the loader hand-off) ----
        const intro = gsap.timeline({ paused: true, defaults: { ease: 'power3.out' } });
        intro
          .from('.fida-nav', { y: -24, autoAlpha: 0, duration: 0.7 }, 0.1)
          .from('.fida-eyebrow', { y: 22, autoAlpha: 0, duration: 0.6 }, 0.2)
          .from(
            '.fida-headline .fida-word > span',
            { yPercent: 118, duration: 0.95, stagger: 0.055, ease: 'power4.out' },
            0.3
          )
          .from('.fida-sub', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.55')
          .from('.fida-hero__demo', { y: 34, autoAlpha: 0, duration: 0.9 }, '-=0.5')
          .from('.fida-cta-row', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.55')
          .from('.fida-install', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.55');
        introRef.current = intro;
        if (started) intro.play();

        // ---- pinned, scroll-scrubbed redaction demo (hero is the stage) ----
        if (pin) {
          ScrollTrigger.create({
            trigger: '.fida-hero',
            start: 'top top',
            end: '+=130%',
            pin: true,
            scrub: true,
            onUpdate: (self) => renderDemo(self.progress),
          });
        } else {
          // Mobile: the hero is taller than the viewport, so pinning it would
          // leave the demo below the fold. Pin just the demo instead — it holds
          // centered while the redaction scrubs, so the animation is actually
          // seen before the page scrolls on to the next section.
          ScrollTrigger.create({
            trigger: '.fida-hero__demo',
            start: 'center 45%',
            end: '+=120%',
            pin: '.fida-hero__demo',
            scrub: true,
            onUpdate: (self) => renderDemo(self.progress),
          });
        }

        // ---- statement: brighten word-by-word ----
        gsap.fromTo(
          '.fida-statement .fida-w',
          { opacity: 0.12 },
          {
            opacity: 1,
            ease: 'none',
            stagger: 0.4,
            scrollTrigger: {
              trigger: '.fida-statement',
              start: 'top 72%',
              end: 'bottom 62%',
              scrub: true,
            },
          }
        );

        // ---- feature blocks: reveal block, then stagger its terminal lines ----
        gsap.utils.toArray<HTMLElement>('.fida-feat').forEach((feat) => {
          const lines = feat.querySelectorAll('.fida-term__line');
          gsap.set(feat.querySelectorAll('[data-reveal]'), { autoAlpha: 0, y: 30 });
          gsap.set(lines, { autoAlpha: 0, y: 8 });
          ScrollTrigger.create({
            trigger: feat,
            start: 'top 78%',
            once: true,
            onEnter: () => {
              gsap.to(feat.querySelectorAll('[data-reveal]'), {
                autoAlpha: 1,
                y: 0,
                duration: 0.7,
                ease: 'power3.out',
                stagger: 0.1,
              });
              gsap.to(lines, {
                autoAlpha: 1,
                y: 0,
                duration: 0.4,
                ease: 'power2.out',
                stagger: 0.08,
                delay: 0.25,
              });
            },
          });
        });

        // ---- generic reveal (CTA panel, etc.) ----
        gsap.set('[data-reveal].fida-solo', { autoAlpha: 0, y: 30 });
        ScrollTrigger.batch('[data-reveal].fida-solo', {
          start: 'top 85%',
          once: true,
          onEnter: (batch) =>
            gsap.to(batch, {
              autoAlpha: 1,
              y: 0,
              duration: 0.7,
              ease: 'power3.out',
              stagger: 0.12,
              overwrite: true,
            }),
        });

        // ---- agent marquee — base drift; scroll velocity boosts + flips it ----
        const marquee = gsap.to('.fida-marquee__track', {
          xPercent: -50,
          duration: 22,
          ease: 'none',
          repeat: -1,
        });
        ScrollTrigger.create({
          onUpdate: (self) => {
            const v = gsap.utils.clamp(-8, 8, self.getVelocity() / 260);
            if (v !== 0) marquee.timeScale(Math.sign(v) * Math.max(1, Math.abs(v)));
            gsap.to(marquee, { timeScale: 1, duration: 0.7, overwrite: true });
          },
        });

        // ---- scan-progress rail — fills with whole-page scroll ----
        gsap.fromTo(
          '.fida-rail > i',
          { scaleY: 0 },
          {
            scaleY: 1,
            ease: 'none',
            scrollTrigger: { trigger: el, start: 'top top', end: 'bottom bottom', scrub: true },
          }
        );

        // ---- pointer micro-interactions — magnetic CTAs only (restrained) ----
        if (pointer) {
          const cleanups: Array<() => void> = [];
          el.querySelectorAll<HTMLElement>('.fida-magnet').forEach((mag) => {
            const mx = gsap.quickTo(mag, 'x', { duration: 0.5, ease: 'power3' });
            const my = gsap.quickTo(mag, 'y', { duration: 0.5, ease: 'power3' });
            const onMove = (e: PointerEvent) => {
              const r = mag.getBoundingClientRect();
              mx((e.clientX - (r.left + r.width / 2)) * 0.3);
              my((e.clientY - (r.top + r.height / 2)) * 0.4);
            };
            const onLeave = () => {
              mx(0);
              my(0);
            };
            mag.addEventListener('pointermove', onMove);
            mag.addEventListener('pointerleave', onLeave);
            cleanups.push(() => {
              mag.removeEventListener('pointermove', onMove);
              mag.removeEventListener('pointerleave', onLeave);
            });
          });
          return () => cleanups.forEach((fn) => fn());
        }
      },
      el
    );

    return () => mm.revert();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const copyInstall = async () => {
    try {
      await navigator.clipboard.writeText(INSTALL_CMD);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard blocked — leave the command visible to copy by hand
    }
  };

  return (
    <div className="fida" ref={root}>
      <Loader onDone={onLoaderDone} />
      <div className="fida-rail" aria-hidden="true">
        <i />
      </div>

      {/* ---------------- Nav ---------------- */}
      <nav className="fida-nav">
        <a className="fida-nav__brand" href="/">
          <Image
            src={fidaLogo}
            alt="Fida"
            width={24}
            height={24}
            priority
            className="invert brightness-0"
          />
          <span>Fida</span>
          <span className="fida-nav__ver">v{packageJson.version}</span>
        </a>
        <div className="fida-nav__links">
          <a href="/docs">Docs</a>
          <a href="https://github.com/ajipurn/fida" target="_blank" rel="noreferrer">
            GitHub
          </a>
        </div>
      </nav>

      {/* ---------------- Hero (pinned stage) ---------------- */}
      <section className="fida-hero">
        <span className="fida-nav-sentinel" aria-hidden="true" />
        <div className="fida-hero__aurora" aria-hidden="true">
          <i className="fida-aurora-a" />
          <i className="fida-aurora-b" />
          <i className="fida-aurora-c" />
          <span className="fida-hero__grid" />
        </div>

        <div className="fida-hero__content">
          <span className="fida-eyebrow">
            <ShieldIcon />
            Local-first · agent-agnostic
          </span>

          <h1 className="fida-headline">
            {HEADLINE.flatMap((word, i) => [
              <span className="fida-word" key={`h${i}`}>
                <span>{word}</span>
              </span>,
              ' ',
            ])}
            <br />
            <span className="fida-headline__accent">
              {HEADLINE_ACCENT.flatMap((word, i) => [
                <span className="fida-word" key={`a${i}`}>
                  <span>{word}</span>
                </span>,
                ' ',
              ])}
            </span>
          </h1>

          <p className="fida-sub">
            Fida installs local protection for AI coding agents, verifies it with a synthetic
            credential, and scans repository risk. Secret values are redacted before reaching
            the model.
          </p>

          {/* ---- redaction demo: the centerpiece, scrubbed by scroll ---- */}
          <div
            className="fida-hero__demo"
            role="img"
            aria-label="An AI agent reads .env through Fida; the file stays readable while the synthetic credential is redacted before it reaches the model."
          >
            <div className="fida-demo">
              <div className="fida-demo__bar">
                <span className="fida-demo__dot" />
                <span className="fida-demo__dot" />
                <span className="fida-demo__dot" />
                <span className="fida-demo__status">protected</span>
              </div>
              <div className="fida-demo__screen">
                <span className="fida-demo__scan" data-scan />
                <div className="fida-line fida-line--cmd">
                  <span className="fida-prompt">$</span> <span data-type />
                  <span className="fida-caret" data-caret />
                </div>
                <div className="fida-line fida-line--leak" data-leak data-redacted="false">
                  DEMO_CREDENTIAL=<span data-secret />
                </div>
                <div className="fida-line fida-line--blocked" data-blocked>
                  <ShieldIcon />
                  SAFE VIEW — detected value redacted
                </div>
                <div className="fida-line fida-line--note" data-note>
                  useful structure returned · the secret never reached the model
                </div>
              </div>
            </div>
            <span className="fida-hero__scrollcue" aria-hidden="true">
              scroll to redact
            </span>
          </div>

          <div className="fida-cta-row">
            <span className="fida-magnet">
              <a className="fida-btn fida-btn--primary" href="/docs">
                Get started
              </a>
            </span>
            <span className="fida-magnet">
              <a
                className="fida-btn fida-btn--ghost"
                href="https://github.com/ajipurn/fida"
                target="_blank"
                rel="noreferrer"
              >
                View on GitHub
              </a>
            </span>
          </div>

          <div className="fida-install">
            <code className="fida-install__cmd">
              <b>$</b>
              {INSTALL_CMD}
            </code>
            <button
              type="button"
              className="fida-install__copy"
              data-copied={copied}
              onClick={copyInstall}
              aria-label={copied ? 'Install command copied' : 'Copy install command'}
            >
              {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </div>
      </section>

      {/* ---------------- Statement ---------------- */}
      <section className="fida-statement">
        <p className="fida-statement__line">
          {STATEMENT.flatMap((word, i) => [
            <span className="fida-w" key={i}>
              {word}
            </span>,
            ' ',
          ])}
        </p>
      </section>

      {/* ---------------- Feature blocks ---------------- */}
      <section className="fida-shell fida-feats">
        <div className="fida-feats__head fida-solo" data-reveal>
          <span className="fida-kicker">install · verify · scan</span>
          <h2>Three commands. Honest coverage.</h2>
          <p>
            Install protection for detected agents, verify the real read and shell paths, then
            see whether a raw secret value can still reach a model.
          </p>
        </div>

        {FEATURES.map((f, i) => (
          <article className={`fida-feat ${i % 2 ? 'fida-feat--rev' : ''}`} key={f.tag}>
            <div className="fida-feat__copy">
              <span className="fida-feat__tag" data-reveal>
                {f.tag}
              </span>
              <h3 data-reveal>{f.title}</h3>
              <p data-reveal>{f.body}</p>
              <code className="fida-feat__cmd" data-reveal>
                {f.cmd}
              </code>
            </div>
            <div className="fida-feat__term" data-reveal>
              <div className="fida-term">
                <div className="fida-term__bar">
                  <span className="fida-term__dot" />
                  <span className="fida-term__dot" />
                  <span className="fida-term__dot" />
                  <span className="fida-term__name">{f.status}</span>
                </div>
                <div className="fida-term__screen">
                  {f.lines.map((ln, j) => (
                    <div
                      className={`fida-term__line${ln.c ? ` is-${ln.c}` : ''}`}
                      key={j}
                    >
                      {ln.p ? <span className="fida-term__prompt">$</span> : null}
                      {ln.t}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </article>
        ))}
      </section>

      {/* ---------------- Agents marquee ---------------- */}
      <section className="fida-marquee" aria-label="Supported agent integrations">
        <div className="fida-marquee__track">
          {[0, 1].map((dup) => (
            <ul className="fida-marquee__group" key={dup} aria-hidden={dup === 1}>
              {AGENTS.map((name) => (
                <li key={name}>
                  {name}
                  <span className="fida-marquee__sep">✳</span>
                </li>
              ))}
            </ul>
          ))}
        </div>
      </section>

      {/* ---------------- Final CTA ---------------- */}
      <section className="fida-shell fida-final">
        <div className="fida-final__panel fida-solo" data-reveal>
          <h2>Protection you can verify.</h2>
          <p>
            One command installs supported integrations, runs a synthetic-secret self-test, and
            scans your repository. Fida reports enforced and best-effort coverage honestly.
          </p>
          <div className="fida-cta-row">
            <span className="fida-magnet">
              <Link className="fida-btn fida-btn--primary" href="/docs">
                Read the docs
              </Link>
            </span>
            <span className="fida-magnet">
              <a
                className="fida-btn fida-btn--ghost"
                href="https://github.com/ajipurn/fida"
                target="_blank"
                rel="noreferrer"
              >
                Star on GitHub
              </a>
            </span>
          </div>
        </div>
      </section>

      {/* ---------------- Footer ---------------- */}
      <footer className="fida-shell fida-foot">
        <div className="fida-foot__row">
          <span className="fida-foot__name">
            Fida <span>— secrets stay secret.</span>
          </span>
          <nav className="fida-foot__links">
            <a href="/docs">Docs</a>
            <a href="https://github.com/ajipurn/fida" target="_blank" rel="noreferrer">
              GitHub
            </a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
