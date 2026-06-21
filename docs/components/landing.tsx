'use client';

import { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import Image from 'next/image';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import Lenis from 'lenis';
import fidaLogo from '@assets/fida-logo.png';
import packageJson from '../package.json';
import { SecretField } from './secret-field';
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

const PILLARS = [
  {
    tag: '01 / protect',
    title: 'Install agent protection',
    body: 'Set up supported integrations and prepare a safe redacted view for model-bound output.',
    cmd: 'fida',
  },
  {
    tag: '02 / verify',
    title: 'Know your coverage',
    body: 'See enforced, best-effort, or incomplete protection alongside the latest synthetic-secret self-test.',
    cmd: 'fida status',
  },
  {
    tag: '03 / scan',
    title: 'Find raw-secret risk',
    body: 'Scan tracked and sensitive ignored files, then distinguish discovered secrets from raw model exposure.',
    cmd: 'fida scan',
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
  const exposureRef = useRef(0);
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
    const typeEl = q<HTMLElement>('[data-type]');
    const secretEl = q<HTMLElement>('[data-secret]');
    const caret = q<HTMLElement>('[data-caret]');
    const scan = q<HTMLElement>('[data-scan]');
    const leak = q<HTMLElement>('[data-leak]');
    const blocked = q<HTMLElement>('[data-blocked]');
    const note = q<HTMLElement>('[data-note]');

    // Deterministic demo state for a scrub position p ∈ [0,1] — read→type→
    // leak→scan→redact→safe. Pure function of p so it scrubs both ways.
    const renderDemo = (p: number) => {
      const tp = clamp01(p / 0.3);
      if (typeEl) typeEl.textContent = TYPED.slice(0, Math.round(tp * TYPED.length));
      if (caret) caret.style.opacity = p < 0.34 ? '1' : '0';

      const redacted = p >= 0.6;
      const showSecret = p >= 0.3;
      if (secretEl) secretEl.textContent = redacted ? REDACTED : showSecret ? DEMO_SECRET : '';

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
      exposureRef.current = p >= 0.3 && p < 0.6 ? 1 : 0;
    };

    const mm = gsap.matchMedia();
    mm.add(
      {
        reduce: '(prefers-reduced-motion: reduce)',
        ok: '(prefers-reduced-motion: no-preference)',
        pointer: '(hover: hover) and (pointer: fine)',
      },
      (ctx) => {
        const { reduce, pointer } = ctx.conditions as {
          reduce: boolean;
          ok: boolean;
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
              '[data-reveal]',
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
          .from('.fida-field', { autoAlpha: 0, duration: 1.4, ease: 'power2.out' }, 0)
          .from('.fida-nav', { y: -24, autoAlpha: 0, duration: 0.7 }, 0.1)
          .from('.fida-eyebrow', { y: 22, autoAlpha: 0, duration: 0.6 }, 0.2)
          .from(
            '.fida-headline .fida-word > span',
            { yPercent: 118, duration: 0.95, stagger: 0.055, ease: 'power4.out' },
            0.3
          )
          .from('.fida-sub', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.55')
          .from('.fida-cta-row', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.45')
          .from('.fida-install', { y: 22, autoAlpha: 0, duration: 0.7 }, '-=0.5')
        introRef.current = intro;
        if (started) intro.play();

        // ---- hero parallax — content drifts up as you leave ----
        gsap.to('.fida-hero__content', {
          yPercent: -14,
          autoAlpha: 0.15,
          ease: 'none',
          scrollTrigger: {
            trigger: '.fida-hero',
            start: 'top top',
            end: 'bottom top',
            scrub: true,
          },
        });

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

        // ---- pinned, scroll-scrubbed redaction demo ----
        ScrollTrigger.create({
          trigger: '[data-demo-sec]',
          start: 'top top',
          end: '+=170%',
          pin: '[data-demo-pin]',
          scrub: true,
          onUpdate: (self) => renderDemo(self.progress),
        });

        // ---- pillar reveal ----
        gsap.set('[data-reveal]', { autoAlpha: 0, y: 30 });
        ScrollTrigger.batch('[data-reveal]', {
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
            // ease back to the calm forward drift
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

        // ---- pointer micro-interactions ----
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

          el.querySelectorAll<HTMLElement>('.fida-card').forEach((card) => {
            gsap.set(card, { transformPerspective: 800, transformOrigin: 'center' });
            const rotX = gsap.quickTo(card, 'rotationX', { duration: 0.5, ease: 'power3' });
            const rotY = gsap.quickTo(card, 'rotationY', { duration: 0.5, ease: 'power3' });
            const ly = gsap.quickTo(card, 'y', { duration: 0.5, ease: 'power3' });
            const onEnter = () => {
              card.style.setProperty('--spot', '1');
              ly(-6);
            };
            const onMove = (e: PointerEvent) => {
              const r = card.getBoundingClientRect();
              const px = (e.clientX - r.left) / r.width;
              const py = (e.clientY - r.top) / r.height;
              card.style.setProperty('--mx', `${px * 100}%`);
              card.style.setProperty('--my', `${py * 100}%`);
              rotY(gsap.utils.clamp(-4, 4, (px - 0.5) * 8));
              rotX(gsap.utils.clamp(-4, 4, (0.5 - py) * 8));
            };
            const onLeave = () => {
              card.style.setProperty('--spot', '0');
              rotX(0);
              rotY(0);
              ly(0);
            };
            card.addEventListener('pointerenter', onEnter);
            card.addEventListener('pointermove', onMove);
            card.addEventListener('pointerleave', onLeave);
            cleanups.push(() => {
              card.removeEventListener('pointerenter', onEnter);
              card.removeEventListener('pointermove', onMove);
              card.removeEventListener('pointerleave', onLeave);
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
        <a className="fida-nav__brand" href="/" data-cursor>
          <Image src={fidaLogo} alt="Fida" width={24} height={24} priority className='invert brightness-0' />
          <span>Fida</span>
          <span className="fida-nav__ver">v{packageJson.version}</span>
        </a>
        <div className="fida-nav__links">
          <a href="/docs" data-cursor>
            Docs
          </a>
          <a href="https://github.com/ajipurn/fida" target="_blank" rel="noreferrer" data-cursor>
            GitHub
          </a>
        </div>
      </nav>

      {/* ---------------- Hero ---------------- */}
      <section className="fida-hero">
        <span className="fida-nav-sentinel" aria-hidden="true" />
        <div className="fida-hero__field">
          <SecretField exposureRef={exposureRef} />
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
            {HEADLINE_ACCENT.flatMap((word, i) => [
              <span className="fida-word fida-headline__accent" key={`a${i}`}>
                <span>{word}</span>
              </span>,
              ' ',
            ])}
          </h1>

          <p className="fida-sub">
            Fida installs local protection for AI coding agents, verifies it with a synthetic
            credential, and scans repository risk. Secret values are redacted before reaching
            the model.
          </p>

          <div className="fida-cta-row">
            <span className="fida-magnet">
              <a className="fida-btn fida-btn--primary" href="/docs" data-cursor>
                Get started
              </a>
            </span>
            <span className="fida-magnet">
              <a
                className="fida-btn fida-btn--ghost"
                href="https://github.com/ajipurn/fida"
                target="_blank"
                rel="noreferrer"
                data-cursor
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
              data-cursor
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

      {/* ---------------- Pinned redaction demo ---------------- */}
      <section className="fida-demo-sec" data-demo-sec>
        <div className="fida-demo-pin" data-demo-pin>
          <div className="fida-demo-cap">
            <span className="fida-kicker">live · redaction</span>
            <h2>Read the file. Not the secret.</h2>
          </div>
          <div
            className="fida-demo"
            data-demo
            role="img"
            aria-label="An AI agent reads .env through Fida; the file stays readable while the synthetic credential is redacted before it reaches the model."
          >
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
        </div>
      </section>

      {/* ---------------- Pillars ---------------- */}
      <section className="fida-shell fida-pillars">
        <div className="fida-pillars__head" data-reveal>
          <h2>Install. Verify. Scan.</h2>
          <p>
            Install protection for detected agents, verify the real read and shell paths, then
            see whether raw secret values can still reach a model.
          </p>
        </div>
        <div className="fida-grid">
          {PILLARS.map((p) => (
            <article className="fida-card" data-reveal key={p.tag}>
              <span className="fida-card__tag">{p.tag}</span>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
              <code>{p.cmd}</code>
            </article>
          ))}
        </div>
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
        <div className="fida-final__panel" data-reveal>
          <h2>Protection you can verify.</h2>
          <p>
            One command installs supported integrations, runs a synthetic-secret self-test, and
            scans your repository. Fida reports enforced and best-effort coverage honestly.
          </p>
          <div className="fida-cta-row">
            <span className="fida-magnet">
              <Link className="fida-btn fida-btn--primary" href="/docs" data-cursor>
                Read the docs
              </Link>
            </span>
            <span className="fida-magnet">
              <a
                className="fida-btn fida-btn--ghost"
                href="https://github.com/ajipurn/fida"
                target="_blank"
                rel="noreferrer"
                data-cursor
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
            <a href="/docs" data-cursor>
              Docs
            </a>
            <a href="https://github.com/ajipurn/fida" target="_blank" rel="noreferrer" data-cursor>
              GitHub
            </a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
