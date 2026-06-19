'use client';

import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import gsap from 'gsap';
import { ScrollTrigger } from 'gsap/ScrollTrigger';
import { OverlayScrollbars } from 'overlayscrollbars';
import 'overlayscrollbars/overlayscrollbars.css';

const INSTALL_CMD =
  'curl -fsSL https://raw.githubusercontent.com/ajipurn/fida/main/install.sh | sh';
const TYPED = 'fida_read .env';
const DEMO_SECRET = 'synthetic-credential-value';
const REDACTED = '\u2022'.repeat(20);

const AGENTS = [
  'Codex',
  'Claude Code',
  'Cursor',
  'OpenCode',
  'Windsurf',
  'Copilot',
  'Antigravity',
];

// Run before paint on the client, fall back to useEffect on the server.
const useIsomorphicLayoutEffect =
  typeof window !== 'undefined' ? useLayoutEffect : useEffect;

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 4.5 5.5v6c0 4.4 3.1 7.6 7.5 9 4.4-1.4 7.5-4.6 7.5-9v-6L12 2.5Z"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path
        d="m8.8 12 2.2 2.2 4.2-4.4"
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
  const demoRef = useRef<gsap.core.Timeline | null>(null);
  const [copied, setCopied] = useState(false);

  useIsomorphicLayoutEffect(() => {
    const el = root.current;
    if (!el) return;

    const q = <T extends Element>(sel: string) => el.querySelector<T>(sel);
    const typeEl = q<HTMLElement>('[data-type]');
    const secretEl = q<HTMLElement>('[data-secret]');
    const scan = q<HTMLElement>('[data-scan]');
    const leak = q<HTMLElement>('[data-leak]');
    const blocked = q<HTMLElement>('[data-blocked]');
    const note = q<HTMLElement>('[data-note]');
    const reveals = Array.from(el.querySelectorAll<HTMLElement>('[data-reveal]'));

    const setFinalDemo = () => {
      if (typeEl) typeEl.textContent = TYPED;
      if (secretEl) secretEl.textContent = REDACTED;
      leak?.setAttribute('data-redacted', 'true');
      gsap.set([leak, blocked, note], { autoAlpha: 1, y: 0 });
      gsap.set(scan, { autoAlpha: 0 });
    };

    const buildDemo = () => {
      const tl = gsap.timeline({ paused: true });
      const counter = { i: 0 };
      tl.set([leak, blocked, note], { autoAlpha: 0, y: 4 })
        .set(scan, { autoAlpha: 0, xPercent: -140 })
        .call(() => {
          if (typeEl) typeEl.textContent = '';
          if (secretEl) secretEl.textContent = DEMO_SECRET;
          leak?.setAttribute('data-redacted', 'false');
          counter.i = 0;
        })
        .to(counter, {
          i: TYPED.length,
          duration: 0.7,
          ease: 'none',
          onUpdate: () => {
            if (typeEl) typeEl.textContent = TYPED.slice(0, Math.round(counter.i));
          },
        })
        .to(leak, { autoAlpha: 1, y: 0, duration: 0.25, ease: 'power2.out' }, '+=0.35')
        // scanning sweep crosses the screen, redacting the secret mid-pass
        .to(scan, { autoAlpha: 1, duration: 0.12 }, '+=0.25')
        .to(scan, { xPercent: 320, duration: 0.75, ease: 'power2.inOut' }, '<')
        .call(
          () => {
            if (secretEl) secretEl.textContent = REDACTED;
            leak?.setAttribute('data-redacted', 'true');
          },
          undefined,
          '<0.32'
        )
        .to(scan, { autoAlpha: 0, duration: 0.18 }, '>-0.12')
        .to(blocked, { autoAlpha: 1, y: 0, duration: 0.3, ease: 'power3.out' }, '-=0.05')
        .to(note, { autoAlpha: 1, y: 0, duration: 0.3, ease: 'power2.out' }, '-=0.12');
      return tl;
    };

    gsap.registerPlugin(ScrollTrigger);

    const agents = q<HTMLElement>('[data-agents]');
    const heroGlow = q<HTMLElement>('.fida-hero__glow');
    const demoCard = q<HTMLElement>('[data-demo]');

    const mm = gsap.matchMedia();

    mm.add(
      {
        reduce: '(prefers-reduced-motion: reduce)',
        full: '(prefers-reduced-motion: no-preference)',
        pointer: '(hover: hover) and (pointer: fine)',
      },
      (ctx) => {
        const { reduce, pointer } = ctx.conditions as {
          reduce: boolean;
          full: boolean;
          pointer: boolean;
        };

        if (reduce) {
          setFinalDemo();
          gsap.set(reveals, { autoAlpha: 1, y: 0 });
          return;
        }

        // hide demo lines + scroll-reveal targets up front
        gsap.set([leak, blocked, note, scan], { autoAlpha: 0 });
        gsap.set(reveals, { autoAlpha: 0, y: 28 });

        const demoTl = buildDemo();
        demoRef.current = demoTl;

        // hero entrance, then kick off the redaction demo
        const entrance = gsap.timeline({ defaults: { ease: 'power3.out' } });
        entrance
          .from('[data-hero-stagger] > *', {
            y: 26,
            autoAlpha: 0,
            duration: 0.6,
            stagger: 0.08,
          })
          .from('[data-demo]', { y: 32, autoAlpha: 0, duration: 0.7 }, '-=0.3')
          .add(() => demoTl.restart(), '-=0.05');

        // coordinated, staggered scroll-reveal (ScrollTrigger.batch > IntersectionObserver)
        ScrollTrigger.batch(reveals, {
          start: 'top 85%',
          once: true,
          onEnter: (batch) =>
            gsap.to(batch, {
              autoAlpha: 1,
              y: 0,
              duration: 0.6,
              ease: 'power3.out',
              stagger: 0.12,
              overwrite: true,
            }),
        });

        // agents label + chips cascade in
        if (agents) {
          gsap.from(
            agents.querySelectorAll('.fida-agents__label, .fida-agents__list li'),
            {
              autoAlpha: 0,
              y: 16,
              duration: 0.5,
              ease: 'power3.out',
              stagger: 0.05,
              scrollTrigger: { trigger: agents, start: 'top 82%', once: true },
            }
          );
        }

        // subtle parallax depth on the hero glow
        if (heroGlow) {
          gsap.to(heroGlow, {
            yPercent: 24,
            ease: 'none',
            scrollTrigger: {
              trigger: '.fida-hero',
              start: 'top top',
              end: 'bottom top',
              scrub: true,
            },
          });
        }

        // interactive 3D tilt on the demo card — fine-pointer devices only, quickTo for 60fps
        if (pointer && demoCard) {
          gsap.set(demoCard, { transformPerspective: 900, transformOrigin: 'center' });
          const tiltX = gsap.utils.clamp(-5, 5);
          const tiltY = gsap.utils.clamp(-5, 5);
          const rotX = gsap.quickTo(demoCard, 'rotationX', { duration: 0.5, ease: 'power3' });
          const rotY = gsap.quickTo(demoCard, 'rotationY', { duration: 0.5, ease: 'power3' });
          const onMove = (e: PointerEvent) => {
            const r = demoCard.getBoundingClientRect();
            rotY(tiltX(gsap.utils.mapRange(0, r.width, -5, 5, e.clientX - r.left)));
            rotX(tiltY(gsap.utils.mapRange(0, r.height, 5, -5, e.clientY - r.top)));
          };
          const onLeave = () => {
            rotX(0);
            rotY(0);
          };
          demoCard.addEventListener('pointermove', onMove);
          demoCard.addEventListener('pointerleave', onLeave);
          return () => {
            demoCard.removeEventListener('pointermove', onMove);
            demoCard.removeEventListener('pointerleave', onLeave);
          };
        }
      },
      el
    );

    return () => mm.revert();
  }, []);

  // Custom overlay scrollbars — page-level, only while the HomePage is mounted.
  useEffect(() => {
    const osInstance = OverlayScrollbars(document.body, {
      scrollbars: { theme: 'os-theme-fida', autoHide: 'leave', autoHideDelay: 600 },
    });
    return () => osInstance.destroy();
  }, []);

  const replay = () => demoRef.current?.restart();

  const copyInstall = async () => {
    try {
      await navigator.clipboard.writeText(INSTALL_CMD);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // clipboard blocked (insecure context / denied) — leave the command visible to copy by hand
    }
  };

  return (
    <div className="fida" ref={root}>
      {/* ---------------- Hero ---------------- */}
      <section className="fida-hero">
        <div className="fida-hero__glow" aria-hidden="true" />
        <div className="fida-shell fida-hero__inner" data-hero-stagger>
          <span className="fida-eyebrow">
            <ShieldIcon />
            Local-first &middot; agent-agnostic
          </span>

          <h1 className="fida-headline">
            Let agents read your code,{' '}
            <span className="fida-headline__accent">not your secrets.</span>
          </h1>

          <p className="fida-sub">
            Fida installs local protection for AI coding agents, verifies it with a
            synthetic credential, and scans repository risk. Secret values are redacted
            before reaching the model.
          </p>

          <div className="fida-cta-row">
            <a className="fida-btn fida-btn--primary" href="/docs">
              Get started
            </a>
            <a
              className="fida-btn fida-btn--ghost"
              href="https://github.com/ajipurn/fida"
              target="_blank"
              rel="noreferrer"
            >
              View on GitHub
            </a>
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

        {/* live redaction demo — content surface, no fake window chrome */}
        <div className="fida-shell">
          <div
            className="fida-demo"
            data-demo
            role="img"
            aria-label="An AI agent reads .env through Fida; the file remains readable while the synthetic credential is redacted before it reaches the model."
          >
            <div className="fida-demo__bar">
              {/* <span className="fida-demo__label">fida gateway</span> */}
              <span className="fida-demo__status">protected</span>
              <button
                type="button"
                className="fida-demo__replay"
                onClick={replay}
                aria-label="Replay the demo"
              >
                replay &#8635;
              </button>
            </div>
            <div className="fida-demo__screen" data-demo-screen aria-hidden="true">
              <span className="fida-demo__scan" data-scan />
              <div className="fida-line fida-line--cmd">
                <span className="fida-prompt">$</span> <span data-type />
                <span className="fida-caret" data-caret />
              </div>
              <div className="fida-line fida-line--leak" data-leak data-redacted="false">
                DEMO_CREDENTIAL=<span className="fida-secret" data-secret>{DEMO_SECRET}</span>
              </div>
              <div className="fida-line fida-line--blocked" data-blocked>
                <ShieldIcon />
                SAFE VIEW &mdash; detected value redacted
              </div>
              <div className="fida-line fida-line--note" data-note>
                useful structure returned &middot; the secret never reached the model
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---------------- Agents strip ---------------- */}
      <section className="fida-shell fida-agents" data-agents>
        <p className="fida-agents__label">Supported agent integrations</p>
        <ul className="fida-agents__list">
          {AGENTS.map((name) => (
            <li key={name}>{name}</li>
          ))}
        </ul>
      </section>

      {/* ---------------- Pillars ---------------- */}
      <section className="fida-shell fida-pillars">
        <div className="fida-pillars__head" data-reveal>
          <h2>Install. Verify. Scan.</h2>
          <p>
            Install protection for detected agents, verify the real read and shell paths,
            then see whether raw secret values can still reach a model.
          </p>
        </div>
        <div className="fida-grid">
          <article className="fida-card" data-reveal>
            <span className="fida-card__tag">01 / protect</span>
            <h3>Install agent protection</h3>
            <p>
              Set up supported integrations and prepare a safe redacted view for model-bound
              output.
            </p>
            <code>fida init</code>
          </article>
          <article className="fida-card" data-reveal>
            <span className="fida-card__tag">02 / verify</span>
            <h3>Know your coverage</h3>
            <p>
              See enforced, best-effort, or incomplete protection alongside the latest
              synthetic-secret self-test.
            </p>
            <code>fida status</code>
          </article>
          <article className="fida-card" data-reveal>
            <span className="fida-card__tag">03 / scan</span>
            <h3>Find raw-secret risk</h3>
            <p>
              Scan tracked and sensitive ignored files, then distinguish discovered secrets
              from raw model exposure.
            </p>
            <code>fida scan</code>
          </article>
        </div>
      </section>

      {/* ---------------- Final CTA ---------------- */}
      <section className="fida-shell fida-final">
        <div className="fida-final__panel" data-reveal>
          <h2>Protection you can verify.</h2>
          <p>
            One command installs supported integrations, runs a synthetic-secret self-test,
            and scans your repository. Fida reports enforced and best-effort coverage
            honestly.
          </p>
          <div className="fida-cta-row">
            <a className="fida-btn fida-btn--primary" href="/docs">
              Read the docs
            </a>
            <a
              className="fida-btn fida-btn--ghost"
              href="https://github.com/ajipurn/fida"
              target="_blank"
              rel="noreferrer"
            >
              Star on GitHub
            </a>
          </div>
        </div>
      </section>

      {/* ---------------- Footer line ---------------- */}
      <footer className="fida-shell fida-foot">
        <div className="fida-foot__row">
          <span className="fida-foot__name">
            Fida <span>&mdash; secrets stay secret.</span>
          </span>
          <nav className="fida-foot__links">
            <a href="/docs">Docs</a>
            <a href="https://github.com/ajipurn/fida" target="_blank" rel="noreferrer">
              GitHub
            </a>
            <a
              href="https://github.com/ajipurn/fida/blob/main/SECURITY.md"
              target="_blank"
              rel="noreferrer"
            >
              Security
            </a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
