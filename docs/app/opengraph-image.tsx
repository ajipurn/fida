import { ImageResponse } from 'next/og';

// Sitewide social share card (1200×630). Next.js serves this for og:image and,
// with no twitter-image present, reuses it for the Twitter card too.
export const alt = 'Fida — keep secret values out of AI coding agents';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          padding: '80px',
          background:
            'radial-gradient(120% 90% at 50% -10%, #0b1322 0%, #06070b 60%)',
          color: '#eef3fa',
          fontFamily: 'sans-serif',
        }}
      >
        <div
          style={{
            display: 'flex',
            fontSize: 26,
            letterSpacing: '0.18em',
            textTransform: 'uppercase',
            color: '#7fb4ff',
          }}
        >
          Local-first secret-leak prevention
        </div>
        <div
          style={{
            display: 'flex',
            marginTop: 24,
            fontSize: 88,
            fontWeight: 800,
            letterSpacing: '-0.04em',
            lineHeight: 1.05,
          }}
        >
          Keep secret values out of AI coding agents
        </div>
        <div
          style={{
            display: 'flex',
            marginTop: 36,
            alignItems: 'center',
            gap: 16,
            fontSize: 40,
            fontWeight: 700,
          }}
        >
          <div
            style={{
              display: 'flex',
              width: 18,
              height: 18,
              borderRadius: 9,
              background: '#7fb4ff',
              boxShadow: '0 0 24px #7fb4ff',
            }}
          />
          Fida
        </div>
      </div>
    ),
    size,
  );
}
