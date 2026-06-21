import type { ReactNode } from 'react';
import type { Metadata } from 'next';
import { IBM_Plex_Sans, IBM_Plex_Mono, Martian_Mono } from 'next/font/google';
import localFont from 'next/font/local';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';

// /docs keeps IBM Plex — proven for long-form reading and code blocks.
const plexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-hum-sans',
});

const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: ['400', '600'],
  variable: '--font-hum-mono',
});

// Landing-only display face — Cabinet Grotesk (Fontshare, self-hosted variable).
const cabinet = localFont({
  src: '../assets/fonts/CabinetGrotesk-Variable.woff2',
  weight: '100 900',
  variable: '--font-cabinet',
  display: 'swap',
});

// Landing-only CLI/mono — Martian Mono (Evil Martians).
const martian = Martian_Mono({
  subsets: ['latin'],
  weight: ['400', '500', '600', '700'],
  variable: '--font-martian',
});

export const metadata: Metadata = {
  title: {
    default: 'Fida',
    template: '%s | Fida',
  },
  description: 'Documentation for Fida, a local-first secret-leak prevention layer for AI coding agents.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html
      lang="en"
      className={`${plexSans.variable} ${plexMono.variable} ${cabinet.variable} ${martian.variable}`}
      suppressHydrationWarning
    >
      <body className="min-h-screen">
        <RootProvider search={{ options: { api: '/api/search' } }}>
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
