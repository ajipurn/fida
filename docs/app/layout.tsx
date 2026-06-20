import type { ReactNode } from 'react';
import type { Metadata } from 'next';
import { IBM_Plex_Sans, IBM_Plex_Mono } from 'next/font/google';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';

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
      className={`${plexSans.variable} ${plexMono.variable}`}
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
