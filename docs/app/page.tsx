import type { Metadata } from 'next';
import { HomeLayout } from 'fumadocs-ui/layouts/home';
import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { baseOptions } from '@/lib/layout.shared';
import { Landing } from '@/components/landing';

const title = 'Fida — keep secret values out of AI coding agents';
const description =
  'Fida is a local-first secret-leak prevention layer for AI coding agents. It finds exposed credentials and gives agents redacted safe views of sensitive files and command output, so a detected secret never reaches model context.';

export const metadata: Metadata = {
  title: { absolute: title },
  description,
  alternates: { canonical: '/' },
  openGraph: { url: '/', title, description },
  twitter: { title, description },
};

const homeOptions: BaseLayoutProps = {
  ...baseOptions(),
  // Landing ships its own minimal nav; hide the fumadocs navbar for a full-bleed hero.
  nav: { enabled: false },
};

export default function HomePage() {
  return (
    <HomeLayout {...homeOptions}>
      <Landing />
    </HomeLayout>
  );
}
