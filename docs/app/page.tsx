
import { HomeLayout } from 'fumadocs-ui/layouts/home';
import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import { baseOptions } from '@/lib/layout.shared';
import { Landing } from '@/components/landing';

const homeOptions: BaseLayoutProps = {
  ...baseOptions(),
};

export default function HomePage() {
  return (
    <HomeLayout {...homeOptions}>
      <Landing />
    </HomeLayout>
  );
}
