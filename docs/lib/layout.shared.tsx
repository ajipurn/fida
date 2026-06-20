import Image from 'next/image';
import fidaLogo from '@assets/fida-logo.png';
import type { BaseLayoutProps } from 'fumadocs-ui/layouts/shared';
import packageJson from '../package.json';

export function baseOptions(): BaseLayoutProps {
  return {
    nav: {
      title: (
        <span className="flex items-center gap-2 font-semibold">
          <Image
            src={fidaLogo}
            alt="Fida logo"
            width={28}
            height={28}
            className="size-7 object-contain dark:brightness-0 dark:invert"
          />
          <span>Fida</span>
          <span className="text-[10px] text-fd-muted-foreground border rounded-full px-1.5 py-0.5 leading-none">v{packageJson.version}</span>
        </span>
      ),
    },
    githubUrl: 'https://github.com/ajipurn/fida',
  };
}
