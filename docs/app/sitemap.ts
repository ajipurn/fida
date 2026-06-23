import type { MetadataRoute } from 'next';
import { source } from '@/lib/source';

const SITE_URL = 'https://fida.my.id';

export default function sitemap(): MetadataRoute.Sitemap {
  const docs = source.getPages().map((page) => ({
    url: new URL(page.url, SITE_URL).toString(),
    changeFrequency: 'weekly' as const,
    priority: 0.7,
  }));

  return [
    { url: SITE_URL, changeFrequency: 'weekly', priority: 1 },
    ...docs,
  ];
}
