import type { MetadataRoute } from 'next';

export default function robots(): MetadataRoute.Robots {
  return {
    rules: { userAgent: '*', allow: '/' },
    sitemap: 'https://fida.my.id/sitemap.xml',
    host: 'https://fida.my.id',
  };
}
