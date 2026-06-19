import { source } from '@/lib/source';
import { createFromSource } from 'fumadocs-core/search/server';

// Powers the fumadocs search dialog (the ⌘K trigger in the HomeLayout/DocsLayout
// navbars). RootProvider's default client fetches this route.
export const { GET } = createFromSource(source);
