import { createMDX } from 'fumadocs-mdx/next';

/** @type {import('next').NextConfig} */
const config = {
  reactStrictMode: false,
};

const withMDX = createMDX();

export default withMDX(config);
