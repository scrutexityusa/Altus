/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // The dashboard renders the control plane's own read model on every request.
  // Caching an authority view would show an operator authority that has
  // already been revoked, which is the one thing this screen must never do.
  experimental: { staleTimes: { dynamic: 0, static: 0 } },
};
export default nextConfig;
