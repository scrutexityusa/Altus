import type { Metadata } from 'next';
import Link from 'next/link';
import './globals.css';

export const metadata: Metadata = {
  title: 'Scrutexity',
  description: 'Runtime authorization for high-consequence agent actions',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-50 text-slate-900 antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2 focus:shadow"
        >
          Skip to content
        </a>
        <header className="border-b border-slate-200 bg-white">
          <div className="mx-auto flex max-w-6xl items-baseline gap-6 px-6 py-4">
            <Link href="/" className="text-base font-semibold tracking-tight">
              Scrutexity
            </Link>
            <p className="text-xs text-slate-500">
              Machine authority control plane &middot; treasury operations
            </p>
          </div>
        </header>
        <main id="main" className="mx-auto max-w-6xl px-6 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
