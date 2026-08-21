import type { Config } from 'tailwindcss';

export default {
  content: ['./app/**/*.{ts,tsx}', './components/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        allow: { fg: '#14532d', bg: '#dcfce7', border: '#86efac' },
        deny: { fg: '#7f1d1d', bg: '#fee2e2', border: '#fca5a5' },
        escalate: { fg: '#78350f', bg: '#fef3c7', border: '#fcd34d' },
      },
      fontFamily: {
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
    },
  },
  plugins: [],
} satisfies Config;
