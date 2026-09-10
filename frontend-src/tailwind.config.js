/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#050810',
          panel: '#0a0f1e',
          border: 'rgba(56, 189, 248, 0.15)',
          cyan: '#22d3ee',
          red: '#f43f5e',
          amber: '#f59e0b',
          green: '#10b981',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', 'Consolas', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'glow-red': 'glowRed 2s ease-in-out infinite',
      },
      keyframes: {
        glowRed: {
          '0%, 100%': { boxShadow: '0 0 5px rgba(244,63,94,0.5)' },
          '50%': { boxShadow: '0 0 20px rgba(244,63,94,0.9)' },
        },
      },
    },
  },
  plugins: [],
}
