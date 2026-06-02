/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        sentri: {
          green: '#22c55e',
          cyan: '#06b6d4',
          red: '#ef4444',
          amber: '#f59e0b'
        }
      },
      boxShadow: {
        glow: '0 0 28px rgba(34, 197, 94, 0.16)'
      }
    }
  },
  plugins: []
};
