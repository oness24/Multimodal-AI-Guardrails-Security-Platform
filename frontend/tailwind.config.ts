import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Cyberpunk color palette
        cyber: {
          bg: '#0a0e1a',
          bgSecondary: '#0f1420',
          bgTertiary: '#151b2e',
          border: '#1a2332',
          borderGlow: '#2a3552',
        },
        neon: {
          cyan: '#00fff9',
          pink: '#ff006e',
          purple: '#bf00ff',
          blue: '#0080ff',
          green: '#00ff41',
          yellow: '#ffed4e',
          orange: '#ff6b35',
        },
        threat: {
          critical: '#ff006e',
          high: '#ff6b35',
          medium: '#ffed4e',
          low: '#00ff41',
          info: '#00fff9',
        },
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'gradient-conic': 'conic-gradient(from 180deg at 50% 50%, var(--tw-gradient-stops))',
        'gradient-cyber': 'linear-gradient(135deg, #0a0e1a 0%, #151b2e 50%, #0f1420 100%)',
        'gradient-neon': 'linear-gradient(135deg, #00fff9 0%, #bf00ff 50%, #ff006e 100%)',
        'grid-cyber': 'linear-gradient(to right, #1a2332 1px, transparent 1px), linear-gradient(to bottom, #1a2332 1px, transparent 1px)',
      },
      boxShadow: {
        'neon-cyan': '0 0 10px #00fff9, 0 0 20px #00fff9, 0 0 30px #00fff9',
        'neon-pink': '0 0 10px #ff006e, 0 0 20px #ff006e, 0 0 30px #ff006e',
        'neon-purple': '0 0 10px #bf00ff, 0 0 20px #bf00ff, 0 0 30px #bf00ff',
        'neon-blue': '0 0 10px #0080ff, 0 0 20px #0080ff, 0 0 30px #0080ff',
        'neon-green': '0 0 10px #00ff41, 0 0 20px #00ff41, 0 0 30px #00ff41',
        'neon-yellow': '0 0 10px #ffed4e, 0 0 20px #ffed4e, 0 0 30px #ffed4e',
        'holographic': '0 0 20px rgba(0, 255, 249, 0.3), 0 0 40px rgba(191, 0, 255, 0.2)',
        'glass': '0 8px 32px 0 rgba(0, 255, 249, 0.1)',
      },
      animation: {
        'pulse-neon': 'pulse-neon 2s ease-in-out infinite',
        'glow': 'glow 2s ease-in-out infinite',
        'float': 'float 3s ease-in-out infinite',
        'scan': 'scan 2s linear infinite',
        'flicker': 'flicker 0.3s ease-in-out infinite',
        'slide-up': 'slide-up 0.5s ease-out',
        'slide-down': 'slide-down 0.5s ease-out',
        'fade-in': 'fade-in 0.5s ease-out',
        'holographic': 'holographic 4s ease-in-out infinite',
      },
      keyframes: {
        'pulse-neon': {
          '0%, 100%': { opacity: '1', filter: 'brightness(1)' },
          '50%': { opacity: '0.8', filter: 'brightness(1.5)' },
        },
        'glow': {
          '0%, 100%': { boxShadow: '0 0 10px rgba(0, 255, 249, 0.5), 0 0 20px rgba(0, 255, 249, 0.3)' },
          '50%': { boxShadow: '0 0 20px rgba(0, 255, 249, 0.8), 0 0 40px rgba(0, 255, 249, 0.5)' },
        },
        'float': {
          '0%, 100%': { transform: 'translateY(0px)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        'scan': {
          '0%': { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100%)' },
        },
        'flicker': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.7' },
        },
        'slide-up': {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'slide-down': {
          '0%': { transform: 'translateY(-20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
        'fade-in': {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        'holographic': {
          '0%, 100%': {
            backgroundPosition: '0% 50%',
            filter: 'hue-rotate(0deg)',
          },
          '50%': {
            backgroundPosition: '100% 50%',
            filter: 'hue-rotate(45deg)',
          },
        },
      },
      backdropBlur: {
        xs: '2px',
      },
      backgroundSize: {
        'grid': '50px 50px',
      },
    },
  },
  plugins: [],
}
export default config
