/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/**/*.{js,jsx,ts,tsx}',
    './public/index.html'
  ],
  theme: {
    extend: {
      colors: {
        eco: {
          green: '#0BA360',
          blue: '#3CBA92'
        }
      },
      backgroundImage: {
        'eco-gradient': 'linear-gradient(135deg, #0BA360 0%, #3CBA92 50%, #1CB5E0 100%)'
      }
    },
  },
  plugins: [],
};
