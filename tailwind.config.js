/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./public/**/*.html', './public/**/*.js'],
  safelist: [
    'tracking-[0.2em]',
    'opacity-[0.03]',
    'active:scale-[0.98]',
    'scale-[0.98]',
    'from-[#4F7BFF]',
    'to-[#6DD5FA]',
    'w-[880px]'
  ],
  theme: {
    extend: {}
  },
  plugins: []
};
