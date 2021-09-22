const { green } = require('tailwindcss/colors')
const colors = require('tailwindcss/colors')

module.exports = {
  purge: {
    enabled: !process.env.ROLLUP_WATCH,
    mode: 'all',
    content: ['./public/index.html', './src/**/*.svelte'],
  },
  darkMode: false, // or 'media' or 'class'
  theme: {
    colors: {
      ...colors,
      blue: colors.lightBlue,
      green: colors.green,
      white: colors.white,
      gray: colors.warmGray,
      red: colors.red,
      grey: colors.grey
    },
    extend: {},
  },
  variants: {
    extend: {
      backgroundColor: ['active'],
      textDecoration: ['active'],
    },
  },
  plugins: [],
}
