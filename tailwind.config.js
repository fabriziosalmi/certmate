/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./templates/**/*.html", "./static/js/**/*.js"],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        primary: '#3b82f6',
        secondary: '#1e40af',
        success: '#22c55e',
        warning: '#f59e0b',
        danger: '#ef4444',
      }
    }
  },
  plugins: [],
}
