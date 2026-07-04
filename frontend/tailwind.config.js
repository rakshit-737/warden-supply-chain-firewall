/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        base: "#0b0f1a",
        panel: "#131a2a",
        panel2: "#1b2438",
        edge: "#28324a",
        accent: "#4f8cff",
        muted: "#8a97b1",
      },
    },
  },
  plugins: [],
};
