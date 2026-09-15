import type { Config } from "tailwindcss";
import defaultTheme from "tailwindcss/defaultTheme";
import { palette } from "./src/theme/palette.ts";

// The colour scale is replaced (not extended) so every colour in the app comes from the
// console palette.
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    colors: {
      transparent: "transparent",
      current: "currentColor",
      inherit: "inherit",
      black: "#000000",
      page: palette.page,
      panel: palette.panel,
      raised: palette.raised,
      sunken: palette.sunken,
      line: { DEFAULT: palette.line, strong: palette.lineStrong },
      ink: { DEFAULT: palette.ink, secondary: palette.inkSecondary, muted: palette.inkMuted },
      accent: palette.accent,
      sev: palette.severity,
      verdict: palette.decision,
    },
    fontFamily: {
      sans: ["Barlow", ...defaultTheme.fontFamily.sans],
      condensed: ['"Barlow Semi Condensed"', "Barlow", ...defaultTheme.fontFamily.sans],
      mono: ['"JetBrains Mono Variable"', ...defaultTheme.fontFamily.mono],
    },
    extend: {
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
    },
  },
  plugins: [],
} satisfies Config;
