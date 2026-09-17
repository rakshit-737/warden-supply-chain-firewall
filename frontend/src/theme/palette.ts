/**
 * Warden console palette (dark only). Colour values for chart code that needs raw values
 * (Recharts). Tailwind reads the same values from the @theme block in src/index.css;
 * palette.test.ts keeps the two in sync.
 *
 * Severity and decision marks were checked with a palette validator against the panel surface
 * (#1A1F27): adjacent pairs clear colour-vision-deficiency separation (OKLab dE >= 13) and the
 * normal-vision floor (dE >= 15), and every mark is >= 3:1 against the surface. Colour is never
 * the only encoding: badges also carry a text label plus a shape (decisions) or pip count
 * (severity). Text always uses the ink tokens, never a mark colour.
 */
export const palette = {
  page: "#13171D",
  panel: "#1A1F27",
  raised: "#222832",
  sunken: "#0F1318",
  line: "#2F3743",
  lineStrong: "#434D5B",
  ink: "#E7EBF1",
  inkSecondary: "#B3BCC9",
  inkMuted: "#8F99A8",
  accent: "#A898FF",
  severity: {
    info: "#8F99A8",
    low: "#58A6E8",
    medium: "#F2D04B",
    high: "#F07A3A",
    critical: "#DB3A7B",
  },
  decision: {
    allow: "#2FBF5B",
    warn: "#F2D04B",
    block: "#DB3A7B",
  },
} as const;
