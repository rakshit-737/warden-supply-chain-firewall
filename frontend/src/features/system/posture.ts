import { booleanOrNull, isRecord, textOrNull } from "../../lib/values";
import { readPath, type ToolRow } from "./systemInfo";

/**
 * Security posture observations derived from GET /system/info and GET /system/tools.
 *
 * Each check looks at one setting the server reports and either notes something worth knowing,
 * finds nothing to note, or cannot tell because the value is missing. Observations describe
 * configuration and its consequences; they are deliberately not phrased as alerts, because a
 * setting that matters in production can be exactly right for a development deployment.
 */

export type ObservationTone = "review" | "note";

export interface Observation {
  id: string;
  /** review: worth a deliberate decision; note: context that explains behaviour. */
  tone: ObservationTone;
  title: string;
  detail: string;
}

export interface PostureReport {
  observations: Observation[];
  /** Labels of the checks that could be evaluated. */
  checked: string[];
  /** Labels of the checks whose settings were not reported (or have not loaded). */
  notAssessed: string[];
}

type Outcome = Observation | "fine" | "unknown";

interface PostureCheck {
  label: string;
  evaluate: (info: unknown, tools: readonly ToolRow[] | null) => Outcome;
}

function flag(info: unknown, ...path: string[]): boolean | null {
  return booleanOrNull(readPath(info, path));
}

const CHECKS: readonly PostureCheck[] = [
  {
    label: "metrics access",
    evaluate: (info) => {
      const enabled = flag(info, "features", "metrics", "enabled");
      if (enabled === false) return "fine";
      const tokenRequired = flag(info, "features", "metrics", "token_required");
      if (enabled === null || tokenRequired === null) return "unknown";
      if (tokenRequired) return "fine";
      return {
        id: "metrics-token",
        tone: "review",
        title: "Metrics can be read without a token",
        detail:
          "The /metrics endpoint is enabled and METRICS_TOKEN is not set, so anyone who can reach the API can read its Prometheus metrics. A token, or restricting the endpoint at the network layer, narrows who can.",
      };
    },
  },
  {
    label: "cache backend",
    evaluate: (info) => {
      const backend = textOrNull(readPath(info, ["runtime", "cache_backend"]));
      if (backend === null) return "unknown";
      if (backend !== "in_process") return "fine";
      return {
        id: "cache-in-process",
        tone: "review",
        title: "Caching and rate limiting are in-process",
        detail:
          "Redis is not in use, so each API process keeps its own caches and rate-limit counters. With several processes or replicas, a client's effective rate limit is a multiple of the configured one.",
      };
    },
  },
  {
    label: "environment",
    evaluate: (info) => {
      const env = textOrNull(readPath(info, ["env"]));
      if (env === null) return "unknown";
      if (env.trim().toLowerCase() === "production") return "fine";
      return {
        id: "environment",
        tone: "note",
        title: `The environment is "${env}", not production`,
        detail:
          "Safeguards the server applies only in production are inactive: it does not insist on a strong SECRET_KEY or a changed first-admin password, DEBUG is allowed, and the refresh cookie is not marked Secure.",
      };
    },
  },
  {
    label: "trusted proxies",
    evaluate: (info) => {
      const configured = flag(info, "runtime", "trusted_proxies_configured");
      if (configured === null) return "unknown";
      if (configured) return "fine";
      return {
        id: "trusted-proxies",
        tone: "note",
        title: "No trusted proxies are configured",
        detail:
          "X-Forwarded-For is ignored, so sign-in and unauthenticated requests are rate limited by the address that connects to the API. If a reverse proxy sits in front of it, those clients share the proxy's limit.",
      };
    },
  },
  {
    label: "vulnerability intelligence",
    evaluate: (info) => {
      const enabled = flag(info, "features", "intel", "enabled");
      if (enabled === null) return "unknown";
      if (!enabled) {
        return {
          id: "intel-disabled",
          tone: "review",
          title: "Vulnerability intelligence is off",
          detail:
            "Scans do not look up known vulnerabilities, so their vulnerability status is reported as disabled and vulnerability-based policy rules have nothing to match.",
        };
      }
      const offline = flag(info, "features", "intel", "offline");
      if (offline === null) return "unknown";
      if (!offline) return "fine";
      return {
        id: "intel-offline",
        tone: "note",
        title: "Vulnerability intelligence is in offline mode",
        detail:
          "No advisory source is contacted, so scans report their vulnerability status as disabled and vulnerability-based policy rules have nothing to match.",
      };
    },
  },
  {
    label: "provenance checks",
    evaluate: (info) => {
      const enabled = flag(info, "features", "provenance");
      if (enabled === null) return "unknown";
      if (enabled) return "fine";
      return {
        id: "provenance-disabled",
        tone: "note",
        title: "Provenance checks are off",
        detail: "Scans do not check where packages come from, such as attestations and trusted publishing.",
      };
    },
  },
  {
    label: "tracing",
    evaluate: (info) => {
      const enabled = flag(info, "features", "tracing", "enabled");
      if (enabled === false) return "fine";
      const active = flag(info, "features", "tracing", "active");
      if (enabled === null || active === null) return "unknown";
      if (active) return "fine";
      return {
        id: "tracing-inactive",
        tone: "note",
        title: "Tracing is switched on but not active",
        detail: "OTEL_ENABLED is set, but the OpenTelemetry API could not be loaded, so no traces are recorded.",
      };
    },
  },
  {
    label: "analysis tools",
    evaluate: (info, tools) => {
      const enabled = readPath(info, ["features", "external_tools_enabled"]);
      if (!isRecord(enabled) || tools === null) return "unknown";
      const missing = Object.entries(enabled)
        .filter(([, on]) => on === true)
        .map(([name]) => name)
        .filter((name) => tools.some((tool) => tool.name === name && !tool.available));
      if (missing.length === 0) return "fine";
      const names = missing.join(", ");
      return {
        id: "tools-missing",
        tone: "review",
        title:
          missing.length === 1
            ? `${names} is enabled but not available`
            : `${missing.length} enabled analysis tools are not available`,
        detail: `${names}: the analyzers that rely on ${missing.length === 1 ? "it" : "them"} cannot run, so scans do not include their findings.`,
      };
    },
  },
];

const TONE_ORDER: Readonly<Record<ObservationTone, number>> = { review: 0, note: 1 };

/** Evaluate every posture check. `tools` is null while the tool list is loading or failed to load. */
export function assessPosture(info: unknown, tools: readonly ToolRow[] | null): PostureReport {
  const report: PostureReport = { observations: [], checked: [], notAssessed: [] };
  for (const check of CHECKS) {
    const outcome = check.evaluate(info, tools);
    if (outcome === "unknown") {
      report.notAssessed.push(check.label);
      continue;
    }
    report.checked.push(check.label);
    if (outcome !== "fine") report.observations.push(outcome);
  }
  // Stable sort: checks keep their order within a tone.
  report.observations.sort((a, b) => TONE_ORDER[a.tone] - TONE_ORDER[b.tone]);
  return report;
}
