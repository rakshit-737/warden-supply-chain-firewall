import { Card } from "../../components/Card";
import { EmptyState } from "../../components/EmptyState";
import { revealInvisible } from "../../lib/text";
import type { ObservationTone, PostureReport } from "./posture";

const TONE_LABEL: Readonly<Record<ObservationTone, string>> = {
  review: "Worth reviewing",
  note: "Note",
};

const TONE_PIP: Readonly<Record<ObservationTone, string>> = {
  review: "bg-sev-medium",
  note: "bg-sev-info",
};

function listText(items: readonly string[]): string {
  return items.join(", ");
}

/** Observations about risky or notable settings in GET /system/info, phrased as facts rather than alarms. */
export function SecurityPosture({ report }: { report: PostureReport }) {
  const { observations, checked, notAssessed } = report;
  return (
    <Card
      title="Security posture"
      description="Observations about this deployment's configuration, drawn only from what the server reports. They describe settings, not detected incidents."
    >
      {observations.length === 0 ? (
        <EmptyState compact title="Nothing stood out in the reported settings." />
      ) : (
        <ul aria-label="Observations" className="flex flex-col">
          {observations.map((observation) => (
            <li
              key={observation.id}
              className="flex flex-col gap-1 border-b border-line/60 py-2.5 first:pt-0 last:border-0 sm:flex-row sm:gap-4"
            >
              <span className="inline-flex shrink-0 items-center gap-1.5 text-xs font-medium text-ink-secondary sm:w-32 sm:pt-0.5">
                <span aria-hidden="true" className={`h-2 w-2 rounded-full ${TONE_PIP[observation.tone]}`} />
                {TONE_LABEL[observation.tone]}
              </span>
              <div className="min-w-0">
                <p className="wrap-break-word font-medium text-ink">{revealInvisible(observation.title)}</p>
                <p className="wrap-break-word text-ink-secondary">{revealInvisible(observation.detail)}</p>
              </div>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-3 flex flex-col gap-0.5 border-t border-line pt-2 text-xs text-ink-muted">
        {checked.length > 0 && <p>Checked: {listText(checked)}.</p>}
        {notAssessed.length > 0 && (
          <p>Not assessed, because the server did not report it or it has not loaded: {listText(notAssessed)}.</p>
        )}
      </div>
    </Card>
  );
}
