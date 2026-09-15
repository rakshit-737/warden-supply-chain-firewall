import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export interface SectionUnavailableProps {
  title: string;
  /** What the view will cover once it exists. */
  summary: string;
}

/** Placeholder for a navigation section whose view has not been built yet. */
export default function SectionUnavailable({ title, summary }: SectionUnavailableProps) {
  return (
    <>
      <PageHeader title={title} description={summary} />
      <EmptyState
        title="This view is not available yet."
        description="This version of the console does not include it. No data is shown here."
      />
    </>
  );
}
