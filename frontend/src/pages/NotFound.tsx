import { Link } from "react-router";
import { EmptyState } from "../components/EmptyState";
import { PageHeader } from "../components/PageHeader";

export default function NotFound() {
  return (
    <>
      <PageHeader title="Page not found" />
      <EmptyState
        title="There is no page at this address."
        action={
          <Link to="/" className="btn-secondary">
            Go to the dashboard
          </Link>
        }
      />
    </>
  );
}
