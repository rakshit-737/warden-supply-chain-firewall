import { getSystemInfo, getSystemTools } from "../api/system";
import { PERMISSIONS } from "../auth/permissions";
import { Card } from "../components/Card";
import { ErrorState } from "../components/ErrorState";
import { PageHeader } from "../components/PageHeader";
import { RequirePermission } from "../components/RequirePermission";
import { LoadingBlock } from "../components/Skeleton";
import { assessPosture } from "../features/system/posture";
import { SecurityPosture } from "../features/system/SecurityPosture";
import { SystemSettingsCards } from "../features/system/SystemSettingsCards";
import { readToolStatuses } from "../features/system/systemInfo";
import { ToolsCard } from "../features/system/ToolsCard";
import { useApiQuery } from "../hooks/useApiQuery";

function SystemView() {
  const info = useApiQuery("system:info", (signal) => getSystemInfo({ signal }));
  const tools = useApiQuery("system:tools", (signal) => getSystemTools({ signal }));
  const toolRows = tools.data === undefined ? undefined : readToolStatuses(tools.data);

  return (
    <>
      <PageHeader
        title="System"
        description="How this deployment is configured: versions, feature switches, enforced limits and analysis tools. The server never reports secrets, connection strings or file paths."
        actions={
          <button
            type="button"
            className="btn-secondary"
            onClick={() => {
              info.reload();
              tools.reload();
            }}
          >
            Refresh
          </button>
        }
      />

      <div className="flex flex-col gap-4">
        {info.data !== undefined ? (
          <>
            {info.error && (
              <ErrorState
                error={info.error}
                title="Refreshing failed. Showing the system information that loaded before."
                onRetry={info.reload}
              />
            )}
            <SecurityPosture report={assessPosture(info.data, toolRows ?? null)} />
            <SystemSettingsCards info={info.data} />
          </>
        ) : info.error ? (
          <ErrorState error={info.error} title="System information could not be loaded" onRetry={info.reload} />
        ) : (
          <Card title="Deployment">
            <LoadingBlock label="Loading system information" rows={6} />
          </Card>
        )}

        <ToolsCard rows={toolRows} loading={tools.loading} error={tools.error} onRetry={tools.reload} />
      </div>
    </>
  );
}

/** System information (system:read: admin and auditor). The server enforces the same permission. */
export default function SystemPage() {
  return (
    <RequirePermission permission={PERMISSIONS.SYSTEM_READ}>
      <SystemView />
    </RequirePermission>
  );
}
