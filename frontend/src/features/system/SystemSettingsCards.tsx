import type { SystemInfo } from "../../api/types";
import { Card } from "../../components/Card";
import { revealInvisible } from "../../lib/text";
import {
  DEPLOYMENT_GROUP,
  FEATURE_GROUPS,
  LIMIT_GROUPS,
  RUNTIME_GROUP,
  formatSetting,
  settingGroup,
  unlistedSettings,
  type SettingGroup,
  type SettingRow,
} from "./systemInfo";

function SettingValue({ row }: { row: SettingRow }) {
  const shown = formatSetting(row.format, row.value);
  if (shown.tone === "on" || shown.tone === "off") {
    const on = shown.tone === "on";
    return (
      <span className="inline-flex items-center gap-1.5">
        <span
          aria-hidden="true"
          className={on ? "h-2 w-2 rounded-full bg-ink" : "h-2 w-2 rounded-full border border-ink-muted"}
        />
        <span className={on ? "text-ink" : "text-ink-secondary"}>{shown.text}</span>
      </span>
    );
  }
  const look =
    shown.tone === "missing" ? "text-ink-muted" : shown.mono ? "font-mono text-[0.8125rem] text-ink" : "text-ink";
  return <span className={look}>{shown.text}</span>;
}

function SettingsList({ rows }: { rows: readonly SettingRow[] }) {
  return (
    <dl className="flex flex-col">
      {rows.map((row) => (
        <div
          key={row.key}
          className="grid grid-cols-[minmax(0,1fr)_minmax(0,auto)] items-baseline gap-4 border-b border-line/60 py-1.5 last:border-0"
        >
          <dt className="min-w-0 wrap-break-word text-ink-secondary">{revealInvisible(row.label)}</dt>
          <dd className="min-w-0 wrap-break-word text-right wrap-anywhere">
            <SettingValue row={row} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function GroupedSettings({ groups }: { groups: readonly SettingGroup[] }) {
  return (
    <div className="grid gap-x-8 gap-y-5 md:grid-cols-2">
      {groups.map((group) => (
        <section key={group.id} aria-labelledby={`system-${group.id}`} className="min-w-0">
          <h3 id={`system-${group.id}`} className="text-[0.8125rem] font-semibold text-ink">
            {group.title}
          </h3>
          {group.note && <p className="text-xs text-ink-muted">{group.note}</p>}
          <div className="mt-1">
            <SettingsList rows={group.rows} />
          </div>
        </section>
      ))}
    </div>
  );
}

/** GET /system/info as grouped cards: deployment, runtime, features, limits and anything else reported. */
export function SystemSettingsCards({ info }: { info: SystemInfo }) {
  const other = unlistedSettings(info);
  return (
    <>
      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Deployment">
          <SettingsList rows={settingGroup(info, DEPLOYMENT_GROUP).rows} />
        </Card>
        <Card title="Runtime">
          <SettingsList rows={settingGroup(info, RUNTIME_GROUP).rows} />
        </Card>
      </div>
      <Card title="Features" description="Configuration switches of this deployment.">
        <GroupedSettings groups={FEATURE_GROUPS.map((group) => settingGroup(info, group))} />
      </Card>
      <Card title="Limits" description="Bounds the server enforces on requests and analysis.">
        <GroupedSettings groups={LIMIT_GROUPS.map((group) => settingGroup(info, group))} />
      </Card>
      {other.length > 0 && (
        <Card title="Other reported values" description="Reported by this server but not described by this version of the console.">
          <SettingsList rows={other} />
        </Card>
      )}
    </>
  );
}
