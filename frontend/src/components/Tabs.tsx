import { useId, useState, type KeyboardEvent, type ReactNode } from "react";

export interface TabItem {
  id: string;
  label: ReactNode;
  /** Optional count chip; omit when the count is not known. */
  count?: number;
  content: ReactNode;
}

export interface TabsProps {
  tabs: TabItem[];
  /** Accessible name of the tab list. */
  label: string;
  value?: string;
  defaultValue?: string;
  onChange?: (id: string) => void;
}

/**
 * WAI-ARIA tabs with automatic activation: arrow keys move between tabs, Home/End jump to the
 * ends, and only the selected tab is in the Tab order. Only the selected panel is rendered.
 */
export function Tabs({ tabs, label, value, defaultValue, onChange }: TabsProps) {
  const baseId = useId();
  const [internal, setInternal] = useState(defaultValue);
  const selected = tabs.find((tab) => tab.id === (value ?? internal)) ?? tabs[0];
  if (!selected) return null;

  const tabId = (id: string) => `${baseId}-tab-${id}`;
  const panelId = (id: string) => `${baseId}-panel-${id}`;

  function select(id: string) {
    if (value === undefined) setInternal(id);
    onChange?.(id);
  }

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    const last = tabs.length - 1;
    const next =
      event.key === "ArrowRight"
        ? (index + 1) % tabs.length
        : event.key === "ArrowLeft"
          ? (index + last) % tabs.length
          : event.key === "Home"
            ? 0
            : event.key === "End"
              ? last
              : null;
    const target = next === null ? undefined : tabs[next];
    if (next === null || !target) return;
    event.preventDefault();
    select(target.id);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  }

  return (
    <div className="min-w-0">
      <div role="tablist" aria-label={label} className="flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((tab, index) => {
          const active = tab.id === selected.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={tabId(tab.id)}
              aria-selected={active}
              aria-controls={active ? panelId(tab.id) : undefined}
              tabIndex={active ? 0 : -1}
              onClick={() => select(tab.id)}
              onKeyDown={(event) => onKeyDown(event, index)}
              className={`-mb-px flex shrink-0 items-center gap-1.5 border-b-2 px-3 py-2 text-[0.8125rem] font-medium ${
                active ? "border-accent text-ink" : "border-transparent text-ink-secondary hover:text-ink"
              }`}
            >
              {tab.label}
              {tab.count !== undefined && (
                <span className="rounded-sm bg-raised px-1.5 text-2xs tabular-nums text-ink-secondary">{tab.count}</span>
              )}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={panelId(selected.id)} aria-labelledby={tabId(selected.id)} tabIndex={0} className="pt-4">
        {selected.content}
      </div>
    </div>
  );
}
