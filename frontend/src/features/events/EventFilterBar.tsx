import { useId, useRef, useState } from "react";
import { EVENT_TYPES, SEVERITIES } from "../../api/types";
import { SelectField } from "../../components/SelectField";
import { SEVERITY_LABEL } from "../../lib/risk";
import {
  SINCE_PRESETS,
  hasActiveEventFilters,
  sinceBefore,
  validateEventTextFilters,
  type EventFilters,
  type EventTextDraft,
  type EventTextErrors,
} from "./eventFilters";
import { EVENT_TYPE_LABEL } from "./eventLabels";
import { FilterErrorSummary, FilterTextField } from "./FilterFields";
import type { ParamChanges } from "./searchParams";
import { toLocalInputValue } from "./time";

const TYPE_OPTIONS = [
  { value: "", label: "Any" },
  ...EVENT_TYPES.map((type) => ({ value: type, label: EVENT_TYPE_LABEL[type] })).sort((a, b) => a.label.localeCompare(b.label)),
];
const SEVERITY_OPTIONS = [{ value: "", label: "Any" }, ...SEVERITIES.map((s) => ({ value: s, label: SEVERITY_LABEL[s] }))];
const STATUS_OPTIONS = [
  { value: "", label: "Any" },
  { value: "false", label: "Unacknowledged" },
  { value: "true", label: "Acknowledged" },
];
const FIELD_ORDER: readonly (keyof EventTextDraft)[] = ["package", "projectId", "since"];

export interface EventFilterBarProps {
  filters: EventFilters;
  /** Receives query-string changes (the offset is reset with every filter change). */
  onChange: (changes: ParamChanges) => void;
}

/**
 * Filters bound to the address. The selects apply at once; the text fields are validated and
 * applied together on submit (Enter or Apply filters), so a half-typed UUID never reaches the server.
 */
export function EventFilterBar({ filters, onChange }: EventFilterBarProps) {
  const baseId = useId();
  const packageRef = useRef<HTMLInputElement>(null);
  const projectRef = useRef<HTMLInputElement>(null);
  const sinceRef = useRef<HTMLInputElement>(null);

  const fromAddress: EventTextDraft = {
    package: filters.package ?? "",
    projectId: filters.projectId ?? "",
    since: toLocalInputValue(filters.since),
  };
  // Typed text is kept until the address changes (a submit, Clear filters, back and forward).
  const basedOn = [fromAddress.package, fromAddress.projectId, filters.since ?? ""].join("\n");
  const [draft, setDraft] = useState<{ basedOn: string; values: EventTextDraft } | null>(null);
  const [invalid, setInvalid] = useState<{ basedOn: string; errors: EventTextErrors } | null>(null);
  const values = draft?.basedOn === basedOn ? draft.values : fromAddress;
  const errors: EventTextErrors = invalid?.basedOn === basedOn ? invalid.errors : {};
  const errorCount = FIELD_ORDER.filter((field) => errors[field]).length;

  function edit(field: keyof EventTextDraft, value: string) {
    setDraft({ basedOn, values: { ...values, [field]: value } });
    if (errors[field]) setInvalid({ basedOn, errors: { ...errors, [field]: undefined } });
  }

  function apply(next: EventTextDraft, sinceIncomplete: boolean) {
    const result = validateEventTextFilters(next, { sinceIncomplete });
    const firstInvalid = FIELD_ORDER.find((field) => result.errors[field]);
    if (firstInvalid) {
      setDraft({ basedOn, values: next });
      setInvalid({ basedOn, errors: result.errors });
      const target = firstInvalid === "package" ? packageRef : firstInvalid === "projectId" ? projectRef : sinceRef;
      target.current?.focus();
      return;
    }
    setDraft(null);
    setInvalid(null);
    // An untouched time keeps the exact value from the address (the input only shows minutes).
    const since = next.since === fromAddress.since ? (filters.since ?? null) : result.values.since;
    onChange({ package: result.values.package, project_id: result.values.projectId, since, offset: null });
  }

  function clear() {
    setDraft(null);
    setInvalid(null);
    onChange({
      type: null,
      severity: null,
      acknowledged: null,
      package: null,
      project_id: null,
      since: null,
      offset: null,
    });
  }

  const active = hasActiveEventFilters(filters) || draft?.basedOn === basedOn;

  return (
    <form
      role="search"
      aria-label="Filter security events"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        apply(values, Boolean(sinceRef.current?.validity.badInput));
      }}
      className="mb-3 flex flex-col gap-3"
    >
      <div className="flex flex-wrap items-start gap-3">
        <SelectField
          id={`${baseId}-type`}
          label="Type"
          className="w-full sm:w-60"
          value={filters.type ?? ""}
          options={TYPE_OPTIONS}
          onChange={(value) => onChange({ type: value, offset: null })}
        />
        <SelectField
          id={`${baseId}-severity`}
          label="Severity"
          className="w-full sm:w-32"
          value={filters.severity ?? ""}
          options={SEVERITY_OPTIONS}
          onChange={(value) => onChange({ severity: value, offset: null })}
        />
        <SelectField
          id={`${baseId}-status`}
          label="Status"
          className="w-full sm:w-40"
          value={filters.acknowledged === undefined ? "" : String(filters.acknowledged)}
          options={STATUS_OPTIONS}
          onChange={(value) => onChange({ acknowledged: value, offset: null })}
        />
        <FilterTextField
          id={`${baseId}-package`}
          label="Package"
          className="w-full sm:w-56"
          inputRef={packageRef}
          mono
          placeholder="Exact name"
          maxLength={214}
          value={values.package}
          error={errors.package}
          onChange={(value) => edit("package", value)}
        />
        <FilterTextField
          id={`${baseId}-project`}
          label="Project ID"
          className="w-full sm:w-80"
          inputRef={projectRef}
          mono
          placeholder="UUID"
          maxLength={64}
          value={values.projectId}
          error={errors.projectId}
          onChange={(value) => edit("projectId", value)}
        />
        <div className="w-full sm:w-56">
          <FilterTextField
            id={`${baseId}-since`}
            label="Since (your local time)"
            type="datetime-local"
            inputRef={sinceRef}
            value={values.since}
            error={errors.since}
            onChange={(value) => edit("since", value)}
          />
          <div role="group" aria-label="Quick time ranges" className="mt-1.5 flex flex-wrap gap-1">
            {SINCE_PRESETS.map((preset) => (
              <button
                key={preset.id}
                type="button"
                className="btn-ghost h-6 px-1.5 text-xs"
                aria-label={preset.description}
                onClick={() => apply({ ...values, since: toLocalInputValue(sinceBefore(preset.ms)) }, false)}
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <button type="submit" className="btn-secondary">
          Apply filters
        </button>
        {active && (
          <button type="button" className="btn-ghost" onClick={clear}>
            Clear filters
          </button>
        )}
        <p className="text-xs text-ink-muted">
          Type, severity and status apply at once. Package, project and time apply with Enter or Apply filters.
        </p>
      </div>
      <FilterErrorSummary count={errorCount} />
    </form>
  );
}
