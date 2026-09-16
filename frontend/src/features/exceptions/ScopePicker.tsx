import { useRef, useState } from "react";
import { humanize } from "../../lib/format";
import { CODES_FILTER_ID, categoryCheckboxId } from "./formIds";
import { EXCEPTABLE_CODE_GROUPS, EXCEPTION_CATEGORIES, NON_OVERRIDABLE_CODES } from "./taxonomy";
import { MAX_CATEGORIES, MAX_CODES } from "./validation";

export interface ScopePickerProps {
  codes: readonly string[];
  categories: readonly string[];
  onCodesChange: (codes: string[]) => void;
  onCategoriesChange: (categories: string[]) => void;
  codesError?: string | null;
  categoriesError?: string | null;
}

function toggled(list: readonly string[], value: string, on: boolean): string[] {
  if (on) return list.includes(value) ? [...list] : [...list, value];
  return list.filter((item) => item !== value);
}

function describedBy(...ids: (string | false | null | undefined)[]): string | undefined {
  const joined = ids.filter(Boolean).join(" ");
  return joined || undefined;
}

/**
 * Multi-select of finding categories and codes as native checkboxes (keyboard and screen-reader
 * operable), with a filter for the long code list. Disable it by wrapping it in a disabled fieldset.
 */
export function ScopePicker({ codes, categories, onCodesChange, onCategoriesChange, codesError, categoriesError }: ScopePickerProps) {
  const [filter, setFilter] = useState("");
  const filterRef = useRef<HTMLInputElement>(null);
  const needle = filter.trim().toUpperCase().replace(/[\s-]+/g, "_");
  const groups = needle
    ? EXCEPTABLE_CODE_GROUPS.map((group) => ({ ...group, codes: group.codes.filter((code) => code.includes(needle)) })).filter(
        (group) => group.codes.length > 0,
      )
    : EXCEPTABLE_CODE_GROUPS;

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <fieldset
        className="min-w-0"
        aria-describedby={describedBy("exc-categories-hint", categoriesError && "exc-categories-error")}
      >
        <legend className="label">Finding categories</legend>
        <p id="exc-categories-hint" className="mb-2 text-xs text-ink-muted">
          Optional. Covers findings in the selected categories. At most {MAX_CATEGORIES}.
        </p>
        <div className="grid max-h-64 gap-x-4 overflow-y-auto rounded border border-line bg-sunken p-2 sm:grid-cols-2">
          {EXCEPTION_CATEGORIES.map((category) => (
            <label key={category} className="flex items-center gap-2 py-0.5 text-[0.8125rem] text-ink">
              <input
                id={categoryCheckboxId(category)}
                type="checkbox"
                className="h-3.5 w-3.5 shrink-0 accent-accent"
                checked={categories.includes(category)}
                onChange={(event) => onCategoriesChange(toggled(categories, category, event.target.checked))}
              />
              {humanize(category)}
            </label>
          ))}
        </div>
        {categoriesError && (
          <p id="exc-categories-error" className="mt-1 text-xs text-sev-critical">
            {categoriesError}
          </p>
        )}
      </fieldset>

      <fieldset className="min-w-0" aria-describedby={describedBy("exc-codes-hint", codesError && "exc-codes-error")}>
        <legend className="label">Finding codes</legend>
        <p id="exc-codes-hint" className="mb-2 text-xs text-ink-muted">
          Optional. At most {MAX_CODES}. {NON_OVERRIDABLE_CODES.join(" and ")} findings can never be excepted, so they are
          not offered.
        </p>
        <label htmlFor={CODES_FILTER_ID} className="sr-only">
          Filter finding codes
        </label>
        <input
          ref={filterRef}
          id={CODES_FILTER_ID}
          type="search"
          className="input mb-2 font-mono"
          placeholder="Filter codes"
          autoComplete="off"
          spellCheck={false}
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
        {codes.length > 0 && (
          <ul aria-label="Selected finding codes" className="mb-2 flex flex-wrap gap-1.5">
            {codes.map((code) => (
              <li key={code}>
                <button
                  type="button"
                  aria-label={`Remove ${code}`}
                  className="inline-flex items-center gap-1 rounded border border-line-strong bg-raised px-1.5 py-0.5 font-mono text-2xs text-ink hover:border-ink-muted"
                  onClick={() => {
                    onCodesChange(toggled(codes, code, false));
                    filterRef.current?.focus();
                  }}
                >
                  {code}
                  <span aria-hidden="true">×</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        <p className="sr-only" aria-live="polite">
          {codes.length === 1 ? "1 code selected" : `${codes.length} codes selected`}
        </p>
        <div className="max-h-64 overflow-y-auto rounded border border-line bg-sunken p-2">
          {groups.length === 0 ? (
            <p className="text-xs text-ink-muted">No codes match the filter.</p>
          ) : (
            groups.map((group) => (
              <fieldset key={group.label} className="mb-2 min-w-0 last:mb-0">
                <legend className="mb-0.5 text-2xs font-medium uppercase tracking-wide text-ink-muted">{group.label}</legend>
                {group.codes.map((code) => (
                  <label key={code} className="flex items-center gap-2 py-0.5 text-ink">
                    <input
                      type="checkbox"
                      className="h-3.5 w-3.5 shrink-0 accent-accent"
                      checked={codes.includes(code)}
                      onChange={(event) => onCodesChange(toggled(codes, code, event.target.checked))}
                    />
                    <span className="break-all font-mono text-xs">{code}</span>
                  </label>
                ))}
              </fieldset>
            ))
          )}
        </div>
        {codesError && (
          <p id="exc-codes-error" className="mt-1 text-xs text-sev-critical">
            {codesError}
          </p>
        )}
      </fieldset>
    </div>
  );
}
