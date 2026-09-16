import { EXCEPTION_CATEGORIES } from "./taxonomy";
import type { ExceptionFormField } from "./validation";

// Element ids of the exception request form, shared by the form and its scope picker so an error summary
// can move focus to the field it describes. Only one request form is on screen at a time.

export function categoryCheckboxId(category: string): string {
  return `exc-category-${category}`;
}

export const CODES_FILTER_ID = "exc-codes-filter";

export const EXCEPTION_FIELD_IDS: Readonly<Record<ExceptionFormField, string>> = {
  package: "exc-package",
  versionSpec: "exc-version-spec",
  policyId: "exc-policy",
  environment: "exc-environment",
  categories: categoryCheckboxId(EXCEPTION_CATEGORIES[0]),
  codes: CODES_FILTER_ID,
  justification: "exc-justification",
  expiresOn: "exc-expires-on",
};
