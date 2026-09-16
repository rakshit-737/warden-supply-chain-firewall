import type { ApiError } from "../../api/client";
import type { UserRegistration, UserRole } from "../../api/types";
import { LAST_ADMIN_ERROR_CODE, PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from "../../api/users";

export interface RegistrationValues {
  email: string;
  password: string;
  confirmPassword: string;
  role: UserRole;
}

/** Fields that can hold an error, in the order they appear in the form. */
export const REGISTRATION_FIELDS = ["email", "password", "confirmPassword"] as const;
export type RegistrationField = (typeof REGISTRATION_FIELDS)[number];
export type RegistrationErrors = Partial<Record<RegistrationField, string>>;

/** New accounts start with the least privileged role, as the server does. */
export const EMPTY_REGISTRATION: RegistrationValues = { email: "", password: "", confirmPassword: "", role: "read_only" };

/** Loose shape check so obvious typos are caught early; the server's email validation is authoritative. */
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Length in Unicode code points, which is how the server counts (an emoji is one character, not two). */
export function codePointLength(text: string): number {
  return Array.from(text).length;
}

/** Mirrors the server's registration rules so mistakes are reported before anything is sent. */
export function validateRegistration(values: RegistrationValues): { errors: RegistrationErrors; body: UserRegistration | null } {
  const errors: RegistrationErrors = {};
  const email = values.email.trim();
  if (email === "") errors.email = "Enter an email address.";
  else if (!EMAIL_SHAPE.test(email)) errors.email = "Enter an email address in the form name@example.com.";

  // Passwords are never trimmed: spaces are valid characters.
  const length = codePointLength(values.password);
  if (values.password === "") errors.password = "Enter a password.";
  else if (length < PASSWORD_MIN_LENGTH) errors.password = `The password must be at least ${PASSWORD_MIN_LENGTH} characters.`;
  else if (length > PASSWORD_MAX_LENGTH) errors.password = `The password can be at most ${PASSWORD_MAX_LENGTH} characters.`;
  else if (values.password.trim() === "") errors.password = "The password cannot consist only of spaces.";

  if (!errors.password && values.confirmPassword !== values.password) {
    errors.confirmPassword = values.confirmPassword === "" ? "Enter the password again." : "The passwords do not match.";
  }

  if (Object.keys(errors).length > 0) return { errors, body: null };
  return { errors, body: { email, password: values.password, role: values.role } };
}

/** True for the server's refusal to demote or deactivate the last active admin. */
export function isLastAdminError(error: ApiError | null | undefined): boolean {
  return error?.status === 409 && error.code === LAST_ADMIN_ERROR_CODE;
}

/** `text` with closing punctuation, so a server message can be followed by another sentence. */
export function asSentence(text: string): string {
  const trimmed = text.trim();
  return trimmed === "" || /[.!?]$/.test(trimmed) ? trimmed : `${trimmed}.`;
}
