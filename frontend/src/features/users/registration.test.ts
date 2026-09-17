import { describe, expect, it } from "vitest";
import { asSentence, isLastAdminError, validateRegistration, type RegistrationValues } from "./registration";
import { describeRole } from "./roles";

const VALID: RegistrationValues = {
  email: "  new.person@example.com ",
  password: "correct horse battery",
  confirmPassword: "correct horse battery",
  role: "developer",
};

describe("validateRegistration", () => {
  it("accepts valid input, trimming the email but never the password", () => {
    const withSpaces = { ...VALID, password: " padded passphrase ", confirmPassword: " padded passphrase " };
    expect(validateRegistration(withSpaces)).toEqual({
      errors: {},
      body: { email: "new.person@example.com", password: " padded passphrase ", role: "developer" },
    });
  });

  it("requires a password of at least 12 characters", () => {
    expect(validateRegistration({ ...VALID, password: "elevenchars", confirmPassword: "elevenchars" }).errors).toEqual({
      password: "The password must be at least 12 characters.",
    });
    expect(validateRegistration({ ...VALID, password: "twelve-chars", confirmPassword: "twelve-chars" }).body).not.toBeNull();
  });

  it("counts characters the way the server does", () => {
    // Eleven emoji are 22 UTF-16 code units but only 11 characters for the server.
    const eleven = "\u{1F510}".repeat(11);
    const twelve = "\u{1F510}".repeat(12);
    expect(validateRegistration({ ...VALID, password: eleven, confirmPassword: eleven }).errors.password).toBeDefined();
    expect(validateRegistration({ ...VALID, password: twelve, confirmPassword: twelve }).body).not.toBeNull();
    const tooLong = "a".repeat(257);
    expect(validateRegistration({ ...VALID, password: tooLong, confirmPassword: tooLong }).errors.password).toBe(
      "The password can be at most 256 characters.",
    );
  });

  it("reports every problem at once", () => {
    const result = validateRegistration({ email: "not-an-email", password: "", confirmPassword: "", role: "read_only" });
    expect(result.body).toBeNull();
    expect(result.errors).toEqual({
      email: "Enter an email address in the form name@example.com.",
      password: "Enter a password.",
    });
    expect(validateRegistration({ ...VALID, confirmPassword: "correct horse batterY" }).errors).toEqual({
      confirmPassword: "The passwords do not match.",
    });
  });

  it("rejects a password made only of spaces", () => {
    const spaces = " ".repeat(16);
    expect(validateRegistration({ ...VALID, password: spaces, confirmPassword: spaces }).errors.password).toBe(
      "The password cannot consist only of spaces.",
    );
  });
});

describe("describeRole", () => {
  it("shows v1 role names as their current role and keeps the reported name", () => {
    expect(describeRole("analyst")).toEqual({ role: "security_analyst", label: "Security analyst", reportedAs: "analyst" });
    expect(describeRole("viewer")).toEqual({ role: "read_only", label: "Read only", reportedAs: "viewer" });
    expect(describeRole("auditor")).toEqual({ role: "auditor", label: "Auditor", reportedAs: null });
    expect(describeRole("superuser")).toEqual({ role: null, label: "Unrecognised role", reportedAs: "superuser" });
    expect(describeRole(undefined)).toEqual({ role: null, label: "Unrecognised role", reportedAs: null });
  });
});

describe("server error helpers", () => {
  it("recognises only the last-admin conflict", () => {
    expect(isLastAdminError({ status: 409, code: "last_admin", message: "m", requestId: null })).toBe(true);
    expect(isLastAdminError({ status: 409, code: "conflict", message: "m", requestId: null })).toBe(false);
    expect(isLastAdminError(null)).toBe(false);
  });

  it("ends a server message as a sentence", () => {
    expect(asSentence("Refusing to remove the last active admin")).toBe("Refusing to remove the last active admin.");
    expect(asSentence("Already a sentence.")).toBe("Already a sentence.");
  });
});
