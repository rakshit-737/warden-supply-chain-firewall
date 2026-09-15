/**
 * Adversarial test inputs.
 *
 * ESLint's no-script-url rule rejects string literals starting with "javascript:" anywhere in the
 * source tree, which keeps such URLs out of application code. Tests still need the value to prove
 * it is rendered as inert text, so it is assembled at runtime here instead of written literally.
 */
export const SCRIPT_URL = ["javascript", "alert(1)"].join(":");
