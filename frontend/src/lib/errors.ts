// Browsers word a failed dynamic import differently; these are the known messages, plus the error
// Vite's preload helper throws when a route's CSS file is missing.
const CHUNK_LOAD_MESSAGES: readonly RegExp[] = [
  /Failed to fetch dynamically imported module/i, // Chromium
  /error loading dynamically imported module/i, // Firefox
  /Importing a module script failed/i, // Safari
  /Unable to preload CSS for/i, // Vite
];

/**
 * True for errors thrown when a code-split chunk could not be loaded. After a redeploy the page still
 * refers to the previous build's content-hashed files, which no longer exist on the server.
 */
export function isChunkLoadError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return error.name === "ChunkLoadError" || CHUNK_LOAD_MESSAGES.some((pattern) => pattern.test(error.message));
}
