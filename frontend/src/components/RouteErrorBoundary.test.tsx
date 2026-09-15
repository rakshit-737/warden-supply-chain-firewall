import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { lazy, Suspense, type ComponentType } from "react";
import { describe, expect, it, vi } from "vitest";
import { isChunkLoadError } from "../lib/errors";
import { RouteErrorBoundary } from "./RouteErrorBoundary";

function Explodes(): never {
  throw new Error("render failed");
}

describe("RouteErrorBoundary", () => {
  it("keeps the page usable and offers a reload when a route chunk no longer exists", async () => {
    const user = userEvent.setup();
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const MissingChunk = lazy<ComponentType>(() =>
      Promise.reject(new TypeError("Failed to fetch dynamically imported module: https://warden.test/assets/Policies-0ld.js")),
    );
    const onReload = vi.fn();
    render(
      <>
        <nav>Navigation</nav>
        <RouteErrorBoundary onReload={onReload}>
          <Suspense fallback={<p>Loading view</p>}>
            <MissingChunk />
          </Suspense>
        </RouteErrorBoundary>
      </>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("This view could not be loaded");
    expect(screen.getByText("Navigation")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reload page" }));
    expect(onReload).toHaveBeenCalledOnce();
  });

  it("shows a generic message for other render errors and clears it when the route changes", () => {
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    const { rerender } = render(
      <RouteErrorBoundary resetKey="/policies">
        <Explodes />
      </RouteErrorBoundary>,
    );
    expect(screen.getByRole("alert")).toHaveTextContent("This view failed to display");

    rerender(
      <RouteErrorBoundary resetKey="/scans">
        <p>Scans view</p>
      </RouteErrorBoundary>,
    );
    expect(screen.queryByRole("alert")).toBeNull();
    expect(screen.getByText("Scans view")).toBeInTheDocument();
  });
});

describe("isChunkLoadError", () => {
  it("recognises failed dynamic imports in each browser family and Vite's preload error", () => {
    for (const message of [
      "Failed to fetch dynamically imported module: https://warden.test/assets/Scans-1.js",
      "error loading dynamically imported module: https://warden.test/assets/Scans-1.js",
      "Importing a module script failed.",
      "Unable to preload CSS for /assets/index-1.css",
    ]) {
      expect(isChunkLoadError(new TypeError(message))).toBe(true);
    }
    expect(isChunkLoadError(new Error("Cannot read properties of undefined (reading 'map')"))).toBe(false);
    expect(isChunkLoadError("Failed to fetch dynamically imported module")).toBe(false);
  });
});
